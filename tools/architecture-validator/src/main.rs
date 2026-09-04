#![allow(dead_code)]

use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<Package>,
    resolve: Option<Resolve>,
}
#[derive(Debug, Deserialize)]
struct Package {
    id: String,
    name: String,
    #[serde(default)]
    dependencies: Vec<PackageDependency>,
}
#[derive(Debug, Deserialize)]
struct PackageDependency {
    name: String,
}
#[derive(Debug, Deserialize)]
struct Resolve {
    nodes: Vec<ResolveNode>,
}
#[derive(Debug, Deserialize)]
struct ResolveNode {
    id: String,
    dependencies: Vec<ResolveDependency>,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResolveDependency {
    Id(String),
    Detailed { pkg: String },
}
#[derive(Debug, Deserialize)]
struct RouteCatalog {
    routes: Vec<Route>,
}
#[derive(Debug, Deserialize)]
struct Route {
    owner: String,
    deployment_unit: Option<String>,
    semantic_owner: Option<String>,
    execution_mode: Option<String>,
}
#[derive(Debug, Deserialize)]
struct OwnershipCatalog {
    ownership: BTreeMap<String, OwnerGroup>,
}
#[derive(Debug, Deserialize)]
struct OwnerGroup {
    deployment_unit: Option<String>,
    semantic_owner: Option<String>,
    database: String,
}
#[derive(Debug, Deserialize)]
struct CrateCatalog {
    crates: Vec<CrateRecord>,
}
#[derive(Debug, Deserialize)]
struct CrateRecord {
    crate_id: String,
    package: String,
    path: String,
    layer: String,
    owner_team: String,
    api_stability: String,
    publish_policy: String,
    allowed_dependencies: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct Graph {
    name: String,
    nodes: BTreeSet<String>,
    edges: Vec<(String, String)>,
}

fn main() {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("validate") {
        usage()
    }
    let mut root = PathBuf::from(".");
    let mut write = true;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            "--check" => write = false,
            "--write" => write = true,
            _ => usage(),
        }
    }
    let mut errors = Vec::new();
    let (compile, runtime, data, metadata) = build_graphs(&root, &mut errors);
    check_boundaries(&compile, &root, &mut errors);
    check_crate_catalog(&root, &metadata, &mut errors);
    if !errors.is_empty() {
        for error in errors {
            eprintln!("error: {error}");
        }
        std::process::exit(1);
    }
    if write {
        write_graphs(&root, &compile, &runtime, &data).unwrap_or_else(|error| {
            eprintln!("error: cannot write architecture graphs: {error}");
            std::process::exit(1)
        });
    }
    println!("Architecture validation successful: {} compile-time edges, {} runtime edges, {} data-access edges.", compile.edges.len(), runtime.edges.len(), data.edges.len());
}

fn usage() -> ! {
    eprintln!("usage: architecture-validator validate [--write|--check] [--root <path>]");
    std::process::exit(2)
}

fn build_graphs(root: &Path, errors: &mut Vec<String>) -> (Graph, Graph, Graph, CargoMetadata) {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(root)
        .output();
    let output = match output {
        Ok(value) if value.status.success() => value,
        Ok(value) => {
            errors.push(format!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&value.stderr).trim()
            ));
            return (
                empty("compile-time"),
                empty("runtime"),
                empty("data-access"),
                CargoMetadata {
                    packages: Vec::new(),
                    resolve: None,
                },
            );
        }
        Err(error) => {
            errors.push(format!("cannot execute cargo metadata: {error}"));
            return (
                empty("compile-time"),
                empty("runtime"),
                empty("data-access"),
                CargoMetadata {
                    packages: Vec::new(),
                    resolve: None,
                },
            );
        }
    };
    let metadata: CargoMetadata = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("cargo metadata JSON error: {error}"));
            return (
                empty("compile-time"),
                empty("runtime"),
                empty("data-access"),
                CargoMetadata {
                    packages: Vec::new(),
                    resolve: None,
                },
            );
        }
    };
    let names: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .map(|package| (package.id.clone(), package.name.clone()))
        .collect();
    let mut compile = empty("compile-time");
    if let Some(resolve) = metadata.resolve.as_ref() {
        for node in &resolve.nodes {
            let Some(from) = names.get(&node.id) else {
                continue;
            };
            compile.nodes.insert(from.clone());
            for dependency in &node.dependencies {
                let dependency_id = match dependency {
                    ResolveDependency::Id(id) => id.as_str(),
                    ResolveDependency::Detailed { pkg } => pkg.as_str(),
                };
                if let Some(to) = names.get(dependency_id) {
                    compile.nodes.insert(to.clone());
                    compile.edges.push((from.clone(), to.clone()));
                }
            }
        }
    }
    let routes = read_yaml::<RouteCatalog>(root, "catalog/routes.yaml", errors);
    let ownership = read_yaml::<OwnershipCatalog>(root, "catalog/data-ownership.yaml", errors);
    let mut runtime = empty("runtime");
    if let Some(routes) = routes {
        for route in routes.routes {
            let owner = route.owner;
            let target = route
                .deployment_unit
                .or(route.semantic_owner)
                .unwrap_or_else(|| owner.clone());
            runtime.nodes.insert(owner.clone());
            runtime.nodes.insert(target.clone());
            runtime.edges.push((owner, target));
            if let Some(mode) = route.execution_mode {
                runtime.nodes.insert(mode);
            }
        }
    }
    let mut data = empty("data-access");
    if let Some(ownership) = ownership {
        for (owner, group) in ownership.ownership {
            let deployment = group.deployment_unit.unwrap_or_else(|| owner.clone());
            let semantic = group.semantic_owner.unwrap_or_else(|| owner.clone());
            let db = group.database;
            data.nodes.insert(owner.clone());
            data.nodes.insert(semantic.clone());
            data.nodes.insert(deployment.clone());
            data.nodes.insert(db.clone());
            data.edges.push((owner.clone(), semantic));
            data.edges.push((owner.clone(), deployment));
            data.edges.push((owner, db));
        }
    }
    dedup_edges(&mut compile);
    dedup_edges(&mut runtime);
    dedup_edges(&mut data);
    (compile, runtime, data, metadata)
}

fn read_yaml<T: for<'de> Deserialize<'de>>(
    root: &Path,
    relative: &str,
    errors: &mut Vec<String>,
) -> Option<T> {
    let path = root.join(relative);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("{relative}: {error}"));
            return None;
        }
    };
    match serde_yaml::from_str(&text) {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(format!("{relative}: YAML error: {error}"));
            None
        }
    }
}

fn empty(name: &str) -> Graph {
    Graph {
        name: name.to_owned(),
        nodes: BTreeSet::new(),
        edges: Vec::new(),
    }
}
fn dedup_edges(graph: &mut Graph) {
    graph.edges.sort();
    graph.edges.dedup();
}

fn check_boundaries(graph: &Graph, _root: &Path, errors: &mut Vec<String>) {
    let forbidden_for_core = ["tokio", "sqlx", "axum", "hyper", "reqwest", "redis"];
    for (from, to) in &graph.edges {
        let project_crate = from.starts_with("northstar-") || from.starts_with("foundation-");
        if project_crate
            && from.ends_with("-core")
            && forbidden_for_core
                .iter()
                .any(|name| to == name || to.starts_with(&format!("{name}-")))
        {
            errors.push(format!(
                "compile-time boundary: core crate '{from}' depends on infrastructure crate '{to}'"
            ));
        }
        if project_crate && (from.contains("edge") || from.ends_with("-transport")) && to == "sqlx"
        {
            errors.push(format!(
                "compile-time boundary: edge crate '{from}' depends directly on sqlx"
            ));
        }
    }
}

fn check_crate_catalog(root: &Path, metadata: &CargoMetadata, errors: &mut Vec<String>) {
    let path = root.join("catalog/crates.yaml");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("catalog/crates.yaml: {error}"));
            return;
        }
    };
    let catalog: CrateCatalog = match serde_yaml::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("catalog/crates.yaml: YAML error: {error}"));
            return;
        }
    };
    let mut ids = BTreeSet::new();
    for record in catalog.crates {
        if !ids.insert(record.crate_id.clone()) {
            errors.push(format!(
                "catalog/crates.yaml.{}: duplicate crate_id",
                record.crate_id
            ));
        }
        if record.owner_team.trim().is_empty()
            || record.api_stability.trim().is_empty()
            || record.allowed_dependencies.is_empty()
        {
            errors.push(format!(
                "catalog/crates.yaml.{}: owner, stability, and dependency budget are required",
                record.crate_id
            ));
        }
        if record.publish_policy != "never" {
            errors.push(format!(
                "catalog/crates.yaml.{}.publish_policy: runtime crates must remain private",
                record.crate_id
            ));
        }
        let Some(package) = metadata
            .packages
            .iter()
            .find(|package| package.name == record.package)
        else {
            errors.push(format!(
                "catalog/crates.yaml.{}.package: '{}' is not in cargo metadata",
                record.crate_id, record.package
            ));
            continue;
        };
        if !root.join(&record.path).join("Cargo.toml").is_file() {
            errors.push(format!(
                "catalog/crates.yaml.{}.path: '{}' does not contain Cargo.toml",
                record.crate_id, record.path
            ));
        }
        if package
            .dependencies
            .iter()
            .any(|dependency| dependency.name == "sqlx")
            && ["foundation", "domain"].contains(&record.layer.as_str())
        {
            errors.push(format!(
                "catalog/crates.yaml.{}.layer: {} crate directly depends on sqlx",
                record.crate_id, record.layer
            ));
        }
    }
}

fn write_graphs(
    root: &Path,
    compile: &Graph,
    runtime: &Graph,
    data: &Graph,
) -> std::io::Result<()> {
    let dir = root.join("docs/architecture/generated");
    fs::create_dir_all(&dir)?;
    let graphs = [compile, runtime, data];
    for graph in graphs {
        let stem = graph.name.as_str();
        fs::write(
            dir.join(format!("{stem}.json")),
            serde_json::to_string_pretty(graph).unwrap() + "\n",
        )?;
        fs::write(dir.join(format!("{stem}.dot")), dot(graph))?;
        fs::write(dir.join(format!("{stem}.mmd")), mermaid(graph))?;
    }
    let all =
        serde_json::json!({ "compile_time": compile, "runtime": runtime, "data_access": data });
    fs::write(
        dir.join("graphs.json"),
        serde_json::to_string_pretty(&all).unwrap() + "\n",
    )
}

fn dot(graph: &Graph) -> String {
    let mut output = format!("digraph {} {{\n", graph.name.replace('-', "_"));
    for node in &graph.nodes {
        output.push_str(&format!("  \"{}\";\n", node.replace('"', "\\\"")));
    }
    for (from, to) in &graph.edges {
        output.push_str(&format!("  \"{}\" -> \"{}\";\n", from, to));
    }
    output.push_str("}\n");
    output
}
fn mermaid(graph: &Graph) -> String {
    let mut output = "flowchart LR\n".to_owned();
    for (from, to) in &graph.edges {
        output.push_str(&format!("  {} --> {}\n", mermaid_id(from), mermaid_id(to)));
    }
    output
}
fn mermaid_id(value: &str) -> String {
    format!(
        "N{}[\"{}\"]",
        value
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        value.replace('"', "'")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_to_sqlx_edge_is_rejected() {
        let mut graph = empty("compile-time");
        graph
            .edges
            .push(("northstar-message-core".to_owned(), "sqlx".to_owned()));
        let mut errors = Vec::new();
        check_boundaries(&graph, Path::new("."), &mut errors);
        assert!(errors
            .iter()
            .any(|error| error.contains("northstar-message-core")));
    }

    #[test]
    fn unrelated_external_core_dependency_is_not_misclassified() {
        let mut graph = empty("compile-time");
        graph
            .edges
            .push(("sqlx-core".to_owned(), "tokio".to_owned()));
        let mut errors = Vec::new();
        check_boundaries(&graph, Path::new("."), &mut errors);
        assert!(errors.is_empty());
    }
}
