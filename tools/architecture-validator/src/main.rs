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
    #[serde(default)]
    workspace_members: Vec<String>,
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
    #[serde(default)]
    kind: Option<String>,
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
#[derive(Debug, Clone, Deserialize)]
struct CrateRecord {
    crate_id: String,
    package: String,
    path: String,
    tier: String,
    #[serde(default)]
    context: Option<String>,
    #[serde(default)]
    role: Option<String>,
    owner_team: String,
    api_stability: String,
    publish_policy: String,
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
    let (compile, data, metadata) = build_graphs(&root, &mut errors);
    check_boundaries(&compile, &root, &mut errors);
    check_crate_catalog(&root, &metadata, &mut errors);
    if !errors.is_empty() {
        for error in errors {
            eprintln!("error: {error}");
        }
        std::process::exit(1);
    }
    if write {
        write_graphs(&root, &compile, &data).unwrap_or_else(|error| {
            eprintln!("error: cannot write architecture graphs: {error}");
            std::process::exit(1)
        });
    }
    println!(
        "Architecture validation successful: {} compile-time edges, {} data-access edges.",
        compile.edges.len(),
        data.edges.len()
    );
}

fn usage() -> ! {
    eprintln!("usage: architecture-validator validate [--write|--check] [--root <path>]");
    std::process::exit(2)
}

fn build_graphs(root: &Path, errors: &mut Vec<String>) -> (Graph, Graph, CargoMetadata) {
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
                empty("data-access"),
                CargoMetadata {
                    packages: Vec::new(),
                    workspace_members: Vec::new(),
                    resolve: None,
                },
            );
        }
        Err(error) => {
            errors.push(format!("cannot execute cargo metadata: {error}"));
            return (
                empty("compile-time"),
                empty("data-access"),
                CargoMetadata {
                    packages: Vec::new(),
                    workspace_members: Vec::new(),
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
                empty("data-access"),
                CargoMetadata {
                    packages: Vec::new(),
                    workspace_members: Vec::new(),
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
    let ownership = read_yaml::<OwnershipCatalog>(root, "catalog/data-ownership.yaml", errors);
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
    dedup_edges(&mut data);
    (compile, data, metadata)
}

/// YAML 1.2 booleans only and `<<` as an ordinary key, preserving catalog parsing behavior.
fn yaml_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
    }
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
    match serde_saphyr::from_str_with_options(&text, yaml_options()) {
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
    let catalog: CrateCatalog = match serde_saphyr::from_str_with_options(&text, yaml_options()) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("catalog/crates.yaml: YAML error: {error}"));
            return;
        }
    };
    let records = catalog.crates;
    let mut ids = BTreeSet::new();
    for record in &records {
        if !ids.insert(record.crate_id.clone()) {
            errors.push(format!(
                "catalog/crates.yaml.{}: duplicate crate_id",
                record.crate_id
            ));
        }
        if record.owner_team.trim().is_empty() || record.api_stability.trim().is_empty() {
            errors.push(format!(
                "catalog/crates.yaml.{}: owner and stability are required",
                record.crate_id
            ));
        }
        if record.publish_policy != "never" {
            errors.push(format!(
                "catalog/crates.yaml.{}.publish_policy: runtime crates must remain private",
                record.crate_id
            ));
        }
        const VALID_TIERS: &[&str] = &[
            "kernel",
            "platform",
            "context",
            "edge",
            "composition",
            "tooling",
        ];
        if !VALID_TIERS.contains(&record.tier.as_str()) {
            errors.push(format!(
                "catalog/crates.yaml.{}.tier: unknown tier '{}'",
                record.crate_id, record.tier
            ));
        }
        let expected = expected_tier(&record.path, &record.package);
        let matches = match &expected {
            Some((exp_tier, exp_context, exp_role)) => {
                &record.tier == exp_tier
                    && &record.context == exp_context
                    && &record.role == exp_role
            }
            None => false,
        };
        if !matches {
            let expected_str = match expected {
                Some((tier, context, role)) => {
                    format_tier(&tier, context.as_deref(), role.as_deref())
                }
                None => "the path is outside the tier directories".to_string(),
            };
            errors.push(format!(
                "catalog/crates.yaml.{}: path '{}' requires tier {expected_str}",
                record.crate_id, record.path
            ));
        }
        if !metadata
            .packages
            .iter()
            .any(|package| package.name == record.package)
        {
            errors.push(format!(
                "catalog/crates.yaml.{}.package: '{}' is not in cargo metadata",
                record.crate_id, record.package
            ));
        }
        if !root.join(&record.path).join("Cargo.toml").is_file() {
            errors.push(format!(
                "catalog/crates.yaml.{}.path: '{}' does not contain Cargo.toml",
                record.crate_id, record.path
            ));
        }
    }
    for member_id in &metadata.workspace_members {
        let name = metadata
            .packages
            .iter()
            .find(|p| &p.id == member_id || &p.name == member_id)
            .map(|p| p.name.as_str())
            .unwrap_or(member_id.as_str());
        if !records.iter().any(|r| r.package == name) {
            errors.push(format!(
                "catalog/crates.yaml: workspace crate '{name}' has no record"
            ));
        }
    }
    check_tiers(
        &records,
        &metadata.packages,
        &metadata.workspace_members,
        errors,
    );
}

const ASYNC_RUNTIME: &[&str] = &[
    "tokio",
    "tokio-util",
    "tokio-stream",
    "futures",
    "futures-util",
    "async-std",
    "mio",
    "socket2",
];

const SQL: &[&str] = &[
    "sqlx",
    "postgres",
    "tokio-postgres",
    "redis",
    "deadpool-postgres",
];

const NETWORK: &[&str] = &[
    "axum",
    "hyper",
    "hyper-util",
    "reqwest",
    "tonic",
    "tower",
    "tower-http",
    "tokio-rustls",
    "rustls",
    "hickory-resolver",
    "hickory-proto",
];

fn expected_tier(path: &str, package: &str) -> Option<(String, Option<String>, Option<String>)> {
    let normalized = path.replace('\\', "/");
    if normalized == "." {
        return Some(("composition".to_string(), None, None));
    }
    let parts: Vec<&str> = normalized.split('/').collect();
    if parts.len() == 3 && parts[0] == "crates" && !parts[2].is_empty() {
        match parts[1] {
            "kernel" => return Some(("kernel".to_string(), None, None)),
            "platform" => return Some(("platform".to_string(), None, None)),
            "edges" => return Some(("edge".to_string(), None, None)),
            _ => return None,
        }
    }
    if parts.len() == 2 && parts[0] == "tools" && !parts[1].is_empty() {
        return Some(("tooling".to_string(), None, None));
    }
    if parts.len() == 4
        && parts[0] == "crates"
        && parts[1] == "contexts"
        && !parts[2].is_empty()
        && !parts[3].is_empty()
    {
        let context = parts[2].to_string();
        let name = if !package.is_empty() {
            package
        } else {
            parts[3]
        };
        let role = if name.ends_with("-application") || name == "northstar-protocol-runtime" {
            "application"
        } else if name.ends_with("-postgres") || name.ends_with("-xmpp") || name.ends_with("-http")
        {
            "adapter"
        } else {
            "core"
        };
        return Some(("context".to_string(), Some(context), Some(role.to_string())));
    }
    None
}

fn tier_text(record: &CrateRecord) -> String {
    format_tier(
        &record.tier,
        record.context.as_deref(),
        record.role.as_deref(),
    )
}

fn format_tier(tier: &str, context: Option<&str>, role: Option<&str>) -> String {
    if tier == "context" {
        format!(
            "context {} {}",
            context.unwrap_or_default(),
            role.unwrap_or_default()
        )
    } else {
        tier.to_string()
    }
}

fn internal_allowed(from: &CrateRecord, to: &CrateRecord) -> bool {
    if to.tier == "tooling" {
        return from.tier == "tooling";
    }
    match from.tier.as_str() {
        "kernel" => to.tier == "kernel",
        "platform" => to.tier == "kernel" || to.tier == "platform",
        "context" => match from.role.as_deref() {
            Some("core") => {
                to.tier == "kernel" || (to.tier == "context" && to.role.as_deref() == Some("core"))
            }
            Some("application") => {
                to.tier == "kernel"
                    || to.tier == "platform"
                    || (to.tier == "context" && to.role.as_deref() == Some("core"))
                    || (to.tier == "context"
                        && to.role.as_deref() == Some("application")
                        && from.context.is_some()
                        && from.context == to.context)
            }
            Some("adapter") => {
                to.tier == "kernel"
                    || to.tier == "platform"
                    || (to.tier == "context" && to.role.as_deref() == Some("core"))
                    || (to.tier == "context"
                        && to.role.as_deref() == Some("application")
                        && from.context.is_some()
                        && from.context == to.context)
                    || (to.tier == "edge" && to.package == "northstar-stream")
            }
            _ => false,
        },
        "edge" => {
            to.tier == "kernel"
                || to.tier == "platform"
                || (to.tier == "context"
                    && (to.role.as_deref() == Some("core")
                        || to.role.as_deref() == Some("application")))
                || (to.tier == "edge"
                    && to.package == "northstar-stream"
                    && from.package != to.package)
        }
        "composition" => true,
        "tooling" => true,
        _ => false,
    }
}

fn external_allowed(from: &CrateRecord, to: &str) -> bool {
    let in_async = ASYNC_RUNTIME.contains(&to);
    let in_sql = SQL.contains(&to);
    let in_network = NETWORK.contains(&to);

    match from.tier.as_str() {
        "kernel" => !in_async && !in_sql && !in_network,
        "platform" => true,
        "context" => match from.role.as_deref() {
            Some("core") => !in_async && !in_sql && !in_network,
            Some("application") => !in_sql && !in_network,
            Some("adapter") => true,
            _ => false,
        },
        "edge" => !in_sql,
        "composition" => true,
        "tooling" => true,
        _ => false,
    }
}

fn check_tiers(
    records: &[CrateRecord],
    packages: &[Package],
    workspace_members: &[String],
    errors: &mut Vec<String>,
) {
    for package in packages {
        if !workspace_members.is_empty()
            && !workspace_members.contains(&package.id)
            && !workspace_members.contains(&package.name)
        {
            continue;
        }
        let Some(from) = records.iter().find(|r| r.package == package.name) else {
            continue;
        };
        for dep in &package.dependencies {
            let is_checked = matches!(dep.kind.as_deref(), None | Some("build"));
            if !is_checked {
                continue;
            }
            if let Some(to) = records.iter().find(|r| r.package == dep.name) {
                if !internal_allowed(from, to) {
                    errors.push(format!(
                        "crate graph: {} ({}) must not depend on {} ({})",
                        from.package,
                        tier_text(from),
                        to.package,
                        tier_text(to)
                    ));
                }
            } else if !external_allowed(from, &dep.name) {
                errors.push(format!(
                    "crate graph: {} ({}) must not depend on external crate {}",
                    from.package,
                    tier_text(from),
                    dep.name
                ));
            }
        }
    }
}

fn write_graphs(root: &Path, compile: &Graph, data: &Graph) -> std::io::Result<()> {
    let dir = root.join("docs/architecture/generated");
    fs::create_dir_all(&dir)?;
    let graphs = [compile, data];
    for graph in graphs {
        let stem = graph.name.as_str();
        fs::write(
            dir.join(format!("{stem}.json")),
            serde_json::to_string_pretty(graph).unwrap() + "\n",
        )?;
        fs::write(dir.join(format!("{stem}.dot")), dot(graph))?;
        fs::write(dir.join(format!("{stem}.mmd")), mermaid(graph))?;
    }
    let all = serde_json::json!({ "compile_time": compile, "data_access": data });
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

    fn record(package: &str, path: &str) -> CrateRecord {
        let (tier, context, role) = expected_tier(path, package)
            .unwrap_or_else(|| panic!("invalid path for test record: {path}"));
        let stability = if tier == "kernel"
            || (tier == "context"
                && (role.as_deref() == Some("core") || role.as_deref() == Some("application")))
        {
            "internal-stable"
        } else {
            "internal"
        };
        CrateRecord {
            crate_id: package.to_string(),
            package: package.to_string(),
            path: path.to_string(),
            tier,
            context,
            role,
            owner_team: "platform".to_string(),
            api_stability: stability.to_string(),
            publish_policy: "never".to_string(),
        }
    }

    #[test]
    fn kernel_depending_on_context_core_is_reported() {
        let kernel = record("northstar-xep-0045", "crates/kernel/northstar-xep-0045");
        let context_core = record(
            "northstar-message-core",
            "crates/contexts/message/northstar-message-core",
        );
        let records = vec![kernel.clone(), context_core.clone()];
        let packages = vec![
            Package {
                id: kernel.package.clone(),
                name: kernel.package.clone(),
                dependencies: vec![PackageDependency {
                    name: context_core.package.clone(),
                    kind: None,
                }],
            },
            Package {
                id: context_core.package.clone(),
                name: context_core.package.clone(),
                dependencies: vec![],
            },
        ];
        let workspace_members = vec![kernel.package.clone(), context_core.package.clone()];
        let mut errors = Vec::new();
        check_tiers(&records, &packages, &workspace_members, &mut errors);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0],
            "crate graph: northstar-xep-0045 (kernel) must not depend on northstar-message-core (context message core)"
        );
    }

    #[test]
    fn context_core_depending_on_another_context_core_is_accepted() {
        let core1 = record(
            "northstar-message-core",
            "crates/contexts/message/northstar-message-core",
        );
        let core2 = record(
            "northstar-auth-core",
            "crates/contexts/auth/northstar-auth-core",
        );
        let records = vec![core1.clone(), core2.clone()];
        let packages = vec![
            Package {
                id: core1.package.clone(),
                name: core1.package.clone(),
                dependencies: vec![PackageDependency {
                    name: core2.package.clone(),
                    kind: None,
                }],
            },
            Package {
                id: core2.package.clone(),
                name: core2.package.clone(),
                dependencies: vec![],
            },
        ];
        let workspace_members = vec![core1.package.clone(), core2.package.clone()];
        let mut errors = Vec::new();
        check_tiers(&records, &packages, &workspace_members, &mut errors);
        assert!(errors.is_empty());
    }

    #[test]
    fn context_application_depending_on_sqlx_is_reported_and_on_tokio_is_accepted() {
        let app = record(
            "northstar-message-application",
            "crates/contexts/message/northstar-message-application",
        );
        let records = vec![app.clone()];
        let workspace_members = vec![app.package.clone()];

        let packages_sqlx = vec![Package {
            id: app.package.clone(),
            name: app.package.clone(),
            dependencies: vec![PackageDependency {
                name: "sqlx".to_string(),
                kind: None,
            }],
        }];
        let mut errors_sqlx = Vec::new();
        check_tiers(
            &records,
            &packages_sqlx,
            &workspace_members,
            &mut errors_sqlx,
        );
        assert_eq!(errors_sqlx.len(), 1);
        assert_eq!(
            errors_sqlx[0],
            "crate graph: northstar-message-application (context message application) must not depend on external crate sqlx"
        );

        let packages_tokio = vec![Package {
            id: app.package.clone(),
            name: app.package.clone(),
            dependencies: vec![PackageDependency {
                name: "tokio".to_string(),
                kind: None,
            }],
        }];
        let mut errors_tokio = Vec::new();
        check_tiers(
            &records,
            &packages_tokio,
            &workspace_members,
            &mut errors_tokio,
        );
        assert!(errors_tokio.is_empty());
    }

    #[test]
    fn context_core_depending_on_tokio_is_reported() {
        let core = record(
            "northstar-message-core",
            "crates/contexts/message/northstar-message-core",
        );
        let records = vec![core.clone()];
        let packages = vec![Package {
            id: core.package.clone(),
            name: core.package.clone(),
            dependencies: vec![PackageDependency {
                name: "tokio".to_string(),
                kind: None,
            }],
        }];
        let workspace_members = vec![core.package.clone()];
        let mut errors = Vec::new();
        check_tiers(&records, &packages, &workspace_members, &mut errors);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0],
            "crate graph: northstar-message-core (context message core) must not depend on external crate tokio"
        );
    }

    #[test]
    fn composition_with_normal_dependency_on_tooling_is_reported_and_dev_dependency_is_accepted() {
        let comp = record("rust-xmpp-server", ".");
        let tool = record("architecture-validator", "tools/architecture-validator");
        let records = vec![comp.clone(), tool.clone()];
        let workspace_members = vec![comp.package.clone(), tool.package.clone()];

        let packages_normal = vec![
            Package {
                id: comp.package.clone(),
                name: comp.package.clone(),
                dependencies: vec![PackageDependency {
                    name: tool.package.clone(),
                    kind: None,
                }],
            },
            Package {
                id: tool.package.clone(),
                name: tool.package.clone(),
                dependencies: vec![],
            },
        ];
        let mut errors_normal = Vec::new();
        check_tiers(
            &records,
            &packages_normal,
            &workspace_members,
            &mut errors_normal,
        );
        assert_eq!(errors_normal.len(), 1);
        assert_eq!(
            errors_normal[0],
            "crate graph: rust-xmpp-server (composition) must not depend on architecture-validator (tooling)"
        );

        let packages_dev = vec![
            Package {
                id: comp.package.clone(),
                name: comp.package.clone(),
                dependencies: vec![PackageDependency {
                    name: tool.package.clone(),
                    kind: Some("dev".to_string()),
                }],
            },
            Package {
                id: tool.package.clone(),
                name: tool.package.clone(),
                dependencies: vec![],
            },
        ];
        let mut errors_dev = Vec::new();
        check_tiers(&records, &packages_dev, &workspace_members, &mut errors_dev);
        assert!(errors_dev.is_empty());
    }

    #[test]
    fn context_application_depending_on_another_context_application_is_reported() {
        let app1 = record(
            "northstar-message-application",
            "crates/contexts/message/northstar-message-application",
        );
        let app2 = record(
            "northstar-session-application",
            "crates/contexts/session/northstar-session-application",
        );
        let records = vec![app1.clone(), app2.clone()];
        let packages = vec![
            Package {
                id: app1.package.clone(),
                name: app1.package.clone(),
                dependencies: vec![PackageDependency {
                    name: app2.package.clone(),
                    kind: None,
                }],
            },
            Package {
                id: app2.package.clone(),
                name: app2.package.clone(),
                dependencies: vec![],
            },
        ];
        let workspace_members = vec![app1.package.clone(), app2.package.clone()];
        let mut errors = Vec::new();
        check_tiers(&records, &packages, &workspace_members, &mut errors);
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0],
            "crate graph: northstar-message-application (context message application) must not depend on northstar-session-application (context session application)"
        );
    }

    #[test]
    fn expected_tier_mapping() {
        assert_eq!(
            expected_tier(
                "crates/contexts/session/northstar-protocol-runtime",
                "northstar-protocol-runtime"
            ),
            Some((
                "context".to_string(),
                Some("session".to_string()),
                Some("application".to_string())
            ))
        );
        assert_eq!(
            expected_tier("crates/kernel/northstar-xep-0045", "northstar-xep-0045"),
            Some(("kernel".to_string(), None, None))
        );
        assert_eq!(
            expected_tier("tools/northstar-test-harness", "northstar-test-harness"),
            Some(("tooling".to_string(), None, None))
        );
        assert_eq!(
            expected_tier(".", "rust-xmpp-server"),
            Some(("composition".to_string(), None, None))
        );
        assert_eq!(
            expected_tier("crates/northstar-xep-0045", "northstar-xep-0045"),
            None
        );
    }
}
