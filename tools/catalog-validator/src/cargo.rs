use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
}
#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    manifest_path: String,
    targets: Vec<Target>,
}
#[derive(Debug, Deserialize)]
struct Target {
    kind: Vec<String>,
    name: String,
}

pub fn validate(root: &Path, services: &[crate::model::Service], errors: &mut Vec<String>) {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root)
        .output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            errors.push(format!(
                "Cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
            return;
        }
        Err(error) => {
            errors.push(format!("cannot execute cargo metadata: {error}"));
            return;
        }
    };
    let metadata: Metadata = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("cargo metadata returned invalid JSON: {error}"));
            return;
        }
    };
    for service in services
        .iter()
        .filter(|service| service.implementation_status != "planned")
    {
        let Some(package_name) = service.cargo_package.as_deref() else {
            errors.push(format!(
                "catalog.services[{}].cargo_package: required for non-planned service",
                service.service_id
            ));
            continue;
        };
        let Some(package) = metadata
            .packages
            .iter()
            .find(|package| package.name == package_name)
        else {
            errors.push(format!(
                "catalog.services[{}].cargo_package: package '{}' is not present in cargo metadata",
                service.service_id, package_name
            ));
            continue;
        };
        if service.runtime_binary.as_deref() == Some("none") {
            if service.implementation_status != "prototype" {
                errors.push(format!("catalog.services[{}].runtime_binary: {} service must declare target/release/<binary>", service.service_id, service.implementation_status));
            }
            if let Some(code_path) = service.code_path.as_deref() {
                if !root.join(code_path).is_dir() {
                    errors.push(format!(
                        "catalog.services[{}].code_path: '{}' does not exist",
                        service.service_id, code_path
                    ));
                }
            }
            continue;
        }
        let Some(binary_name) = service
            .runtime_binary
            .as_deref()
            .and_then(|path| path.strip_prefix("target/release/"))
        else {
            errors.push(format!(
                "catalog.services[{}].runtime_binary: expected target/release/<binary>",
                service.service_id
            ));
            continue;
        };
        if !package.targets.iter().any(|target| {
            target.kind.iter().any(|kind| kind == "bin") && target.name == binary_name
        }) {
            errors.push(format!(
                "catalog.services[{}].runtime_binary: binary target '{}' is missing",
                service.service_id, binary_name
            ));
        }
        if let Some(code_path) = service.code_path.as_deref() {
            if !root.join(code_path).is_dir() {
                errors.push(format!(
                    "catalog.services[{}].code_path: '{}' does not exist",
                    service.service_id, code_path
                ));
            }
        }
        if !Path::new(&package.manifest_path).exists() {
            errors.push(format!(
                "catalog.services[{}].cargo_package: manifest '{}' does not exist",
                service.service_id, package.manifest_path
            ));
        }
    }
}
