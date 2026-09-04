use std::{path::Path, process::Command};

pub fn validate(
    root: &Path,
    services: &[crate::model::Service],
    strict: bool,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let valid = [
        "planned",
        "scaffold",
        "prototype",
        "executable-prototype",
        "integrated",
        "production-candidate",
        "production",
    ];
    let current_commit = git_output(root, &["rev-parse", "HEAD"]);
    for service in services {
        if !valid.contains(&service.implementation_status.as_str()) {
            errors.push(format!(
                "catalog.services[{}].implementation_status: unsupported maturity state",
                service.service_id
            ));
        }
        if let Some(evidence) = &service.evidence {
            if !valid.contains(&evidence.status.as_str()) {
                errors.push(format!(
                    "catalog.services[{}].evidence.status: unsupported maturity state '{}'",
                    service.service_id, evidence.status
                ));
            }
            if service.implementation_status == "planned" && evidence.status != "planned" {
                errors.push(format!("catalog.services[{}].evidence.status: planned service evidence must be planned", service.service_id));
            }
            if service.implementation_status != "planned"
                && evidence.status != service.implementation_status
            {
                errors.push(format!("catalog.services[{}].evidence.status: '{}' does not match implementation_status '{}'", service.service_id, evidence.status, service.implementation_status));
            }

            let requires_commit = ["integrated", "production-candidate", "production"]
                .contains(&service.implementation_status.as_str());
            if requires_commit {
                let Some(commit) = evidence.last_verified_commit.as_deref() else {
                    continue;
                };
                if !is_commit(root, commit) {
                    errors.push(format!(
                        "catalog.services[{}].evidence.last_verified_commit: '{}' is not a commit in this repository",
                        service.service_id, commit
                    ));
                } else if strict {
                    let Some(head) = current_commit.as_deref() else {
                        errors.push(format!(
                            "catalog.services[{}].evidence: strict mode requires a git worktree with a readable HEAD",
                            service.service_id
                        ));
                        continue;
                    };
                    if !is_ancestor(root, commit, head) {
                        errors.push(format!(
                            "catalog.services[{}].evidence.last_verified_commit: '{}' is not an ancestor of HEAD",
                            service.service_id, commit
                        ));
                    }
                }
            }
        }
    }
    if strict
        && services.iter().any(|service| {
            ["integrated", "production-candidate", "production"]
                .contains(&service.implementation_status.as_str())
        })
        && current_commit.is_none()
    {
        warnings.push("strict mode: git ancestry could not be inspected".to_owned());
    }
}

fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn is_commit(root: &Path, commit: &str) -> bool {
    Command::new("git")
        .args(["cat-file", "-e", &format!("{commit}^{commit}")])
        .current_dir(root)
        .status()
        .is_ok_and(|status| status.success())
}

fn is_ancestor(root: &Path, candidate: &str, head: &str) -> bool {
    Command::new("git")
        .args(["merge-base", "--is-ancestor", candidate, head])
        .current_dir(root)
        .status()
        .is_ok_and(|status| status.success())
}
