use std::{fs, path::Path};

pub fn validate(root: &Path, services: &[crate::model::Service], errors: &mut Vec<String>) {
    for service in services.iter().filter(|service| {
        ["integrated", "production"].contains(&service.implementation_status.as_str())
    }) {
        if service.database.as_deref() == Some("none") {
            continue;
        }
        let Some(code_path) = service.code_path.as_deref() else {
            continue;
        };
        let path = root.join(code_path).join("migrations");
        let has_sql = fs::read_dir(&path)
            .map(|entries| {
                entries
                    .flatten()
                    .any(|entry| entry.path().extension().is_some_and(|ext| ext == "sql"))
            })
            .unwrap_or(false);
        if !has_sql {
            errors.push(format!(
                "catalog.services[{}].database: integrated service has no SQL migrations under {}",
                service.service_id,
                path.display()
            ));
        }
    }
}
