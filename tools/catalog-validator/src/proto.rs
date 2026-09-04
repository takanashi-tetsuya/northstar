use std::{fs, path::Path};

pub fn validate(root: &Path, services: &[crate::model::Service], errors: &mut Vec<String>) {
    for service in services.iter().filter(|service| {
        ["integrated", "production"].contains(&service.implementation_status.as_str())
    }) {
        let Some(id) = service
            .service_id
            .strip_prefix("xep-")
            .or(Some(service.service_id.as_str()))
        else {
            continue;
        };
        let candidates = [
            root.join("contracts/proto/northstar")
                .join(id.replace('-', "_"))
                .join("v1"),
            root.join("contracts/proto/northstar")
                .join(&service.service_id)
                .join("v1"),
        ];
        if !candidates.iter().any(|path| fs::read_dir(path).is_ok()) {
            errors.push(format!("catalog.services[{}].evidence: integrated service has no protobuf contract directory", service.service_id));
        }
    }
}
