use std::{fs, path::Path};

pub fn validate(root: &Path, services: &[crate::model::Service], errors: &mut Vec<String>) {
    let has_k8s = root.join("deploy/kubernetes").is_dir();
    let has_compose = root
        .join("deploy/compose/docker-compose.microservices.yml")
        .is_file();
    for service in services
        .iter()
        .filter(|service| service.implementation_status == "production")
    {
        if !has_k8s && !has_compose {
            errors.push(format!("catalog.services[{}].deployment_unit: production service has no deployment manifest", service.service_id));
        }
        if service
            .image
            .as_deref()
            .is_none_or(|image| image == "none" || image.is_empty())
        {
            errors.push(format!(
                "catalog.services[{}].image: production service must declare an image",
                service.service_id
            ));
        }
    }
    let _ = fs::metadata(root);
}
