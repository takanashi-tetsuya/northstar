use crate::{
    cargo, deploy, evidence, migrations,
    model::{OwnershipCatalog, RouteCatalog, ServiceCatalog, XepOwnershipCatalog},
    proto,
};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

#[derive(Debug, Default)]
pub struct Report {
    pub services: usize,
    pub routes: usize,
    pub tables: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

const MODES: &[&str] = &[
    "remote-authority",
    "remote-worker",
    "transport",
    "control-plane",
    "bff",
    "local-sdk",
    "signed-policy-snapshot",
    "pass-through-codec",
];

fn read_yaml<T: serde::de::DeserializeOwned>(
    root: &Path,
    relative: &str,
    errors: &mut Vec<String>,
) -> Option<T> {
    let path = root.join(relative);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("{relative}: cannot read file: {error}"));
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

pub fn run(root: &Path, strict: bool) -> Report {
    let mut report = Report::default();
    validate_schema_assets(root, &mut report.errors);
    validate_data_policy_assets(root, &mut report.errors);
    let Some(services) =
        read_yaml::<ServiceCatalog>(root, "catalog/services.yaml", &mut report.errors)
    else {
        return report;
    };
    let Some(routes) = read_yaml::<RouteCatalog>(root, "catalog/routes.yaml", &mut report.errors)
    else {
        return report;
    };
    let Some(ownership) =
        read_yaml::<OwnershipCatalog>(root, "catalog/data-ownership.yaml", &mut report.errors)
    else {
        return report;
    };
    let xep =
        read_yaml::<XepOwnershipCatalog>(root, "catalog/xep-ownership.yaml", &mut report.errors);

    report.services = services.services.len();
    report.routes = routes.routes.len();
    let mut service_ids = HashSet::new();
    let mut service_databases = HashMap::new();
    for (index, service) in services.services.iter().enumerate() {
        let path = format!("catalog.services[{index}] ({})", service.service_id);
        if !service_ids.insert(&service.service_id) {
            report
                .errors
                .push(format!("{path}.service_id: duplicate service id"));
        }
        if service.service_id.trim().is_empty() {
            report
                .errors
                .push(format!("{path}.service_id: must not be empty"));
        }
        if !MODES.contains(&service.execution_class.as_str()) {
            report.errors.push(format!(
                "{path}.execution_class: unsupported mode '{}'; expected one of {}",
                service.execution_class,
                MODES.join(", ")
            ));
        }
        for (name, value) in [
            ("owner_team", service.owner_team.as_deref()),
            ("criticality", service.criticality.as_deref()),
            ("region_mode", service.region_mode.as_deref()),
            ("home_key", service.home_key.as_deref()),
            ("runtime_binary", service.runtime_binary.as_deref()),
            ("image", service.image.as_deref()),
            ("database", service.database.as_deref()),
            ("deployment_unit", service.deployment_unit.as_deref()),
            ("semantic_owner", service.semantic_owner.as_deref()),
        ] {
            if value.is_none_or(str::is_empty) {
                report
                    .errors
                    .push(format!("{path}.{name}: required catalog field is missing"));
            }
        }
        if service.data_classes.as_ref().is_none_or(Vec::is_empty) {
            report.errors.push(format!(
                "{path}.data_classes: at least one class is required"
            ));
        }
        let database = service.database.as_deref().unwrap_or("none");
        service_databases.insert(service.service_id.as_str(), database);
        if ["local-sdk", "pass-through-codec"].contains(&service.execution_class.as_str())
            && database != "none"
        {
            report.errors.push(format!(
                "{path}.database: {} services cannot own database '{database}'",
                service.execution_class
            ));
        }
        if [
            "remote-authority",
            "remote-worker",
            "signed-policy-snapshot",
        ]
        .contains(&service.execution_class.as_str())
            && database == "none"
        {
            report.errors.push(format!(
                "{path}.database: {} service must declare a logical database",
                service.execution_class
            ));
        }
        if let Some(evidence) = &service.evidence {
            if evidence.status.trim().is_empty() {
                report
                    .errors
                    .push(format!("{path}.evidence.status: must not be empty"));
            }
            if evidence.required_checks.is_empty() {
                report.errors.push(format!(
                    "{path}.evidence.required_checks: must contain at least one check"
                ));
            }
            if ["integrated", "production-candidate", "production"]
                .contains(&service.implementation_status.as_str())
                && evidence
                    .last_verified_commit
                    .as_deref()
                    .is_none_or(str::is_empty)
            {
                report.errors.push(format!(
                    "{path}.evidence.last_verified_commit: required for {} status",
                    service.implementation_status
                ));
            }
        } else {
            report
                .errors
                .push(format!("{path}.evidence: required for every service"));
        }
        if service.implementation_status != "planned" {
            if service.code_path.as_deref().is_none_or(str::is_empty) {
                report.errors.push(format!(
                    "{path}.code_path: required for non-planned service"
                ));
            }
            if service.cargo_package.as_deref().is_none_or(str::is_empty) {
                report.errors.push(format!(
                    "{path}.cargo_package: required for non-planned service"
                ));
            }
        }
    }

    let mut route_keys = HashSet::new();
    for (index, route) in routes.routes.iter().enumerate() {
        let path = format!("catalog.routes[{index}]");
        let key = format!(
            "{}::{}::{}::{}",
            route.namespace, route.element, route.stanza, route.phase
        );
        if !route_keys.insert(key.clone()) {
            report
                .errors
                .push(format!("{path}: duplicate route key {key}"));
        }
        if !service_ids.contains(&route.owner) {
            report
                .errors
                .push(format!("{path}.owner: unknown service '{}'", route.owner));
        }
        for (name, present) in [
            ("stanza_kind", route.stanza_kind.is_some()),
            ("semantic_owner", route.semantic_owner.is_some()),
            ("deployment_unit", route.deployment_unit.is_some()),
            ("execution_mode", route.execution_mode.is_some()),
            ("required_principal", route.required_principal.is_some()),
            ("required_scope", route.required_scope.is_some()),
            ("deadline_ms", route.deadline_ms.is_some()),
            ("max_payload_bytes", route.max_payload_bytes.is_some()),
            ("retry_policy", route.retry_policy.is_some()),
            ("idempotency", route.idempotency.is_some()),
            ("ordering_key", route.ordering_key.is_some()),
            ("fanout", route.fanout.is_some()),
            ("failure_mode", route.failure_mode.is_some()),
            ("observability", route.observability.is_some()),
        ] {
            if !present {
                report
                    .errors
                    .push(format!("{path}.{name}: required route field is missing"));
            }
        }
        if route
            .execution_mode
            .as_deref()
            .is_some_and(|mode| !MODES.contains(&mode))
        {
            report
                .errors
                .push(format!("{path}.execution_mode: unsupported mode"));
        }
        if route
            .failure_mode
            .as_deref()
            .is_some_and(|mode| !["fail-closed", "fail-open"].contains(&mode))
        {
            report.errors.push(format!(
                "{path}.failure_mode: must be fail-closed or fail-open"
            ));
        }
        if route.observability.as_ref().is_some_and(|obs| {
            obs.trace_category.trim().is_empty() || obs.required_labels.is_empty()
        }) {
            report.errors.push(format!(
                "{path}.observability: trace_category and required_labels are required"
            ));
        }
    }

    let mut table_names = HashSet::new();
    for (owner, group) in &ownership.ownership {
        if !service_ids.contains(owner) {
            report.errors.push(format!(
                "catalog.data-ownership.ownership.{owner}: unknown service owner"
            ));
        }
        for (name, value) in [
            ("logical_database", group.logical_database.as_deref()),
            ("owner", group.owner.as_deref()),
            ("deployment_unit", group.deployment_unit.as_deref()),
            ("semantic_owner", group.semantic_owner.as_deref()),
            ("cluster_class", group.cluster_class.as_deref()),
            ("runtime_role", group.runtime_role.as_deref()),
            ("migrator_role", group.migrator_role.as_deref()),
            ("owner_role", group.owner_role.as_deref()),
            ("ops_role", group.ops_role.as_deref()),
            ("backup_role", group.backup_role.as_deref()),
        ] {
            if value.is_none_or(str::is_empty) {
                report.errors.push(format!(
                    "catalog.data-ownership.ownership.{owner}.{name}: required field is missing"
                ));
            }
        }
        if group.logical_database.as_deref() != Some(group.database.as_str()) {
            report.errors.push(format!("catalog.data-ownership.ownership.{owner}.logical_database: must equal database for the logical ownership record"));
        }
        if let Some(service_database) = service_databases.get(owner.as_str()) {
            if *service_database != "none" && *service_database != group.database {
                report.errors.push(format!("catalog.data-ownership.ownership.{owner}.database: '{}' disagrees with service catalog database '{}'", group.database, service_database));
            }
        }
        for (index, table) in group.tables.iter().enumerate() {
            let Some(name) = table.name() else {
                report.errors.push(format!(
                    "catalog.data-ownership.ownership.{owner}.tables[{index}]: missing table name"
                ));
                continue;
            };
            if !table_names.insert(name.to_owned()) {
                report.errors.push(format!("catalog.data-ownership.ownership.{owner}.tables[{index}]: table '{name}' has multiple owners"));
            }
            if let crate::model::TableRef::Detailed(table) = table {
                for (field, present) in [
                    (
                        "data_class",
                        table.data_class.as_ref().is_some_and(|v| !v.is_empty()),
                    ),
                    (
                        "retention_class",
                        table
                            .retention_class
                            .as_ref()
                            .is_some_and(|v| !v.is_empty()),
                    ),
                    ("legal_hold", table.legal_hold.is_some()),
                    (
                        "delete_owner",
                        table.delete_owner.as_ref().is_some_and(|v| !v.is_empty()),
                    ),
                    (
                        "export_owner",
                        table.export_owner.as_ref().is_some_and(|v| !v.is_empty()),
                    ),
                    (
                        "residency",
                        table.residency.as_ref().is_some_and(|v| !v.is_empty()),
                    ),
                    (
                        "primary_key",
                        table.primary_key.as_ref().is_some_and(|v| !v.is_empty()),
                    ),
                    (
                        "home_key",
                        table.home_key.as_ref().is_some_and(|v| !v.is_empty()),
                    ),
                    (
                        "partitioning",
                        table.partitioning.as_ref().is_some_and(|v| !v.is_empty()),
                    ),
                    ("pii", table.pii.is_some()),
                    ("content", table.content.is_some()),
                    ("secret", table.secret.is_some()),
                    (
                        "encryption_key_class",
                        table
                            .encryption_key_class
                            .as_ref()
                            .is_some_and(|v| !v.is_empty()),
                    ),
                    ("backup_rpo_hours", table.backup_rpo_hours.is_some()),
                    ("backup_rto_minutes", table.backup_rto_minutes.is_some()),
                    ("restore_order", table.restore_order.is_some()),
                ] {
                    if !present {
                        report.errors.push(format!("catalog.data-ownership.ownership.{owner}.tables[{index}].{field}: required field is missing"));
                    }
                }
            } else {
                report.errors.push(format!("catalog.data-ownership.ownership.{owner}.tables[{index}]: table metadata object is required"));
            }
        }
    }
    report.tables = table_names.len();

    if let Some(xep) = xep {
        for (name, ownership) in xep.xep_ownership {
            if ownership.semantic_owner.trim().is_empty()
                || ownership.deployment_unit.trim().is_empty()
                || !MODES.contains(&ownership.execution_mode.as_str())
            {
                report.errors.push(format!("catalog/xep-ownership.yaml.{name}: semantic_owner, deployment_unit and valid execution_mode are required"));
            }
        }
    }

    cargo::validate(root, &services.services, &mut report.errors);
    proto::validate(root, &services.services, &mut report.errors);
    migrations::validate(root, &services.services, &mut report.errors);
    deploy::validate(root, &services.services, &mut report.errors);
    evidence::validate(
        root,
        &services.services,
        strict,
        &mut report.errors,
        &mut report.warnings,
    );
    report
}

fn validate_schema_assets(root: &Path, errors: &mut Vec<String>) {
    for relative in [
        "catalog/schema/services.schema.json",
        "catalog/schema/routes.schema.json",
        "catalog/schema/data-ownership.schema.json",
        "catalog/schema/evidence.schema.json",
        "catalog/schema/crates.schema.json",
    ] {
        let path = root.join(relative);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                errors.push(format!("{relative}: cannot read schema: {error}"));
                continue;
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{relative}: invalid JSON schema: {error}"));
                continue;
            }
        };
        for key in ["$schema", "$id", "type"] {
            if value.get(key).and_then(serde_json::Value::as_str).is_none() {
                errors.push(format!("{relative}.{key}: schema metadata is required"));
            }
        }
    }
}

fn validate_data_policy_assets(root: &Path, errors: &mut Vec<String>) {
    for (relative, collection) in [
        ("catalog/database-clusters.yaml", "clusters"),
        ("catalog/data-classes.yaml", "data_classes"),
        ("catalog/retention-classes.yaml", "retention_classes"),
    ] {
        let path = root.join(relative);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                errors.push(format!("{relative}: cannot read policy catalog: {error}"));
                continue;
            }
        };
        let value: serde_yaml::Value = match serde_yaml::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                errors.push(format!("{relative}: YAML error: {error}"));
                continue;
            }
        };
        if value
            .get("version")
            .and_then(serde_yaml::Value::as_str)
            .is_none()
        {
            errors.push(format!("{relative}.version: required"));
        }
        if value
            .get(collection)
            .and_then(serde_yaml::Value::as_sequence)
            .is_none_or(Vec::is_empty)
        {
            errors.push(format!(
                "{relative}.{collection}: at least one entry is required"
            ));
        }
    }
}
