#![allow(dead_code)]

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct ServiceCatalog {
    pub version: String,
    pub services: Vec<Service>,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub service_id: String,
    pub implementation_status: String,
    pub name: String,
    pub code_path: Option<String>,
    pub cargo_package: Option<String>,
    pub execution_class: String,
    pub owner_team: Option<String>,
    pub criticality: Option<String>,
    pub data_classes: Option<Vec<String>>,
    pub region_mode: Option<String>,
    pub home_key: Option<String>,
    pub runtime_binary: Option<String>,
    pub image: Option<String>,
    pub database: Option<String>,
    pub deployment_unit: Option<String>,
    pub semantic_owner: Option<String>,
    pub rpc: Option<Contracts>,
    pub events: Option<Contracts>,
    pub evidence: Option<Evidence>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Contracts {
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub consumes: Vec<String>,
    #[serde(default)]
    pub produces: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Evidence {
    pub status: String,
    #[serde(default)]
    pub last_verified_commit: Option<String>,
    #[serde(default)]
    pub required_checks: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RouteCatalog {
    pub version: String,
    pub routes: Vec<Route>,
}

#[derive(Debug, Deserialize)]
pub struct Route {
    pub namespace: String,
    pub element: String,
    pub stanza: String,
    pub stanza_kind: Option<String>,
    pub phase: String,
    pub owner: String,
    pub semantic_owner: Option<String>,
    pub deployment_unit: Option<String>,
    pub execution_mode: Option<String>,
    pub required_principal: Option<String>,
    pub required_scope: Option<String>,
    pub deadline_ms: Option<u64>,
    pub max_payload_bytes: Option<u64>,
    pub retry_policy: Option<String>,
    pub idempotency: Option<bool>,
    pub ordering_key: Option<String>,
    pub fanout: Option<bool>,
    pub failure_mode: Option<String>,
    pub observability: Option<Observability>,
}

#[derive(Debug, Deserialize)]
pub struct Observability {
    pub trace_category: String,
    #[serde(default)]
    pub required_labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OwnershipCatalog {
    pub version: String,
    pub ownership: HashMap<String, OwnerGroup>,
}

#[derive(Debug, Deserialize)]
pub struct OwnerGroup {
    pub database: String,
    pub logical_database: Option<String>,
    pub owner: Option<String>,
    pub deployment_unit: Option<String>,
    pub semantic_owner: Option<String>,
    pub cluster_class: Option<String>,
    pub runtime_role: Option<String>,
    pub migrator_role: Option<String>,
    pub owner_role: Option<String>,
    pub ops_role: Option<String>,
    pub backup_role: Option<String>,
    #[serde(default)]
    pub tables: Vec<TableRef>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TableRef {
    Name(String),
    Detailed(Box<Table>),
}

impl TableRef {
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            Self::Detailed(table) => Some(&table.name),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Table {
    pub name: String,
    pub data_class: Option<String>,
    pub retention_class: Option<String>,
    pub legal_hold: Option<bool>,
    pub delete_owner: Option<String>,
    pub export_owner: Option<String>,
    pub residency: Option<String>,
    pub primary_key: Option<String>,
    pub home_key: Option<String>,
    pub partitioning: Option<String>,
    pub pii: Option<bool>,
    pub content: Option<bool>,
    pub secret: Option<bool>,
    pub encryption_key_class: Option<String>,
    pub backup_rpo_hours: Option<f64>,
    pub backup_rto_minutes: Option<f64>,
    pub restore_order: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct XepOwnershipCatalog {
    pub version: String,
    pub xep_ownership: HashMap<String, XepOwnership>,
}

#[derive(Debug, Deserialize)]
pub struct XepOwnership {
    pub semantic_owner: String,
    pub deployment_unit: String,
    pub execution_mode: String,
}
