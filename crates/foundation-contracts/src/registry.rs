//! Protocol registry contract.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub namespace: String,
    pub element: String,
    pub stanza: String,
    pub phase: String,
    pub service_id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoFeature {
    pub var: String,
    pub service_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetRouteSnapshotRequest {
    pub since_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetRouteSnapshotResponse {
    pub snapshot_version: u64,
    pub signature: Vec<u8>,
    pub routes: Vec<RouteEntry>,
    pub disco_features: Vec<DiscoFeature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterInstanceRequest {
    pub service_id: String,
    pub instance_id: String,
    pub endpoint: String,
    pub weight: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterInstanceResponse {
    pub acknowledged: bool,
    pub current_registry_version: u64,
}
