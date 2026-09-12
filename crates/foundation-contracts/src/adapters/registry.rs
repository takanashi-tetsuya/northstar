//! Registry domain values.  Registry RPC messages remain generated.

use super::{
    assertions::SessionAssertion,
    common::{ErrorDetail, IdempotencyKey, TraceContext},
};
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
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchSnapshotsRequest {
    pub after_version: u64,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetRouteSnapshotResponse {
    pub snapshot_version: u64,
    pub signature: Vec<u8>,
    pub routes: Vec<RouteEntry>,
    pub disco_features: Vec<DiscoFeature>,
    pub digest: Vec<u8>,
    pub key_id: String,
    pub algorithm: String,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterInstanceRequest {
    pub service_id: String,
    pub instance_id: String,
    pub endpoint: String,
    pub weight: u64,
    pub operator_assertion: Option<SessionAssertion>,
    pub idempotency_key: Option<IdempotencyKey>,
    pub trace: Option<TraceContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterInstanceResponse {
    pub acknowledged: bool,
    pub current_registry_version: u64,
    pub error: Option<ErrorDetail>,
}
