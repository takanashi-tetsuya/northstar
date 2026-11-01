//! What a node reports back after it accepted one delivery for a local recipient.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeDeliveryReceipt {
    pub delivered: bool,
    pub accepted_full_jid: Option<String>,
    pub acknowledged: bool,
    pub mix_supported: usize,
    pub mix_unsupported: usize,
    pub mix_unknown: usize,
    pub mix_handoff: Option<ClusterMixHandoff>,
}

/// The durable local boundary reached by a remote node after it accepted one
/// exact MIX source. The source node uses this only to decide that its old
/// lease was transferred; database rows retain the actual new lease token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterMixHandoff {
    SocketFenced,
    SmPersisted,
    BoshPersisted,
}
