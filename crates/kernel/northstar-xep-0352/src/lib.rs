#![forbid(unsafe_code)]

//! Capability-free XEP-0352 Client State Indication wire protocol, state machine,
//! and policy queue library for Northstar.
//!
//! This crate implements transport-neutral XEP-0352 parsing, validation,
//! state transitions, traffic delivery classification, signal coalescing,
//! and bounded deferred queues with explicit overflow decisions.
//!
//! It has zero dependencies on Tokio, databases, sockets, clocks, or global state.

pub mod error;
pub mod policy;
pub mod queue;
pub mod state;
pub mod wire;

pub use error::{CsiError, PolicyError, QueueError, StateError, WireError};
pub use policy::{
    canonicalize_jid, classify_stanza, CoalescingKey, CsiPolicyConfig, DeliveryAction,
    OverflowPolicy, StanzaMetadata, DEFAULT_MAX_DEFERRED_BYTES, DEFAULT_MAX_DEFERRED_STANZAS,
};
pub use queue::{DeferredEntry, DeferredQueue, EnqueueResult, OverflowDecision};
pub use state::{CsiState, CsiStateMachine, TransitionOutcome};
pub use wire::{
    build_active, build_inactive, build_indication, build_stream_feature, is_valid_indication_node,
    parse_indication, parse_indication_node, CsiIndication, NAMESPACE,
};

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

/// Stable numeric identifier for XEP-0352.
pub const XEP_ID: XepId = XepId::new(352);

/// Extension descriptor for static feature resolution and route registration.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Client State Indication",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::Stream,
            namespace: NAMESPACE,
            local_name: "active",
        },
        StanzaRoute {
            stanza: StanzaKind::Stream,
            namespace: NAMESPACE,
            local_name: "inactive",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_metadata_matches_specification() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Client State Indication");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 2);

        let mut route_names = DESCRIPTOR
            .routes
            .iter()
            .map(|r| {
                assert_eq!(r.stanza, StanzaKind::Stream);
                assert_eq!(r.namespace, NAMESPACE);
                r.local_name
            })
            .collect::<Vec<_>>();
        route_names.sort();
        assert_eq!(route_names, vec!["active", "inactive"]);
    }
}
