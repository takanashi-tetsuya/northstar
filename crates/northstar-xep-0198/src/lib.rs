#![forbid(unsafe_code)]

//! Capability-free XEP-0198 Stream Management wire protocol and state machine for Northstar.
//!
//! This crate implements transport-neutral XEP-0198 parsing, building, 32-bit counter
//! arithmetic, unacknowledged outbound queue accounting, negotiation policy decisions,
//! and deterministic lifecycle state transitions.
//!
//! It deliberately has no dependencies on Tokio, PostgreSQL/SQLx, sockets, network I/O,
//! or server AppState.

pub mod counter;
pub mod error;
pub mod negotiation;
pub mod queue;
pub mod state;
pub mod wire;

// Re-export core XEP metadata types
pub use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

// Re-export primary types and functions for ergonomic use
pub use counter::{acknowledgement_delta, SmCounter};
pub use error::{
    AckError, FailedReason, NegotiationError, QueueError, SmError, StateError, WireError,
};
pub use negotiation::{
    negotiate_enable, peer_ip_matches, resumability_allowed, resumed_offline_replay_eligible,
    same_device_matches, EnableConfig, IpBindingPolicy, NegotiatedEnable,
};
pub use queue::{UnackedEntry, UnackedQueue};
pub use state::{ActiveSession, ResumeSuccessOutcome, SmState, SmStateMachine, SuspendedSession};
pub use wire::{
    build_a, build_enable, build_enabled, build_failed, build_failed_str,
    build_handled_count_too_high_stream_error, build_r, build_resume, build_resumed,
    is_valid_location, is_valid_previd, is_valid_sm_control, parse_a, parse_enable, parse_enabled,
    parse_failed, parse_r, parse_resume, parse_resumed, AckAnswerElement, AckRequestElement,
    EnableElement, EnabledElement, FailedElement, ResumeElement, ResumedElement,
    MAX_LOCATION_BYTES, MAX_PREVID_BYTES, NAMESPACE, STANZA_ERROR_NAMESPACE, STREAMS_NAMESPACE,
    STREAM_ERROR_NAMESPACE,
};

/// Numeric XEP identity for XEP-0198 Stream Management.
pub const XEP_ID: XepId = XepId::new(198);

/// Static extension descriptor for catalog registration and capability-free feature resolution.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Stream Management",
    default_enabled: true,
    dependencies: &[],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::Stream,
            namespace: NAMESPACE,
            local_name: "enable",
        },
        StanzaRoute {
            stanza: StanzaKind::Stream,
            namespace: NAMESPACE,
            local_name: "resume",
        },
        StanzaRoute {
            stanza: StanzaKind::Stream,
            namespace: NAMESPACE,
            local_name: "r",
        },
        StanzaRoute {
            stanza: StanzaKind::Stream,
            namespace: NAMESPACE,
            local_name: "a",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_integrity() {
        assert_eq!(DESCRIPTOR.id, XepId::new(198));
        assert_eq!(DESCRIPTOR.name, "Stream Management");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 4);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "enable");
        assert_eq!(DESCRIPTOR.routes[1].local_name, "resume");
        assert_eq!(DESCRIPTOR.routes[2].local_name, "r");
        assert_eq!(DESCRIPTOR.routes[3].local_name, "a");
    }
}
