#![forbid(unsafe_code)]

pub mod caps;
pub mod mix;

pub use caps::*;
pub use mix::*;

use std::sync::Arc;

/// Aggregated runtime indices for the XMPP protocol adapter.
#[derive(Clone)]
pub struct XmppProtocolRuntime {
    pub mix_iq: Arc<mix::MixIqRelayIndex>,
    pub caps_cache: Arc<caps::CapsCacheIndex>,
    pub caps_by_jid: Arc<caps::CapsResourceIndex>,
    pub pending_caps: Arc<caps::PendingCapsIndex>,
    pub federated_caps_gates: Arc<caps::FederatedCapsGateIndex>,
    pub caps_effect_dispatcher: Arc<caps::CapsEffectDispatcher>,
}

impl Default for XmppProtocolRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl XmppProtocolRuntime {
    pub fn new() -> Self {
        Self {
            mix_iq: Arc::new(mix::MixIqRelayIndex::new()),
            caps_cache: Arc::new(caps::CapsCacheIndex::new()),
            caps_by_jid: Arc::new(caps::CapsResourceIndex::new()),
            pending_caps: Arc::new(caps::PendingCapsIndex::new()),
            federated_caps_gates: Arc::new(caps::FederatedCapsGateIndex::new()),
            caps_effect_dispatcher: caps::CapsEffectDispatcher::new(),
        }
    }
}
