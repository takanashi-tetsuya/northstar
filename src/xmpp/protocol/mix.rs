//! Tests of the MIX session glue, which lives in `northstar-mix-xmpp`.

#[cfg(test)]
use anyhow::Result;

#[cfg(test)]
use northstar_room_core::mix::MixSessionCapability;

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod stage4_saved;

#[cfg(test)]
use futures::{future::BoxFuture, stream::FuturesUnordered};

#[cfg(test)]
use northstar_mix_xmpp::{
    channel_delivery::*, claimed::*, federation::*, iq_parse::*, local_delivery::*, message::*,
    payloads::*, relay::*, session::*, worker::*,
};

#[cfg(test)]
use northstar_room_application::mix_service::outbox;

#[cfg(test)]
use northstar_room_application::mix_service::outbox::core as mix_worker;

#[cfg(test)]
use northstar_room_application::mix_service::{
    MamArchiveQuery, MixBusinessReplay, MixParticipant, PamMembership, StoreEventOutcome,
    NODE_MESSAGES, NODE_PRESENCE,
};

#[cfg(test)]
use northstar_room_core::mix_iq_relay::MixIqRelayStage;

#[cfg(test)]
use northstar_stream::local_routes::session_table::{
    mix_presence_epoch_is_current, mix_presence_fallback_is_suppressed,
};

#[cfg(test)]
use northstar_xmpp_types::jid::CanonicalJid;

#[cfg(test)]
use roxmltree::Document;

#[cfg(test)]
use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "mix_tests.rs"]
mod tests;

#[cfg(test)]
mod shared_claimed_delivery_policy_tests;
