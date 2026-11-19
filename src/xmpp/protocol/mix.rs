//! Tests of the MIX session glue, which lives in `northstar-mix-xmpp`.

#[cfg(test)]
use northstar_room_core::mix::MixSessionCapability;

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
use northstar_mix_xmpp::{
    channel_delivery::ChannelStanzaDeliveryOutcome,
    claimed::{process_claimed_mix_delivery_with_port, ClaimedMixDeliveryPort},
    local_delivery::{
        classify_durable_mix_route, try_send_local_durable_mix_observed,
        DurableMixRouteAvailability, DurableMixRouteDisposition, MixDeliveryRoutePending,
        MixLocalTransportFailure,
    },
    message::mix_replay_semantics,
};

#[cfg(test)]
use northstar_room_application::mix_service::outbox;

#[cfg(test)]
use northstar_room_application::mix_service::outbox::core as mix_worker;

#[cfg(test)]
use northstar_xmpp_types::jid::CanonicalJid;

#[cfg(test)]
pub(crate) mod stage4_saved;
