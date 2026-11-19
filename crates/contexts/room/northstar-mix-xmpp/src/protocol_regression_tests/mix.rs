//! Tests of the MIX session glue.

use crate::{
    channel_delivery::*, claimed::*, federation::*, iq_parse::*, local_delivery::*, message::*,
    payloads::*, relay::*, session::*, worker::*,
};
use anyhow::Result;
use futures::{future::BoxFuture, stream::FuturesUnordered};
use northstar_room_application::mix_service::outbox;
use northstar_room_application::mix_service::{
    MamArchiveQuery, MixParticipant, PamMembership, NODE_MESSAGES, NODE_PRESENCE,
};
use northstar_room_core::mix::MixSessionCapability;
use roxmltree::Document;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

mod shared_claimed_delivery_policy_tests;
#[path = "mix_tests.rs"]
mod tests;
