//! Regression tests for remote room actors.

use crate::federated_muc::*;
use anyhow::Result;
use northstar_message_core::validation::validate_routed_message;
use northstar_room_application::muc_service::{MucRoom, SerializableMucOccupant};
use northstar_stream::local_routes::muc::{MucOccupant, MucOccupantEndpoint};

mod tests;
