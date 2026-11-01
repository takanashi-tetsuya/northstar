//! Remote room actors. `northstar-muc-xmpp` holds the handlers; the root keeps
//! their fault-injection tests.

#[cfg(test)]
use crate::services::xml_util::validate_routed_message;
#[cfg(test)]
use crate::xmpp::local_routes::muc::{MucOccupant, MucOccupantEndpoint};
#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use northstar_muc_xmpp::federated_muc::*;
#[cfg(test)]
use northstar_room_application::muc_service::{MucRoom, SerializableMucOccupant};

#[cfg(test)]
mod tests;
