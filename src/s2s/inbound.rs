use crate::{db, state::AppState};
use anyhow::{Context, Result};
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use roxmltree::Document;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::*;

mod dispatch;
mod iq;

use self::iq::route_inbound_iq;
use northstar_roster_xmpp::federated_presence::route_inbound_presence;
use northstar_s2s::inbound::{
    authenticated_s2s_sender, locally_hosted_identity_domain, same_s2s_domain,
};

pub(crate) use self::dispatch::{route_inbound_component, route_inbound_for_connection};
pub(crate) use northstar_s2s::host::InboundFederationRoute;

#[cfg(test)]
use self::dispatch::{
    s2s_stream_address_error, valid_inbound_wire_namespace, validate_inbound_core_stanza,
    InboundCoreValidation,
};
#[cfg(test)]
use self::iq::{bare_account_iq_may_route_to_service_resource, is_xep0357_notification_publish};

#[cfg(test)]
#[path = "inbound_tests.rs"]
mod tests;
