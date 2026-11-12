use crate::{db, state::AppState};
use anyhow::{Context, Result};
use northstar_xml_builder::rewrite::{set_from, set_to};
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use roxmltree::Document;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::*;

mod dispatch;
mod iq;
mod presence;

use self::iq::route_inbound_iq;
use self::presence::route_inbound_presence;
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
use self::presence::{canonical_subscription_stanza, presence_probe_status_response};

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("inbound", include_str!("inbound.rs")),
    ("dispatch", include_str!("inbound/dispatch.rs")),
    ("presence", include_str!("inbound/presence.rs")),
    ("iq", include_str!("inbound/iq.rs")),
];

#[cfg(test)]
fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[path = "inbound_tests.rs"]
mod tests;

#[cfg(test)]
mod module_source_tests;
