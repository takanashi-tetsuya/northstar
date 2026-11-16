//! The inbound side of a federation stream: negotiation (STARTTLS, SASL EXTERNAL, Dialback and XEP-0288
//! bidirectional streams) and the authenticated session that reads the peer's stanzas and hands each to the node
//! through [`S2sHost::route_inbound_stanza`](crate::host::S2sHost::route_inbound_stanza). Authenticated stanza
//! authorization and dispatch use the narrow ports in [`InboundHost`](crate::inbound_host::InboundHost).

use crate::host::InboundFederationRoute;
use crate::inbound_host::InboundHost;
use crate::outbound::*;
use crate::tls::*;
use crate::util::*;
use anyhow::{Context, Result};
use futures::FutureExt;
use northstar_federation_application::registry::*;
use northstar_federation_application::FederationEnvelope;
use northstar_federation_core::dialback::*;
use northstar_federation_core::wire::*;
use northstar_federation_core::{
    AdvertisedStreamLimits, DialbackOutcome, DIALBACK_NS, IO_TIMEOUT,
    S2S_AUTHENTICATED_IDLE_TIMEOUT, STREAM_LIMITS_NS,
};
use northstar_xml_builder::stream::stream_id;
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use roxmltree::Document;
use std::borrow::Cow;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

mod dispatch;
mod iq;
mod negotiation;
mod session;

pub use self::dispatch::{route_inbound_component, route_inbound_for_connection};
use self::iq::route_inbound_iq;
pub use self::negotiation::{
    authenticated_s2s_sender, locally_hosted_identity_domain, same_s2s_domain,
};
use self::negotiation::{inbound_connection, inbound_xmpps_connection};
use self::session::drive_authenticated_inbound;
pub use self::session::{reply_within_peer_limit, serve, serve_s2s_tls};

#[cfg(test)]
use self::dispatch::{
    s2s_stream_address_error, valid_inbound_wire_namespace, validate_inbound_core_stanza,
    InboundCoreValidation,
};
#[cfg(test)]
use self::iq::{bare_account_iq_may_route_to_service_resource, is_xep0357_notification_publish};
#[cfg(test)]
use self::negotiation::{
    hosted_s2s_domain, is_certificate_downgrade, parse_bidi_request,
    restore_inherited_dialback_namespace, valid_external_auth_shape, valid_starttls_request,
    BidiRequest,
};
#[cfg(test)]
use self::session::{initial_bidi_route_admissible, wait_for_federation_shutdown};

#[cfg(test)]
mod tests;
