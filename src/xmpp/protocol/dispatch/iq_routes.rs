//! The routing table of the client IQ dispatch.
//!
//! Routes are registered once. A route's gate decides whether its handler answers
//! the request, the request is answered `service-unavailable`, or it is treated
//! like a request without a route, which `ProtocolSession::iq` answers
//! `feature-not-implemented`.

use super::*;
use northstar_stream::{HandlerFuture, IqKind, IqRequest, IqRoute, IqRouter};
use std::sync::LazyLock;

/// A handler of the client IQ dispatch.
pub(super) type RootIqHandler =
    for<'a> fn(&'a mut ProtocolSession, IqRequest<'a>) -> HandlerFuture<'a, Action>;

/// Whether a route dispatches unconditionally or only while its conditions are met.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RouteGate {
    /// The route always handles the request.
    Always,
    /// The route handles the request while its XEP route switch is on; otherwise the request is
    /// unsupported.
    RouteEnabled,
    /// The route handles the request while its XEP route switch is on; otherwise the request is
    /// answered `service-unavailable`.
    RouteEnabledOrUnavailable,
    /// The route handles the request while the HTTP upload service is enabled
    /// (`session.http_upload_enabled()`, the same call the XEP-0363 arms use as their guard);
    /// otherwise the request is unsupported.
    HttpUpload,
}

/// What the dispatch does with a request that has a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Admission {
    /// The route's handler answers the request.
    Handle,
    /// The request is answered like one without a route.
    Unsupported,
    /// The request is answered `service-unavailable`.
    Unavailable,
}

/// A registered route: its handler and its gate.
#[derive(Clone, Copy)]
pub(super) struct RootIqRoute {
    pub(super) handler: RootIqHandler,
    pub(super) gate: RouteGate,
}

impl RootIqRoute {
    /// What the dispatch does with a request for this route.
    pub(super) fn admission(
        &self,
        session: &ProtocolSession,
        element: &str,
        namespace: &str,
        kind: IqKind,
    ) -> Admission {
        match self.gate {
            RouteGate::Always => Admission::Handle,
            RouteGate::RouteEnabled => {
                let stanza_kind = match kind {
                    IqKind::Get => northstar_xep_core::StanzaKind::IqGet,
                    IqKind::Set => northstar_xep_core::StanzaKind::IqSet,
                };
                if session
                    .state
                    .xmpp_route_enabled(stanza_kind, namespace, element)
                {
                    Admission::Handle
                } else {
                    Admission::Unsupported
                }
            }
            RouteGate::RouteEnabledOrUnavailable => {
                let stanza_kind = match kind {
                    IqKind::Get => northstar_xep_core::StanzaKind::IqGet,
                    IqKind::Set => northstar_xep_core::StanzaKind::IqSet,
                };
                if session
                    .state
                    .xmpp_route_enabled(stanza_kind, namespace, element)
                {
                    Admission::Handle
                } else {
                    Admission::Unavailable
                }
            }
            RouteGate::HttpUpload => {
                if session.http_upload_enabled() {
                    Admission::Handle
                } else {
                    Admission::Unsupported
                }
            }
        }
    }
}

const ROUTES: &[(IqRoute, RootIqHandler, RouteGate)] = &[
    (
        IqRoute::new(
            "command",
            "http://jabber.org/protocol/commands",
            IqKind::Set,
        ),
        command,
        RouteGate::Always,
    ),
    (
        IqRoute::new("register", crate::xmpp::protocol::ibr::IBR2_NS, IqKind::Get),
        ibr2_register_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("register", crate::xmpp::protocol::ibr::IBR2_NS, IqKind::Set),
        ibr2_register_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("response", crate::xmpp::protocol::ibr::IBR2_NS, IqKind::Set),
        ibr2_response_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("cancel", crate::xmpp::protocol::ibr::IBR2_NS, IqKind::Set),
        ibr2_cancel_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("bind", "urn:ietf:params:xml:ns:xmpp-bind", IqKind::Set),
        bind,
        RouteGate::Always,
    ),
    (
        IqRoute::new(
            "session",
            "urn:ietf:params:xml:ns:xmpp-session",
            IqKind::Set,
        ),
        session,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "jabber:iq:roster", IqKind::Get),
        roster_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "jabber:iq:roster", IqKind::Set),
        roster_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "http://jabber.org/protocol/muc#owner", IqKind::Get),
        muc_owner_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "http://jabber.org/protocol/muc#owner", IqKind::Set),
        muc_owner_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "http://jabber.org/protocol/muc#admin", IqKind::Get),
        muc_admin_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "http://jabber.org/protocol/muc#admin", IqKind::Set),
        muc_admin_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("moderate", "urn:xmpp:message-moderate:1", IqKind::Set),
        muc_moderate,
        RouteGate::Always,
    ),
    (
        IqRoute::new(
            "query",
            "http://jabber.org/protocol/disco#info",
            IqKind::Get,
        ),
        disco_info,
        RouteGate::Always,
    ),
    (
        IqRoute::new(
            "query",
            "http://jabber.org/protocol/disco#items",
            IqKind::Get,
        ),
        disco_items,
        RouteGate::Always,
    ),
    (
        IqRoute::new("vCard", "vcard-temp", IqKind::Get),
        vcard_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("vCard", "vcard-temp", IqKind::Set),
        vcard_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("pubsub", "http://jabber.org/protocol/pubsub", IqKind::Set),
        pubsub_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("pubsub", "http://jabber.org/protocol/pubsub", IqKind::Get),
        pubsub_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "jabber:iq:private", IqKind::Get),
        private_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "jabber:iq:private", IqKind::Set),
        private_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", northstar_xep_0016::NAMESPACE, IqKind::Get),
        privacy_get,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("query", northstar_xep_0016::NAMESPACE, IqKind::Set),
        privacy_set,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("ping", northstar_xep_0199::NAMESPACE, IqKind::Get),
        ping,
        RouteGate::RouteEnabledOrUnavailable,
    ),
    (
        IqRoute::new("time", northstar_xep_0202::NAMESPACE, IqKind::Get),
        time,
        RouteGate::RouteEnabledOrUnavailable,
    ),
    (
        IqRoute::new("query", northstar_xep_0092::NAMESPACE, IqKind::Get),
        version,
        RouteGate::RouteEnabledOrUnavailable,
    ),
    (
        IqRoute::new("services", northstar_xep_0215::NAMESPACE, IqKind::Get),
        external_services,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("credentials", northstar_xep_0215::NAMESPACE, IqKind::Get),
        external_credentials,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("enable", northstar_xep_0357::XMLNS_PUSH, IqKind::Set),
        push_enable,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("disable", northstar_xep_0357::XMLNS_PUSH, IqKind::Set),
        push_disable,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("query", northstar_xep_0313::XMLNS_MAM, IqKind::Set),
        mam_query_set,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("query", northstar_xep_0313::XMLNS_MAM, IqKind::Get),
        mam_query_get,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("metadata", northstar_xep_0313::XMLNS_MAM, IqKind::Get),
        mam_metadata,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("prefs", northstar_xep_0313::XMLNS_MAM, IqKind::Get),
        mam_prefs_get,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("prefs", northstar_xep_0313::XMLNS_MAM, IqKind::Set),
        mam_prefs_set,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("enable", northstar_xep_0280::NAMESPACE, IqKind::Set),
        carbons_enable,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("disable", northstar_xep_0280::NAMESPACE, IqKind::Set),
        carbons_disable,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("blocklist", northstar_xep_0191::NAMESPACE, IqKind::Get),
        blocklist,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("block", northstar_xep_0191::NAMESPACE, IqKind::Set),
        block,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("unblock", northstar_xep_0191::NAMESPACE, IqKind::Set),
        unblock,
        RouteGate::RouteEnabled,
    ),
    (
        IqRoute::new("query", "jabber:iq:register", IqKind::Get),
        register_get,
        RouteGate::Always,
    ),
    (
        IqRoute::new("query", "jabber:iq:register", IqKind::Set),
        register_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new(
            "unique",
            "http://jabber.org/protocol/muc#unique",
            IqKind::Get,
        ),
        muc_unique,
        RouteGate::Always,
    ),
    (
        IqRoute::new("request", northstar_xep_0363::NAMESPACE, IqKind::Get),
        http_upload_slot,
        RouteGate::HttpUpload,
    ),
    (
        IqRoute::new("request", northstar_xep_0363::NAMESPACE, IqKind::Set),
        http_upload_set,
        RouteGate::HttpUpload,
    ),
    (
        IqRoute::new(
            "pubsub",
            "http://jabber.org/protocol/pubsub#owner",
            IqKind::Set,
        ),
        pubsub_owner_set,
        RouteGate::Always,
    ),
    (
        IqRoute::new(
            "pubsub",
            "http://jabber.org/protocol/pubsub#owner",
            IqKind::Get,
        ),
        pubsub_owner_get,
        RouteGate::Always,
    ),
];

fn build_routes() -> IqRouter<RootIqRoute> {
    let mut router = IqRouter::new();
    for &(route, handler, gate) in ROUTES {
        let result = router.register(route, RootIqRoute { handler, gate });
        debug_assert!(result.is_ok(), "duplicate IQ route");
    }
    router
}

pub(super) static IQ_ROUTES: LazyLock<IqRouter<RootIqRoute>> = LazyLock::new(build_routes);

fn command<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        crate::xmpp::protocol::commands::handle(
            session,
            request.id,
            request.stanza,
            request.payload,
        )
        .await
    })
}

fn ibr2_register_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(Ok(
        session.ibr_flows_iq(request.id, request.payload)
    )))
}

fn ibr2_register_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.select_ibr_flow_iq(request.id, request.payload))
}

fn ibr2_response_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.handle_ibr_response_iq(request.id, request.payload))
}

fn ibr2_cancel_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(Ok(
        session.handle_ibr_cancel_iq(request.id, request.payload)
    )))
}

fn bind<'a>(session: &'a mut ProtocolSession, request: IqRequest<'a>) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if !valid_bind_payload(request.payload) {
            Ok(Action::Send(iq_error(request.id, "bad-request")))
        } else {
            session.bind(request.id, request.payload).await
        }
    })
}

fn session<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    let _ = session;
    Box::pin(async move {
        if valid_empty_iq_payload(request.payload) {
            Ok(Action::Send(iq_result(request.id, "")))
        } else {
            Ok(Action::Send(iq_error(request.id, "bad-request")))
        }
    })
}

fn roster_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.roster_get(request.id, request.stanza, request.payload))
}

fn roster_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.roster_set(request.id, request.stanza, request.payload))
}

fn muc_owner_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.muc_owner_get(request.id, request.stanza))
}

fn muc_owner_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.muc_owner_set(request.id, request.stanza, request.payload))
}

fn muc_admin_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.muc_admin_get(request.id, request.stanza, request.payload))
}

fn muc_admin_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.muc_admin_set(request.id, request.stanza, request.payload))
}

fn muc_moderate<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.muc_moderate(request.id, request.stanza, request.payload))
}

fn disco_info<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.disco_info(request.id, request.stanza.attribute("to"), request.payload))
}

fn disco_items<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.disco_items(request.id, request.stanza.attribute("to"), request.payload))
}

fn vcard_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.vcard_get(request.id, request.stanza))
}

fn vcard_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.vcard_set(request.id, request.stanza, request.payload, request.raw))
}

fn pubsub_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.pubsub_domain()))
        {
            session
                .pubsub_iq_set(
                    request.id,
                    request.payload,
                    request.stanza.attribute("to").unwrap_or(""),
                )
                .await
        } else {
            let result = session
                .pep_publish(request.id, request.stanza, request.payload, request.raw)
                .await;
            map_pubsub_capacity_result(request.id, result)
        }
    })
}

fn pubsub_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.pubsub_domain()))
        {
            session.pubsub_iq_get(request.id, request.payload).await
        } else {
            session
                .pep_get(request.id, request.stanza, request.payload)
                .await
        }
    })
}

fn private_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.private_get(request.id, request.stanza.attribute("to"), request.payload))
}

fn private_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.private_set(
        request.id,
        request.stanza.attribute("to"),
        request.payload,
        request.raw,
    ))
}

fn privacy_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.privacy_get(request.id, request.stanza, request.payload))
}

fn privacy_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.privacy_set(request.id, request.stanza, request.payload))
}

fn ping<'a>(session: &'a mut ProtocolSession, request: IqRequest<'a>) -> HandlerFuture<'a, Action> {
    let _ = session;
    Box::pin(async move {
        if northstar_xep_0199::parse_ping_element(request.payload).is_err() {
            Ok(Action::Send(iq_error(request.id, "bad-request")))
        } else {
            Ok(Action::Send(iq_result(
                request.id,
                northstar_xep_0199::build_response(),
            )))
        }
    })
}

fn time<'a>(session: &'a mut ProtocolSession, request: IqRequest<'a>) -> HandlerFuture<'a, Action> {
    let _ = session;
    Box::pin(async move {
        if northstar_xep_0202::parse_time_request_element(request.payload).is_err() {
            return Ok(Action::Send(iq_error(request.id, "bad-request")));
        }
        let now = chrono::Utc::now();
        match northstar_xep_0202::build_response_from_parts(
            northstar_xep_0202::DEFAULT_TZO,
            &now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ) {
            Ok(payload) => Ok(Action::Send(iq_result(request.id, &payload))),
            Err(error) => {
                tracing::error!(%error, "failed to build validated XEP-0202 response");
                Ok(Action::Send(iq_error(request.id, "internal-server-error")))
            }
        }
    })
}

fn version<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if northstar_xep_0092::parse_query_request_element(request.payload).is_err() {
            return Ok(Action::Send(iq_error(request.id, "bad-request")));
        }
        let os = session
            .state
            .xmpp_version_includes_os()
            .then_some(xmpp_version_os());
        match northstar_xep_0092::build_response_from_parts(
            session.state.server_name(),
            env!("CARGO_PKG_VERSION"),
            os,
        ) {
            Ok(payload) => Ok(Action::Send(iq_result(request.id, &payload))),
            Err(error) => {
                tracing::error!(%error, "failed to build validated XEP-0092 response");
                Ok(Action::Send(iq_error(request.id, "internal-server-error")))
            }
        }
    })
}

fn external_services<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(session.external_services(
        request.id,
        request.stanza,
        request.payload,
    )))
}

fn external_credentials<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(session.external_credentials(
        request.id,
        request.stanza,
        request.payload,
    )))
}

fn push_enable<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.enable_push(request.id, request.stanza, request.payload, request.raw))
}

fn push_disable<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.disable_push(request.id, request.stanza, request.payload))
}

fn mam_query_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.mam(request.id, request.payload, request.stanza.attribute("to")))
}

fn mam_query_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.mam_query_form(request.id, request.stanza.attribute("to"), request.payload))
}

fn mam_metadata<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.mam_metadata(request.id, request.stanza.attribute("to"), request.payload))
}

fn mam_prefs_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.mam_preferences_get(
        request.id,
        request.stanza.attribute("to"),
        request.payload,
    ))
}

fn mam_prefs_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.mam_preferences_set(
        request.id,
        request.stanza.attribute("to"),
        request.payload,
    ))
}

fn carbons_enable<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(session.set_carbons(
        request.id,
        request.stanza,
        request.payload,
        true,
    )))
}

fn carbons_disable<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(session.set_carbons(
        request.id,
        request.stanza,
        request.payload,
        false,
    )))
}

fn blocklist<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.blocklist(request.id, request.stanza, request.payload))
}

fn block<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.block(request.id, request.stanza, request.payload))
}

fn unblock<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.unblock(request.id, request.stanza, request.payload))
}

fn register_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        let muc_domain = session.muc_domain();
        let is_local_muc_room = request.stanza.attribute("to").is_some_and(|to| {
            crate::xmpp::protocol::muc::canonical_local_muc_room(to, &muc_domain).is_some()
        });
        if is_local_muc_room {
            session.muc_register_get(request.id, request.stanza).await
        } else {
            session.registration_form(request.id, request.payload).await
        }
    })
}

fn register_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        let muc_domain = session.muc_domain();
        let is_local_muc_room = request.stanza.attribute("to").is_some_and(|to| {
            crate::xmpp::protocol::muc::canonical_local_muc_room(to, &muc_domain).is_some()
        });
        if is_local_muc_room {
            session
                .muc_register_set(request.id, request.stanza, request.payload)
                .await
        } else if session.authenticated.is_none() {
            session.register(request.id, request.payload).await
        } else {
            session.change_password(request.id, request.payload).await
        }
    })
}

fn muc_unique<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        let muc_domain = session.muc_domain();
        Ok(Action::Send(iq_result_from(
            request.id,
            request.stanza.attribute("to").unwrap_or(&muc_domain),
            &format!(
                "<unique xmlns='http://jabber.org/protocol/muc#unique'>{}</unique>",
                uuid::Uuid::new_v4()
            ),
        )))
    })
}

fn http_upload_slot<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.http_upload_slot(request.id, request.stanza.attribute("to"), request.payload))
}

/// XEP-0363 defines slot allocation as an IQ-get. The upload
/// service is known and implemented, so using IQ-set is a
/// malformed request rather than an unknown feature.
fn http_upload_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        Ok(Action::Send(iq_error_from(
            request.id,
            &session.upload_domain(),
            "bad-request",
        )))
    })
}

fn pubsub_owner_set<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.pubsub_domain()))
        {
            session.pubsub_owner_set(request.id, request.payload).await
        } else {
            let result = session
                .pep_owner_set(request.id, request.stanza, request.payload)
                .await;
            map_pubsub_capacity_result(request.id, result)
        }
    })
}

fn pubsub_owner_get<'a>(
    session: &'a mut ProtocolSession,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.pubsub_domain()))
        {
            session.pubsub_owner_get(request.id, request.payload).await
        } else {
            session
                .pep_owner_get(request.id, request.stanza, request.payload)
                .await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_registers_once() {
        assert_eq!(ROUTES.len(), 48);
        assert_eq!(build_routes().len(), ROUTES.len());
    }
}
