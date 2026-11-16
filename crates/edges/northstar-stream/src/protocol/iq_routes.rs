//! The routing table of the client IQ dispatch.
//!
//! Routes are registered once. A route's gate decides whether its handler answers
//! the request, the request is answered `service-unavailable`, or it is treated
//! like a request without a route, which `ProtocolSession::iq` answers
//! `feature-not-implemented`.

use super::dispatch::route::{ClientIqHandler, ClientIqRoute, RouteGate};
use super::dispatch::{
    is_service_jid, map_pubsub_capacity_result, valid_bind_payload, valid_empty_iq_payload,
    xmpp_version_os,
};
use super::ProtocolSession;
use crate::transport::Action;
use crate::{HandlerFuture, IqKind, IqRequest, IqRoute, IqRouter};
use northstar_xml_builder::stanza::{iq_error, iq_error_from, iq_result, iq_result_from};

mod host;
pub use host::IqRouteHost;

// Expand the same declarations with typed handlers in production and placeholder
// values in the registration test, which needs no node or session fixture.
macro_rules! routes {
    ($handler:ident) => {
        &[
            (
                IqRoute::new(
                    "command",
                    "http://jabber.org/protocol/commands",
                    IqKind::Set,
                ),
                $handler!(command),
                RouteGate::Always,
            ),
            (
                IqRoute::new("register", northstar_auth_xmpp::ibr::IBR2_NS, IqKind::Get),
                $handler!(ibr2_register_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("register", northstar_auth_xmpp::ibr::IBR2_NS, IqKind::Set),
                $handler!(ibr2_register_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("response", northstar_auth_xmpp::ibr::IBR2_NS, IqKind::Set),
                $handler!(ibr2_response_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("cancel", northstar_auth_xmpp::ibr::IBR2_NS, IqKind::Set),
                $handler!(ibr2_cancel_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("bind", "urn:ietf:params:xml:ns:xmpp-bind", IqKind::Set),
                $handler!(bind),
                RouteGate::Always,
            ),
            (
                IqRoute::new(
                    "session",
                    "urn:ietf:params:xml:ns:xmpp-session",
                    IqKind::Set,
                ),
                $handler!(session),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "jabber:iq:roster", IqKind::Get),
                $handler!(roster_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "jabber:iq:roster", IqKind::Set),
                $handler!(roster_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "http://jabber.org/protocol/muc#owner", IqKind::Get),
                $handler!(muc_owner_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "http://jabber.org/protocol/muc#owner", IqKind::Set),
                $handler!(muc_owner_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "http://jabber.org/protocol/muc#admin", IqKind::Get),
                $handler!(muc_admin_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "http://jabber.org/protocol/muc#admin", IqKind::Set),
                $handler!(muc_admin_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("moderate", "urn:xmpp:message-moderate:1", IqKind::Set),
                $handler!(muc_moderate),
                RouteGate::Always,
            ),
            (
                IqRoute::new(
                    "query",
                    "http://jabber.org/protocol/disco#info",
                    IqKind::Get,
                ),
                $handler!(disco_info),
                RouteGate::Always,
            ),
            (
                IqRoute::new(
                    "query",
                    "http://jabber.org/protocol/disco#items",
                    IqKind::Get,
                ),
                $handler!(disco_items),
                RouteGate::Always,
            ),
            (
                IqRoute::new("vCard", "vcard-temp", IqKind::Get),
                $handler!(vcard_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("vCard", "vcard-temp", IqKind::Set),
                $handler!(vcard_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("pubsub", "http://jabber.org/protocol/pubsub", IqKind::Set),
                $handler!(pubsub_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("pubsub", "http://jabber.org/protocol/pubsub", IqKind::Get),
                $handler!(pubsub_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "jabber:iq:private", IqKind::Get),
                $handler!(private_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "jabber:iq:private", IqKind::Set),
                $handler!(private_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", northstar_xep_0016::NAMESPACE, IqKind::Get),
                $handler!(privacy_get),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("query", northstar_xep_0016::NAMESPACE, IqKind::Set),
                $handler!(privacy_set),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("ping", northstar_xep_0199::NAMESPACE, IqKind::Get),
                $handler!(ping),
                RouteGate::RouteEnabledOrUnavailable,
            ),
            (
                IqRoute::new("time", northstar_xep_0202::NAMESPACE, IqKind::Get),
                $handler!(time),
                RouteGate::RouteEnabledOrUnavailable,
            ),
            (
                IqRoute::new("query", northstar_xep_0092::NAMESPACE, IqKind::Get),
                $handler!(version),
                RouteGate::RouteEnabledOrUnavailable,
            ),
            (
                IqRoute::new("services", northstar_xep_0215::NAMESPACE, IqKind::Get),
                $handler!(external_services),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("credentials", northstar_xep_0215::NAMESPACE, IqKind::Get),
                $handler!(external_credentials),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("enable", northstar_xep_0357::XMLNS_PUSH, IqKind::Set),
                $handler!(push_enable),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("disable", northstar_xep_0357::XMLNS_PUSH, IqKind::Set),
                $handler!(push_disable),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("query", northstar_xep_0313::XMLNS_MAM, IqKind::Set),
                $handler!(mam_query_set),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("query", northstar_xep_0313::XMLNS_MAM, IqKind::Get),
                $handler!(mam_query_get),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("metadata", northstar_xep_0313::XMLNS_MAM, IqKind::Get),
                $handler!(mam_metadata),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("prefs", northstar_xep_0313::XMLNS_MAM, IqKind::Get),
                $handler!(mam_prefs_get),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("prefs", northstar_xep_0313::XMLNS_MAM, IqKind::Set),
                $handler!(mam_prefs_set),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("enable", northstar_xep_0280::NAMESPACE, IqKind::Set),
                $handler!(carbons_enable),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("disable", northstar_xep_0280::NAMESPACE, IqKind::Set),
                $handler!(carbons_disable),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("blocklist", northstar_xep_0191::NAMESPACE, IqKind::Get),
                $handler!(blocklist),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("block", northstar_xep_0191::NAMESPACE, IqKind::Set),
                $handler!(block),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("unblock", northstar_xep_0191::NAMESPACE, IqKind::Set),
                $handler!(unblock),
                RouteGate::RouteEnabled,
            ),
            (
                IqRoute::new("query", "jabber:iq:register", IqKind::Get),
                $handler!(register_get),
                RouteGate::Always,
            ),
            (
                IqRoute::new("query", "jabber:iq:register", IqKind::Set),
                $handler!(register_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new(
                    "unique",
                    "http://jabber.org/protocol/muc#unique",
                    IqKind::Get,
                ),
                $handler!(muc_unique),
                RouteGate::Always,
            ),
            (
                IqRoute::new("request", northstar_xep_0363::NAMESPACE, IqKind::Get),
                $handler!(http_upload_slot),
                RouteGate::HttpUpload,
            ),
            (
                IqRoute::new("request", northstar_xep_0363::NAMESPACE, IqKind::Set),
                $handler!(http_upload_set),
                RouteGate::HttpUpload,
            ),
            (
                IqRoute::new(
                    "pubsub",
                    "http://jabber.org/protocol/pubsub#owner",
                    IqKind::Set,
                ),
                $handler!(pubsub_owner_set),
                RouteGate::Always,
            ),
            (
                IqRoute::new(
                    "pubsub",
                    "http://jabber.org/protocol/pubsub#owner",
                    IqKind::Get,
                ),
                $handler!(pubsub_owner_get),
                RouteGate::Always,
            ),
        ]
    };
}

fn register_routes<T: Copy, R>(
    routes: &[(IqRoute, T, RouteGate)],
    mut entry: impl FnMut(T, RouteGate) -> R,
) -> IqRouter<R> {
    let mut router = IqRouter::new();
    for &(route, handler, gate) in routes {
        let result = router.register(route, entry(handler, gate));
        debug_assert!(result.is_ok(), "duplicate IQ route");
    }
    router
}

/// Builds the client IQ table once for the composition root's host.
pub fn build_routes<H: IqRouteHost>() -> IqRouter<ClientIqRoute<H>> {
    macro_rules! handler {
        ($name:ident) => {
            $name::<H> as ClientIqHandler<H>
        };
    }

    register_routes(routes!(handler), |handler, gate| ClientIqRoute {
        handler,
        gate,
    })
}

fn command<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::command(session, request))
}

fn ibr2_register_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(Ok(
        session.ibr_flows_iq(request.id, request.payload)
    )))
}

fn ibr2_register_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.select_ibr_flow_iq(request.id, request.payload))
}

fn ibr2_response_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.handle_ibr_response_iq(request.id, request.payload))
}

fn ibr2_cancel_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(Ok(
        session.handle_ibr_cancel_iq(request.id, request.payload)
    )))
}

fn bind<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if !valid_bind_payload(request.payload) {
            Ok(Action::Send(iq_error(request.id, "bad-request")))
        } else {
            session.bind(request.id, request.payload).await
        }
    })
}

fn session<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
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

fn roster_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::roster_get(session, request))
}

fn roster_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::roster_set(session, request))
}

fn muc_owner_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::muc_owner_get(session, request))
}

fn muc_owner_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::muc_owner_set(session, request))
}

fn muc_admin_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::muc_admin_get(session, request))
}

fn muc_admin_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::muc_admin_set(session, request))
}

fn muc_moderate<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::muc_moderate(session, request))
}

fn disco_info<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.disco_info(request.id, request.stanza.attribute("to"), request.payload))
}

fn disco_items<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.disco_items(request.id, request.stanza.attribute("to"), request.payload))
}

fn vcard_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::vcard_get(session, request))
}

fn vcard_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::vcard_set(session, request))
}

fn pubsub_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.host().pubsub_domain()))
        {
            H::pubsub_iq_set(session, request).await
        } else {
            let result = H::pep_publish(session, request).await;
            map_pubsub_capacity_result(request.id, result)
        }
    })
}

fn pubsub_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.host().pubsub_domain()))
        {
            H::pubsub_iq_get(session, request).await
        } else {
            H::pep_get(session, request).await
        }
    })
}

fn private_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::private_get(session, request))
}

fn private_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::private_set(session, request))
}

fn privacy_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::privacy_get(session, request))
}

fn privacy_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::privacy_set(session, request))
}

fn ping<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
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

fn time<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
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
                tracing::error!(
                    target: "northstar_server::xmpp::protocol::iq_routes",
                    %error,
                    "failed to build validated XEP-0202 response"
                );
                Ok(Action::Send(iq_error(request.id, "internal-server-error")))
            }
        }
    })
}

fn version<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if northstar_xep_0092::parse_query_request_element(request.payload).is_err() {
            return Ok(Action::Send(iq_error(request.id, "bad-request")));
        }
        let os = session
            .host()
            .xmpp_version_includes_os()
            .then_some(xmpp_version_os());
        match northstar_xep_0092::build_response_from_parts(
            session.host().server_name(),
            session.host().server_version(),
            os,
        ) {
            Ok(payload) => Ok(Action::Send(iq_result(request.id, &payload))),
            Err(error) => {
                tracing::error!(
                    target: "northstar_server::xmpp::protocol::iq_routes",
                    %error,
                    "failed to build validated XEP-0092 response"
                );
                Ok(Action::Send(iq_error(request.id, "internal-server-error")))
            }
        }
    })
}

fn external_services<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(H::external_services(session, request)))
}

fn external_credentials<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(H::external_credentials(
        session, request,
    )))
}

fn push_enable<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.enable_push(request.id, request.stanza, request.payload, request.raw))
}

fn push_disable<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(session.disable_push(request.id, request.stanza, request.payload))
}

fn mam_query_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::mam_query_set(session, request))
}

fn mam_query_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::mam_query_get(session, request))
}

fn mam_metadata<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::mam_metadata(session, request))
}

fn mam_prefs_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::mam_prefs_get(session, request))
}

fn mam_prefs_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::mam_prefs_set(session, request))
}

fn carbons_enable<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(session.set_carbons(
        request.id,
        request.stanza,
        request.payload,
        true,
    )))
}

fn carbons_disable<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(std::future::ready(session.set_carbons(
        request.id,
        request.stanza,
        request.payload,
        false,
    )))
}

fn blocklist<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::blocklist(session, request))
}

fn block<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::block(session, request))
}

fn unblock<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::unblock(session, request))
}

fn register_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        let muc_domain = session.host().muc_domain();
        let is_local_muc_room = request
            .stanza
            .attribute("to")
            .is_some_and(|to| H::is_local_muc_room(to, &muc_domain));
        if is_local_muc_room {
            H::muc_register_get(session, request).await
        } else {
            session.registration_form(request.id, request.payload).await
        }
    })
}

fn register_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        let muc_domain = session.host().muc_domain();
        let is_local_muc_room = request
            .stanza
            .attribute("to")
            .is_some_and(|to| H::is_local_muc_room(to, &muc_domain));
        if is_local_muc_room {
            H::muc_register_set(session, request).await
        } else if session.authenticated.is_none() {
            session.register(request.id, request.payload).await
        } else {
            session.change_password(request.id, request.payload).await
        }
    })
}

fn muc_unique<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        let muc_domain = session.host().muc_domain();
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

fn http_upload_slot<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(H::http_upload_slot(session, request))
}

/// XEP-0363 defines slot allocation as an IQ-get. The upload
/// service is known and implemented, so using IQ-set is a
/// malformed request rather than an unknown feature.
fn http_upload_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        Ok(Action::Send(iq_error_from(
            request.id,
            &session.host().upload_domain(),
            "bad-request",
        )))
    })
}

fn pubsub_owner_set<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.host().pubsub_domain()))
        {
            H::pubsub_owner_set(session, request).await
        } else {
            let result = H::pep_owner_set(session, request).await;
            map_pubsub_capacity_result(request.id, result)
        }
    })
}

fn pubsub_owner_get<'a, H: IqRouteHost>(
    session: &'a mut ProtocolSession<H>,
    request: IqRequest<'a>,
) -> HandlerFuture<'a, Action> {
    Box::pin(async move {
        if request
            .stanza
            .attribute("to")
            .is_some_and(|to| is_service_jid(to, &session.host().pubsub_domain()))
        {
            H::pubsub_owner_get(session, request).await
        } else {
            H::pep_owner_get(session, request).await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_registers_once() {
        macro_rules! handler {
            ($name:ident) => {
                ()
            };
        }

        const ROUTES: &[(IqRoute, (), RouteGate)] = routes!(handler);
        assert_eq!(ROUTES.len(), 48);
        assert_eq!(register_routes(ROUTES, |(), gate| gate).len(), ROUTES.len());
    }
}
