//! The route type of the client IQ dispatch. A route pairs a handler with a gate that decides whether the
//! handler answers the request, the request is answered `service-unavailable`, or it is treated like a
//! request without a route. The composition root builds the route table.

use super::super::{ProtocolSession, SessionHost};
use crate::transport::Action;
use crate::{HandlerFuture, IqKind, IqRequest};

/// A handler of the client IQ dispatch.
pub type ClientIqHandler<H> =
    for<'a> fn(&'a mut ProtocolSession<H>, IqRequest<'a>) -> HandlerFuture<'a, Action>;

/// Whether a route dispatches unconditionally or only while its conditions are met.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteGate {
    /// The route always handles the request.
    Always,
    /// The route handles the request while its XEP route switch is on; otherwise the request is
    /// unsupported.
    RouteEnabled,
    /// The route handles the request while its XEP route switch is on; otherwise the request is
    /// answered `service-unavailable`.
    RouteEnabledOrUnavailable,
    /// The route handles the request while the HTTP upload service is enabled
    /// (`session.host.http_upload_enabled()`, the same call the XEP-0363 arms use as their guard);
    /// otherwise the request is unsupported.
    HttpUpload,
}

/// What the dispatch does with a request that has a route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// The route's handler answers the request.
    Handle,
    /// The request is answered like one without a route.
    Unsupported,
    /// The request is answered `service-unavailable`.
    Unavailable,
}

/// A registered route: its handler and its gate.
pub struct ClientIqRoute<H: SessionHost> {
    pub handler: ClientIqHandler<H>,
    pub gate: RouteGate,
}

impl<H: SessionHost> Clone for ClientIqRoute<H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: SessionHost> Copy for ClientIqRoute<H> {}

impl<H: SessionHost> ClientIqRoute<H> {
    /// What the dispatch does with a request for this route.
    pub fn admission(
        &self,
        session: &ProtocolSession<H>,
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
                    .host
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
                    .host
                    .xmpp_route_enabled(stanza_kind, namespace, element)
                {
                    Admission::Handle
                } else {
                    Admission::Unavailable
                }
            }
            RouteGate::HttpUpload => {
                if session.host.http_upload_enabled() {
                    Admission::Handle
                } else {
                    Admission::Unsupported
                }
            }
        }
    }
}
