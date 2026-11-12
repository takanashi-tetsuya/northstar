use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_message_application::extdisco::ExtDiscoService;
use northstar_message_xmpp::extdisco::{self, ExtDiscoHost, ExtDiscoSession};
use roxmltree::Node;
use std::net::IpAddr;

impl<H: SessionHost + ExtDiscoHost> ExtDiscoSession for ProtocolSession<H> {
    type Action = Action;

    fn extdisco_service(&self) -> &ExtDiscoService {
        self.host.extdisco_service()
    }

    fn authenticated_username(&self) -> Option<&str> {
        self.authenticated
            .as_ref()
            .map(|user| user.username.as_str())
    }

    fn full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn peer_ip(&self) -> IpAddr {
        self.peer_ip
    }
}

impl<H: SessionHost + ExtDiscoHost> ProtocolSession<H> {
    pub(crate) fn external_services(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        services: Node<'_, '_>,
    ) -> Result<Action> {
        extdisco::external_services(self, id, iq, services)
    }

    pub(crate) fn external_credentials(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        credentials: Node<'_, '_>,
    ) -> Result<Action> {
        extdisco::external_credentials(self, id, iq, credentials)
    }
}
