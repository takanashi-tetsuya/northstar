use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_message_xmpp::extdisco::{self, ExtDiscoHost};
use roxmltree::Node;

/// The session handlers of extdisco.rs.
pub(crate) trait ExtDiscoHandlers {
    fn external_services(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        services: Node<'_, '_>,
    ) -> Result<Action>;

    fn external_credentials(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        credentials: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + ExtDiscoHost> ExtDiscoHandlers for ProtocolSession<H> {
    fn external_services(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        services: Node<'_, '_>,
    ) -> Result<Action> {
        extdisco::external_services(self, id, iq, services)
    }

    fn external_credentials(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        credentials: Node<'_, '_>,
    ) -> Result<Action> {
        extdisco::external_credentials(self, id, iq, credentials)
    }
}
