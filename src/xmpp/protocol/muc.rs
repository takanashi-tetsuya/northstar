//! XEP-0045 multi-user chat for local clients.
//!
//! `northstar-muc-xmpp` holds the handlers. This seam gives them the live
//! session and maps their replies back to session actions.

use super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_muc_xmpp::muc as handlers;
use northstar_muc_xmpp::ports::{MucHost, Occupant};
use northstar_stream::outbound::OutboundSender;
use roxmltree::Node;

#[cfg(test)]
pub(crate) mod saved_stage4;

/// The session handlers of muc.rs.
pub(crate) trait MucHandlers {
    /// The session host whose occupancy records the handlers return.
    type Host: MucHost;

    async fn authorized_muc_occupant(&self, room_jid: &str)
        -> Result<Option<Occupant<Self::Host>>>;

    async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action>;

    async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action>;

    async fn muc_admin_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_admin_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_moderate(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        moderate: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action>;

    async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn muc_register_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action>;

    async fn muc_register_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action>;
}

impl<H: SessionHost + MucHost<Outbound = OutboundSender>> MucHandlers for ProtocolSession<H> {
    type Host = H;

    async fn authorized_muc_occupant(&self, room_jid: &str) -> Result<Option<Occupant<H>>> {
        handlers::authorized_muc_occupant(self, room_jid).await
    }

    async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        Ok(handlers::groupchat::muc_message(self, root, raw)
            .await?
            .into())
    }

    async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        Ok(handlers::join::muc_presence(&*self, root, raw)
            .await?
            .into())
    }

    async fn muc_admin_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::admin::muc_admin_get(self, id, iq, query)
            .await?
            .into())
    }

    async fn muc_admin_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::admin::muc_admin_set(self, id, iq, query)
            .await?
            .into())
    }

    async fn muc_moderate(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        moderate: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::moderate::muc_moderate(self, id, iq, moderate)
            .await?
            .into())
    }

    async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        Ok(handlers::owner::muc_owner_get(self, id, iq).await?.into())
    }

    async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::owner::muc_owner_set(self, id, iq, query)
            .await?
            .into())
    }

    async fn muc_register_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        Ok(handlers::register::muc_register_get(self, id, iq)
            .await?
            .into())
    }

    async fn muc_register_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        Ok(handlers::register::muc_register_set(self, id, iq, query)
            .await?
            .into())
    }
}

#[cfg(test)]
use handlers::{admin_batch::*, discussion::*, join::*, moderate::*, *};
#[cfg(test)]
use northstar_room_application::muc_service::{
    MucAdminBatchChange, MucAdminBatchOutcome, MucAffiliationTarget, MucDiscussionAdmission,
};
#[cfg(test)]
use northstar_room_application::{
    PostCommitAdmissionError as MucPostCommitAdmissionError, PostCommitPlan as MucPostCommitPlan,
};
#[cfg(test)]
use northstar_xml_builder::message_policy::encrypted_archive_stanza;

#[cfg(test)]
#[path = "muc_tests.rs"]
mod tests;
