//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`, and the handlers the root's client IQ route table calls on
//! it.

use crate::ArchiveSessionHost;
use anyhow::Result;
use northstar_archive_application::{
    ArchiveRow, MamPreferencesWriter, MamQueryRepository, MamRoomAccess, MamService,
};
use northstar_room_core::stanza::{mam_muc_stanza, muc_occupant_id, set_muc_occupant_id};
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use roxmltree::Node;

// From src/xmpp/protocol/mam.rs.
impl<H: SessionHost + ArchiveSessionHost> crate::MamSession for ProtocolSession<H> {
    fn mam_account(&self) -> Option<(uuid::Uuid, &str)> {
        self.authenticated
            .as_ref()
            .map(|user| (user.id, user.username.as_str()))
    }

    fn mam_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn mam_local_domain(&self) -> &str {
        self.host().archive_local_domain()
    }

    fn mam_muc_domain(&self) -> String {
        self.host().archive_muc_domain()
    }

    fn mam_joined_room(&self, room_bare_jid: &str) -> bool {
        self.joined_rooms.contains_key(room_bare_jid)
    }

    fn mam_service(
        &self,
    ) -> &MamService<
        impl MamQueryRepository<Error = anyhow::Error> + MamPreferencesWriter<Error = anyhow::Error>,
    > {
        self.host().mam_service()
    }

    fn mam_room_stanza(&self, access: &MamRoomAccess, item: &ArchiveRow) -> String {
        let occupant_id = muc_occupant_id(access.occupant_id_secret(), &item.peer_jid);
        let authoritative = set_muc_occupant_id(&item.stanza, &occupant_id);
        mam_muc_stanza(&authoritative, &item.peer_jid, access.reveal_real_jid())
    }
}

fn action(reply: crate::MamReply) -> Action {
    match reply {
        crate::MamReply::Send(x) => Action::Send(x),
        crate::MamReply::SendMany(x) => Action::SendMany(x),
    }
}

/// The MAM handlers the root calls on the session.
#[allow(async_fn_in_trait)] // Called on the root's concrete session type only.
pub trait MamHandlers {
    async fn mam_preferences_get(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam_preferences_set(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam_query_form(
        &self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam_metadata(
        &self,
        id: &str,
        to: Option<&str>,
        metadata: Node<'_, '_>,
    ) -> Result<Action>;

    async fn mam(&self, id: &str, query: Node<'_, '_>, to: Option<&str>) -> Result<Action>;
}

impl<H: SessionHost + ArchiveSessionHost> MamHandlers for ProtocolSession<H> {
    async fn mam_preferences_get(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action> {
        crate::mam_preferences_get(self, id, to, prefs)
            .await
            .map(action)
    }

    async fn mam_preferences_set(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action> {
        crate::mam_preferences_set(self, id, to, prefs)
            .await
            .map(action)
    }

    async fn mam_query_form(
        &self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        crate::mam_query_form(self, id, to, query).await.map(action)
    }

    async fn mam_metadata(
        &self,
        id: &str,
        to: Option<&str>,
        metadata: Node<'_, '_>,
    ) -> Result<Action> {
        crate::mam_metadata(self, id, to, metadata)
            .await
            .map(action)
    }

    async fn mam(&self, id: &str, query: Node<'_, '_>, to: Option<&str>) -> Result<Action> {
        crate::mam_query(self, id, query, to).await.map(action)
    }
}
