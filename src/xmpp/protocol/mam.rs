use super::{Action, ProtocolSession};
use crate::services::xml_util::{mam_muc_stanza, muc_occupant_id, set_muc_occupant_id};
use anyhow::Result;
use northstar_archive_application::{
    ArchiveRow, MamPreferencesWriter, MamQueryRepository, MamRoomAccess, MamService,
};
use roxmltree::Node;

pub(crate) use northstar_archive_xmpp::{parse_mam_query, ParsedMamQuery};

fn action(reply: northstar_archive_xmpp::MamReply) -> Action {
    match reply {
        northstar_archive_xmpp::MamReply::Send(x) => Action::Send(x),
        northstar_archive_xmpp::MamReply::SendMany(x) => Action::SendMany(x),
    }
}

impl ProtocolSession {
    pub(crate) async fn mam_preferences_get(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_preferences_get(self, id, to, prefs)
            .await
            .map(action)
    }

    pub(crate) async fn mam_preferences_set(
        &self,
        id: &str,
        to: Option<&str>,
        prefs: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_preferences_set(self, id, to, prefs)
            .await
            .map(action)
    }

    pub(crate) async fn mam_query_form(
        &self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_query_form(self, id, to, query)
            .await
            .map(action)
    }

    pub(crate) async fn mam_metadata(
        &self,
        id: &str,
        to: Option<&str>,
        metadata: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_metadata(self, id, to, metadata)
            .await
            .map(action)
    }

    pub(crate) async fn mam(
        &self,
        id: &str,
        query: Node<'_, '_>,
        to: Option<&str>,
    ) -> Result<Action> {
        northstar_archive_xmpp::mam_query(self, id, query, to)
            .await
            .map(action)
    }
}

impl northstar_archive_xmpp::MamSession for ProtocolSession {
    fn mam_account(&self) -> Option<(uuid::Uuid, &str)> {
        self.authenticated
            .as_ref()
            .map(|user| (user.id, user.username.as_str()))
    }

    fn mam_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn mam_local_domain(&self) -> &str {
        self.state.local_domain()
    }

    fn mam_muc_domain(&self) -> String {
        self.muc_domain()
    }

    fn mam_joined_room(&self, room_bare_jid: &str) -> bool {
        self.joined_rooms.contains_key(room_bare_jid)
    }

    fn mam_service(
        &self,
    ) -> &MamService<
        impl MamQueryRepository<Error = anyhow::Error> + MamPreferencesWriter<Error = anyhow::Error>,
    > {
        self.state.mam_service()
    }

    fn mam_room_stanza(&self, access: &MamRoomAccess, item: &ArchiveRow) -> String {
        let occupant_id = muc_occupant_id(access.occupant_id_secret(), &item.peer_jid);
        let authoritative = set_muc_occupant_id(&item.stanza, &occupant_id);
        mam_muc_stanza(&authoritative, &item.peer_jid, access.reveal_real_jid())
    }
}
