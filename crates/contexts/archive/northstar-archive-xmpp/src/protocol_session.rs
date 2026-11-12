//! The protocol session as this context sees it: the impls of this crate's session ports for
//! `northstar_stream::protocol::ProtocolSession`.

use crate::ArchiveSessionHost;
use northstar_archive_application::{
    ArchiveRow, MamPreferencesWriter, MamQueryRepository, MamRoomAccess, MamService,
};
use northstar_room_core::stanza::{mam_muc_stanza, muc_occupant_id, set_muc_occupant_id};
use northstar_stream::protocol::{ProtocolSession, SessionHost};

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
