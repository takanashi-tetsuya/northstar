//! `AppState` methods beside the live MUC occupant table: occupant listing, live membership validation, endpoint
//! delivery and shutdown notices. The table's own operations are `LocalMucOccupantTable`'s, in northstar-stream.

use super::*;

/// Fixed concurrency keeps one slow transport from blocking other shutdown
/// notices without spawning tasks or increasing the root's total deadline.
pub(crate) async fn count_shutdown_notification_completions<I, F>(notifications: I) -> usize
where
    I: IntoIterator<Item = F>,
    F: std::future::Future<Output = bool>,
{
    use futures::StreamExt;
    futures::stream::iter(notifications)
        .buffer_unordered(16)
        .fold(0, |confirmed, written| async move {
            confirmed + usize::from(written)
        })
        .await
}

impl AppState {
    pub fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, MucOccupant)> {
        self.session_cleanup_local().muc_occupants_for(room_jid)
    }

    /// Resolve a room membership only when it is still owned by the exact
    /// live transport and occupancy incarnation.  A room/nickname pair is
    /// deliberately insufficient because both values can be reused after a
    /// kick, disconnect, or resume race.
    pub fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        room_jid: &str,
        membership: &JoinedMucMembership,
    ) -> Option<MucOccupant> {
        if connection_id.is_nil() || membership.cluster_epoch.is_nil() {
            return None;
        }
        let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid).ok()?;
        let room_jid = northstar_xmpp_types::jid::canonicalize_bare(room_jid).ok()?;
        let session = self.sessions.get(&full_jid)?;
        if session.connection_id != connection_id
            || !session
                .muc_memberships
                .get(&room_jid)
                .is_some_and(|current| current.value() == membership)
        {
            return None;
        }
        drop(session);
        let key = northstar_room_core::stanza::muc_occupant_key(&room_jid, &membership.nick);
        self.room
            .muc_occupants
            .get(&key)
            .filter(|occupant| {
                muc_actor_identity_matches(
                    occupant,
                    &full_jid,
                    connection_id,
                    &room_jid,
                    membership,
                )
            })
            .map(|occupant| occupant.value().clone())
    }

    pub async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        self.muc_delivery_context()
            .deliver_to_muc_occupant(occupant, stanza)
            .await
    }

    pub(super) async fn deliver_to_muc_occupant_inner(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> bool {
        self.muc_delivery_context()
            .deliver_to_muc_occupant_inner(occupant, stanza, receipt, write_receipt)
            .await
    }

    pub async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> std::collections::HashSet<String> {
        self.muc_delivery_context()
            .blocked_muc_recipient_accounts(occupants, stanza_senders)
            .await
    }

    pub async fn deliver_to_muc_occupant_unchecked(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> bool {
        self.muc_delivery_context()
            .deliver_to_muc_occupant_unchecked(occupant, stanza)
            .await
    }

    /// Give live locally-owned MUC endpoints XEP-0045 system-shutdown status.
    /// Count only completed TCP/WS writes or BOSH client response ACKs; SM
    /// persistence alone cannot satisfy this process-local completion. The
    /// root supervises the whole loop under one bounded, cancellable window.
    pub async fn notify_muc_system_shutdown(&self) -> usize {
        let occupants = self
            .room
            .muc_occupants
            .iter()
            .filter(|entry| matches!(&entry.value().endpoint, MucOccupantEndpoint::Local(_)))
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        count_shutdown_notification_completions(occupants.into_iter().map(|occupant| async move {
            let serialized = SerializableMucOccupant::from(&occupant);
            let stanza = northstar_room_core::stanza::muc_presence_stanza_with_status(
                &serialized,
                &occupant.full_jid,
                true,
                true,
                false,
                None,
                true,
                Some(332),
                None,
                None,
            );
            let (receipt, mut received) = tokio::sync::mpsc::unbounded_channel();
            self.deliver_to_muc_occupant_inner(&occupant, stanza, None, Some(receipt))
                .await
                && received.recv().await.is_some()
        }))
        .await
    }
}
