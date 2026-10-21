//! `AppState` methods over the live MUC occupant table, and shutdown notices; the exact table operations are in `xmpp::local_routes::muc_table`.

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

    pub(crate) fn local_muc_occupant_by_nick(
        &self,
        room_jid: &str,
        nick: &str,
    ) -> Option<MucOccupant> {
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
        let key = crate::services::xml_util::muc_occupant_key(&room_jid, nick);
        self.muc_occupants
            .get(&key)
            .filter(|occupant| occupant.room_jid == room_jid)
            .map(|occupant| occupant.value().clone())
    }

    pub(crate) fn local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        with_local_muc_occupant_exact(&self.muc_occupants, identity, |current| current.clone())
    }

    /// Refresh presence fields only while this exact transport still owns the
    /// nickname. Keep the current endpoint so an SM suspension cannot be undone.
    pub(crate) fn refresh_local_muc_presence_exact(
        &self,
        prepared: &MucOccupant,
        apply_policy: bool,
    ) -> Option<MucOccupant> {
        refresh_local_muc_presence_exact_in(&self.muc_occupants, prepared, apply_policy)
    }

    /// Update only the exact old federated actor after PostgreSQL commits a
    /// connection rebind. A late old-stream disconnect cannot remove it.
    pub(crate) fn rebind_local_federated_muc_occupant_exact(
        &self,
        old: &MucOccupant,
        new_connection_id: uuid::Uuid,
    ) -> Option<MucOccupant> {
        rebind_local_federated_muc_occupant_exact_in(&self.muc_occupants, old, new_connection_id)
    }

    /// Move a nickname after the caller's room gate or PG transition. A local
    /// collision restores the exact removed old value; a committed cluster
    /// collision leaves the other incarnation untouched for reconciliation.
    pub(crate) fn move_local_muc_nickname_exact(
        &self,
        old: LocalMucOccupantIdentity<'_>,
        renamed: &MucOccupant,
        cluster_committed: bool,
    ) -> LocalMucNicknameMove {
        move_local_muc_nickname_exact_in(&self.muc_occupants, old, renamed, cluster_committed)
    }

    /// Publish a join under one map shard lock without replacing a later
    /// transport that acquired the same nickname.
    pub(crate) fn publish_local_muc_join_if_vacant(
        &self,
        joining: &MucOccupant,
    ) -> LocalMucJoinPublication {
        publish_local_muc_join_if_vacant_in(&self.muc_occupants, joining)
    }

    /// Compare and remove under one map shard lock. Callers retain the removed
    /// value for any post-removal delivery; no map guard crosses an await.
    pub(crate) fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        remove_local_muc_occupant_exact_from(&self.muc_occupants, identity)
    }

    /// Apply a registration or admin affiliation change to the same live
    /// occupancy that was authorized. The returned snapshot holds no map lock.
    pub(crate) fn set_local_muc_affiliation_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        affiliation: &str,
        moderated: bool,
        only_if_none: bool,
        expected_affiliation: Option<&str>,
    ) -> Option<MucOccupant> {
        set_local_muc_affiliation_exact_in(
            &self.muc_occupants,
            identity,
            affiliation,
            moderated,
            only_if_none,
            expected_affiliation,
        )
    }

    /// Change only the role and optional room visibility of an exact occupant.
    pub(crate) fn set_local_muc_role_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        expected_role: &str,
        role: &str,
        non_anonymous: Option<bool>,
    ) -> Option<MucOccupant> {
        set_local_muc_role_exact_in(
            &self.muc_occupants,
            identity,
            expected_role,
            role,
            non_anonymous,
        )
    }

    /// Recompute policy fields from the current affiliation, preserving
    /// transport, presence payload and any other concurrently refreshed data.
    pub(crate) fn refresh_local_muc_policy_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        moderated: Option<bool>,
        non_anonymous: Option<bool>,
    ) -> Option<(MucOccupant, bool)> {
        refresh_local_muc_policy_exact_in(&self.muc_occupants, identity, moderated, non_anonymous)
    }

    /// Revoke the exact live protocol actor membership represented by an
    /// occupant.  All four identities are required so a delayed kick or
    /// teardown cannot affect a later connection or a reused nickname.
    pub fn remove_live_muc_membership(&self, occupant: &SerializableMucOccupant) -> bool {
        remove_live_muc_membership_in(&self.sessions, occupant)
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
        let full_jid = crate::jid::canonical_session_key(full_jid).ok()?;
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
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
        let key = crate::services::xml_util::muc_occupant_key(&room_jid, &membership.nick);
        self.muc_occupants
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
            .muc_occupants
            .iter()
            .filter(|entry| matches!(&entry.value().endpoint, MucOccupantEndpoint::Local(_)))
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        count_shutdown_notification_completions(occupants.into_iter().map(|occupant| async move {
            let serialized = SerializableMucOccupant::from(&occupant);
            let stanza = crate::services::xml_util::muc_presence_stanza_with_status(
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
