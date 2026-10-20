//! Local MUC occupants: exact occupant updates, live membership, delivery and shutdown notices.

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

#[derive(Clone)]
pub struct MucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub endpoint: MucOccupantEndpoint,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    pub occupant_id: String,
    /// Per-occupancy ABA guard used for atomic nickname changes in Redis.
    /// This value is internal and is never exposed in XMPP stanzas.
    pub cluster_epoch: uuid::Uuid,
    /// Exact transport incarnation which owns this occupancy.  A resumed SM
    /// stream updates this value while preserving the occupancy epoch; a
    /// recreated post-crash occupancy receives a fresh epoch.
    pub connection_id: uuid::Uuid,
    /// Durable stream epoch owning this local occupant, when XEP-0198
    /// resumption is enabled.
    pub sm_session_id: Option<uuid::Uuid>,
    pub payload: String,
}

impl<'a> From<&'a MucOccupant> for LocalMucOccupantIdentity<'a> {
    fn from(occupant: &'a MucOccupant) -> Self {
        Self {
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            full_jid: &occupant.full_jid,
            connection_id: occupant.connection_id,
            cluster_epoch: occupant.cluster_epoch,
        }
    }
}

pub(crate) fn remove_local_muc_occupant_exact_from(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
) -> Option<MucOccupant> {
    if identity.connection_id.is_nil() || identity.cluster_epoch.is_nil() {
        return None;
    }
    let room_jid = crate::jid::canonicalize_bare(identity.room_jid).ok()?;
    let key = crate::services::xml_util::muc_occupant_key(&room_jid, identity.nick);
    occupants
        .remove_if(&key, |_, current| {
            current.room_jid == room_jid
                && muc_departure_identity_matches(
                    current,
                    identity.full_jid,
                    identity.connection_id,
                    identity.cluster_epoch,
                )
        })
        .map(|(_, occupant)| occupant)
}

pub(super) fn with_local_muc_occupant_exact<R>(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    update: impl FnOnce(&mut MucOccupant) -> R,
) -> Option<R> {
    if identity.connection_id.is_nil() || identity.cluster_epoch.is_nil() {
        return None;
    }
    let room_jid = crate::jid::canonicalize_bare(identity.room_jid).ok()?;
    let key = crate::services::xml_util::muc_occupant_key(&room_jid, identity.nick);
    let mut occupant = occupants.get_mut(&key)?;
    if occupant.room_jid != room_jid
        || !muc_departure_identity_matches(
            &occupant,
            identity.full_jid,
            identity.connection_id,
            identity.cluster_epoch,
        )
    {
        return None;
    }
    Some(update(&mut occupant))
}

pub(super) fn set_local_muc_affiliation_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    affiliation: &str,
    moderated: bool,
    only_if_none: bool,
    expected_affiliation: Option<&str>,
) -> Option<MucOccupant> {
    with_local_muc_occupant_exact(occupants, identity, |current| {
        if expected_affiliation.is_some_and(|expected| current.affiliation != expected) {
            return None;
        }
        if !only_if_none || current.affiliation == "none" {
            current.affiliation = affiliation.to_owned();
            current.role = if matches!(current.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if moderated && current.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
        }
        Some(current.clone())
    })
    .flatten()
}

pub(super) fn set_local_muc_role_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    expected_role: &str,
    role: &str,
    non_anonymous: Option<bool>,
) -> Option<MucOccupant> {
    with_local_muc_occupant_exact(occupants, identity, |current| {
        if current.role != expected_role {
            return None;
        }
        current.role = role.to_owned();
        if let Some(non_anonymous) = non_anonymous {
            current.room_non_anonymous = non_anonymous;
        }
        Some(current.clone())
    })
    .flatten()
}

pub(super) fn refresh_local_muc_policy_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    moderated: Option<bool>,
    non_anonymous: Option<bool>,
) -> Option<(MucOccupant, bool)> {
    with_local_muc_occupant_exact(occupants, identity, |current| {
        let before_role = current.role.clone();
        let before_non_anonymous = current.room_non_anonymous;
        if let Some(moderated) = moderated {
            current.role = if matches!(current.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if moderated && current.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
        }
        if let Some(non_anonymous) = non_anonymous {
            current.room_non_anonymous = non_anonymous;
        }
        let changed =
            current.role != before_role || current.room_non_anonymous != before_non_anonymous;
        (current.clone(), changed)
    })
}

pub(super) fn muc_presence_endpoint_matches(current: &MucOccupant, prepared: &MucOccupant) -> bool {
    match (&current.endpoint, &prepared.endpoint) {
        (MucOccupantEndpoint::Local(_), MucOccupantEndpoint::Local(_)) => true,
        (
            MucOccupantEndpoint::Federated {
                authenticated_domain: current_domain,
                connection_id: current_connection,
            },
            MucOccupantEndpoint::Federated {
                authenticated_domain: prepared_domain,
                connection_id: prepared_connection,
            },
        ) => current_domain == prepared_domain && current_connection == prepared_connection,
        (MucOccupantEndpoint::Suspended(current), MucOccupantEndpoint::Suspended(prepared)) => {
            Arc::ptr_eq(current, prepared)
        }
        _ => false,
    }
}

pub(super) fn refresh_local_muc_presence_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    prepared: &MucOccupant,
    apply_policy: bool,
) -> Option<MucOccupant> {
    with_local_muc_occupant_exact(occupants, prepared.into(), |current| {
        if !muc_presence_endpoint_matches(current, prepared) {
            return None;
        }
        current.payload.clone_from(&prepared.payload);
        if apply_policy {
            current.affiliation.clone_from(&prepared.affiliation);
            current.role.clone_from(&prepared.role);
            current.room_non_anonymous = prepared.room_non_anonymous;
        }
        Some(current.clone())
    })
    .flatten()
}

pub(super) fn rebind_local_federated_muc_occupant_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    old: &MucOccupant,
    new_connection_id: uuid::Uuid,
) -> Option<MucOccupant> {
    let MucOccupantEndpoint::Federated {
        authenticated_domain,
        ..
    } = &old.endpoint
    else {
        return None;
    };
    if new_connection_id.is_nil() || new_connection_id == old.connection_id {
        return None;
    }
    with_local_muc_occupant_exact(occupants, old.into(), |current| {
        if !muc_presence_endpoint_matches(current, old) {
            return None;
        }
        current.connection_id = new_connection_id;
        current.endpoint = MucOccupantEndpoint::Federated {
            authenticated_domain: authenticated_domain.clone(),
            connection_id: new_connection_id,
        };
        Some(current.clone())
    })
    .flatten()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalMucNicknameMove {
    Published,
    AlreadyPublished,
    DeferredToReconciliation,
    OldMissing,
    CollisionRestored,
    CollisionRestoreFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalMucJoinPublication {
    Published,
    AlreadyPublished,
    Occupied,
}

pub(super) fn publish_local_muc_join_if_vacant_in(
    occupants: &DashMap<String, MucOccupant>,
    joining: &MucOccupant,
) -> LocalMucJoinPublication {
    let Some(room_jid) = crate::jid::canonicalize_bare(&joining.room_jid).ok() else {
        return LocalMucJoinPublication::Occupied;
    };
    if joining.connection_id.is_nil() || joining.cluster_epoch.is_nil() {
        return LocalMucJoinPublication::Occupied;
    }
    let key = crate::services::xml_util::muc_occupant_key(&room_jid, &joining.nick);
    match occupants.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(joining.clone());
            LocalMucJoinPublication::Published
        }
        dashmap::mapref::entry::Entry::Occupied(entry)
            if entry.get().room_jid == room_jid
                && entry.get().nick == joining.nick
                && muc_departure_identity_matches(
                    entry.get(),
                    &joining.full_jid,
                    joining.connection_id,
                    joining.cluster_epoch,
                ) =>
        {
            LocalMucJoinPublication::AlreadyPublished
        }
        dashmap::mapref::entry::Entry::Occupied(_) => LocalMucJoinPublication::Occupied,
    }
}

pub(super) fn move_local_muc_nickname_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    old: LocalMucOccupantIdentity<'_>,
    renamed: &MucOccupant,
    cluster_committed: bool,
) -> LocalMucNicknameMove {
    let Some(room_jid) = crate::jid::canonicalize_bare(old.room_jid).ok() else {
        return LocalMucNicknameMove::OldMissing;
    };
    if old.nick == renamed.nick
        || renamed.room_jid != room_jid
        || renamed.full_jid != old.full_jid
        || renamed.connection_id != old.connection_id
        || renamed.cluster_epoch != old.cluster_epoch
        || old.connection_id.is_nil()
        || old.cluster_epoch.is_nil()
    {
        return LocalMucNicknameMove::OldMissing;
    }
    let old_key = crate::services::xml_util::muc_occupant_key(&room_jid, old.nick);
    let removed_old = remove_local_muc_occupant_exact_from(occupants, old);
    if removed_old.is_none() {
        return if cluster_committed {
            LocalMucNicknameMove::DeferredToReconciliation
        } else {
            LocalMucNicknameMove::OldMissing
        };
    }
    let new_key = crate::services::xml_util::muc_occupant_key(&room_jid, &renamed.nick);
    let destination = match occupants.entry(new_key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(renamed.clone());
            LocalMucNicknameMove::Published
        }
        dashmap::mapref::entry::Entry::Occupied(entry)
            if entry.get().room_jid == room_jid
                && muc_departure_identity_matches(
                    entry.get(),
                    &renamed.full_jid,
                    renamed.connection_id,
                    renamed.cluster_epoch,
                ) =>
        {
            LocalMucNicknameMove::AlreadyPublished
        }
        dashmap::mapref::entry::Entry::Occupied(_) => {
            LocalMucNicknameMove::DeferredToReconciliation
        }
    };
    if destination != LocalMucNicknameMove::DeferredToReconciliation || cluster_committed {
        return destination;
    }
    let old_occupant = removed_old.expect("old occupancy was removed above");
    match occupants.entry(old_key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(old_occupant);
            LocalMucNicknameMove::CollisionRestored
        }
        dashmap::mapref::entry::Entry::Occupied(_) => LocalMucNicknameMove::CollisionRestoreFailed,
    }
}

impl From<&MucOccupant> for SerializableMucOccupant {
    fn from(occ: &MucOccupant) -> Self {
        Self {
            full_jid: occ.full_jid.clone(),
            room_jid: occ.room_jid.clone(),
            nick: occ.nick.clone(),
            affiliation: occ.affiliation.clone(),
            role: occ.role.clone(),
            room_non_anonymous: occ.room_non_anonymous,
            occupant_id: occ.occupant_id.clone(),
            cluster_epoch: occ.cluster_epoch,
            connection_id: occ.connection_id,
            federated_domain: match &occ.endpoint {
                MucOccupantEndpoint::Local(_) | MucOccupantEndpoint::Suspended(_) => None,
                MucOccupantEndpoint::Federated {
                    authenticated_domain,
                    ..
                } => Some(authenticated_domain.clone()),
            },
            sm_session_id: occ.sm_session_id,
            payload: occ.payload.clone(),
        }
    }
}

pub(super) fn remove_live_muc_membership_in(
    sessions: &DashMap<String, OnlineSession>,
    occupant: &SerializableMucOccupant,
) -> bool {
    let Ok(full_jid) = crate::jid::canonical_session_key(&occupant.full_jid) else {
        return false;
    };
    let Some(session) = sessions.get(&full_jid) else {
        return false;
    };
    if occupant.connection_id.is_nil() || session.connection_id != occupant.connection_id {
        return false;
    }
    session
        .muc_memberships
        .remove_if(&occupant.room_jid, |_, membership| {
            membership.nick == occupant.nick
                && membership.cluster_epoch == occupant.cluster_epoch
                && !membership.cluster_epoch.is_nil()
        })
        .is_some()
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
