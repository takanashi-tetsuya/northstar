//! Exact operations on the live MUC occupant table and on session MUC memberships. The composition root owns the
//! tables themselves.

use super::muc::{
    muc_departure_identity_matches, LocalMucJoinPublication, LocalMucNicknameMove, MucOccupant,
    MucOccupantEndpoint,
};
use super::session::OnlineSession;
use crate::services::muc::{LocalMucOccupantIdentity, SerializableMucOccupant};
use dashmap::DashMap;
use std::sync::Arc;

pub(crate) fn remove_local_muc_occupant_exact_from(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
) -> Option<MucOccupant> {
    if identity.connection_id.is_nil() || identity.cluster_epoch.is_nil() {
        return None;
    }
    let room_jid = northstar_xmpp_types::jid::canonicalize_bare(identity.room_jid).ok()?;
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

pub(crate) fn with_local_muc_occupant_exact<R>(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    update: impl FnOnce(&mut MucOccupant) -> R,
) -> Option<R> {
    if identity.connection_id.is_nil() || identity.cluster_epoch.is_nil() {
        return None;
    }
    let room_jid = northstar_xmpp_types::jid::canonicalize_bare(identity.room_jid).ok()?;
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

pub(crate) fn set_local_muc_affiliation_exact_in(
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

pub(crate) fn set_local_muc_role_exact_in(
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

pub(crate) fn refresh_local_muc_policy_exact_in(
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

pub(crate) fn muc_presence_endpoint_matches(current: &MucOccupant, prepared: &MucOccupant) -> bool {
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

pub(crate) fn refresh_local_muc_presence_exact_in(
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

pub(crate) fn rebind_local_federated_muc_occupant_exact_in(
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

pub(crate) fn publish_local_muc_join_if_vacant_in(
    occupants: &DashMap<String, MucOccupant>,
    joining: &MucOccupant,
) -> LocalMucJoinPublication {
    let Some(room_jid) = northstar_xmpp_types::jid::canonicalize_bare(&joining.room_jid).ok()
    else {
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

pub(crate) fn move_local_muc_nickname_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    old: LocalMucOccupantIdentity<'_>,
    renamed: &MucOccupant,
    cluster_committed: bool,
) -> LocalMucNicknameMove {
    let Some(room_jid) = northstar_xmpp_types::jid::canonicalize_bare(old.room_jid).ok() else {
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

pub(crate) fn remove_live_muc_membership_in(
    sessions: &DashMap<String, OnlineSession>,
    occupant: &SerializableMucOccupant,
) -> bool {
    let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(&occupant.full_jid) else {
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

pub(crate) fn local_cluster_muc_projection_snapshot_in(
    occupants: &DashMap<String, MucOccupant>,
) -> Vec<MucOccupant> {
    occupants
        .iter()
        .map(|entry| entry.value().clone())
        .collect()
}
