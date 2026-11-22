//! Wake committed room operations and apply MUC fan-out commands.

use super::*;
use crate::{
    listener_dispatch::ClusterListenerDispatch, muc_delivery_endpoints::ClusterMucDeliveryEndpoints,
};

pub(super) fn wake_muc_operation<A: ClusterAdapters>(
    dispatch: &ClusterListenerDispatch<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let control_processed = &mut turn.control_processed;
    let valid = uuid::Uuid::parse_str(target).is_ok()
        && json["operation_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .is_some()
        && json["database_event_id"]
            .as_str()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .is_some()
        && json["event_sequence"]
            .as_i64()
            .is_some_and(|value| value >= 1);
    if valid {
        // This is deliberately the only side effect of the Redis
        // command. The worker re-reads the operation, exact audience
        // and payload digest from PostgreSQL before delivery.
        dispatch.wake_muc_outbox();
        *control_processed = Some(true);
    }
}

pub(super) async fn evict_muc_occupant<A: ClusterAdapters>(
    dispatch: &ClusterListenerDispatch<A>,
    muc_endpoints: &ClusterMucDeliveryEndpoints,
    muc_delivery: &ClusterMucDelivery<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let ListenerTurn {
        delivered,
        control_processed,
        ..
    } = turn;
    if let Ok(occupant) = serde_json::from_value::<
        northstar_room_application::muc_service::SerializableMucOccupant,
    >(json["occupant"].clone())
    {
        let status = json["status"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok());
        let reason = json["reason"].as_str().filter(|value| value.len() <= 4096);
        let actor_nick = json["actor_nick"].as_str();
        if status.is_some()
            && occupant.room_jid == target
            && !occupant.cluster_epoch.is_nil()
            && !occupant.connection_id.is_nil()
        {
            if let Some(removed) = muc_endpoints.revoke_exact_recipient_returning_local(&occupant) {
                let self_presence = northstar_room_core::stanza::muc_presence_stanza_with_status(
                    &occupant,
                    &removed.full_jid,
                    true,
                    true,
                    false,
                    None,
                    true,
                    status,
                    actor_nick,
                    reason,
                );
                *delivered += usize::from(
                    muc_delivery
                        .deliver_to_muc_occupant(&removed, self_presence)
                        .await,
                );
            }
            if muc_endpoints.room_occupants(target).is_empty() {
                let _ = dispatch.leave_empty_muc_room(target).await;
            }
            *control_processed = Some(true);
        }
    }
}

pub(super) async fn destroy_muc_room<A: ClusterAdapters>(
    muc_endpoints: &ClusterMucDeliveryEndpoints,
    muc_delivery: &ClusterMucDelivery<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let ListenerTurn {
        delivered,
        control_processed,
        ..
    } = turn;
    if let Ok(room) = northstar_xmpp_types::jid::canonicalize_bare(target) {
        let alternate = json["alternate"]
            .as_str()
            .and_then(|jid| northstar_xmpp_types::jid::canonicalize_bare(jid).ok());
        let reason = json["reason"]
            .as_str()
            .filter(|reason| reason.len() <= 4096);
        let identities =
            serde_json::from_value::<Vec<MucOccupancyIdentity>>(json["occupancies"].clone())
                .ok()
                .filter(|items| items.len() <= 10_000);
        if let Some(identities) = identities {
            for identity in identities {
                if identity.cluster_epoch.is_nil() || identity.connection_id.is_nil() {
                    continue;
                }
                let removed = muc_endpoints.remove_local_exact(
                    northstar_room_application::muc_service::LocalMucOccupantIdentity {
                        room_jid: &room,
                        nick: &identity.nick,
                        full_jid: &identity.full_jid,
                        connection_id: identity.connection_id,
                        cluster_epoch: identity.cluster_epoch,
                    },
                );
                if let Some(occupant) = removed {
                    let serializable =
                        northstar_room_application::muc_service::SerializableMucOccupant::from(
                            &occupant,
                        );
                    muc_endpoints.remove_live_membership_exact(&serializable);
                    let presence = northstar_room_core::stanza::muc_destroy_presence(
                        &serializable,
                        alternate.as_deref(),
                        reason,
                    );
                    *delivered += usize::from(
                        muc_delivery
                            .deliver_to_muc_occupant(&occupant, presence)
                            .await,
                    );
                }
            }
            *control_processed = Some(true);
        }
    }
}

pub(super) async fn change_muc_role<A: ClusterAdapters>(
    muc_endpoints: &ClusterMucDeliveryEndpoints,
    muc_delivery: &ClusterMucDelivery<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let ListenerTurn {
        delivered,
        control_processed,
        ..
    } = turn;
    if let Ok(occupant) = serde_json::from_value::<
        northstar_room_application::muc_service::SerializableMucOccupant,
    >(json["occupant"].clone())
    {
        if occupant.room_jid == target
            && !occupant.cluster_epoch.is_nil()
            && matches!(
                occupant.role.as_str(),
                "moderator" | "participant" | "visitor"
            )
        {
            muc_endpoints.apply_policy_projection_exact(&occupant);
            for session in muc_endpoints.room_occupants(target) {
                let self_presence = session.full_jid == occupant.full_jid;
                let presence = northstar_room_core::stanza::muc_presence_stanza(
                    &occupant,
                    &session.full_jid,
                    false,
                    self_presence,
                    false,
                    None,
                    occupant.room_non_anonymous || self_presence || session.role == "moderator",
                );
                *delivered += usize::from(
                    muc_delivery
                        .deliver_to_muc_occupant(&session, presence)
                        .await,
                );
            }
            *control_processed = Some(true);
        }
    }
}

pub(super) async fn change_muc_nickname<A: ClusterAdapters>(
    muc_endpoints: &ClusterMucDeliveryEndpoints,
    muc_delivery: &ClusterMucDelivery<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let delivered = &mut turn.delivered;
    if let (Ok(old_occupant), Ok(new_occupant)) = (
        serde_json::from_value::<northstar_room_application::muc_service::SerializableMucOccupant>(
            json["old_occupant"].clone(),
        ),
        serde_json::from_value::<northstar_room_application::muc_service::SerializableMucOccupant>(
            json["new_occupant"].clone(),
        ),
    ) {
        if old_occupant.cluster_epoch == new_occupant.cluster_epoch
            && old_occupant.full_jid == new_occupant.full_jid
            && old_occupant.room_jid == target
            && new_occupant.room_jid == target
            && old_occupant.nick != new_occupant.nick
        {
            let id = json["id"].as_str();
            for session in muc_endpoints.room_occupants(target) {
                let unavailable = northstar_room_core::stanza::muc_nickname_change_presence(
                    &old_occupant,
                    &northstar_room_application::muc_service::SerializableMucOccupant::from(
                        &session,
                    ),
                    &new_occupant.nick,
                    id,
                );
                *delivered += usize::from(
                    muc_delivery
                        .deliver_to_muc_occupant(&session, unavailable)
                        .await,
                );
                let available = northstar_room_core::stanza::muc_presence_stanza(
                    &new_occupant,
                    &session.full_jid,
                    false,
                    session.full_jid == new_occupant.full_jid,
                    false,
                    id,
                    new_occupant.room_non_anonymous
                        || session.full_jid == new_occupant.full_jid
                        || session.role == "moderator",
                );
                *delivered += usize::from(
                    muc_delivery
                        .deliver_to_muc_occupant(&session, available)
                        .await,
                );
            }
        }
    }
}

pub(super) async fn fan_out_muc_presence<A: ClusterAdapters>(
    muc_endpoints: &ClusterMucDeliveryEndpoints,
    muc_delivery: &ClusterMucDelivery<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let delivered = &mut turn.delivered;
    if let Ok(occupant) = serde_json::from_value::<
        northstar_room_application::muc_service::SerializableMucOccupant,
    >(json["occupant"].clone())
    {
        let unavailable = json["unavailable"].as_bool().unwrap_or(false);
        let created = json["created"].as_bool().unwrap_or(false);
        let id = json["id"].as_str();
        let removal_status = json["removal_status"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok());
        let actor_nick = json["actor_nick"].as_str();
        let reason = json["reason"].as_str();
        for session in muc_endpoints.room_occupants(target) {
            let disclose = occupant.room_non_anonymous || session.role == "moderator";
            let self_presence = session.full_jid == occupant.full_jid;
            let presence = northstar_room_core::stanza::muc_presence_stanza_with_status(
                &occupant,
                &session.full_jid,
                unavailable,
                self_presence,
                created,
                id,
                disclose,
                removal_status,
                actor_nick,
                reason,
            );
            *delivered += usize::from(
                muc_delivery
                    .deliver_to_muc_occupant(&session, presence)
                    .await,
            );
        }
    }
}

pub(super) async fn deliver_muc_private_stanza<A: ClusterAdapters>(
    muc_endpoints: &ClusterMucDeliveryEndpoints,
    muc_delivery: &ClusterMucDelivery<A>,
    json: &serde_json::Value,
    target: &str,
    stanza: &str,
    muc_senders: &[String],
    turn: &mut ListenerTurn,
) {
    let delivered = &mut turn.delivered;
    if let Some(nick) = json["target_nick"].as_str() {
        if let Some(session) = muc_endpoints.cached_recipient(target, nick) {
            let delivery = set_to(stanza, &session.full_jid);
            let blocked = muc_delivery
                .blocked_muc_recipient_accounts(std::slice::from_ref(&session), muc_senders)
                .await;
            if !northstar_xmpp_types::jid::canonical_bare_key(&session.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                *delivered += usize::from(
                    muc_delivery
                        .deliver_to_muc_occupant_unchecked(&session, delivery)
                        .await,
                );
            }
        }
    }
}

pub(super) async fn broadcast_muc_stanza<A: ClusterAdapters>(
    muc_endpoints: &ClusterMucDeliveryEndpoints,
    muc_delivery: &ClusterMucDelivery<A>,
    target: &str,
    stanza: &str,
    muc_senders: &[String],
    turn: &mut ListenerTurn,
) {
    let delivered = &mut turn.delivered;
    let sessions = muc_endpoints.room_occupants(target);
    let blocked = muc_delivery
        .blocked_muc_recipient_accounts(&sessions, muc_senders)
        .await;
    for session in sessions {
        if northstar_xmpp_types::jid::canonical_bare_key(&session.full_jid)
            .is_ok_and(|owner| blocked.contains(&owner))
        {
            continue;
        }
        let delivery = set_to(stanza, &session.full_jid);
        *delivered += usize::from(
            muc_delivery
                .deliver_to_muc_occupant_unchecked(&session, delivery)
                .await,
        );
    }
}
