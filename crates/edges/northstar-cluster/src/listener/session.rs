//! Apply exact session, account, and stream-management teardown commands.

use super::*;
use crate::{
    listener_dispatch::ClusterListenerDispatch,
    listener_sm_muc_teardown::ClusterListenerSmMucTeardown,
};

pub(super) async fn terminate_session<A: ClusterAdapters>(
    dispatch: &ClusterListenerDispatch<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) -> Result<()> {
    let ListenerTurn {
        delivered,
        control_processed,
        control_outcome,
        ..
    } = turn;
    let instance = json["connection_id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    if let (Ok(target), Some(instance)) = (
        northstar_xmpp_types::jid::canonical_session_key(target),
        instance,
    ) {
        match dispatch.terminate_exact_session(&target, instance).await? {
            SessionTerminationEffect::Absent => {
                *control_processed = Some(true);
                *control_outcome = Some(ClusterControlOutcome::AuthoritativelyAbsent);
            }
            SessionTerminationEffect::WrongOwner => {
                *control_processed = Some(false);
                *control_outcome = Some(ClusterControlOutcome::WrongOwner);
            }
            SessionTerminationEffect::Matched => {
                *delivered = 1;
                *control_processed = Some(true);
                *control_outcome = Some(ClusterControlOutcome::Matched);
            }
        }
    }
    Ok(())
}

pub(super) fn replace_user_agent<A: ClusterAdapters>(
    dispatch: &ClusterListenerDispatch<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let ListenerTurn {
        delivered,
        control_processed,
        ..
    } = turn;
    let parsed = northstar_xmpp_types::jid::canonicalize_bare(target)
        .ok()
        .zip(
            json["user_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok()),
        )
        .zip(
            json["device_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok()),
        );
    let epoch = json["minimum_epoch"].as_i64().filter(|value| *value > 0);
    if let (Some(((account, user_id), device_id)), Some(epoch)) = (parsed, epoch) {
        for (_, session) in dispatch.session_entries_for(&account) {
            if user_agent_control_revokes(
                session.user_id,
                session.user_agent_id,
                session.user_agent_epoch,
                user_id,
                device_id,
                epoch,
            ) {
                session.disconnect.cancel();
                *delivered += 1;
            }
        }
        *control_processed = Some(true);
    }
}

pub(super) fn teardown_account_generation<A: ClusterAdapters>(
    dispatch: &ClusterListenerDispatch<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let ListenerTurn {
        delivered,
        control_processed,
        ..
    } = turn;
    let parsed = northstar_xmpp_types::jid::canonicalize_bare(target)
        .ok()
        .zip(
            json["user_id"]
                .as_str()
                .and_then(|value| uuid::Uuid::parse_str(value).ok()),
        );
    let generation = json["minimum_generation"]
        .as_i64()
        .filter(|value| *value >= 0);
    if let (Some((account, user_id)), Some(generation)) = (parsed, generation) {
        *delivered += dispatch.revoke_account_before_generation(user_id, &account, generation);
        *control_processed = Some(true);
    }
}

pub(super) fn teardown_sm_session<A: ClusterAdapters>(
    dispatch: &ClusterListenerDispatch<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let ListenerTurn {
        delivered,
        control_processed,
        ..
    } = turn;
    if let Some(sm_session_id) = json["sm_session_id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
    {
        if let Ok(target) = northstar_xmpp_types::jid::canonical_session_key(target) {
            if dispatch.fence_sm_session(&target, sm_session_id) {
                *delivered = 1;
            }
            *control_processed = Some(true);
        }
    }
}

pub(super) async fn teardown_sm_muc_session<A: ClusterAdapters>(
    sm_muc_teardown: &ClusterListenerSmMucTeardown<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) {
    let ListenerTurn {
        delivered,
        control_processed,
        ..
    } = turn;
    let parsed = json["sm_session_id"]
        .as_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .zip(
            serde_json::from_value::<
                northstar_room_application::muc_service::SerializableMucOccupant,
            >(json["occupant"].clone())
            .ok(),
        );
    if let Some((sm_session_id, occupant)) = parsed {
        let target_matches = northstar_xmpp_types::jid::canonicalize_bare(target)
            .ok()
            .is_some_and(|room| room == occupant.room_jid);
        if target_matches {
            match sm_muc_teardown
                .teardown_exact(sm_session_id, &occupant)
                .await
            {
                Ok(_) => {
                    *delivered = 1;
                    *control_processed = Some(true);
                }
                Err(error) => {
                    tracing::warn!(?error, %target, "clustered SM MUC teardown failed and will be retried by its DB lease owner")
                }
            }
        }
    }
}
