mod admin;
mod admin_batch;
mod discussion;
mod groupchat;
mod join;
mod message;
mod moderate;
mod owner;
mod presence;
mod register;

#[cfg(test)]
pub(crate) mod saved_stage4;

#[cfg(test)]
use self::admin_batch::MucAdminMutationKind;
use self::admin_batch::{
    classify_muc_admin_items, is_exact_muc_removal_target, parse_muc_admin_batch, MucAdminChange,
};
pub(super) use self::admin_batch::{
    muc_admin_batch_error, parse_muc_admin_raw_items, MucAdminParseError, MucAdminRawItem,
};
#[cfg(test)]
use self::discussion::MucDiscussionLive;
use self::discussion::{MucMessageFanout, PreparedMucDiscussion};
#[cfg(test)]
use self::join::{muc_presence_payload, muc_sender_is_blocked};
#[cfg(test)]
use self::moderate::{parse_moderation_request, ModerationRequest};
pub(super) use self::owner::muc_room_configuration_form;

use super::{Action, ProtocolSession};
use crate::services::muc::fanout::{
    run_muc_discussion_fanout, run_muc_fanout, MucFanoutDisposition, MucFanoutPort, MucFanoutStage,
};
use crate::services::muc::{
    ClusterMucAffiliationSubject, ClusterMucConfigurationOutcome, ClusterMucInviteAuthority,
    ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucPrincipal, ClusterMucRegistrationOutcome,
    ClusterMucTransitionOutcome, DurableMucInviteOutcome, MucActorAuthority, MucActorPrincipal,
    MucAdminBatchChange, MucAdminBatchOutcome, MucAdminSnapshot, MucAffiliationBatchCommand,
    MucAffiliationBatchOutcome, MucAffiliationBatchWrite, MucAffiliationChange,
    MucAffiliationTarget, MucConfigUpdate, MucConfigurationCommand, MucConfigurationOutcome,
    MucConfigurationWrite, MucDiscussion, MucDiscussionAdmission, MucRegistrationCommand,
    MucRegistrationOutcome, MucRegistrationTarget, MucRegistrationWrite, MucRetractionCommand,
    MucRetractionKind, MucRetractionMutation, MucRetractionOutcome, MucRoom, MucSubjectCommand,
    MucSubjectMutation, MucSubjectOutcome, OfflineStoreOutcome, OfflineStorePolicy,
};
use crate::services::xml_util::*;
use crate::state::muc_cluster_effects::MucPresencePublication;
use crate::xmpp::frame_execution::Stage;
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use northstar_room_application::discussion as discussion_owner;
#[cfg(test)]
use northstar_room_application::PostCommitAdmissionError as MucPostCommitAdmissionError;
use northstar_room_application::PostCommitPlan as MucPostCommitPlan;
use northstar_room_core::MucJoinSnapshotError;
use northstar_xmpp_types::jid::{canonical_bare_key, prepare_domainpart, CanonicalJid};
use northstar_xmpp_types::jid_text::{bare_jid, localpart};
use roxmltree::Node;
use std::sync::atomic::Ordering;

pub(super) fn temporary_muc_offline_policy(state: &crate::state::AppState) -> OfflineStorePolicy {
    let limits = state.offline_delivery_limits();
    OfflineStorePolicy {
        max_messages: limits.max_messages,
        max_bytes: limits.max_bytes,
        ttl_days: limits.ttl_days,
        mam_backed: false,
    }
}

/// Release a PG join that could not become a local occupant after an ABA
/// collision. The leave and Redis cleanup target only the newly committed
/// incarnation; a failed PG compensation remains fenced by its finite lease.
pub(super) async fn compensate_unpublished_cluster_muc_join(
    state: &crate::state::AppState,
    room: &MucRoom,
    occupant: &crate::xmpp::local_routes::muc::MucOccupant,
) {
    match state
        .muc_service()
        .local_cluster_occupancy_target(room.id, occupant.cluster_epoch, occupant.connection_id)
        .await
    {
        Ok(Some(target)) => {
            let operation_id = uuid::Uuid::new_v4();
            match state
                .muc_service()
                .transition_local_cluster_occupancy(
                    operation_id,
                    &target,
                    "leave",
                    state.muc_cluster_node_id(),
                    None,
                    None,
                    occupant.sm_session_id,
                    std::time::Duration::from_secs(90),
                )
                .await
            {
                Ok(ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay) => {
                    if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
                        tracing::warn!(?error, %operation_id, room=%occupant.room_jid,
                            "unpublished MUC join was compensated; event wake will be recovered by polling");
                    }
                }
                Ok(outcome) => {
                    tracing::error!(?outcome, room=%occupant.room_jid, nick=%occupant.nick,
                    "PG rejected compensation of unpublished MUC join")
                }
                Err(error) => tracing::error!(?error, room=%occupant.room_jid, nick=%occupant.nick,
                    "PG compensation of unpublished MUC join failed; lease expiry will fence it"),
            }
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(?error, room=%occupant.room_jid, nick=%occupant.nick,
                "could not locate unpublished MUC join for compensation");
        }
    }
    // This join never became a local occupant. Remove only its exact Redis
    // projection, even if PG already expired it or compensation is retried.
    if let Err(error) = state.remove_exact_muc_soft_state(occupant).await {
        tracing::warn!(?error, room=%occupant.room_jid, nick=%occupant.nick,
            epoch=%occupant.cluster_epoch, connection=%occupant.connection_id,
            "could not remove Redis projection of unpublished MUC join");
    }
}

#[derive(Debug)]
struct MucClusterEffectFailure {
    stage: &'static str,
    error: anyhow::Error,
}

enum MucClusterEffect {
    FanOut {
        room: String,
        stanza: String,
        real_sender: Option<String>,
        stage: &'static str,
    },
    Evict {
        occupant: crate::services::muc::SerializableMucOccupant,
        status: u16,
        actor_nick: Option<String>,
        reason: Option<String>,
        stage: &'static str,
    },
    Leave {
        room: String,
        stage: &'static str,
    },
    Register {
        room: String,
        nick: String,
        json: String,
        stage: &'static str,
    },
    Presence {
        room: String,
        occupant: crate::services::muc::SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        removal_status: Option<u16>,
        actor_nick: Option<String>,
        reason: Option<String>,
        stage: &'static str,
    },
}

impl MucClusterEffect {
    async fn execute(
        self,
        state: &crate::state::AppState,
    ) -> std::result::Result<(), MucClusterEffectFailure> {
        let (stage, result) = match self {
            Self::FanOut {
                room,
                stanza,
                real_sender,
                stage,
            } => (
                stage,
                state
                    .publish_muc_cluster_stanza(&room, &stanza, real_sender.as_deref())
                    .await,
            ),
            Self::Evict {
                occupant,
                status,
                actor_nick,
                reason,
                stage,
            } => (
                stage,
                state
                    .evict_cluster_muc_occupant(
                        &occupant,
                        status,
                        actor_nick.as_deref(),
                        reason.as_deref(),
                    )
                    .await,
            ),
            Self::Leave { room, stage } => (stage, state.leave_cluster_muc_room(&room).await),
            Self::Register {
                room,
                nick,
                json,
                stage,
            } => (
                stage,
                state
                    .register_cluster_muc_occupant(&room, &nick, &json)
                    .await
                    .map(|_| ()),
            ),
            Self::Presence {
                room,
                occupant,
                unavailable,
                created,
                removal_status,
                actor_nick,
                reason,
                stage,
            } => (
                stage,
                state
                    .publish_muc_cluster_presence(MucPresencePublication {
                        room: &room,
                        occupant: &occupant,
                        unavailable,
                        created,
                        removal_status,
                        actor_nick: actor_nick.as_deref(),
                        reason: reason.as_deref(),
                    })
                    .await,
            ),
        };
        result.map_err(|error| MucClusterEffectFailure { stage, error })
    }
}

fn record_muc_post_commit_failure(
    state: &crate::state::AppState,
    room: &str,
    recipient: &str,
    stage: &str,
) {
    state.muc_telemetry().post_commit_failure();
    tracing::warn!(room, recipient, stage, "post-commit MUC side effect failed");
}

async fn run_muc_cluster_effects<const CAPACITY: usize>(
    state: &crate::state::AppState,
    room: &str,
    plan: MucPostCommitPlan<MucClusterEffect, CAPACITY>,
) {
    plan.run(
        |effect| effect.execute(state),
        |failure| {
            let MucClusterEffectFailure { stage, error } = failure;
            record_muc_post_commit_failure(state, room, "*", stage);
            tracing::warn!(room, stage, ?error, "ordered MUC post-commit effect failed");
        },
    )
    .await;
}

async fn run_muc_cluster_fan_out(
    state: &crate::state::AppState,
    room: &str,
    stanza: &str,
    real_sender: Option<&str>,
    stage: &'static str,
) {
    let mut plan = MucPostCommitPlan::<MucClusterEffect, 1>::new();
    plan.try_push(MucClusterEffect::FanOut {
        room: room.to_owned(),
        stanza: stanza.to_owned(),
        real_sender: real_sender.map(str::to_owned),
        stage,
    })
    .expect("a one-effect MUC post-commit plan has capacity");
    run_muc_cluster_effects(state, room, plan).await;
}

async fn run_muc_cluster_eviction(
    state: &crate::state::AppState,
    room: &str,
    occupant: crate::services::muc::SerializableMucOccupant,
    status: u16,
    actor_nick: Option<&str>,
    reason: Option<&str>,
    leave_if_empty: bool,
) {
    let mut plan = MucPostCommitPlan::<MucClusterEffect, 3>::new();
    plan.try_push(MucClusterEffect::Evict {
        occupant: occupant.clone(),
        status,
        actor_nick: actor_nick.map(str::to_owned),
        reason: reason.map(str::to_owned),
        stage: "cluster occupant eviction",
    })
    .expect("a three-effect MUC post-commit plan has eviction capacity");
    if leave_if_empty {
        plan.try_push(MucClusterEffect::Leave {
            room: room.to_owned(),
            stage: "cluster room departure",
        })
        .expect("a three-effect MUC post-commit plan has departure capacity");
    }
    plan.try_push(MucClusterEffect::Presence {
        room: room.to_owned(),
        occupant,
        unavailable: true,
        created: false,
        removal_status: Some(status),
        actor_nick: actor_nick.map(str::to_owned),
        reason: reason.map(str::to_owned),
        stage: "cluster eviction presence",
    })
    .expect("a three-effect MUC post-commit plan has presence capacity");
    run_muc_cluster_effects(state, room, plan).await;
}

async fn run_muc_cluster_occupant_refresh(
    state: &crate::state::AppState,
    room: &str,
    nick: &str,
    json: String,
    occupant: crate::services::muc::SerializableMucOccupant,
) {
    let mut plan = MucPostCommitPlan::<MucClusterEffect, 2>::new();
    plan.try_push(MucClusterEffect::Register {
        room: room.to_owned(),
        nick: nick.to_owned(),
        json,
        stage: "cluster occupant refresh",
    })
    .expect("a two-effect MUC post-commit plan has refresh capacity");
    plan.try_push(MucClusterEffect::Presence {
        room: room.to_owned(),
        occupant,
        unavailable: false,
        created: false,
        removal_status: None,
        actor_nick: None,
        reason: None,
        stage: "cluster policy presence",
    })
    .expect("a two-effect MUC post-commit plan has presence capacity");
    run_muc_cluster_effects(state, room, plan).await;
}

pub(super) fn muc_voice_request(room_jid: &str, full_jid: &str, nick: &str) -> String {
    XmlElement::new("message")
        .attr("from", room_jid)
        .attr("type", "normal")
        .attr("id", uuid::Uuid::new_v4())
        .child(
            XmlElement::namespaced("x", "jabber:x:data")
                .attr("type", "form")
                .child(XmlElement::new("title").text("Voice request"))
                .child(
                    XmlElement::new("instructions")
                        .text("Approve this request to grant the occupant voice."),
                )
                .child(xdata_value_field(
                    "FORM_TYPE",
                    "hidden",
                    "http://jabber.org/protocol/muc#request",
                ))
                .child(xdata_value_field("muc#role", "list-single", "participant"))
                .child(xdata_value_field("muc#jid", "jid-single", full_jid))
                .child(xdata_value_field("muc#roomnick", "text-single", nick))
                .child(xdata_value_field("muc#request_allow", "boolean", "false")),
        )
        .finish()
}

#[cfg(test)]
fn can_retrieve_muc_affiliation_list(
    requester_affiliation: &str,
    requested_affiliation: &str,
    members_only: bool,
    non_anonymous: bool,
) -> bool {
    let (Some(requester), Some(requested)) = (
        northstar_xep_0045::Affiliation::from_str_name(requester_affiliation),
        northstar_xep_0045::Affiliation::from_str_name(requested_affiliation),
    ) else {
        return false;
    };
    northstar_xep_0045::evaluate_affiliation_list_access(
        requester,
        requested,
        members_only,
        non_anonymous,
    ) == northstar_xep_0045::PermissionDecision::Allowed
}

pub(super) fn should_broadcast_offline_affiliation_change(
    non_anonymous: bool,
    target_is_occupant: bool,
    previous_affiliation: &str,
    new_affiliation: &str,
) -> bool {
    let (Some(previous), Some(new)) = (
        northstar_xep_0045::Affiliation::from_str_name(previous_affiliation),
        northstar_xep_0045::Affiliation::from_str_name(new_affiliation),
    ) else {
        return false;
    };
    northstar_xep_0045::should_broadcast_offline_affiliation_change(
        non_anonymous,
        target_is_occupant,
        previous,
        new,
    )
}

pub(crate) fn muc_offline_affiliation_change_notice(
    room_jid: &str,
    target_bare_jid: &str,
    affiliation: &str,
    nick: Option<&str>,
    reason: Option<&str>,
) -> String {
    let mut item = XmlElement::new("item")
        .attr("affiliation", affiliation)
        .attr("jid", target_bare_jid)
        .attr("role", "none")
        .optional_attr("nick", nick);
    if let Some(reason) = reason {
        item.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    XmlElement::namespaced("message", "jabber:client")
        .attr("from", room_jid)
        .attr("type", "normal")
        .child(XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user").child(item))
        .finish()
}

pub(super) async fn deliver_muc_offline_affiliation_change_notice(
    state: &crate::state::AppState,
    room_jid: &str,
    target_bare_jid: &str,
    affiliation: &str,
    nick: Option<&str>,
    reason: Option<&str>,
) {
    let notice =
        muc_offline_affiliation_change_notice(room_jid, target_bare_jid, affiliation, nick, reason);
    for (_, recipient) in state.muc_occupants_for(room_jid) {
        let delivery = set_to(&notice, &recipient.full_jid);
        if !state.deliver_to_muc_occupant(&recipient, delivery).await {
            record_muc_post_commit_failure(
                state,
                room_jid,
                &recipient.full_jid,
                "offline-affiliation-notice",
            );
        }
    }
    if let Err(error) = state
        .publish_muc_cluster_stanza(room_jid, &notice, None)
        .await
    {
        state.muc_telemetry().post_commit_failure();
        tracing::warn!(
            room = %room_jid,
            target = %target_bare_jid,
            ?error,
            "failed to broadcast offline MUC affiliation change"
        );
    }
}

pub(super) fn canonical_local_muc_room(
    value: &str,
    expected_domain: &str,
) -> Option<(String, String)> {
    let room = CanonicalJid::parse_bare(value).ok()?;
    let expected_domain = prepare_domainpart(expected_domain).ok()?;
    let localpart = room.localpart()?;
    if room.domainpart() != expected_domain || !valid_muc_room(localpart) {
        return None;
    }
    Some((room.to_string(), localpart.to_owned()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MucHistoryRequest {
    pub(super) max_stanzas: usize,
    pub(super) max_chars: Option<usize>,
    pub(super) since: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for MucHistoryRequest {
    fn default() -> Self {
        Self {
            max_stanzas: 20,
            max_chars: None,
            since: None,
        }
    }
}

/// Parse the four XEP-0045 history controls.  The service applies its normal
/// 20-stanza policy when no smaller explicit bound is supplied and caps every
/// request at 100 complete stanzas.
pub(super) fn parse_muc_history_request(
    root: Node<'_, '_>,
    now: chrono::DateTime<chrono::Utc>,
) -> std::result::Result<MucHistoryRequest, ()> {
    let muc_extensions = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
        })
        .collect::<Vec<_>>();
    if muc_extensions.len() > 1 {
        return Err(());
    }
    let Some(extension) = muc_extensions.first().copied() else {
        return Ok(MucHistoryRequest::default());
    };
    let histories = extension
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "history")
        .collect::<Vec<_>>();
    if histories.is_empty() {
        return Ok(MucHistoryRequest::default());
    }
    if histories.len() != 1 {
        return Err(());
    }
    let history = histories[0];
    if history.children().any(|node| node.is_element())
        || history.text().is_some_and(|text| !text.trim().is_empty())
        || history.attributes().any(|attribute| {
            !matches!(
                attribute.name(),
                "maxchars" | "maxstanzas" | "seconds" | "since"
            )
        })
    {
        return Err(());
    }

    let parse_nonnegative = |name: &str| -> std::result::Result<Option<u64>, ()> {
        history
            .attribute(name)
            .map(|value| {
                if value.is_empty() || value.starts_with('+') {
                    return Err(());
                }
                value.parse::<u64>().map_err(|_| ())
            })
            .transpose()
    };
    let max_stanzas = parse_nonnegative("maxstanzas")?
        .map(|value| value.min(100) as usize)
        .unwrap_or(20);
    let max_chars = parse_nonnegative("maxchars")?.map(|value| value.min(4 * 1024 * 1024) as usize);
    let seconds_since = parse_nonnegative("seconds")?.map(|seconds| {
        let seconds = seconds.min(i64::MAX as u64) as i64;
        now.checked_sub_signed(chrono::Duration::seconds(seconds))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)
    });
    let explicit_since = history
        .attribute("since")
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(value)
                .map(|value| value.with_timezone(&chrono::Utc))
                .map_err(|_| ())
        })
        .transpose()?;
    let since = match (seconds_since, explicit_since) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    };
    Ok(MucHistoryRequest {
        max_stanzas,
        max_chars,
        since,
    })
}

pub(super) fn apply_muc_history_bounds(
    mut stanzas: Vec<String>,
    request: MucHistoryRequest,
) -> Vec<String> {
    if stanzas.len() > request.max_stanzas {
        stanzas.drain(..stanzas.len() - request.max_stanzas);
    }
    if let Some(max_chars) = request.max_chars {
        let mut used = 0usize;
        let mut keep_from = stanzas.len();
        for (index, stanza) in stanzas.iter().enumerate().rev() {
            let next = used.saturating_add(stanza.chars().count());
            if next > max_chars {
                break;
            }
            used = next;
            keep_from = index;
        }
        stanzas.drain(..keep_from);
    }
    stanzas
}

pub(super) fn current_muc_subject_stanza(
    room: &MucRoom,
    room_jid: &str,
    recipient: &str,
) -> String {
    let changed_at = room
        .subject_changed_at
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    northstar_xep_0045::build_subject_message(
        room_jid,
        recipient,
        room.subject.as_deref().unwrap_or_default(),
        changed_at.as_deref(),
    )
}

pub(super) fn is_allowed_muc_presence_payload_namespace(namespace: &str) -> bool {
    northstar_xep_0045::is_allowed_muc_presence_payload_namespace(namespace)
}

pub(super) fn parse_muc_origin_id(root: Node<'_, '_>) -> std::result::Result<Option<String>, ()> {
    let mut origin_id = None;
    for child in root.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "origin-id"
            && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
    }) {
        if origin_id.is_some()
            || child.attributes().any(|attribute| attribute.name() != "id")
            || child.children().any(|node| node.is_element())
            || child.text().is_some_and(|text| !text.trim().is_empty())
        {
            return Err(());
        }
        let id = child.attribute("id").ok_or(())?;
        if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
            return Err(());
        }
        origin_id = Some(id.to_owned());
    }
    Ok(origin_id)
}

/// A subject mutation is a subject-only groupchat command.  A message that
/// also has body/thread content remains an ordinary discussion stanza and
/// cannot accidentally mutate persistent room state.
pub(super) fn parse_muc_subject_command(
    root: Node<'_, '_>,
) -> std::result::Result<Option<String>, ()> {
    northstar_xep_0045::parse_subject_command(root).map_err(|_| ())
}

pub(super) fn parse_muc_author_retraction(
    root: Node<'_, '_>,
) -> std::result::Result<Option<uuid::Uuid>, ()> {
    let direct = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "retract"
                && node.tag_name().namespace() == Some("urn:xmpp:message-retract:1")
        })
        .collect::<Vec<_>>();
    let apply_to = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "apply-to"
                && node.tag_name().namespace() == Some("urn:xmpp:fasten:0")
        })
        .collect::<Vec<_>>();
    if direct.len() > 1 || (!direct.is_empty() && !apply_to.is_empty()) {
        return Err(());
    }
    if let Some(retract) = direct.first().copied() {
        if retract
            .attributes()
            .any(|attribute| attribute.name() != "id")
            || retract.children().any(|node| node.is_element())
            || retract.text().is_some_and(|text| !text.trim().is_empty())
            || root.children().any(|node| {
                node.is_element()
                    && matches!(node.tag_name().name(), "subject" | "thread")
                    && node
                        .tag_name()
                        .namespace()
                        .is_none_or(|namespace| namespace == "jabber:client")
            })
        {
            return Err(());
        }
        let target = retract.attribute("id").ok_or(())?;
        let target = uuid::Uuid::parse_str(target).map_err(|_| ())?;
        if target.to_string() != retract.attribute("id").unwrap_or_default() {
            return Err(());
        }
        return Ok(Some(target));
    }
    if apply_to.is_empty() {
        return Ok(None);
    }
    if apply_to.len() != 1
        || apply_to[0]
            .attributes()
            .any(|attribute| attribute.name() != "id")
        || root.children().any(|node| {
            node.is_element()
                && matches!(node.tag_name().name(), "body" | "subject" | "thread")
                && node
                    .tag_name()
                    .namespace()
                    .is_none_or(|namespace| namespace == "jabber:client")
        })
    {
        return Err(());
    }
    let children = apply_to[0]
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if children.len() != 1
        || children[0].tag_name().name() != "retract"
        || children[0].tag_name().namespace() != Some("urn:xmpp:message-retract:1")
        || children[0].attributes().len() != 0
        || children[0].children().any(|node| node.is_element())
        || children[0]
            .text()
            .is_some_and(|text| !text.trim().is_empty())
    {
        return Err(());
    }
    let target = apply_to[0].attribute("id").ok_or(())?;
    let target = uuid::Uuid::parse_str(target).map_err(|_| ())?;
    if target.to_string() != apply_to[0].attribute("id").unwrap_or_default() {
        return Err(());
    }
    Ok(Some(target))
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum MucVoiceForm {
    Request,
    Approval {
        jid: String,
        nick: String,
        allow: bool,
    },
}

pub(super) fn parse_muc_invitation_decline(
    root: Node<'_, '_>,
) -> std::result::Result<Option<(String, Option<String>)>, ()> {
    let declines = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
        })
        .flat_map(|extension| {
            extension.children().filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "decline"
                    && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
            })
        })
        .collect::<Vec<_>>();
    if declines.is_empty() {
        return Ok(None);
    }
    if declines.len() != 1
        || declines[0]
            .attributes()
            .any(|attribute| attribute.name() != "to")
    {
        return Err(());
    }
    let target = CanonicalJid::parse(declines[0].attribute("to").ok_or(())?)
        .map_err(|_| ())?
        .to_string();
    let children = declines[0]
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if children.len() > 1
        || children.first().is_some_and(|node| {
            node.tag_name().name() != "reason"
                || node.tag_name().namespace() != Some("http://jabber.org/protocol/muc#user")
                || node.children().any(|child| child.is_element())
        })
    {
        return Err(());
    }
    let reason = children
        .first()
        .and_then(|reason| reason.text())
        .filter(|reason| !reason.is_empty())
        .map(str::to_owned);
    Ok(Some((target, reason)))
}

pub(super) fn parse_muc_voice_form(
    root: Node<'_, '_>,
) -> std::result::Result<Option<MucVoiceForm>, ()> {
    let candidates = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:data")
                && xdata_field(*node, "FORM_TYPE") == Some("http://jabber.org/protocol/muc#request")
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(None);
    }
    if candidates.len() != 1 || candidates[0].attribute("type") != Some("submit") {
        return Err(());
    }
    let form = candidates[0];
    let fields = form
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "field")
        .collect::<Vec<_>>();
    let mut names = std::collections::HashSet::new();
    if fields.iter().any(|field| {
        field
            .attribute("var")
            .is_none_or(|name| !names.insert(name))
    }) {
        return Err(());
    }
    if xdata_field(form, "muc#role") != Some("participant") {
        return Err(());
    }
    let has_approval_fields = ["muc#jid", "muc#roomnick", "muc#request_allow"]
        .iter()
        .any(|name| names.contains(name));
    if !has_approval_fields {
        if names.len() != 2 || !names.contains("FORM_TYPE") || !names.contains("muc#role") {
            return Err(());
        }
        return Ok(Some(MucVoiceForm::Request));
    }
    if names.len() != 5
        || ![
            "FORM_TYPE",
            "muc#role",
            "muc#jid",
            "muc#roomnick",
            "muc#request_allow",
        ]
        .iter()
        .all(|name| names.contains(name))
    {
        return Err(());
    }
    let jid = CanonicalJid::parse(xdata_field(form, "muc#jid").ok_or(())?).map_err(|_| ())?;
    if jid.localpart().is_none() || jid.resourcepart().is_none() {
        return Err(());
    }
    let nick = prepare_muc_nick(xdata_field(form, "muc#roomnick").ok_or(())?).map_err(|_| ())?;
    let allow = match xdata_field(form, "muc#request_allow").ok_or(())? {
        "1" | "true" => true,
        "0" | "false" => false,
        _ => return Err(()),
    };
    Ok(Some(MucVoiceForm::Approval {
        jid: jid.to_string(),
        nick,
        allow,
    }))
}

impl ProtocolSession {
    /// Return the room actor only when the private session marker, the live
    /// route, and the shared occupant record all describe the same immutable
    /// occupancy incarnation.
    pub(crate) fn validated_muc_occupant(
        &self,
        room_jid: &str,
    ) -> Option<crate::xmpp::local_routes::muc::MucOccupant> {
        let full_jid = self.full_jid.as_deref()?;
        let membership = self
            .joined_rooms
            .get(room_jid)
            .map(|membership| membership.value().clone())?;
        self.state
            .validated_local_muc_occupant(full_jid, self.connection_id, room_jid, &membership)
    }

    /// A local session marker alone does not authorize a room mutation. The
    /// exact PostgreSQL occupancy must still be live; Redis only caches it.
    pub(crate) async fn authorized_muc_occupant(
        &self,
        room_jid: &str,
    ) -> Result<Option<crate::xmpp::local_routes::muc::MucOccupant>> {
        let Some(occupant) = self.validated_muc_occupant(room_jid) else {
            return Ok(None);
        };
        if !self.state.muc_pg_authority_enabled() {
            return Ok(Some(occupant));
        }
        let Some((_, room_localpart)) = canonical_local_muc_room(room_jid, &self.muc_domain())
        else {
            return Ok(None);
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(None);
        };
        let Some(target) = self
            .state
            .muc_service()
            .local_cluster_occupancy_target(room.id, occupant.cluster_epoch, occupant.connection_id)
            .await?
        else {
            self.state.muc_telemetry().authority_rejected();
            return Ok(None);
        };
        if target.room_epoch != room.room_epoch
            || target.full_jid != occupant.full_jid
            || target.nick != occupant.nick
            || !self
                .state
                .muc_service()
                .renew_local_cluster_occupancy(
                    &target,
                    self.state.muc_cluster_node_id(),
                    std::time::Duration::from_secs(90),
                )
                .await?
        {
            self.state.muc_telemetry().authority_rejected();
            return Ok(None);
        }
        Ok(Some(occupant))
    }

    pub(crate) fn muc_domain(&self) -> String {
        prepare_domainpart(&format!("conference.{}", self.state.local_domain()))
            .expect("configured XMPP domain must form a valid MUC service domain")
    }
}

#[cfg(test)]
#[path = "muc_tests.rs"]
mod tests;
