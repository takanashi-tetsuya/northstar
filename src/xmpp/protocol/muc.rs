use super::{Action, ProtocolSession};
use crate::services::muc::{
    ClusterMucAffiliationSubject, ClusterMucConfigurationOutcome, ClusterMucInviteAuthority,
    ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucPrincipal, ClusterMucRegistrationOutcome,
    ClusterMucTransitionOutcome, DurableMucInviteOutcome, MucActorAuthority, MucActorPrincipal,
    MucAdminSnapshot, MucAffiliationBatchOutcome, MucAffiliationChange, MucAffiliationTarget,
    MucConfigUpdate, MucConfigurationOutcome, MucDiscussion, MucDiscussionAdmission,
    MucRegistrationOutcome, MucRetractionKind, MucRetractionMutation, MucRetractionOutcome,
    MucRoom, MucSubjectMutation, OfflineStoreOutcome, OfflineStorePolicy,
};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use crate::{
    jid::{canonical_bare_key, prepare_domainpart, CanonicalJid},
    state::{bare_jid, localpart},
};
use anyhow::Result;
use roxmltree::Node;
use std::{collections::VecDeque, future::Future, sync::atomic::Ordering};

// Keep the live-session admission bound equal to the durable XEP-0198
// snapshot bound in the durable SM service. Rejecting the 257th room at join time is safer
// than discovering at disconnect that the session can no longer be resumed.
const MAX_JOINED_ROOMS_PER_SESSION: usize = 256;

/// A small, request-owned post-commit plan.
///
/// MUC mutations commit before their Redis wake/fan-out side effects run.  A
/// detached task per mutation is both unbounded and impossible to observe at
/// shutdown.  Keeping the plan request-owned gives us a hard capacity, strict
/// ordering and explicit failure accounting without holding a database
/// transaction across network I/O.
#[derive(Debug)]
struct MucPostCommitPlan<T, const CAPACITY: usize> {
    effects: VecDeque<T>,
    sealed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MucPostCommitAdmissionError {
    Full,
    Sealed,
}

impl<T, const CAPACITY: usize> MucPostCommitPlan<T, CAPACITY> {
    fn new() -> Self {
        Self {
            effects: VecDeque::with_capacity(CAPACITY),
            sealed: false,
        }
    }

    fn try_push(&mut self, effect: T) -> std::result::Result<(), MucPostCommitAdmissionError> {
        if self.sealed {
            return Err(MucPostCommitAdmissionError::Sealed);
        }
        if self.effects.len() >= CAPACITY {
            return Err(MucPostCommitAdmissionError::Full);
        }
        self.effects.push_back(effect);
        Ok(())
    }

    fn seal(&mut self) {
        self.sealed = true;
    }

    async fn run<E, Execute, ExecuteFuture, OnFailure>(
        mut self,
        mut execute: Execute,
        mut on_failure: OnFailure,
    ) where
        Execute: FnMut(T) -> ExecuteFuture,
        ExecuteFuture: Future<Output = std::result::Result<(), E>>,
        OnFailure: FnMut(E),
    {
        self.seal();
        while let Some(effect) = self.effects.pop_front() {
            if let Err(error) = execute(effect).await {
                // A failed best-effort wake must not reorder or suppress the
                // remaining committed effects.
                on_failure(error);
            }
        }
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
        occupant: crate::state::SerializableMucOccupant,
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
        occupant: crate::state::SerializableMucOccupant,
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
            } => {
                let result = if let Some(real_sender) = real_sender {
                    state
                        .cluster
                        .send_to_muc_from(&room, &stanza, &real_sender)
                        .await
                } else {
                    state.cluster.send_to_muc(&room, &stanza).await
                };
                (stage, result)
            }
            Self::Evict {
                occupant,
                status,
                actor_nick,
                reason,
                stage,
            } => (
                stage,
                state
                    .cluster
                    .evict_muc_occupant(&occupant, status, actor_nick.as_deref(), reason.as_deref())
                    .await
                    .map(|_| ()),
            ),
            Self::Leave { room, stage } => (stage, state.cluster.leave_muc(&room).await),
            Self::Register {
                room,
                nick,
                json,
                stage,
            } => (
                stage,
                state
                    .cluster
                    .register_muc_occupant(&room, &nick, &json)
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
                    .cluster
                    .send_muc_presence_with_status(
                        &room,
                        &occupant,
                        unavailable,
                        created,
                        None,
                        removal_status,
                        actor_nick.as_deref(),
                        reason.as_deref(),
                    )
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
    state
        .metrics
        .muc_post_commit_delivery_failures_total
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .post_accept_side_effect_failures_total
        .fetch_add(1, Ordering::Relaxed);
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
    occupant: crate::state::SerializableMucOccupant,
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
    occupant: crate::state::SerializableMucOccupant,
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

pub(super) fn muc_xdata_value_field(
    variable: &'static str,
    kind: &'static str,
    value: impl ToString,
) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .attr("type", kind)
        .child(XmlElement::new("value").text(value.to_string()))
}

fn muc_xdata_option(value: &'static str, label: Option<&'static str>) -> XmlElement {
    XmlElement::new("option")
        .optional_attr("label", label)
        .child(XmlElement::new("value").text(value))
}

pub(super) fn muc_room_configuration_form(room: &MucRoom, whois: &str) -> String {
    let allow_private_messages = if room.allow_private_messages {
        "anyone"
    } else {
        "none"
    };
    let allow_pm = muc_xdata_value_field(
        "muc#roomconfig_allowpm",
        "list-single",
        allow_private_messages,
    )
    .child(muc_xdata_option("anyone", None))
    .child(muc_xdata_option("none", None));
    let whois_field = muc_xdata_value_field("muc#roomconfig_whois", "list-single", whois)
        .child(muc_xdata_option("anyone", Some("Anyone")))
        .child(muc_xdata_option("moderators", Some("Moderators only")));
    let mut max_users =
        muc_xdata_value_field("muc#roomconfig_maxusers", "list-single", room.max_occupants);
    for value in ["10", "20", "50", "100", "500", "1000"] {
        max_users.push_child(muc_xdata_option(value, None));
    }
    let form = XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "form")
        .child(XmlElement::new("title").text("Room configuration"))
        .child(muc_xdata_value_field(
            "FORM_TYPE",
            "hidden",
            "http://jabber.org/protocol/muc#roomconfig",
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_roomname",
            "text-single",
            room.title.as_deref().unwrap_or(&room.localpart),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_roomdesc",
            "text-single",
            room.description.as_deref().unwrap_or_default(),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_persistentroom",
            "boolean",
            bool_value(room.persistent),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_membersonly",
            "boolean",
            bool_value(room.members_only),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_publicroom",
            "boolean",
            bool_value(room.public),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_moderatedroom",
            "boolean",
            bool_value(room.moderated),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_changesubject",
            "boolean",
            bool_value(room.allow_subject_change),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_allowinvites",
            "boolean",
            bool_value(room.allow_invites),
        ))
        .child(allow_pm)
        .child(muc_xdata_value_field(
            "muc#roomconfig_enablelogging",
            "boolean",
            bool_value(room.logging_enabled),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_allowregister",
            "boolean",
            bool_value(room.allow_registration),
        ))
        .child(whois_field)
        .child(max_users)
        .child(muc_xdata_value_field(
            "muc#roomconfig_passwordprotectedroom",
            "boolean",
            bool_value(room.password_hash.is_some()),
        ))
        .child(muc_xdata_value_field(
            "muc#roomconfig_roomsecret",
            "text-private",
            "",
        ));
    XmlElement::namespaced("query", "http://jabber.org/protocol/muc#owner")
        .child(form)
        .finish()
}

#[cfg(test)]
fn can_retrieve_muc_affiliation_list(
    requester_affiliation: &str,
    requested_affiliation: &str,
    members_only: bool,
    non_anonymous: bool,
) -> bool {
    if !matches!(
        requested_affiliation,
        "owner" | "admin" | "member" | "outcast"
    ) {
        return false;
    }

    if matches!(requester_affiliation, "owner" | "admin") {
        return true;
    }

    // XEP-0045 recommends making the member list available to members of a
    // members-only room. OMEMO clients also need the owner and admin lists so
    // that offline affiliates are included as encryption recipients. Limit
    // that wider visibility to members-only, non-anonymous rooms where real
    // JIDs are intentionally visible to every member.
    requester_affiliation == "member"
        && members_only
        && non_anonymous
        && matches!(requested_affiliation, "owner" | "admin" | "member")
}

pub(super) fn should_broadcast_offline_affiliation_change(
    non_anonymous: bool,
    target_is_occupant: bool,
    previous_affiliation: &str,
    new_affiliation: &str,
) -> bool {
    // XEP-0045 communicates an online affiliate's change with updated
    // presence. When the affiliate is offline, a room-origin normal message
    // is the interoperable equivalent consumed by existing clients. Never
    // expose the target's bare JID to occupants of a semi-anonymous room.
    non_anonymous && !target_is_occupant && previous_affiliation != new_affiliation
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
    if let Err(error) = state.cluster.send_to_muc(room_jid, &notice).await {
        state
            .metrics
            .muc_post_commit_delivery_failures_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .post_accept_side_effect_failures_total
            .fetch_add(1, Ordering::Relaxed);
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

#[derive(Debug, Eq, PartialEq)]
struct ModerationRequest {
    target_id: uuid::Uuid,
    reason: Option<String>,
}

fn parse_moderation_request(
    moderate: Node<'_, '_>,
) -> std::result::Result<ModerationRequest, &'static str> {
    if moderate.tag_name().name() != "moderate"
        || moderate.tag_name().namespace() != Some("urn:xmpp:message-moderate:1")
        || moderate
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
        || moderate
            .children()
            .filter(|child| child.is_text())
            .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("bad-request");
    }
    let target = moderate.attribute("id").ok_or("bad-request")?;
    let target_id = uuid::Uuid::parse_str(target).map_err(|_| "item-not-found")?;
    if target_id.to_string() != target {
        // Archive IDs are opaque. Accepting another spelling of the UUID
        // would make an identifier compare equal even though it was never
        // issued on the wire by this room.
        return Err("item-not-found");
    }
    let mut retract_seen = false;
    let mut reason = None;
    for child in moderate.children().filter(|child| child.is_element()) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("retract", Some("urn:xmpp:message-retract:1")) => {
                if retract_seen
                    || child.attributes().len() != 0
                    || child.children().any(|node| node.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                {
                    return Err("bad-request");
                }
                retract_seen = true;
            }
            ("reason", Some("urn:xmpp:message-moderate:1")) => {
                if reason.is_some()
                    || child.attributes().len() != 0
                    || child.children().any(|node| node.is_element())
                {
                    return Err("bad-request");
                }
                let value = child.text().unwrap_or_default().trim();
                if value.is_empty() {
                    return Err("bad-request");
                }
                if value.len() > 1_024 {
                    return Err("not-acceptable");
                }
                reason = Some(value.to_owned());
            }
            _ => return Err("bad-request"),
        }
    }
    if !retract_seen {
        return Err("bad-request");
    }
    Ok(ModerationRequest { target_id, reason })
}

fn muc_sender_is_blocked(
    patterns: &[String],
    owner_bare: &str,
    visible_sender: &str,
    real_sender: Option<&str>,
) -> bool {
    [Some(visible_sender), real_sender]
        .into_iter()
        .flatten()
        .filter(|sender| {
            crate::jid::canonical_bare_key(sender)
                .is_ok_and(|sender_bare| sender_bare != owner_bare)
        })
        .any(|sender| {
            patterns
                .iter()
                .any(|pattern| crate::services::blocking::BlockingService::matches(pattern, sender))
        })
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
    let mut message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", room_jid)
        .attr("to", recipient)
        .attr("type", "groupchat");
    if let Some(changed_at) = room.subject_changed_at {
        message.push_child(
            XmlElement::namespaced("delay", "urn:xmpp:delay")
                .attr("from", room_jid)
                .attr(
                    "stamp",
                    changed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                ),
        );
    }
    message
        .child(XmlElement::new("subject").text(room.subject.clone().unwrap_or_default()))
        .finish()
}

fn muc_presence_payload(root: Node<'_, '_>, raw: &str) -> String {
    let mut payload = String::new();
    for child in root.children().filter(|node| node.is_element()) {
        let namespace = child.tag_name().namespace().unwrap_or_default();
        if is_allowed_muc_presence_payload_namespace(namespace) {
            let range = child.range();
            payload.push_str(&raw[range.start..range.end]);
        }
    }
    payload
}

pub(super) fn is_allowed_muc_presence_payload_namespace(namespace: &str) -> bool {
    !matches!(
        namespace,
        "http://jabber.org/protocol/muc"
            | "http://jabber.org/protocol/muc#user"
            | "http://jabber.org/protocol/muc#admin"
            | "http://jabber.org/protocol/muc#owner"
            | "urn:xmpp:occupant-id:0"
            | "urn:xmpp:sid:0"
            | "urn:xmpp:delay"
            | "jabber:x:delay"
    )
}

fn has_muc_join_extension(root: Node<'_, '_>) -> bool {
    root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "x"
            && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
    })
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
    let has_discussion_content = root.children().any(|node| {
        node.is_element()
            && matches!(node.tag_name().name(), "body" | "thread")
            && node
                .tag_name()
                .namespace()
                .is_none_or(|namespace| namespace == "jabber:client")
    });
    if has_discussion_content {
        return Ok(None);
    }
    let subjects = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "subject"
                && node
                    .tag_name()
                    .namespace()
                    .is_none_or(|namespace| namespace == "jabber:client")
        })
        .collect::<Vec<_>>();
    if subjects.is_empty() {
        return Ok(None);
    }
    if subjects.len() != 1
        || subjects[0].attributes().len() != 0
        || subjects[0].children().any(|node| node.is_element())
    {
        return Err(());
    }
    Ok(Some(subjects[0].text().unwrap_or_default().to_owned()))
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
    ) -> Option<crate::state::MucOccupant> {
        let full_jid = self.full_jid.as_deref()?;
        let membership = self
            .joined_rooms
            .get(room_jid)
            .map(|membership| membership.value().clone())?;
        self.state
            .validated_local_muc_occupant(full_jid, self.connection_id, room_jid, &membership)
    }

    /// In clustered mode, the local identity proof is necessary but not
    /// sufficient: the exact PostgreSQL occupancy incarnation is the
    /// cross-node authority. Redis is deliberately not consulted here; a
    /// cached nickname must never authorize a room mutation after its lease,
    /// room epoch, connection UUID or occupancy incarnation changed.
    pub(crate) async fn authorized_muc_occupant(
        &self,
        room_jid: &str,
    ) -> Result<Option<crate::state::MucOccupant>> {
        let Some(occupant) = self.validated_muc_occupant(room_jid) else {
            return Ok(None);
        };
        if !self.state.cluster.is_enabled() {
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
            self.state
                .metrics
                .cluster_muc_authority_rejections_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                    &self.state.cluster.node_id,
                    std::time::Duration::from_secs(90),
                )
                .await?
        {
            self.state
                .metrics
                .cluster_muc_authority_rejections_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(None);
        }
        Ok(Some(occupant))
    }

    pub(crate) async fn muc_register_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        if !room.allow_registration {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-allowed")));
        }
        let payload = if let Some(nick) = self
            .state
            .muc_service()
            .local_reserved_nick(room.id, user.id)
            .await?
        {
            XmlElement::namespaced("query", "jabber:iq:register")
                .child(XmlElement::new("registered"))
                .child(XmlElement::new("username").text(nick))
                .finish()
        } else {
            let title = format!(
                "{} Registration",
                room.title.as_deref().unwrap_or(&room.localpart)
            );
            XmlElement::namespaced("query", "jabber:iq:register")
                .child(
                    XmlElement::namespaced("x", "jabber:x:data")
                        .attr("type", "form")
                        .child(XmlElement::new("title").text(title))
                        .child(
                            XmlElement::new("instructions")
                                .text("Choose the nickname to reserve in this room."),
                        )
                        .child(muc_xdata_value_field(
                            "FORM_TYPE",
                            "hidden",
                            "http://jabber.org/protocol/muc#register",
                        ))
                        .child(
                            XmlElement::new("field")
                                .attr("var", "muc#register_roomnick")
                                .attr("type", "text-single")
                                .child(XmlElement::new("required")),
                        ),
                )
                .finish()
        };
        Ok(Action::Send(iq_result_from(id, &room_jid, &payload)))
    }

    pub(crate) async fn muc_register_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if self.full_jid.is_none() {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        }
        let Some((room_jid, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let Some(initial_room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        let gated_room_id = initial_room.id;
        let gated_room_epoch = initial_room.room_epoch;
        let _local_room_guard = if self.state.cluster.is_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await,
            )
        };
        // The initial snapshot only identifies the room gate. Re-read all
        // mutable policy after acquiring it so a concurrent owner/admin
        // command cannot commit a new access model while this request applies
        // stale in-memory side effects.
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        if room.id != gated_room_id || room.room_epoch != gated_room_epoch {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        }
        if !room.allow_registration {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-allowed")));
        }
        let requester_bare = format!("{}@{}", user.username, self.state.config.domain);
        let elements = query
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if elements.len() == 1
            && elements[0].tag_name().name() == "remove"
            && elements[0].tag_name().namespace() == Some("jabber:iq:register")
            && !elements[0].children().any(|node| node.is_element())
        {
            if self.state.cluster.is_enabled() {
                self.state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                let Some(full_jid) = self.full_jid.as_deref() else {
                    return Ok(Action::Send(iq_error_from(id, &room_jid, "not-authorized")));
                };
                let operation_id = uuid::Uuid::new_v4();
                let outcome = self
                    .state
                    .muc_service()
                    .mutate_local_cluster_registration(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        room.config_version,
                        &ClusterMucPrincipal::Local {
                            user_id: user.id,
                            bare_jid: requester_bare.clone(),
                        },
                        full_jid,
                        None,
                    )
                    .await?;
                return match outcome {
                    ClusterMucRegistrationOutcome::Applied { .. }
                    | ClusterMucRegistrationOutcome::Replay { .. } => {
                        self.state
                            .muc_service()
                            .wake_committed_operation(&self.state.cluster, operation_id)
                            .await?;
                        Ok(Action::Send(iq_result_from(id, &room_jid, "")))
                    }
                    ClusterMucRegistrationOutcome::Outcast
                    | ClusterMucRegistrationOutcome::NotAllowed => {
                        Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")))
                    }
                    ClusterMucRegistrationOutcome::Conflict => {
                        Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")))
                    }
                    ClusterMucRegistrationOutcome::Stale
                    | ClusterMucRegistrationOutcome::Destroyed => {
                        Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")))
                    }
                };
            }
            let affiliation_changed = self
                .state
                .muc_service()
                .unregister_local_member(room.id, user.id)
                .await?;
            let affiliation = self
                .state
                .muc_service()
                .local_affiliation(room.id, user.id)
                .await?
                .unwrap_or_else(|| "none".to_owned());
            let mut target_is_occupant = false;
            if let Some(joined) = self.joined_rooms.get(&room_jid) {
                let joined_nick = joined.nick.clone();
                drop(joined);
                let key = muc_occupant_key(&room_jid, &joined_nick);
                if let Some(mut occupant) = self.state.muc_occupants.get_mut(&key) {
                    target_is_occupant = true;
                    occupant.affiliation = affiliation;
                    occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                        "moderator"
                    } else if room.moderated && occupant.affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    }
                    .to_owned();
                    let updated = crate::state::SerializableMucOccupant::from(&*occupant);
                    let updated_json = serde_json::to_string(&updated)?;
                    drop(occupant);
                    let _ = self
                        .state
                        .cluster
                        .register_muc_occupant(&room_jid, &joined_nick, &updated_json)
                        .await;
                    for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                        let self_presence = recipient.full_jid == updated.full_jid;
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            room.non_anonymous || self_presence || recipient.role == "moderator",
                        );
                        let _ = self
                            .state
                            .deliver_to_muc_occupant(&recipient, presence)
                            .await;
                    }
                }
            }
            if affiliation_changed
                && should_broadcast_offline_affiliation_change(
                    room.non_anonymous,
                    target_is_occupant,
                    "member",
                    "none",
                )
            {
                deliver_muc_offline_affiliation_change_notice(
                    &self.state,
                    &room_jid,
                    &requester_bare,
                    "none",
                    None,
                    None,
                )
                .await;
            }
            return Ok(Action::Send(iq_result_from(id, &room_jid, "")));
        }
        if elements.len() != 1
            || elements[0].tag_name().name() != "x"
            || elements[0].tag_name().namespace() != Some("jabber:x:data")
            || elements[0].attribute("type") != Some("submit")
            || xdata_field(elements[0], "FORM_TYPE")
                != Some("http://jabber.org/protocol/muc#register")
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "bad-request")));
        }
        let Some(nick) = xdata_field(elements[0], "muc#register_roomnick") else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "bad-request")));
        };
        let Ok(nick) = prepare_muc_nick(nick) else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-acceptable")));
        };
        if self.state.cluster.is_enabled() {
            self.state
                .cluster
                .admit(crate::cluster::ClusterOperation::MucMutation)?;
            let Some(full_jid) = self.full_jid.as_deref() else {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "not-authorized")));
            };
            let operation_id = uuid::Uuid::new_v4();
            let outcome = self
                .state
                .muc_service()
                .mutate_local_cluster_registration(
                    operation_id,
                    room.id,
                    room.room_epoch,
                    room.config_version,
                    &ClusterMucPrincipal::Local {
                        user_id: user.id,
                        bare_jid: requester_bare.clone(),
                    },
                    full_jid,
                    Some(&nick),
                )
                .await?;
            return match outcome {
                ClusterMucRegistrationOutcome::Applied { .. }
                | ClusterMucRegistrationOutcome::Replay { .. } => {
                    self.state
                        .muc_service()
                        .wake_committed_operation(&self.state.cluster, operation_id)
                        .await?;
                    Ok(Action::Send(iq_result_from(id, &room_jid, "")))
                }
                ClusterMucRegistrationOutcome::Conflict => {
                    Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")))
                }
                ClusterMucRegistrationOutcome::Outcast
                | ClusterMucRegistrationOutcome::NotAllowed => {
                    Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")))
                }
                ClusterMucRegistrationOutcome::Stale | ClusterMucRegistrationOutcome::Destroyed => {
                    Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")))
                }
            };
        }
        let occupants = self
            .state
            .cluster
            .get_muc_occupants(&room_jid)
            .await
            .unwrap_or_default();
        if occupants.get(&nick).is_some_and(|json| {
            serde_json::from_str::<crate::state::SerializableMucOccupant>(json)
                .ok()
                .is_some_and(|occupant| bare_jid(&occupant.full_jid) != requester_bare)
        }) || self
            .state
            .muc_occupants_for(&room_jid)
            .iter()
            .any(|(_, occupant)| {
                occupant.nick == nick && bare_jid(&occupant.full_jid) != requester_bare
            })
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
        }
        let affiliation_changed = match self
            .state
            .muc_service()
            .register_local_member(room.id, user.id, &nick)
            .await?
        {
            MucRegistrationOutcome::Registered {
                affiliation_changed,
            } => affiliation_changed,
            MucRegistrationOutcome::Conflict => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
            }
            MucRegistrationOutcome::Outcast => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
            }
        };
        let mut target_is_occupant = false;
        if let Some(joined) = self.joined_rooms.get(&room_jid) {
            let joined_nick = joined.nick.clone();
            drop(joined);
            let key = muc_occupant_key(&room_jid, &joined_nick);
            if let Some(mut occupant) = self.state.muc_occupants.get_mut(&key) {
                target_is_occupant = true;
                if occupant.affiliation == "none" {
                    occupant.affiliation = "member".to_owned();
                    if room.moderated {
                        occupant.role = "participant".to_owned();
                    }
                }
                let updated = crate::state::SerializableMucOccupant::from(&*occupant);
                let updated_json = serde_json::to_string(&updated)?;
                drop(occupant);
                let _ = self
                    .state
                    .cluster
                    .register_muc_occupant(&room_jid, &joined_nick, &updated_json)
                    .await;
                for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                    let self_presence = recipient.full_jid == updated.full_jid;
                    let presence = muc_presence_stanza(
                        &updated,
                        &recipient.full_jid,
                        false,
                        self_presence,
                        false,
                        None,
                        room.non_anonymous || self_presence || recipient.role == "moderator",
                    );
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&recipient, presence)
                        .await;
                }
            }
        }
        if affiliation_changed
            && should_broadcast_offline_affiliation_change(
                room.non_anonymous,
                target_is_occupant,
                "none",
                "member",
            )
        {
            deliver_muc_offline_affiliation_change_notice(
                &self.state,
                &room_jid,
                &requester_bare,
                "member",
                Some(&nick),
                None,
            )
            .await;
        }
        Ok(Action::Send(iq_result_from(id, &room_jid, "")))
    }

    pub(crate) async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        let Some(from) = self.full_jid.as_deref() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(to) = root.attribute("to") else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        let Ok(to_jid) = crate::jid::CanonicalJid::parse(to) else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        if to_jid.domainpart() != self.muc_domain() || to_jid.localpart().is_none() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "jid-malformed",
            )));
        }
        let room_jid = to_jid.bare();
        let decline = match parse_muc_invitation_decline(root) {
            Ok(decline) => decline,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        if let Some((target_raw, reason)) = decline {
            if to_jid.resourcepart().is_some()
                || !matches!(root.attribute("type"), None | Some("normal"))
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
            if self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
                .is_none()
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            }
            let target = CanonicalJid::parse(&target_raw).map_err(|error| {
                anyhow::anyhow!("validated MUC decline target became invalid: {error}")
            })?;
            let mut decline = XmlElement::new("decline").attr("from", bare_jid(from));
            if let Some(reason) = reason.as_deref() {
                decline.push_child(XmlElement::new("reason").text(reason.to_owned()));
            }
            let extension =
                XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user").child(decline);
            let hints = processing_hints_fragment(root, raw);
            let temporary_storage = offline_storage_permitted(root);
            let forwarded = XmlElement::new("message")
                .attr("from", &room_jid)
                .attr("to", &target_raw)
                .attr("type", "normal")
                .attr(
                    "id",
                    root.attribute("id")
                        .filter(|id| !id.is_empty() && id.len() <= 128)
                        .unwrap_or("muc-decline"),
                )
                .child(extension)
                .validated_fragment(&hints)?
                .finish();
            if target.domainpart() == self.muc_domain()
                && target.bare() == room_jid
                && target.resourcepart().is_some()
            {
                let nick = target
                    .resourcepart()
                    .expect("decline occupant resource checked");
                let key = muc_occupant_key(&room_jid, nick);
                if let Some(recipient) = self
                    .state
                    .muc_occupants
                    .get(&key)
                    .map(|entry| entry.value().clone())
                {
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&recipient, forwarded.clone())
                        .await;
                }
                self.state
                    .cluster
                    .send_muc_private_from(&room_jid, nick, &forwarded, from)
                    .await?;
                return Ok(Action::None);
            }
            if target.domainpart() == self.state.config.domain {
                let Some(username) = target.localpart() else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "modify",
                        "jid-malformed",
                    )));
                };
                let Some(recipient) = self
                    .state
                    .muc_service()
                    .enabled_local_account(username)
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                };
                if self
                    .state
                    .muc_service()
                    .is_blocked_for_account(recipient.id, &target.bare(), &room_jid)
                    .await?
                    || self
                        .state
                        .muc_service()
                        .is_blocked_for_account(recipient.id, &target.bare(), from)
                        .await?
                {
                    return Ok(Action::None);
                }
                let mut sessions = self.state.session_entries_for(&target_raw);
                if target.resourcepart().is_none() {
                    sessions.retain(|(_, session)| {
                        session.available.load(Ordering::Relaxed)
                            && session.priority.load(Ordering::Relaxed) >= 0
                    });
                    sessions.sort_by(|(left_jid, left), (right_jid, right)| {
                        right
                            .priority
                            .load(Ordering::Relaxed)
                            .cmp(&left.priority.load(Ordering::Relaxed))
                            .then_with(|| left_jid.cmp(right_jid))
                    });
                }
                let mut delivered = sessions
                    .into_iter()
                    .any(|(_, session)| session.sender.try_send(forwarded.clone()).is_ok());
                if !delivered {
                    for node_id in self
                        .state
                        .cluster
                        .lookup_nodes(&target_raw)
                        .await
                        .unwrap_or_default()
                    {
                        if node_id != self.state.cluster.node_id
                            && self
                                .state
                                .cluster
                                .send_to_node_primary(&node_id, &target_raw, &forwarded)
                                .await
                                .is_ok_and(|receipt| receipt.delivered && receipt.acknowledged)
                        {
                            delivered = true;
                            break;
                        }
                    }
                }
                if !delivered && temporary_storage {
                    let delayed = add_delay_from(&forwarded, chrono::Utc::now(), Some(&room_jid));
                    let outcome = self
                        .state
                        .muc_service()
                        .store_local_muc_offline(
                            recipient.id,
                            &room_jid,
                            &delayed,
                            false,
                            OfflineStorePolicy {
                                max_messages: self.state.config.offline_max_messages_per_account,
                                max_bytes: self.state.config.offline_max_bytes_per_account,
                                ttl_days: self.state.config.offline_message_ttl_days,
                                mam_backed: false,
                            },
                        )
                        .await?;
                    if outcome == OfflineStoreOutcome::QuotaExceeded {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "wait",
                            "resource-constraint",
                        )));
                    }
                    if outcome == OfflineStoreOutcome::RecipientUnavailable {
                        return Ok(Action::None);
                    }
                    if let Err(error) =
                        super::misc::send_push_notification(&self.state, recipient.id).await
                    {
                        tracing::warn!(?error, recipient_id = %recipient.id, %room_jid, "accepted offline MUC invitation decline could not trigger push notification");
                    }
                }
                return Ok(Action::None);
            }
            if !self
                .state
                .config
                .external_route_domain_allowed(target.domainpart())
                || !self
                    .state
                    .federation
                    .send(target.domainpart(), forwarded, Some(room_jid.clone()))
                    .await
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "wait",
                    "remote-server-timeout",
                )));
            }
            return Ok(Action::None);
        }
        let Some(own) = self.authorized_muc_occupant(&room_jid).await? else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "not-acceptable",
            )));
        };
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(current_room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        let current_affiliation = self
            .state
            .muc_service()
            .local_affiliation(current_room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if current_affiliation == "outcast"
            || (current_room.members_only && current_affiliation == "none")
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let voice_form = match parse_muc_voice_form(root) {
            Ok(form) => form,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        if let Some(voice_form) = voice_form {
            if to_jid.resourcepart().is_some()
                || !matches!(root.attribute("type"), None | Some("normal"))
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
            let Some(room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            let mut occupants = self
                .state
                .cluster
                .get_muc_occupants(&room_jid)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(nick, json)| {
                    serde_json::from_str::<crate::state::SerializableMucOccupant>(&json)
                        .ok()
                        .map(|occupant| (nick, occupant))
                })
                .collect::<std::collections::HashMap<_, _>>();
            for (_, occupant) in self.state.muc_occupants_for(&room_jid) {
                occupants.insert(
                    occupant.nick.clone(),
                    crate::state::SerializableMucOccupant::from(&occupant),
                );
            }
            match voice_form {
                MucVoiceForm::Request => {
                    if !room.moderated || own.role != "visitor" {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    }
                    let request = XmlElement::new("message")
                        .attr("from", &room_jid)
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
                                .child(muc_xdata_value_field(
                                    "FORM_TYPE",
                                    "hidden",
                                    "http://jabber.org/protocol/muc#request",
                                ))
                                .child(muc_xdata_value_field(
                                    "muc#role",
                                    "list-single",
                                    "participant",
                                ))
                                .child(muc_xdata_value_field(
                                    "muc#jid",
                                    "jid-single",
                                    &own.full_jid,
                                ))
                                .child(muc_xdata_value_field(
                                    "muc#roomnick",
                                    "text-single",
                                    &own.nick,
                                ))
                                .child(muc_xdata_value_field(
                                    "muc#request_allow",
                                    "boolean",
                                    "false",
                                )),
                        )
                        .finish();
                    for moderator in occupants
                        .values()
                        .filter(|occupant| occupant.role == "moderator")
                    {
                        let key = muc_occupant_key(&room_jid, &moderator.nick);
                        if let Some(local) = self
                            .state
                            .muc_occupants
                            .get(&key)
                            .map(|entry| entry.value().clone())
                        {
                            let _ = self
                                .state
                                .deliver_to_muc_occupant(&local, set_to(&request, &local.full_jid))
                                .await;
                        }
                        self.state
                            .cluster
                            .send_muc_private_from(
                                &room_jid,
                                &moderator.nick,
                                &request,
                                &own.full_jid,
                            )
                            .await?;
                    }
                    return Ok(Action::None);
                }
                MucVoiceForm::Approval { jid, nick, allow } => {
                    if own.role != "moderator" {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    }
                    let Some(target) = occupants.get(&nick) else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    if target.full_jid != jid || target.role != "visitor" {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "not-allowed",
                        )));
                    }
                    if !allow {
                        return Ok(Action::None);
                    }
                    if !self.state.cluster.is_enabled() {
                        // Single-node rooms intentionally keep live occupancy
                        // authority in memory.  Requiring the clustered
                        // PostgreSQL tuple here made every valid voice grant
                        // fail with <forbidden/> because no cluster occupancy
                        // row exists in this supported deployment mode.
                        // Re-check the exact connection/incarnation under the
                        // map write guard so a departed/rejoined occupant
                        // cannot inherit an approval addressed to its stale
                        // nickname.
                        let target_key = muc_occupant_key(&room_jid, &target.nick);
                        let Some(mut current) = self.state.muc_occupants.get_mut(&target_key)
                        else {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                from,
                                "cancel",
                                "item-not-found",
                            )));
                        };
                        if current.full_jid != target.full_jid
                            || current.connection_id != target.connection_id
                            || current.cluster_epoch != target.cluster_epoch
                            || current.role != "visitor"
                        {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                from,
                                "cancel",
                                "item-not-found",
                            )));
                        }
                        current.role = "participant".to_owned();
                        let updated = crate::state::SerializableMucOccupant::from(&*current);
                        drop(current);
                        for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                            let self_presence = recipient.full_jid == updated.full_jid
                                && recipient.connection_id == updated.connection_id
                                && recipient.cluster_epoch == updated.cluster_epoch;
                            let presence = muc_presence_stanza(
                                &updated,
                                &recipient.full_jid,
                                false,
                                self_presence,
                                false,
                                root.attribute("id"),
                                updated.room_non_anonymous
                                    || self_presence
                                    || recipient.role == "moderator",
                            );
                            let _ = self
                                .state
                                .deliver_to_muc_occupant(&recipient, presence)
                                .await;
                        }
                        return Ok(Action::None);
                    }
                    let service = self.state.muc_service();
                    let Some(actor_target) = service
                        .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    };
                    let Some(target_authority) = service
                        .local_cluster_occupancy_target_by_nick(
                            room.id,
                            room.room_epoch,
                            &target.nick,
                        )
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    if actor_target.full_jid != own.full_jid
                        || actor_target.connection_uuid != own.connection_id
                        || target_authority.full_jid != target.full_jid
                        || target_authority.connection_uuid != target.connection_id
                    {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                    let operation_id =
                        crate::services::muc::MucService::operation_id(&serde_json::json!({
                            "kind":"voice_approval","stream":self.connection_id,
                            "stanza_id":root.attribute("id"),"room":room_jid,
                            "actor":actor_target,"target":target_authority,"role":"participant"
                        }))?;
                    match service
                        .change_local_cluster_role(
                            operation_id,
                            &actor_target,
                            &target_authority,
                            "participant",
                            None,
                        )
                        .await?
                    {
                        ClusterMucTransitionOutcome::Applied
                        | ClusterMucTransitionOutcome::Replay => {}
                        ClusterMucTransitionOutcome::Unauthorized => {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                from,
                                "auth",
                                "forbidden",
                            )));
                        }
                        _ => {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                from,
                                "cancel",
                                "item-not-found",
                            )));
                        }
                    }
                    if let Err(error) = self
                        .state
                        .muc_service()
                        .wake_committed_operation(&self.state.cluster, operation_id)
                        .await
                    {
                        tracing::warn!(?error, %operation_id, "committed MUC voice approval wake failed; PostgreSQL outbox will catch up");
                    }
                    return Ok(Action::None);
                }
            }
        }

        if to.contains('/') {
            let Some(room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            if !room.allow_private_messages {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            if !matches!(
                root.attribute("type").unwrap_or("normal"),
                "chat" | "normal"
            ) {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
            let Some(target_nick) = to_jid.resourcepart() else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "jid-malformed",
                )));
            };
            let target_key = muc_occupant_key(&room_jid, target_nick);
            let local_target = self
                .state
                .muc_occupants
                .get(&target_key)
                .map(|entry| entry.value().clone());
            let (target_full_jid, route_via_cluster) = if let Some(target) = &local_target {
                (target.full_jid.clone(), false)
            } else {
                let occupants = self
                    .state
                    .cluster
                    .get_muc_occupants(&room_jid)
                    .await
                    .unwrap_or_default();
                let Some(target) = occupants.get(target_nick).and_then(|json| {
                    serde_json::from_str::<crate::state::SerializableMucOccupant>(json).ok()
                }) else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                };
                (target.full_jid, true)
            };

            let rewritten = set_muc_occupant_id(
                &add_stanza_id(
                    &set_to(
                        &set_from(raw, &format!("{room_jid}/{}", own.nick)),
                        &target_full_jid,
                    ),
                    &room_jid,
                    uuid::Uuid::new_v4(),
                ),
                &own.occupant_id,
            );

            if route_via_cluster {
                self.state
                    .cluster
                    .send_muc_private_from(&room_jid, target_nick, &rewritten, from)
                    .await?;
            } else if let Some(target) = local_target {
                let blocked = self
                    .state
                    .blocked_muc_recipient_accounts(
                        std::slice::from_ref(&target),
                        &[format!("{room_jid}/{}", own.nick), from.to_owned()],
                    )
                    .await;
                if crate::jid::canonical_bare_key(&target.full_jid)
                    .is_ok_and(|owner| blocked.contains(&owner))
                {
                    return Ok(Action::None);
                }
                let _ = self
                    .state
                    .deliver_to_muc_occupant_unchecked(&target, rewritten)
                    .await;
            }
            return Ok(Action::None);
        }

        if root.attribute("type") != Some("groupchat") {
            let mut has_invites = false;
            if let Some(room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            {
                for x in root.children().filter(|n| {
                    n.is_element()
                        && n.tag_name().name() == "x"
                        && n.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
                }) {
                    for invite in x
                        .children()
                        .filter(|n| n.is_element() && n.tag_name().name() == "invite")
                    {
                        if let Some(invitee_raw) = invite.attribute("to") {
                            has_invites = true;
                            let Ok(invitee) = CanonicalJid::parse(invitee_raw) else {
                                return Ok(Action::Send(muc_stanza_error(
                                    root,
                                    from,
                                    "modify",
                                    "jid-malformed",
                                )));
                            };
                            let Some(invitee_localpart) = invitee.localpart() else {
                                return Ok(Action::Send(muc_stanza_error(
                                    root,
                                    from,
                                    "modify",
                                    "jid-malformed",
                                )));
                            };
                            let invitee_jid = invitee.to_string();
                            let invitee_bare = invitee.bare();
                            let invitee_domain = invitee.domainpart();
                            if invitee_domain == self.state.config.domain {
                                if let Some(invitee_user) = self
                                    .state
                                    .muc_service()
                                    .enabled_local_account(invitee_localpart)
                                    .await?
                                {
                                    let blocked_room = self
                                        .state
                                        .muc_service()
                                        .is_blocked_for_account(
                                            invitee_user.id,
                                            &invitee_bare,
                                            &room_jid,
                                        )
                                        .await?;
                                    let blocked_inviter = self
                                        .state
                                        .muc_service()
                                        .is_blocked_for_account(
                                            invitee_user.id,
                                            &invitee_bare,
                                            from,
                                        )
                                        .await?;
                                    if blocked_room || blocked_inviter {
                                        continue;
                                    }
                                }
                            }
                            // XEP-0045 roomconfig_allowinvites grants members
                            // an additional privilege; it never restricts an
                            // owner or administrator's inherent privilege.
                            let privileged_inviter =
                                matches!(own.affiliation.as_str(), "owner" | "admin");
                            if !privileged_inviter && (own.role == "visitor" || !room.allow_invites)
                            {
                                return Ok(Action::Send(muc_stanza_error(
                                    root,
                                    from,
                                    "auth",
                                    "forbidden",
                                )));
                            }
                            let reason = child_text(invite, "reason");
                            let mut invite_out = XmlElement::new("invite").attr("from", from);
                            if let Some(r) = reason {
                                invite_out.push_child(XmlElement::new("reason").text(r.to_owned()));
                            }
                            let hints = processing_hints_fragment(root, raw);
                            let temporary_storage = offline_storage_permitted(root);

                            let local_durable_invite_id = if room.members_only
                                && invitee_domain == self.state.config.domain
                            {
                                Some(crate::services::muc::MucService::operation_id(
                                    &serde_json::json!({
                                        "kind":"muc_invitation","stream":self.connection_id,
                                        "stanza_id":root.attribute("id"),"room":room_jid,
                                        "actor":from,"invitee":invitee_bare,"reason":reason,
                                    }),
                                )?)
                            } else {
                                None
                            };
                            let forwarded = set_muc_occupant_id(
                                &add_stanza_id(
                                    &XmlElement::new("message")
                                        .attr("from", &room_jid)
                                        .attr("to", &invitee_jid)
                                        .attr("type", "normal")
                                        .child(
                                            XmlElement::namespaced(
                                                "x",
                                                "http://jabber.org/protocol/muc#user",
                                            )
                                            .child(invite_out),
                                        )
                                        .validated_fragment(&hints)?
                                        .finish(),
                                    &room_jid,
                                    uuid::Uuid::new_v4(),
                                ),
                                &own.occupant_id,
                            );
                            // Cluster protocol v6 can infer a durable delivery
                            // only when the recipient-authoritative stanza-id
                            // is the exact spool key. Protocol v7 also carries
                            // the explicit fence, so keeping both makes rolling
                            // upgrades fail safe without weakening identity.
                            let forwarded = local_durable_invite_id
                                .map_or(forwarded.clone(), |id| {
                                    add_stanza_id(&forwarded, &invitee_bare, id)
                                });

                            if invitee_domain == self.state.config.domain {
                                let Some(recipient) = self
                                    .state
                                    .muc_service()
                                    .enabled_local_account(invitee_localpart)
                                    .await?
                                else {
                                    return Ok(Action::Send(muc_stanza_error(
                                        root,
                                        from,
                                        "cancel",
                                        "service-unavailable",
                                    )));
                                };
                                if room.members_only && !temporary_storage {
                                    return Ok(Action::Send(muc_stanza_error(
                                        root,
                                        from,
                                        "wait",
                                        "service-unavailable",
                                    )));
                                }
                                let (durable_invite, affiliation_changed) = if room.members_only {
                                    let delayed = add_delay_from(
                                        &forwarded,
                                        chrono::Utc::now(),
                                        Some(&room_jid),
                                    );
                                    let cluster_authority = if self.state.cluster.is_enabled() {
                                        self.state
                                            .cluster
                                            .admit(crate::cluster::ClusterOperation::MucMutation)?;
                                        let Some(actor_target) = self
                                            .state
                                            .muc_service()
                                            .local_cluster_occupancy_target(
                                                room.id,
                                                own.cluster_epoch,
                                                own.connection_id,
                                            )
                                            .await?
                                        else {
                                            return Ok(Action::Send(muc_stanza_error(
                                                root,
                                                from,
                                                "auth",
                                                "forbidden",
                                            )));
                                        };
                                        let actor_user = self
                                            .authenticated
                                            .as_ref()
                                            .expect("MUC message actor is authenticated");
                                        Some(ClusterMucInviteAuthority {
                                            operation_id: local_durable_invite_id.expect(
                                                "local members-only invite allocates a fence",
                                            ),
                                            expected_room_epoch: room.room_epoch,
                                            expected_config_version: room.config_version,
                                            actor: ClusterMucPrincipal::Local {
                                                user_id: actor_user.id,
                                                bare_jid: bare_jid(from).to_owned(),
                                            },
                                            actor_full_jid: from.to_owned(),
                                            actor_target: Some(actor_target),
                                            subject: ClusterMucAffiliationSubject::Local {
                                                user_id: recipient.id,
                                                bare_jid: invitee_bare.clone(),
                                            },
                                            reason: reason.map(str::to_owned),
                                        })
                                    } else {
                                        None
                                    };
                                    match self
                                        .state
                                        .muc_service()
                                        .admit_local_invite_command(
                                            local_durable_invite_id.expect(
                                                "local members-only invite allocates a fence",
                                            ),
                                            room.id,
                                            recipient.id,
                                            &room_jid,
                                            &delayed,
                                            false,
                                            OfflineStorePolicy {
                                                max_messages: self
                                                    .state
                                                    .config
                                                    .offline_max_messages_per_account,
                                                max_bytes: self
                                                    .state
                                                    .config
                                                    .offline_max_bytes_per_account,
                                                ttl_days: self
                                                    .state
                                                    .config
                                                    .offline_message_ttl_days,
                                                mam_backed: false,
                                            },
                                            cluster_authority.as_ref(),
                                        )
                                        .await?
                                    {
                                        DurableMucInviteOutcome::Stored {
                                            id,
                                            affiliation_changed,
                                        } => {
                                            if let Some(authority) = &cluster_authority {
                                                self.state
                                                    .muc_service()
                                                    .wake_committed_operation(
                                                        &self.state.cluster,
                                                        authority.operation_id,
                                                    )
                                                    .await?;
                                            }
                                            (Some(id), affiliation_changed)
                                        }
                                        DurableMucInviteOutcome::Replay { id: _ } => {
                                            if let Some(authority) = &cluster_authority {
                                                self.state
                                                    .muc_service()
                                                    .wake_committed_operation(
                                                        &self.state.cluster,
                                                        authority.operation_id,
                                                    )
                                                    .await?;
                                            }
                                            return Ok(Action::None);
                                        }
                                        DurableMucInviteOutcome::QuotaExceeded => {
                                            return Ok(Action::Send(muc_stanza_error(
                                                root,
                                                from,
                                                "wait",
                                                "resource-constraint",
                                            )));
                                        }
                                        DurableMucInviteOutcome::RecipientUnavailable => {
                                            continue;
                                        }
                                        DurableMucInviteOutcome::Outcast => {
                                            return Ok(Action::Send(muc_stanza_error(
                                                root,
                                                from,
                                                "auth",
                                                "forbidden",
                                            )));
                                        }
                                        DurableMucInviteOutcome::AuthorityRejected => {
                                            return Ok(Action::Send(muc_stanza_error(
                                                root,
                                                from,
                                                "auth",
                                                "forbidden",
                                            )));
                                        }
                                        DurableMucInviteOutcome::Stale => {
                                            return Ok(Action::Send(muc_stanza_error(
                                                root,
                                                from,
                                                "cancel",
                                                "item-not-found",
                                            )));
                                        }
                                    }
                                } else {
                                    (None, false)
                                };
                                if affiliation_changed && !self.state.cluster.is_enabled() {
                                    let locally_present =
                                        self.state.muc_occupants_for(&room_jid).iter().any(
                                            |(_, occupant)| {
                                                canonical_bare_key(&occupant.full_jid).ok()
                                                    == Some(invitee_bare.clone())
                                            },
                                        );
                                    let remotely_present = match self
                                        .state
                                        .cluster
                                        .get_muc_occupants(&room_jid)
                                        .await
                                    {
                                        Ok(occupants) => occupants.into_values().any(|json| {
                                            serde_json::from_str::<
                                                crate::state::SerializableMucOccupant,
                                            >(&json)
                                            .ok()
                                            .and_then(|occupant| {
                                                canonical_bare_key(&occupant.full_jid).ok()
                                            }) == Some(invitee_bare.clone())
                                        }),
                                        Err(error) => {
                                            record_muc_post_commit_failure(
                                                &self.state,
                                                &room_jid,
                                                &invitee_bare,
                                                "invite-affiliation-presence-check",
                                            );
                                            tracing::warn!(
                                                ?error,
                                                room = %room_jid,
                                                target = %invitee_bare,
                                                "could not determine whether a newly invited member is already in the room"
                                            );
                                            true
                                        }
                                    };
                                    if should_broadcast_offline_affiliation_change(
                                        room.non_anonymous,
                                        locally_present || remotely_present,
                                        "none",
                                        "member",
                                    ) {
                                        deliver_muc_offline_affiliation_change_notice(
                                            &self.state,
                                            &room_jid,
                                            &invitee_bare,
                                            "member",
                                            None,
                                            reason,
                                        )
                                        .await;
                                    }
                                }
                                let mut targets = self.state.session_entries_for(&invitee_jid);
                                if invitee.resourcepart().is_none() {
                                    targets.retain(|(_, session)| {
                                        session.available.load(Ordering::Relaxed)
                                            && session.priority.load(Ordering::Relaxed) >= 0
                                    });
                                    targets.sort_by(|(left_jid, left), (right_jid, right)| {
                                        right
                                            .priority
                                            .load(Ordering::Relaxed)
                                            .cmp(&left.priority.load(Ordering::Relaxed))
                                            .then_with(|| left_jid.cmp(right_jid))
                                    });
                                }
                                let carbon_eligible = should_carbon(root);
                                let live_delivery = durable_invite.map(|message_id| {
                                    crate::outbound::DurableDelivery {
                                        recipient_id: recipient.id,
                                        message_id,
                                        claim_id: None,
                                    }
                                });
                                let mut delivered = false;
                                let mut delivered_full_jid = None;
                                for (full_jid, target) in targets {
                                    let accepted = if let Some(delivery) = live_delivery {
                                        target
                                            .sender
                                            .try_send_durable(forwarded.clone(), delivery)
                                            .is_ok()
                                    } else {
                                        target.sender.try_send(forwarded.clone()).is_ok()
                                    };
                                    if accepted {
                                        let counter = if live_delivery.is_some() {
                                            &self
                                                .state
                                                .metrics
                                                .online_queue_durable_acceptances_total
                                        } else {
                                            &self
                                                .state
                                                .metrics
                                                .online_queue_volatile_acceptances_total
                                        };
                                        counter.fetch_add(1, Ordering::Relaxed);
                                        delivered = true;
                                        delivered_full_jid = Some(full_jid);
                                        break;
                                    }
                                }
                                if !delivered {
                                    if let Ok(nodes) =
                                        self.state.cluster.lookup_nodes(&invitee_jid).await
                                    {
                                        for node_id in nodes {
                                            if node_id == self.state.cluster.node_id {
                                                continue;
                                            }
                                            let receipt = if let Some(delivery) = live_delivery {
                                                self.state
                                                    .cluster
                                                    .send_to_node_primary_durable(
                                                        &node_id,
                                                        &invitee_jid,
                                                        &forwarded,
                                                        delivery,
                                                    )
                                                    .await
                                                    .unwrap_or_default()
                                            } else {
                                                self.state
                                                    .cluster
                                                    .send_to_node_primary(
                                                        &node_id,
                                                        &invitee_jid,
                                                        &forwarded,
                                                    )
                                                    .await
                                                    .unwrap_or_default()
                                            };
                                            if receipt.delivered && receipt.acknowledged {
                                                delivered = true;
                                                delivered_full_jid = receipt.accepted_full_jid;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if delivered && carbon_eligible {
                                    super::messaging::send_received_carbons_for_state(
                                        &self.state,
                                        &invitee_bare,
                                        delivered_full_jid.as_deref(),
                                        &forwarded,
                                    )
                                    .await;
                                }
                                if !delivered && durable_invite.is_none() && temporary_storage {
                                    let delayed = add_delay_from(
                                        &forwarded,
                                        chrono::Utc::now(),
                                        Some(&room_jid),
                                    );
                                    let offline_outcome = self
                                        .state
                                        .muc_service()
                                        .store_local_muc_offline(
                                            recipient.id,
                                            &room_jid,
                                            &delayed,
                                            false,
                                            OfflineStorePolicy {
                                                max_messages: self
                                                    .state
                                                    .config
                                                    .offline_max_messages_per_account,
                                                max_bytes: self
                                                    .state
                                                    .config
                                                    .offline_max_bytes_per_account,
                                                ttl_days: self
                                                    .state
                                                    .config
                                                    .offline_message_ttl_days,
                                                mam_backed: false,
                                            },
                                        )
                                        .await?;
                                    if offline_outcome == OfflineStoreOutcome::QuotaExceeded {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "wait",
                                            "resource-constraint",
                                        )));
                                    }
                                    if offline_outcome == OfflineStoreOutcome::RecipientUnavailable
                                    {
                                        return Ok(Action::None);
                                    }
                                }
                                if !delivered && temporary_storage {
                                    if let Err(error) = super::misc::send_push_notification(
                                        &self.state,
                                        recipient.id,
                                    )
                                    .await
                                    {
                                        tracing::warn!(?error, recipient_id = %recipient.id, %room_jid, "accepted offline mediated MUC invitation could not trigger push notification");
                                    }
                                }
                            } else if room.members_only {
                                let operation_id = crate::services::muc::MucService::operation_id(
                                    &serde_json::json!({
                                        "kind":"muc_invitation","stream":self.connection_id,
                                        "stanza_id":root.attribute("id"),"room":room_jid,
                                        "actor":from,"invitee":invitee_bare,"reason":reason,
                                    }),
                                )?;
                                let cluster_authority = if self.state.cluster.is_enabled() {
                                    self.state
                                        .cluster
                                        .admit(crate::cluster::ClusterOperation::MucMutation)?;
                                    let Some(actor_target) = self
                                        .state
                                        .muc_service()
                                        .local_cluster_occupancy_target(
                                            room.id,
                                            own.cluster_epoch,
                                            own.connection_id,
                                        )
                                        .await?
                                    else {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "auth",
                                            "forbidden",
                                        )));
                                    };
                                    let actor_user = self
                                        .authenticated
                                        .as_ref()
                                        .expect("MUC message actor is authenticated");
                                    Some(ClusterMucInviteAuthority {
                                        operation_id,
                                        expected_room_epoch: room.room_epoch,
                                        expected_config_version: room.config_version,
                                        actor: ClusterMucPrincipal::Local {
                                            user_id: actor_user.id,
                                            bare_jid: bare_jid(from).to_owned(),
                                        },
                                        actor_full_jid: from.to_owned(),
                                        actor_target: Some(actor_target),
                                        subject: ClusterMucAffiliationSubject::Federated {
                                            bare_jid: invitee_bare.clone(),
                                        },
                                        reason: reason.map(str::to_owned),
                                    })
                                } else {
                                    None
                                };
                                match self
                                    .state
                                    .muc_service()
                                    .admit_federated_invite_command(
                                        room.id,
                                        &invitee_bare,
                                        invitee_domain,
                                        &forwarded,
                                        Some(&room_jid),
                                        self.state.federation.outbox_policy().into(),
                                        cluster_authority.as_ref(),
                                    )
                                    .await
                                {
                                    Ok(true) => {
                                        self.state.federation.wake_outbox();
                                        if cluster_authority.is_some() {
                                            self.state
                                                .muc_service()
                                                .wake_committed_operation(
                                                    &self.state.cluster,
                                                    operation_id,
                                                )
                                                .await?;
                                        }
                                    }
                                    Ok(false) => {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "auth",
                                            "forbidden",
                                        )));
                                    }
                                    Err(error) => {
                                        tracing::warn!(?error, %invitee_bare, %room_jid, "federated mediated MUC invite admission failed atomically");
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "wait",
                                            "resource-constraint",
                                        )));
                                    }
                                }
                            } else {
                                if !self
                                    .state
                                    .federation
                                    .send(invitee_domain, forwarded, Some(room_jid.clone()))
                                    .await
                                {
                                    return Ok(Action::Send(muc_stanza_error(
                                        root,
                                        from,
                                        "wait",
                                        "remote-server-timeout",
                                    )));
                                }
                            }
                        }
                    }
                }
            }
            if has_invites {
                return Ok(Action::None);
            }
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
        let Some(initial_room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        // Single-node occupancy is intentionally process-local. Hold the one
        // room mutation gate from the final incarnation/affiliation check
        // through database admission and live fan-out. Clustered rooms use
        // the exact PostgreSQL occupancy tuple in the admission transaction.
        let local_authority_guard = if self.state.cluster.is_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await,
            )
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        if room.id != initial_room.id || room.room_epoch != initial_room.room_epoch {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        }
        let Some(own) = self.validated_muc_occupant(&room_jid) else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        };
        let current_affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if current_affiliation != own.affiliation
            || current_affiliation == "outcast"
            || (room.members_only && current_affiliation == "none")
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let cluster_target = if self.state.cluster.is_enabled() {
            let target = self
                .state
                .muc_service()
                .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
                .await?;
            let Some(target) = target.filter(|target| {
                target.room_epoch == room.room_epoch
                    && target.full_jid == own.full_jid
                    && target.nick == own.nick
                    && target.connection_uuid == own.connection_id
            }) else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            };
            Some(target)
        } else {
            None
        };
        if own.role == "visitor" {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let subject_command = match parse_muc_subject_command(root) {
            Ok(subject) => subject,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        let origin_id = match parse_muc_origin_id(root) {
            Ok(origin_id) => origin_id,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        let author_retraction = match parse_muc_author_retraction(root) {
            Ok(retraction) => retraction,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "bad-request",
                )));
            }
        };
        if subject_command.is_some() && author_retraction.is_some() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
        if subject_command.is_some() && own.role != "moderator" && !room.allow_subject_change {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        let room_from = format!("{room_jid}/{}", own.nick);
        let stable_id = uuid::Uuid::new_v4();
        let rewritten = set_muc_occupant_id(
            &add_stanza_id(
                &set_to(&set_from(raw, &room_from), &room_jid),
                &room_jid,
                stable_id,
            ),
            &own.occupant_id,
        );
        let encrypted = is_encrypted(root);
        let archive_enabled = room.logging_enabled
            && !has_no_store_hint(root)
            && (encrypted || !self.state.config.require_encrypted_archive);
        let archive = if archive_enabled && encrypted {
            encrypted_archive_stanza(&rewritten)
        } else {
            rewritten.clone()
        };
        let actor_scope = canonical_bare_key(from)?;
        let actor_authority = MucActorAuthority {
            clustered: self.state.cluster.is_enabled(),
            expected_room_epoch: room.room_epoch,
            principal: MucActorPrincipal::Local {
                user_id: user.id,
                local_domain: &self.state.config.domain,
            },
            actor_scope: &actor_scope,
            full_jid: from,
            nick: &own.nick,
            occupant_incarnation: own.cluster_epoch,
            connection_uuid: own.connection_id,
            expected_role: &own.role,
            expected_affiliation: &current_affiliation,
            cluster_target,
        };
        if let Some(target_id) = author_retraction {
            let Some(original) = self
                .state
                .muc_service()
                .local_message_by_id(room.id, target_id)
                .await?
            else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            if canonical_bare_key(&original.sender_jid).ok().as_deref()
                != Some(actor_scope.as_str())
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "wait",
                    "internal-server-error",
                )));
            };
            let original_root = original_document.root_element();
            if original_root.tag_name().name() != "message"
                || original_root.attribute("type") != Some("groupchat")
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "not-acceptable",
                )));
            }
            let stamp = chrono::Utc::now();
            let retraction_message_id = root
                .attribute("id")
                .map(str::to_owned)
                .unwrap_or_else(|| stable_id.to_string());
            let tombstone = XmlElement::namespaced("message", "jabber:client")
                .attr("from", original_root.attribute("from").unwrap_or(&room_jid))
                .attr("to", &room_jid)
                .attr("type", "groupchat")
                .attr("id", original_root.attribute("id").unwrap_or_default())
                .child(
                    XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                        .attr("id", target_id)
                        .attr("by", &room_jid),
                )
                .child(
                    XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0").attr(
                        "id",
                        muc_occupant_id(&room.occupant_id_secret, &original.sender_jid),
                    ),
                )
                .child(
                    XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
                        .attr("id", &retraction_message_id)
                        .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ")),
                )
                .finish();
            match self
                .state
                .muc_service()
                .retract_local_message_and_archive_action(MucRetractionMutation {
                    action_id: stable_id,
                    room_id: room.id,
                    target_id,
                    expected_stanza: &original.stanza,
                    actor_scope: &actor_scope,
                    sender_jid: from,
                    nick: &own.nick,
                    tombstone: &tombstone,
                    action_stanza: &rewritten,
                    reason: None,
                    kind: MucRetractionKind::Author,
                    authority: actor_authority,
                })
                .await?
            {
                MucRetractionOutcome::Applied => {}
                MucRetractionOutcome::Unauthorized => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                    return Ok(Action::Send(muc_stanza_error(
                        root, from, "cancel", "conflict",
                    )));
                }
            }
        } else if let Some(subject) = subject_command.as_deref() {
            let service = self.state.muc_service();
            let Some(actor_target) = service
                .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                .await?
            else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            };
            if actor_target.full_jid != own.full_jid
                || actor_target.connection_uuid != own.connection_id
            {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "auth",
                    "forbidden",
                )));
            }
            let operation_id =
                crate::services::muc::MucService::operation_id(&serde_json::json!({
                    "kind":"subject","stream":self.connection_id,"stanza_id":root.attribute("id"),
                    "room":room_jid,"actor":actor_target,"subject":subject,"archive":archive_enabled
                }))?;
            match service
                .set_local_cluster_subject(
                    operation_id,
                    room.room_epoch,
                    room.config_version,
                    &actor_target,
                    MucSubjectMutation {
                        stanza_id: stable_id,
                        room_id: room.id,
                        actor_scope: &actor_scope,
                        sender_jid: from,
                        nick: &own.nick,
                        subject,
                        stanza: &archive,
                        encrypted,
                    },
                    archive_enabled,
                )
                .await?
            {
                ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                ClusterMucTransitionOutcome::Unauthorized => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                _ => {
                    return Ok(Action::Send(muc_stanza_error(
                        root, from, "cancel", "conflict",
                    )));
                }
            }
            if let Err(error) = self
                .state
                .muc_service()
                .wake_committed_operation(&self.state.cluster, operation_id)
                .await
            {
                tracing::warn!(?error, %operation_id, "committed MUC subject wake failed; PostgreSQL outbox will catch up");
            }
            return Ok(Action::None);
        } else {
            let admission = self
                .state
                .muc_service()
                .admit_local_discussion(MucDiscussion {
                    id: stable_id,
                    room_id: room.id,
                    actor_scope: &actor_scope,
                    origin_id: origin_id.as_deref(),
                    sender_jid: from,
                    nick: &own.nick,
                    stanza: &archive,
                    encrypted,
                    archive: archive_enabled,
                    retention_days: self.state.config.muc_mam_retention_days,
                    authority: actor_authority,
                })
                .await?;
            match admission {
                MucDiscussionAdmission::Stored(_) => {}
                MucDiscussionAdmission::Replay(_) => return Ok(Action::None),
                MucDiscussionAdmission::Unauthorized => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                MucDiscussionAdmission::Stale => {
                    return Ok(Action::Send(muc_stanza_error(
                        root, from, "cancel", "conflict",
                    )));
                }
            }
        }
        run_muc_cluster_fan_out(
            &self.state,
            &room_jid,
            &rewritten,
            Some(from),
            "cluster fan-out",
        )
        .await;

        let occupants = self
            .state
            .muc_occupants_for(&room_jid)
            .into_iter()
            .map(|(_, occupant)| occupant)
            .collect::<Vec<_>>();
        let blocked = self
            .state
            .blocked_muc_recipient_accounts(&occupants, &[room_from.clone(), from.to_owned()])
            .await;
        for occupant in occupants {
            if crate::jid::canonical_bare_key(&occupant.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                continue;
            }
            let delivery = set_to(&rewritten, &occupant.full_jid);
            tracing::debug!(room=%room_jid, to=%occupant.full_jid, "MUC routing stanza");
            if !self
                .state
                .deliver_to_muc_occupant_unchecked(&occupant, delivery)
                .await
            {
                record_muc_post_commit_failure(
                    &self.state,
                    &room_jid,
                    &occupant.full_jid,
                    "local/federated occupant queue",
                );
            }
        }
        // The single-node authority gate is intentionally released only after
        // the accepted incarnation's complete live fan-out has been queued.
        drop(local_authority_guard);
        self.state
            .metrics
            .messages_routed_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(Action::None)
    }

    /// XEP-0425 moderated message retraction. Only a currently joined room
    /// moderator may act, and only the room-issued XEP-0359 ID is accepted.
    pub(crate) async fn muc_moderate(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        moderate: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let Some(initial_moderator) = self.authorized_muc_occupant(&room_jid).await? else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        };
        if initial_moderator.role != "moderator" {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        }
        let moderation = match parse_moderation_request(moderate) {
            Ok(moderation) => moderation,
            Err(condition) => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, condition)));
            }
        };
        let target_id = moderation.target_id;
        let reason = moderation.reason.as_deref();
        let Some(initial_room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        let local_authority_guard = if self.state.cluster.is_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await,
            )
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        if room.id != initial_room.id || room.room_epoch != initial_room.room_epoch {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
        }
        let Some(moderator) = self.validated_muc_occupant(&room_jid) else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        };
        if moderator.full_jid != initial_moderator.full_jid
            || moderator.connection_id != initial_moderator.connection_id
            || moderator.cluster_epoch != initial_moderator.cluster_epoch
            || moderator.role != "moderator"
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        }
        let current_affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if current_affiliation != moderator.affiliation || current_affiliation == "outcast" {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        }
        let cluster_target = if self.state.cluster.is_enabled() {
            let Some(target) = self
                .state
                .muc_service()
                .local_cluster_occupancy_target(
                    room.id,
                    moderator.cluster_epoch,
                    moderator.connection_id,
                )
                .await?
                .filter(|target| {
                    target.room_epoch == room.room_epoch
                        && target.full_jid == moderator.full_jid
                        && target.nick == moderator.nick
                        && target.connection_uuid == moderator.connection_id
                })
            else {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
            };
            Some(target)
        } else {
            None
        };
        let Some(original) = self
            .state
            .muc_service()
            .local_message_by_id(room.id, target_id)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
            tracing::error!(room=%room_jid, stanza_id=%target_id, "archived MUC stanza is not valid XML");
            return Ok(Action::Send(iq_error_from(
                id,
                &room_jid,
                "internal-server-error",
            )));
        };
        let original_root = original_document.root_element();
        if original_root.tag_name().name() != "message"
            || original_root.attribute("type") != Some("groupchat")
            || !is_abuse_rated_message(original_root)
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-acceptable")));
        }

        let moderator_occupant = format!("{room_jid}/{}", moderator.nick);
        let author_occupant_id = muc_occupant_id(&room.occupant_id_secret, &original.sender_jid);
        let stamp = chrono::Utc::now();
        let action_id = uuid::Uuid::new_v4();
        let target_text = target_id.to_string();
        let moderated = XmlElement::namespaced("moderated", "urn:xmpp:message-moderate:1")
            .attr("by", &moderator_occupant)
            .child(
                XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                    .attr("id", &moderator.occupant_id),
            );
        let mut retracted = XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
            .attr("id", action_id)
            .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ"))
            .child(moderated.clone());
        if let Some(reason) = reason {
            retracted.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let tombstone = XmlElement::namespaced("message", "jabber:client")
            .attr("from", original_root.attribute("from").unwrap_or(&room_jid))
            .attr("to", &room_jid)
            .attr("type", "groupchat")
            .attr("id", original_root.attribute("id").unwrap_or(&target_text))
            .child(
                XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                    .attr("id", target_id)
                    .attr("by", &room_jid),
            )
            .child(
                XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                    .attr("id", &author_occupant_id),
            )
            .child(retracted)
            .finish();
        let mut retract = XmlElement::namespaced("retract", "urn:xmpp:message-retract:1")
            .attr("id", target_id)
            .child(moderated);
        if let Some(reason) = reason {
            retract.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let notice_xml = XmlElement::namespaced("message", "jabber:client")
            .attr("from", &room_jid)
            .attr("to", &room_jid)
            .attr("type", "groupchat")
            .attr("id", action_id)
            .child(retract)
            .finish();
        let moderation_notice = add_stanza_id(
            &set_muc_occupant_id(&notice_xml, &moderator.occupant_id),
            &room_jid,
            action_id,
        );
        let actor_scope = canonical_bare_key(full_jid)?;
        match self
            .state
            .muc_service()
            .retract_local_message_and_archive_action(MucRetractionMutation {
                action_id,
                room_id: room.id,
                target_id,
                expected_stanza: &original.stanza,
                actor_scope: &actor_scope,
                sender_jid: full_jid,
                nick: &moderator.nick,
                tombstone: &tombstone,
                action_stanza: &moderation_notice,
                reason,
                kind: MucRetractionKind::Moderator,
                authority: MucActorAuthority {
                    clustered: self.state.cluster.is_enabled(),
                    expected_room_epoch: room.room_epoch,
                    principal: MucActorPrincipal::Local {
                        user_id: user.id,
                        local_domain: &self.state.config.domain,
                    },
                    actor_scope: &actor_scope,
                    full_jid,
                    nick: &moderator.nick,
                    occupant_incarnation: moderator.cluster_epoch,
                    connection_uuid: moderator.connection_id,
                    expected_role: &moderator.role,
                    expected_affiliation: &current_affiliation,
                    cluster_target,
                },
            })
            .await?
        {
            MucRetractionOutcome::Applied => {}
            MucRetractionOutcome::Unauthorized => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
            }
            MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
            }
        }
        run_muc_cluster_fan_out(
            &self.state,
            &room_jid,
            &moderation_notice,
            None,
            "cluster moderation fan-out",
        )
        .await;
        for (_, occupant) in self.state.muc_occupants_for(&room_jid) {
            let delivery = set_to(&moderation_notice, &occupant.full_jid);
            if !self
                .state
                .deliver_to_muc_occupant(&occupant, delivery)
                .await
            {
                record_muc_post_commit_failure(
                    &self.state,
                    &room_jid,
                    &occupant.full_jid,
                    "moderation occupant queue",
                );
            }
        }
        drop(local_authority_guard);
        Ok(Action::Send(iq_result_from(id, &room_jid, "")))
    }

    pub(crate) async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid_owned, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let room_jid = room_jid_owned.as_str();
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if room.configuration_is_expired(chrono::Utc::now()) {
            // The lifecycle helper commits the tombstone and immutable
            // audience outbox atomically.  Cluster workers poll that outbox;
            // never publish the old executable Redis destroy command here.
            let _ = self
                .state
                .muc_service()
                .delete_expired_locked_room(room.id)
                .await?;
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        if room.is_locked() && !room.can_configure_locked_room(full_jid, chrono::Utc::now()) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        if self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .as_deref()
            != Some("owner")
        {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        let whois = if room.non_anonymous {
            "anyone"
        } else {
            "moderators"
        };
        let form = muc_room_configuration_form(&room, whois);
        Ok(Action::Send(iq_result_from(id, room_jid, &form)))
    }

    pub(crate) async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid_owned, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let room_jid = room_jid_owned.as_str();
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        let gated_room_id = room.id;
        let gated_room_epoch = room.room_epoch;
        let mut local_room_guard = if self.state.cluster.is_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(room.id)
                    .await,
            )
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if room.id != gated_room_id || room.room_epoch != gated_room_epoch {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        if room.configuration_is_expired(chrono::Utc::now()) {
            let _ = self
                .state
                .muc_service()
                .delete_expired_locked_room(room.id)
                .await?;
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        if room.is_locked() && !room.can_configure_locked_room(full_jid, chrono::Utc::now()) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        if self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .as_deref()
            != Some("owner")
        {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }

        if let Some(destroy) = query.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "destroy"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#owner")
        }) {
            let alternate = match destroy.attribute("jid") {
                Some(jid) => match CanonicalJid::parse_bare(jid) {
                    Ok(jid) => Some(jid.to_string()),
                    Err(_) => {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                    }
                },
                None => None,
            };
            let reason = child_text(destroy, "reason");
            if reason.is_some_and(|value| value.len() > 4096) {
                return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
            }
            let occupants = self.state.muc_occupants_for(room_jid);
            let mut cluster_destroy_operation = None;
            if self.state.cluster.is_enabled() {
                self.state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                let Some(actor) = self.authorized_muc_occupant(room_jid).await? else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let Some(target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        actor.cluster_epoch,
                        actor.connection_id,
                    )
                    .await?
                else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let operation_id = uuid::Uuid::new_v4();
                match self
                    .state
                    .muc_service()
                    .destroy_local_cluster_room(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        Some(&target),
                        "local_database",
                        Some(full_jid),
                        alternate.as_deref(),
                        reason,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_destroy_operation = Some(operation_id)
                    }
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Conflict => {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
                    }
                }
            } else {
                self.state.muc_service().delete_room(room.id).await?;
            }
            let mut direct_destroy_deliveries = Vec::new();
            for (key, occupant) in occupants {
                let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                self.state.remove_live_muc_membership(&serializable);
                self.state.muc_occupants.remove_if(&key, |_, current| {
                    current.full_jid == occupant.full_jid
                        && current.connection_id == occupant.connection_id
                        && current.cluster_epoch == occupant.cluster_epoch
                });
                if cluster_destroy_operation.is_none() {
                    let unavailable =
                        muc_destroy_presence(&serializable, alternate.as_deref(), reason);
                    direct_destroy_deliveries.push((occupant, unavailable));
                }
            }
            drop(local_room_guard.take());
            for (occupant, unavailable) in direct_destroy_deliveries {
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&occupant, unavailable)
                    .await;
            }
            if let Some(operation_id) = cluster_destroy_operation {
                if let Err(error) = self
                    .state
                    .muc_service()
                    .wake_committed_operation(&self.state.cluster, operation_id)
                    .await
                {
                    tracing::warn!(?error, room=%room_jid, %operation_id,
                        "room destruction committed; signed wake will be recovered by polling");
                }
            }
            return Ok(Action::Send(iq_result_from(id, room_jid, "")));
        }

        let form = query.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:data")
        });
        if form.is_some_and(|form| form.attribute("type") == Some("cancel")) {
            if room.is_locked()
                && self
                    .state
                    .muc_service()
                    .cancel_locked_room(room.id, full_jid)
                    .await?
            {
                let mut direct_cancel_deliveries = Vec::new();
                for (key, occupant) in self.state.muc_occupants_for(room_jid) {
                    let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                    self.state.remove_live_muc_membership(&serializable);
                    self.state.muc_occupants.remove_if(&key, |_, current| {
                        current.cluster_epoch == occupant.cluster_epoch
                            && current.connection_id == occupant.connection_id
                    });
                    self.joined_rooms.remove_if(room_jid, |_, membership| {
                        membership.cluster_epoch == occupant.cluster_epoch
                    });
                    if !self.state.cluster.is_enabled() {
                        let unavailable = muc_destroy_presence(&serializable, None, None);
                        direct_cancel_deliveries.push((occupant, unavailable));
                    }
                }
                drop(local_room_guard.take());
                for (occupant, unavailable) in direct_cancel_deliveries {
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&occupant, unavailable)
                        .await;
                }
            }
            return Ok(Action::Send(iq_result_from(id, room_jid, "")));
        }
        if let Some(form) = form {
            if !matches!(form.attribute("type"), None | Some("submit"))
                || xdata_field(form, "FORM_TYPE")
                    .is_some_and(|value| value != "http://jabber.org/protocol/muc#roomconfig")
            {
                return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            let title = xdata_field(form, "muc#roomconfig_roomname")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(room.title.as_deref().unwrap_or(&room.localpart));
            if title.len() > 255 {
                return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
            }
            let description = xdata_field(form, "muc#roomconfig_roomdesc")
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if description.is_some_and(|value| value.len() > 4096) {
                return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
            }
            let persistent = match xdata_bool(form, "muc#roomconfig_persistentroom") {
                Ok(value) => value.unwrap_or(room.persistent),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let members_only = match xdata_bool(form, "muc#roomconfig_membersonly") {
                Ok(value) => value.unwrap_or(room.members_only),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let public = match xdata_bool(form, "muc#roomconfig_publicroom") {
                Ok(value) => value.unwrap_or(room.public),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let moderated = match xdata_bool(form, "muc#roomconfig_moderatedroom") {
                Ok(value) => value.unwrap_or(room.moderated),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let non_anonymous = match xdata_field(form, "muc#roomconfig_whois") {
                None => room.non_anonymous,
                Some("anyone") => true,
                Some("moderators") => false,
                Some(_) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let max_occupants = match xdata_field(form, "muc#roomconfig_maxusers") {
                None => room.max_occupants,
                Some(value) => match value.parse::<i32>() {
                    Ok(value @ 2..=1000) => value,
                    _ => return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable"))),
                },
            };
            let password_protected = match xdata_bool(form, "muc#roomconfig_passwordprotectedroom")
            {
                Ok(value) => value.unwrap_or(room.password_hash.is_some()),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_subject_change = match xdata_bool(form, "muc#roomconfig_changesubject") {
                Ok(value) => value.unwrap_or(room.allow_subject_change),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_invites = match xdata_bool(form, "muc#roomconfig_allowinvites") {
                Ok(value) => value.unwrap_or(room.allow_invites),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_private_messages = match xdata_field(form, "muc#roomconfig_allowpm") {
                None => room.allow_private_messages,
                Some("anyone") => true,
                Some("none") => false,
                Some(_) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let logging_enabled = match xdata_bool(form, "muc#roomconfig_enablelogging") {
                Ok(value) => value.unwrap_or(room.logging_enabled),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_registration = match xdata_bool(form, "muc#roomconfig_allowregister") {
                Ok(value) => value.unwrap_or(room.allow_registration),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let supplied_room_secret = xdata_field(form, "muc#roomconfig_roomsecret")
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let replacement_password_hash = if password_protected {
                if let Some(secret) = supplied_room_secret {
                    let secret = zeroize::Zeroizing::new(secret.to_owned());
                    // Argon2 is intentionally outside the room writer gate.
                    // Reacquire and validate the exact room/config/owner
                    // snapshot before committing the prepared hash.
                    drop(local_room_guard.take());
                    let password_hash = match crate::password_work::run(move || {
                        crate::services::muc::MucService::hash_room_password(&secret)
                    })
                    .await
                    {
                        Ok(hash) => hash,
                        Err(error) if error.is_overloaded() => {
                            return Ok(Action::Send(iq_error_from(
                                id,
                                room_jid,
                                "resource-constraint",
                            )));
                        }
                        Err(crate::password_work::PasswordWorkError::Computation(_)) => {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
                        }
                        Err(error) => {
                            return Err(anyhow::anyhow!(
                                "room password hashing task failed: {error}"
                            ));
                        }
                    };
                    if !self.state.cluster.is_enabled() {
                        local_room_guard = Some(
                            self.state
                                .muc_service()
                                .lock_local_room_mutation(room.id)
                                .await,
                        );
                        let Some(refreshed_room) = self
                            .state
                            .muc_service()
                            .local_room_snapshot(&room_localpart)
                            .await?
                        else {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                        };
                        if refreshed_room.room_epoch != room.room_epoch
                            || refreshed_room.config_version != room.config_version
                        {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
                        }
                        if self
                            .state
                            .muc_service()
                            .local_affiliation(room.id, user.id)
                            .await?
                            .as_deref()
                            != Some("owner")
                        {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                        }
                    }
                    Some(password_hash)
                } else if let Some(existing) = room.password_hash.clone() {
                    Some(existing)
                } else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
            } else {
                None
            };
            let configuration_outcome = if self.state.cluster.is_enabled() {
                self.state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                let Some(actor) = self.authorized_muc_occupant(room_jid).await? else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let Some(actor_target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        actor.cluster_epoch,
                        actor.connection_id,
                    )
                    .await?
                else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let operation_id = uuid::Uuid::new_v4();
                let outcome = self
                    .state
                    .muc_service()
                    .update_local_cluster_config(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        room.config_version,
                        &actor_target,
                        &ClusterMucPrincipal::Local {
                            user_id: user.id,
                            bare_jid: bare_jid(full_jid).to_owned(),
                        },
                        full_jid,
                        MucConfigUpdate {
                            title: Some(title),
                            description,
                            persistent,
                            members_only,
                            public,
                            moderated,
                            non_anonymous,
                            max_occupants,
                            password_hash: replacement_password_hash.as_deref(),
                            allow_subject_change,
                            allow_invites,
                            allow_private_messages,
                            logging_enabled,
                            allow_registration,
                        },
                    )
                    .await?;
                match outcome {
                    ClusterMucConfigurationOutcome::Applied
                    | ClusterMucConfigurationOutcome::Replay => {
                        if let Err(error) = self
                            .state
                            .muc_service()
                            .wake_committed_operation(&self.state.cluster, operation_id)
                            .await
                        {
                            tracing::warn!(?error, %operation_id, room=%room_jid,
                                "durable MUC config committed; signed wake will be recovered by polling");
                        }
                        MucConfigurationOutcome::Applied
                    }
                    ClusterMucConfigurationOutcome::LockedByAnother
                    | ClusterMucConfigurationOutcome::Unauthorized => {
                        MucConfigurationOutcome::LockedByAnother
                    }
                    ClusterMucConfigurationOutcome::Expired => MucConfigurationOutcome::Expired,
                    ClusterMucConfigurationOutcome::Missing
                    | ClusterMucConfigurationOutcome::Stale
                    | ClusterMucConfigurationOutcome::Destroyed => MucConfigurationOutcome::Missing,
                }
            } else {
                self.state
                    .muc_service()
                    .update_local_legacy_config(
                        room.id,
                        full_jid,
                        MucConfigUpdate {
                            title: Some(title),
                            description,
                            persistent,
                            members_only,
                            public,
                            moderated,
                            non_anonymous,
                            max_occupants,
                            password_hash: replacement_password_hash.as_deref(),
                            allow_subject_change,
                            allow_invites,
                            allow_private_messages,
                            logging_enabled,
                            allow_registration,
                        },
                    )
                    .await?
            };
            match configuration_outcome {
                MucConfigurationOutcome::Applied => {}
                MucConfigurationOutcome::LockedByAnother => {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                }
                MucConfigurationOutcome::Expired | MucConfigurationOutcome::Missing => {
                    let _ = self
                        .state
                        .muc_service()
                        .delete_expired_locked_room(room.id)
                        .await;
                    return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                }
            }
            if self.state.cluster.is_enabled() {
                // The immutable PostgreSQL audience/outbox owns every
                // clustered consequence, including members-only eviction and
                // role/privacy refresh. Returning here prevents the legacy
                // Redis mutation messages below from becoming a second,
                // unauthorised control plane.
                return Ok(Action::Send(iq_result_from(id, room_jid, "")));
            }
            // Complete every authoritative in-memory transition under the
            // room writer gate, but execute Redis/network fan-out only after
            // releasing it. This keeps policy and occupancy linearizable
            // without allowing slow recipients to block unrelated commands
            // which hash to the same fixed shard.
            let actor_nick = self
                .joined_rooms
                .get(room_jid)
                .map(|membership| membership.nick.clone());
            let mut evicted = Vec::new();
            let mut refreshed = Vec::new();
            for (key, mut occupant) in self.state.muc_occupants_for(room_jid) {
                if members_only && !room.members_only && occupant.affiliation == "none" {
                    occupant.role = "none".to_owned();
                    let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                    self.state.remove_live_muc_membership(&serializable);
                    if self
                        .state
                        .muc_occupants
                        .remove_if(&key, |_, current| {
                            current.full_jid == occupant.full_jid
                                && current.connection_id == occupant.connection_id
                                && current.cluster_epoch == occupant.cluster_epoch
                        })
                        .is_some()
                    {
                        evicted.push(occupant);
                    }
                    continue;
                }

                let mut changed = false;
                if moderated != room.moderated {
                    let next_role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                        "moderator"
                    } else if moderated && occupant.affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    };
                    if occupant.role != next_role {
                        occupant.role = next_role.to_owned();
                        changed = true;
                    }
                }
                if non_anonymous != room.non_anonymous {
                    occupant.room_non_anonymous = non_anonymous;
                    changed = true;
                }
                if changed {
                    let Some(mut current) = self.state.muc_occupants.get_mut(&key) else {
                        continue;
                    };
                    if current.full_jid != occupant.full_jid
                        || current.connection_id != occupant.connection_id
                        || current.cluster_epoch != occupant.cluster_epoch
                    {
                        continue;
                    }
                    *current = occupant.clone();
                    drop(current);
                    refreshed.push(occupant);
                }
            }
            let room_empty_after_policy = self.state.muc_occupants_for(room_jid).is_empty();
            drop(local_room_guard.take());

            let eviction_count = evicted.len();
            for (index, occupant) in evicted.into_iter().enumerate() {
                let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                run_muc_cluster_eviction(
                    &self.state,
                    room_jid,
                    serializable.clone(),
                    322,
                    actor_nick.as_deref(),
                    None,
                    room_empty_after_policy && index + 1 == eviction_count,
                )
                .await;
                for (_, recipient) in self.state.muc_occupants_for(room_jid) {
                    let presence = muc_presence_stanza_with_status(
                        &serializable,
                        &recipient.full_jid,
                        true,
                        false,
                        false,
                        None,
                        occupant.room_non_anonymous || recipient.role == "moderator",
                        Some(322),
                        actor_nick.as_deref(),
                        None,
                    );
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&recipient, presence)
                        .await;
                }
                let self_presence = muc_presence_stanza_with_status(
                    &serializable,
                    &occupant.full_jid,
                    true,
                    true,
                    false,
                    None,
                    true,
                    Some(322),
                    actor_nick.as_deref(),
                    None,
                );
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&occupant, self_presence)
                    .await;
            }
            for occupant in refreshed {
                let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                if let Ok(json) = serde_json::to_string(&serializable) {
                    run_muc_cluster_occupant_refresh(
                        &self.state,
                        room_jid,
                        &occupant.nick,
                        json,
                        serializable.clone(),
                    )
                    .await;
                }
                for (_, recipient) in self.state.muc_occupants_for(room_jid) {
                    let self_presence = occupant.full_jid == recipient.full_jid;
                    let presence = muc_presence_stanza(
                        &serializable,
                        &recipient.full_jid,
                        false,
                        self_presence,
                        false,
                        None,
                        non_anonymous || self_presence || recipient.role == "moderator",
                    );
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&recipient, presence)
                        .await;
                }
            }
            if non_anonymous != room.non_anonymous {
                let occupants = self.state.muc_occupants_for(room_jid);
                for (_, subject) in &occupants {
                    for (_, recipient) in &occupants {
                        let self_presence = subject.full_jid == recipient.full_jid;
                        let presence = muc_presence_stanza(
                            &crate::state::SerializableMucOccupant::from(subject),
                            &recipient.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            non_anonymous || self_presence || recipient.role == "moderator",
                        );
                        let _ = self
                            .state
                            .deliver_to_muc_occupant(recipient, presence)
                            .await;
                    }
                }
            }
            let mut config_statuses = vec!["104"];
            if logging_enabled != room.logging_enabled {
                config_statuses.push(if logging_enabled { "170" } else { "171" });
            }
            if non_anonymous != room.non_anonymous {
                config_statuses.push(if non_anonymous { "172" } else { "173" });
            }
            for (_, recipient) in self.state.muc_occupants_for(room_jid) {
                let mut extension =
                    XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user");
                for code in &config_statuses {
                    extension.push_child(XmlElement::new("status").attr("code", code));
                }
                let notice = XmlElement::namespaced("message", "jabber:client")
                    .attr("from", room_jid)
                    .attr("to", &recipient.full_jid)
                    .attr("type", "groupchat")
                    .child(extension)
                    .finish();
                let _ = self.state.deliver_to_muc_occupant(&recipient, notice).await;
            }
        }
        Ok(Action::Send(iq_result_from(id, room_jid, "")))
    }

    pub(crate) fn muc_domain(&self) -> String {
        prepare_domainpart(&format!("conference.{}", self.state.config.domain))
            .expect("configured XMPP domain must form a valid MUC service domain")
    }

    pub(crate) async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        let Some(user) = self.authenticated.clone() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.clone() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(to) = root.attribute("to") else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        };
        let Ok(to_jid) = crate::jid::CanonicalJid::parse(to) else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        };
        if to_jid.domainpart() != self.muc_domain() || to_jid.localpart().is_none() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        }
        let room_jid = to_jid.bare();
        let nick = to_jid.resourcepart().unwrap_or_default();
        if !valid_muc_room(localpart(&room_jid)) || !valid_muc_nick(nick) {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "jid-malformed",
            )));
        }
        if root.attribute("type") == Some("unavailable") {
            let Some(joined) = self
                .joined_rooms
                .get(&room_jid)
                .map(|entry| entry.value().clone())
            else {
                return Ok(Action::None);
            };
            let mut local_departure_room = None;
            let local_departure_guard = if self.state.cluster.is_enabled() {
                None
            } else {
                let Some(initial_room) = self
                    .state
                    .muc_service()
                    .local_room_snapshot(localpart(&room_jid))
                    .await?
                else {
                    self.joined_rooms.remove_if(&room_jid, |_, current| {
                        current.cluster_epoch == joined.cluster_epoch
                    });
                    return Ok(Action::None);
                };
                let guard = self
                    .state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await;
                let Some(refreshed_room) = self
                    .state
                    .muc_service()
                    .local_room_snapshot(localpart(&room_jid))
                    .await?
                else {
                    let stale_key = muc_occupant_key(&room_jid, &joined.nick);
                    self.state
                        .muc_occupants
                        .remove_if(&stale_key, |_, occupant| {
                            occupant.full_jid == full_jid
                                && occupant.connection_id == self.connection_id
                                && occupant.cluster_epoch == joined.cluster_epoch
                        });
                    self.joined_rooms.remove_if(&room_jid, |_, current| {
                        current.cluster_epoch == joined.cluster_epoch
                    });
                    return Ok(Action::None);
                };
                if refreshed_room.room_epoch != initial_room.room_epoch {
                    let stale_key = muc_occupant_key(&room_jid, &joined.nick);
                    self.state
                        .muc_occupants
                        .remove_if(&stale_key, |_, occupant| {
                            occupant.full_jid == full_jid
                                && occupant.connection_id == self.connection_id
                                && occupant.cluster_epoch == joined.cluster_epoch
                        });
                    self.joined_rooms.remove_if(&room_jid, |_, current| {
                        current.cluster_epoch == joined.cluster_epoch
                    });
                    return Ok(Action::None);
                }
                local_departure_room = Some(refreshed_room);
                Some(guard)
            };
            let mut clustered_leave = false;
            let mut clustered_event_id = None;
            let mut clustered_room_id = None;
            if self.state.cluster.is_enabled() {
                if let Some(room) = self
                    .state
                    .muc_service()
                    .local_room_snapshot(localpart(&room_jid))
                    .await?
                {
                    clustered_room_id = Some(room.id);
                    if let Some(target) = self
                        .state
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            joined.cluster_epoch,
                            self.connection_id,
                        )
                        .await?
                    {
                        let cluster_operation_id = uuid::Uuid::new_v4();
                        match self
                            .state
                            .muc_service()
                            .transition_local_cluster_occupancy(
                                cluster_operation_id,
                                &target,
                                "leave",
                                &self.state.cluster.node_id,
                                None,
                                None,
                                self.sm_db_id,
                                std::time::Duration::from_secs(90),
                            )
                            .await?
                        {
                            ClusterMucTransitionOutcome::Applied
                            | ClusterMucTransitionOutcome::Replay => {
                                clustered_leave = true;
                                clustered_event_id = Some(cluster_operation_id.to_string());
                            }
                            ClusterMucTransitionOutcome::Stale
                            | ClusterMucTransitionOutcome::Destroyed => {}
                            ClusterMucTransitionOutcome::Conflict
                            | ClusterMucTransitionOutcome::Unauthorized => {
                                return Ok(Action::Send(muc_stanza_error(
                                    root,
                                    &full_jid,
                                    "cancel",
                                    "not-acceptable",
                                )));
                            }
                        }
                        if let Err(error) = self
                            .state
                            .muc_service()
                            .wake_committed_operation(&self.state.cluster, cluster_operation_id)
                            .await
                        {
                            tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                                "MUC leave committed; signed wake failed and PostgreSQL polling will catch up");
                        }
                    }
                }
            }
            self.joined_rooms
                .remove_if(&room_jid, |_, current| current == &joined);
            let key = muc_occupant_key(&room_jid, &joined.nick);
            let Some((_, departed)) = self.state.muc_occupants.remove_if(&key, |_, occupant| {
                occupant.full_jid == full_jid
                    && occupant.connection_id == self.connection_id
                    && occupant.cluster_epoch == joined.cluster_epoch
            }) else {
                return Ok(Action::None);
            };

            let serializable = crate::state::SerializableMucOccupant::from(&departed);
            let locally_empty = self.state.muc_occupants_for(&room_jid).is_empty();
            if locally_empty {
                if let Some(room) = local_departure_room.as_ref() {
                    // Keep the room gate until the conditional temporary-room
                    // delete commits. A concurrent join cannot otherwise
                    // publish an occupant between the empty check and delete.
                    self.state
                        .muc_service()
                        .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                        .await?;
                }
            }
            drop(local_departure_guard);
            let removed_globally = self
                .state
                .cluster
                .unregister_muc_occupant_epoch(
                    &room_jid,
                    &departed.nick,
                    departed.cluster_epoch,
                    departed.connection_id,
                )
                .await
                .unwrap_or(false);
            if locally_empty {
                self.state.cluster.leave_muc(&room_jid).await?;
            }
            if !clustered_leave {
                self.state
                    .cluster
                    .send_muc_presence(&room_jid, &serializable, true, false, root.attribute("id"))
                    .await?;
            }
            let remaining = self.state.muc_occupants_for(&room_jid);
            if !clustered_leave {
                for (_, target) in &remaining {
                    let presence = muc_presence_stanza(
                        &crate::state::SerializableMucOccupant::from(&departed),
                        &target.full_jid,
                        true,
                        false,
                        false,
                        None,
                        departed.room_non_anonymous || target.role == "moderator",
                    );
                    let _ = self.state.deliver_to_muc_occupant(target, presence).await;
                }
            }
            let self_presence = muc_presence_stanza(
                &crate::state::SerializableMucOccupant::from(&departed),
                &full_jid,
                true,
                true,
                false,
                clustered_event_id.as_deref().or(root.attribute("id")),
                true,
            );
            let globally_empty = if let Some(room_id) = clustered_room_id {
                self.state
                    .muc_service()
                    .cluster_room_is_empty(room_id)
                    .await?
            } else {
                removed_globally
                    && self
                        .state
                        .cluster
                        .get_muc_occupants(&room_jid)
                        .await?
                        .is_empty()
            };
            if self.state.cluster.is_enabled() && remaining.is_empty() && globally_empty {
                if let Some(room) = self
                    .state
                    .muc_service()
                    .local_room_snapshot(localpart(&room_jid))
                    .await?
                {
                    self.state
                        .muc_service()
                        .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                        .await?;
                }
            }
            return Ok(Action::Send(self_presence));
        }
        if root.attribute("type").is_some() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "modify",
                "bad-request",
            )));
        }

        // A moderator can remove an occupant from another protocol session.
        // That operation owns the shared occupant map but cannot mutate the
        // target session's private `joined_rooms` map.  Treat a local join
        // marker without its exact occupant as stale so the next presence is
        // a real rejoin (and re-evaluates outcast/members-only policy) rather
        // than returning a one-shot `not-acceptable` error.
        if let Some(joined) = self
            .joined_rooms
            .get(&room_jid)
            .map(|membership| membership.value().clone())
        {
            let stale = self.authorized_muc_occupant(&room_jid).await?.is_none();
            if stale {
                self.joined_rooms
                    .remove_if(&room_jid, |_, current| current == &joined);
            }
        }

        if let Some(joined) = self
            .joined_rooms
            .get(&room_jid)
            .map(|membership| membership.value().clone())
        {
            let joined_nick = joined.nick;
            let old_key = muc_occupant_key(&room_jid, &joined_nick);
            let Some(mut occupant) = self.authorized_muc_occupant(&room_jid).await? else {
                self.joined_rooms.remove(&room_jid);
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "cancel",
                    "not-acceptable",
                )));
            };
            occupant.payload = muc_presence_payload(root, raw);
            if joined_nick == nick {
                let local_refresh_guard = if self.state.cluster.is_enabled() {
                    None
                } else {
                    let Some(initial_room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let guard = self
                        .state
                        .muc_service()
                        .lock_local_room_mutation(initial_room.id)
                        .await;
                    let Some(refreshed_room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    if refreshed_room.room_epoch != initial_room.room_epoch {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                    let Some(current) = self.state.muc_occupants.get(&old_key) else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    };
                    if current.full_jid != full_jid
                        || current.connection_id != self.connection_id
                        || current.cluster_epoch != joined.cluster_epoch
                    {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                    let requested_payload = occupant.payload.clone();
                    occupant = current.clone();
                    drop(current);
                    occupant.payload = requested_payload;
                    let affiliation = self
                        .state
                        .muc_service()
                        .local_affiliation(refreshed_room.id, user.id)
                        .await?;
                    if affiliation.as_deref() == Some("outcast") {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "auth",
                            "forbidden",
                        )));
                    }
                    if refreshed_room.members_only && affiliation.is_none() {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "auth",
                            "registration-required",
                        )));
                    }
                    occupant.affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
                    occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                        "moderator"
                    } else if refreshed_room.moderated && occupant.affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    }
                    .to_owned();
                    occupant.room_non_anonymous = refreshed_room.non_anonymous;
                    Some(guard)
                };
                if self.state.cluster.is_enabled() {
                    let Some(room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let Some(target) = self
                        .state
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            occupant.cluster_epoch,
                            occupant.connection_id,
                        )
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    };
                    if !self
                        .state
                        .muc_service()
                        .refresh_local_cluster_presence(
                            &target,
                            &self.state.cluster.node_id,
                            &occupant.payload,
                            std::time::Duration::from_secs(90),
                        )
                        .await?
                    {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                }
                let Some(mut current) = self.state.muc_occupants.get_mut(&old_key) else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                };
                if current.full_jid != full_jid
                    || current.connection_id != self.connection_id
                    || current.cluster_epoch != joined.cluster_epoch
                {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                }
                *current = occupant.clone();
                occupant = current.clone();
                drop(current);
                drop(local_refresh_guard);
                let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                if let Ok(json) = serde_json::to_string(&serializable) {
                    let cache_result = self
                        .state
                        .cluster
                        .register_muc_occupant(&room_jid, nick, &json)
                        .await;
                    if self.state.cluster.is_enabled() {
                        if let Err(error) = cache_result {
                            tracing::warn!(?error, room=%room_jid, nick=%nick,
                                "could not refresh Redis MUC presence soft-state");
                        }
                    } else if !cache_result? {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                    self.state
                        .cluster
                        .send_muc_presence(
                            &room_jid,
                            &serializable,
                            false,
                            false,
                            root.attribute("id"),
                        )
                        .await?;
                }
                let resync = has_muc_join_extension(root);
                for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                    let self_presence = recipient.full_jid == full_jid;
                    if resync && self_presence {
                        continue;
                    }
                    let update = muc_presence_stanza(
                        &serializable,
                        &recipient.full_jid,
                        false,
                        self_presence,
                        false,
                        root.attribute("id"),
                        serializable.room_non_anonymous
                            || self_presence
                            || recipient.role == "moderator",
                    );
                    let _ = self.state.deliver_to_muc_occupant(&recipient, update).await;
                }
                if resync {
                    let Some(room) = self
                        .state
                        .muc_service()
                        .local_room_snapshot(localpart(&room_jid))
                        .await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let history_request = match parse_muc_history_request(root, chrono::Utc::now())
                    {
                        Ok(request) => request,
                        Err(()) => {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                &full_jid,
                                "modify",
                                "bad-request",
                            )));
                        }
                    };
                    let owner_bare = bare_jid(&full_jid);
                    let blocked_patterns = self.state.muc_service().blocked_jids(user.id).await?;
                    let mut replies = Vec::new();
                    let mut roster_nicks = std::collections::HashSet::new();
                    for (_, present) in self.state.muc_occupants_for(&room_jid) {
                        if present.cluster_epoch == occupant.cluster_epoch {
                            continue;
                        }
                        let visible_sender = format!("{room_jid}/{}", present.nick);
                        let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
                        if !muc_sender_is_blocked(
                            &blocked_patterns,
                            owner_bare,
                            &visible_sender,
                            real_sender,
                        ) && roster_nicks.insert(present.nick.clone())
                        {
                            replies.push(muc_presence_stanza(
                                &crate::state::SerializableMucOccupant::from(&present),
                                &full_jid,
                                false,
                                false,
                                false,
                                None,
                                room.non_anonymous || occupant.role == "moderator",
                            ));
                        }
                    }
                    for json in self
                        .state
                        .cluster
                        .get_muc_occupants(&room_jid)
                        .await?
                        .into_values()
                    {
                        let Ok(present) =
                            serde_json::from_str::<crate::state::SerializableMucOccupant>(&json)
                        else {
                            continue;
                        };
                        if present.cluster_epoch == occupant.cluster_epoch {
                            continue;
                        }
                        let visible_sender = format!("{room_jid}/{}", present.nick);
                        let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
                        if !muc_sender_is_blocked(
                            &blocked_patterns,
                            owner_bare,
                            &visible_sender,
                            real_sender,
                        ) && roster_nicks.insert(present.nick.clone())
                        {
                            replies.push(muc_presence_stanza(
                                &present,
                                &full_jid,
                                false,
                                false,
                                false,
                                None,
                                room.non_anonymous || occupant.role == "moderator",
                            ));
                        }
                    }
                    replies.push(muc_presence_stanza(
                        &serializable,
                        &full_jid,
                        false,
                        true,
                        false,
                        root.attribute("id"),
                        true,
                    ));
                    let mut history = Vec::new();
                    if history_request.max_stanzas != 0 && room.logging_enabled {
                        for message in self
                            .state
                            .muc_service()
                            .local_history_since(room.id, 100, history_request.since)
                            .await?
                        {
                            let visible_sender = roxmltree::Document::parse(&message.stanza)
                                .ok()
                                .and_then(|document| {
                                    document.root_element().attribute("from").map(str::to_owned)
                                })
                                .unwrap_or_else(|| room_jid.clone());
                            if muc_sender_is_blocked(
                                &blocked_patterns,
                                owner_bare,
                                &visible_sender,
                                room.non_anonymous.then_some(message.sender_jid.as_str()),
                            ) {
                                continue;
                            }
                            let authoritative = set_muc_occupant_id(
                                &message.stanza,
                                &muc_occupant_id(&room.occupant_id_secret, &message.sender_jid),
                            );
                            let authoritative = if room.non_anonymous {
                                add_muc_sender(&authoritative, &message.sender_jid)
                            } else {
                                authoritative
                            };
                            history.push(set_to(
                                &add_delay_from(
                                    &authoritative,
                                    message.created_at,
                                    Some(&room_jid),
                                ),
                                &full_jid,
                            ));
                        }
                    }
                    replies.extend(apply_muc_history_bounds(history, history_request));
                    replies.push(current_muc_subject_stanza(&room, &room_jid, &full_jid));
                    return Ok(Action::SendMany(replies));
                }
                return Ok(Action::None);
            }

            let Some(room) = self
                .state
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await?
            else {
                self.joined_rooms.remove(&room_jid);
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "cancel",
                    "item-not-found",
                )));
            };
            if self
                .state
                .muc_service()
                .local_nick_reserved_for_other(room.id, user.id, nick)
                .await?
            {
                return Ok(Action::Send(muc_stanza_error(
                    root, &full_jid, "cancel", "conflict",
                )));
            }

            let local_rename_guard = if self.state.cluster.is_enabled() {
                None
            } else {
                Some(
                    self.state
                        .muc_service()
                        .lock_local_room_mutation(room.id)
                        .await,
                )
            };

            if local_rename_guard.is_some() {
                let requested_payload = occupant.payload.clone();
                let Some(refreshed_room) = self
                    .state
                    .muc_service()
                    .local_room_snapshot(localpart(&room_jid))
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                };
                if refreshed_room.room_epoch != room.room_epoch {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                }
                let Some(current) = self.validated_muc_occupant(&room_jid) else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                };
                occupant = current;
                occupant.payload = requested_payload;
                let affiliation = self
                    .state
                    .muc_service()
                    .local_affiliation(refreshed_room.id, user.id)
                    .await?;
                if affiliation.as_deref() == Some("outcast") {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "forbidden",
                    )));
                }
                if refreshed_room.members_only && affiliation.is_none() {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "registration-required",
                    )));
                }
                let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
                if occupant.affiliation != affiliation {
                    occupant.affiliation = affiliation;
                    occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                        "moderator"
                    } else if refreshed_room.moderated {
                        "visitor"
                    } else {
                        "participant"
                    }
                    .to_owned();
                }
                occupant.room_non_anonymous = refreshed_room.non_anonymous;
                if self
                    .state
                    .muc_service()
                    .local_nick_reserved_for_other(refreshed_room.id, user.id, nick)
                    .await?
                {
                    return Ok(Action::Send(muc_stanza_error(
                        root, &full_jid, "cancel", "conflict",
                    )));
                }
            }

            let new_key = muc_occupant_key(&room_jid, nick);
            if !self.state.cluster.is_enabled() && self.state.muc_occupants.contains_key(&new_key) {
                return Ok(Action::Send(muc_stanza_error(
                    root, &full_jid, "cancel", "conflict",
                )));
            }
            let old_occupant = occupant.clone();
            let old_serializable = crate::state::SerializableMucOccupant::from(&old_occupant);
            occupant.nick = nick.to_owned();
            let new_serializable = crate::state::SerializableMucOccupant::from(&occupant);
            let old_json = serde_json::to_string(&old_serializable)?;
            let new_json = serde_json::to_string(&new_serializable)?;
            let mut cluster_operation = None;
            if self.state.cluster.is_enabled() {
                self.state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                let Some(target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                };
                let cluster_operation_id = uuid::Uuid::new_v4();
                match self
                    .state
                    .muc_service()
                    .rename_local_cluster_occupancy(
                        cluster_operation_id,
                        &target,
                        &self.state.cluster.node_id,
                        nick,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_operation = Some(cluster_operation_id)
                    }
                    ClusterMucTransitionOutcome::Conflict => {
                        return Ok(Action::Send(muc_stanza_error(
                            root, &full_jid, "cancel", "conflict",
                        )));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            &full_jid,
                            "cancel",
                            "not-acceptable",
                        )));
                    }
                }
                if let Err(error) = self
                    .state
                    .muc_service()
                    .wake_committed_operation(&self.state.cluster, cluster_operation_id)
                    .await
                {
                    tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                        "MUC rename committed; signed wake failed and PostgreSQL polling will catch up");
                }
            }
            match self
                .state
                .cluster
                .rename_muc_occupant(
                    &room_jid,
                    &joined_nick,
                    nick,
                    occupant.cluster_epoch,
                    &old_json,
                    &new_json,
                )
                .await
            {
                Ok(crate::cluster::MucRename::Renamed) => {}
                Ok(crate::cluster::MucRename::Conflict) => {
                    tracing::warn!(%room_jid, old_nick=%joined_nick, new_nick=%nick,
                        "Redis MUC nickname cache conflicted after PostgreSQL committed; reconciliation will replace soft state");
                }
                Ok(crate::cluster::MucRename::Stale) => {
                    tracing::warn!(%room_jid, old_nick=%joined_nick, new_nick=%nick,
                        "Redis MUC nickname cache was stale after PostgreSQL committed");
                }
                Err(error) => {
                    self.state.cluster.record_control_plane_failure(&error);
                    tracing::warn!(?error, %room_jid,
                        "PostgreSQL committed MUC rename; Redis wake/cache update will be reconciled");
                }
            }
            // DashMap cannot atomically move an entry between two keys.  The
            // room writer gate makes the single-node transition linearizable:
            // remove the exact old incarnation first, then publish the new
            // nickname with Entry. Readers can briefly observe the actor as
            // absent, but never as two occupants. Cluster mode has already
            // committed the rename in PostgreSQL; its local map is soft state
            // and follows the same old-first ordering without rolling PG back.
            let removed_old = self.state.muc_occupants.remove_if(&old_key, |_, current| {
                current.full_jid == full_jid
                    && current.connection_id == self.connection_id
                    && current.cluster_epoch == occupant.cluster_epoch
            });
            if removed_old.is_none() {
                if cluster_operation.is_some() {
                    tracing::warn!(room=%room_jid, old_nick=%joined_nick, new_nick=%nick,
                        "PG-authoritative MUC rename found an already-pruned old local cache entry");
                } else {
                    self.joined_rooms.remove_if(&room_jid, |_, current| {
                        current.cluster_epoch == occupant.cluster_epoch
                    });
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "not-acceptable",
                    )));
                }
            }
            if self.state.cluster.is_enabled() {
                if let Some((_, stale)) = self.state.muc_occupants.remove(&new_key) {
                    tracing::warn!(
                        %room_jid,
                        %nick,
                        stale_full_jid = %stale.full_jid,
                        stale_epoch = %stale.cluster_epoch,
                        "evicting stale local MUC nickname cache entry after PostgreSQL rename"
                    );
                }
            }
            let locally_reserved = match self.state.muc_occupants.entry(new_key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(_) => false,
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    entry.insert(occupant.clone());
                    true
                }
            };
            if !locally_reserved {
                if !self.state.cluster.is_enabled() {
                    // The exact old entry was removed above. Restore it before
                    // rejecting so a failed rename cannot silently evict the
                    // actor. An occupied old key indicates an out-of-contract
                    // ungated writer; do not overwrite that actor.
                    if let dashmap::mapref::entry::Entry::Vacant(entry) =
                        self.state.muc_occupants.entry(old_key.clone())
                    {
                        entry.insert(old_occupant);
                    } else {
                        tracing::error!(%room_jid, old_nick=%joined_nick,
                            "could not restore local MUC actor after nickname collision");
                    }
                }
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    if self.state.cluster.is_enabled() {
                        "wait"
                    } else {
                        "cancel"
                    },
                    if self.state.cluster.is_enabled() {
                        "internal-server-error"
                    } else {
                        "conflict"
                    },
                )));
            }
            self.joined_rooms.insert(
                room_jid.clone(),
                crate::state::JoinedMucMembership {
                    nick: nick.to_owned(),
                    cluster_epoch: occupant.cluster_epoch,
                },
            );
            drop(local_rename_guard);
            if cluster_operation.is_some() {
                return Ok(Action::None);
            }
            self.state
                .cluster
                .send_muc_nickname_change(
                    &room_jid,
                    &old_serializable,
                    &new_serializable,
                    root.attribute("id"),
                )
                .await?;
            for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                let recipient_serializable =
                    crate::state::SerializableMucOccupant::from(&recipient);
                let unavailable = muc_nickname_change_presence(
                    &old_serializable,
                    &recipient_serializable,
                    nick,
                    root.attribute("id"),
                );
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&recipient, unavailable)
                    .await;
                let self_presence = recipient.full_jid == full_jid;
                let available = muc_presence_stanza(
                    &new_serializable,
                    &recipient.full_jid,
                    false,
                    self_presence,
                    false,
                    root.attribute("id"),
                    new_serializable.room_non_anonymous
                        || self_presence
                        || recipient.role == "moderator",
                );
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&recipient, available)
                    .await;
            }
            return Ok(Action::None);
        }

        if self.joined_rooms.len() >= MAX_JOINED_ROOMS_PER_SESSION {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "wait",
                "resource-constraint",
            )));
        }
        let history_request = match parse_muc_history_request(root, chrono::Utc::now()) {
            Ok(request) => request,
            Err(()) => {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "modify",
                    "bad-request",
                )));
            }
        };
        let key = muc_occupant_key(&room_jid, nick);
        if !self.state.cluster.is_enabled() && self.state.muc_occupants.contains_key(&key) {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        let (room, created) = match self
            .state
            .muc_service()
            .get_or_create_local_room(localpart(&room_jid), user.id, &full_jid)
            .await
        {
            Ok(result) => result,
            Err(error) if crate::services::muc::MucService::is_capacity_exhausted(&error) => {
                self.state
                    .metrics
                    .capacity_reservations_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "wait",
                    "resource-constraint",
                )));
            }
            Err(error) => return Err(error),
        };
        if !created && room.configuration_is_expired(chrono::Utc::now()) {
            let _ = self
                .state
                .muc_service()
                .delete_expired_locked_room(room.id)
                .await?;
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        }
        if !created
            && room.is_locked()
            && !room.can_configure_locked_room(&full_jid, chrono::Utc::now())
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        }
        if created {
            let actor_bare = format!("{}@{}", user.username, self.state.config.domain);
            let _ =
                super::mix_muc::maybe_link_local_mirror(&self.state, &room.localpart, &actor_bare)
                    .await?;
        }
        let affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?;
        tracing::info!(
            room = %room_jid, user = %user.username, user_id = %user.id,
            room_id = %room.id, members_only = %room.members_only,
            affiliation = ?affiliation, "MUC join: affiliation check"
        );
        if affiliation.as_deref() == Some("outcast") {
            tracing::warn!(room = %room_jid, user = %user.username, "MUC join denied: user is outcast");
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "forbidden",
            )));
        }
        if let Some(password_hash) = room.password_hash.as_deref() {
            let supplied_password = root
                .children()
                .find(|node| {
                    node.is_element()
                        && node.tag_name().name() == "x"
                        && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
                })
                .and_then(|x| child_text(x, "password"))
                .unwrap_or_default();
            let password_hash = zeroize::Zeroizing::new(password_hash.to_owned());
            let supplied_password = zeroize::Zeroizing::new(supplied_password.to_owned());
            let password_valid = match crate::password_work::run(move || {
                Ok(crate::services::muc::MucService::verify_room_password(
                    &password_hash,
                    &supplied_password,
                ))
            })
            .await
            {
                Ok(valid) => valid,
                Err(error) if error.is_overloaded() => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "wait",
                        "resource-constraint",
                    )));
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "room password verification task failed: {error}"
                    ));
                }
            };
            if !password_valid {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    &full_jid,
                    "auth",
                    "not-authorized",
                )));
            }
        }
        if room.members_only && affiliation.is_none() {
            tracing::warn!(room = %room_jid, user = %user.username, "MUC join denied: members-only and no affiliation");
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "registration-required",
            )));
        }
        if self
            .state
            .muc_service()
            .local_nick_reserved_for_other(room.id, user.id, nick)
            .await?
        {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        let local_join_guard = if self.state.cluster.is_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(room.id)
                    .await,
            )
        };
        let Some(refreshed_room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        };
        if refreshed_room.room_epoch != room.room_epoch {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        }
        if refreshed_room.config_version != room.config_version {
            // Password/policy validation above belongs to the exact config
            // version read before the expensive password check. Ask the
            // client to retry instead of accepting under a mixed policy.
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "wait",
                "resource-constraint",
            )));
        }
        let room = refreshed_room;
        if room.configuration_is_expired(chrono::Utc::now())
            || (room.is_locked() && !room.can_configure_locked_room(&full_jid, chrono::Utc::now()))
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "cancel",
                "item-not-found",
            )));
        }
        let affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?;
        if affiliation.as_deref() == Some("outcast") {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "forbidden",
            )));
        }
        if room.members_only && affiliation.is_none() {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "auth",
                "registration-required",
            )));
        }
        if self
            .state
            .muc_service()
            .local_nick_reserved_for_other(room.id, user.id, nick)
            .await?
        {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        // The early check above is only a fast path. In single-node mode the
        // exact nickname and room capacity must be rechecked while holding the
        // room gate because independent client sessions join concurrently.
        if !self.state.cluster.is_enabled() && self.state.muc_occupants.contains_key(&key) {
            return Ok(Action::Send(muc_stanza_error(
                root, &full_jid, "cancel", "conflict",
            )));
        }
        let local_occupant_count = if self.state.cluster.is_enabled() {
            0
        } else {
            self.state.muc_occupants_for(&room_jid).len()
        };
        // XEP-0045 requires a reasonable administrative reserve so a room
        // cannot be permanently locked by filling every public slot.
        let privileged_join = matches!(affiliation.as_deref(), Some("owner" | "admin"));
        let effective_capacity = room.max_occupants as usize + usize::from(privileged_join) * 10;
        if !self.state.cluster.is_enabled() && local_occupant_count >= effective_capacity {
            return Ok(Action::Send(muc_stanza_error(
                root,
                &full_jid,
                "wait",
                "service-unavailable",
            )));
        }

        let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
        let role = if matches!(affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else if room.moderated && affiliation == "none" {
            "visitor"
        } else {
            "participant"
        }
        .to_owned();

        let payload = muc_presence_payload(root, raw);

        let occupant = crate::state::MucOccupant {
            full_jid: full_jid.clone(),
            room_jid: room_jid.clone(),
            nick: nick.to_owned(),
            endpoint: crate::state::MucOccupantEndpoint::Local(self.outbound.clone()),
            affiliation,
            role,
            room_non_anonymous: room.non_anonymous,
            occupant_id: muc_occupant_id(&room.occupant_id_secret, bare_jid(&full_jid)),
            cluster_epoch: uuid::Uuid::new_v4(),
            connection_id: self.connection_id,
            sm_session_id: self.sm_db_id,
            payload,
        };
        let serializable = crate::state::SerializableMucOccupant::from(&occupant);
        let mut cluster_event_id = None;
        if self.state.cluster.is_enabled() {
            self.state
                .cluster
                .admit(crate::cluster::ClusterOperation::MucMutation)?;
            // PostgreSQL is the only clustered occupancy authority.  The
            // following Redis reservation is retained as a soft cache for
            // presence fan-out, but it can no longer authorize the join.
            let principal = ClusterMucPrincipal::Local {
                user_id: user.id,
                bare_jid: bare_jid(&full_jid).to_owned(),
            };
            let cluster_operation_id = uuid::Uuid::new_v4();
            match self
                .state
                .muc_service()
                .claim_local_cluster_occupancy(ClusterMucJoin {
                    operation_id: cluster_operation_id,
                    room_id: room.id,
                    expected_room_epoch: room.room_epoch,
                    expected_config_version: room.config_version,
                    principal,
                    full_jid: &full_jid,
                    nick,
                    owner_node_id: &self.state.cluster.node_id,
                    connection_uuid: self.connection_id,
                    connection_epoch: 1,
                    sm_session_id: self.sm_db_id,
                    occupant_incarnation: occupant.cluster_epoch,
                    presence_payload: &occupant.payload,
                    lease: std::time::Duration::from_secs(90),
                })
                .await?
            {
                ClusterMucJoinOutcome::Joined(authority)
                | ClusterMucJoinOutcome::Replay(authority) => {
                    debug_assert_eq!(authority.occupant_incarnation, occupant.cluster_epoch);
                    debug_assert_eq!(authority.connection_uuid, self.connection_id);
                }
                ClusterMucJoinOutcome::Outcast => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "forbidden",
                    )));
                }
                ClusterMucJoinOutcome::MembershipRequired => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "auth",
                        "registration-required",
                    )));
                }
                ClusterMucJoinOutcome::ReservedNickname
                | ClusterMucJoinOutcome::NicknameConflict
                | ClusterMucJoinOutcome::FullJidConflict => {
                    return Ok(Action::Send(muc_stanza_error(
                        root, &full_jid, "cancel", "conflict",
                    )));
                }
                ClusterMucJoinOutcome::Full => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "wait",
                        "service-unavailable",
                    )));
                }
                ClusterMucJoinOutcome::RoomMissing
                | ClusterMucJoinOutcome::RoomDestroyed
                | ClusterMucJoinOutcome::RoomLocked
                | ClusterMucJoinOutcome::StaleRoom => {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        &full_jid,
                        "cancel",
                        "item-not-found",
                    )));
                }
            }
            cluster_event_id = Some(cluster_operation_id.to_string());
            if let Err(error) = self
                .state
                .muc_service()
                .wake_committed_operation(&self.state.cluster, cluster_operation_id)
                .await
            {
                tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                    "MUC join committed; signed wake failed and PostgreSQL polling will catch up");
            }
            // Lazily remove occupants whose node lease has expired before the
            // atomic nickname/capacity reservation.
            if let Err(error) = self.state.cluster.get_muc_occupants(&room_jid).await {
                tracing::warn!(?error, %room_jid,
                    "PostgreSQL committed MUC join; Redis occupancy cache refresh failed");
            }
            match self
                .state
                .cluster
                .try_register_muc_occupant(
                    &room_jid,
                    nick,
                    &serde_json::to_string(&serializable)?,
                    effective_capacity,
                )
                .await
            {
                Ok(crate::cluster::MucRegistration::Joined) => {}
                Ok(crate::cluster::MucRegistration::Conflict)
                | Ok(crate::cluster::MucRegistration::Full) => {
                    tracing::warn!(%room_jid, %nick,
                        "Redis MUC cache disagreed with committed PostgreSQL occupancy; cache will reconcile");
                }
                Err(error) => tracing::warn!(?error, %room_jid,
                    "PostgreSQL committed MUC join; Redis cache update failed"),
            }
        }
        // Snapshot the already-published local audience before publishing the
        // joining occupant. In single-node mode the room mutation guard keeps
        // this set stable through publication; in clustered mode PostgreSQL
        // has already admitted the join and this remains only a local fan-out
        // snapshot (the durable cluster event covers other nodes).
        let local_existing = self.state.muc_occupants_for(&room_jid);
        let locally_published = match self.state.muc_occupants.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(_) => false,
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(occupant.clone());
                true
            }
        };
        if !locally_published {
            // Clustered mode already committed the authoritative nickname and
            // treats a local collision as stale cache elsewhere. A collision
            // here can only be a single-node admission race and must not
            // overwrite the actor which won the room gate.
            if !self.state.cluster.is_enabled() {
                return Ok(Action::Send(muc_stanza_error(
                    root, &full_jid, "cancel", "conflict",
                )));
            }
            tracing::warn!(%room_jid, %nick, "replacing stale local MUC actor after authoritative clustered join");
            self.state
                .muc_occupants
                .insert(muc_occupant_key(&room_jid, nick), occupant.clone());
        }
        self.joined_rooms.insert(
            room_jid.clone(),
            crate::state::JoinedMucMembership {
                nick: nick.to_owned(),
                cluster_epoch: occupant.cluster_epoch,
            },
        );
        drop(local_join_guard);

        if let Ok(json) = serde_json::to_string(&serializable) {
            let _ = self.state.cluster.join_muc(&room_jid).await;
            let _ = self
                .state
                .cluster
                .register_muc_occupant(&room_jid, nick, &json)
                .await;
            if cluster_event_id.is_none() {
                let _ = self
                    .state
                    .cluster
                    .send_muc_presence(
                        &room_jid,
                        &serializable,
                        false,
                        created,
                        root.attribute("id"),
                    )
                    .await;
            }
        }

        let global_map = self
            .state
            .cluster
            .get_muc_occupants(&room_jid)
            .await
            .unwrap_or_default();
        let owner_bare = bare_jid(&full_jid);
        let blocked_patterns = self.state.muc_service().blocked_jids(user.id).await?;
        let mut replies = Vec::with_capacity(global_map.len() + 24);
        let mut roster_nicks = std::collections::HashSet::new();
        for (_, json_str) in global_map {
            if let Ok(present) =
                serde_json::from_str::<crate::state::SerializableMucOccupant>(&json_str)
            {
                let visible_sender = format!("{room_jid}/{}", present.nick);
                let real_sender = room.non_anonymous.then_some(present.full_jid.as_str());
                if present.nick != nick
                    && !muc_sender_is_blocked(
                        &blocked_patterns,
                        owner_bare,
                        &visible_sender,
                        real_sender,
                    )
                    && roster_nicks.insert(present.nick.clone())
                {
                    replies.push(muc_presence_stanza(
                        &present,
                        &full_jid,
                        false,
                        false,
                        false,
                        None,
                        room.non_anonymous || occupant.role == "moderator",
                    ));
                }
            }
        }
        for (_, target) in &local_existing {
            let visible_sender = format!("{room_jid}/{}", target.nick);
            let real_sender = room.non_anonymous.then_some(target.full_jid.as_str());
            if !muc_sender_is_blocked(&blocked_patterns, owner_bare, &visible_sender, real_sender)
                && roster_nicks.insert(target.nick.clone())
            {
                replies.push(muc_presence_stanza(
                    &crate::state::SerializableMucOccupant::from(target),
                    &full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                ));
            }
            if cluster_event_id.is_none() {
                let joined = muc_presence_stanza(
                    &serializable,
                    &target.full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || target.role == "moderator",
                );
                let _ = self.state.deliver_to_muc_occupant(target, joined).await;
            }
        }
        let mut self_join = muc_presence_stanza(
            &serializable,
            &full_jid,
            false,
            true,
            created,
            cluster_event_id.as_deref().or(root.attribute("id")),
            true,
        );
        if room.logging_enabled {
            self_join = add_muc_user_status(&self_join, 170);
        }
        replies.push(self_join);
        tracing::info!(
            room = %room_jid, user = %user.username,
            "MUC join: success"
        );

        // XEP-0045 requires initial room presence first, then all selected
        // history, and only then the current subject.  Subject-only archive
        // records remain available through MAM but are not join history.
        let mut history_stanzas = Vec::new();
        let history_candidates = if history_request.max_stanzas == 0 || !room.logging_enabled {
            Vec::new()
        } else {
            self.state
                .muc_service()
                .local_history_since(room.id, 100, history_request.since)
                .await?
        };
        for message in history_candidates {
            let visible_sender = roxmltree::Document::parse(&message.stanza)
                .ok()
                .and_then(|document| document.root_element().attribute("from").map(str::to_owned))
                .unwrap_or_else(|| room_jid.clone());
            if muc_sender_is_blocked(
                &blocked_patterns,
                owner_bare,
                &visible_sender,
                room.non_anonymous.then_some(message.sender_jid.as_str()),
            ) {
                continue;
            }
            let occupant_id = muc_occupant_id(&room.occupant_id_secret, &message.sender_jid);
            let authoritative = set_muc_occupant_id(&message.stanza, &occupant_id);
            let history = if room.non_anonymous {
                add_muc_sender(&authoritative, &message.sender_jid)
            } else {
                authoritative
            };
            history_stanzas.push(set_to(
                &add_delay_from(&history, message.created_at, Some(&room_jid)),
                &full_jid,
            ));
        }
        replies.extend(apply_muc_history_bounds(history_stanzas, history_request));
        replies.push(current_muc_subject_stanza(&room, &room_jid, &full_jid));
        Ok(Action::SendMany(replies))
    }

    pub(crate) async fn muc_admin_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid_owned, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let room_jid = room_jid_owned.as_str();
        let Some(initial_room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        let _local_authority_guard = if self.state.cluster.is_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await,
            )
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if room.id != initial_room.id || room.room_epoch != initial_room.room_epoch {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        let Some(item) = query
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "item")
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        };

        let requested_affiliation = item.attribute("affiliation");
        let requested_role = item.attribute("role");
        if requested_affiliation.is_some() == requested_role.is_some() {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        }
        if let Some(requested_role) = requested_role {
            if !matches!(requested_role, "moderator" | "participant" | "visitor") {
                return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            let actor = self.validated_muc_occupant(room_jid);
            let asserted_local_role = actor
                .as_ref()
                .map(|occupant| occupant.role.as_str())
                .unwrap_or("none");
            let actor_target = if self.state.cluster.is_enabled() {
                if let Some(actor) = actor.as_ref() {
                    self.state
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            actor.cluster_epoch,
                            actor.connection_id,
                        )
                        .await?
                        .filter(|target| {
                            target.room_epoch == room.room_epoch
                                && target.full_jid == actor.full_jid
                                && target.nick == actor.nick
                                && target.connection_uuid == actor.connection_id
                        })
                } else {
                    None
                }
            } else {
                None
            };
            let actor_scope = canonical_bare_key(full_jid)?;
            let role_list = match self
                .state
                .muc_service()
                .authorized_admin_role_list(
                    room.id,
                    room.room_epoch,
                    user.id,
                    &actor_scope,
                    asserted_local_role,
                    actor_target.as_ref(),
                    self.state.cluster.is_enabled(),
                    requested_role,
                )
                .await?
            {
                MucAdminSnapshot::Authorized(list) => list,
                MucAdminSnapshot::Unauthorized => {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                }
                MucAdminSnapshot::Stale => {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                }
            };
            let reveal_real_jids =
                role_list.non_anonymous || role_list.requester_role == "moderator";
            let mut occupants = if self.state.cluster.is_enabled() {
                role_list
                    .entries
                    .into_iter()
                    .map(|entry| (entry.nick, entry.bare_jid))
                    .collect::<Vec<_>>()
            } else {
                self.state
                    .muc_occupants_for(room_jid)
                    .into_iter()
                    .filter(|(_, occupant)| occupant.role == requested_role)
                    .filter_map(|(_, occupant)| {
                        canonical_bare_key(&occupant.full_jid)
                            .ok()
                            .map(|bare| (occupant.nick, bare))
                    })
                    .collect::<Vec<_>>()
            };
            occupants.sort_by(|left, right| left.0.cmp(&right.0));
            let mut result =
                XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
            for (nick, bare) in occupants {
                result.push_child(
                    XmlElement::new("item")
                        .attr("nick", &nick)
                        .attr("role", requested_role)
                        .optional_attr("jid", reveal_real_jids.then_some(bare.as_str())),
                );
            }
            return Ok(Action::Send(iq_result_from(id, room_jid, &result.finish())));
        }
        let requested_affiliation =
            requested_affiliation.expect("exclusive role/affiliation check");
        if !matches!(
            requested_affiliation,
            "owner" | "admin" | "member" | "outcast"
        ) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        }

        let actor_scope = canonical_bare_key(full_jid)?;
        let entries = match self
            .state
            .muc_service()
            .authorized_admin_affiliation_list(
                room.id,
                room.room_epoch,
                user.id,
                &actor_scope,
                requested_affiliation,
            )
            .await?
        {
            MucAdminSnapshot::Authorized(entries) => entries,
            MucAdminSnapshot::Unauthorized => {
                return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
            }
            MucAdminSnapshot::Stale => {
                return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
            }
        };
        let mut result = XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
        for entry in entries {
            result.push_child(
                XmlElement::new("item")
                    .attr("affiliation", &entry.affiliation)
                    .attr("jid", &entry.bare_jid),
            );
        }
        Ok(Action::Send(iq_result_from(id, room_jid, &result.finish())))
    }
}

impl ProtocolSession {
    pub(crate) async fn muc_admin_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid_owned, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let room_jid = room_jid_owned.as_str();
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        let gated_room_id = room.id;
        let gated_room_epoch = room.room_epoch;
        let _local_room_guard = if self.state.cluster.is_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(room.id)
                    .await,
            )
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if room.id != gated_room_id || room.room_epoch != gated_room_epoch {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        let my_affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        let actor = self.authorized_muc_occupant(room_jid).await?;
        let actor_nick = actor.as_ref().map(|occupant| occupant.nick.clone());
        let my_role = actor
            .as_ref()
            .map(|occupant| occupant.role.clone())
            .unwrap_or_else(|| "none".to_owned());
        if !matches!(my_affiliation.as_str(), "owner" | "admin") && my_role != "moderator" {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        let items = query
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if items.is_empty() || items.iter().any(|node| node.tag_name().name() != "item") {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        }
        if items.iter().any(|item| {
            item.attribute("affiliation").is_some() == item.attribute("role").is_some()
                || (item.attribute("affiliation").is_some() && item.attribute("jid").is_none())
                || (item.attribute("role").is_some() && item.attribute("nick").is_none())
        }) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        }
        let affiliation_count = items
            .iter()
            .filter(|item| item.attribute("affiliation").is_some())
            .count();
        let role_count = items.len().saturating_sub(affiliation_count);
        if (affiliation_count > 0 && role_count > 0) || role_count > 1 {
            // The repository currently has atomic batch semantics for
            // affiliations and exact single-target semantics for role/kick.
            // Reject unsupported mixed/multi-role shapes before any write.
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        }

        // Validate the entire IQ before committing any durable affiliation
        // changes.  XEP-0045 allows multiple items in one request; returning
        // an error after committing a valid prefix would violate the IQ's
        // request/response semantics and can strand a room without its owner.
        let mut durable_changes = Vec::new();
        let mut previous_affiliations = std::collections::HashMap::new();
        let global_occupants = if self.state.cluster.is_enabled() {
            std::collections::HashMap::new()
        } else {
            self.state
                .cluster
                .get_muc_occupants(room_jid)
                .await?
                .into_values()
                .filter_map(|json| {
                    serde_json::from_str::<crate::state::SerializableMucOccupant>(&json).ok()
                })
                .map(|occupant| (occupant.nick.clone(), occupant))
                .collect::<std::collections::HashMap<_, _>>()
        };
        for item in &items {
            if let (Some(target_raw), Some(new_affil)) =
                (item.attribute("jid"), item.attribute("affiliation"))
            {
                if !matches!(my_affiliation.as_str(), "owner" | "admin") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                }
                if !matches!(new_affil, "owner" | "admin" | "member" | "outcast" | "none") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
                if (new_affil == "owner" && my_affiliation != "owner")
                    || (my_affiliation == "admin" && matches!(new_affil, "owner" | "admin"))
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                let Ok(target) = CanonicalJid::parse(target_raw) else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                };
                let Some(target_localpart) = target.localpart() else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                };
                let target_bare = target.bare();
                if new_affil == "outcast"
                    && self
                        .full_jid
                        .as_deref()
                        .and_then(|jid| canonical_bare_key(jid).ok())
                        .as_deref()
                        == Some(target_bare.as_str())
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
                }
                let (target, current) = if target.domainpart() == self.state.config.domain {
                    let Some(target_user) = self
                        .state
                        .muc_service()
                        .enabled_local_account(target_localpart)
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                    };
                    (
                        MucAffiliationTarget::LocalUsername(target_localpart.to_owned()),
                        self.state
                            .muc_service()
                            .local_affiliation(room.id, target_user.id)
                            .await?,
                    )
                } else {
                    (
                        MucAffiliationTarget::FederatedBareJid(target_bare.clone()),
                        self.state
                            .muc_service()
                            .federated_affiliation(room.id, &target_bare)
                            .await?,
                    )
                };
                if my_affiliation == "admin"
                    && matches!(current.as_deref(), Some("owner" | "admin"))
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                previous_affiliations
                    .insert(target_bare, current.unwrap_or_else(|| "none".to_owned()));
                durable_changes.push(MucAffiliationChange {
                    target,
                    affiliation: new_affil.to_owned(),
                });
            } else if let (Some(target_nick), Some(new_role)) =
                (item.attribute("nick"), item.attribute("role"))
            {
                if my_role != "moderator" {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                }
                if !matches!(new_role, "moderator" | "participant" | "visitor" | "none") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
                let Ok(target_nick) = prepare_muc_nick(target_nick) else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                };
                let target_key = muc_occupant_key(room_jid, &target_nick);
                let target = if self.state.cluster.is_enabled() {
                    let authoritative = self
                        .state
                        .muc_service()
                        .local_cluster_occupancy_target_by_nick(
                            room.id,
                            room.room_epoch,
                            &target_nick,
                        )
                        .await?;
                    if let Some(authoritative) = authoritative {
                        self.state
                            .muc_service()
                            .exact_local_cluster_occupancy_snapshot(&authoritative)
                            .await?
                            .map(|occupancy| crate::state::SerializableMucOccupant {
                                full_jid: occupancy.full_jid,
                                room_jid: room_jid.to_owned(),
                                nick: occupancy.nick,
                                affiliation: occupancy.affiliation,
                                role: occupancy.role,
                                room_non_anonymous: room.non_anonymous,
                                occupant_id: String::new(),
                                cluster_epoch: occupancy.occupant_incarnation,
                                connection_id: occupancy.connection_uuid,
                                federated_domain: None,
                                sm_session_id: occupancy.sm_session_id,
                                payload: String::new(),
                            })
                    } else {
                        None
                    }
                } else {
                    self.state
                        .muc_occupants
                        .get(&target_key)
                        .map(|occupant| crate::state::SerializableMucOccupant::from(&*occupant))
                        .or_else(|| global_occupants.get(&target_nick).cloned())
                };
                let Some(target) = target else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                };
                if (my_affiliation == "admin"
                    && matches!(target.affiliation.as_str(), "owner" | "admin"))
                    || ((new_role == "moderator" || target.role == "moderator")
                        && !matches!(my_affiliation.as_str(), "owner" | "admin"))
                    || (matches!(target.affiliation.as_str(), "owner" | "admin")
                        && !matches!(my_affiliation.as_str(), "owner" | "admin"))
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
            }
        }
        let all_affiliation_changes = items
            .iter()
            .all(|item| item.attribute("affiliation").is_some());
        let mut cluster_affiliation_operation = None;
        let affiliation_outcome = if self.state.cluster.is_enabled() && !durable_changes.is_empty()
        {
            self.state
                .cluster
                .admit(crate::cluster::ClusterOperation::MucMutation)?;
            let Some(actor) = self.authorized_muc_occupant(room_jid).await? else {
                return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
            };
            let Some(actor_target) = self
                .state
                .muc_service()
                .local_cluster_occupancy_target(room.id, actor.cluster_epoch, actor.connection_id)
                .await?
            else {
                return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
            };
            let operation_id =
                crate::services::muc::MucService::operation_id(&serde_json::json!({
                    "kind":"admin_affiliation_batch","stream":self.connection_id,"iq_id":id,
                    "room":room_jid,"actor":full_jid,"changes":durable_changes,
                }))?;
            let outcome = self
                .state
                .muc_service()
                .apply_local_cluster_affiliations_batch(
                    operation_id,
                    room.id,
                    room.room_epoch,
                    room.config_version,
                    &actor_target,
                    &ClusterMucPrincipal::Local {
                        user_id: user.id,
                        bare_jid: bare_jid(full_jid).to_owned(),
                    },
                    full_jid,
                    &durable_changes,
                )
                .await?;
            cluster_affiliation_operation = Some(operation_id);
            outcome
        } else {
            self.state
                .muc_service()
                .set_local_legacy_affiliations_batch(room.id, &durable_changes)
                .await?
        };
        match affiliation_outcome {
            MucAffiliationBatchOutcome::Applied => {}
            MucAffiliationBatchOutcome::DuplicateTarget => {
                return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            MucAffiliationBatchOutcome::LastOwner => {
                return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
            }
            MucAffiliationBatchOutcome::MissingTarget => {
                return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
            }
            MucAffiliationBatchOutcome::Unauthorized => {
                return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
            }
            MucAffiliationBatchOutcome::Stale | MucAffiliationBatchOutcome::Destroyed => {
                return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
            }
        }

        if let Some(operation_id) = cluster_affiliation_operation {
            if let Err(error) = self
                .state
                .muc_service()
                .wake_committed_operation(&self.state.cluster, operation_id)
                .await
            {
                tracing::warn!(?error, %operation_id, room=%room_jid,
                    "durable MUC affiliation batch committed; signed wake will be recovered by polling");
            }
            if all_affiliation_changes {
                // The PostgreSQL audience worker renders every live role
                // change/removal. Do not execute the legacy Redis mutation
                // loop below in clustered mode.
                return Ok(Action::Send(iq_result_from(id, room_jid, "")));
            }
        }

        if self.state.cluster.is_enabled() {
            let role_items = items
                .iter()
                .filter(|item| item.attribute("role").is_some())
                .collect::<Vec<_>>();
            if !role_items.is_empty() {
                let Some(actor_occupant) = actor.as_ref() else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let Some(actor_target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        actor_occupant.cluster_epoch,
                        actor_occupant.connection_id,
                    )
                    .await?
                else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                for item in role_items {
                    let target_nick = prepare_muc_nick(
                        item.attribute("nick").expect("role item validated above"),
                    )
                    .expect("role nickname validated above");
                    let Some(target) = self
                        .state
                        .muc_service()
                        .local_cluster_occupancy_target_by_nick(
                            room.id,
                            room.room_epoch,
                            &target_nick,
                        )
                        .await?
                    else {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                    };
                    let new_role = item.attribute("role").expect("role item validated above");
                    let reason = child_text(*item, "reason");
                    let operation_id =
                        crate::services::muc::MucService::operation_id(&serde_json::json!({
                            "kind":"admin_role","stream":self.connection_id,"iq_id":id,
                            "room":room_jid,"actor":actor_target,"target":target,
                            "role":new_role,"reason":reason,
                        }))?;
                    let outcome = if new_role == "none" {
                        self.state
                            .muc_service()
                            .kick_local_cluster_occupancy(
                                operation_id,
                                &actor_target,
                                &target,
                                reason,
                            )
                            .await?
                    } else {
                        self.state
                            .muc_service()
                            .change_local_cluster_role(
                                operation_id,
                                &actor_target,
                                &target,
                                new_role,
                                reason,
                            )
                            .await?
                    };
                    match outcome {
                        ClusterMucTransitionOutcome::Applied
                        | ClusterMucTransitionOutcome::Replay => {}
                        ClusterMucTransitionOutcome::Unauthorized => {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                        }
                        ClusterMucTransitionOutcome::Stale
                        | ClusterMucTransitionOutcome::Destroyed => {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                        }
                        ClusterMucTransitionOutcome::Conflict => {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
                        }
                    }
                    if let Err(error) = self
                        .state
                        .muc_service()
                        .wake_committed_operation(&self.state.cluster, operation_id)
                        .await
                    {
                        tracing::warn!(?error, %operation_id, room=%room_jid,
                            "durable MUC role operation committed; signed wake will be recovered by polling");
                    }
                }
            }
            // All clustered control changes above are now durable and their
            // exact audience deliveries are owned by the PG outbox.
            return Ok(Action::Send(iq_result_from(id, room_jid, "")));
        }

        for item in items {
            if let (Some(target_raw), Some(new_affil)) =
                (item.attribute("jid"), item.attribute("affiliation"))
            {
                if !matches!(my_affiliation.as_str(), "owner" | "admin") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                }
                if !matches!(new_affil, "owner" | "admin" | "member" | "outcast" | "none") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
                if new_affil == "owner" && my_affiliation != "owner" {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                if my_affiliation == "admin" && matches!(new_affil, "owner" | "admin") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                let Ok(target) = CanonicalJid::parse(target_raw) else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                };
                let Some(target_localpart) = target.localpart() else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                };
                let target_bare = target.bare();
                if new_affil == "outcast"
                    && self
                        .full_jid
                        .as_deref()
                        .and_then(|jid| canonical_bare_key(jid).ok())
                        .as_deref()
                        == Some(target_bare.as_str())
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
                }
                let target_is_local = target.domainpart() == self.state.config.domain;
                if target_is_local
                    && self
                        .state
                        .muc_service()
                        .enabled_local_account(target_localpart)
                        .await?
                        .is_none()
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                }
                let target_affiliation = if target_is_local {
                    let target_user = self
                        .state
                        .muc_service()
                        .enabled_local_account(target_localpart)
                        .await?
                        .expect("local target existence checked above");
                    self.state
                        .muc_service()
                        .local_affiliation(room.id, target_user.id)
                        .await?
                } else {
                    self.state
                        .muc_service()
                        .federated_affiliation(room.id, &target_bare)
                        .await?
                };
                if my_affiliation == "admin"
                    && matches!(target_affiliation.as_deref(), Some("owner" | "admin"))
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                let reason = child_text(item, "reason").map(str::to_owned);

                tracing::info!(room = %room_jid, target = %target_bare, affiliation = %new_affil, "MUC admin_set: publishing atomically committed affiliation");

                // Broadcast presence if they are in the room
                let occupants: Vec<_> = self
                    .state
                    .muc_occupants_for(room_jid)
                    .into_iter()
                    .filter(|(_, occ)| {
                        canonical_bare_key(&occ.full_jid).ok() == Some(target_bare.clone())
                    })
                    .collect();
                let local_identities = occupants
                    .iter()
                    .map(|(_, occupant)| (occupant.cluster_epoch, occupant.connection_id))
                    .collect::<std::collections::HashSet<_>>();
                let remote_occupants = self
                    .state
                    .cluster
                    .get_muc_occupants(room_jid)
                    .await?
                    .into_values()
                    .filter_map(|json| {
                        serde_json::from_str::<crate::state::SerializableMucOccupant>(&json).ok()
                    })
                    .filter(|occupant| {
                        canonical_bare_key(&occupant.full_jid).ok() == Some(target_bare.clone())
                            && !local_identities
                                .contains(&(occupant.cluster_epoch, occupant.connection_id))
                    })
                    .collect::<Vec<_>>();

                let target_is_occupant = !occupants.is_empty() || !remote_occupants.is_empty();
                let previous_affiliation = previous_affiliations
                    .get(&target_bare)
                    .map(String::as_str)
                    .unwrap_or("none");
                if should_broadcast_offline_affiliation_change(
                    room.non_anonymous,
                    target_is_occupant,
                    previous_affiliation,
                    new_affil,
                ) {
                    deliver_muc_offline_affiliation_change_notice(
                        &self.state,
                        room_jid,
                        &target_bare,
                        new_affil,
                        item.attribute("nick"),
                        reason.as_deref(),
                    )
                    .await;
                }

                for (key, mut occupant) in occupants {
                    occupant.affiliation = new_affil.to_owned();
                    let remove_from_room =
                        new_affil == "outcast" || (new_affil == "none" && room.members_only);
                    if remove_from_room {
                        occupant.role = "none".to_owned();
                        let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                        self.state.remove_live_muc_membership(&serializable);
                        self.state.muc_occupants.remove_if(&key, |_, current| {
                            current.full_jid == occupant.full_jid
                                && current.connection_id == occupant.connection_id
                                && current.cluster_epoch == occupant.cluster_epoch
                        });
                        let is_empty = self.state.muc_occupants_for(room_jid).is_empty();
                        let removal_status = if new_affil == "outcast" { 301 } else { 321 };
                        run_muc_cluster_eviction(
                            &self.state,
                            room_jid,
                            serializable,
                            removal_status,
                            actor_nick.as_deref(),
                            reason.as_deref(),
                            is_empty,
                        )
                        .await;
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let presence = muc_presence_stanza_with_status(
                                &crate::state::SerializableMucOccupant::from(&occupant),
                                &other.full_jid,
                                true,
                                false,
                                false,
                                None,
                                occupant.room_non_anonymous || other.role == "moderator",
                                Some(if new_affil == "outcast" { 301 } else { 321 }),
                                actor_nick.as_deref(),
                                reason.as_deref(),
                            );
                            let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                        }
                        let self_presence = muc_presence_stanza_with_status(
                            &crate::state::SerializableMucOccupant::from(&occupant),
                            &occupant.full_jid,
                            true,
                            true,
                            false,
                            None,
                            true,
                            Some(if new_affil == "outcast" { 301 } else { 321 }),
                            actor_nick.as_deref(),
                            reason.as_deref(),
                        );
                        let _ = self
                            .state
                            .deliver_to_muc_occupant(&occupant, self_presence)
                            .await;
                    } else {
                        occupant.role = if matches!(new_affil, "owner" | "admin") {
                            "moderator"
                        } else if room.moderated && new_affil == "none" {
                            "visitor"
                        } else {
                            "participant"
                        }
                        .to_owned();
                        self.state.muc_occupants.insert(key, occupant.clone());

                        let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                        if let Ok(json) = serde_json::to_string(&serializable) {
                            run_muc_cluster_occupant_refresh(
                                &self.state,
                                room_jid,
                                &occupant.nick,
                                json,
                                serializable,
                            )
                            .await;
                        }

                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let self_presence = other.full_jid == occupant.full_jid;
                            let presence = muc_presence_stanza(
                                &crate::state::SerializableMucOccupant::from(&occupant),
                                &other.full_jid,
                                false,
                                self_presence,
                                false,
                                None,
                                occupant.room_non_anonymous
                                    || self_presence
                                    || other.role == "moderator",
                            );
                            let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                        }
                    }
                }
                for remote in remote_occupants {
                    let remove_from_room =
                        new_affil == "outcast" || (new_affil == "none" && room.members_only);
                    if remove_from_room {
                        let mut updated = remote;
                        updated.affiliation = new_affil.to_owned();
                        updated.role = "none".to_owned();
                        let removal_status = if new_affil == "outcast" { 301 } else { 321 };
                        if self
                            .state
                            .cluster
                            .evict_muc_occupant(
                                &updated,
                                removal_status,
                                actor_nick.as_deref(),
                                reason.as_deref(),
                            )
                            .await?
                        {
                            self.state
                                .cluster
                                .send_muc_presence_with_status(
                                    room_jid,
                                    &updated,
                                    true,
                                    false,
                                    None,
                                    Some(removal_status),
                                    actor_nick.as_deref(),
                                    reason.as_deref(),
                                )
                                .await?;
                            for (_, other) in self.state.muc_occupants_for(room_jid) {
                                let presence = muc_presence_stanza_with_status(
                                    &updated,
                                    &other.full_jid,
                                    true,
                                    false,
                                    false,
                                    None,
                                    updated.room_non_anonymous || other.role == "moderator",
                                    Some(removal_status),
                                    actor_nick.as_deref(),
                                    reason.as_deref(),
                                );
                                let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                            }
                        }
                    } else {
                        let role = if matches!(new_affil, "owner" | "admin") {
                            "moderator"
                        } else if room.moderated && new_affil == "none" {
                            "visitor"
                        } else {
                            "participant"
                        };
                        let updated = match self
                            .state
                            .cluster
                            .change_muc_occupant_affiliation(room_jid, &remote, new_affil, role)
                            .await?
                        {
                            crate::cluster::MucRoleChange::Changed(updated) => *updated,
                            crate::cluster::MucRoleChange::Stale => continue,
                        };
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let presence = muc_presence_stanza(
                                &updated,
                                &other.full_jid,
                                false,
                                false,
                                false,
                                None,
                                updated.room_non_anonymous || other.role == "moderator",
                            );
                            let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                        }
                    }
                }
            } else if let (Some(target_nick), Some(new_role)) =
                (item.attribute("nick"), item.attribute("role"))
            {
                if my_role != "moderator" {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                }
                if !matches!(new_role, "moderator" | "participant" | "visitor" | "none") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
                let Ok(target_nick) = prepare_muc_nick(target_nick) else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                };
                let target_key = muc_occupant_key(room_jid, &target_nick);
                let local_target = self
                    .state
                    .muc_occupants
                    .get(&target_key)
                    .map(|value| value.clone());
                if local_target.is_none() {
                    let remote = self
                        .state
                        .cluster
                        .get_muc_occupants(room_jid)
                        .await?
                        .get(&target_nick)
                        .and_then(|json| {
                            serde_json::from_str::<crate::state::SerializableMucOccupant>(json).ok()
                        });
                    let Some(mut remote) = remote else {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                    };
                    if my_affiliation == "admin"
                        && matches!(remote.affiliation.as_str(), "owner" | "admin")
                    {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                    }
                    if (new_role == "moderator" || remote.role == "moderator")
                        && !matches!(my_affiliation.as_str(), "owner" | "admin")
                    {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                    }
                    if matches!(remote.affiliation.as_str(), "owner" | "admin")
                        && !matches!(my_affiliation.as_str(), "owner" | "admin")
                    {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                    }
                    let reason = child_text(item, "reason").map(str::to_owned);
                    if new_role == "none" {
                        remote.role = "none".to_owned();
                        if !self
                            .state
                            .cluster
                            .evict_muc_occupant(
                                &remote,
                                307,
                                actor_nick.as_deref(),
                                reason.as_deref(),
                            )
                            .await?
                        {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                        }
                        self.state
                            .cluster
                            .send_muc_presence_with_status(
                                room_jid,
                                &remote,
                                true,
                                false,
                                None,
                                Some(307),
                                actor_nick.as_deref(),
                                reason.as_deref(),
                            )
                            .await?;
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let presence = muc_presence_stanza_with_status(
                                &remote,
                                &other.full_jid,
                                true,
                                false,
                                false,
                                None,
                                remote.room_non_anonymous || other.role == "moderator",
                                Some(307),
                                actor_nick.as_deref(),
                                reason.as_deref(),
                            );
                            let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                        }
                    } else {
                        let updated = match self
                            .state
                            .cluster
                            .change_muc_occupant_role(room_jid, &remote, new_role)
                            .await?
                        {
                            crate::cluster::MucRoleChange::Changed(updated) => *updated,
                            crate::cluster::MucRoleChange::Stale => {
                                return Ok(Action::Send(iq_error_from(
                                    id,
                                    room_jid,
                                    "item-not-found",
                                )));
                            }
                        };
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let presence = muc_presence_stanza(
                                &updated,
                                &other.full_jid,
                                false,
                                false,
                                false,
                                None,
                                updated.room_non_anonymous || other.role == "moderator",
                            );
                            let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                        }
                    }
                    continue;
                }
                let mut occupant = local_target.expect("checked above");
                if my_affiliation == "admin"
                    && matches!(occupant.affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                if (new_role == "moderator" || occupant.role == "moderator")
                    && !matches!(my_affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                if matches!(occupant.affiliation.as_str(), "owner" | "admin")
                    && !matches!(my_affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }
                occupant.role = new_role.to_owned();
                if new_role == "none" {
                    let reason = child_text(item, "reason").map(str::to_owned);
                    let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                    self.state.remove_live_muc_membership(&serializable);
                    self.state
                        .muc_occupants
                        .remove_if(&target_key, |_, current| {
                            current.full_jid == occupant.full_jid
                                && current.connection_id == occupant.connection_id
                                && current.cluster_epoch == occupant.cluster_epoch
                        });
                    let is_empty = self.state.muc_occupants_for(room_jid).is_empty();
                    run_muc_cluster_eviction(
                        &self.state,
                        room_jid,
                        serializable,
                        307,
                        actor_nick.as_deref(),
                        reason.as_deref(),
                        is_empty,
                    )
                    .await;
                    for (_, other) in self.state.muc_occupants_for(room_jid) {
                        let self_presence = other.full_jid == occupant.full_jid;
                        let presence = muc_presence_stanza_with_status(
                            &crate::state::SerializableMucOccupant::from(&occupant),
                            &other.full_jid,
                            true,
                            self_presence,
                            false,
                            None,
                            occupant.room_non_anonymous
                                || self_presence
                                || other.role == "moderator",
                            Some(307),
                            actor_nick.as_deref(),
                            reason.as_deref(),
                        );
                        let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                    }
                    let presence = muc_presence_stanza_with_status(
                        &crate::state::SerializableMucOccupant::from(&occupant),
                        &occupant.full_jid,
                        true,
                        true,
                        false,
                        None,
                        true,
                        Some(307),
                        actor_nick.as_deref(),
                        reason.as_deref(),
                    );
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&occupant, presence)
                        .await;
                } else {
                    self.state
                        .muc_occupants
                        .insert(target_key, occupant.clone());
                    for (_, other) in self.state.muc_occupants_for(room_jid) {
                        let self_presence = other.full_jid == occupant.full_jid;
                        let presence = muc_presence_stanza(
                            &crate::state::SerializableMucOccupant::from(&occupant),
                            &other.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            occupant.room_non_anonymous
                                || self_presence
                                || other.role == "moderator",
                        );
                        let _ = self.state.deliver_to_muc_occupant(&other, presence).await;
                    }
                }
            } else {
                return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
            }
        }

        Ok(Action::Send(iq_result_from(id, room_jid, "")))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_muc_history_bounds, can_retrieve_muc_affiliation_list, canonical_local_muc_room,
        muc_offline_affiliation_change_notice, muc_presence_payload, muc_sender_is_blocked,
        parse_moderation_request, parse_muc_author_retraction, parse_muc_history_request,
        parse_muc_invitation_decline, parse_muc_origin_id, parse_muc_subject_command,
        parse_muc_voice_form, should_broadcast_offline_affiliation_change, ModerationRequest,
        MucHistoryRequest, MucPostCommitAdmissionError, MucPostCommitPlan, MucVoiceForm,
    };

    #[test]
    fn post_commit_plan_has_a_hard_capacity_and_rejects_work_after_seal() {
        let mut plan = MucPostCommitPlan::<u8, 1>::new();
        assert_eq!(plan.try_push(1), Ok(()));
        assert_eq!(plan.try_push(2), Err(MucPostCommitAdmissionError::Full));
        plan.seal();
        assert_eq!(plan.try_push(3), Err(MucPostCommitAdmissionError::Sealed));
    }

    #[tokio::test]
    async fn post_commit_plan_preserves_order_and_observes_failure_without_stopping() {
        let mut plan = MucPostCommitPlan::<u8, 3>::new();
        for step in [1, 2, 3] {
            plan.try_push(step).unwrap();
        }
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        plan.run(
            {
                let observed = observed.clone();
                move |step| {
                    let observed = observed.clone();
                    async move {
                        observed.lock().unwrap().push(step);
                        if step == 2 {
                            Err(step)
                        } else {
                            Ok(())
                        }
                    }
                }
            },
            {
                let failures = failures.clone();
                move |step| failures.lock().unwrap().push(step)
            },
        )
        .await;
        assert_eq!(*observed.lock().unwrap(), vec![1, 2, 3]);
        assert_eq!(*failures.lock().unwrap(), vec![2]);
    }

    #[test]
    fn offline_affiliation_notices_are_identity_safe_and_structurally_exact() {
        assert!(should_broadcast_offline_affiliation_change(
            true, false, "none", "member"
        ));
        assert!(!should_broadcast_offline_affiliation_change(
            false, false, "none", "member"
        ));
        assert!(!should_broadcast_offline_affiliation_change(
            true, true, "none", "member"
        ));
        assert!(!should_broadcast_offline_affiliation_change(
            true, false, "member", "member"
        ));

        let xml = muc_offline_affiliation_change_notice(
            "room@conference.example.test",
            "new.member@example.test",
            "member",
            Some("New & Member"),
            Some("Invite <accepted>"),
        );
        let document = roxmltree::Document::parse(&xml).unwrap();
        let message = document.root_element();
        assert_eq!(message.tag_name().name(), "message");
        assert_eq!(message.tag_name().namespace(), Some("jabber:client"));
        assert_eq!(
            message.attribute("from"),
            Some("room@conference.example.test")
        );
        assert_eq!(message.attribute("type"), Some("normal"));
        assert_eq!(message.attribute("to"), None);
        let x = message
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
            })
            .unwrap();
        let item = x
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "item")
            .unwrap();
        assert_eq!(item.attribute("affiliation"), Some("member"));
        assert_eq!(item.attribute("jid"), Some("new.member@example.test"));
        assert_eq!(item.attribute("role"), Some("none"));
        assert_eq!(item.attribute("nick"), Some("New & Member"));
        assert_eq!(
            item.children()
                .find(|node| node.is_element() && node.tag_name().name() == "reason")
                .and_then(|node| node.text()),
            Some("Invite <accepted>")
        );
    }

    #[test]
    fn moderated_retraction_shape_is_exact_and_ids_remain_opaque() {
        let target = "de305d54-75b4-431b-adb2-eb6b9e546013";
        let xml = format!(
            "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/><reason> Spam </reason></moderate>"
        );
        let document = roxmltree::Document::parse(&xml).unwrap();
        assert_eq!(
            parse_moderation_request(document.root_element()).unwrap(),
            ModerationRequest {
                target_id: uuid::Uuid::parse_str(target).unwrap(),
                reason: Some("Spam".to_owned()),
            }
        );

        for xml in [
            format!(
                "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/><retract xmlns='urn:xmpp:message-retract:1'/></moderate>"
            ),
            format!(
                "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'><payload/></retract></moderate>"
            ),
            format!(
                "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><unknown/></moderate>"
            ),
            format!(
                "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><reason>why</reason></moderate>"
            ),
        ] {
            let document = roxmltree::Document::parse(&xml).unwrap();
            assert_eq!(
                parse_moderation_request(document.root_element()).unwrap_err(),
                "bad-request",
                "{xml}"
            );
        }

        let uppercase = format!(
            "<moderate xmlns='urn:xmpp:message-moderate:1' id='{}'><retract xmlns='urn:xmpp:message-retract:1'/></moderate>",
            target.to_ascii_uppercase()
        );
        let document = roxmltree::Document::parse(&uppercase).unwrap();
        assert_eq!(
            parse_moderation_request(document.root_element()).unwrap_err(),
            "item-not-found"
        );
    }

    #[test]
    fn room_addresses_use_rfc_7622_domain_and_bare_semantics() {
        assert_eq!(
            canonical_local_muc_room(
                "Lounge@Conference.B\u{fc}cher.Example.",
                "conference.bücher.example"
            ),
            Some((
                "lounge@conference.bücher.example".to_owned(),
                "lounge".to_owned()
            ))
        );
        assert!(canonical_local_muc_room(
            "lounge@conference.example.test/Nick",
            "conference.example.test"
        )
        .is_none());
        assert!(
            canonical_local_muc_room("lounge@example.test", "conference.example.test").is_none()
        );
    }

    #[test]
    fn client_presence_cannot_forge_server_asserted_muc_identity_or_delay() {
        let xml = "<presence xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc'/><x xmlns='http://jabber.org/protocol/muc#user'><item jid='victim@example.test' affiliation='owner' role='moderator'/></x><occupant-id xmlns='urn:xmpp:occupant-id:0' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='room@example.test'/><delay xmlns='urn:xmpp:delay' stamp='2000-01-01T00:00:00Z'/><c xmlns='http://jabber.org/protocol/caps' node='client' ver='1'/></presence>";
        let document = roxmltree::Document::parse(xml).unwrap();
        let payload = muc_presence_payload(document.root_element(), xml);
        assert_eq!(
            payload,
            "<c xmlns='http://jabber.org/protocol/caps' node='client' ver='1'/>"
        );
    }

    #[test]
    fn voice_forms_distinguish_requests_from_strict_moderator_approvals() {
        let request = roxmltree::Document::parse(
            "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field></x></message>",
        )
        .unwrap();
        assert_eq!(
            parse_muc_voice_form(request.root_element()),
            Ok(Some(MucVoiceForm::Request))
        );

        let approval = roxmltree::Document::parse(
            "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field><field var='muc#jid'><value>visitor@example.test/Phone</value></field><field var='muc#roomnick'><value>Visitor</value></field><field var='muc#request_allow'><value>1</value></field></x></message>",
        )
        .unwrap();
        assert_eq!(
            parse_muc_voice_form(approval.root_element()),
            Ok(Some(MucVoiceForm::Approval {
                jid: "visitor@example.test/Phone".to_owned(),
                nick: "Visitor".to_owned(),
                allow: true,
            }))
        );

        for malformed in [
            "<message><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field></x></message>",
            "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>moderator</value></field></x></message>",
            "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field><field var='muc#role'><value>participant</value></field></x></message>",
            "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field><field var='muc#jid'><value>bare@example.test</value></field><field var='muc#roomnick'><value>Visitor</value></field><field var='muc#request_allow'><value>yes</value></field></x></message>",
        ] {
            let document = roxmltree::Document::parse(malformed).unwrap();
            assert!(parse_muc_voice_form(document.root_element()).is_err());
        }
    }

    #[test]
    fn mediated_invitation_declines_are_strict_and_keep_the_reason() {
        let decline = roxmltree::Document::parse(
            "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='inviter@example.test'><reason>Not today</reason></decline></x></message>",
        )
        .unwrap();
        assert_eq!(
            parse_muc_invitation_decline(decline.root_element()),
            Ok(Some((
                "inviter@example.test".to_owned(),
                Some("Not today".to_owned())
            )))
        );
        let absent = roxmltree::Document::parse("<message><body>hello</body></message>").unwrap();
        assert_eq!(
            parse_muc_invitation_decline(absent.root_element()),
            Ok(None)
        );
        for malformed in [
            "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline/></x></message>",
            "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='a@example.test'/><decline to='b@example.test'/></x></message>",
            "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='a@example.test' from='forged@example.test'/></x></message>",
            "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='a@example.test'><reason>one</reason><reason>two</reason></decline></x></message>",
        ] {
            let document = roxmltree::Document::parse(malformed).unwrap();
            assert!(parse_muc_invitation_decline(document.root_element()).is_err());
        }
    }

    #[test]
    fn owners_and_admins_can_retrieve_persisted_affiliation_lists() {
        for requester in ["owner", "admin"] {
            for requested in ["owner", "admin", "member", "outcast"] {
                assert!(can_retrieve_muc_affiliation_list(
                    requester, requested, false, false
                ));
            }
        }
    }

    #[test]
    fn members_can_retrieve_omemo_recipient_lists_in_private_non_anonymous_rooms() {
        for requested in ["owner", "admin", "member"] {
            assert!(can_retrieve_muc_affiliation_list(
                "member", requested, true, true
            ));
        }
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "outcast", true, true
        ));
    }

    #[test]
    fn ordinary_members_cannot_expand_jid_visibility_in_other_room_types() {
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "member", false, true
        ));
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "member", true, false
        ));
        assert!(!can_retrieve_muc_affiliation_list(
            "none", "member", true, true
        ));
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "invalid", true, true
        ));
    }

    #[test]
    fn muc_blocking_matches_room_nick_and_real_sender_but_not_own_resources() {
        let owner = "alice@example.test";
        assert!(muc_sender_is_blocked(
            &["room@conference.example.test".to_owned()],
            owner,
            "room@conference.example.test/Romeo",
            Some("romeo@example.test/Phone"),
        ));
        assert!(muc_sender_is_blocked(
            &["romeo@example.test".to_owned()],
            owner,
            "room@conference.example.test/Romeo",
            Some("romeo@example.test/Phone"),
        ));
        assert!(!muc_sender_is_blocked(
            &["alice@example.test".to_owned()],
            owner,
            "room@conference.example.test/Alice",
            Some("alice@example.test/Phone"),
        ));
    }

    #[test]
    fn history_identity_and_subject_commands_have_strict_unambiguous_shapes() {
        let document = roxmltree::Document::parse(
            "<message type='groupchat'><subject>new</subject><origin-id xmlns='urn:xmpp:sid:0' id='client-1'/></message>",
        )
        .unwrap();
        let root = document.root_element();
        assert_eq!(parse_muc_subject_command(root), Ok(Some("new".to_owned())));
        assert_eq!(parse_muc_origin_id(root), Ok(Some("client-1".to_owned())));

        let discussion = roxmltree::Document::parse(
            "<message type='groupchat'><subject>caption</subject><body>discussion</body></message>",
        )
        .unwrap();
        assert_eq!(
            parse_muc_subject_command(discussion.root_element()),
            Ok(None)
        );
        for malformed in [
            "<message><subject>a</subject><subject>b</subject></message>",
            "<message><subject xml:lang='en'>a</subject></message>",
            "<message><origin-id xmlns='urn:xmpp:sid:0'/></message>",
            "<message><origin-id xmlns='urn:xmpp:sid:0' id='a'/><origin-id xmlns='urn:xmpp:sid:0' id='b'/></message>",
        ] {
            let malformed = roxmltree::Document::parse(malformed).unwrap();
            let root = malformed.root_element();
            assert!(parse_muc_subject_command(root).is_err() || parse_muc_origin_id(root).is_err());
        }
    }

    #[test]
    fn author_retraction_parser_prefers_current_direct_shape_without_legacy_ambiguity() {
        let target = "de305d54-75b4-431b-adb2-eb6b9e546013";
        let direct_xml = format!(
            "<message type='groupchat'><retract xmlns='urn:xmpp:message-retract:1' id='{target}'/><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:message-retract:1'/><body>message retracted</body></message>"
        );
        let direct = roxmltree::Document::parse(&direct_xml).unwrap();
        assert_eq!(
            parse_muc_author_retraction(direct.root_element()),
            Ok(Some(uuid::Uuid::parse_str(target).unwrap()))
        );
        let valid_xml = format!(
            "<message type='groupchat'><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"
        );
        let valid = roxmltree::Document::parse(&valid_xml).unwrap();
        assert_eq!(
            parse_muc_author_retraction(valid.root_element()),
            Ok(Some(uuid::Uuid::parse_str(target).unwrap()))
        );
        for malformed in [
            format!("<message><body>x</body><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"),
            format!("<message><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"),
            format!("<message><retract xmlns='urn:xmpp:message-retract:1' id='{target}'/><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"),
            "<message><apply-to xmlns='urn:xmpp:fasten:0' id='not-a-uuid'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>".to_owned(),
        ] {
            let malformed = roxmltree::Document::parse(&malformed).unwrap();
            assert!(parse_muc_author_retraction(malformed.root_element()).is_err());
        }
    }

    #[test]
    fn history_controls_are_strict_combined_and_bounded() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-26T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let document = roxmltree::Document::parse(
            "<presence><x xmlns='http://jabber.org/protocol/muc'><history maxchars='4096' maxstanzas='500' seconds='3600' since='2026-08-26T11:30:00Z'/></x></presence>",
        )
        .unwrap();
        let request = parse_muc_history_request(document.root_element(), now).unwrap();
        assert_eq!(request.max_stanzas, 100);
        assert_eq!(request.max_chars, Some(4096));
        assert_eq!(
            request.since,
            Some(
                chrono::DateTime::parse_from_rfc3339("2026-08-26T11:30:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc)
            )
        );

        for malformed in [
            "<presence><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='-1'/></x></presence>",
            "<presence><x xmlns='http://jabber.org/protocol/muc'><history seconds='1.5'/></x></presence>",
            "<presence><x xmlns='http://jabber.org/protocol/muc'><history since='not-a-date'/></x></presence>",
            "<presence><x xmlns='http://jabber.org/protocol/muc'><history unknown='1'/></x></presence>",
            "<presence><x xmlns='http://jabber.org/protocol/muc'><history/><history/></x></presence>",
        ] {
            let document = roxmltree::Document::parse(malformed).unwrap();
            assert!(parse_muc_history_request(document.root_element(), now).is_err());
        }
    }

    #[test]
    fn history_bounds_keep_the_newest_complete_stanzas_and_exclude_subject_events() {
        let request = MucHistoryRequest {
            max_stanzas: 3,
            max_chars: Some(4),
            since: None,
        };
        assert_eq!(
            apply_muc_history_bounds(
                vec!["old".to_owned(), "ab".to_owned(), "cd".to_owned()],
                request
            ),
            vec!["ab".to_owned(), "cd".to_owned()]
        );
    }
}
