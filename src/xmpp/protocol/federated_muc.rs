//! Federated XEP-0045 room actors.
//!
//! An authenticated S2S domain is an authorization boundary, not a local
//! account. Remote occupants therefore live in the room map with a federated
//! endpoint and use a separate persistent-affiliation table.

use crate::services::muc::{
    ClusterMucAffiliationSubject, ClusterMucConfigurationOutcome, ClusterMucInviteAuthority,
    ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucPrincipal, ClusterMucRegistrationOutcome,
    ClusterMucTransitionOutcome, DurableMucInviteOutcome, MucActorAuthority, MucActorPrincipal,
    MucAffiliationBatchOutcome, MucAffiliationChange, MucAffiliationTarget, MucConfigUpdate,
    MucConfigurationOutcome, MucDiscussion, MucDiscussionAdmission, MucRegistrationOutcome,
    MucRetractionKind, MucRetractionMutation, MucRetractionOutcome, MucRoom, MucSubjectMutation,
    MucSubjectOutcome, OfflineStoreOutcome, OfflineStorePolicy,
};
use crate::state::{
    bare_jid, localpart, AppState, MucOccupant, MucOccupantEndpoint, SerializableMucOccupant,
};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::{Context, Result};
use roxmltree::Node;
use std::sync::atomic::Ordering;

fn record_federated_muc_post_commit_failure(
    state: &AppState,
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
    tracing::warn!(
        room,
        recipient,
        stage,
        "post-commit federated MUC delivery was not admitted"
    );
}

fn authenticated_remote_actor(authenticated_domain: &str, from: &str) -> bool {
    let Ok(actor) = crate::jid::CanonicalJid::parse(from) else {
        return false;
    };
    let Ok(domain) = crate::jid::prepare_domainpart(authenticated_domain) else {
        return false;
    };
    actor.localpart().is_some() && actor.resourcepart().is_some() && actor.domainpart() == domain
}

fn same_remote_actor(left: &str, right: &str) -> bool {
    matches!(
        (
            crate::jid::canonicalize(left),
            crate::jid::canonicalize(right)
        ),
        (Ok(left), Ok(right)) if left == right
    )
}

fn same_authenticated_domain(left: &str, right: &str) -> bool {
    matches!(
        (
            crate::jid::prepare_domainpart(left),
            crate::jid::prepare_domainpart(right)
        ),
        (Ok(left), Ok(right)) if left == right
    )
}

fn canonical_authenticated_domain(domain: &str) -> String {
    crate::jid::prepare_domainpart(domain)
        .expect("authenticated S2S domain must already satisfy RFC 7622")
}

fn muc_domain(state: &AppState) -> String {
    crate::jid::prepare_domainpart(&format!("conference.{}", state.config.domain))
        .expect("configured XMPP domain must form a valid MUC service domain")
}

fn federated_endpoint_matches(occupant: &MucOccupant, authenticated_domain: &str) -> bool {
    matches!(
        &occupant.endpoint,
        MucOccupantEndpoint::Federated { authenticated_domain: domain, .. }
            if same_authenticated_domain(domain, authenticated_domain)
    )
}

fn is_idempotent_remote_join(
    occupant: &MucOccupant,
    authenticated_domain: &str,
    actor_full_jid: &str,
    requested_nick: &str,
) -> bool {
    same_remote_actor(&occupant.full_jid, actor_full_jid)
        && occupant.nick == requested_nick
        && federated_endpoint_matches(occupant, authenticated_domain)
}

fn federated_history_stanza(room: &MucRoom, archived_stanza: &str, sender_jid: &str) -> String {
    federated_history_stanza_with_access(room, archived_stanza, sender_jid, room.non_anonymous)
}

fn federated_history_stanza_with_access(
    room: &MucRoom,
    archived_stanza: &str,
    sender_jid: &str,
    reveal_real_jid: bool,
) -> String {
    let occupant_id = muc_occupant_id(&room.occupant_id_secret, sender_jid);
    let authoritative = set_muc_occupant_id(archived_stanza, &occupant_id);
    if reveal_real_jid {
        add_muc_sender(&authoritative, sender_jid)
    } else {
        authoritative
    }
}

#[derive(Clone)]
struct FederatedStanza {
    element: String,
    from: String,
    to: String,
    id: Option<String>,
    kind: Option<String>,
    raw: String,
}

impl FederatedStanza {
    fn from_node(root: Node<'_, '_>, raw: &str) -> Self {
        Self {
            element: root.tag_name().name().to_owned(),
            from: root.attribute("from").unwrap_or_default().to_owned(),
            to: root.attribute("to").unwrap_or_default().to_owned(),
            id: root.attribute("id").map(str::to_owned),
            kind: root.attribute("type").map(str::to_owned),
            raw: raw.to_owned(),
        }
    }
}

struct FederatedPresenceRequest {
    stanza: FederatedStanza,
    password: String,
    payload: String,
    history_request: std::result::Result<super::muc::MucHistoryRequest, ()>,
    muc_join: bool,
}

impl FederatedPresenceRequest {
    fn from_node(root: Node<'_, '_>, raw: &str) -> Self {
        let password = root
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
            })
            .and_then(|x| child_text(x, "password"))
            .unwrap_or_default()
            .to_owned();
        let mut payload = String::new();
        for child in root.children().filter(|node| node.is_element()) {
            let namespace = child.tag_name().namespace().unwrap_or_default();
            if super::muc::is_allowed_muc_presence_payload_namespace(namespace) {
                let range = child.range();
                payload.push_str(&raw[range.start..range.end]);
            }
        }
        Self {
            stanza: FederatedStanza::from_node(root, raw),
            password,
            payload,
            history_request: super::muc::parse_muc_history_request(root, chrono::Utc::now()),
            muc_join: root.children().any(|node| {
                node.is_element()
                    && node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
            }),
        }
    }
}

struct FederatedInvite {
    invitee: Option<String>,
    reason: Option<String>,
}

struct FederatedMessageRequest {
    stanza: FederatedStanza,
    validation_error: Option<(&'static str, &'static str)>,
    invites: Vec<FederatedInvite>,
    decline: std::result::Result<Option<(String, Option<String>)>, ()>,
    subject: std::result::Result<Option<String>, ()>,
    origin_id: std::result::Result<Option<String>, ()>,
    author_retraction: std::result::Result<Option<uuid::Uuid>, ()>,
    encrypted: bool,
    temporary_storage: bool,
    permanent_storage: bool,
    carbon_eligible: bool,
    hints: String,
    voice_form: std::result::Result<Option<super::muc::MucVoiceForm>, ()>,
}

impl FederatedMessageRequest {
    fn from_node(root: Node<'_, '_>, raw: &str) -> Self {
        let validation_error = validate_routed_message(root)
            .err()
            .map(|condition| (stanza_error_type(condition), condition));
        let invites = root
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
            })
            .flat_map(|x| {
                x.children()
                    .filter(|node| node.is_element() && node.tag_name().name() == "invite")
            })
            .map(|invite| FederatedInvite {
                invitee: invite.attribute("to").map(str::to_owned),
                reason: child_text(invite, "reason").map(str::to_owned),
            })
            .collect();
        let subject = super::muc::parse_muc_subject_command(root);
        let decline = super::muc::parse_muc_invitation_decline(root);
        let origin_id = super::muc::parse_muc_origin_id(root);
        let author_retraction = super::muc::parse_muc_author_retraction(root);
        let voice_form = super::muc::parse_muc_voice_form(root);
        let storage = message_storage_policy(root).unwrap_or(MessageStoragePolicy {
            temporary: false,
            permanent: false,
        });
        Self {
            stanza: FederatedStanza::from_node(root, raw),
            validation_error,
            invites,
            decline,
            subject,
            origin_id,
            author_retraction,
            encrypted: is_encrypted(root),
            temporary_storage: storage.temporary,
            permanent_storage: storage.permanent,
            carbon_eligible: should_carbon(root),
            hints: processing_hints_fragment(root, raw),
            voice_form,
        }
    }
}

struct FederatedAdminItem {
    jid: Option<String>,
    nick: Option<String>,
    affiliation: Option<String>,
    role: Option<String>,
    reason: Option<String>,
}

fn parse_federated_admin_set(
    query: Node<'_, '_>,
) -> std::result::Result<Vec<FederatedAdminItem>, &'static str> {
    if query.attributes().len() != 0 {
        return Err("bad-request");
    }
    let elements = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if elements.is_empty() || elements.len() > 100 {
        return Err("bad-request");
    }
    let mut items = Vec::with_capacity(elements.len());
    for item in elements {
        if item.tag_name().name() != "item"
            || item.tag_name().namespace() != Some("http://jabber.org/protocol/muc#admin")
            || item.attributes().any(|attribute| {
                !matches!(attribute.name(), "jid" | "nick" | "affiliation" | "role")
            })
        {
            return Err("bad-request");
        }
        let children = item
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if children.len() > 1 {
            return Err("bad-request");
        }
        let reason = match children.first() {
            Some(reason)
                if reason.tag_name().name() == "reason"
                    && reason.tag_name().namespace()
                        == Some("http://jabber.org/protocol/muc#admin")
                    && reason.attributes().len() == 0
                    && !reason.children().any(|node| node.is_element()) =>
            {
                let value = reason.text().unwrap_or_default();
                if value.len() > 4096 {
                    return Err("not-acceptable");
                }
                Some(value.to_owned())
            }
            Some(_) => return Err("bad-request"),
            None => None,
        };
        items.push(FederatedAdminItem {
            jid: item.attribute("jid").map(str::to_owned),
            nick: item.attribute("nick").map(str::to_owned),
            affiliation: item.attribute("affiliation").map(str::to_owned),
            role: item.attribute("role").map(str::to_owned),
            reason,
        });
    }
    Ok(items)
}

type FederatedMamQuery = super::mam::ParsedMamQuery;

enum FederatedIqPayload {
    Ping,
    DiscoInfo {
        node: Option<String>,
    },
    DiscoInfoError,
    DiscoItems(super::discovery::DiscoItemsRequest),
    DiscoItemsError(&'static str),
    Unique,
    OwnerGet,
    OwnerSet,
    RegisterGet,
    RegisterSet,
    AdminGet {
        affiliation: Option<String>,
        role: Option<String>,
    },
    AdminSet {
        items: Vec<FederatedAdminItem>,
    },
    AdminError(&'static str),
    Moderate {
        target: Option<String>,
        reason: Option<String>,
        has_retract: bool,
    },
    MamForm,
    MamQuery(FederatedMamQuery),
    MamMetadata,
    MamError(&'static str),
    Unsupported,
}

struct FederatedIqRequest {
    stanza: FederatedStanza,
    payload: FederatedIqPayload,
}

impl FederatedIqRequest {
    fn from_node(root: Node<'_, '_>, raw: &str) -> Self {
        let kind = root.attribute("type").unwrap_or("get");
        let payload = root
            .children()
            .find(|node| node.is_element())
            .map(|child| {
                let name = child.tag_name().name();
                let namespace = child.tag_name().namespace().unwrap_or_default();
                match (name, namespace, kind) {
                    ("ping", "urn:xmpp:ping", "get") => FederatedIqPayload::Ping,
                    ("query", "http://jabber.org/protocol/disco#info", "get") => {
                        if child
                            .attributes()
                            .any(|attribute| attribute.name() != "node")
                            || child.children().any(|node| node.is_element())
                            || child.text().is_some_and(|text| !text.trim().is_empty())
                        {
                            FederatedIqPayload::DiscoInfoError
                        } else {
                            FederatedIqPayload::DiscoInfo {
                                node: child.attribute("node").map(str::to_owned),
                            }
                        }
                    }
                    ("query", "http://jabber.org/protocol/disco#items", "get") => {
                        match super::discovery::parse_disco_items_query(child) {
                            Ok(request) => FederatedIqPayload::DiscoItems(request),
                            Err(condition) => FederatedIqPayload::DiscoItemsError(condition),
                        }
                    }
                    ("unique", "http://jabber.org/protocol/muc#unique", "get")
                        if child.attributes().len() == 0
                            && !child.children().any(|node| node.is_element())
                            && child.text().is_none_or(|text| text.trim().is_empty()) =>
                    {
                        FederatedIqPayload::Unique
                    }
                    ("query", "http://jabber.org/protocol/muc#owner", "get") => {
                        FederatedIqPayload::OwnerGet
                    }
                    ("query", "http://jabber.org/protocol/muc#owner", "set") => {
                        FederatedIqPayload::OwnerSet
                    }
                    ("query", "jabber:iq:register", "get") => FederatedIqPayload::RegisterGet,
                    ("query", "jabber:iq:register", "set") => FederatedIqPayload::RegisterSet,
                    ("query", "http://jabber.org/protocol/muc#admin", "get") => {
                        let affiliation = child
                            .children()
                            .find(|node| node.is_element() && node.tag_name().name() == "item")
                            .and_then(|item| item.attribute("affiliation"))
                            .map(str::to_owned);
                        let role = child
                            .children()
                            .find(|node| node.is_element() && node.tag_name().name() == "item")
                            .and_then(|item| item.attribute("role"))
                            .map(str::to_owned);
                        FederatedIqPayload::AdminGet { affiliation, role }
                    }
                    ("query", "http://jabber.org/protocol/muc#admin", "set") => {
                        match parse_federated_admin_set(child) {
                            Ok(items) => FederatedIqPayload::AdminSet { items },
                            Err(condition) => FederatedIqPayload::AdminError(condition),
                        }
                    }
                    ("moderate", "urn:xmpp:message-moderate:1", "set") => {
                        FederatedIqPayload::Moderate {
                            target: child.attribute("id").map(str::to_owned),
                            reason: child_text(child, "reason").map(str::to_owned),
                            has_retract: child.children().any(|node| {
                                node.is_element()
                                    && node.tag_name().name() == "retract"
                                    && node.tag_name().namespace()
                                        == Some("urn:xmpp:message-retract:1")
                            }),
                        }
                    }
                    ("query", "urn:xmpp:mam:2", "get")
                        if child.attributes().len() == 0
                            && !child.children().any(|node| node.is_element())
                            && child.text().is_none_or(|text| text.trim().is_empty()) =>
                    {
                        FederatedIqPayload::MamForm
                    }
                    ("query", "urn:xmpp:mam:2", "set") => {
                        match super::mam::parse_mam_query(child) {
                            Ok(query) => FederatedIqPayload::MamQuery(query),
                            Err(condition) => FederatedIqPayload::MamError(condition),
                        }
                    }
                    ("metadata", "urn:xmpp:mam:2", "get")
                        if child.attributes().len() == 0
                            && !child.children().any(|node| node.is_element())
                            && child.text().is_none_or(|text| text.trim().is_empty()) =>
                    {
                        FederatedIqPayload::MamMetadata
                    }
                    _ => FederatedIqPayload::Unsupported,
                }
            })
            .unwrap_or(FederatedIqPayload::Unsupported);
        Self {
            stanza: FederatedStanza::from_node(root, raw),
            payload,
        }
    }
}

fn federated_error(
    stanza: &FederatedStanza,
    recipient: &str,
    error_type: &str,
    condition: &str,
) -> Option<String> {
    let condition = XmlElement::dynamic(condition)
        .ok()?
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    let mut reply = XmlElement::dynamic(&stanza.element)
        .ok()?
        .attr("xmlns", "jabber:client")
        .attr("from", &stanza.to)
        .attr("to", recipient)
        .attr("type", "error")
        .attr("id", stanza.id.as_deref().unwrap_or_default());
    if stanza.element == "presence" {
        reply.push_child(XmlElement::namespaced(
            "x",
            "http://jabber.org/protocol/muc",
        ));
    }
    reply.push_child(
        XmlElement::new("error")
            .attr("by", bare_jid(&stanza.to))
            .attr("type", error_type)
            .child(condition),
    );
    Some(reply.finish())
}

fn federated_iq_result(stanza: &FederatedStanza, from: &str, to: &str, payload: &str) -> String {
    let mut iq = XmlElement::namespaced("iq", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", "result")
        .attr("id", stanza.id.as_deref().unwrap_or_default());
    if iq.push_validated_fragment(payload).is_err() {
        return XmlElement::namespaced("iq", "jabber:client")
            .attr("from", from)
            .attr("to", to)
            .attr("type", "error")
            .attr("id", stanza.id.as_deref().unwrap_or_default())
            .child(
                XmlElement::new("error")
                    .attr("type", "wait")
                    .child(XmlElement::namespaced(
                        "internal-server-error",
                        "urn:ietf:params:xml:ns:xmpp-stanzas",
                    )),
            )
            .finish();
    }
    iq.finish()
}

fn same_bare_jid(left: &str, right: &str) -> bool {
    matches!(
        (
            crate::jid::canonical_bare_key(left),
            crate::jid::canonical_bare_key(right)
        ),
        (Ok(left), Ok(right)) if left == right
    )
}

fn can_retrieve_affiliations(
    requester: &str,
    requested: &str,
    members_only: bool,
    non_anonymous: bool,
) -> bool {
    matches!(requested, "owner" | "admin" | "member" | "outcast")
        && (matches!(requester, "owner" | "admin")
            || (requester == "member"
                && members_only
                && non_anonymous
                && matches!(requested, "owner" | "admin" | "member")))
}

async fn unregister_remote_occupant(
    state: &AppState,
    key: &str,
    mut departed: MucOccupant,
    removal_status: Option<u16>,
) -> Result<()> {
    let room_jid = departed.room_jid.clone();
    let mut local_departure_room = None;
    let local_departure_guard = if state.cluster.is_enabled() {
        None
    } else {
        let Some(initial_room) = state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
        else {
            state.muc_occupants.remove_if(key, |_, current| {
                current.full_jid == departed.full_jid
                    && current.connection_id == departed.connection_id
                    && current.cluster_epoch == departed.cluster_epoch
            });
            return Ok(());
        };
        let guard = state
            .muc_service()
            .lock_local_room_mutation(initial_room.id)
            .await;
        let Some(refreshed_room) = state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
        else {
            state.muc_occupants.remove_if(key, |_, current| {
                current.full_jid == departed.full_jid
                    && current.connection_id == departed.connection_id
                    && current.cluster_epoch == departed.cluster_epoch
            });
            return Ok(());
        };
        if refreshed_room.room_epoch != initial_room.room_epoch {
            state.muc_occupants.remove_if(key, |_, current| {
                current.full_jid == departed.full_jid
                    && current.connection_id == departed.connection_id
                    && current.cluster_epoch == departed.cluster_epoch
            });
            return Ok(());
        }
        let Some(current) = state
            .muc_occupants
            .get(key)
            .map(|entry| entry.value().clone())
        else {
            return Ok(());
        };
        if current.full_jid != departed.full_jid
            || current.connection_id != departed.connection_id
            || current.cluster_epoch != departed.cluster_epoch
        {
            return Ok(());
        }
        departed = current;
        local_departure_room = Some(refreshed_room);
        Some(guard)
    };
    departed.role = "none".to_owned();
    let serializable = SerializableMucOccupant::from(&departed);
    let mut clustered_leave = false;
    if state.cluster.is_enabled() {
        state
            .cluster
            .admit(crate::cluster::ClusterOperation::MucMutation)?;
        let room = state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
            .context("federated MUC leave references a missing room")?;
        let target = state
            .muc_service()
            .local_cluster_occupancy_target(room.id, departed.cluster_epoch, departed.connection_id)
            .await?
            .context("federated MUC leave lost its exact PG occupancy")?;
        let operation_id = uuid::Uuid::new_v4();
        match state
            .muc_service()
            .transition_local_cluster_occupancy(
                operation_id,
                &target,
                "leave",
                &state.cluster.node_id,
                None,
                None,
                departed.sm_session_id,
                std::time::Duration::from_secs(90),
            )
            .await?
        {
            ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
            other => anyhow::bail!("federated MUC leave was rejected by PG authority: {other:?}"),
        }
        clustered_leave = true;
        if let Err(error) = state
            .muc_service()
            .wake_committed_operation(&state.cluster, operation_id)
            .await
        {
            tracing::warn!(?error, %operation_id, room=%room_jid,
                "federated MUC leave committed; signed wake will be recovered by polling");
        }
    }
    let removed_locally = state.muc_occupants.remove_if(key, |_, current| {
        current.full_jid == departed.full_jid
            && current.connection_id == departed.connection_id
            && current.cluster_epoch == departed.cluster_epoch
    });
    if removed_locally.is_none() && !state.cluster.is_enabled() {
        return Ok(());
    }
    let locally_empty = state.muc_occupants_for(&room_jid).is_empty();
    if locally_empty {
        if let Some(room) = local_departure_room.as_ref() {
            // Empty-room deletion is part of the same single-node writer
            // critical section as occupant removal. Otherwise a concurrent
            // join can publish between the empty check and the delete.
            state
                .muc_service()
                .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                .await?;
        }
    }
    drop(local_departure_guard);
    let removed_globally = if clustered_leave {
        state
            .cluster
            .unregister_muc_occupant_epoch(
                &room_jid,
                &departed.nick,
                departed.cluster_epoch,
                departed.connection_id,
            )
            .await
            .unwrap_or(false)
    } else {
        state
            .cluster
            .evict_muc_occupant(&serializable, removal_status.unwrap_or(307), None, None)
            .await?
    };
    let globally_empty =
        removed_globally && state.cluster.get_muc_occupants(&room_jid).await?.is_empty();
    if locally_empty && globally_empty {
        state.cluster.leave_muc(&room_jid).await?;
    }
    if !clustered_leave {
        state
            .cluster
            .send_muc_presence_with_status(
                &room_jid,
                &serializable,
                true,
                false,
                None,
                removal_status,
                None,
                None,
            )
            .await?;
    }
    if clustered_leave {
        if let Some(room) = state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
        {
            if state.muc_service().cluster_room_is_empty(room.id).await? {
                state
                    .muc_service()
                    .delete_temporary_room(room.id, room.room_epoch, room.config_version)
                    .await?;
            }
        }
        return Ok(());
    }
    for (_, recipient) in state.muc_occupants_for(&room_jid) {
        let presence = muc_presence_stanza_with_status(
            &serializable,
            &recipient.full_jid,
            true,
            false,
            false,
            None,
            departed.room_non_anonymous || recipient.role == "moderator",
            removal_status,
            None,
            None,
        );
        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
    }
    Ok(())
}

/// Handle a presence addressed to a local conference room by a remote entity.
/// `authenticated_domain` and `connection_id` MUST come from the authenticated
/// S2S stream, never from stanza attributes.
pub(crate) fn federated_muc_presence<'a>(
    state: &'a AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    root: Node<'_, '_>,
    raw: &str,
) -> impl std::future::Future<Output = Result<Option<String>>> + Send + 'a {
    let authenticated_domain = authenticated_domain.to_owned();
    let request = FederatedPresenceRequest::from_node(root, raw);
    async move {
        federated_muc_presence_owned(state, &authenticated_domain, connection_id, request).await
    }
}

async fn federated_muc_presence_owned(
    state: &AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    request: FederatedPresenceRequest,
) -> Result<Option<String>> {
    let from = request.stanza.from.as_str();
    let to = request.stanza.to.as_str();
    if !authenticated_remote_actor(authenticated_domain, from) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let actor = crate::jid::CanonicalJid::parse(from)
        .expect("authenticated_remote_actor already validated the full JID");
    let actor_full_jid = actor.to_string();
    let actor_bare_jid = actor.bare();
    let Ok(to_jid) = crate::jid::CanonicalJid::parse(to) else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    };
    let room_jid = to_jid.bare();
    if to_jid.domainpart() != muc_domain(state) || to_jid.localpart().is_none() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    let nick = to_jid.resourcepart().unwrap_or_default();
    if !valid_muc_room(localpart(&room_jid)) || !valid_muc_nick(nick) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    }

    let existing = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
    if matches!(
        request.stanza.kind.as_deref(),
        Some("unavailable" | "error")
    ) {
        if let Some((key, occupant)) = existing {
            let exact_connection = matches!(
                &occupant.endpoint,
                MucOccupantEndpoint::Federated { connection_id: owner, .. }
                    if *owner == connection_id && occupant.connection_id == connection_id
            );
            if !federated_endpoint_matches(&occupant, authenticated_domain) || !exact_connection {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "not-authorized",
                ));
            }
            let status = (request.stanza.kind.as_deref() == Some("error")).then_some(333);
            unregister_remote_occupant(state, &key, occupant, status).await?;
        }
        return Ok(None);
    }
    if request.stanza.kind.is_some() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        ));
    }
    if let Some((mut key, mut occupant)) = existing {
        let mut guarded_room = None;
        let local_actor_guard = if state.cluster.is_enabled() {
            None
        } else {
            let Some(initial_room) = state
                .muc_service()
                .federated_room_snapshot(localpart(&room_jid))
                .await?
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            let guard = state
                .muc_service()
                .lock_local_room_mutation(initial_room.id)
                .await;
            let Some(refreshed_room) = state
                .muc_service()
                .federated_room_snapshot(localpart(&room_jid))
                .await?
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            if refreshed_room.room_epoch != initial_room.room_epoch {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            let Some((current_key, current)) =
                state
                    .muc_occupants_for(&room_jid)
                    .into_iter()
                    .find(|(_, current)| {
                        same_remote_actor(&current.full_jid, &actor_full_jid)
                            && current.cluster_epoch == occupant.cluster_epoch
                            && current.connection_id == occupant.connection_id
                    })
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-acceptable",
                ));
            };
            key = current_key;
            occupant = current;
            guarded_room = Some(refreshed_room);
            Some(guard)
        };
        let exact_connection = matches!(
            &occupant.endpoint,
            MucOccupantEndpoint::Federated { connection_id: owner, .. }
                if *owner == connection_id && occupant.connection_id == connection_id
        );
        if !federated_endpoint_matches(&occupant, authenticated_domain) || !exact_connection {
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        }
        if occupant.nick != nick {
            let room = if let Some(room) = guarded_room.as_ref() {
                room.clone()
            } else {
                let Some(room) = state
                    .muc_service()
                    .federated_room_snapshot(localpart(&room_jid))
                    .await?
                else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                room
            };
            let affiliation = state
                .muc_service()
                .federated_affiliation(room.id, &actor_bare_jid)
                .await?;
            if affiliation.as_deref() == Some("outcast") {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            if room.members_only && affiliation.is_none() {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "registration-required",
                ));
            }
            if state
                .muc_service()
                .federated_nick_reserved_for_other(room.id, &actor_bare_jid, nick)
                .await?
            {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
            occupant.affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
            occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if room.moderated && occupant.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
            occupant.room_non_anonymous = room.non_anonymous;
            let old_occupant = occupant.clone();
            let old_serializable = SerializableMucOccupant::from(&old_occupant);
            let old_nick = occupant.nick.clone();
            occupant.nick = nick.to_owned();
            occupant.payload = request.payload.clone();
            occupant.endpoint = MucOccupantEndpoint::Federated {
                authenticated_domain: canonical_authenticated_domain(authenticated_domain),
                connection_id,
            };
            let new_serializable = SerializableMucOccupant::from(&occupant);
            let old_json = serde_json::to_string(&old_serializable)?;
            let new_json = serde_json::to_string(&new_serializable)?;
            let mut cluster_operation = None;
            if state.cluster.is_enabled() {
                state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                let target = state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        occupant.cluster_epoch,
                        occupant.connection_id,
                    )
                    .await?
                    .context("federated MUC rename lost its exact PG occupancy")?;
                let operation_id = uuid::Uuid::new_v4();
                match state
                    .muc_service()
                    .rename_local_cluster_occupancy(
                        operation_id,
                        &target,
                        &state.cluster.node_id,
                        nick,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_operation = Some(operation_id)
                    }
                    ClusterMucTransitionOutcome::Conflict => {
                        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "not-acceptable",
                        ));
                    }
                }
                if let Err(error) = state
                    .cluster
                    .rename_muc_occupant(
                        &room_jid,
                        &old_nick,
                        nick,
                        occupant.cluster_epoch,
                        &old_json,
                        &new_json,
                    )
                    .await
                {
                    tracing::warn!(?error, room=%room_jid,
                        "could not refresh Redis MUC nickname soft-state after PG commit");
                }
            } else {
                match state
                    .cluster
                    .rename_muc_occupant(
                        &room_jid,
                        &old_nick,
                        nick,
                        occupant.cluster_epoch,
                        &old_json,
                        &new_json,
                    )
                    .await?
                {
                    crate::cluster::MucRename::Renamed => {}
                    crate::cluster::MucRename::Conflict => {
                        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                    }
                    crate::cluster::MucRename::Stale => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "not-acceptable",
                        ));
                    }
                }
            }
            let new_key = muc_occupant_key(&room_jid, nick);
            // Publish an old-key -> new-key move in old-first order. The
            // single-node writer gate prevents another room mutation from
            // interleaving; readers may see a short absence but can never see
            // the same actor under both nicknames.
            let removed_old = state.muc_occupants.remove_if(&key, |_, current| {
                current.full_jid == actor_full_jid
                    && current.connection_id == occupant.connection_id
                    && current.cluster_epoch == occupant.cluster_epoch
            });
            if removed_old.is_none() {
                if cluster_operation.is_some() {
                    tracing::warn!(room=%room_jid, old_nick=%old_nick, new_nick=%nick,
                        "PG-authoritative MUC rename found an already-pruned old soft-state entry");
                } else {
                    let _ = state
                        .cluster
                        .rename_muc_occupant(
                            &room_jid,
                            nick,
                            &old_nick,
                            occupant.cluster_epoch,
                            &new_json,
                            &old_json,
                        )
                        .await;
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "not-acceptable",
                    ));
                }
            }
            if state.cluster.is_enabled() {
                if let Some((_, stale)) = state.muc_occupants.remove(&new_key) {
                    tracing::warn!(
                        room=%room_jid,
                        %nick,
                        stale_full_jid=%stale.full_jid,
                        stale_epoch=%stale.cluster_epoch,
                        "evicting stale federated MUC nickname cache entry after PostgreSQL rename"
                    );
                }
            }
            let locally_reserved = match state.muc_occupants.entry(new_key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(_) => false,
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    entry.insert(occupant.clone());
                    true
                }
            };
            if !locally_reserved {
                if !state.cluster.is_enabled() {
                    if let dashmap::mapref::entry::Entry::Vacant(entry) =
                        state.muc_occupants.entry(key.clone())
                    {
                        entry.insert(old_occupant);
                    } else {
                        tracing::error!(room=%room_jid, old_nick=%old_nick,
                            "could not restore federated MUC actor after nickname collision");
                    }
                    drop(local_actor_guard);
                    let _ = state
                        .cluster
                        .rename_muc_occupant(
                            &room_jid,
                            nick,
                            &old_nick,
                            occupant.cluster_epoch,
                            &new_json,
                            &old_json,
                        )
                        .await;
                    return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                }
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "internal-server-error",
                ));
            }
            drop(local_actor_guard);
            if let Some(operation_id) = cluster_operation {
                if let Err(error) = state
                    .muc_service()
                    .wake_committed_operation(&state.cluster, operation_id)
                    .await
                {
                    tracing::warn!(?error, %operation_id, room=%room_jid,
                        "federated MUC rename committed; signed wake will be recovered by polling");
                }
                return Ok(None);
            }
            state
                .cluster
                .send_muc_nickname_change(
                    &room_jid,
                    &old_serializable,
                    &new_serializable,
                    request.stanza.id.as_deref(),
                )
                .await?;
            for (_, recipient) in state.muc_occupants_for(&room_jid) {
                let recipient_serializable = SerializableMucOccupant::from(&recipient);
                let unavailable = muc_nickname_change_presence(
                    &old_serializable,
                    &recipient_serializable,
                    nick,
                    request.stanza.id.as_deref(),
                );
                let _ = state.deliver_to_muc_occupant(&recipient, unavailable).await;
                let self_presence = recipient.full_jid == actor_full_jid;
                let available = muc_presence_stanza(
                    &new_serializable,
                    &recipient.full_jid,
                    false,
                    self_presence,
                    false,
                    request.stanza.id.as_deref(),
                    room.non_anonymous || self_presence || recipient.role == "moderator",
                );
                let _ = state.deliver_to_muc_occupant(&recipient, available).await;
            }
            return Ok(None);
        }
        if !is_idempotent_remote_join(&occupant, authenticated_domain, &actor_full_jid, nick) {
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        }
        if let Some(room) = guarded_room.as_ref() {
            let affiliation = state
                .muc_service()
                .federated_affiliation(room.id, &actor_bare_jid)
                .await?;
            if affiliation.as_deref() == Some("outcast") {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            if room.members_only && affiliation.is_none() {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "registration-required",
                ));
            }
            occupant.affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
            occupant.role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if room.moderated && occupant.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
            occupant.room_non_anonymous = room.non_anonymous;
        }
        occupant.endpoint = MucOccupantEndpoint::Federated {
            authenticated_domain: canonical_authenticated_domain(authenticated_domain),
            connection_id,
        };
        occupant.payload = request.payload.clone();
        let serializable = SerializableMucOccupant::from(&occupant);
        let json = serde_json::to_string(&serializable)?;
        if state.cluster.is_enabled() {
            let room = state
                .muc_service()
                .federated_room_snapshot(localpart(&room_jid))
                .await?
                .context("federated MUC presence refresh references a missing room")?;
            let target = state
                .muc_service()
                .local_cluster_occupancy_target(
                    room.id,
                    occupant.cluster_epoch,
                    occupant.connection_id,
                )
                .await?
                .context("federated MUC presence refresh lost its exact PG occupancy")?;
            if !state
                .muc_service()
                .refresh_local_cluster_presence(
                    &target,
                    &state.cluster.node_id,
                    &occupant.payload,
                    std::time::Duration::from_secs(90),
                )
                .await?
            {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-acceptable",
                ));
            }
        }
        if state.cluster.is_enabled() {
            // PostgreSQL accepted the exact occupancy refresh. Any local
            // value under this nickname is only stale soft state.
            state.muc_occupants.insert(key.clone(), occupant.clone());
        } else {
            let Some(mut current) = state.muc_occupants.get_mut(&key) else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-acceptable",
                ));
            };
            if current.full_jid != actor_full_jid
                || current.connection_id != occupant.connection_id
                || current.cluster_epoch != occupant.cluster_epoch
            {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
            *current = occupant.clone();
        }
        drop(local_actor_guard);
        if state.cluster.is_enabled() {
            if let Err(error) = state
                .cluster
                .register_muc_occupant(&room_jid, nick, &json)
                .await
            {
                tracing::warn!(?error, room=%room_jid, nick=%nick,
                    "could not refresh Redis MUC presence soft-state");
            }
        } else if !state
            .cluster
            .register_muc_occupant(&room_jid, nick, &json)
            .await?
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "not-acceptable",
            ));
        }
        state
            .cluster
            .send_muc_presence(
                &room_jid,
                &serializable,
                false,
                false,
                request.stanza.id.as_deref(),
            )
            .await?;
        for (_, recipient) in state.muc_occupants_for(&room_jid) {
            let self_presence = recipient.full_jid == actor_full_jid;
            if request.muc_join && self_presence {
                continue;
            }
            let update = muc_presence_stanza(
                &serializable,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                request.stanza.id.as_deref(),
                serializable.room_non_anonymous || self_presence || recipient.role == "moderator",
            );
            let _ = state.deliver_to_muc_occupant(&recipient, update).await;
        }
        if request.muc_join {
            let Some(room) = state
                .muc_service()
                .federated_room_snapshot(localpart(&room_jid))
                .await?
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            let history_request = match request.history_request {
                Ok(request) => request,
                Err(()) => {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "modify",
                        "bad-request",
                    ));
                }
            };
            let mut roster_nicks = std::collections::HashSet::new();
            for (_, present) in state.muc_occupants_for(&room_jid) {
                if present.cluster_epoch == occupant.cluster_epoch
                    || !roster_nicks.insert(present.nick.clone())
                {
                    continue;
                }
                let roster_presence = muc_presence_stanza(
                    &SerializableMucOccupant::from(&present),
                    &actor_full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                );
                let _ = state
                    .deliver_to_muc_occupant(&occupant, roster_presence)
                    .await;
            }
            for json in state
                .cluster
                .get_muc_occupants(&room_jid)
                .await?
                .into_values()
            {
                let Ok(present) = serde_json::from_str::<SerializableMucOccupant>(&json) else {
                    continue;
                };
                if present.cluster_epoch == occupant.cluster_epoch
                    || !roster_nicks.insert(present.nick.clone())
                {
                    continue;
                }
                let roster_presence = muc_presence_stanza(
                    &present,
                    &actor_full_jid,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                );
                let _ = state
                    .deliver_to_muc_occupant(&occupant, roster_presence)
                    .await;
            }
            let self_presence = muc_presence_stanza(
                &serializable,
                &actor_full_jid,
                false,
                true,
                false,
                request.stanza.id.as_deref(),
                true,
            );
            let _ = state
                .deliver_to_muc_occupant(&occupant, self_presence)
                .await;
            let mut history = Vec::new();
            if history_request.max_stanzas != 0 && room.logging_enabled {
                for message in state
                    .muc_service()
                    .federated_history_since(room.id, 100, history_request.since)
                    .await?
                {
                    let stanza =
                        federated_history_stanza(&room, &message.stanza, &message.sender_jid);
                    history.push(set_to(
                        &add_delay_from(&stanza, message.created_at, Some(&room_jid)),
                        &actor_full_jid,
                    ));
                }
            }
            for delivery in super::muc::apply_muc_history_bounds(history, history_request) {
                let _ = state.deliver_to_muc_occupant(&occupant, delivery).await;
            }
            let subject = super::muc::current_muc_subject_stanza(&room, &room_jid, &actor_full_jid);
            let _ = state.deliver_to_muc_occupant(&occupant, subject).await;
        }
        return Ok(None);
    }

    let (room, created) = match state
        .muc_service()
        .get_or_create_federated_room(localpart(&room_jid), &actor_full_jid)
        .await
    {
        Ok(result) => result,
        Err(error) if crate::services::muc::MucService::is_capacity_exhausted(&error) => {
            state
                .metrics
                .capacity_reservations_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(federated_error(
                &request.stanza,
                from,
                "wait",
                "resource-constraint",
            ));
        }
        Err(error) => return Err(error),
    };
    if !created && room.configuration_is_expired(chrono::Utc::now()) {
        // PostgreSQL records the tombstone and terminal audience outbox in
        // one transaction. Redis is not an executable control plane.
        let _ = state
            .muc_service()
            .delete_expired_locked_room(room.id)
            .await?;
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    if !created
        && room.is_locked()
        && !room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now())
    {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    if created {
        let _ = super::mix_muc::maybe_link_local_mirror(state, &room.localpart, &actor_bare_jid)
            .await?;
    }
    let affiliation = state
        .muc_service()
        .federated_affiliation(room.id, &actor_bare_jid)
        .await?;
    if affiliation.as_deref() == Some("outcast") {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    if let Some(password_hash) = room.password_hash.as_deref() {
        let supplied = zeroize::Zeroizing::new(request.password.clone());
        let password_hash = zeroize::Zeroizing::new(password_hash.to_owned());
        let valid = match crate::password_work::run(move || {
            Ok(crate::services::muc::MucService::verify_room_password(
                &password_hash,
                &supplied,
            ))
        })
        .await
        {
            Ok(valid) => valid,
            Err(error) if error.is_overloaded() => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "resource-constraint",
                ));
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "room password verification task failed: {error}"
                ));
            }
        };
        if !valid {
            return Ok(federated_error(
                &request.stanza,
                from,
                "auth",
                "not-authorized",
            ));
        }
    }
    let local_join_guard = if state.cluster.is_enabled() {
        None
    } else {
        Some(state.muc_service().lock_local_room_mutation(room.id).await)
    };
    let (room, affiliation) = if local_join_guard.is_some() {
        let Some(refreshed_room) = state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        };
        if refreshed_room.room_epoch != room.room_epoch {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        if refreshed_room.config_version != room.config_version {
            // Password verification and the rest of the preliminary policy
            // check belonged to the old configuration. Retry rather than
            // authorizing a join under a mixed policy snapshot.
            return Ok(federated_error(
                &request.stanza,
                from,
                "wait",
                "resource-constraint",
            ));
        }
        if refreshed_room.configuration_is_expired(chrono::Utc::now())
            || (refreshed_room.is_locked()
                && !refreshed_room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now()))
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        let refreshed_affiliation = state
            .muc_service()
            .federated_affiliation(refreshed_room.id, &actor_bare_jid)
            .await?;
        (refreshed_room, refreshed_affiliation)
    } else {
        (room, affiliation)
    };
    if affiliation.as_deref() == Some("outcast") {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    if room.members_only && affiliation.is_none() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "registration-required",
        ));
    }
    if state
        .muc_service()
        .federated_nick_reserved_for_other(room.id, &actor_bare_jid, nick)
        .await?
    {
        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
    }
    let local_occupant_count = if state.cluster.is_enabled() {
        0
    } else {
        state.muc_occupants_for(&room_jid).len()
    };
    let privileged_join = matches!(affiliation.as_deref(), Some("owner" | "admin"));
    let effective_capacity = room.max_occupants as usize + usize::from(privileged_join) * 10;
    if !state.cluster.is_enabled() && local_occupant_count >= effective_capacity {
        return Ok(federated_error(
            &request.stanza,
            from,
            "wait",
            "service-unavailable",
        ));
    }
    let key = muc_occupant_key(&room_jid, nick);
    if !state.cluster.is_enabled() && state.muc_occupants.contains_key(&key) {
        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
    }
    let history_request = match request.history_request {
        Ok(history_request) => history_request,
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
    let role = if matches!(affiliation.as_str(), "owner" | "admin") {
        "moderator"
    } else if room.moderated && affiliation == "none" {
        "visitor"
    } else {
        "participant"
    }
    .to_owned();
    let occupant = MucOccupant {
        full_jid: actor_full_jid.clone(),
        room_jid: room_jid.clone(),
        nick: nick.to_owned(),
        endpoint: MucOccupantEndpoint::Federated {
            authenticated_domain: canonical_authenticated_domain(authenticated_domain),
            connection_id,
        },
        affiliation,
        role,
        room_non_anonymous: room.non_anonymous,
        occupant_id: muc_occupant_id(&room.occupant_id_secret, &actor_bare_jid),
        cluster_epoch: uuid::Uuid::new_v4(),
        connection_id,
        sm_session_id: None,
        payload: request.payload.clone(),
    };
    let serializable = SerializableMucOccupant::from(&occupant);
    let mut cluster_event_id = None;
    if state.cluster.is_enabled() {
        state
            .cluster
            .admit(crate::cluster::ClusterOperation::MucMutation)?;
        let principal = ClusterMucPrincipal::Federated {
            bare_jid: actor_bare_jid.clone(),
            authenticated_domain: canonical_authenticated_domain(authenticated_domain),
        };
        let cluster_operation_id = uuid::Uuid::new_v4();
        match state
            .muc_service()
            .claim_local_cluster_occupancy(ClusterMucJoin {
                operation_id: cluster_operation_id,
                room_id: room.id,
                expected_room_epoch: room.room_epoch,
                expected_config_version: room.config_version,
                principal,
                full_jid: &actor_full_jid,
                nick,
                owner_node_id: &state.cluster.node_id,
                connection_uuid: connection_id,
                connection_epoch: 1,
                sm_session_id: None,
                occupant_incarnation: occupant.cluster_epoch,
                presence_payload: &occupant.payload,
                lease: std::time::Duration::from_secs(90),
            })
            .await?
        {
            ClusterMucJoinOutcome::Joined(authority) | ClusterMucJoinOutcome::Replay(authority) => {
                debug_assert_eq!(authority.occupant_incarnation, occupant.cluster_epoch);
            }
            ClusterMucJoinOutcome::Outcast => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            ClusterMucJoinOutcome::MembershipRequired => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "auth",
                    "registration-required",
                ));
            }
            ClusterMucJoinOutcome::ReservedNickname
            | ClusterMucJoinOutcome::NicknameConflict
            | ClusterMucJoinOutcome::FullJidConflict => {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
            ClusterMucJoinOutcome::Full => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "service-unavailable",
                ));
            }
            ClusterMucJoinOutcome::RoomMissing
            | ClusterMucJoinOutcome::RoomDestroyed
            | ClusterMucJoinOutcome::RoomLocked
            | ClusterMucJoinOutcome::StaleRoom => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
        }
        cluster_event_id = Some(cluster_operation_id.to_string());
        if let Err(error) = state
            .muc_service()
            .wake_committed_operation(&state.cluster, cluster_operation_id)
            .await
        {
            tracing::warn!(?error, %room_jid, operation_id=%cluster_operation_id,
                "federated MUC join committed; signed wake failed and PostgreSQL polling will catch up");
        }
        if let Err(error) = state.cluster.get_muc_occupants(&room_jid).await {
            tracing::warn!(?error, %room_jid,
                "PostgreSQL committed federated MUC join; Redis cache refresh failed");
        }
        match state
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
                    "Redis federated MUC cache disagreed with committed PostgreSQL occupancy");
            }
            Err(error) => tracing::warn!(?error, %room_jid,
                "PostgreSQL committed federated MUC join; Redis cache update failed"),
        }
    }
    // Snapshot the existing local audience before publishing the joining
    // remote occupant. The single-node room mutation guard makes this exact;
    // clustered delivery to other nodes remains driven by the committed
    // PostgreSQL event rather than by this in-memory view.
    let local_existing = state.muc_occupants_for(&room_jid);
    let locally_published = match state.muc_occupants.entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(_) => false,
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(occupant.clone());
            true
        }
    };
    if !locally_published {
        if !state.cluster.is_enabled() {
            return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
        }
        tracing::warn!(room=%room_jid, %nick,
            "replacing stale local federated MUC actor after authoritative clustered join");
        state.muc_occupants.insert(key, occupant.clone());
    }
    drop(local_join_guard);
    state.cluster.join_muc(&room_jid).await?;
    state
        .cluster
        .register_muc_occupant(&room_jid, nick, &serde_json::to_string(&serializable)?)
        .await?;
    if cluster_event_id.is_none() {
        state
            .cluster
            .send_muc_presence(
                &room_jid,
                &serializable,
                false,
                created,
                request.stanza.id.as_deref(),
            )
            .await?;
    }

    let global = state
        .cluster
        .get_muc_occupants(&room_jid)
        .await
        .unwrap_or_default();
    let mut roster_nicks = std::collections::HashSet::new();
    for json in global.values() {
        if let Ok(present) = serde_json::from_str::<SerializableMucOccupant>(json) {
            if present.nick != nick && roster_nicks.insert(present.nick.clone()) {
                let roster_presence = muc_presence_stanza(
                    &present,
                    from,
                    false,
                    false,
                    false,
                    None,
                    room.non_anonymous || occupant.role == "moderator",
                );
                let _ = state
                    .deliver_to_muc_occupant(&occupant, roster_presence)
                    .await;
            }
        }
    }
    for (_, present) in &local_existing {
        if roster_nicks.insert(present.nick.clone()) {
            let roster_presence = muc_presence_stanza(
                &SerializableMucOccupant::from(present),
                from,
                false,
                false,
                false,
                None,
                room.non_anonymous || occupant.role == "moderator",
            );
            let _ = state
                .deliver_to_muc_occupant(&occupant, roster_presence)
                .await;
        }
        if cluster_event_id.is_none() {
            let joined = muc_presence_stanza(
                &serializable,
                &present.full_jid,
                false,
                false,
                false,
                None,
                room.non_anonymous || present.role == "moderator",
            );
            let _ = state.deliver_to_muc_occupant(present, joined).await;
        }
    }
    let self_presence = muc_presence_stanza(
        &serializable,
        &actor_full_jid,
        false,
        true,
        created,
        cluster_event_id.as_deref().or(request.stanza.id.as_deref()),
        true,
    );
    let _ = state
        .deliver_to_muc_occupant(&occupant, self_presence)
        .await;
    let mut history = Vec::new();
    if history_request.max_stanzas != 0 && room.logging_enabled {
        for message in state
            .muc_service()
            .federated_history_since(room.id, 100, history_request.since)
            .await?
        {
            let stanza = federated_history_stanza(&room, &message.stanza, &message.sender_jid);
            history.push(set_to(
                &add_delay_from(&stanza, message.created_at, Some(&room_jid)),
                &actor_full_jid,
            ));
        }
    }
    for delivery in super::muc::apply_muc_history_bounds(history, history_request) {
        let _ = state.deliver_to_muc_occupant(&occupant, delivery).await;
    }
    let subject = super::muc::current_muc_subject_stanza(&room, &room_jid, &actor_full_jid);
    let _ = state.deliver_to_muc_occupant(&occupant, subject).await;
    Ok(None)
}

/// Handle messages from a remote room actor. Authorization is bound to the
/// occupant endpoint, not merely to a claimed room nickname.
pub(crate) fn federated_muc_message<'a>(
    state: &'a AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    root: Node<'_, '_>,
    raw: &str,
) -> impl std::future::Future<Output = Result<Option<String>>> + Send + 'a {
    let authenticated_domain = authenticated_domain.to_owned();
    let request = FederatedMessageRequest::from_node(root, raw);
    async move {
        federated_muc_message_owned(state, &authenticated_domain, connection_id, request).await
    }
}

async fn federated_muc_message_owned(
    state: &AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    request: FederatedMessageRequest,
) -> Result<Option<String>> {
    let from = request.stanza.from.as_str();
    let to = request.stanza.to.as_str();
    if let Some((error_type, condition)) = request.validation_error {
        // RFC 6120 section 8.3.1 forbids reflecting an error in response to
        // another error stanza. Other malformed remote MUC messages get the
        // same bounded modern-message validation as local C2S messages before
        // any room/archive admission can observe them.
        if request.stanza.kind.as_deref() == Some("error") {
            return Ok(None);
        }
        return Ok(federated_error(
            &request.stanza,
            from,
            error_type,
            condition,
        ));
    }
    if !authenticated_remote_actor(authenticated_domain, from) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let actor_full_jid = crate::jid::canonicalize(from)
        .expect("authenticated_remote_actor already validated the full JID");
    // The clustered invitation authority is account scoped, while the exact
    // full JID remains independently bound to the authenticated occupancy.
    // Derive both from the already authenticated S2S actor; never reuse the
    // room JID, invitee JID or an unprepared `from` value as the principal.
    let actor_bare_jid = crate::jid::canonical_bare_key(&actor_full_jid)?;
    let Ok(to_jid) = crate::jid::CanonicalJid::parse(to) else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    };
    let room_jid = to_jid.bare();
    if to_jid.domainpart() != muc_domain(state) || to_jid.localpart().is_none() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    let decline = match &request.decline {
        Ok(decline) => decline.clone(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    if let Some((target_raw, reason)) = decline {
        if to_jid.resourcepart().is_some()
            || !matches!(request.stanza.kind.as_deref(), None | Some("normal"))
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
        if state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
            .is_none()
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        let Ok(target) = crate::jid::CanonicalJid::parse(&target_raw) else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let Some(target_localpart) = target.localpart() else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let mut decline = XmlElement::new("decline").attr("from", bare_jid(&actor_full_jid));
        if let Some(reason) = reason.as_deref() {
            decline.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let forwarded = XmlElement::namespaced("message", "jabber:client")
            .attr("from", &room_jid)
            .attr("to", &target_raw)
            .attr("type", "normal")
            .attr(
                "id",
                request
                    .stanza
                    .id
                    .as_deref()
                    .filter(|id| !id.is_empty() && id.len() <= 128)
                    .unwrap_or("muc-decline"),
            )
            .child(
                XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user").child(decline),
            )
            .validated_fragment(&request.hints)?
            .finish();
        if target.domainpart() == state.config.domain {
            let Some(recipient) = state
                .muc_service()
                .enabled_local_account(target_localpart)
                .await?
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            let target_bare = target.bare();
            if state
                .muc_service()
                .is_blocked_for_account(recipient.id, &target_bare, &room_jid)
                .await?
                || state
                    .muc_service()
                    .is_blocked_for_account(recipient.id, &target_bare, &actor_full_jid)
                    .await?
            {
                return Ok(None);
            }
            let mut targets = state.session_entries_for(&target_raw);
            if target.resourcepart().is_none() {
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
            let mut delivered = targets
                .into_iter()
                .any(|(_, session)| session.sender.try_send(forwarded.clone()).is_ok());
            if !delivered {
                for node_id in state
                    .cluster
                    .lookup_nodes(&target_raw)
                    .await
                    .unwrap_or_default()
                {
                    if node_id != state.cluster.node_id
                        && state
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
            if !delivered && request.temporary_storage {
                let delayed = add_delay_from(&forwarded, chrono::Utc::now(), Some(&room_jid));
                let outcome = state
                    .muc_service()
                    .store_federated_muc_offline(
                        recipient.id,
                        &room_jid,
                        &delayed,
                        false,
                        OfflineStorePolicy {
                            max_messages: state.config.offline_max_messages_per_account,
                            max_bytes: state.config.offline_max_bytes_per_account,
                            ttl_days: state.config.offline_message_ttl_days,
                            mam_backed: false,
                        },
                    )
                    .await?;
                if outcome == OfflineStoreOutcome::QuotaExceeded {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "wait",
                        "resource-constraint",
                    ));
                }
                if outcome == OfflineStoreOutcome::RecipientUnavailable {
                    return Ok(None);
                }
                if let Err(error) = super::misc::send_push_notification(state, recipient.id).await {
                    tracing::warn!(?error, recipient_id = %recipient.id, %room_jid, "accepted federated offline MUC invitation decline could not trigger push notification");
                }
            }
            return Ok(None);
        }
        if !state
            .config
            .external_route_domain_allowed(target.domainpart())
            || !state
                .federation
                .send(target.domainpart(), forwarded, Some(room_jid.clone()))
                .await
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "wait",
                "remote-server-timeout",
            ));
        }
        return Ok(None);
    }
    let Some((_, own)) = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid))
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-acceptable",
        ));
    };
    if !federated_endpoint_matches(&own, authenticated_domain) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    // Only an available presence refresh may transfer the transport endpoint
    // of an existing federated occupant. Message traffic is authorized by the
    // authenticated domain but must not silently seize the occupant from the
    // connection/incarnation admitted by the room authority.
    let Some(room) = state
        .muc_service()
        .federated_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    };
    let voice_form = match &request.voice_form {
        Ok(form) => form.as_ref(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    if let Some(voice_form) = voice_form {
        if to_jid.resourcepart().is_some()
            || !matches!(request.stanza.kind.as_deref(), None | Some("normal"))
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
        let mut occupants = state
            .cluster
            .get_muc_occupants(&room_jid)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(nick, json)| {
                serde_json::from_str::<SerializableMucOccupant>(&json)
                    .ok()
                    .map(|occupant| (nick, occupant))
            })
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in state.muc_occupants_for(&room_jid) {
            occupants.insert(
                occupant.nick.clone(),
                SerializableMucOccupant::from(&occupant),
            );
        }
        match voice_form {
            super::muc::MucVoiceForm::Request => {
                if !room.moderated || own.role != "visitor" {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
                let voice_request = XmlElement::new("message")
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
                            .child(super::muc::muc_xdata_value_field(
                                "FORM_TYPE",
                                "hidden",
                                "http://jabber.org/protocol/muc#request",
                            ))
                            .child(super::muc::muc_xdata_value_field(
                                "muc#role",
                                "list-single",
                                "participant",
                            ))
                            .child(super::muc::muc_xdata_value_field(
                                "muc#jid",
                                "jid-single",
                                &own.full_jid,
                            ))
                            .child(super::muc::muc_xdata_value_field(
                                "muc#roomnick",
                                "text-single",
                                &own.nick,
                            ))
                            .child(super::muc::muc_xdata_value_field(
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
                    if let Some(local) = state
                        .muc_occupants
                        .get(&key)
                        .map(|entry| entry.value().clone())
                    {
                        let _ = state
                            .deliver_to_muc_occupant(
                                &local,
                                set_to(&voice_request, &local.full_jid),
                            )
                            .await;
                    }
                    state
                        .cluster
                        .send_muc_private_from(
                            &room_jid,
                            &moderator.nick,
                            &voice_request,
                            &own.full_jid,
                        )
                        .await?;
                }
                return Ok(None);
            }
            super::muc::MucVoiceForm::Approval { jid, nick, allow } => {
                if own.role != "moderator" {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
                let Some(target) = occupants.get(nick) else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if target.full_jid != *jid || target.role != "visitor" {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "not-allowed",
                    ));
                }
                if !allow {
                    return Ok(None);
                }
                let service = state.muc_service();
                let Some(actor_target) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                    .await?
                else {
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                };
                let Some(target_authority) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target.nick)
                    .await?
                else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if actor_target.full_jid != own.full_jid
                    || actor_target.connection_uuid != own.connection_id
                    || target_authority.full_jid != target.full_jid
                    || target_authority.connection_uuid != target.connection_id
                {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                }
                let operation_id =
                    crate::services::muc::MucService::operation_id(&serde_json::json!({
                        "kind":"voice_approval","stream":connection_id,
                        "stanza_id":request.stanza.id,"room":room_jid,
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
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                    _ => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                }
                if let Err(error) = state
                    .muc_service()
                    .wake_committed_operation(&state.cluster, operation_id)
                    .await
                {
                    tracing::warn!(?error, %operation_id, "committed federated MUC voice approval wake failed; PostgreSQL outbox will catch up");
                }
                return Ok(None);
            }
        }
    }
    if to.contains('/') {
        if !room.allow_private_messages {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        }
        if !matches!(
            request.stanza.kind.as_deref().unwrap_or("normal"),
            "chat" | "normal"
        ) {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
        let Some(target_nick) = to_jid.resourcepart() else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let target_key = muc_occupant_key(&room_jid, target_nick);
        let local_target = state
            .muc_occupants
            .get(&target_key)
            .map(|value| value.clone());
        let (target_full_jid, route_via_cluster) = if let Some(target) = &local_target {
            (target.full_jid.clone(), false)
        } else {
            let global = state.cluster.get_muc_occupants(&room_jid).await?;
            let Some(target) = global
                .get(target_nick)
                .and_then(|json| serde_json::from_str::<SerializableMucOccupant>(json).ok())
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            (target.full_jid, true)
        };
        let private = set_muc_occupant_id(
            &add_stanza_id(
                &set_to(
                    &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
                    &target_full_jid,
                ),
                &room_jid,
                uuid::Uuid::new_v4(),
            ),
            &own.occupant_id,
        );
        if route_via_cluster {
            state
                .cluster
                .send_muc_private_from(&room_jid, target_nick, &private, &actor_full_jid)
                .await?;
        } else if let Some(target) = local_target {
            let blocked = state
                .blocked_muc_recipient_accounts(
                    std::slice::from_ref(&target),
                    &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
                )
                .await;
            if !crate::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                let _ = state
                    .deliver_to_muc_occupant_unchecked(&target, private)
                    .await;
            }
        }
        return Ok(None);
    }
    if request.stanza.kind.as_deref() != Some("groupchat") {
        let privileged_inviter = matches!(own.affiliation.as_str(), "owner" | "admin");
        if !request.invites.is_empty()
            && !privileged_inviter
            && (own.role == "visitor" || !room.allow_invites)
        {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        }
        let mut delivered_invitation = false;
        for invite in &request.invites {
            let Some(invitee_raw) = invite.invitee.as_deref() else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "bad-request",
                ));
            };
            let Ok(invitee) = crate::jid::CanonicalJid::parse(invitee_raw) else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let Some(invitee_localpart) = invitee.localpart() else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let invitee_jid = invitee.to_string();
            let invitee_bare = invitee.bare();
            let invitee_domain = invitee.domainpart();
            if invitee_domain == state.config.domain {
                if let Some(local_user) = state
                    .muc_service()
                    .enabled_local_account(invitee_localpart)
                    .await?
                {
                    let blocked_room = state
                        .muc_service()
                        .is_blocked_for_account(local_user.id, &invitee_bare, &room_jid)
                        .await?;
                    let blocked_inviter = state
                        .muc_service()
                        .is_blocked_for_account(local_user.id, &invitee_bare, &actor_full_jid)
                        .await?;
                    if blocked_room || blocked_inviter {
                        delivered_invitation = true;
                        continue;
                    }
                }
            }
            let reason = invite.reason.as_deref();
            let mut invite_out = XmlElement::new("invite").attr("from", from);
            if let Some(reason) = reason {
                invite_out.push_child(XmlElement::new("reason").text(reason.to_owned()));
            }
            let local_durable_invite_id =
                if room.members_only && invitee_domain == state.config.domain {
                    Some(crate::services::muc::MucService::operation_id(
                        &serde_json::json!({
                            "kind":"muc_invitation","stream":connection_id,
                            "stanza_id":request.stanza.id,"room":room_jid,
                            "actor":actor_full_jid,"invitee":invitee_bare,"reason":reason,
                        }),
                    )?)
                } else {
                    None
                };
            let invitation = set_muc_occupant_id(
                &add_stanza_id(
                    &XmlElement::namespaced("message", "jabber:client")
                        .attr("from", &room_jid)
                        .attr("to", &invitee_jid)
                        .attr("type", "normal")
                        .child(
                            XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user")
                                .child(invite_out),
                        )
                        .validated_fragment(&request.hints)?
                        .finish(),
                    &room_jid,
                    uuid::Uuid::new_v4(),
                ),
                &own.occupant_id,
            );
            let invitation = local_durable_invite_id.map_or(invitation.clone(), |id| {
                add_stanza_id(&invitation, &invitee_bare, id)
            });
            if invitee_domain == state.config.domain {
                let Some(local_user) = state
                    .muc_service()
                    .enabled_local_account(invitee_localpart)
                    .await?
                else {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if room.members_only && !request.temporary_storage {
                    return Ok(federated_error(
                        &request.stanza,
                        from,
                        "wait",
                        "service-unavailable",
                    ));
                }
                let durable_invite = if room.members_only {
                    let delayed = add_delay_from(&invitation, chrono::Utc::now(), Some(&room_jid));
                    let cluster_authority = if state.cluster.is_enabled() {
                        state
                            .cluster
                            .admit(crate::cluster::ClusterOperation::MucMutation)?;
                        let Some(actor_target) = state
                            .muc_service()
                            .local_cluster_occupancy_target(
                                room.id,
                                own.cluster_epoch,
                                own.connection_id,
                            )
                            .await?
                        else {
                            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                        };
                        Some(ClusterMucInviteAuthority {
                            operation_id: local_durable_invite_id
                                .expect("local members-only invite allocates a fence"),
                            expected_room_epoch: room.room_epoch,
                            expected_config_version: room.config_version,
                            actor: ClusterMucPrincipal::Federated {
                                bare_jid: actor_bare_jid.clone(),
                                authenticated_domain: authenticated_domain.to_owned(),
                            },
                            actor_full_jid: actor_full_jid.clone(),
                            actor_target: Some(actor_target),
                            subject: ClusterMucAffiliationSubject::Local {
                                user_id: local_user.id,
                                bare_jid: invitee_bare.clone(),
                            },
                            reason: reason.map(str::to_owned),
                        })
                    } else {
                        None
                    };
                    match state
                        .muc_service()
                        .admit_local_invite_command(
                            local_durable_invite_id
                                .expect("local members-only invite allocates a fence"),
                            room.id,
                            local_user.id,
                            &room_jid,
                            &delayed,
                            false,
                            OfflineStorePolicy {
                                max_messages: state.config.offline_max_messages_per_account,
                                max_bytes: state.config.offline_max_bytes_per_account,
                                ttl_days: state.config.offline_message_ttl_days,
                                mam_backed: false,
                            },
                            cluster_authority.as_ref(),
                        )
                        .await?
                    {
                        DurableMucInviteOutcome::Stored { id, .. } => {
                            if let Some(authority) = &cluster_authority {
                                state
                                    .muc_service()
                                    .wake_committed_operation(
                                        &state.cluster,
                                        authority.operation_id,
                                    )
                                    .await?;
                            }
                            Some(id)
                        }
                        DurableMucInviteOutcome::Replay { .. } => {
                            if let Some(authority) = &cluster_authority {
                                state
                                    .muc_service()
                                    .wake_committed_operation(
                                        &state.cluster,
                                        authority.operation_id,
                                    )
                                    .await?;
                            }
                            return Ok(None);
                        }
                        DurableMucInviteOutcome::QuotaExceeded => {
                            return Ok(federated_error(
                                &request.stanza,
                                from,
                                "wait",
                                "resource-constraint",
                            ));
                        }
                        DurableMucInviteOutcome::RecipientUnavailable => {
                            // The local invitee disappeared after the initial
                            // route lookup.  Suppress the invitation without
                            // exposing account lifecycle state to the remote
                            // room occupant.
                            return Ok(None);
                        }
                        DurableMucInviteOutcome::Outcast => {
                            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                        }
                        DurableMucInviteOutcome::AuthorityRejected => {
                            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                        }
                        DurableMucInviteOutcome::Stale => {
                            return Ok(federated_error(
                                &request.stanza,
                                from,
                                "cancel",
                                "item-not-found",
                            ));
                        }
                    }
                } else {
                    None
                };
                let mut targets = state.session_entries_for(&invitee_jid);
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
                let live_delivery =
                    durable_invite.map(|message_id| crate::outbound::DurableDelivery {
                        recipient_id: local_user.id,
                        message_id,
                        claim_id: None,
                    });
                let mut delivered = false;
                let mut delivered_full_jid = None;
                for (full_jid, session) in targets {
                    let accepted = if let Some(delivery) = live_delivery {
                        session
                            .sender
                            .try_send_durable(invitation.clone(), delivery)
                            .is_ok()
                    } else {
                        session.sender.try_send(invitation.clone()).is_ok()
                    };
                    if accepted {
                        let counter = if live_delivery.is_some() {
                            &state.metrics.online_queue_durable_acceptances_total
                        } else {
                            &state.metrics.online_queue_volatile_acceptances_total
                        };
                        counter.fetch_add(1, Ordering::Relaxed);
                        delivered = true;
                        delivered_full_jid = Some(full_jid);
                        break;
                    }
                }
                if !delivered {
                    for node_id in state
                        .cluster
                        .lookup_nodes(&invitee_jid)
                        .await
                        .unwrap_or_default()
                    {
                        if node_id != state.cluster.node_id {
                            let receipt = if let Some(delivery) = live_delivery {
                                state
                                    .cluster
                                    .send_to_node_primary_durable(
                                        &node_id,
                                        &invitee_jid,
                                        &invitation,
                                        delivery,
                                    )
                                    .await
                                    .unwrap_or_default()
                            } else {
                                state
                                    .cluster
                                    .send_to_node_primary(&node_id, &invitee_jid, &invitation)
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
                if delivered {
                    if request.carbon_eligible {
                        super::messaging::send_received_carbons_for_state(
                            state,
                            &invitee_bare,
                            delivered_full_jid.as_deref(),
                            &invitation,
                        )
                        .await;
                    }
                } else if durable_invite.is_none() && request.temporary_storage {
                    let delayed = add_delay_from(&invitation, chrono::Utc::now(), Some(&room_jid));
                    let offline_outcome = state
                        .muc_service()
                        .store_federated_muc_offline(
                            local_user.id,
                            &room_jid,
                            &delayed,
                            false,
                            OfflineStorePolicy {
                                max_messages: state.config.offline_max_messages_per_account,
                                max_bytes: state.config.offline_max_bytes_per_account,
                                ttl_days: state.config.offline_message_ttl_days,
                                mam_backed: false,
                            },
                        )
                        .await?;
                    if offline_outcome == OfflineStoreOutcome::QuotaExceeded {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "wait",
                            "resource-constraint",
                        ));
                    }
                    if offline_outcome == OfflineStoreOutcome::RecipientUnavailable {
                        return Ok(None);
                    }
                }
                if !delivered && request.temporary_storage {
                    if let Err(error) =
                        super::misc::send_push_notification(state, local_user.id).await
                    {
                        tracing::warn!(?error, recipient_id = %local_user.id, %room_jid, "accepted federated offline mediated MUC invitation could not trigger push notification");
                    }
                }
            } else if room.members_only {
                let operation_id =
                    crate::services::muc::MucService::operation_id(&serde_json::json!({
                        "kind":"muc_invitation","stream":connection_id,
                        "stanza_id":request.stanza.id,"room":room_jid,
                        "actor":actor_full_jid,"invitee":invitee_bare,"reason":reason,
                    }))?;
                let cluster_authority = if state.cluster.is_enabled() {
                    state
                        .cluster
                        .admit(crate::cluster::ClusterOperation::MucMutation)?;
                    let Some(actor_target) = state
                        .muc_service()
                        .local_cluster_occupancy_target(
                            room.id,
                            own.cluster_epoch,
                            own.connection_id,
                        )
                        .await?
                    else {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    };
                    Some(ClusterMucInviteAuthority {
                        operation_id,
                        expected_room_epoch: room.room_epoch,
                        expected_config_version: room.config_version,
                        actor: ClusterMucPrincipal::Federated {
                            bare_jid: actor_bare_jid.clone(),
                            authenticated_domain: authenticated_domain.to_owned(),
                        },
                        actor_full_jid: actor_full_jid.clone(),
                        actor_target: Some(actor_target),
                        subject: ClusterMucAffiliationSubject::Federated {
                            bare_jid: invitee_bare.clone(),
                        },
                        reason: reason.map(str::to_owned),
                    })
                } else {
                    None
                };
                match state
                    .muc_service()
                    .admit_federated_invite_command(
                        room.id,
                        &invitee_bare,
                        invitee_domain,
                        &invitation,
                        Some(&room_jid),
                        state.federation.outbox_policy().into(),
                        cluster_authority.as_ref(),
                    )
                    .await
                {
                    Ok(true) => {
                        state.federation.wake_outbox();
                        if cluster_authority.is_some() {
                            state
                                .muc_service()
                                .wake_committed_operation(&state.cluster, operation_id)
                                .await?;
                        }
                    }
                    Ok(false) => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                    Err(error) => {
                        tracing::warn!(?error, %invitee_bare, %room_jid, "federated mediated MUC invite admission failed atomically");
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "wait",
                            "resource-constraint",
                        ));
                    }
                }
            } else if !state
                .federation
                .send(invitee_domain, invitation, Some(room_jid.clone()))
                .await
            {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "wait",
                    "remote-server-timeout",
                ));
            }
            delivered_invitation = true;
        }
        return if delivered_invitation {
            Ok(None)
        } else {
            Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ))
        };
    }
    // In single-node mode the room map is the occupancy authority. Serialize
    // the final remote endpoint/incarnation check, durable admission and live
    // fan-out with the same room gate used by kick/ban/leave. Cluster mode
    // instead presents the exact PostgreSQL occupancy tuple below.
    let local_authority_guard = if state.cluster.is_enabled() {
        None
    } else {
        Some(state.muc_service().lock_local_room_mutation(room.id).await)
    };
    let Some(refreshed_room) = state
        .muc_service()
        .federated_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    };
    if refreshed_room.id != room.id || refreshed_room.room_epoch != room.room_epoch {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    let Some((_, refreshed_own)) =
        state
            .muc_occupants_for(&room_jid)
            .into_iter()
            .find(|(_, occupant)| {
                occupant.full_jid == own.full_jid
                    && occupant.connection_id == own.connection_id
                    && occupant.cluster_epoch == own.cluster_epoch
                    && occupant.nick == own.nick
            })
    else {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    };
    if !federated_endpoint_matches(&refreshed_own, authenticated_domain) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let room = refreshed_room;
    let own = refreshed_own;
    let current_affiliation = state
        .muc_service()
        .federated_affiliation(room.id, &actor_bare_jid)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if current_affiliation != own.affiliation
        || current_affiliation == "outcast"
        || (room.members_only && current_affiliation == "none")
    {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    let cluster_target = if state.cluster.is_enabled() {
        let Some(target) = state
            .muc_service()
            .local_cluster_occupancy_target(room.id, own.cluster_epoch, own.connection_id)
            .await?
            .filter(|target| {
                target.room_epoch == room.room_epoch
                    && target.full_jid == own.full_jid
                    && target.nick == own.nick
                    && target.connection_uuid == own.connection_id
            })
        else {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        };
        Some(target)
    } else {
        None
    };
    if own.role == "visitor" {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    let subject_command = match &request.subject {
        Ok(subject) => subject.as_deref(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    let origin_id = match &request.origin_id {
        Ok(origin_id) => origin_id.as_deref(),
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    let author_retraction = match request.author_retraction {
        Ok(retraction) => retraction,
        Err(()) => {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "bad-request",
            ));
        }
    };
    if subject_command.is_some() && author_retraction.is_some() {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        ));
    }
    if subject_command.is_some()
        && own.role != "moderator"
        && !(room.allow_subject_change && own.role == "participant")
    {
        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
    }
    let stable_id = uuid::Uuid::new_v4();
    let reflected = set_muc_occupant_id(
        &add_stanza_id(
            &set_to(
                &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
                &room_jid,
            ),
            &room_jid,
            stable_id,
        ),
        &own.occupant_id,
    );
    let encrypted = request.encrypted;
    let archive_enabled = room.logging_enabled
        && request.permanent_storage
        && (encrypted || !state.config.require_encrypted_archive);
    let archive = if archive_enabled && encrypted {
        encrypted_archive_stanza(&reflected)
    } else {
        reflected.clone()
    };
    let actor_scope = crate::jid::canonical_bare_key(&actor_full_jid)?;
    let actor_authority = MucActorAuthority {
        clustered: state.cluster.is_enabled(),
        expected_room_epoch: room.room_epoch,
        principal: MucActorPrincipal::Federated {
            bare_jid: &actor_bare_jid,
            authenticated_domain,
        },
        actor_scope: &actor_scope,
        full_jid: &actor_full_jid,
        nick: &own.nick,
        occupant_incarnation: own.cluster_epoch,
        connection_uuid: own.connection_id,
        expected_role: &own.role,
        expected_affiliation: &current_affiliation,
        cluster_target,
    };
    if let Some(target_id) = author_retraction {
        let Some(original) = state
            .muc_service()
            .federated_message_by_id(room.id, target_id)
            .await?
        else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        };
        if crate::jid::canonical_bare_key(&original.sender_jid)
            .ok()
            .as_deref()
            != Some(actor_scope.as_str())
        {
            return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
        }
        let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "wait",
                "internal-server-error",
            ));
        };
        let original_root = original_document.root_element();
        if original_root.tag_name().name() != "message"
            || original_root.attribute("type") != Some("groupchat")
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "not-acceptable",
            ));
        }
        let stamp = chrono::Utc::now();
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
                    .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ")),
            )
            .finish();
        match state
            .muc_service()
            .retract_local_message_and_archive_action(MucRetractionMutation {
                action_id: stable_id,
                room_id: room.id,
                target_id,
                expected_stanza: &original.stanza,
                actor_scope: &actor_scope,
                sender_jid: &actor_full_jid,
                nick: &own.nick,
                tombstone: &tombstone,
                action_stanza: &reflected,
                reason: None,
                kind: MucRetractionKind::Author,
                authority: actor_authority,
            })
            .await?
        {
            MucRetractionOutcome::Applied => {}
            MucRetractionOutcome::Unauthorized => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
        }
    } else if let Some(subject) = subject_command {
        let service = state.muc_service();
        if state.cluster.is_enabled() {
            let Some(actor_target) = service
                .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                .await?
            else {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            };
            if actor_target.full_jid != own.full_jid
                || actor_target.connection_uuid != own.connection_id
            {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            let operation_id =
                crate::services::muc::MucService::operation_id(&serde_json::json!({
                    "kind":"subject","stream":connection_id,"stanza_id":request.stanza.id,
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
                        sender_jid: &actor_full_jid,
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
                    return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                }
                _ => return Ok(federated_error(&request.stanza, from, "cancel", "conflict")),
            }
            if let Err(error) = state
                .muc_service()
                .wake_committed_operation(&state.cluster, operation_id)
                .await
            {
                tracing::warn!(?error, %operation_id, "committed federated MUC subject wake failed; PostgreSQL outbox will catch up");
            }
            return Ok(None);
        }
        match service
            .set_local_subject(
                MucSubjectMutation {
                    stanza_id: stable_id,
                    room_id: room.id,
                    actor_scope: &actor_scope,
                    sender_jid: &actor_full_jid,
                    nick: &own.nick,
                    subject,
                    stanza: &archive,
                    encrypted,
                },
                archive_enabled,
                actor_authority,
            )
            .await?
        {
            MucSubjectOutcome::Applied => {}
            MucSubjectOutcome::Unauthorized => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            MucSubjectOutcome::Stale => {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
        }
    } else {
        let admission = state
            .muc_service()
            .admit_local_discussion(MucDiscussion {
                id: stable_id,
                room_id: room.id,
                actor_scope: &actor_scope,
                origin_id,
                sender_jid: &actor_full_jid,
                nick: &own.nick,
                stanza: &archive,
                encrypted,
                archive: archive_enabled,
                retention_days: state.config.muc_mam_retention_days,
                authority: actor_authority,
            })
            .await?;
        match admission {
            MucDiscussionAdmission::Stored(_) => {}
            MucDiscussionAdmission::Replay(_) => return Ok(None),
            MucDiscussionAdmission::Unauthorized => {
                return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
            }
            MucDiscussionAdmission::Stale => {
                return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
            }
        }
    }
    match state
        .cluster
        .send_to_muc_from(&room_jid, &reflected, &actor_full_jid)
        .await
    {
        Ok(()) => {}
        Err(_) => record_federated_muc_post_commit_failure(
            state,
            &room_jid,
            "*",
            "cluster groupchat fan-out",
        ),
    }
    let occupants = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .map(|(_, occupant)| occupant)
        .collect::<Vec<_>>();
    let blocked = state
        .blocked_muc_recipient_accounts(
            &occupants,
            &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
        )
        .await;
    for occupant in occupants {
        if crate::jid::canonical_bare_key(&occupant.full_jid)
            .is_ok_and(|owner| blocked.contains(&owner))
        {
            continue;
        }
        let delivery = set_to(&reflected, &occupant.full_jid);
        if !state
            .deliver_to_muc_occupant_unchecked(&occupant, delivery)
            .await
        {
            record_federated_muc_post_commit_failure(
                state,
                &room_jid,
                &occupant.full_jid,
                "occupant groupchat queue",
            );
        }
    }
    drop(local_authority_guard);
    state
        .metrics
        .messages_routed_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(None)
}

/// Handle room/service IQs from an authenticated remote room actor. XML is
/// converted to owned data before this future is created, so S2S connection
/// tasks remain `Send` across database and network awaits.
pub(crate) fn federated_muc_iq<'a>(
    state: &'a AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    root: Node<'_, '_>,
    raw: &str,
) -> impl std::future::Future<Output = Result<Option<String>>> + Send + 'a {
    let authenticated_domain = authenticated_domain.to_owned();
    let request = FederatedIqRequest::from_node(root, raw);
    async move { federated_muc_iq_owned(state, &authenticated_domain, connection_id, request).await }
}

async fn federated_muc_iq_owned(
    state: &AppState,
    authenticated_domain: &str,
    _connection_id: uuid::Uuid,
    request: FederatedIqRequest,
) -> Result<Option<String>> {
    let from = request.stanza.from.as_str();
    let to = request.stanza.to.as_str();
    if !authenticated_remote_actor(authenticated_domain, from) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    let actor_full_jid = crate::jid::canonicalize(from)
        .expect("authenticated_remote_actor already validated the full JID");
    let actor_bare_jid = crate::jid::canonical_bare_key(&actor_full_jid)?;
    let conference_domain = muc_domain(state);
    let Ok(to_jid) = crate::jid::CanonicalJid::parse(to) else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    };
    let room_jid = to_jid.bare();
    let service_request = to_jid.localpart().is_none() && to_jid.domainpart() == conference_domain;
    if !service_request && to_jid.domainpart() != conference_domain {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }

    if service_request {
        let payload = match request.payload {
            FederatedIqPayload::Ping => String::new(),
            FederatedIqPayload::DiscoInfo { node: None } => {
                let mut query =
                    XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info").child(
                        XmlElement::new("identity")
                            .attr("category", "conference")
                            .attr("type", "text")
                            .attr("name", format!("{} Group Chat", state.config.server_name)),
                    );
                for feature in [
                    "http://jabber.org/protocol/disco#info",
                    "http://jabber.org/protocol/disco#items",
                    "http://jabber.org/protocol/muc",
                    "http://jabber.org/protocol/muc#unique",
                    "http://jabber.org/protocol/rsm",
                    "urn:xmpp:mam:2",
                    "urn:xmpp:mam:2#extended",
                    "urn:xmpp:occupant-id:0",
                    "urn:xmpp:message-moderate:1",
                    "urn:xmpp:message-retract:1",
                    "urn:xmpp:message-retract:1#tombstone",
                    "urn:xmpp:ping",
                    "urn:xmpp:sid:0",
                ] {
                    query.push_child(XmlElement::new("feature").attr("var", feature));
                }
                query.finish()
            }
            FederatedIqPayload::DiscoInfo { node: Some(_) } => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            FederatedIqPayload::DiscoInfoError => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "modify",
                    "bad-request",
                ));
            }
            FederatedIqPayload::DiscoItems(disco) if disco.node.is_none() => {
                let page = match state
                    .muc_service()
                    .federated_public_room_page(
                        disco.after.as_deref(),
                        disco.before.as_ref().map(|value| value.as_deref()),
                        disco.max,
                    )
                    .await?
                {
                    Some(page) => page,
                    None => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                };
                let mut query =
                    XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
                for room in &page.rooms {
                    query.push_child(
                        XmlElement::new("item")
                            .attr("jid", format!("{}@{}", room.localpart, conference_domain))
                            .attr("name", room.title.as_deref().unwrap_or(&room.localpart)),
                    );
                }
                query.push_validated_fragment(&super::discovery::disco_rsm_result(
                    page.rooms.first().map(|room| room.localpart.as_str()),
                    page.rooms.last().map(|room| room.localpart.as_str()),
                    page.first_index,
                    page.total,
                ))?;
                query.finish()
            }
            FederatedIqPayload::DiscoItemsError(condition) => {
                return Ok(federated_error(&request.stanza, from, "modify", condition));
            }
            FederatedIqPayload::Unique => {
                XmlElement::namespaced("unique", "http://jabber.org/protocol/muc#unique")
                    .text(uuid::Uuid::new_v4().simple().to_string())
                    .finish()
            }
            _ => {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "feature-not-implemented",
                ));
            }
        };
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &conference_domain,
            &actor_full_jid,
            &payload,
        )));
    }

    if !valid_muc_room(localpart(&room_jid)) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "jid-malformed",
        ));
    }
    let Some(room) = state
        .muc_service()
        .federated_room_snapshot(localpart(&room_jid))
        .await?
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    };
    // Keep an unconfigured room invisible to every remote session except the
    // exact full JID that created it.  This matches the locked-room join and
    // owner-query boundary instead of leaking a reserved room via disco.
    if room.is_locked() && !room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now()) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "item-not-found",
        ));
    }
    if matches!(&request.payload, FederatedIqPayload::DiscoInfoError) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "modify",
            "bad-request",
        ));
    }
    if let FederatedIqPayload::DiscoInfo { node: Some(node) } = &request.payload {
        if node != "x-roomuser-item" {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
            .attr("node", "x-roomuser-item");
        if let Some(nick) = state
            .muc_service()
            .federated_reserved_nick(room.id, &actor_bare_jid)
            .await?
        {
            payload.push_child(
                XmlElement::new("identity")
                    .attr("category", "conference")
                    .attr("type", "text")
                    .attr("name", nick),
            );
        }
        let payload = payload.finish();
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            &payload,
        )));
    }
    if matches!(
        &request.payload,
        FederatedIqPayload::DiscoInfo { node: None }
    ) {
        let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
            .child(
                XmlElement::new("identity")
                    .attr("category", "conference")
                    .attr("type", "text")
                    .attr("name", room.title.as_deref().unwrap_or(&room.localpart)),
            );
        for feature in [
            "http://jabber.org/protocol/disco#info".to_owned(),
            "http://jabber.org/protocol/disco#items".to_owned(),
            "http://jabber.org/protocol/muc".to_owned(),
            "http://jabber.org/protocol/rsm".to_owned(),
            "urn:xmpp:mam:2".to_owned(),
            "urn:xmpp:mam:2#extended".to_owned(),
            "urn:xmpp:ping".to_owned(),
            "urn:xmpp:sid:0".to_owned(),
            "urn:xmpp:occupant-id:0".to_owned(),
            "urn:xmpp:message-moderate:1".to_owned(),
            "urn:xmpp:message-retract:1".to_owned(),
            format!("muc_{}", if room.public { "public" } else { "hidden" }),
            format!(
                "muc_{}",
                if room.persistent {
                    "persistent"
                } else {
                    "temporary"
                }
            ),
            format!(
                "muc_{}",
                if room.members_only {
                    "membersonly"
                } else {
                    "open"
                }
            ),
            format!(
                "muc_{}",
                if room.moderated {
                    "moderated"
                } else {
                    "unmoderated"
                }
            ),
            format!(
                "muc_{}",
                if room.non_anonymous {
                    "nonanonymous"
                } else {
                    "semianonymous"
                }
            ),
            format!(
                "muc_{}",
                if room.password_hash.is_some() {
                    "passwordprotected"
                } else {
                    "unsecured"
                }
            ),
        ] {
            payload.push_child(XmlElement::new("feature").attr("var", feature));
        }
        let payload = payload.finish();
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            &payload,
        )));
    }
    if matches!(&request.payload, FederatedIqPayload::Ping) {
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            "",
        )));
    }

    if matches!(
        &request.payload,
        FederatedIqPayload::RegisterGet | FederatedIqPayload::RegisterSet
    ) {
        if room.is_locked() && !room.can_configure_locked_room(&actor_full_jid, chrono::Utc::now())
        {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        }
        if !room.allow_registration {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "not-allowed",
            ));
        }
        if matches!(&request.payload, FederatedIqPayload::RegisterGet) {
            let payload = if let Some(nick) = state
                .muc_service()
                .federated_reserved_nick(room.id, &actor_bare_jid)
                .await?
            {
                XmlElement::namespaced("query", "jabber:iq:register")
                    .child(XmlElement::new("registered"))
                    .child(XmlElement::new("username").text(nick))
                    .finish()
            } else {
                XmlElement::namespaced("query", "jabber:iq:register")
                    .child(
                        XmlElement::namespaced("x", "jabber:x:data")
                            .attr("type", "form")
                            .child(XmlElement::new("title").text(format!(
                                "{} Registration",
                                room.title.as_deref().unwrap_or(&room.localpart)
                            )))
                            .child(
                                XmlElement::new("instructions")
                                    .text("Choose the nickname to reserve in this room."),
                            )
                            .child(super::muc::muc_xdata_value_field(
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
            return Ok(Some(federated_iq_result(
                &request.stanza,
                &room_jid,
                &actor_full_jid,
                &payload,
            )));
        }
        let action = match parse_federated_registration_action(&request.stanza.raw) {
            Ok(action) => action,
            Err(condition) => {
                return Ok(federated_error(&request.stanza, from, "modify", condition));
            }
        };
        let local_registration_guard = if state.cluster.is_enabled() {
            None
        } else {
            Some(state.muc_service().lock_local_room_mutation(room.id).await)
        };
        let room = if local_registration_guard.is_some() {
            let Some(refreshed_room) = state
                .muc_service()
                .federated_room_snapshot(localpart(&room_jid))
                .await?
            else {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            };
            if refreshed_room.room_epoch != room.room_epoch {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            if !refreshed_room.allow_registration {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "not-allowed",
                ));
            }
            refreshed_room
        } else {
            room
        };
        let (affiliation_changed, previous_affiliation, affiliation, notice_nick) = match action {
            FederatedRegistrationAction::Remove => {
                if state.cluster.is_enabled() {
                    state
                        .cluster
                        .admit(crate::cluster::ClusterOperation::MucMutation)?;
                    let operation_id = uuid::Uuid::new_v4();
                    let outcome = state
                        .muc_service()
                        .mutate_local_cluster_registration(
                            operation_id,
                            room.id,
                            room.room_epoch,
                            room.config_version,
                            &ClusterMucPrincipal::Federated {
                                bare_jid: actor_bare_jid.clone(),
                                authenticated_domain: authenticated_domain.to_owned(),
                            },
                            &actor_full_jid,
                            None,
                        )
                        .await?;
                    return match outcome {
                        ClusterMucRegistrationOutcome::Applied { .. }
                        | ClusterMucRegistrationOutcome::Replay { .. } => {
                            state
                                .muc_service()
                                .wake_committed_operation(&state.cluster, operation_id)
                                .await?;
                            Ok(Some(federated_iq_result(
                                &request.stanza,
                                &room_jid,
                                &actor_full_jid,
                                "",
                            )))
                        }
                        ClusterMucRegistrationOutcome::Conflict => {
                            Ok(federated_error(&request.stanza, from, "cancel", "conflict"))
                        }
                        ClusterMucRegistrationOutcome::Outcast
                        | ClusterMucRegistrationOutcome::NotAllowed => {
                            Ok(federated_error(&request.stanza, from, "auth", "forbidden"))
                        }
                        ClusterMucRegistrationOutcome::Stale
                        | ClusterMucRegistrationOutcome::Destroyed => Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )),
                    };
                }
                let changed = state
                    .muc_service()
                    .unregister_federated_member(room.id, &actor_bare_jid)
                    .await?;
                (changed, "member", "none", None)
            }
            FederatedRegistrationAction::Register(nick) => {
                if state.cluster.is_enabled() {
                    state
                        .cluster
                        .admit(crate::cluster::ClusterOperation::MucMutation)?;
                    let operation_id = uuid::Uuid::new_v4();
                    let outcome = state
                        .muc_service()
                        .mutate_local_cluster_registration(
                            operation_id,
                            room.id,
                            room.room_epoch,
                            room.config_version,
                            &ClusterMucPrincipal::Federated {
                                bare_jid: actor_bare_jid.clone(),
                                authenticated_domain: authenticated_domain.to_owned(),
                            },
                            &actor_full_jid,
                            Some(&nick),
                        )
                        .await?;
                    return match outcome {
                        ClusterMucRegistrationOutcome::Applied { .. }
                        | ClusterMucRegistrationOutcome::Replay { .. } => {
                            state
                                .muc_service()
                                .wake_committed_operation(&state.cluster, operation_id)
                                .await?;
                            Ok(Some(federated_iq_result(
                                &request.stanza,
                                &room_jid,
                                &actor_full_jid,
                                "",
                            )))
                        }
                        ClusterMucRegistrationOutcome::Conflict => {
                            Ok(federated_error(&request.stanza, from, "cancel", "conflict"))
                        }
                        ClusterMucRegistrationOutcome::Outcast
                        | ClusterMucRegistrationOutcome::NotAllowed => {
                            Ok(federated_error(&request.stanza, from, "auth", "forbidden"))
                        }
                        ClusterMucRegistrationOutcome::Stale
                        | ClusterMucRegistrationOutcome::Destroyed => Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        )),
                    };
                }
                let mut occupants = state.cluster.get_muc_occupants(&room_jid).await?;
                for (_, occupant) in state.muc_occupants_for(&room_jid) {
                    occupants.insert(
                        occupant.nick.clone(),
                        serde_json::to_string(&SerializableMucOccupant::from(&occupant))?,
                    );
                }
                if occupants.get(&nick).is_some_and(|json| {
                    serde_json::from_str::<SerializableMucOccupant>(json)
                        .ok()
                        .is_some_and(|occupant| {
                            crate::jid::canonical_bare_key(&occupant.full_jid)
                                .ok()
                                .as_deref()
                                != Some(actor_bare_jid.as_str())
                        })
                }) {
                    return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                }
                let changed = match state
                    .muc_service()
                    .register_federated_member(room.id, &actor_bare_jid, &nick)
                    .await?
                {
                    MucRegistrationOutcome::Registered {
                        affiliation_changed,
                    } => affiliation_changed,
                    MucRegistrationOutcome::Conflict => {
                        return Ok(federated_error(&request.stanza, from, "cancel", "conflict"));
                    }
                    MucRegistrationOutcome::Outcast => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                };
                (changed, "none", "member", Some(nick))
            }
        };
        let joined = state
            .muc_occupants_for(&room_jid)
            .into_iter()
            .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
        let target_is_occupant = joined.is_some();
        if let Some((key, own)) = joined {
            let affiliation = state
                .muc_service()
                .federated_affiliation(room.id, &actor_bare_jid)
                .await?
                .unwrap_or_else(|| "none".to_owned());
            publish_occupant_change(
                state,
                &room,
                &own,
                &key,
                own.clone(),
                OccupantChange {
                    affiliation: Some(&affiliation),
                    role: None,
                    reason: None,
                },
            )
            .await?;
        }
        drop(local_registration_guard);
        if affiliation_changed
            && super::muc::should_broadcast_offline_affiliation_change(
                room.non_anonymous,
                target_is_occupant,
                previous_affiliation,
                affiliation,
            )
        {
            super::muc::deliver_muc_offline_affiliation_change_notice(
                state,
                &room_jid,
                &actor_bare_jid,
                affiliation,
                notice_nick.as_deref(),
                None,
            )
            .await;
        }
        return Ok(Some(federated_iq_result(
            &request.stanza,
            &room_jid,
            &actor_full_jid,
            "",
        )));
    }

    if matches!(
        &request.payload,
        FederatedIqPayload::MamForm
            | FederatedIqPayload::MamQuery(_)
            | FederatedIqPayload::MamMetadata
            | FederatedIqPayload::MamError(_)
    ) {
        let joined = state
            .muc_occupants_for(&room_jid)
            .iter()
            .any(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid));
        return match &request.payload {
            FederatedIqPayload::MamForm => match state
                .mam_service()
                .authorize_federated_room(&room.localpart, &actor_bare_jid, joined)
                .await?
            {
                crate::services::mam::MamRoomAccessOutcome::Allowed(_) => {
                    Ok(Some(federated_iq_result(
                        &request.stanza,
                        &room_jid,
                        &actor_full_jid,
                        mam_extended_form(),
                    )))
                }
                crate::services::mam::MamRoomAccessOutcome::Missing => Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                )),
                crate::services::mam::MamRoomAccessOutcome::Forbidden => {
                    Ok(federated_error(&request.stanza, from, "auth", "forbidden"))
                }
            },
            FederatedIqPayload::MamMetadata => {
                let (access, (first, last)) = match state
                    .mam_service()
                    .authorized_federated_room_boundaries(&room.localpart, &actor_bare_jid, joined)
                    .await?
                {
                    crate::services::mam::MamRoomReadOutcome::Allowed { access, value } => {
                        (access, value)
                    }
                    crate::services::mam::MamRoomReadOutcome::Missing => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                    crate::services::mam::MamRoomReadOutcome::Forbidden => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                };
                debug_assert_eq!(access.localpart(), room.localpart);
                let mut metadata = XmlElement::namespaced("metadata", "urn:xmpp:mam:2");
                if let Some(value) = first {
                    metadata.push_child(
                        XmlElement::new("start").attr("id", value.id).attr(
                            "timestamp",
                            value
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                if let Some(value) = last {
                    metadata.push_child(
                        XmlElement::new("end").attr("id", value.id).attr(
                            "timestamp",
                            value
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                Ok(Some(federated_iq_result(
                    &request.stanza,
                    &room_jid,
                    &actor_full_jid,
                    &metadata.finish(),
                )))
            }
            FederatedIqPayload::MamError(condition) => {
                match state
                    .mam_service()
                    .authorize_federated_room(&room.localpart, &actor_bare_jid, joined)
                    .await?
                {
                    crate::services::mam::MamRoomAccessOutcome::Allowed(_) => {}
                    crate::services::mam::MamRoomAccessOutcome::Missing => {
                        return Ok(federated_error(
                            &request.stanza,
                            from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                    crate::services::mam::MamRoomAccessOutcome::Forbidden => {
                        return Ok(federated_error(&request.stanza, from, "auth", "forbidden"));
                    }
                }
                let error_type = if *condition == "resource-constraint" {
                    "wait"
                } else if matches!(*condition, "bad-request" | "jid-malformed") {
                    "modify"
                } else {
                    "cancel"
                };
                Ok(federated_error(
                    &request.stanza,
                    from,
                    error_type,
                    condition,
                ))
            }
            FederatedIqPayload::MamQuery(query) => {
                federated_muc_mam(
                    state,
                    authenticated_domain,
                    &request.stanza,
                    (&room.localpart, &actor_bare_jid, joined),
                    (&room_jid, &actor_full_jid),
                    query.clone(),
                )
                .await
            }
            _ => unreachable!(),
        };
    }

    let Some((_, own)) = state
        .muc_occupants_for(&room_jid)
        .into_iter()
        .find(|(_, occupant)| same_remote_actor(&occupant.full_jid, &actor_full_jid))
    else {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    };
    if !federated_endpoint_matches(&own, authenticated_domain) {
        return Ok(federated_error(
            &request.stanza,
            from,
            "auth",
            "not-authorized",
        ));
    }
    // An IQ does not refresh occupancy ownership. Presence is the sole path
    // which can rebind a federated endpoint after exact authority checks.

    if to.contains('/') {
        let Some(target_nick) = to_jid.resourcepart() else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "modify",
                "jid-malformed",
            ));
        };
        let target_key = muc_occupant_key(&room_jid, target_nick);
        let Some(target) = state
            .muc_occupants
            .get(&target_key)
            .map(|entry| entry.value().clone())
        else {
            return Ok(federated_error(
                &request.stanza,
                from,
                "cancel",
                "item-not-found",
            ));
        };
        let forwarded = set_to(
            &set_from(&request.stanza.raw, &format!("{room_jid}/{}", own.nick)),
            &target.full_jid,
        );
        let blocked = state
            .blocked_muc_recipient_accounts(
                std::slice::from_ref(&target),
                &[format!("{room_jid}/{}", own.nick), actor_full_jid.clone()],
            )
            .await;
        if !crate::jid::canonical_bare_key(&target.full_jid)
            .is_ok_and(|owner| blocked.contains(&owner))
        {
            let _ = state
                .deliver_to_muc_occupant_unchecked(&target, forwarded)
                .await;
        }
        return Ok(None);
    }

    match request.payload {
        FederatedIqPayload::DiscoItems(disco) if disco.node.is_none() => {
            let mut occupant_map = state
                .cluster
                .get_muc_occupants(&room_jid)
                .await?
                .into_values()
                .filter_map(|json| serde_json::from_str::<SerializableMucOccupant>(&json).ok())
                .map(|occupant| (occupant.nick.clone(), occupant))
                .collect::<std::collections::HashMap<_, _>>();
            for (_, occupant) in state.muc_occupants_for(&room_jid) {
                let occupant = SerializableMucOccupant::from(&occupant);
                occupant_map.insert(occupant.nick.clone(), occupant);
            }
            let mut occupants = occupant_map.into_values().collect::<Vec<_>>();
            occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
            let cursor = disco
                .after
                .as_deref()
                .or_else(|| disco.before.as_ref().and_then(|value| value.as_deref()));
            if cursor.is_some_and(|cursor| !occupants.iter().any(|item| item.nick == cursor)) {
                return Ok(federated_error(
                    &request.stanza,
                    from,
                    "cancel",
                    "item-not-found",
                ));
            }
            let total = occupants.len() as i64;
            let mut page = occupants
                .iter()
                .filter(|occupant| {
                    disco
                        .after
                        .as_deref()
                        .is_none_or(|after| occupant.nick.as_str() > after)
                        && disco
                            .before
                            .as_ref()
                            .and_then(|value| value.as_deref())
                            .is_none_or(|before| occupant.nick.as_str() < before)
                })
                .cloned()
                .collect::<Vec<_>>();
            if disco.before.is_some() {
                page.reverse();
            }
            page.truncate(disco.max.clamp(0, 100) as usize);
            if disco.before.is_some() {
                page.reverse();
            }
            let first_index = page
                .first()
                .and_then(|first| occupants.iter().position(|item| item.nick == first.nick))
                .map_or(0, |index| index as i64);
            let mut payload =
                XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
            for occupant in &page {
                payload.push_child(
                    XmlElement::new("item").attr("jid", format!("{}/{}", room_jid, occupant.nick)),
                );
            }
            payload.push_validated_fragment(&super::discovery::disco_rsm_result(
                page.first().map(|occupant| occupant.nick.as_str()),
                page.last().map(|occupant| occupant.nick.as_str()),
                first_index,
                total,
            ))?;
            let payload = payload.finish();
            Ok(Some(federated_iq_result(
                &request.stanza,
                &room_jid,
                &actor_full_jid,
                &payload,
            )))
        }
        FederatedIqPayload::DiscoItemsError(condition) => {
            Ok(federated_error(&request.stanza, from, "modify", condition))
        }
        FederatedIqPayload::AdminGet { affiliation, role } => {
            federated_muc_admin_get(state, &request.stanza, &room, &own, affiliation, role).await
        }
        FederatedIqPayload::OwnerGet => {
            federated_muc_owner(state, &request.stanza, &room, &own, false).await
        }
        FederatedIqPayload::OwnerSet => {
            federated_muc_owner(state, &request.stanza, &room, &own, true).await
        }
        FederatedIqPayload::AdminSet { items } => {
            federated_muc_admin_set(state, &request.stanza, &room, &own, items).await
        }
        FederatedIqPayload::AdminError(condition) => {
            Ok(federated_error(&request.stanza, from, "modify", condition))
        }
        FederatedIqPayload::Moderate {
            target,
            reason,
            has_retract,
        } => {
            federated_muc_moderate(
                state,
                &request.stanza,
                &room,
                &own,
                target,
                reason,
                has_retract,
            )
            .await
        }
        _ => Ok(federated_error(
            &request.stanza,
            from,
            "cancel",
            "feature-not-implemented",
        )),
    }
}

async fn federated_muc_mam(
    state: &AppState,
    authenticated_domain: &str,
    stanza: &FederatedStanza,
    authorization: (&str, &str, bool),
    delivery: (&str, &str),
    query: FederatedMamQuery,
) -> Result<Option<String>> {
    let (room_localpart, actor_bare_jid, joined) = authorization;
    let (room_jid, recipient) = delivery;
    let flip_page = query.flip_page;
    let query_id = query.query_id.clone();
    let outcome = state
        .mam_service()
        .admit_federated_room_stream(
            &state.federation,
            crate::services::mam::FederatedMamStreamRequest::new(
                authenticated_domain,
                room_localpart,
                actor_bare_jid,
                joined,
                &query.query,
            ),
            |page| {
                let access = page.access();
                let rows: Box<dyn Iterator<Item = _>> = if flip_page {
                    Box::new(page.rows().iter().rev())
                } else {
                    Box::new(page.rows().iter())
                };
                let mut responses = Vec::with_capacity(page.rows().len() + 1);
                for item in rows {
                    let occupant_id = muc_occupant_id(access.occupant_id_secret(), item.peer_jid());
                    let authoritative = set_muc_occupant_id(item.stanza(), &occupant_id);
                    let archived = if access.reveal_real_jid() {
                        add_muc_sender(&authoritative, item.peer_jid())
                    } else {
                        authoritative
                    };
                    let forwarded = XmlElement::namespaced("forwarded", "urn:xmpp:forward:0")
                        .child(
                            XmlElement::namespaced("delay", "urn:xmpp:delay").attr(
                                "stamp",
                                item.created_at()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                            ),
                        )
                        .validated_fragment(&archived)?;
                    let result = XmlElement::namespaced("result", "urn:xmpp:mam:2")
                        .attr("id", item.id())
                        .optional_attr("queryid", query_id.as_deref())
                        .child(forwarded);
                    responses.push(
                        XmlElement::namespaced("message", "jabber:client")
                            .attr("from", room_jid)
                            .attr("to", recipient)
                            .attr("id", uuid::Uuid::new_v4())
                            .child(result)
                            .finish(),
                    );
                }
                let mut rsm = XmlElement::namespaced("set", "http://jabber.org/protocol/rsm");
                if let (Some(first), Some(last)) = (page.rows().first(), page.rows().last()) {
                    rsm.push_child(
                        XmlElement::new("first")
                            .attr("index", page.first_index())
                            .text(first.id().to_string()),
                    );
                    rsm.push_child(XmlElement::new("last").text(last.id().to_string()));
                }
                rsm.push_child(XmlElement::new("count").text(page.total().to_string()));
                let fin = XmlElement::namespaced("fin", "urn:xmpp:mam:2")
                    .attr("complete", page.complete())
                    .attr("stable", "true")
                    .child(rsm)
                    .finish();
                responses.push(federated_iq_result(stanza, room_jid, recipient, &fin));
                Ok(responses)
            },
        )
        .await?;
    match outcome {
        crate::services::mam::FederatedMamAdmissionOutcome::Queued => Ok(None),
        crate::services::mam::FederatedMamAdmissionOutcome::Missing
        | crate::services::mam::FederatedMamAdmissionOutcome::PageMissing => Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        )),
        crate::services::mam::FederatedMamAdmissionOutcome::Forbidden => {
            Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"))
        }
        crate::services::mam::FederatedMamAdmissionOutcome::OutboxRejected => Ok(federated_error(
            stanza,
            &stanza.from,
            "wait",
            "remote-server-timeout",
        )),
    }
}

#[derive(Debug)]
struct FederatedRoomConfig {
    title: Option<String>,
    description: Option<String>,
    persistent: bool,
    members_only: bool,
    public: bool,
    moderated: bool,
    non_anonymous: bool,
    max_occupants: i32,
    password_secret: Option<String>,
    keep_password_hash: bool,
    allow_subject_change: bool,
    allow_invites: bool,
    allow_private_messages: bool,
    logging_enabled: bool,
    allow_registration: bool,
}

enum FederatedOwnerAction {
    Cancel,
    Destroy {
        alternate: Option<String>,
        reason: Option<String>,
    },
    Configure(FederatedRoomConfig),
}

enum FederatedRegistrationAction {
    Remove,
    Register(String),
}

fn parse_federated_registration_action(
    raw: &str,
) -> std::result::Result<FederatedRegistrationAction, &'static str> {
    let document = roxmltree::Document::parse(raw).map_err(|_| "bad-request")?;
    let query = document
        .root_element()
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "query"
                && node.tag_name().namespace() == Some("jabber:iq:register")
        })
        .ok_or("bad-request")?;
    let elements = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if elements.len() == 1
        && elements[0].tag_name().name() == "remove"
        && elements[0].tag_name().namespace() == Some("jabber:iq:register")
        && !elements[0].children().any(|node| node.is_element())
    {
        return Ok(FederatedRegistrationAction::Remove);
    }
    if elements.len() != 1
        || elements[0].tag_name().name() != "x"
        || elements[0].tag_name().namespace() != Some("jabber:x:data")
        || elements[0].attribute("type") != Some("submit")
        || xdata_field(elements[0], "FORM_TYPE") != Some("http://jabber.org/protocol/muc#register")
    {
        return Err("bad-request");
    }
    let nick = xdata_field(elements[0], "muc#register_roomnick").ok_or("bad-request")?;
    let nick = prepare_muc_nick(nick).map_err(|_| "not-acceptable")?;
    Ok(FederatedRegistrationAction::Register(nick))
}

fn federated_owner_form(room: &MucRoom) -> String {
    super::muc::muc_room_configuration_form(
        room,
        if room.non_anonymous {
            "anyone"
        } else {
            "moderators"
        },
    )
}

fn parse_federated_owner_action(
    raw: &str,
    room: &MucRoom,
) -> std::result::Result<FederatedOwnerAction, &'static str> {
    let document = roxmltree::Document::parse(raw).map_err(|_| "bad-request")?;
    let root = document.root_element();
    let query = root
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "query"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#owner")
        })
        .ok_or("bad-request")?;
    let children = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if children.len() != 1 {
        return Err("bad-request");
    }
    let child = children[0];
    if child.tag_name().name() == "destroy"
        && child.tag_name().namespace() == Some("http://jabber.org/protocol/muc#owner")
    {
        if child
            .children()
            .filter(|node| node.is_element())
            .any(|node| {
                node.tag_name().name() != "reason"
                    || node.tag_name().namespace() != Some("http://jabber.org/protocol/muc#owner")
            })
        {
            return Err("bad-request");
        }
        let alternate = child
            .attribute("jid")
            .map(crate::jid::canonicalize_bare)
            .transpose()
            .map_err(|_| "jid-malformed")?;
        let reason = child_text(child, "reason").map(str::to_owned);
        if reason.as_ref().is_some_and(|value| value.len() > 4096) {
            return Err("not-acceptable");
        }
        return Ok(FederatedOwnerAction::Destroy { alternate, reason });
    }
    if child.tag_name().name() != "x" || child.tag_name().namespace() != Some("jabber:x:data") {
        return Err("bad-request");
    }
    if child.attribute("type") == Some("cancel") {
        return Ok(FederatedOwnerAction::Cancel);
    }
    if !matches!(child.attribute("type"), None | Some("submit"))
        || xdata_field(child, "FORM_TYPE")
            .is_some_and(|value| value != "http://jabber.org/protocol/muc#roomconfig")
    {
        return Err("bad-request");
    }
    let title = xdata_field(child, "muc#roomconfig_roomname")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| room.title.clone())
        .or_else(|| Some(room.localpart.clone()));
    if title.as_ref().is_some_and(|value| value.len() > 255) {
        return Err("not-acceptable");
    }
    let description = xdata_field(child, "muc#roomconfig_roomdesc")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| room.description.clone());
    if description.as_ref().is_some_and(|value| value.len() > 4096) {
        return Err("not-acceptable");
    }
    let read_bool = |name, fallback| {
        xdata_bool(child, name)
            .map(|value| value.unwrap_or(fallback))
            .map_err(|()| "bad-request")
    };
    let persistent = read_bool("muc#roomconfig_persistentroom", room.persistent)?;
    let members_only = read_bool("muc#roomconfig_membersonly", room.members_only)?;
    let public = read_bool("muc#roomconfig_publicroom", room.public)?;
    let moderated = read_bool("muc#roomconfig_moderatedroom", room.moderated)?;
    let allow_subject_change =
        read_bool("muc#roomconfig_changesubject", room.allow_subject_change)?;
    let allow_invites = read_bool("muc#roomconfig_allowinvites", room.allow_invites)?;
    let logging_enabled = read_bool("muc#roomconfig_enablelogging", room.logging_enabled)?;
    let allow_registration = read_bool("muc#roomconfig_allowregister", room.allow_registration)?;
    let non_anonymous = match xdata_field(child, "muc#roomconfig_whois") {
        None => room.non_anonymous,
        Some("anyone") => true,
        Some("moderators") => false,
        Some(_) => return Err("bad-request"),
    };
    let allow_private_messages = match xdata_field(child, "muc#roomconfig_allowpm") {
        None => room.allow_private_messages,
        Some("anyone") => true,
        Some("none") => false,
        Some(_) => return Err("bad-request"),
    };
    let max_occupants = match xdata_field(child, "muc#roomconfig_maxusers") {
        None => room.max_occupants,
        Some(value) => value
            .parse::<i32>()
            .ok()
            .filter(|value| (2..=1000).contains(value))
            .ok_or("not-acceptable")?,
    };
    let password_protected = read_bool(
        "muc#roomconfig_passwordprotectedroom",
        room.password_hash.is_some(),
    )?;
    let password_secret = xdata_field(child, "muc#roomconfig_roomsecret")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if password_protected && password_secret.is_none() && room.password_hash.is_none() {
        return Err("bad-request");
    }
    Ok(FederatedOwnerAction::Configure(FederatedRoomConfig {
        title,
        description,
        persistent,
        members_only,
        public,
        moderated,
        non_anonymous,
        max_occupants,
        password_secret,
        keep_password_hash: password_protected && room.password_hash.is_some(),
        allow_subject_change,
        allow_invites,
        allow_private_messages,
        logging_enabled,
        allow_registration,
    }))
}

async fn federated_muc_owner(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    requester: &MucOccupant,
    set: bool,
) -> Result<Option<String>> {
    let mut guarded_room = None;
    let mut guarded_requester = None;
    let _local_room_guard = if set && !state.cluster.is_enabled() {
        let guard = state.muc_service().lock_local_room_mutation(room.id).await;
        let Some(refreshed_room) = state
            .muc_service()
            .federated_room_snapshot(&room.localpart)
            .await?
        else {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        };
        if refreshed_room.room_epoch != room.room_epoch {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        }
        let Some(mut current_requester) = state
            .muc_occupants_for(&requester.room_jid)
            .into_iter()
            .map(|(_, occupant)| occupant)
            .find(|occupant| {
                occupant.full_jid == requester.full_jid
                    && occupant.connection_id == requester.connection_id
                    && occupant.cluster_epoch == requester.cluster_epoch
            })
        else {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        };
        current_requester.affiliation = state
            .muc_service()
            .federated_affiliation(refreshed_room.id, bare_jid(&current_requester.full_jid))
            .await?
            .unwrap_or_else(|| "none".to_owned());
        guarded_room = Some(refreshed_room);
        guarded_requester = Some(current_requester);
        Some(guard)
    } else {
        None
    };
    let room = guarded_room.as_ref().unwrap_or(room);
    let requester = guarded_requester.as_ref().unwrap_or(requester);
    if requester.affiliation != "owner" {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if room.configuration_is_expired(chrono::Utc::now()) {
        let _ = state
            .muc_service()
            .delete_expired_locked_room(room.id)
            .await?;
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    }
    if room.is_locked() && !room.can_configure_locked_room(&requester.full_jid, chrono::Utc::now())
    {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if !set {
        return Ok(Some(federated_iq_result(
            stanza,
            &requester.room_jid,
            &requester.full_jid,
            &federated_owner_form(room),
        )));
    }
    let action = match parse_federated_owner_action(&stanza.raw, room) {
        Ok(action) => action,
        Err(condition) => {
            return Ok(federated_error(stanza, &stanza.from, "modify", condition));
        }
    };
    match action {
        FederatedOwnerAction::Cancel => {
            if room.is_locked() {
                state
                    .muc_service()
                    .cancel_locked_room(room.id, &requester.full_jid)
                    .await?;
                for (key, occupant) in state.muc_occupants_for(&requester.room_jid) {
                    let serializable = SerializableMucOccupant::from(&occupant);
                    state.remove_live_muc_membership(&serializable);
                    state.muc_occupants.remove_if(&key, |_, current| {
                        current.cluster_epoch == occupant.cluster_epoch
                            && current.connection_id == occupant.connection_id
                    });
                    if !state.cluster.is_enabled() {
                        let unavailable = muc_destroy_presence(&serializable, None, None);
                        let _ = state.deliver_to_muc_occupant(&occupant, unavailable).await;
                    }
                }
            }
        }
        FederatedOwnerAction::Destroy { alternate, reason } => {
            let mut cluster_operation = None;
            if state.cluster.is_enabled() {
                state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                let Some(actor_target) = state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        requester.cluster_epoch,
                        requester.connection_id,
                    )
                    .await?
                else {
                    return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                };
                let operation_id = uuid::Uuid::new_v4();
                match state
                    .muc_service()
                    .destroy_local_cluster_room(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        Some(&actor_target),
                        "federated_verified",
                        Some(&requester.full_jid),
                        alternate.as_deref(),
                        reason.as_deref(),
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_operation = Some(operation_id)
                    }
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Conflict => {
                        return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
                    }
                }
            } else {
                state.muc_service().delete_room(room.id).await?;
            }
            for (key, occupant) in state.muc_occupants_for(&requester.room_jid) {
                let serializable = SerializableMucOccupant::from(&occupant);
                state.remove_live_muc_membership(&serializable);
                state.muc_occupants.remove_if(&key, |_, current| {
                    current.cluster_epoch == occupant.cluster_epoch
                        && current.connection_id == occupant.connection_id
                });
                if cluster_operation.is_none() {
                    let unavailable = muc_destroy_presence(
                        &serializable,
                        alternate.as_deref(),
                        reason.as_deref(),
                    );
                    let _ = state.deliver_to_muc_occupant(&occupant, unavailable).await;
                }
            }
            if let Some(operation_id) = cluster_operation {
                if let Err(error) = state
                    .muc_service()
                    .wake_committed_operation(&state.cluster, operation_id)
                    .await
                {
                    tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                        "federated MUC destroy committed; signed wake will be recovered by polling");
                }
            }
        }
        FederatedOwnerAction::Configure(config) => {
            let replacement_password_hash = if let Some(secret) = config.password_secret {
                let secret = zeroize::Zeroizing::new(secret);
                match crate::password_work::run(move || {
                    crate::services::muc::MucService::hash_room_password(&secret)
                })
                .await
                {
                    Ok(hash) => Some(hash),
                    Err(error) if error.is_overloaded() => {
                        return Ok(federated_error(
                            stanza,
                            &stanza.from,
                            "wait",
                            "resource-constraint",
                        ));
                    }
                    Err(error) => {
                        return Err(anyhow::anyhow!("room password hashing failed: {error}"));
                    }
                }
            } else if config.keep_password_hash {
                room.password_hash.clone()
            } else {
                None
            };
            let mut cluster_operation = None;
            let outcome = if state.cluster.is_enabled() {
                state
                    .cluster
                    .admit(crate::cluster::ClusterOperation::MucMutation)?;
                let authenticated_domain = match &requester.endpoint {
                    crate::state::MucOccupantEndpoint::Federated {
                        authenticated_domain,
                        ..
                    } => authenticated_domain.clone(),
                    _ => anyhow::bail!("federated MUC owner lost its S2S domain proof"),
                };
                let Some(actor_target) = state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        requester.cluster_epoch,
                        requester.connection_id,
                    )
                    .await?
                else {
                    return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                };
                let operation_id = uuid::Uuid::new_v4();
                let clustered = state
                    .muc_service()
                    .update_local_cluster_config(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        room.config_version,
                        &actor_target,
                        &ClusterMucPrincipal::Federated {
                            bare_jid: bare_jid(&requester.full_jid).to_owned(),
                            authenticated_domain,
                        },
                        &requester.full_jid,
                        MucConfigUpdate {
                            title: config.title.as_deref(),
                            description: config.description.as_deref(),
                            persistent: config.persistent,
                            members_only: config.members_only,
                            public: config.public,
                            moderated: config.moderated,
                            non_anonymous: config.non_anonymous,
                            max_occupants: config.max_occupants,
                            password_hash: replacement_password_hash.as_deref(),
                            allow_subject_change: config.allow_subject_change,
                            allow_invites: config.allow_invites,
                            allow_private_messages: config.allow_private_messages,
                            logging_enabled: config.logging_enabled,
                            allow_registration: config.allow_registration,
                        },
                    )
                    .await?;
                cluster_operation = Some(operation_id);
                match clustered {
                    ClusterMucConfigurationOutcome::Applied
                    | ClusterMucConfigurationOutcome::Replay => MucConfigurationOutcome::Applied,
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
                state
                    .muc_service()
                    .update_local_legacy_config(
                        room.id,
                        &requester.full_jid,
                        MucConfigUpdate {
                            title: config.title.as_deref(),
                            description: config.description.as_deref(),
                            persistent: config.persistent,
                            members_only: config.members_only,
                            public: config.public,
                            moderated: config.moderated,
                            non_anonymous: config.non_anonymous,
                            max_occupants: config.max_occupants,
                            password_hash: replacement_password_hash.as_deref(),
                            allow_subject_change: config.allow_subject_change,
                            allow_invites: config.allow_invites,
                            allow_private_messages: config.allow_private_messages,
                            logging_enabled: config.logging_enabled,
                            allow_registration: config.allow_registration,
                        },
                    )
                    .await?
            };
            if outcome != MucConfigurationOutcome::Applied {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    if outcome == MucConfigurationOutcome::LockedByAnother {
                        "auth"
                    } else {
                        "cancel"
                    },
                    if outcome == MucConfigurationOutcome::LockedByAnother {
                        "forbidden"
                    } else {
                        "item-not-found"
                    },
                ));
            }
            if let Some(operation_id) = cluster_operation {
                if let Err(error) = state
                    .muc_service()
                    .wake_committed_operation(&state.cluster, operation_id)
                    .await
                {
                    tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                        "federated MUC config committed; signed wake will be recovered by polling");
                }
                return Ok(Some(federated_iq_result(
                    stanza,
                    &requester.room_jid,
                    &requester.full_jid,
                    "",
                )));
            }
            let updated_room = state
                .muc_service()
                .federated_room_snapshot(&room.localpart)
                .await?
                .ok_or_else(|| anyhow::anyhow!("configured MUC room disappeared"))?;
            if state.cluster.is_enabled()
                && ((updated_room.members_only && !room.members_only)
                    || updated_room.moderated != room.moderated
                    || updated_room.non_anonymous != room.non_anonymous)
            {
                let global = state.cluster.get_muc_occupants(&requester.room_jid).await?;
                for (nick, raw) in global {
                    let Ok(mut occupant) =
                        serde_json::from_str::<crate::state::SerializableMucOccupant>(&raw)
                    else {
                        continue;
                    };
                    if occupant.room_jid != requester.room_jid
                        || occupant.nick != nick
                        || occupant.cluster_epoch.is_nil()
                        || occupant.connection_id.is_nil()
                    {
                        continue;
                    }
                    let key = muc_occupant_key(&requester.room_jid, &nick);
                    let locally_owned = state.muc_occupants.get(&key).is_some_and(|local| {
                        local.full_jid == occupant.full_jid
                            && local.cluster_epoch == occupant.cluster_epoch
                            && local.connection_id == occupant.connection_id
                    });
                    if locally_owned {
                        continue;
                    }
                    if updated_room.members_only
                        && !room.members_only
                        && occupant.affiliation == "none"
                    {
                        occupant.role = "none".to_owned();
                        if state
                            .cluster
                            .evict_muc_occupant(&occupant, 322, Some(&requester.nick), None)
                            .await?
                        {
                            state
                                .cluster
                                .send_muc_presence_with_status(
                                    &requester.room_jid,
                                    &occupant,
                                    true,
                                    false,
                                    None,
                                    Some(322),
                                    Some(&requester.nick),
                                    None,
                                )
                                .await?;
                        }
                        continue;
                    }
                    let desired_role = if matches!(occupant.affiliation.as_str(), "owner" | "admin")
                    {
                        "moderator"
                    } else if updated_room.moderated && occupant.affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    };
                    if occupant.role != desired_role
                        || occupant.room_non_anonymous != updated_room.non_anonymous
                    {
                        let _ = state
                            .cluster
                            .change_muc_occupant_policy(
                                &requester.room_jid,
                                &occupant,
                                desired_role,
                                updated_room.non_anonymous,
                            )
                            .await?;
                    }
                }
            }
            for (key, mut occupant) in state.muc_occupants_for(&requester.room_jid) {
                if updated_room.members_only && !room.members_only && occupant.affiliation == "none"
                {
                    publish_occupant_change(
                        state,
                        &updated_room,
                        requester,
                        &key,
                        occupant,
                        OccupantChange {
                            affiliation: None,
                            role: Some("none"),
                            reason: None,
                        },
                    )
                    .await?;
                    continue;
                }
                let desired_role = if matches!(occupant.affiliation.as_str(), "owner" | "admin") {
                    "moderator"
                } else if updated_room.moderated && occupant.affiliation == "none" {
                    "visitor"
                } else {
                    "participant"
                };
                let visibility_changed = occupant.room_non_anonymous != updated_room.non_anonymous;
                occupant.room_non_anonymous = updated_room.non_anonymous;
                if occupant.role != desired_role || visibility_changed {
                    publish_occupant_change(
                        state,
                        &updated_room,
                        requester,
                        &key,
                        occupant,
                        OccupantChange {
                            affiliation: None,
                            role: Some(desired_role),
                            reason: None,
                        },
                    )
                    .await?;
                }
            }
            let mut statuses = vec!["104"];
            if config.logging_enabled != room.logging_enabled {
                statuses.push(if config.logging_enabled { "170" } else { "171" });
            }
            if config.non_anonymous != room.non_anonymous {
                statuses.push(if config.non_anonymous { "172" } else { "173" });
            }
            for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                let mut extension =
                    XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user");
                for code in &statuses {
                    extension.push_child(XmlElement::new("status").attr("code", code));
                }
                let notice = XmlElement::namespaced("message", "jabber:client")
                    .attr("from", &requester.room_jid)
                    .attr("to", &recipient.full_jid)
                    .attr("type", "groupchat")
                    .child(extension)
                    .finish();
                let _ = state.deliver_to_muc_occupant(&recipient, notice).await;
            }
        }
    }
    Ok(Some(federated_iq_result(
        stanza,
        &requester.room_jid,
        &requester.full_jid,
        "",
    )))
}

async fn federated_muc_admin_get(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    requester: &MucOccupant,
    requested_affiliation: Option<String>,
    requested_role: Option<String>,
) -> Result<Option<String>> {
    if requested_affiliation.is_some() == requested_role.is_some() {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    if let Some(requested) = requested_role {
        if !matches!(requested.as_str(), "moderator" | "participant" | "visitor") {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "bad-request",
            ));
        }
        if requester.role != "moderator"
            && !matches!(requester.affiliation.as_str(), "owner" | "admin")
        {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        }
        let mut occupant_map = state
            .cluster
            .get_muc_occupants(&requester.room_jid)
            .await?
            .into_values()
            .filter_map(|json| serde_json::from_str::<SerializableMucOccupant>(&json).ok())
            .map(|occupant| (occupant.nick.clone(), occupant))
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in state.muc_occupants_for(&requester.room_jid) {
            let occupant = SerializableMucOccupant::from(&occupant);
            occupant_map.insert(occupant.nick.clone(), occupant);
        }
        let mut occupants = occupant_map
            .into_values()
            .filter(|occupant| occupant.role == requested)
            .collect::<Vec<_>>();
        occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
        let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
        for occupant in occupants {
            payload.push_child(
                XmlElement::new("item")
                    .attr("nick", &occupant.nick)
                    .attr("role", &requested)
                    .optional_attr(
                        "jid",
                        (room.non_anonymous || requester.role == "moderator")
                            .then(|| bare_jid(&occupant.full_jid)),
                    ),
            );
        }
        let payload = payload.finish();
        return Ok(Some(federated_iq_result(
            stanza,
            &requester.room_jid,
            &requester.full_jid,
            &payload,
        )));
    }
    let requested = requested_affiliation.expect("exclusive affiliation/role check");
    if !can_retrieve_affiliations(
        &requester.affiliation,
        &requested,
        room.members_only,
        room.non_anonymous,
    ) {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    let mut payload = XmlElement::namespaced("query", "http://jabber.org/protocol/muc#admin");
    for username in state
        .muc_service()
        .local_affiliations(room.id, &requested)
        .await?
    {
        payload.push_child(
            XmlElement::new("item")
                .attr("affiliation", &requested)
                .attr("jid", format!("{}@{}", username, state.config.domain)),
        );
    }
    for jid in state
        .muc_service()
        .federated_affiliations(room.id, &requested)
        .await?
    {
        payload.push_child(
            XmlElement::new("item")
                .attr("affiliation", &requested)
                .attr("jid", &jid),
        );
    }
    let payload = payload.finish();
    Ok(Some(federated_iq_result(
        stanza,
        &requester.room_jid,
        &requester.full_jid,
        &payload,
    )))
}

struct OccupantChange<'a> {
    affiliation: Option<&'a str>,
    role: Option<&'a str>,
    reason: Option<&'a str>,
}

async fn publish_occupant_change(
    state: &AppState,
    room: &MucRoom,
    actor: &MucOccupant,
    key: &str,
    mut target: MucOccupant,
    change: OccupantChange<'_>,
) -> Result<()> {
    if let Some(affiliation) = change.affiliation {
        target.affiliation = affiliation.to_owned();
    }
    if let Some(role) = change.role {
        target.role = role.to_owned();
    } else {
        target.role = if matches!(target.affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else if room.moderated && target.affiliation == "none" {
            "visitor"
        } else {
            "participant"
        }
        .to_owned();
    }
    let removal_status = if target.affiliation == "outcast" {
        Some(301)
    } else if target.affiliation == "none" && room.members_only {
        Some(321)
    } else if target.role == "none" {
        Some(307)
    } else {
        None
    };
    let actor_nick = actor.nick.as_str();
    let serializable = SerializableMucOccupant::from(&target);
    if let Some(status) = removal_status {
        state.muc_occupants.remove_if(key, |_, current| {
            current.full_jid == target.full_jid
                && current.connection_id == target.connection_id
                && current.cluster_epoch == target.cluster_epoch
        });
        state
            .cluster
            .evict_muc_occupant(&serializable, status, Some(actor_nick), change.reason)
            .await?;
        if state.muc_occupants_for(&target.room_jid).is_empty() {
            state.cluster.leave_muc(&target.room_jid).await?;
        }
        state
            .cluster
            .send_muc_presence_with_status(
                &target.room_jid,
                &serializable,
                true,
                false,
                None,
                Some(status),
                Some(actor_nick),
                change.reason,
            )
            .await?;
        for (_, recipient) in state.muc_occupants_for(&target.room_jid) {
            let presence = muc_presence_stanza_with_status(
                &serializable,
                &recipient.full_jid,
                true,
                false,
                false,
                None,
                target.room_non_anonymous || recipient.role == "moderator",
                Some(status),
                Some(actor_nick),
                change.reason,
            );
            let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
        }
        let self_presence = muc_presence_stanza_with_status(
            &serializable,
            &target.full_jid,
            true,
            true,
            false,
            None,
            true,
            Some(status),
            Some(actor_nick),
            change.reason,
        );
        let _ = state.deliver_to_muc_occupant(&target, self_presence).await;
    } else {
        state.muc_occupants.insert(key.to_owned(), target.clone());
        let json = serde_json::to_string(&serializable)?;
        state
            .cluster
            .register_muc_occupant(&target.room_jid, &target.nick, &json)
            .await?;
        state
            .cluster
            .send_muc_presence(&target.room_jid, &serializable, false, false, None)
            .await?;
        for (_, recipient) in state.muc_occupants_for(&target.room_jid) {
            let self_presence = same_remote_actor(&recipient.full_jid, &target.full_jid);
            let presence = muc_presence_stanza(
                &serializable,
                &recipient.full_jid,
                false,
                self_presence,
                false,
                None,
                target.room_non_anonymous || self_presence || recipient.role == "moderator",
            );
            let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
        }
    }
    Ok(())
}

async fn federated_muc_admin_set(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    requester: &MucOccupant,
    items: Vec<FederatedAdminItem>,
) -> Result<Option<String>> {
    let mut guarded_room = None;
    let mut guarded_requester = None;
    let _local_room_guard = if state.cluster.is_enabled() {
        None
    } else {
        let guard = state.muc_service().lock_local_room_mutation(room.id).await;
        let Some(refreshed_room) = state
            .muc_service()
            .federated_room_snapshot(&room.localpart)
            .await?
        else {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        };
        if refreshed_room.room_epoch != room.room_epoch {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        }
        let Some(mut current_requester) = state
            .muc_occupants_for(&requester.room_jid)
            .into_iter()
            .map(|(_, occupant)| occupant)
            .find(|occupant| {
                occupant.full_jid == requester.full_jid
                    && occupant.connection_id == requester.connection_id
                    && occupant.cluster_epoch == requester.cluster_epoch
            })
        else {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        };
        current_requester.affiliation = state
            .muc_service()
            .federated_affiliation(refreshed_room.id, bare_jid(&current_requester.full_jid))
            .await?
            .unwrap_or_else(|| "none".to_owned());
        guarded_room = Some(refreshed_room);
        guarded_requester = Some(current_requester);
        Some(guard)
    };
    let room = guarded_room.as_ref().unwrap_or(room);
    let requester = guarded_requester.as_ref().unwrap_or(requester);
    if !matches!(requester.affiliation.as_str(), "owner" | "admin") {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if items.is_empty() {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    if items.iter().any(|item| {
        item.affiliation.is_some() == item.role.is_some()
            || (item.affiliation.is_some() && item.jid.is_none())
            || (item.role.is_some() && item.nick.is_none())
    }) {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    let affiliation_count = items
        .iter()
        .filter(|item| item.affiliation.is_some())
        .count();
    let role_count = items.len().saturating_sub(affiliation_count);
    if (affiliation_count > 0 && role_count > 0) || role_count > 1 {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }

    // Preflight the complete IQ, then commit every durable affiliation in a
    // single room-serialized transaction.  A remote administrator must never
    // observe a successful prefix if a later item is malformed, stale, or
    // would revoke the final owner.
    let mut durable_changes = Vec::new();
    let mut previous_affiliations = std::collections::HashMap::new();
    let global_occupants = if state.cluster.is_enabled() {
        std::collections::HashMap::new()
    } else {
        state
            .cluster
            .get_muc_occupants(&requester.room_jid)
            .await?
            .into_values()
            .filter_map(|json| serde_json::from_str::<SerializableMucOccupant>(&json).ok())
            .map(|occupant| (occupant.nick.clone(), occupant))
            .collect::<std::collections::HashMap<_, _>>()
    };
    for item in &items {
        if let (Some(target_jid), Some(affiliation)) =
            (item.jid.as_deref(), item.affiliation.as_deref())
        {
            if !matches!(
                affiliation,
                "owner" | "admin" | "member" | "outcast" | "none"
            ) {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            if (affiliation == "owner" && requester.affiliation != "owner")
                || (requester.affiliation == "admin" && matches!(affiliation, "owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            let Ok(target) = crate::jid::CanonicalJid::parse_bare(target_jid) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let Some(target_localpart) = target.localpart() else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let target_bare = target.to_string();
            if affiliation == "outcast" && same_bare_jid(&requester.full_jid, &target_bare) {
                return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
            }
            let (target, current) = if target.domainpart() == state.config.domain {
                let Some(target_user) = state
                    .muc_service()
                    .enabled_local_account(target_localpart)
                    .await?
                else {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                (
                    MucAffiliationTarget::LocalUsername(target_localpart.to_owned()),
                    state
                        .muc_service()
                        .local_affiliation(room.id, target_user.id)
                        .await?,
                )
            } else {
                (
                    MucAffiliationTarget::FederatedBareJid(target_bare.clone()),
                    state
                        .muc_service()
                        .federated_affiliation(room.id, &target_bare)
                        .await?,
                )
            };
            if requester.affiliation == "admin"
                && matches!(current.as_deref(), Some("owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            previous_affiliations.insert(target_bare, current.unwrap_or_else(|| "none".to_owned()));
            durable_changes.push(MucAffiliationChange {
                target,
                affiliation: affiliation.to_owned(),
            });
        } else if let (Some(target_nick), Some(role)) = (item.nick.as_deref(), item.role.as_deref())
        {
            if !matches!(role, "moderator" | "participant" | "visitor" | "none") {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            let Ok(target_nick) = prepare_muc_nick(target_nick) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let key = muc_occupant_key(&requester.room_jid, &target_nick);
            let target = if state.cluster.is_enabled() {
                let authoritative = state
                    .muc_service()
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target_nick)
                    .await?;
                if let Some(authoritative) = authoritative {
                    state
                        .muc_service()
                        .exact_local_cluster_occupancy_snapshot(&authoritative)
                        .await?
                        .map(|occupancy| SerializableMucOccupant {
                            full_jid: occupancy.full_jid,
                            room_jid: requester.room_jid.clone(),
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
                state
                    .muc_occupants
                    .get(&key)
                    .map(|occupant| SerializableMucOccupant::from(&*occupant))
                    .or_else(|| global_occupants.get(&target_nick).cloned())
            };
            let Some(target) = target else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "item-not-found",
                ));
            };
            if requester.affiliation == "admin"
                && matches!(target.affiliation.as_str(), "owner" | "admin")
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
        }
    }
    let mut cluster_affiliation_operation = None;
    let affiliation_outcome = if state.cluster.is_enabled() && !durable_changes.is_empty() {
        state
            .cluster
            .admit(crate::cluster::ClusterOperation::MucMutation)?;
        let authenticated_domain = match &requester.endpoint {
            crate::state::MucOccupantEndpoint::Federated {
                authenticated_domain,
                ..
            } => authenticated_domain.clone(),
            _ => anyhow::bail!("federated MUC admin lost its S2S domain proof"),
        };
        let Some(actor_target) = state
            .muc_service()
            .local_cluster_occupancy_target(
                room.id,
                requester.cluster_epoch,
                requester.connection_id,
            )
            .await?
        else {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        };
        let operation_id = crate::services::muc::MucService::operation_id(&serde_json::json!({
            "kind":"admin_affiliation_batch","stream":requester.connection_id,
            "iq_id":stanza.id,"room":requester.room_jid,"actor":requester.full_jid,
            "changes":durable_changes,
        }))?;
        let outcome = state
            .muc_service()
            .apply_local_cluster_affiliations_batch(
                operation_id,
                room.id,
                room.room_epoch,
                room.config_version,
                &actor_target,
                &ClusterMucPrincipal::Federated {
                    bare_jid: bare_jid(&requester.full_jid).to_owned(),
                    authenticated_domain,
                },
                &requester.full_jid,
                &durable_changes,
            )
            .await?;
        cluster_affiliation_operation = Some(operation_id);
        outcome
    } else {
        state
            .muc_service()
            .set_local_legacy_affiliations_batch(room.id, &durable_changes)
            .await?
    };
    match affiliation_outcome {
        MucAffiliationBatchOutcome::Applied => {}
        MucAffiliationBatchOutcome::DuplicateTarget => {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "bad-request",
            ));
        }
        MucAffiliationBatchOutcome::LastOwner => {
            return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
        }
        MucAffiliationBatchOutcome::MissingTarget => {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "cancel",
                "item-not-found",
            ));
        }
        MucAffiliationBatchOutcome::Unauthorized => {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        }
        MucAffiliationBatchOutcome::Stale | MucAffiliationBatchOutcome::Destroyed => {
            return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
        }
    }
    if let Some(operation_id) = cluster_affiliation_operation {
        if let Err(error) = state
            .muc_service()
            .wake_committed_operation(&state.cluster, operation_id)
            .await
        {
            tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                "federated MUC affiliation batch committed; signed wake will be recovered by polling");
        }
    }
    if state.cluster.is_enabled() {
        let Some(actor_target) = state
            .muc_service()
            .local_cluster_occupancy_target(
                room.id,
                requester.cluster_epoch,
                requester.connection_id,
            )
            .await?
        else {
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        };
        for item in items.iter().filter(|item| item.role.is_some()) {
            let target_nick =
                prepare_muc_nick(item.nick.as_deref().expect("role item validated above"))
                    .expect("role nickname validated above");
            let Some(target) = state
                .muc_service()
                .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target_nick)
                .await?
            else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "item-not-found",
                ));
            };
            let new_role = item.role.as_deref().expect("role item validated above");
            let operation_id =
                crate::services::muc::MucService::operation_id(&serde_json::json!({
                    "kind":"admin_role","stream":requester.connection_id,"iq_id":stanza.id,
                    "room":requester.room_jid,"actor":actor_target,"target":target,
                    "role":new_role,"reason":item.reason,
                }))?;
            let outcome = if new_role == "none" {
                state
                    .muc_service()
                    .kick_local_cluster_occupancy(
                        operation_id,
                        &actor_target,
                        &target,
                        item.reason.as_deref(),
                    )
                    .await?
            } else {
                state
                    .muc_service()
                    .change_local_cluster_role(
                        operation_id,
                        &actor_target,
                        &target,
                        new_role,
                        item.reason.as_deref(),
                    )
                    .await?
            };
            match outcome {
                ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                ClusterMucTransitionOutcome::Unauthorized => {
                    return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
                }
                ClusterMucTransitionOutcome::Stale | ClusterMucTransitionOutcome::Destroyed => {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "item-not-found",
                    ));
                }
                ClusterMucTransitionOutcome::Conflict => {
                    return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
                }
            }
            if let Err(error) = state
                .muc_service()
                .wake_committed_operation(&state.cluster, operation_id)
                .await
            {
                tracing::warn!(?error, %operation_id, room=%requester.room_jid,
                    "federated MUC role operation committed; signed wake will be recovered by polling");
            }
        }
        return Ok(Some(federated_iq_result(
            stanza,
            &requester.room_jid,
            &requester.full_jid,
            "",
        )));
    }
    for item in items {
        if let (Some(target_jid), Some(affiliation)) =
            (item.jid.as_deref(), item.affiliation.as_deref())
        {
            if !matches!(
                affiliation,
                "owner" | "admin" | "member" | "outcast" | "none"
            ) {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            if (affiliation == "owner" && requester.affiliation != "owner")
                || (requester.affiliation == "admin" && matches!(affiliation, "owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            let Ok(target) = crate::jid::CanonicalJid::parse_bare(target_jid) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let Some(target_localpart) = target.localpart() else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let target_bare = target.to_string();
            if affiliation == "outcast" && same_bare_jid(&requester.full_jid, &target_bare) {
                return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
            }
            let target_affiliation = if target.domainpart() == state.config.domain {
                let target_user = state
                    .muc_service()
                    .enabled_local_account(target_localpart)
                    .await?;
                match target_user {
                    Some(target_user) => {
                        state
                            .muc_service()
                            .local_affiliation(room.id, target_user.id)
                            .await?
                    }
                    None => {
                        return Ok(federated_error(
                            stanza,
                            &stanza.from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                }
            } else {
                state
                    .muc_service()
                    .federated_affiliation(room.id, &target_bare)
                    .await?
            };
            if requester.affiliation == "admin"
                && matches!(target_affiliation.as_deref(), Some("owner" | "admin"))
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            let present: Vec<_> = state
                .muc_occupants_for(&requester.room_jid)
                .into_iter()
                .filter(|(_, occupant)| same_bare_jid(&occupant.full_jid, &target_bare))
                .collect();
            let local_identities = present
                .iter()
                .map(|(_, occupant)| (occupant.cluster_epoch, occupant.connection_id))
                .collect::<std::collections::HashSet<_>>();
            let remote_present = global_occupants
                .values()
                .filter(|occupant| {
                    same_bare_jid(&occupant.full_jid, &target_bare)
                        && !local_identities
                            .contains(&(occupant.cluster_epoch, occupant.connection_id))
                })
                .cloned()
                .collect::<Vec<_>>();
            let target_is_occupant = !present.is_empty() || !remote_present.is_empty();
            let previous_affiliation = previous_affiliations
                .get(&target_bare)
                .map(String::as_str)
                .unwrap_or("none");
            if super::muc::should_broadcast_offline_affiliation_change(
                room.non_anonymous,
                target_is_occupant,
                previous_affiliation,
                affiliation,
            ) {
                super::muc::deliver_muc_offline_affiliation_change_notice(
                    state,
                    &requester.room_jid,
                    &target_bare,
                    affiliation,
                    item.nick.as_deref(),
                    item.reason.as_deref(),
                )
                .await;
            }
            for (key, occupant) in present {
                publish_occupant_change(
                    state,
                    room,
                    requester,
                    &key,
                    occupant,
                    OccupantChange {
                        affiliation: Some(affiliation),
                        role: None,
                        reason: item.reason.as_deref(),
                    },
                )
                .await?;
            }
            for remote in remote_present {
                let remove_from_room =
                    affiliation == "outcast" || (affiliation == "none" && room.members_only);
                if remove_from_room {
                    let mut updated = remote;
                    updated.affiliation = affiliation.to_owned();
                    updated.role = "none".to_owned();
                    let status = if affiliation == "outcast" { 301 } else { 321 };
                    if state
                        .cluster
                        .evict_muc_occupant(
                            &updated,
                            status,
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        )
                        .await?
                    {
                        state
                            .cluster
                            .send_muc_presence_with_status(
                                &requester.room_jid,
                                &updated,
                                true,
                                false,
                                None,
                                Some(status),
                                Some(&requester.nick),
                                item.reason.as_deref(),
                            )
                            .await?;
                        for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                            let presence = muc_presence_stanza_with_status(
                                &updated,
                                &recipient.full_jid,
                                true,
                                false,
                                false,
                                None,
                                updated.room_non_anonymous || recipient.role == "moderator",
                                Some(status),
                                Some(&requester.nick),
                                item.reason.as_deref(),
                            );
                            let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                        }
                    }
                } else {
                    let role = if matches!(affiliation, "owner" | "admin") {
                        "moderator"
                    } else if room.moderated && affiliation == "none" {
                        "visitor"
                    } else {
                        "participant"
                    };
                    let updated = match state
                        .cluster
                        .change_muc_occupant_affiliation(
                            &requester.room_jid,
                            &remote,
                            affiliation,
                            role,
                        )
                        .await?
                    {
                        crate::cluster::MucRoleChange::Changed(updated) => *updated,
                        crate::cluster::MucRoleChange::Stale => continue,
                    };
                    state
                        .cluster
                        .send_muc_presence(&requester.room_jid, &updated, false, false, None)
                        .await?;
                    for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            false,
                            false,
                            None,
                            updated.room_non_anonymous || recipient.role == "moderator",
                        );
                        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                    }
                }
            }
        } else if let (Some(target_nick), Some(role)) = (item.nick.as_deref(), item.role.as_deref())
        {
            if !matches!(role, "moderator" | "participant" | "visitor" | "none") {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "bad-request",
                ));
            }
            let Ok(target_nick) = prepare_muc_nick(target_nick) else {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "modify",
                    "jid-malformed",
                ));
            };
            let key = muc_occupant_key(&requester.room_jid, &target_nick);
            let local_target = state
                .muc_occupants
                .get(&key)
                .map(|entry| entry.value().clone());
            if local_target.is_none() {
                let Some(mut target) = global_occupants.get(&target_nick).cloned() else {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "item-not-found",
                    ));
                };
                if requester.affiliation == "admin"
                    && matches!(target.affiliation.as_str(), "owner" | "admin")
                {
                    return Ok(federated_error(
                        stanza,
                        &stanza.from,
                        "cancel",
                        "not-allowed",
                    ));
                }
                if role == "none" {
                    target.role = "none".to_owned();
                    if !state
                        .cluster
                        .evict_muc_occupant(
                            &target,
                            307,
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        )
                        .await?
                    {
                        return Ok(federated_error(
                            stanza,
                            &stanza.from,
                            "cancel",
                            "item-not-found",
                        ));
                    }
                    state
                        .cluster
                        .send_muc_presence_with_status(
                            &requester.room_jid,
                            &target,
                            true,
                            false,
                            None,
                            Some(307),
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        )
                        .await?;
                    for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                        let presence = muc_presence_stanza_with_status(
                            &target,
                            &recipient.full_jid,
                            true,
                            false,
                            false,
                            None,
                            target.room_non_anonymous || recipient.role == "moderator",
                            Some(307),
                            Some(&requester.nick),
                            item.reason.as_deref(),
                        );
                        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                    }
                } else {
                    let updated = match state
                        .cluster
                        .change_muc_occupant_role(&requester.room_jid, &target, role)
                        .await?
                    {
                        crate::cluster::MucRoleChange::Changed(updated) => *updated,
                        crate::cluster::MucRoleChange::Stale => {
                            return Ok(federated_error(
                                stanza,
                                &stanza.from,
                                "cancel",
                                "item-not-found",
                            ));
                        }
                    };
                    state
                        .cluster
                        .send_muc_presence(&requester.room_jid, &updated, false, false, None)
                        .await?;
                    for (_, recipient) in state.muc_occupants_for(&requester.room_jid) {
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            false,
                            false,
                            None,
                            updated.room_non_anonymous || recipient.role == "moderator",
                        );
                        let _ = state.deliver_to_muc_occupant(&recipient, presence).await;
                    }
                }
                continue;
            }
            let target = local_target.expect("remote cluster target handled above");
            if requester.affiliation == "admin"
                && matches!(target.affiliation.as_str(), "owner" | "admin")
            {
                return Ok(federated_error(
                    stanza,
                    &stanza.from,
                    "cancel",
                    "not-allowed",
                ));
            }
            publish_occupant_change(
                state,
                room,
                requester,
                &key,
                target,
                OccupantChange {
                    affiliation: None,
                    role: Some(role),
                    reason: item.reason.as_deref(),
                },
            )
            .await?;
        } else {
            return Ok(federated_error(
                stanza,
                &stanza.from,
                "modify",
                "bad-request",
            ));
        }
    }
    Ok(Some(federated_iq_result(
        stanza,
        &requester.room_jid,
        &requester.full_jid,
        "",
    )))
}

async fn federated_muc_moderate(
    state: &AppState,
    stanza: &FederatedStanza,
    room: &MucRoom,
    moderator: &MucOccupant,
    target: Option<String>,
    reason: Option<String>,
    has_retract: bool,
) -> Result<Option<String>> {
    let authenticated_domain = match &moderator.endpoint {
        MucOccupantEndpoint::Federated {
            authenticated_domain,
            ..
        } => authenticated_domain.clone(),
        _ => return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden")),
    };
    let local_authority_guard = if state.cluster.is_enabled() {
        None
    } else {
        Some(state.muc_service().lock_local_room_mutation(room.id).await)
    };
    let Some(refreshed_room) = state
        .muc_service()
        .federated_room_snapshot(localpart(&moderator.room_jid))
        .await?
    else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    };
    if refreshed_room.id != room.id || refreshed_room.room_epoch != room.room_epoch {
        return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
    }
    let Some((_, refreshed_moderator)) = state
        .muc_occupants_for(&moderator.room_jid)
        .into_iter()
        .find(|(_, current)| {
            current.full_jid == moderator.full_jid
                && current.connection_id == moderator.connection_id
                && current.cluster_epoch == moderator.cluster_epoch
                && current.nick == moderator.nick
        })
    else {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    };
    if !federated_endpoint_matches(&refreshed_moderator, &authenticated_domain) {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "auth",
            "not-authorized",
        ));
    }
    let room = &refreshed_room;
    let moderator = &refreshed_moderator;
    let actor_scope = crate::jid::canonical_bare_key(&moderator.full_jid)?;
    let current_affiliation = state
        .muc_service()
        .federated_affiliation(room.id, &actor_scope)
        .await?
        .unwrap_or_else(|| "none".to_owned());
    if current_affiliation != moderator.affiliation || current_affiliation == "outcast" {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    let cluster_target = if state.cluster.is_enabled() {
        let Some(target) = state
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
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        };
        Some(target)
    } else {
        None
    };
    if moderator.role != "moderator" {
        return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
    }
    if !has_retract {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    }
    let Some(target) = target else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "bad-request",
        ));
    };
    let Ok(target_id) = uuid::Uuid::parse_str(&target) else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    };
    let reason = reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if reason.is_some_and(|value| value.len() > 1024) {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "modify",
            "not-acceptable",
        ));
    }
    let Some(original) = state
        .muc_service()
        .federated_message_by_id(room.id, target_id)
        .await?
    else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "item-not-found",
        ));
    };
    let Some((original_from, original_client_id)) = (|| {
        let document = roxmltree::Document::parse(&original.stanza).ok()?;
        let root = document.root_element();
        (root.tag_name().name() == "message" && root.attribute("type") == Some("groupchat")).then(
            || {
                (
                    root.attribute("from")
                        .unwrap_or(&moderator.room_jid)
                        .to_owned(),
                    root.attribute("id").unwrap_or(&target).to_owned(),
                )
            },
        )
    })() else {
        return Ok(federated_error(
            stanza,
            &stanza.from,
            "cancel",
            "not-acceptable",
        ));
    };
    let moderator_occupant = format!("{}/{}", moderator.room_jid, moderator.nick);
    let author_occupant_id = muc_occupant_id(&room.occupant_id_secret, &original.sender_jid);
    let stamp = chrono::Utc::now();
    let moderated = XmlElement::namespaced("moderated", "urn:xmpp:message-moderate:1")
        .attr("by", &moderator_occupant)
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &moderator.occupant_id),
        );
    let mut retracted = XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
        .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ"))
        .child(moderated.clone());
    if let Some(reason) = reason {
        retracted.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    let tombstone = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &original_from)
        .attr("to", &moderator.room_jid)
        .attr("type", "groupchat")
        .attr("id", &original_client_id)
        .child(
            XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                .attr("id", target_id)
                .attr("by", &moderator.room_jid),
        )
        .child(
            XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                .attr("id", &author_occupant_id),
        )
        .child(retracted)
        .finish();
    let action_id = uuid::Uuid::new_v4();
    let mut retract = XmlElement::namespaced("retract", "urn:xmpp:message-retract:1")
        .attr("id", target_id)
        .child(moderated);
    if let Some(reason) = reason {
        retract.push_child(XmlElement::new("reason").text(reason.to_owned()));
    }
    let notice_xml = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &moderator.room_jid)
        .attr("to", &moderator.room_jid)
        .attr("type", "groupchat")
        .attr("id", action_id)
        .child(retract)
        .finish();
    let notice = add_stanza_id(
        &set_muc_occupant_id(&notice_xml, &moderator.occupant_id),
        &moderator.room_jid,
        action_id,
    );
    match state
        .muc_service()
        .retract_local_message_and_archive_action(MucRetractionMutation {
            action_id,
            room_id: room.id,
            target_id,
            expected_stanza: &original.stanza,
            actor_scope: &actor_scope,
            sender_jid: &moderator.full_jid,
            nick: &moderator.nick,
            tombstone: &tombstone,
            action_stanza: &notice,
            reason,
            kind: MucRetractionKind::Moderator,
            authority: MucActorAuthority {
                clustered: state.cluster.is_enabled(),
                expected_room_epoch: room.room_epoch,
                principal: MucActorPrincipal::Federated {
                    bare_jid: &actor_scope,
                    authenticated_domain: &authenticated_domain,
                },
                actor_scope: &actor_scope,
                full_jid: &moderator.full_jid,
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
            return Ok(federated_error(stanza, &stanza.from, "auth", "forbidden"));
        }
        MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
            return Ok(federated_error(stanza, &stanza.from, "cancel", "conflict"));
        }
    }
    match state
        .cluster
        .send_to_muc(&moderator.room_jid, &notice)
        .await
    {
        Ok(()) => {}
        Err(_) => record_federated_muc_post_commit_failure(
            state,
            &moderator.room_jid,
            "*",
            "cluster moderation fan-out",
        ),
    }
    for (_, occupant) in state.muc_occupants_for(&moderator.room_jid) {
        let delivery = set_to(&notice, &occupant.full_jid);
        if !state.deliver_to_muc_occupant(&occupant, delivery).await {
            record_federated_muc_post_commit_failure(
                state,
                &moderator.room_jid,
                &occupant.full_jid,
                "moderation occupant queue",
            );
        }
    }
    drop(local_authority_guard);
    Ok(Some(federated_iq_result(
        stanza,
        &moderator.room_jid,
        &moderator.full_jid,
        "",
    )))
}

/// Remove every remote actor bound to a closed authenticated S2S connection.
/// A later stanza on another connection rebinds the endpoint before cleanup.
pub(crate) async fn federated_muc_connection_closed(
    state: &AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
) -> Result<()> {
    let departed: Vec<_> = state
        .muc_occupants
        .iter()
        .filter_map(|entry| match &entry.value().endpoint {
            MucOccupantEndpoint::Federated {
                authenticated_domain: domain,
                connection_id: bound_connection,
                ..
            } if same_authenticated_domain(domain, authenticated_domain)
                && *bound_connection == connection_id =>
            {
                Some((entry.key().clone(), entry.value().clone()))
            }
            _ => None,
        })
        .collect();
    for (key, occupant) in departed {
        unregister_remote_occupant(state, &key, occupant, Some(333)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn federated_mediated_invites_preserve_original_carbon_eligibility() {
        let invite = "<message from='alice@remote.test/Phone' to='room@conference.example.test'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x></message>";
        let document = roxmltree::Document::parse(invite).unwrap();
        assert!(
            FederatedMessageRequest::from_node(document.root_element(), invite).carbon_eligible
        );

        let private = "<message from='alice@remote.test/Phone' to='room@conference.example.test'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x><private xmlns='urn:xmpp:carbons:2'/></message>";
        let document = roxmltree::Document::parse(private).unwrap();
        assert!(
            !FederatedMessageRequest::from_node(document.root_element(), private).carbon_eligible
        );

        // XEP-0334 explicitly says no-copy never overrides RFC 6121 handling
        // for a bare destination. The original mediated invitation is sent
        // to the bare room JID, so this invalid sender hint is ignored.
        let bare_no_copy = "<message from='alice@remote.test/Phone' to='room@conference.example.test'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x><no-copy xmlns='urn:xmpp:hints'/></message>";
        let document = roxmltree::Document::parse(bare_no_copy).unwrap();
        assert!(
            FederatedMessageRequest::from_node(document.root_element(), bare_no_copy)
                .carbon_eligible
        );
    }

    fn remote_occupant(domain: &str) -> MucOccupant {
        MucOccupant {
            full_jid: format!("alice@{domain}/phone"),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Federated {
                authenticated_domain: domain.to_owned(),
                connection_id: uuid::Uuid::nil(),
            },
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: false,
            occupant_id: "opaque".to_owned(),
            cluster_epoch: uuid::Uuid::new_v4(),
            connection_id: uuid::Uuid::nil(),
            sm_session_id: None,
            payload: String::new(),
        }
    }

    fn room(non_anonymous: bool) -> MucRoom {
        MucRoom {
            id: uuid::Uuid::nil(),
            room_epoch: uuid::Uuid::nil(),
            config_version: 1,
            localpart: "room".to_owned(),
            title: None,
            description: None,
            persistent: true,
            members_only: false,
            public: true,
            moderated: false,
            non_anonymous,
            max_occupants: 100,
            subject: None,
            subject_changed_at: None,
            allow_subject_change: false,
            allow_invites: true,
            allow_private_messages: true,
            logging_enabled: true,
            allow_registration: true,
            password_hash: None,
            occupant_id_secret: vec![7_u8; 32],
            configuration_owner_jid: None,
            configuration_expires_at: None,
        }
    }

    #[test]
    fn authenticated_domain_must_own_the_full_remote_jid() {
        assert!(authenticated_remote_actor(
            "remote.test",
            "alice@remote.test/phone"
        ));
        assert!(authenticated_remote_actor(
            "REMOTE.TEST",
            "alice@remote.test/phone"
        ));
        assert!(authenticated_remote_actor(
            "B\u{fc}CHER.Example.",
            "Alice@bücher.example/Phone"
        ));
        for forged in [
            "alice@evil.test/phone",
            "alice@remote.test",
            "alice@remote.test/",
            "remote.test",
            "remote.test/gateway",
            "alice@remote.test/\u{0007}",
            "alice@@remote.test/phone",
        ] {
            assert!(!authenticated_remote_actor("remote.test", forged));
        }
    }

    #[test]
    fn duplicate_remote_join_is_idempotent_only_for_the_same_actor_nick_and_domain() {
        let occupant = remote_occupant("remote.test");
        assert!(is_idempotent_remote_join(
            &occupant,
            "REMOTE.TEST",
            "alice@remote.test/phone",
            "Alice",
        ));
        assert!(!is_idempotent_remote_join(
            &occupant,
            "remote.test",
            "alice@remote.test/phone",
            "alice",
        ));
        assert!(!is_idempotent_remote_join(
            &occupant,
            "evil.test",
            "alice@remote.test/phone",
            "Alice",
        ));
        assert!(!is_idempotent_remote_join(
            &occupant,
            "remote.test",
            "alice@remote.test/laptop",
            "Alice",
        ));
        assert!(!is_idempotent_remote_join(
            &occupant,
            "remote.test",
            "alice@remote.test/Phone",
            "Alice",
        ));
        assert!(!is_idempotent_remote_join(
            &occupant,
            "remote.test",
            "alice@remote.test/phone",
            "Alice2",
        ));
    }

    #[test]
    fn federated_owner_actions_are_strict_and_support_instant_cancel_and_destroy() {
        let room = room(true);
        let instant = "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/></query></iq>";
        let FederatedOwnerAction::Configure(config) =
            parse_federated_owner_action(instant, &room).unwrap()
        else {
            panic!("empty submit must select instant-room defaults")
        };
        assert_eq!(config.title.as_deref(), Some("room"));
        assert!(config.public);
        assert!(config.non_anonymous);

        let cancel = "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='cancel'/></query></iq>";
        assert!(matches!(
            parse_federated_owner_action(cancel, &room),
            Ok(FederatedOwnerAction::Cancel)
        ));
        let destroy = "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy jid='replacement@conference.example.test'><reason>closed</reason></destroy></query></iq>";
        assert!(matches!(
            parse_federated_owner_action(destroy, &room),
            Ok(FederatedOwnerAction::Destroy { alternate: Some(jid), reason: Some(reason) })
                if jid == "replacement@conference.example.test" && reason == "closed"
        ));
        for invalid in [
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>",
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/><destroy/></query></iq>",
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'><destroy><unknown/></destroy></query></iq>",
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='form'/></query></iq>",
        ] {
            assert!(parse_federated_owner_action(invalid, &room).is_err());
        }
    }

    #[test]
    fn semi_anonymous_history_keeps_occupant_id_without_disclosing_real_jid() {
        let sender = "alice@remote.test/phone";
        let archived = "<message xmlns='jabber:client' from='room@conference.example.test/Alice' type='groupchat'><body>hello</body></message>";
        let anonymous = federated_history_stanza(&room(false), archived, sender);
        assert!(anonymous.contains("urn:xmpp:occupant-id:0"));
        assert!(!anonymous.contains("alice@remote.test"));
        assert!(!anonymous.contains("urn:northstar:muc:sender:0"));

        let disclosed = federated_history_stanza(&room(true), archived, sender);
        assert!(disclosed.contains("urn:xmpp:occupant-id:0"));
        assert!(disclosed.contains("urn:northstar:muc:sender:0"));
        assert!(disclosed.contains("alice@remote.test"));
        assert!(!disclosed.contains("/phone"));

        let privileged = federated_history_stanza_with_access(&room(false), archived, sender, true);
        assert!(privileged.contains("alice@remote.test"));
    }

    #[test]
    fn federated_iq_parser_owns_admin_items_and_preserves_malformed_requests() {
        let xml = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set' id='a1'><query xmlns='http://jabber.org/protocol/muc#admin'><item jid='bad@@remote.test' affiliation='outcast'><reason>spam</reason></item><item role='none'/></query></iq>";
        let document = roxmltree::Document::parse(xml).unwrap();
        let parsed = FederatedIqRequest::from_node(document.root_element(), xml);
        drop(document);
        let FederatedIqPayload::AdminSet { items } = parsed.payload else {
            panic!("admin set was not parsed");
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].jid.as_deref(), Some("bad@@remote.test"));
        assert_eq!(items[0].reason.as_deref(), Some("spam"));
        assert_eq!(items[1].jid, None);
        assert_eq!(items[1].nick, None);
        assert_eq!(parsed.stanza.id.as_deref(), Some("a1"));

        for malformed in [
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'><unknown/></query></iq>",
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Alice' role='none'><reason>a</reason><reason>b</reason></item></query></iq>",
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Alice' role='none' actor='forged'/></query></iq>",
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'/></iq>",
        ] {
            let document = roxmltree::Document::parse(malformed).unwrap();
            assert!(matches!(
                FederatedIqRequest::from_node(document.root_element(), malformed).payload,
                FederatedIqPayload::AdminError("bad-request")
            ));
        }
    }

    #[test]
    fn federated_iq_parser_captures_bounded_mam_and_moderation_controls() {
        let mam = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set'><query xmlns='urn:xmpp:mam:2' queryid='q1'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>alice@remote.test</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>999</max><before/></set></query></iq>";
        let document = roxmltree::Document::parse(mam).unwrap();
        let parsed = FederatedIqRequest::from_node(document.root_element(), mam);
        let FederatedIqPayload::MamQuery(query) = parsed.payload else {
            panic!("MAM query was not parsed");
        };
        assert_eq!(query.query_id.as_deref(), Some("q1"));
        assert_eq!(query.query.with_jid.as_deref(), Some("alice@remote.test"));
        assert_eq!(query.query.max, 100);
        assert!(crate::services::muc::MucService::archive_page_is_last(
            &query.query.page
        ));

        let metadata = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='get'><metadata xmlns='urn:xmpp:mam:2'/></iq>";
        let document = roxmltree::Document::parse(metadata).unwrap();
        assert!(matches!(
            FederatedIqRequest::from_node(document.root_element(), metadata).payload,
            FederatedIqPayload::MamMetadata
        ));

        let malformed = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='unknown'><value>x</value></field></x></query></iq>";
        let document = roxmltree::Document::parse(malformed).unwrap();
        assert!(matches!(
            FederatedIqRequest::from_node(document.root_element(), malformed).payload,
            FederatedIqPayload::MamError("feature-not-implemented")
        ));

        let moderate = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set'><moderate xmlns='urn:xmpp:message-moderate:1' id='de305d54-75b4-431b-adb2-eb6b9e546013'><retract xmlns='urn:xmpp:message-retract:1'/><reason>abuse</reason></moderate></iq>";
        let document = roxmltree::Document::parse(moderate).unwrap();
        let parsed = FederatedIqRequest::from_node(document.root_element(), moderate);
        let FederatedIqPayload::Moderate {
            target,
            reason,
            has_retract,
        } = parsed.payload
        else {
            panic!("moderation request was not parsed");
        };
        assert_eq!(
            target.as_deref(),
            Some("de305d54-75b4-431b-adb2-eb6b9e546013")
        );
        assert_eq!(reason.as_deref(), Some("abuse"));
        assert!(has_retract);
    }

    #[test]
    fn federated_iq_parser_accepts_only_structurally_empty_unique_requests() {
        let valid = "<iq from='alice@remote.test/Phone' to='conference.example.test' type='get' id='u1'><unique xmlns='http://jabber.org/protocol/muc#unique'/></iq>";
        let document = roxmltree::Document::parse(valid).unwrap();
        assert!(matches!(
            FederatedIqRequest::from_node(document.root_element(), valid).payload,
            FederatedIqPayload::Unique
        ));

        let malformed = "<iq from='alice@remote.test/Phone' to='conference.example.test' type='get' id='u2'><unique xmlns='http://jabber.org/protocol/muc#unique' bogus='1'/></iq>";
        let document = roxmltree::Document::parse(malformed).unwrap();
        assert!(matches!(
            FederatedIqRequest::from_node(document.root_element(), malformed).payload,
            FederatedIqPayload::Unsupported
        ));
    }

    #[test]
    fn federated_room_disco_preserves_reserved_nick_node_and_rejects_extra_shape() {
        let reserved = "<iq from='alice@remote.test/Phone' to='room@conference.example.test' type='get'><query xmlns='http://jabber.org/protocol/disco#info' node='x-roomuser-item'/></iq>";
        let document = roxmltree::Document::parse(reserved).unwrap();
        assert!(matches!(
            FederatedIqRequest::from_node(document.root_element(), reserved).payload,
            FederatedIqPayload::DiscoInfo { node: Some(node) } if node == "x-roomuser-item"
        ));

        for malformed in [
            "<iq type='get'><query xmlns='http://jabber.org/protocol/disco#info' bogus='1'/></iq>",
            "<iq type='get'><query xmlns='http://jabber.org/protocol/disco#info'><item/></query></iq>",
        ] {
            let document = roxmltree::Document::parse(malformed).unwrap();
            assert!(matches!(
                FederatedIqRequest::from_node(document.root_element(), malformed).payload,
                FederatedIqPayload::DiscoInfoError
            ));
        }
    }
}
