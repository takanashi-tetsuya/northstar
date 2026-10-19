//! Federated XEP-0045 room actors.
//!
//! An authenticated S2S domain is an authorization boundary, not a local
//! account. Remote occupants therefore live in the room map with a federated
//! endpoint and use a separate persistent-affiliation table.

use crate::platform::jid_text::{bare_jid, localpart};
use crate::services::mam::{FederatedMamMetadataCommand, MamMetadataResult};
use crate::services::muc::{
    ClusterMucAffiliationSubject, ClusterMucConfigurationOutcome, ClusterMucInviteAuthority,
    ClusterMucJoin, ClusterMucJoinOutcome, ClusterMucPrincipal, ClusterMucRegistrationOutcome,
    ClusterMucTransitionOutcome, DurableMucInviteOutcome, MucActorAuthority, MucActorPrincipal,
    MucAffiliationBatchOutcome, MucAffiliationChange, MucAffiliationTarget, MucConfigUpdate,
    MucConfigurationOutcome, MucDiscussion, MucDiscussionAdmission, MucRegistrationOutcome,
    MucRetractionKind, MucRetractionMutation, MucRetractionOutcome, MucRoom, MucSubjectMutation,
    MucSubjectOutcome, OfflineStoreOutcome,
};
use crate::state::{AppState, MucOccupant, MucOccupantEndpoint, SerializableMucOccupant};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::{Context, Result};
use northstar_room_core::MucJoinSnapshotError;
use roxmltree::Node;
use std::sync::atomic::Ordering;

mod admin;
mod iq;
mod message;
mod moderate;
mod owner;
mod presence;
#[cfg(test)]
mod tests;

pub(crate) use self::iq::federated_muc_iq;
pub(crate) use self::message::federated_muc_message;
pub(crate) use self::presence::federated_muc_presence;

fn record_federated_muc_post_commit_failure(
    state: &AppState,
    room: &str,
    recipient: &str,
    stage: &str,
) {
    state
        .federated_muc_telemetry()
        .post_commit_delivery_failed();
    state.federated_muc_telemetry().post_accept_failed();
    tracing::warn!(
        room,
        recipient,
        stage,
        "post-commit federated MUC delivery was not admitted"
    );
}

trait FederatedJoinProjectionPort: Sync {
    fn join_room(&self, room_jid: &str) -> impl std::future::Future<Output = Result<()>> + Send;
    fn register_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        exact_occupant_json: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn publish_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        created: bool,
        id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

impl FederatedJoinProjectionPort for AppState {
    fn join_room(&self, room_jid: &str) -> impl std::future::Future<Output = Result<()>> + Send {
        self.federated_muc_join_room(room_jid)
    }

    fn register_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        exact_occupant_json: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        self.federated_muc_register_occupant(room_jid, nick, exact_occupant_json)
    }

    fn publish_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        created: bool,
        id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        self.federated_muc_publish_presence(room_jid, occupant, false, created, id)
    }
}

enum FederatedJoinProjectionResult {
    Committed {
        room_join: Result<()>,
        registration: Result<bool>,
    },
    Legacy,
}

struct FederatedJoinProjectionRequest<'a> {
    committed: bool,
    room_jid: &'a str,
    nick: &'a str,
    exact_occupant_json: &'a str,
    occupant: &'a SerializableMucOccupant,
    created: bool,
    id: Option<&'a str>,
}

/// PostgreSQL has already committed its join and outbox. Redis is a repairable
/// projection in that mode, so neither attempted write can suppress the
/// joiner's initial presence. Legacy mode still requires each Redis effect.
async fn project_federated_join<P: FederatedJoinProjectionPort>(
    port: &P,
    request: FederatedJoinProjectionRequest<'_>,
) -> Result<FederatedJoinProjectionResult> {
    let room_join = port.join_room(request.room_jid).await;
    if request.committed {
        // Exact registration may repair stale Redis capacity state even when
        // publishing the room index failed; attempt both in this order.
        let registration = port
            .register_occupant(request.room_jid, request.nick, request.exact_occupant_json)
            .await;
        return Ok(FederatedJoinProjectionResult::Committed {
            room_join,
            registration,
        });
    }
    room_join?;
    port.register_occupant(request.room_jid, request.nick, request.exact_occupant_json)
        .await?;
    port.publish_presence(
        request.room_jid,
        request.occupant,
        request.created,
        request.id,
    )
    .await?;
    Ok(FederatedJoinProjectionResult::Legacy)
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
    crate::jid::prepare_domainpart(&format!("conference.{}", state.local_domain()))
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
    fn from_node(
        root: Node<'_, '_>,
        raw: &str,
        validation: std::result::Result<(), &'static str>,
    ) -> Self {
        let validation_error = validation
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
    PingError,
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
                    ("ping", northstar_xep_0199::NAMESPACE, "get") => {
                        if northstar_xep_0199::parse_ping_element(child).is_ok() {
                            FederatedIqPayload::Ping
                        } else {
                            FederatedIqPayload::PingError
                        }
                    }
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
    iq_result_to(stanza.id.as_deref().unwrap_or_default(), from, to, payload)
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
    use northstar_xep_0045::{Affiliation, PermissionDecision};

    if !matches!(requested, "owner" | "admin" | "member" | "outcast") {
        return false;
    }
    let (Some(requester), Some(requested)) = (
        Affiliation::from_str_name(requester),
        Affiliation::from_str_name(requested),
    ) else {
        return false;
    };
    northstar_xep_0045::evaluate_affiliation_list_access(
        requester,
        requested,
        members_only,
        non_anonymous,
    ) == PermissionDecision::Allowed
}

async fn unregister_remote_occupant(
    state: &AppState,
    mut departed: MucOccupant,
    removal_status: Option<u16>,
) -> Result<()> {
    let room_jid = departed.room_jid.clone();
    let mut local_departure_room = None;
    let local_departure_guard = if state.federated_muc_pg_authority_enabled() {
        None
    } else {
        let Some(initial_room) = state
            .muc_service()
            .federated_room_snapshot(localpart(&room_jid))
            .await?
        else {
            state.remove_local_muc_occupant_exact((&departed).into());
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
            state.remove_local_muc_occupant_exact((&departed).into());
            return Ok(());
        };
        if refreshed_room.room_epoch != initial_room.room_epoch {
            state.remove_local_muc_occupant_exact((&departed).into());
            return Ok(());
        }
        let Some(current) = state.local_muc_occupant_exact((&departed).into()) else {
            return Ok(());
        };
        departed = current;
        local_departure_room = Some(refreshed_room);
        Some(guard)
    };
    departed.role = "none".to_owned();
    let mut clustered_leave = false;
    if state.federated_muc_pg_authority_enabled() {
        state.federated_muc_admit_mutation()?;
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
        let outcome = if removal_status == Some(333) {
            state
                .muc_service()
                .disconnect_local_cluster_occupancy(
                    operation_id,
                    &target,
                    state.federated_muc_owner_node_id(),
                )
                .await?
        } else {
            state
                .muc_service()
                .transition_local_cluster_occupancy(
                    operation_id,
                    &target,
                    "leave",
                    state.federated_muc_owner_node_id(),
                    None,
                    None,
                    departed.sm_session_id,
                    std::time::Duration::from_secs(90),
                )
                .await?
        };
        match outcome {
            ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
            other => anyhow::bail!("federated MUC leave was rejected by PG authority: {other:?}"),
        }
        clustered_leave = true;
        if let Err(error) = state.wake_committed_muc_operation(operation_id).await {
            tracing::warn!(?error, %operation_id, room=%room_jid,
                "federated MUC leave committed; signed wake will be recovered by polling");
        }
    }
    let removed_locally = state.remove_local_muc_occupant_exact((&departed).into());
    if removed_locally.is_none() && !state.federated_muc_pg_authority_enabled() {
        return Ok(());
    }
    if let Some(mut removed) = removed_locally {
        removed.role = "none".to_owned();
        departed = removed;
    }
    let serializable = SerializableMucOccupant::from(&departed);
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
            .remove_exact_muc_soft_state(&departed)
            .await
            .unwrap_or(false)
    } else {
        state
            .federated_muc_evict_occupant(&serializable, removal_status.unwrap_or(307), None, None)
            .await?
    };
    let globally_empty = removed_globally
        && state
            .federated_muc_global_occupants(&room_jid)
            .await?
            .is_empty();
    if locally_empty && globally_empty {
        state.federated_muc_leave_room(&room_jid).await?;
    }
    if !clustered_leave {
        state
            .federated_muc_publish_removal_presence(
                &room_jid,
                &serializable,
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

/// Remove every remote actor bound to a closed authenticated S2S connection.
/// A later stanza on another connection rebinds the endpoint before cleanup.
pub(crate) async fn federated_muc_connection_closed(
    state: &AppState,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
) -> Result<()> {
    let departed =
        state.federated_muc_occupants_for_closed_connection(authenticated_domain, connection_id);
    for occupant in departed {
        unregister_remote_occupant(state, occupant, Some(333)).await?;
    }
    Ok(())
}
