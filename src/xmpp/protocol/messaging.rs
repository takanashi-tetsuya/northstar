use super::{Action, ProtocolSession};
use crate::cluster::{DirectPostCommitMode, DirectSpoolEligibility};
#[cfg(test)]
use crate::services::messaging::direct_workflow::PreparedHandoffNext;
use crate::services::messaging::{
    admit_offline_then_push, ArchiveWrite, DirectMessageRouter, DirectRouteDelivery,
    DirectRouteOutcome, DirectRouteRejection, DirectRouteRequest, DirectRouteTarget,
    DurableAdmissionOutcome, FederationDelivery, IdentityAuthority, LocalDelivery,
    LocalMucInviteAdmission, LocalRecipientDecision, MessageIdentity, MessagePostCommit,
    OfflineAdmissionOutcome, OutboundPolicyDecision, PersonalMessageDestination,
    RemoteMucInviteAdmission, RemoteMucInviteAdmissionOutcome, ValidatedPersonalMessage,
};
use crate::services::muc::{ClusterMucAffiliationSubject, DurableMucInviteOutcome};
use crate::services::privacy::PrivacyStanzaKind;
use crate::services::retractions::{DeliveryProjection, RetractionOutcome};
use crate::services::{
    message_admission::witness::DirectOperationHandle,
    messaging::direct_workflow::{
        continue_prepared_local_direct, preserved_transaction, ContinuedLocalDirect,
        LiveDirectBinding, LocalPreparation, PreparedLocalDirect,
    },
};
use crate::xmpp::frame_execution::Stage;
use crate::xmpp::xml_util::*;
use crate::{
    security::abuse::{
        MessageAdmissionLease, MessageAdmissionRequest, MessageAdmissionStart, PowProof,
    },
    state::bare_jid,
};
use anyhow::Result;
use northstar_message_application::{
    direct_commit::TransactionOutcome,
    direct_lifecycle::{OriginalAdmission, PreparationAdmission},
};
pub(crate) use northstar_message_core::{
    bare_message_route, durable_direct_delivery_allowed, full_no_match_route,
    missing_user_message_should_error, undelivered_disposition, BareMessageRoute,
    DirectDeliveryMode, FullNoMatchRoute, UndeliveredDisposition,
};
use roxmltree::Node;
use std::{future::Future, sync::atomic::Ordering};

mod message_delivery;

#[cfg(test)]
mod saved_case;

/// One validated original. Rating is selected here by the existing predicate;
/// callers cannot manufacture a no-admission branch by supplying a boolean.
struct OriginalDirectMessage<'a> {
    actor_id: uuid::Uuid,
    sender: &'a str,
    target: &'a str,
    message_type: &'a str,
    routed_raw: &'a str,
    origin_id: Option<String>,
    stanza_id: Option<&'a str>,
    admission: OriginalAdmissionKind,
}

enum OriginalAdmissionKind {
    Rated(String),
    NoAdmissionRequired,
}

impl<'a> OriginalDirectMessage<'a> {
    fn capture(
        root: Node<'a, '_>,
        actor_id: uuid::Uuid,
        sender: &'a str,
        target: &'a str,
        routed_raw: &'a str,
    ) -> Self {
        let admission = if is_abuse_rated_message(root) {
            OriginalAdmissionKind::Rated(set_root_attribute(
                &set_from(routed_raw, bare_jid(sender)),
                "to",
                target,
            ))
        } else {
            OriginalAdmissionKind::NoAdmissionRequired
        };
        Self {
            actor_id,
            sender,
            target,
            message_type: root.attribute("type").unwrap_or("normal"),
            routed_raw,
            origin_id: direct_origin_id(root),
            stanza_id: root.attribute("id"),
            admission,
        }
    }
    fn rated_payload(&self) -> Option<&str> {
        match &self.admission {
            OriginalAdmissionKind::Rated(payload) => Some(payload),
            OriginalAdmissionKind::NoAdmissionRequired => None,
        }
    }
    fn project_local<'b>(
        &'b self,
        authority: LocalProjectionAuthority<'b>,
        encrypted: bool,
        retraction: Option<&str>,
    ) -> LocalOriginalProjection<'a, 'b> {
        // These transformations stay at their original local preparation point,
        // after generated stanza IDs and before the original policy awaits.
        let rewritten = set_from(self.routed_raw, self.sender);
        let routed = strip_stanza_ids_by_domain(&rewritten, authority.domain);
        let sender_archive = add_stanza_id(
            &rewritten,
            bare_jid(self.sender),
            authority.sender_stable_id,
        );
        let recipient_delivery = if authority.recipient_id == self.actor_id {
            sender_archive.clone()
        } else {
            add_stanza_id(
                &routed,
                authority.recipient_bare,
                authority.recipient_stable_id,
            )
        };
        let archive = |stanza: &str| {
            if encrypted {
                if let Some(target) = retraction {
                    super::retractions::encrypted_retraction_archive(stanza, target)
                } else {
                    encrypted_archive_stanza(stanza)
                }
            } else {
                stanza.to_owned()
            }
        };
        let sender_archive_stanza = archive(&sender_archive);
        let recipient_archive_stanza = archive(&recipient_delivery);
        LocalOriginalProjection {
            source: self,
            authority,
            encrypted,
            rewritten,
            sender_archive,
            recipient_delivery,
            sender_archive_stanza,
            recipient_archive_stanza,
        }
    }
}

struct LocalProjectionAuthority<'a> {
    recipient_id: uuid::Uuid,
    recipient_bare: &'a str,
    sender_stable_id: uuid::Uuid,
    recipient_stable_id: uuid::Uuid,
    domain: &'a str,
}

struct LocalOriginalProjection<'source, 'a> {
    source: &'a OriginalDirectMessage<'source>,
    authority: LocalProjectionAuthority<'a>,
    encrypted: bool,
    rewritten: String,
    sender_archive: String,
    recipient_delivery: String,
    sender_archive_stanza: String,
    recipient_archive_stanza: String,
}

struct DelayedLocalProjection<'source, 'local, 'a> {
    local: &'a LocalOriginalProjection<'source, 'local>,
    stanza: String,
    archive_policy: LocalArchivePolicy,
}

#[derive(Clone, Copy, Default)]
struct LocalArchivePolicy {
    sender_enabled: bool,
    recipient_enabled: bool,
}

#[cfg(test)]
mod direct_preparation_tests;

impl<'source, 'local> LocalOriginalProjection<'source, 'local> {
    fn delayed(
        &self,
        at: chrono::DateTime<chrono::Utc>,
        archive_policy: LocalArchivePolicy,
    ) -> DelayedLocalProjection<'source, 'local, '_> {
        DelayedLocalProjection {
            local: self,
            stanza: add_delay_from(&self.recipient_delivery, at, Some(self.authority.domain)),
            archive_policy,
        }
    }
}

impl<'source, 'local, 'live> DelayedLocalProjection<'source, 'local, 'live> {
    fn bind<'a>(
        &self,
        owner: DirectOperationHandle,
        command: ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
    ) -> Result<PreparedLocalDirect<'a, 'live>> {
        let source = self.local.source;
        let authority = &self.local.authority;
        let PersonalMessageDestination::Local(destination) = command.destination else {
            anyhow::bail!("prepared direct is not local");
        };
        anyhow::ensure!(
            destination.recipient_id == authority.recipient_id
                && destination.delivery_id == authority.recipient_stable_id
                && destination.encrypted == self.local.encrypted
                && destination.mam_backed == self.archive_policy.recipient_enabled,
            "prepared direct destination mismatch"
        );
        let expected_owners = [
            self.archive_policy
                .sender_enabled
                .then_some(source.actor_id),
            (self.archive_policy.recipient_enabled && authority.recipient_id != source.actor_id)
                .then_some(authority.recipient_id),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        anyhow::ensure!(
            command.archives.len() == expected_owners.len(),
            "prepared direct archive set mismatch"
        );
        for (projection, expected_owner) in command.archives.iter().zip(expected_owners) {
            anyhow::ensure!(
                projection.owner_id == expected_owner,
                "prepared direct archive order/owner mismatch"
            );
            let (id, peer, stanza) = if projection.owner_id == source.actor_id {
                (
                    authority.sender_stable_id,
                    source.target,
                    self.local.sender_archive_stanza.as_str(),
                )
            } else if projection.owner_id == authority.recipient_id {
                (
                    authority.recipient_stable_id,
                    source.sender,
                    self.local.recipient_archive_stanza.as_str(),
                )
            } else {
                anyhow::bail!("prepared direct archive owner mismatch");
            };
            anyhow::ensure!(
                projection.id == id
                    && projection.peer_jid == peer
                    && projection.stanza == stanza
                    && projection.encrypted == self.local.encrypted
                    && projection.stanza_id == source.stanza_id,
                "prepared direct archive projection mismatch"
            );
        }
        let admission = match &source.admission {
            OriginalAdmissionKind::Rated(payload) => {
                PreparationAdmission::Rated(OriginalAdmission {
                    actor_id: source.actor_id,
                    account_bare: bare_jid(source.sender),
                    normalized_target: source.target,
                    origin_id: source.origin_id.as_deref(),
                    normalized_payload: payload,
                })
            }
            OriginalAdmissionKind::NoAdmissionRequired => PreparationAdmission::NoAdmissionRequired,
        };
        PreparedLocalDirect::bind(
            owner,
            LocalPreparation {
                actor_id: source.actor_id,
                sender_bare: bare_jid(source.sender),
                sender_full: source.sender,
                target_bare: bare_jid(source.target),
                target_full: source.target,
                message_type: source.message_type,
                live_stanza: &self.local.recipient_delivery,
                origin_id: source.origin_id.as_deref(),
                identity_payload: &self.local.rewritten,
                stored_stanza: &self.stanza,
                admission,
            },
            command,
            eligibility,
            LiveDirectBinding {
                sender: source.sender,
                target: source.target,
                target_bare: bare_jid(source.target),
                message_type: source.message_type,
                stanza: &self.local.recipient_delivery,
                recipient_id: authority.recipient_id,
            },
        )
    }
}

fn mixes_personal_retraction_and_direct_invite(root: Node<'_, '_>) -> bool {
    let has_retraction = root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "retract"
            && node.tag_name().namespace() == Some("urn:xmpp:message-retract:1")
    });
    has_retraction
        && root.children().any(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:conference")
        })
}

/// A degraded cluster can only accept a durable bare-account direct message.
/// The recipient spool is account scoped; an exact resource or an invitation
/// cannot be represented by that authority while Redis is unavailable.
fn degraded_local_direct_eligible(
    root: Node<'_, '_>,
    bare_target: bool,
    personal_retraction: bool,
    archive_requires_encryption: bool,
) -> bool {
    bare_target
        && matches!(
            root.attribute("type").unwrap_or("normal"),
            "normal" | "chat"
        )
        && !personal_retraction
        && !root.children().any(|node| {
            node.is_element()
                && ((node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("jabber:x:conference"))
                    || (node.tag_name().name() == "pubsub"
                        && node.tag_name().namespace()
                            == Some("http://jabber.org/protocol/pubsub")))
        })
        && !signal_only_direct_message(root)
        && direct_delivery_mode(root) == DirectDeliveryMode::Durable
        && (!archive_requires_encryption || is_encrypted(root))
}

/// An explicit store hint does not turn a receipt/chat-state signal into
/// ordinary direct content for degraded admission.
fn signal_only_direct_message(root: Node<'_, '_>) -> bool {
    let mut signal = false;
    for node in root.children().filter(|node| node.is_element()) {
        let namespace = node.tag_name().namespace().unwrap_or_default();
        let name = node.tag_name().name();
        let is_signal = (namespace == "http://jabber.org/protocol/chatstates"
            && matches!(
                name,
                "active" | "composing" | "paused" | "inactive" | "gone"
            ))
            || (namespace == "urn:xmpp:receipts" && name == "received")
            || (namespace == "urn:xmpp:chat-markers:0" && matches!(name, "markable" | "displayed"));
        if is_signal {
            signal = true;
            continue;
        }
        if namespace == "urn:xmpp:hints"
            || (matches!(namespace, "" | "jabber:client") && name == "thread")
            || namespace == "urn:xmpp:sid:0"
            || (namespace == "urn:northstar:pow:1" && name == "pow")
        {
            continue;
        }
        return false;
    }
    signal
}

fn direct_spool_eligibility(
    stanza_eligible: bool,
    account_default_privacy_permits: bool,
) -> DirectSpoolEligibility {
    if stanza_eligible && account_default_privacy_permits {
        DirectSpoolEligibility::Eligible
    } else {
        DirectSpoolEligibility::LiveOnly
    }
}

/// An outbox wake is only a hint to process a row that has already committed.
/// A failed or replayed admission must never send a new wake to the worker.
async fn wake_federation_outbox_after_commit<F, W>(
    commit: F,
    wake: W,
) -> Result<DurableAdmissionOutcome>
where
    F: Future<Output = Result<DurableAdmissionOutcome>>,
    W: FnOnce(),
{
    let outcome = commit.await?;
    if matches!(
        outcome,
        DurableAdmissionOutcome::Stored {
            post_commit: MessagePostCommit::WakeFederationOutbox,
            ..
        }
    ) {
        wake();
    }
    Ok(outcome)
}

impl ProtocolSession {
    /// Ordinary controlled tests use the actual frame owner without constructing
    /// a session. The returned runner owns observation before child polling.
    #[cfg(test)]
    pub(crate) fn retained_direct_frame_for_test<C, F, T>(
        child: C,
    ) -> (
        DirectOperationHandle,
        impl Future<Output = std::result::Result<T, crate::xmpp::frame_execution::FrameFailure>>,
    )
    where
        C: FnOnce(DirectOperationHandle) -> F,
        F: Future<Output = Result<T>>,
    {
        let execution = crate::xmpp::frame_execution::FrameExecution::new(
            super::ClientTransport::Tcp,
            direct_preparation_tests::FRAME_MESSAGE,
        );
        let operation = execution.direct_operation();
        let future = child(operation.clone());
        (operation, execution.run(future))
    }

    async fn finalize_message_admission(
        &self,
        lease: &mut Option<MessageAdmissionLease>,
        route: &'static str,
    ) {
        crate::services::message_admission::finalize_message_admission_with(
            self.state.message_admission_service(),
            lease,
            route,
            || self.message_operation(),
            || self.enter_frame_stage(Stage::MessageFollowup),
            || self.state.personal_message_telemetry().post_accept_failed(),
        )
        .await;
    }

    async fn direct_invite_admission(
        &self,
        root: Node<'_, '_>,
        inviter_id: uuid::Uuid,
    ) -> Result<DirectInviteAdmission> {
        let Some(room_jid) = root
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("jabber:x:conference")
            })
            .and_then(|node| node.attribute("jid"))
            .and_then(|jid| crate::jid::CanonicalJid::parse_bare(jid).ok())
            .filter(|jid| jid.domainpart() == self.muc_domain() && jid.localpart().is_some())
        else {
            return Ok(DirectInviteAdmission::None);
        };
        let Some(room) = self
            .state
            .muc_service()
            .room(
                room_jid
                    .localpart()
                    .expect("validated MUC room has a localpart"),
            )
            .await?
        else {
            return Ok(DirectInviteAdmission::None);
        };
        if !room.members_only {
            return Ok(DirectInviteAdmission::None);
        }
        let affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, inviter_id)
            .await?;
        Ok(
            if affiliation
                .as_deref()
                .is_some_and(|value| matches!(value, "owner" | "admin" | "member"))
            {
                DirectInviteAdmission::MembersOnly {
                    room_id: room.id,
                    room_epoch: room.room_epoch,
                    config_version: room.config_version,
                }
            } else {
                DirectInviteAdmission::Forbidden
            },
        )
    }

    pub(crate) async fn send_sent_carbons(
        &self,
        from: &str,
        forwarded: &str,
        delivered_self: Option<&str>,
        muc_scope: Option<(&str, &str)>,
    ) {
        crate::services::message_carbons::send_sent_carbons(
            &*self.state,
            from,
            forwarded,
            delivered_self,
            muc_scope,
        )
        .await;
    }

    pub(crate) async fn send_received_carbons(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        crate::services::message_carbons::send_received_carbons(
            &*self.state,
            recipient,
            delivered,
            forwarded,
        )
        .await;
    }
}

fn direct_origin_id(root: Node<'_, '_>) -> Option<String> {
    root.children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "origin-id"
                && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
        })
        .and_then(|node| node.attribute("id"))
        .map(str::to_owned)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectInviteAdmission {
    None,
    MembersOnly {
        room_id: uuid::Uuid,
        room_epoch: uuid::Uuid,
        config_version: i64,
    },
    Forbidden,
}

/// RFC 6120 forbids generating a stanza error in response to a stanza that
/// is already of type `error`. Keep that invariant at every rejection point
/// in the message pipeline, including policy and federation failures.
fn message_error(root: Node<'_, '_>, error_type: &str, condition: &str) -> Action {
    if root.attribute("type") == Some("error") {
        Action::None
    } else {
        Action::Send(stanza_error(root, error_type, condition))
    }
}

fn message_blocked_error(root: Node<'_, '_>) -> Action {
    if root.attribute("type") == Some("error") {
        Action::None
    } else {
        Action::Send(blocked_stanza_error(root))
    }
}

#[cfg(test)]
fn offline_storage_eligible(root: Node<'_, '_>) -> bool {
    matches!(
        root.attribute("type").unwrap_or("normal"),
        "normal" | "chat"
    )
}

/// Classify direct messages without conflating an explicit XEP-0334 privacy
/// request with the protocol defaults for ephemeral signal-only messages.
pub(crate) fn direct_delivery_mode(root: Node<'_, '_>) -> DirectDeliveryMode {
    northstar_message_core::classify_direct_delivery(
        has_explicit_no_store_hint(root),
        offline_storage_permitted(root),
    )
}

/// Return the exact client-controlled commitment used by PoW v2. Routing uses
/// a separate server-authoritative stanza whose `from` and inherited
/// `xml:lang` may have been materialized at dispatch. Those assertions must
/// never become bytes the client is required to predict.
fn message_pow_intent_payload(client_raw: &str) -> String {
    strip_untrusted_direct_delays(&strip_pow_element(client_raw), None)
}

#[cfg(test)]
mod tests;
