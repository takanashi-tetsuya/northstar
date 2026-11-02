use crate::ports::{MessageFrameStage, MessageHost, MessageOutcome, MessageSession};
use crate::retractions::{apply_outbound_personal_retraction, apply_personal_retraction};
use anyhow::Result;
use northstar_abuse_policy::message_admission::{MessageAdmissionLease, MessageAdmissionStart};
use northstar_abuse_policy::stanza::{abuse_stanza_error, strip_pow_element};
use northstar_abuse_policy::{MessageAdmissionRequest, PowProof};
use northstar_message_application::message_admission::witness::DirectOperationHandle;
use northstar_message_application::message_carbons::{send_received_carbons, send_sent_carbons};
use northstar_message_application::messaging::direct_workflow::{
    continue_prepared_local_direct, preserved_transaction, ContinuedLocalDirect, LiveDirectBinding,
    LocalPreparation, PreparedLocalDirect,
};
use northstar_message_application::messaging::{
    admit_offline_then_push, ArchiveWrite, DirectMessageRouter, DirectRouteDelivery,
    DirectRouteOutcome, DirectRouteRejection, DirectRouteRequest, DirectRouteTarget,
    DurableAdmissionOutcome, FederationDelivery, FullJidFallbackPort, IdentityAuthority,
    LocalDelivery, LocalMucInviteAdmission, LocalRecipientDecision, MessageIdentity,
    MessagePostCommit, OfflineAdmissionOutcome, OutboundPolicyDecision, PersonalMessageDestination,
    RemoteMucInviteAdmission, RemoteMucInviteAdmissionOutcome, ValidatedPersonalMessage,
};
use northstar_message_application::retractions::{DeliveryProjection, RetractionOutcome};
use northstar_message_application::{
    direct_commit::TransactionOutcome,
    direct_lifecycle::{OriginalAdmission, PreparationAdmission},
};
use northstar_message_core::direct_delivery_mode;
use northstar_message_core::retraction::retraction_target;
use northstar_message_core::validation::strip_untrusted_direct_delays;
use northstar_message_core::{
    bare_message_route, durable_direct_delivery_allowed, full_no_match_route,
    missing_user_message_should_error, undelivered_disposition, BareMessageRoute,
    DirectDeliveryMode, DirectPostCommitMode, DirectSpoolEligibility, FullNoMatchRoute,
    UndeliveredDisposition,
};
use northstar_room_core::{ClusterMucAffiliationSubject, DurableMucInviteOutcome};
use northstar_xep_0280::should_copy as should_carbon;
use northstar_xep_0359::{add_stanza_id, strip_stanza_ids_by_domain};
use northstar_xml_builder::message_policy::{
    add_delay_from, encrypted_archive_stanza, encrypted_retraction_archive_stanza,
    has_explicit_no_store_hint, is_abuse_rated_message, mam_storage_eligible,
    offline_storage_permitted,
};
use northstar_xml_builder::rewrite::{set_from, set_root_attribute};
use northstar_xml_builder::stanza::{
    blocked_stanza_error, is_encrypted, stanza_error, stanza_error_type,
};
use northstar_xmpp_types::jid_text::bare_jid;
use roxmltree::Node;
use std::future::Future;

mod message_delivery;
mod projection;

pub use self::message_delivery::message;
use self::projection::*;

/// What the root crate's tests over the real outbound queue need to prepare an original.
#[cfg(any(test, feature = "test-support"))]
pub mod preparation_fixture {
    pub use super::projection::{
        direct_spool_eligibility, DelayedLocalProjection, LocalArchivePolicy,
        LocalOriginalProjection, LocalProjectionAuthority, OriginalDirectMessage,
    };
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

async fn finalize_message_admission<S: MessageSession>(
    session: &S,
    lease: &mut Option<MessageAdmissionLease>,
    route: &'static str,
) {
    let state = session.host();
    northstar_message_application::message_admission::finalize_message_admission_with(
        state.message_admission_service(),
        lease,
        route,
        || session.message_operation(),
        || session.enter_frame_stage(MessageFrameStage::Followup),
        || state.personal_message_telemetry().post_accept_failed(),
    )
    .await;
}

async fn direct_invite_admission<S: MessageSession>(
    session: &S,
    root: Node<'_, '_>,
    inviter_id: uuid::Uuid,
) -> Result<DirectInviteAdmission> {
    let state = session.host();
    let Some(room_jid) = root
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:conference")
        })
        .and_then(|node| node.attribute("jid"))
        .and_then(|jid| northstar_xmpp_types::jid::CanonicalJid::parse_bare(jid).ok())
        .filter(|jid| jid.domainpart() == session.muc_domain() && jid.localpart().is_some())
    else {
        return Ok(DirectInviteAdmission::None);
    };
    let Some(room) = state
        .direct_invite_room(
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
    let affiliation = state.direct_invite_affiliation(room.id, inviter_id).await?;
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
fn message_error<A: MessageOutcome>(root: Node<'_, '_>, error_type: &str, condition: &str) -> A {
    if root.attribute("type") == Some("error") {
        A::none()
    } else {
        A::send(stanza_error(root, error_type, condition))
    }
}

fn message_blocked_error<A: MessageOutcome>(root: Node<'_, '_>) -> A {
    if root.attribute("type") == Some("error") {
        A::none()
    } else {
        A::send(blocked_stanza_error(root))
    }
}

#[cfg(test)]
fn offline_storage_eligible(root: Node<'_, '_>) -> bool {
    matches!(
        root.attribute("type").unwrap_or("normal"),
        "normal" | "chat"
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
