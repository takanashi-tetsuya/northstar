//! XEP-0369 MIX Core, XEP-0405 MIX-PAM, and XEP-0406 MIX Administration.
//!
//! MIX channel nodes intentionally use their own persistence and permission
//! checks.  They are not exposed through the general-purpose PubSub service:
//! in particular, clients cannot publish participant, configuration, allowed,
//! or banned items without going through the MIX authorization model.

mod channel_delivery;
mod channel_iq;
mod channel_mam;
mod channel_pubsub;
mod claimed;
mod federation;
mod forms;
mod iq_parse;
mod local_delivery;
mod message;
mod payloads;
mod presence;
mod relay;
mod session;
#[cfg(test)]
pub(crate) mod stage4_saved;
mod worker;

use self::channel_delivery::{
    addressed_mix_delivery, deliver_channel_stanza, deliver_claimed_channel_stanza,
    ChannelStanzaDatabaseLane, ChannelStanzaDelivery, ChannelStanzaDeliveryOutcome,
};
#[cfg(test)]
use self::channel_delivery::{finish_mix_delivery_owner, record_claimed_cluster_result};
use self::channel_iq::{handle_channel_iq, join_error};
use self::channel_mam::handle_mix_mam_iq;
use self::channel_pubsub::{
    field_first, pubsub_get, pubsub_publish, pubsub_retract, validate_form_fields,
    PubSubRetractRequest,
};
#[cfg(test)]
use self::claimed::{
    bounded_mix_outbox_turn, process_claimed_mix_delivery_with_port,
    run_claimed_mix_effect_with_lease, ClaimedMixDeliveryPort, MixOutboxDeadlineElapsed,
    MixOutboxShutdown,
};
use self::claimed::{
    cancellable_mix_outbox_turn, drainable_mix_outbox_claim, mix_outbox_deadline_elapsed,
    mix_outbox_is_shutting_down, process_claimed_mix_delivery, process_claimed_pam_result,
    record_mix_post_commit_failure,
};
use self::federation::pam_membership_receives;
#[cfg(test)]
use self::federation::{
    authenticated_actor, authenticated_full_actor, authenticated_mix_service,
    federated_mix_iq_is_mutation, AuthenticatedMixIqActor,
};
pub(crate) use self::federation::{
    federated_mix_iq, federated_mix_message, federated_mix_presence,
};
use self::iq_parse::{
    mix_iq_route_candidate, parse_iq, parse_join, parse_mix_disco_info, IqOperation,
    MixDiscoInfoRequest, OwnedIq,
};
#[cfg(test)]
use self::local_delivery::MixLocalTransportFailure;
use self::local_delivery::{
    classify_durable_mix_route, permanent_mix_delivery_error, try_send_local_durable_mix,
    try_send_local_durable_mix_observed, DurableMixRouteAvailability, DurableMixRouteDisposition,
    MixDeliveryRoutePending, PermanentMixDeliveryError,
};
#[cfg(test)]
use self::message::{
    message_children, mix_replay_semantics, mix_retraction_target, private_message_children,
};
use self::message::{
    message_error, process_channel_message, reflected_mix_stanza_id,
    validate_reflected_mix_identity, validate_reflected_mix_presence_identity,
};
#[cfg(test)]
use self::payloads::parse_remote_join_result;
use self::payloads::{
    core_join_payload, decode_participant_jid, encoded_participant_jid, mix_empty_pubsub,
    mix_pubsub_publish_ack, pam_join_payload, parse_remote_iq_error, parse_remote_pam_success,
};
pub(crate) use self::payloads::{mix_channel_disco_info_payload, mix_service_disco_info_payload};
pub(crate) use self::presence::{
    mix_presence_route_is_current, publish_verified_mix_presence_with,
};
use self::presence::{presence_children, process_channel_presence};
use self::relay::{
    deliver_mix_relay_stanza, expire_mix_iq_relay, handle_channel_relay_request, parse_relay_iq,
    register_mix_iq_relay, relay_error, relay_iq_xml, relay_vcard_payload, RelayIq,
};
#[cfg(test)]
use self::relay::{encoded_participant_full_jid, RelayPayload};
use self::session::push_mix_roster_update;
#[cfg(test)]
use self::session::{mix_broadcast_presence_action, MixBroadcastPresenceAction};
use super::{Action, ProtocolSession};
use crate::jid::{prepare_domainpart, CanonicalJid};
use crate::services::mix::outbox::{self, core as mix_worker};
use crate::services::mix::{
    ArchiveBoundary, BeginRemotePamJoin, BeginRemotePamLeave, ClaimedPamResult,
    CreateChannelOutcome, FederatedMixIqReplay, FederatedMixMutation, JoinChannelOutcome,
    JoinMixRequest, MamArchiveQuery, MixAccessEntryOperation, MixAccessEntryUpdate, MixAccessList,
    MixBusinessReplay, MixChannel, MixConfigUpdate, MixEvent, MixInfoUpdate, MixInvitationProof,
    MixMutationOutcome, MixParticipant, MixParticipantPreference, MixPresenceProbeTarget,
    MixReadOutcome, MixReplayIdentity, MixRoleUpdate, PamMembership, PamOperationReplay,
    PresenceOutcome, RegisterMixNickOutcome, RemotePamCompletionOutcome, RemotePamJoin,
    RetractMixMessageOutcome, RetractMixMessageRequest, SetNickError, SourceArchiveAdmission,
    StoreEventOutcome, StoreMixMessageRequest, ALL_NODES, NODE_ALLOWED, NODE_AVATAR_DATA,
    NODE_AVATAR_METADATA, NODE_BANNED, NODE_CONFIG, NODE_INFO, NODE_JIDMAP, NODE_MESSAGES,
    NODE_PRESENCE,
};
use crate::state::mix_iq_relay::{MixIqRelayExpiryContext, MixIqRelayRoute};
use crate::state::mix_outbox::MixOutboxContext;
use crate::state::mix_presence_recovery::MixPresenceRecoveryContext;
use crate::state::{AppState, MixIqRelayStage, PendingMixIqRelay};
use crate::xmpp::frame_execution::{SessionExecutions, Stage};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::{
    add_stanza_id, iq_error_to, iq_result_to, is_encrypted, mam_extended_form, stanza_error,
    stanza_error_type,
};
use anyhow::{Context, Result};
pub(crate) use worker::start_mix_delivery_outbox;
use worker::*;

use forms::{
    is_xdata, parse_fields, parse_preference_submission, preference_result_form,
    preference_template_form,
};
use futures::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(test)]
use crate::state::{mix_presence_epoch_is_current, mix_presence_fallback_is_suppressed};

pub(crate) const CORE_NS: &str = "urn:xmpp:mix:core:1";
pub(crate) const PAM_NS: &str = "urn:xmpp:mix:pam:2";
pub(crate) const ADMIN_NS: &str = "urn:xmpp:mix:admin:0";
pub(crate) const PRESENCE_NS: &str = "urn:xmpp:mix:presence:0";
pub(crate) const ANON_NS: &str = "urn:xmpp:mix:anon:0";
pub(crate) const MISC_NS: &str = "urn:xmpp:mix:misc:0";
const PUBSUB_NS: &str = "http://jabber.org/protocol/pubsub";
const MAM_NS: &str = "urn:xmpp:mam:2";
const MAX_CHANNELS_PER_OWNER: i64 = 100;
const MAX_ITEMS_PAGE: i64 = 200;

/// One linearizable correlation budget for every MIX IQ relay. Expiry is
/// drained by a single supervised worker; admission never creates one timer
/// task per untrusted request.
#[allow(unused_imports)]
pub(crate) use northstar_protocol_runtime::mix::MixIqRelayIndex;
pub(crate) use northstar_protocol_runtime::mix::MIX_IQ_RELAY_TTL;

fn same_jid_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

fn local_mix_domain(state: &AppState) -> String {
    prepare_domainpart(&format!("mix.{}", state.local_domain()))
        .expect("configured XMPP domain must form a valid MIX service domain")
}

fn local_muc_domain(state: &AppState) -> String {
    prepare_domainpart(&format!("conference.{}", state.local_domain()))
        .expect("configured XMPP domain must form a valid MUC service domain")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MixSessionCapability {
    Supported,
    Unsupported,
    Unknown,
}

pub(crate) fn session_mix_capability(state: &AppState, full_jid: &str) -> MixSessionCapability {
    match super::caps::verified_caps_has_any_feature(state, full_jid, &[CORE_NS, PAM_NS]) {
        Some(true) => MixSessionCapability::Supported,
        Some(false) => MixSessionCapability::Unsupported,
        None => MixSessionCapability::Unknown,
    }
}

pub(crate) fn start_mix_iq_relay_expiry(
    context: Arc<MixIqRelayExpiryContext>,
    registry: Arc<crate::workers::WorkerRegistry>,
    cancel: tokio_util::sync::CancellationToken,
) {
    registry.supervise(
        "mix-iq-relay-expiry",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(10)),
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let cancel = cancel.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(250));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = interval.tick() => {
                            for pending in context.take_expired(Instant::now()) {
                                expire_mix_iq_relay(context.route(), pending).await;
                            }
                            heartbeat.ok();
                        }
                    }
                }
            }
        },
    );
}

pub(crate) fn start_mix_presence_recovery(
    context: Arc<MixPresenceRecoveryContext>,
    registry: Arc<crate::workers::WorkerRegistry>,
    cutoff: chrono::DateTime<chrono::Utc>,
    // The state layer snapshots these targets straight from its own
    // repository query; the persistence-type conversion happens on this
    // boundary so the protocol never names the storage DTO.
    probes: impl IntoIterator<Item = impl Into<MixPresenceProbeTarget>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let probes: Vec<MixPresenceProbeTarget> = probes.into_iter().map(Into::into).collect();
    registry.supervise(
        "mix-presence-recovery",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::OneShot,
        Some(Duration::from_secs(90)),
        cancel,
        move |heartbeat| {
            let context = Arc::clone(&context);
            let probes = probes.clone();
            async move {
        for probe in probes {
            let Ok(participant) = CanonicalJid::parse_bare(&probe.participant_jid) else {
                tracing::warn!(participant = %probe.participant_jid, "ignored malformed persisted MIX participant JID");
                continue;
            };
            let domain = participant.domainpart();
            if same_jid_domain(domain, context.local_domain()) {
                for (full_jid, connection_id, caps_generation) in context.routes().local_epochs(&probe.participant_jid) {
                    publish_verified_mix_presence_with(
                        &context,
                        &full_jid,
                        connection_id,
                        caps_generation,
                    )
                    .await?;
                }
                continue;
            }
            if !context.federation_domain_allowed(domain) { continue; }
            let stanza = XmlElement::namespaced("presence", "jabber:client")
                .attr("type", "probe")
                .attr("from", &probe.channel_jid)
                .attr("to", &probe.participant_jid)
                .finish();
            context.send_federated(domain, stanza, None).await;
        }
        // The deadline is intentionally short and bounded: a remote resource
        // that cannot answer a startup probe is no longer authoritative
        // current state. A later available presence recreates the item.
        tokio::time::sleep(MIX_IQ_RELAY_TTL).await;
        let _expired_count = match context.expire_unrefreshed(cutoff).await {
            Ok(expired) => expired,
            Err(error) => {
                return Err(error).context("failed to expire unrefreshed MIX presence");
            }
        };
        // Expiry and every unavailable projection were committed atomically;
        // the delivery worker owns transport retries.
        heartbeat.ok();
        Ok(())
            }
        },
    );
}

#[cfg(test)]
#[path = "mix_tests.rs"]
mod tests;

#[cfg(test)]
mod shared_claimed_delivery_policy_tests;
