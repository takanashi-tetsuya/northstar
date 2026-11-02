//! XEP-0369 MIX Core, XEP-0405 MIX-PAM, and XEP-0406 MIX Administration.
//!
//! MIX channel nodes intentionally use their own persistence and permission
//! checks.  They are not exposed through the general-purpose PubSub service:
//! in particular, clients cannot publish participant, configuration, allowed,
//! or banned items without going through the MIX authorization model.

pub mod channel_delivery;
pub mod channel_iq;
pub mod channel_mam;
pub mod channel_pubsub;
pub mod claimed;
pub mod federation;
pub mod forms;
pub mod iq_parse;
pub mod local_delivery;
pub mod message;
pub mod payloads;
pub mod ports;
pub mod presence;
pub mod relay;
pub mod session;
pub mod worker;

use self::channel_delivery::{
    addressed_mix_delivery, deliver_channel_stanza, deliver_claimed_channel_stanza,
    ChannelStanzaDatabaseLane, ChannelStanzaDelivery, ChannelStanzaDeliveryOutcome,
};
use self::channel_iq::{handle_channel_iq, join_error};
use self::channel_mam::handle_mix_mam_iq;
use self::channel_pubsub::{
    field_first, pubsub_get, pubsub_publish, pubsub_retract, validate_form_fields,
    PubSubRetractRequest,
};
use self::claimed::{
    cancellable_mix_outbox_turn, drainable_mix_outbox_claim, mix_outbox_deadline_elapsed,
    mix_outbox_is_shutting_down, process_claimed_mix_delivery, process_claimed_pam_result,
    record_mix_post_commit_failure,
};
use self::federation::pam_membership_receives;
pub use self::federation::{federated_mix_iq, federated_mix_message, federated_mix_presence};
use self::iq_parse::{
    mix_iq_route_candidate, parse_iq, parse_join, parse_mix_disco_info, IqOperation,
    MixDiscoInfoRequest, OwnedIq,
};
use self::local_delivery::{
    classify_durable_mix_route, permanent_mix_delivery_error, try_send_local_durable_mix,
    try_send_local_durable_mix_observed, DurableMixRouteAvailability, DurableMixRouteDisposition,
    MixDeliveryRoutePending, PermanentMixDeliveryError,
};
use self::message::{
    message_error, process_channel_message, reflected_mix_stanza_id,
    validate_reflected_mix_identity, validate_reflected_mix_presence_identity,
};
use self::payloads::{
    core_join_payload, decode_participant_jid, encoded_participant_jid, mix_empty_pubsub,
    mix_pubsub_publish_ack, pam_join_payload, parse_remote_iq_error, parse_remote_pam_success,
};
pub use self::payloads::{mix_channel_disco_info_payload, mix_service_disco_info_payload};
use self::ports::*;
pub use self::presence::{mix_presence_route_is_current, publish_verified_mix_presence_with};
use self::presence::{presence_children, process_channel_presence};
use self::relay::{
    deliver_mix_relay_stanza, expire_mix_iq_relay, handle_channel_relay_request, parse_relay_iq,
    register_mix_iq_relay, relay_error, relay_iq_xml, relay_vcard_payload, RelayIq,
};
use self::session::push_mix_roster_update;
use anyhow::{Context, Result};
use northstar_federation_core::FederationRoute;
use northstar_room_application::mix_service::outbox;
use northstar_room_application::mix_service::outbox::core as mix_worker;
use northstar_room_application::mix_service::{
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
pub use northstar_room_core::mix::{
    MixSessionCapability, ADMIN_NS, ANON_NS, CORE_NS, MISC_NS, PAM_NS, PRESENCE_NS,
};
use northstar_xep_0313::build_extended_form as mam_extended_form;
use northstar_xep_0359::add_stanza_id;
use northstar_xml_builder::stanza::{
    iq_error_to, iq_result_to, is_encrypted, stanza_error, stanza_error_type,
};
use northstar_xml_builder::XmlElement;
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
pub use worker::start_mix_delivery_outbox;
use worker::*;

use forms::{
    is_xdata, parse_fields, parse_preference_submission, preference_result_form,
    preference_template_form,
};
use futures::{future::BoxFuture, stream::FuturesUnordered, StreamExt};
use northstar_room_core::mix_iq_relay::{MixIqRelayStage, PendingMixIqRelay};
use roxmltree::{Document, Node};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

const PUBSUB_NS: &str = "http://jabber.org/protocol/pubsub";
const MAM_NS: &str = "urn:xmpp:mam:2";
const MAX_CHANNELS_PER_OWNER: i64 = 100;
const MAX_ITEMS_PAGE: i64 = 200;

/// One linearizable correlation budget for every MIX IQ relay. Expiry is
/// drained by a single supervised worker; admission never creates one timer
/// task per untrusted request.
pub use northstar_room_core::mix_iq_relay::MIX_IQ_RELAY_TTL;

fn same_jid_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

pub fn local_mix_domain(local_domain: &str) -> String {
    prepare_domainpart(&format!("mix.{local_domain}"))
        .expect("configured XMPP domain must form a valid MIX service domain")
}

fn local_muc_domain(local_domain: &str) -> String {
    prepare_domainpart(&format!("conference.{local_domain}"))
        .expect("configured XMPP domain must form a valid MUC service domain")
}

pub fn start_mix_iq_relay_expiry(
    context: Arc<impl MixIqRelayExpiryPort>,
    registry: Arc<northstar_runtime::workers::WorkerRegistry>,
    cancel: tokio_util::sync::CancellationToken,
) {
    registry.supervise(
        "mix-iq-relay-expiry",
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::Continuous,
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

pub fn start_mix_presence_recovery(
    context: Arc<impl MixPresenceRecoveryPort>,
    registry: Arc<northstar_runtime::workers::WorkerRegistry>,
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
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::OneShot,
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
                        context.as_ref(),
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
