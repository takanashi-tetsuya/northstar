use super::super::{
    publish_verified_mix_presence_with, same_jid_domain, Arc, CanonicalJid, Context, Duration,
    XmlElement, MIX_IQ_RELAY_TTL,
};
use crate::ports::*;
use northstar_room_application::mix_service::MixPresenceProbeTarget;

pub fn start_mix_presence_recovery(
    context: Arc<impl MixPresenceRecoveryPort>,
    registry: Arc<northstar_runtime::workers::WorkerRegistry>,
    cutoff: northstar_time::DateTime<northstar_time::Utc>,
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
