use super::super::{
    same_jid_domain, Arc, CanonicalJid, Context, Duration, XmlElement, MIX_IQ_RELAY_TTL,
};
use crate::ports::*;
use crate::presence::publish_route_presence;
use anyhow::Result;
use northstar_room_application::mix_service::{
    RecoveryEpoch, RecoveryPresenceSource, RecoveryProbeTarget, RecoveryProgress,
    RECOVERY_PRESENCE_PAGE_CAP,
};
use std::future::Future;

const RETRY_MIN: Duration = Duration::from_millis(100);
const RETRY_MAX: Duration = Duration::from_secs(1);

pub fn start_mix_presence_recovery(
    context: Arc<impl MixPresenceRecoveryPort>,
    registry: Arc<northstar_runtime::workers::WorkerRegistry>,
    epoch: RecoveryEpoch,
    probes: Vec<RecoveryProbeTarget>,
    cancel: tokio_util::sync::CancellationToken,
) {
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
                    let participant = CanonicalJid::parse_bare(probe.participant.as_str())?;
                    let domain = participant.domainpart();
                    if same_jid_domain(domain, context.local_domain()) {
                        for (full_jid, connection_id, caps_generation) in
                            context.routes().local_epochs(probe.participant.as_str())
                        {
                            let source = RecoveryPresenceSource::parse(&full_jid)?;
                            publish_route_presence(
                                context.as_ref(),
                                &source,
                                connection_id,
                                caps_generation,
                                Some(epoch),
                            )
                            .await?;
                            heartbeat.ok();
                        }
                    } else if context.federation_domain_allowed(domain) {
                        let stanza = XmlElement::namespaced("presence", "jabber:client")
                            .attr("type", "probe")
                            .attr("from", probe.channel.as_str())
                            .attr("to", probe.participant.as_str())
                            .finish();
                        context.send_federated(domain, stanza, None).await;
                    }
                    heartbeat.ok();
                }
                drain_recovery_pages(
                    |budget| context.expire_recovery_presence_page(epoch, budget),
                    || heartbeat.ok(),
                )
                .await
            }
        },
    );
}

async fn drain_recovery_pages<F: Future<Output = Result<RecoveryProgress>>>(
    mut expire_page: impl FnMut(u32) -> F,
    mut heartbeat: impl FnMut(),
) -> Result<()> {
    tokio::time::sleep(MIX_IQ_RELAY_TTL).await;
    let mut retry = RETRY_MIN;
    loop {
        let progress = expire_page(RECOVERY_PRESENCE_PAGE_CAP)
            .await
            .context("failed to expire unrefreshed MIX presence")?;
        heartbeat();
        if !progress.has_remaining {
            return Ok(());
        }
        if progress.expired == 0 {
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(RETRY_MAX);
        } else {
            retry = RETRY_MIN;
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests;
