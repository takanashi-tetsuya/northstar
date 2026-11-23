use super::super::{expire_mix_iq_relay, Arc, Duration, Instant, MixIqRelayExpiryPort};

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
