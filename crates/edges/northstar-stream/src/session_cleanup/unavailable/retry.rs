use anyhow::Result;
use futures::{stream, StreamExt};
use northstar_session_application::sm_teardown_presence::ExactPresenceAcceptance;
use std::{fmt::Debug, future::Future};

pub(super) async fn publish_remaining<T, F>(
    mut pending: Vec<T>,
    send: impl Fn(T) -> F,
) -> Result<()>
where
    T: Debug,
    F: Future<Output = (T, Result<ExactPresenceAcceptance>)>,
{
    let mut unknown = false;
    for _ in 0..2 {
        pending = stream::iter(pending)
            .map(&send)
            .buffer_unordered(16)
            .filter_map(|(target, result)| {
                let pending = match result {
                    Ok(ExactPresenceAcceptance::Accepted | ExactPresenceAcceptance::Gone) => None,
                    Ok(ExactPresenceAcceptance::Retry) => Some(target),
                    Ok(ExactPresenceAcceptance::Unknown) => {
                        unknown = true;
                        None
                    }
                    Err(error) => {
                        tracing::warn!(?error, ?target, "terminal presence acceptance is unknown");
                        unknown = true;
                        None
                    }
                };
                std::future::ready(pending)
            })
            .collect()
            .await;
        if pending.is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    anyhow::ensure!(
        pending.is_empty() && !unknown,
        "terminal presence requires refresh"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
