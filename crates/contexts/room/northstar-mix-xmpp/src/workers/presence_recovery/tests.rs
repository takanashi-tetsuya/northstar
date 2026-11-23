use super::*;
use std::{cell::Cell, future::ready};
use tokio::time::Instant;

#[tokio::test(start_paused = true)]
async fn recovery_drains_capped_pages_after_the_probe_window() {
    let start = Instant::now();
    let mut calls = Vec::new();
    let heartbeats = Cell::new(0);
    drain_recovery_pages(
        |budget| {
            calls.push((budget, start.elapsed()));
            ready(Ok(RecoveryProgress {
                expired: budget as usize,
                has_remaining: calls.len() < 3,
            }))
        },
        || heartbeats.set(heartbeats.get() + 1),
    )
    .await
    .unwrap();
    assert_eq!(calls, vec![(128, MIX_IQ_RELAY_TTL); 3]);
    assert_eq!(heartbeats.get(), 3);
}

#[tokio::test(start_paused = true)]
async fn recovery_retries_empty_nonterminal_pages_with_capped_backoff() {
    let start = Instant::now();
    let mut calls = Vec::new();
    drain_recovery_pages(
        |budget| {
            assert_eq!(budget, RECOVERY_PRESENCE_PAGE_CAP);
            calls.push(start.elapsed());
            ready(Ok(RecoveryProgress {
                expired: usize::from(calls.len() == 7),
                has_remaining: calls.len() < 9,
            }))
        },
        || {},
    )
    .await
    .unwrap();
    assert_eq!(calls[0], MIX_IQ_RELAY_TTL);
    assert_eq!(
        calls
            .windows(2)
            .map(|pair| (pair[1] - pair[0]).as_millis())
            .collect::<Vec<_>>(),
        [100, 200, 400, 800, 1000, 1000, 0, 100],
    );
}
