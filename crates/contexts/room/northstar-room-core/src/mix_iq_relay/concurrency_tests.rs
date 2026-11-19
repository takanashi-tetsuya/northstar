use super::{MixIqRelayIndex, MixIqRelayStage};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn relay_stage(seed: usize) -> MixIqRelayStage {
    MixIqRelayStage::Participant {
        requester_full_jid: format!("alice@example.test/{seed}"),
        original_id: format!("original-{seed}"),
        expected_from: "channel@mix.example.test".to_owned(),
        channel_jid: "channel@mix.example.test".to_owned(),
    }
}

#[test]
fn mix_iq_relay_admission_is_concurrently_hard_bounded() {
    let limit = 8;
    let workers = 64;
    let index = Arc::new(MixIqRelayIndex::with_limits(limit, Duration::from_secs(30)));
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let mut threads = Vec::new();
    for seed in 0..workers {
        let index = Arc::clone(&index);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            index.admit(format!("relay-{seed}"), relay_stage(seed), Instant::now())
        }));
    }
    let admitted = threads
        .into_iter()
        .map(|thread| thread.join().expect("MIX relay worker panicked"))
        .filter(|admitted| *admitted)
        .count();
    assert_eq!(admitted, limit);
    assert_eq!(index.len(), limit);
}

#[test]
fn mix_iq_relay_expiry_has_one_exact_consumer() {
    let index = MixIqRelayIndex::with_limits(2, Duration::ZERO);
    assert!(index.admit("relay".to_owned(), relay_stage(1), Instant::now()));
    assert_eq!(index.take_expired(Instant::now()).len(), 1);
    assert!(index.take_expired(Instant::now()).is_empty());
    assert_eq!(index.len(), 0);
}

#[test]
fn mix_iq_relay_response_and_expiry_cannot_both_claim_one_id() {
    let index = Arc::new(MixIqRelayIndex::with_limits(2, Duration::ZERO));
    assert!(index.admit("relay".to_owned(), relay_stage(1), Instant::now()));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let response_index = Arc::clone(&index);
    let response_barrier = Arc::clone(&barrier);
    let response = std::thread::spawn(move || {
        response_barrier.wait();
        response_index.remove("relay").is_some()
    });
    barrier.wait();
    let expired = index.take_expired(Instant::now()).len();
    let responded = response.join().expect("MIX response worker panicked");
    assert_eq!(expired + usize::from(responded), 1);
    assert!(index.is_empty());
}
