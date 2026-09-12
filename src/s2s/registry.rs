use super::{BidiS2sSession, FederationEnvelope, OutboundS2sSession};
use dashmap::{mapref::entry::Entry, DashMap};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Result of atomically publishing a newly-created outbound connection.
/// A live incumbent always wins; a closed incumbent is replaced in-place.
pub(crate) enum OutboundRegistration {
    Inserted,
    Existing(mpsc::Sender<FederationEnvelope>),
}

/// Guard-free snapshot of one bidirectional route. No DashMap guard crosses
/// the registry boundary or survives queue admission.
pub(crate) struct BidiRouteSnapshot {
    pub(crate) local_domain: String,
    pub(crate) sender: mpsc::Sender<FederationEnvelope>,
}

/// A hint belongs to one published, authenticated stream incarnation. The
/// private identity also fences a remove/reinsert which happens to reuse a UUID.
#[derive(Clone)]
pub(crate) struct BidiRecoverySnapshot {
    pub(crate) connection_id: Uuid,
    pub(crate) local_domain: String,
    pub(crate) remote_domain: String,
    pub(crate) sender: mpsc::Sender<FederationEnvelope>,
    pub(crate) disconnect: CancellationToken,
    key: String,
    identity: Arc<()>,
}

/// Facts observed from the real domain head. A leased head has a lock token,
/// including an expired lease: normal claiming must rotate that token.
#[derive(Clone, Copy)]
pub(crate) struct BidiRecoveryHead {
    pub(crate) id: Uuid,
    pub(crate) attempt_count: i32,
    pub(crate) leased: bool,
    pub(crate) due: bool,
    pub(crate) direction_matches: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BidiRecoveryAction {
    Retain,
    Consumed,
    /// The hint is already consumed. Only now may the caller prepare/poll its
    /// exact-head CAS; cancellation or an unknown result cannot reuse the hint.
    RetryHead,
}

#[derive(Default)]
enum BidiRecoveryState {
    #[default]
    Unobserved,
    Bound {
        id: Uuid,
        attempt_count: i32,
    },
    Consumed,
}

impl BidiRecoveryState {
    fn observe(&mut self, head: Option<BidiRecoveryHead>) -> BidiRecoveryAction {
        if matches!(self, Self::Consumed) {
            return BidiRecoveryAction::Consumed;
        }
        let Some(head) = head else {
            *self = Self::Consumed;
            return BidiRecoveryAction::Consumed;
        };
        if !head.direction_matches {
            *self = Self::Consumed;
            return BidiRecoveryAction::Consumed;
        }
        match *self {
            Self::Unobserved => {
                *self = Self::Bound {
                    id: head.id,
                    attempt_count: head.attempt_count,
                };
            }
            Self::Bound { id, attempt_count }
                if id != head.id || attempt_count != head.attempt_count =>
            {
                *self = Self::Consumed;
                return BidiRecoveryAction::Consumed;
            }
            Self::Bound { .. } => {}
            Self::Consumed => unreachable!(),
        }
        if head.leased {
            return BidiRecoveryAction::Retain;
        }
        *self = Self::Consumed;
        if head.due {
            BidiRecoveryAction::Consumed
        } else {
            BidiRecoveryAction::RetryHead
        }
    }
}

struct RegisteredBidi {
    session: BidiS2sSession,
    remote_domain: String,
    identity: Arc<()>,
    recovery: BidiRecoveryState,
}

impl RegisteredBidi {
    fn live(&self) -> bool {
        !self.session.disconnect.is_cancelled() && !self.session.sender.is_closed()
    }

    fn matches(&self, snapshot: &BidiRecoverySnapshot) -> bool {
        self.live()
            && self.session.connection_id == snapshot.connection_id
            && self.session.local_domain == snapshot.local_domain
            && self.remote_domain == snapshot.remote_domain
            && self.session.sender.same_channel(&snapshot.sender)
            && Arc::ptr_eq(&self.identity, &snapshot.identity)
    }
}

/// Process-local ownership boundary for live S2S routes.
///
/// Outbound workers are fenced by their exact mpsc channel identity, while
/// XEP-0288 bidirectional streams are fenced by their server-generated
/// connection UUID. Callers receive cloned senders/snapshots only and can
/// never retain a shard lock or mutate the underlying maps directly.
#[derive(Default)]
pub(crate) struct S2sConnectionRegistry {
    outbound: DashMap<String, OutboundS2sSession>,
    bidirectional: DashMap<String, RegisteredBidi>,
    bidi_recovery_cursor: AtomicUsize,
}

impl S2sConnectionRegistry {
    pub(crate) fn live_outbound_sender(
        &self,
        key: &str,
    ) -> Option<mpsc::Sender<FederationEnvelope>> {
        self.outbound
            .get(key)
            .and_then(|session| (!session.sender.is_closed()).then(|| session.sender.clone()))
    }

    pub(crate) fn register_outbound(
        &self,
        key: String,
        session: OutboundS2sSession,
    ) -> OutboundRegistration {
        match self.outbound.entry(key) {
            Entry::Occupied(entry) if !entry.get().sender.is_closed() => {
                OutboundRegistration::Existing(entry.get().sender.clone())
            }
            Entry::Occupied(mut entry) => {
                entry.insert(session);
                OutboundRegistration::Inserted
            }
            Entry::Vacant(entry) => {
                entry.insert(session);
                OutboundRegistration::Inserted
            }
        }
    }

    pub(crate) fn remove_outbound_if_sender(
        &self,
        key: &str,
        owner: &mpsc::Sender<FederationEnvelope>,
    ) -> bool {
        self.outbound
            .remove_if(key, |_, session| session.sender.same_channel(owner))
            .is_some()
    }

    pub(crate) fn authenticated_outbound_sender(
        &self,
        key: &str,
    ) -> Option<mpsc::Sender<FederationEnvelope>> {
        self.outbound.get(key).and_then(|session| {
            (session.is_authenticated() && !session.sender.is_closed())
                .then(|| session.sender.clone())
        })
    }

    pub(crate) fn register_bidirectional_if_vacant(
        &self,
        key: String,
        mut session: BidiS2sSession,
    ) -> std::result::Result<(), BidiS2sSession> {
        let Some((local, remote)) = key.split_once('\0') else {
            return Err(session);
        };
        let Ok(canonical_local) = crate::jid::prepare_domainpart(&session.local_domain) else {
            return Err(session);
        };
        if canonical_local != local
            || super::bidi_connection_key(local, remote).as_deref() != Some(key.as_str())
            || session.disconnect.is_cancelled()
            || session.sender.is_closed()
        {
            return Err(session);
        }
        session.local_domain = canonical_local;
        let remote_domain = remote.to_owned();
        match self.bidirectional.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(RegisteredBidi {
                    session,
                    remote_domain,
                    identity: Arc::new(()),
                    recovery: BidiRecoveryState::default(),
                });
                Ok(())
            }
            Entry::Occupied(_) => Err(session),
        }
    }

    /// Round-robin selection prevents leased heads retained over many polls
    /// from monopolizing a small limit. Rotate the first entry even when the
    /// batch includes every peer: a shared deadline may stop after its first
    /// database operation. Temporary keys and all persistent hint
    /// state are bounded by the existing live connection registry.
    pub(crate) fn pending_bidi_recoveries(&self, limit: usize) -> Vec<BidiRecoverySnapshot> {
        if limit == 0 {
            return Vec::new();
        }
        let mut keys: Vec<_> = self
            .bidirectional
            .iter()
            .filter(|entry| entry.live() && !matches!(entry.recovery, BidiRecoveryState::Consumed))
            .map(|entry| entry.key().clone())
            .collect();
        keys.sort_unstable();
        let count = limit.min(keys.len());
        if count == 0 {
            return Vec::new();
        }
        let start = self.bidi_recovery_cursor.fetch_add(1, Ordering::Relaxed) % keys.len();
        keys.iter()
            .cycle()
            .skip(start)
            .take(count)
            .filter_map(|key| {
                let entry = self.bidirectional.get(key)?;
                if !entry.live() || matches!(entry.recovery, BidiRecoveryState::Consumed) {
                    return None;
                }
                Some(BidiRecoverySnapshot {
                    connection_id: entry.session.connection_id,
                    local_domain: entry.session.local_domain.clone(),
                    remote_domain: entry.remote_domain.clone(),
                    sender: entry.session.sender.clone(),
                    disconnect: entry.session.disconnect.clone(),
                    key: key.clone(),
                    identity: Arc::clone(&entry.identity),
                })
            })
            .collect()
    }

    pub(crate) fn bidi_recovery_is_current(&self, snapshot: &BidiRecoverySnapshot) -> bool {
        self.bidirectional
            .get(&snapshot.key)
            .is_some_and(|entry| entry.matches(snapshot))
    }

    /// Validates the exact published incarnation and consumes the one-shot
    /// permission synchronously before returning RetryHead. No guard survives
    /// this method or can be held across the caller's database await.
    pub(crate) fn observe_bidi_recovery(
        &self,
        snapshot: &BidiRecoverySnapshot,
        head: Option<BidiRecoveryHead>,
    ) -> BidiRecoveryAction {
        let Some(mut entry) = self.bidirectional.get_mut(&snapshot.key) else {
            return BidiRecoveryAction::Consumed;
        };
        if !entry.matches(snapshot) {
            return BidiRecoveryAction::Consumed;
        }
        entry.recovery.observe(head)
    }

    pub(crate) fn bidirectional_route(&self, key: &str) -> Option<BidiRouteSnapshot> {
        self.bidirectional
            .get(key)
            .map(|session| BidiRouteSnapshot {
                local_domain: session.session.local_domain.clone(),
                sender: session.session.sender.clone(),
            })
    }

    pub(crate) fn remove_bidirectional_if_connection(
        &self,
        key: &str,
        connection_id: Uuid,
    ) -> bool {
        self.bidirectional
            .remove_if(key, |_, session| {
                session.session.connection_id == connection_id
            })
            .is_some()
    }

    /// Island mode intentionally drains only client-initiated outbound
    /// workers, matching the previous behavior. Established inbound streams
    /// remain registered but routing policy rejects their federation traffic.
    pub(crate) fn clear_outbound_for_island_mode(&self) {
        self.outbound.clear();
    }

    pub(crate) fn outbound_count(&self) -> usize {
        self.outbound.len()
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    fn publish(
        registry: &S2sConnectionRegistry,
        local: &str,
        remote: &str,
    ) -> (BidiRecoverySnapshot, mpsc::Receiver<FederationEnvelope>) {
        let (sender, receiver) = mpsc::channel(1);
        let connection_id = Uuid::new_v4();
        let key = super::super::bidi_connection_key(local, remote).unwrap();
        assert!(registry
            .register_bidirectional_if_vacant(
                key,
                BidiS2sSession::new(
                    connection_id,
                    local.to_owned(),
                    sender,
                    CancellationToken::new()
                ),
            )
            .is_ok());
        let snapshot = registry
            .pending_bidi_recoveries(usize::MAX)
            .into_iter()
            .find(|snapshot| snapshot.connection_id == connection_id)
            .unwrap();
        (snapshot, receiver)
    }

    fn delayed_head() -> BidiRecoveryHead {
        BidiRecoveryHead {
            id: Uuid::new_v4(),
            attempt_count: 3,
            leased: false,
            due: false,
            direction_matches: true,
        }
    }

    #[test]
    fn leased_head_retains_hint_until_same_attempt_fails_then_retries_once() {
        let registry = S2sConnectionRegistry::default();
        let (snapshot, _receiver) = publish(&registry, "local.example", "remote.example");
        let head = delayed_head();
        for due in [false, true] {
            assert_eq!(
                registry.observe_bidi_recovery(
                    &snapshot,
                    Some(BidiRecoveryHead {
                        leased: true,
                        due,
                        ..head
                    })
                ),
                BidiRecoveryAction::Retain
            );
        }
        assert_eq!(registry.pending_bidi_recoveries(1).len(), 1);
        assert_eq!(
            registry.observe_bidi_recovery(&snapshot, Some(head)),
            BidiRecoveryAction::RetryHead
        );
        assert!(registry.pending_bidi_recoveries(1).is_empty());
        // Consuming a hint never removes its authenticated route.
        assert!(registry.bidi_recovery_is_current(&snapshot));
        assert!(registry.bidirectional_route(&snapshot.key).is_some());
        assert_eq!(
            registry.observe_bidi_recovery(&snapshot, Some(head)),
            BidiRecoveryAction::Consumed
        );
    }

    #[test]
    fn a_new_head_or_attempt_cannot_inherit_an_observed_heads_hint() {
        for change_attempt in [false, true] {
            let registry = S2sConnectionRegistry::default();
            let (snapshot, _receiver) = publish(&registry, "local.example", "remote.example");
            let head = delayed_head();
            assert_eq!(
                registry.observe_bidi_recovery(
                    &snapshot,
                    Some(BidiRecoveryHead {
                        leased: true,
                        ..head
                    })
                ),
                BidiRecoveryAction::Retain
            );
            let changed = if change_attempt {
                BidiRecoveryHead {
                    attempt_count: head.attempt_count + 1,
                    ..head
                }
            } else {
                BidiRecoveryHead {
                    id: Uuid::new_v4(),
                    ..head
                }
            };
            assert_eq!(
                registry.observe_bidi_recovery(&snapshot, Some(changed)),
                BidiRecoveryAction::Consumed
            );
            assert_eq!(
                registry.observe_bidi_recovery(&snapshot, Some(head)),
                BidiRecoveryAction::Consumed
            );
        }
    }

    #[test]
    fn missing_or_disappeared_head_consumes_hint_without_retrying_a_successor() {
        for observe_first in [false, true] {
            let registry = S2sConnectionRegistry::default();
            let (snapshot, _receiver) = publish(&registry, "local.example", "remote.example");
            if observe_first {
                assert_eq!(
                    registry.observe_bidi_recovery(
                        &snapshot,
                        Some(BidiRecoveryHead {
                            leased: true,
                            ..delayed_head()
                        })
                    ),
                    BidiRecoveryAction::Retain
                );
            }
            assert_eq!(
                registry.observe_bidi_recovery(&snapshot, None),
                BidiRecoveryAction::Consumed
            );
            assert_eq!(
                registry.observe_bidi_recovery(&snapshot, Some(delayed_head())),
                BidiRecoveryAction::Consumed
            );
        }
    }

    #[test]
    fn due_head_uses_normal_claiming_and_wrong_direction_fails_closed() {
        for wrong_direction in [false, true] {
            let registry = S2sConnectionRegistry::default();
            let (snapshot, _receiver) = publish(&registry, "local.example", "remote.example");
            let head = BidiRecoveryHead {
                due: !wrong_direction,
                direction_matches: !wrong_direction,
                leased: wrong_direction,
                ..delayed_head()
            };
            assert_eq!(
                registry.observe_bidi_recovery(&snapshot, Some(head)),
                BidiRecoveryAction::Consumed
            );
            assert_eq!(
                registry.observe_bidi_recovery(&snapshot, Some(delayed_head())),
                BidiRecoveryAction::Consumed
            );
        }
    }

    #[test]
    fn cancel_or_closed_sender_revokes_even_an_already_cloned_snapshot() {
        for close_sender in [false, true] {
            let registry = S2sConnectionRegistry::default();
            let (snapshot, receiver) = publish(&registry, "local.example", "remote.example");
            assert!(registry.bidi_recovery_is_current(&snapshot));
            if close_sender {
                drop(receiver);
            } else {
                snapshot.disconnect.cancel();
            }
            assert!(!registry.bidi_recovery_is_current(&snapshot));
            assert!(registry.pending_bidi_recoveries(1).is_empty());
            assert_eq!(
                registry.observe_bidi_recovery(&snapshot, Some(delayed_head())),
                BidiRecoveryAction::Consumed
            );
        }
    }

    #[test]
    fn removal_and_republication_invalidate_uuid_and_sender_reusing_snapshots() {
        let registry = S2sConnectionRegistry::default();
        let (old, _receiver) = publish(&registry, "local.example", "remote.example");
        assert!(!registry.remove_bidirectional_if_connection(&old.key, Uuid::new_v4()));
        assert!(registry.remove_bidirectional_if_connection(&old.key, old.connection_id));
        assert!(!registry.bidi_recovery_is_current(&old));
        assert!(registry
            .register_bidirectional_if_vacant(
                old.key.clone(),
                BidiS2sSession::new(
                    old.connection_id,
                    old.local_domain.clone(),
                    old.sender.clone(),
                    old.disconnect.clone(),
                )
            )
            .is_ok());
        let new = registry.pending_bidi_recoveries(1).pop().unwrap();
        assert!(!registry.bidi_recovery_is_current(&old));
        assert!(registry.bidi_recovery_is_current(&new));
        let head = delayed_head();
        assert_eq!(
            registry.observe_bidi_recovery(&old, Some(head)),
            BidiRecoveryAction::Consumed
        );
        assert_eq!(
            registry.observe_bidi_recovery(&new, Some(head)),
            BidiRecoveryAction::RetryHead
        );
    }

    #[test]
    fn failed_publication_neither_resets_nor_consumes_incumbent_hint() {
        for consume_incumbent in [false, true] {
            let registry = S2sConnectionRegistry::default();
            let (old, _receiver) = publish(&registry, "local.example", "remote.example");
            let head = delayed_head();
            let expected = if consume_incumbent {
                BidiRecoveryAction::RetryHead
            } else {
                BidiRecoveryAction::Retain
            };
            assert_eq!(
                registry.observe_bidi_recovery(
                    &old,
                    Some(BidiRecoveryHead {
                        leased: !consume_incumbent,
                        ..head
                    })
                ),
                expected
            );
            let (sender, _new_receiver) = mpsc::channel(1);
            assert!(registry
                .register_bidirectional_if_vacant(
                    old.key.clone(),
                    BidiS2sSession::new(
                        Uuid::new_v4(),
                        old.local_domain.clone(),
                        sender,
                        CancellationToken::new(),
                    )
                )
                .is_err());
            assert!(registry.bidi_recovery_is_current(&old));
            let expected = if consume_incumbent {
                BidiRecoveryAction::Consumed
            } else {
                BidiRecoveryAction::RetryHead
            };
            assert_eq!(registry.observe_bidi_recovery(&old, Some(head)), expected);
            assert_eq!(
                registry.observe_bidi_recovery(&old, Some(head)),
                BidiRecoveryAction::Consumed
            );
        }
    }

    #[test]
    fn failed_publication_preserves_the_incumbents_exact_bound_head() {
        let registry = S2sConnectionRegistry::default();
        let (old, _receiver) = publish(&registry, "local.example", "remote.example");
        assert_eq!(
            registry.observe_bidi_recovery(
                &old,
                Some(BidiRecoveryHead {
                    leased: true,
                    ..delayed_head()
                })
            ),
            BidiRecoveryAction::Retain
        );
        let (sender, _new_receiver) = mpsc::channel(1);
        assert!(registry
            .register_bidirectional_if_vacant(
                old.key.clone(),
                BidiS2sSession::new(
                    Uuid::new_v4(),
                    old.local_domain.clone(),
                    sender,
                    CancellationToken::new(),
                )
            )
            .is_err());
        assert_eq!(
            registry.observe_bidi_recovery(&old, Some(delayed_head())),
            BidiRecoveryAction::Consumed
        );
    }

    #[test]
    fn canonical_identity_and_sender_fence_snapshot_tampering_without_harming_incumbent() {
        let registry = S2sConnectionRegistry::default();
        let (snapshot, _receiver) = publish(&registry, "LOCAL.EXAMPLE", "remote.example");
        assert_eq!(snapshot.local_domain, "local.example");
        assert_eq!(snapshot.remote_domain, "remote.example");
        for field in 0..3 {
            let mut wrong = snapshot.clone();
            let (sender, _wrong_receiver) = mpsc::channel(1);
            match field {
                0 => wrong.local_domain = "third.example".to_owned(),
                1 => wrong.remote_domain = "third.example".to_owned(),
                _ => wrong.sender = sender,
            }
            assert!(!registry.bidi_recovery_is_current(&wrong));
            assert_eq!(
                registry.observe_bidi_recovery(&wrong, Some(delayed_head())),
                BidiRecoveryAction::Consumed
            );
        }
        assert_eq!(
            registry.observe_bidi_recovery(&snapshot, Some(delayed_head())),
            BidiRecoveryAction::RetryHead
        );
    }

    #[test]
    fn invalid_route_pair_or_dead_connection_cannot_publish_a_hint() {
        let registry = S2sConnectionRegistry::default();
        for invalid in 0..3 {
            let (sender, receiver) = mpsc::channel(1);
            let disconnect = CancellationToken::new();
            let key = if invalid == 0 {
                "wrong.example\0remote.example".to_owned()
            } else {
                super::super::bidi_connection_key("local.example", "remote.example").unwrap()
            };
            if invalid == 1 {
                disconnect.cancel();
            }
            if invalid == 2 {
                drop(receiver);
            }
            assert!(registry
                .register_bidirectional_if_vacant(
                    key,
                    BidiS2sSession::new(
                        Uuid::new_v4(),
                        "local.example".to_owned(),
                        sender,
                        disconnect,
                    )
                )
                .is_err());
            assert!(registry.pending_bidi_recoveries(1).is_empty());
        }
    }

    #[test]
    fn retained_leases_do_not_starve_other_peers_under_a_small_snapshot_limit() {
        let registry = S2sConnectionRegistry::default();
        let mut receivers = Vec::new();
        for index in 0..7 {
            let (snapshot, receiver) =
                publish(&registry, "local.example", &format!("peer{index}.example"));
            assert_eq!(
                registry.observe_bidi_recovery(
                    &snapshot,
                    Some(BidiRecoveryHead {
                        leased: true,
                        ..delayed_head()
                    })
                ),
                BidiRecoveryAction::Retain
            );
            receivers.push(receiver);
        }
        assert!(registry.pending_bidi_recoveries(0).is_empty());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..receivers.len() {
            let selected = registry.pending_bidi_recoveries(2);
            assert_eq!(selected.len(), 2);
            assert_ne!(selected[0].connection_id, selected[1].connection_id);
            seen.extend(selected.iter().map(|snapshot| snapshot.connection_id));
        }
        assert_eq!(seen.len(), receivers.len());
        assert_eq!(registry.pending_bidi_recoveries(100).len(), receivers.len());
    }

    #[test]
    fn a_shared_deadline_that_only_reaches_the_first_snapshot_still_visits_every_peer() {
        let registry = S2sConnectionRegistry::default();
        let mut receivers = Vec::new();
        for index in 0..7 {
            let (_snapshot, receiver) = publish(
                &registry,
                "local.example",
                &format!("slow-peer{index}.example"),
            );
            receivers.push(receiver);
        }
        let mut reached = std::collections::HashSet::new();
        for _ in 0..receivers.len() {
            // The production helper may exhaust its common deadline during
            // the first read. The rest of this selected batch remains pending.
            let selected = registry.pending_bidi_recoveries(100);
            assert_eq!(selected.len(), receivers.len());
            reached.insert(selected[0].connection_id);
        }
        assert_eq!(reached.len(), receivers.len());
    }

    #[test]
    fn concurrent_observers_can_prepare_only_one_recovery_cas() {
        let registry = S2sConnectionRegistry::default();
        let (snapshot, _receiver) = publish(&registry, "local.example", "remote.example");
        let barrier = std::sync::Barrier::new(4);
        let head = delayed_head();
        let actions = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        registry.observe_bidi_recovery(&snapshot, Some(head))
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            actions
                .iter()
                .filter(|action| **action == BidiRecoveryAction::RetryHead)
                .count(),
            1
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| **action == BidiRecoveryAction::Consumed)
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn cas_permission_is_consumed_before_first_poll_and_survives_cancellation() {
        use std::sync::atomic::AtomicBool;
        let registry = S2sConnectionRegistry::default();
        let (snapshot, _receiver) = publish(&registry, "local.example", "remote.example");
        let head = delayed_head();
        assert_eq!(
            registry.observe_bidi_recovery(&snapshot, Some(head)),
            BidiRecoveryAction::RetryHead
        );
        let first_polled = AtomicBool::new(false);
        let mut cas = Box::pin(async {
            first_polled.store(true, Ordering::Relaxed);
            std::future::pending::<()>().await;
        });
        assert!(!first_polled.load(Ordering::Relaxed));
        assert!(registry.pending_bidi_recoveries(1).is_empty());
        assert_eq!(
            registry.observe_bidi_recovery(&snapshot, Some(head)),
            BidiRecoveryAction::Consumed
        );
        tokio::select! {
            biased;
            _ = &mut cas => panic!("pending CAS unexpectedly completed"),
            _ = std::future::ready(()) => {}
        }
        assert!(first_polled.load(Ordering::Relaxed));
        // Dropping an in-flight CAS represents cancellation or an unknown SQL
        // outcome. A later poll of this stream must not grant another attempt.
        drop(cas);
        assert_eq!(
            registry.observe_bidi_recovery(&snapshot, Some(head)),
            BidiRecoveryAction::Consumed
        );
    }
}
