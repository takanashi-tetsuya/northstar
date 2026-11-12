use super::test_support::*;
use super::*;
use crate::outbound::DurableDelivery;
use northstar_delivery_core::sm_ownership::{HDecision, Knowledge, KnowledgeClass};

#[tokio::test]
async fn record_limits_and_real_governor_reject_before_append_or_persistence() {
    for limit in 0..3 {
        let mut fixture = Fixture::new(true, vec![]);
        let before_h = fixture.sm.outbound_h;
        let _pressure = if limit == 2 {
            let available = 65_536 - fixture.sm.capacity.as_ref().unwrap().reserved_bytes();
            Some(
                fixture
                    .port
                    .governor
                    .try_reserve_transient(available)
                    .unwrap(),
            )
        } else {
            None
        };
        if limit == 0 {
            fixture.policy.buffer.max_unacked_stanzas = 0;
        }
        if limit == 1 {
            fixture.policy.buffer.max_unacked_bytes = 0;
        }
        assert!(fixture.record(&c2s_item()).await.is_err());
        assert!(fixture.sm.unacked.is_empty());
        assert_eq!(fixture.sm.outbound_h, before_h);
        assert!(!fixture.sm.resume_allowed);
        assert!(!fixture.port.events().contains(&"checkpoint"));
        assert!(!fixture.snapshot().appended);
    }
}
#[tokio::test]
async fn nonpersisted_record_keeps_fifo_without_claiming_sm_ownership() {
    let mut fixture = Fixture::new(false, vec![]);
    let (receipt_tx, mut receipt_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut item = c2s_item();
    item.transport_receipt = Some(receipt_tx);
    assert!(!fixture.record(&item).await.unwrap());
    assert_eq!(fixture.sm.unacked.len(), 1);
    assert_eq!(fixture.sm.outbound_h, 11);
    assert_eq!(fixture.snapshot().knowledge, Knowledge::NotRequested);
    assert!(!fixture.snapshot().notification_attempted);
    assert!(receipt_rx.try_recv().is_err());
    assert_eq!(fixture.port.events(), vec!["record", "grow"]);
}
#[tokio::test]
async fn record_wraps_h_and_restores_only_typed_supersession() {
    for cut in [
        Cut::Superseded,
        Cut::BeforeCommit,
        Cut::RolledBack,
        Cut::Success,
    ] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.sm.outbound_h = u32::MAX;
        fixture.sm.acked_h = u32::MAX;
        fixture.port.cut = cut;
        let item = c2s_item();
        let result = fixture.record(&item).await;
        assert_eq!(result.is_ok(), cut == Cut::Success);
        assert_eq!(
            fixture.sm.unacked.len(),
            usize::from(cut != Cut::Superseded)
        );
        assert_eq!(
            fixture.sm.outbound_h,
            if cut == Cut::Superseded { u32::MAX } else { 0 }
        );
        assert_eq!(fixture.snapshot().restored, cut == Cut::Superseded);
        assert!(fixture.snapshot().appended);
        if cut == Cut::RolledBack {
            assert_eq!(fixture.snapshot().knowledge, Knowledge::RollbackKnown);
        }
        if cut == Cut::Success {
            assert_eq!(
                fixture.port.events(),
                vec![
                    "record",
                    "grow",
                    "reserve_snapshot",
                    "grow",
                    "checkpoint",
                    "commit",
                    "receipt"
                ]
            );
        }
    }
}
#[tokio::test]
async fn record_drop_preserves_append_and_exact_commit_or_rollback_knowledge() {
    for cut in [
        Cut::DuringCommit,
        Cut::AfterReceiptPending,
        Cut::RollbackPending,
    ] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.cut = cut;
        let item = c2s_item();
        let mut future = Box::pin(fixture.record(&item));
        assert!(poll_once(future.as_mut()).is_pending());
        drop(future);
        assert_eq!(fixture.sm.unacked.len(), 1);
        assert_eq!(fixture.sm.outbound_h, 11);
        let snapshot = fixture.snapshot();
        assert!(snapshot.appended);
        assert!(!snapshot.restored);
        assert!(!snapshot.notification_attempted);
        assert_eq!(snapshot.terminal, Some(Terminal::Cancelled));
        assert_eq!(
            snapshot.summary().knowledge,
            match cut {
                Cut::DuringCommit => KnowledgeClass::CommitCallEntered,
                Cut::AfterReceiptPending => KnowledgeClass::ReceiptKnown,
                _ => KnowledgeClass::RollbackCallEntered,
            }
        );
    }
}
#[tokio::test]
async fn record_rotations_precede_actual_mix_notification_and_wrong_return_is_rejected() {
    for wrong in [false, true] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.rotate = true;
        if wrong {
            fixture.port.cut = Cut::WrongReturnedRotation;
        }
        let (item, mut receipt) =
            OutboundItem::durable_mix("<message id='mix'/>".to_owned(), mix());
        let result = fixture.record(&item).await;
        assert_eq!(result.is_ok(), !wrong);
        assert_eq!(
            fixture.sm.unacked[0]
                .source
                .unwrap()
                .mix()
                .unwrap()
                .lease_token,
            Uuid::from_u128(if wrong { 602 } else { 999 })
        );
        if wrong {
            assert!(receipt.try_recv().is_err());
            assert!(!fixture.snapshot().ownership_applied);
        } else {
            assert_eq!(
                receipt.try_recv().unwrap(),
                crate::outbound::MixTransportCompletion::SmPersisted {
                    session_id: fixture.sm.db_id.unwrap()
                }
            );
        }
        assert_eq!(fixture.snapshot().notification_attempted, !wrong);
        assert_eq!(
            fixture.snapshot().summary().knowledge,
            KnowledgeClass::ReceiptKnown
        );
    }
}
#[tokio::test]
async fn acknowledgement_uses_existing_h_rules_for_invalid_zero_delta_and_wrap() {
    for h in [9, 15, u32::MAX] {
        let mut fixture = Fixture::new(true, mixed_queue());
        let before = fixture.sm.unacked.clone();
        assert!(!fixture.ack(h).await.unwrap());
        assert_eq!(fixture.sm.unacked, before);
        assert_eq!(fixture.snapshot().h_decision, HDecision::Invalid);
        assert!(fixture.port.events().is_empty());
    }
    let mut zero = Fixture::new(true, vec![plain()]);
    assert!(zero.ack(10).await.unwrap());
    assert_eq!(zero.sm.unacked.len(), 1);
    assert!(zero.port.events().contains(&"commit"));
    let mut wrap = Fixture::new(true, vec![plain(), plain(), plain()]);
    wrap.sm.acked_h = u32::MAX - 1;
    wrap.sm.outbound_h = 1;
    assert!(wrap.ack(1).await.unwrap());
    assert!(wrap.sm.unacked.is_empty());
    assert_eq!(wrap.sm.acked_h, 1);
}
#[tokio::test]
async fn acknowledgement_binds_mixed_prefix_plain_slots_and_returned_suffix_rotations() {
    let mut fixture = Fixture::new(true, mixed_queue());
    fixture.port.rotate = true;
    assert!(fixture.ack(12).await.unwrap());
    assert_eq!(fixture.sm.acked_h, 12);
    assert_eq!(fixture.sm.unacked.len(), 2);
    assert_eq!(fixture.sm.unacked[0], plain());
    assert_eq!(
        fixture.sm.unacked[1]
            .source
            .unwrap()
            .mix()
            .unwrap()
            .lease_token,
        Uuid::from_u128(999)
    );
    let snapshot = fixture.snapshot();
    let binding = snapshot.binding.as_ref().unwrap();
    assert_eq!(
        binding.whole,
        vec![
            None,
            Some(TransportOwnershipSource::C2s(c2s())),
            None,
            Some(TransportOwnershipSource::Mix(mix()))
        ]
    );
    assert_eq!(binding.acknowledged.len(), 2);
    assert_eq!(snapshot.acknowledged_h_applied, Some(12));
    assert_eq!(snapshot.summary().committed_settled, Some(1));
    assert_eq!(
        fixture.port.events(),
        vec![
            "reserve_snapshot",
            "checkpoint",
            "commit",
            "receipt",
            "shrink"
        ]
    );
}
#[tokio::test]
async fn acknowledgement_failure_and_drop_never_erase_known_transaction_receipt() {
    for cut in [
        Cut::BeforeCommit,
        Cut::DuringCommit,
        Cut::CommitError,
        Cut::AfterReceiptPending,
        Cut::AfterReceiptError,
        Cut::RollbackPending,
        Cut::RollbackError,
        Cut::RolledBack,
    ] {
        let mut fixture = Fixture::new(true, mixed_queue());
        fixture.port.cut = cut;
        let original = fixture.sm.unacked.clone();
        let mut future = Box::pin(fixture.ack(12));
        let result = poll_once(future.as_mut());
        assert_eq!(
            result.is_pending(),
            matches!(
                cut,
                Cut::DuringCommit | Cut::AfterReceiptPending | Cut::RollbackPending
            )
        );
        if let Poll::Ready(result) = result {
            assert!(result.is_err());
        }
        drop(future);
        assert_eq!(fixture.sm.unacked, original);
        assert_eq!(fixture.sm.acked_h, 10);
        assert_eq!(fixture.snapshot().acknowledged_h_applied, None);
        assert_eq!(
            fixture.snapshot().summary().knowledge,
            match cut {
                Cut::BeforeCommit => KnowledgeClass::NoCommitRequested,
                Cut::DuringCommit | Cut::CommitError => KnowledgeClass::CommitCallEntered,
                Cut::AfterReceiptPending | Cut::AfterReceiptError => KnowledgeClass::ReceiptKnown,
                Cut::RolledBack => KnowledgeClass::RollbackKnown,
                _ => KnowledgeClass::RollbackCallEntered,
            }
        );
    }
}
#[tokio::test]
async fn injected_post_ack_capacity_failure_keeps_committed_fifo_and_h() {
    let mut fixture = Fixture::new(true, mixed_queue());
    fixture.port.injected_shrink_error = true;
    assert!(fixture.ack(12).await.is_err());
    assert_eq!(fixture.sm.acked_h, 12);
    assert_eq!(fixture.sm.unacked.len(), 2);
    let snapshot = fixture.snapshot();
    assert_eq!(snapshot.acknowledged_h_applied, Some(12));
    assert_eq!(snapshot.capacity_completed, Some(false));
    assert_eq!(snapshot.summary().knowledge, KnowledgeClass::ReceiptKnown);
}
#[tokio::test]
async fn nonpersisted_plain_ack_skips_commit_while_persisted_plain_ack_commits() {
    for persisted in [false, true] {
        let mut fixture = Fixture::new(persisted, vec![plain()]);
        assert!(fixture.ack(11).await.unwrap());
        assert_eq!(fixture.port.events().contains(&"commit"), persisted);
        assert_eq!(
            fixture.snapshot().summary().knowledge,
            if persisted {
                KnowledgeClass::ReceiptKnown
            } else {
                KnowledgeClass::NoPersistence
            }
        );
    }
}
#[tokio::test]
async fn nonpersisted_fake_authority_distinguishes_absent_c2s_and_strict_mix_failure() {
    // This is a fake repository compatibility case, not SQL qualification.
    let delivery = DurableDelivery {
        claim_id: None,
        ..c2s()
    };
    let mut fixture = Fixture::new(
        false,
        vec![SmUnackedStanza::with_source(
            "<message/>".to_owned(),
            Some(TransportOwnershipSource::C2s(delivery)),
        )],
    );
    fixture.port.absent_unclaimed = true;
    assert!(fixture.ack(11).await.unwrap());
    assert_eq!(
        fixture.snapshot().summary().committed_absent_unclaimed,
        Some(1)
    );
    assert_eq!(fixture.snapshot().summary().committed_settled, Some(0));
    let mut mixed = Fixture::new(false, mixed_queue());
    mixed.port.cut = Cut::MissingMix;
    let before = mixed.sm.unacked.clone();
    assert!(mixed.ack(14).await.is_err());
    assert_eq!(mixed.sm.unacked, before);
    assert_eq!(mixed.sm.acked_h, 10);
    assert!(!mixed.port.events().contains(&"commit"));
}
#[test]
fn private_preparation_rejects_changed_epoch_whole_cut_payload_and_projection() {
    let mut fixture = Fixture::new(true, mixed_queue());
    let observation = fixture.turn().start(Purpose::Acknowledge { h: 12 });
    observation.h_decision(Some(2));
    let acknowledged = fixture
        .sm
        .unacked
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    let mut snapshot = fixture.metadata.view().snapshot(
        &fixture.sm,
        fixture.sm.unacked.iter().skip(2).cloned().collect(),
    );
    snapshot.acked_h = 12;
    let policy = CheckpointPolicy {
        ttl_seconds: 60,
        live_lease_seconds: 30,
        max_stanzas: 32,
        max_bytes: 16_384,
    };
    let session = fixture.sm.db_id.unwrap();
    let connection = Uuid::from_u128(402);
    let before = observation.snapshot();
    for change in 0..5 {
        let mut altered = snapshot.clone();
        let mut session = session;
        let mut connection = connection;
        let mut prefix = acknowledged.clone();
        match change {
            0 => session = Uuid::nil(),
            1 => connection = Uuid::nil(),
            2 => altered.acked_h = 13,
            3 => altered.unacked[0].stanza = "<presence type='unavailable'/>".to_owned(),
            _ => prefix.swap(0, 1),
        }
        assert!(PreparedCheckpoint::bind(
            &observation,
            session,
            connection,
            &fixture.sm.unacked,
            &altered,
            &prefix,
            policy
        )
        .is_err());
        assert_eq!(observation.snapshot(), before);
    }
    let prepared = PreparedCheckpoint::bind(
        &observation,
        session,
        connection,
        &fixture.sm.unacked,
        &snapshot,
        &acknowledged,
        policy,
    )
    .unwrap();
    let before = observation.snapshot();
    for change in 0..4 {
        let mut altered = snapshot.clone();
        let mut policy = policy;
        match change {
            0 => altered.unacked[0].stanza = "<message>changed</message>".to_owned(),
            1 => altered.active_privacy_list = Some("changed-private-policy".to_owned()),
            2 => altered.user_agent_id = Some(Uuid::nil()),
            _ => policy.ttl_seconds += 1,
        }
        assert!(prepared
            .validate_projection(
                session,
                connection,
                northstar_session_application::sm::ownership::SnapshotProjection::from(&altered),
                &acknowledged,
                policy
            )
            .is_err());
        assert_eq!(observation.snapshot(), before);
    }
    assert!(fixture.port.events().is_empty());
    let debug = format!("{prepared:?} {observation:?} {:?}", observation.snapshot());
    assert!(!debug.contains("<presence"));
    assert!(!debug.contains("private-policy"));
    assert!(!debug.contains(&c2s().claim_id.unwrap().to_string()));
}
#[tokio::test]
async fn replaced_turn_slot_keeps_old_receipt_and_full_snapshot_independent() {
    let mut fixture = Fixture::new(true, vec![]);
    fixture.record(&c2s_item()).await.unwrap();
    let old = fixture.sm.current_operation.as_ref().unwrap().clone();
    let before = old.snapshot();
    let mut turn = fixture.turn();
    let current = turn.start(Purpose::Checkpoint);
    SmTurnRunner::new(current.clone(), async {
        turn.checkpoint_in_turn(&current).await
    })
    .await
    .unwrap();
    assert_eq!(old.snapshot(), before);
    assert_eq!(current.snapshot().scope.purpose, Purpose::Checkpoint);
    assert_eq!(current.snapshot().terminal, Some(Terminal::Returned));
    assert_eq!(old.snapshot().scope.purpose, Purpose::Record);
    assert!(matches!(
        old.snapshot().knowledge,
        Knowledge::ReceiptKnown(_)
    ));
}
struct DropProbe {
    observation: Observation,
    dropped: Arc<AtomicBool>,
    panic_poll: bool,
    panic_drop: bool,
    ready: bool,
}
impl Future for DropProbe {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
        if self.panic_poll {
            panic!("SM child poll panic");
        }
        if self.ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
impl Drop for DropProbe {
    fn drop(&mut self) {
        assert!(self.observation.snapshot().terminal.is_none());
        self.dropped.store(true, Ordering::SeqCst);
        if self.panic_drop {
            panic!("SM child drop panic");
        }
    }
}
#[test]
fn turn_owner_drops_child_before_summary_and_preserves_caught_panic() {
    for case in 0..5 {
        let mut fixture = Fixture::new(true, vec![]);
        let observation = fixture.turn().start(Purpose::Checkpoint);
        let dropped = Arc::new(AtomicBool::new(false));
        let child = DropProbe {
            observation: observation.clone(),
            dropped: dropped.clone(),
            panic_poll: case == 3,
            panic_drop: case == 4,
            ready: case == 2 || case == 4,
        };
        let mut future = Box::pin(SmTurnRunner::new(observation.clone(), child));
        if case != 0 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_once(future.as_mut())
            }));
            if case >= 3 {
                let payload = result.unwrap_err();
                assert_eq!(
                    payload.downcast_ref::<&str>().copied(),
                    Some(if case == 3 {
                        "SM child poll panic"
                    } else {
                        "SM child drop panic"
                    })
                );
            } else {
                assert_eq!(result.unwrap().is_ready(), case == 2);
            }
        }
        drop(future);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(
            observation.snapshot().terminal,
            Some(if case >= 3 {
                Terminal::Panicked
            } else if case == 2 {
                Terminal::Returned
            } else {
                Terminal::Cancelled
            })
        );
    }
}
#[tokio::test]
async fn mislabeled_typed_supersession_after_commit_keeps_fifo_h_and_original_error() {
    // Adapter-mismatch hardening. Current SQL emits this typed error only
    // before COMMIT; the fake drives the real wrapper before relabeling.
    for cut in [
        Cut::Superseded,
        Cut::TypedAfterCommitError,
        Cut::TypedAfterReceipt,
    ] {
        let mut fixture = Fixture::new(true, vec![]);
        fixture.port.cut = cut;
        let error = fixture.record(&c2s_item()).await.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<crate::outbound::DurableDeliverySuperseded>()
                .unwrap()
                .message_id,
            c2s().message_id
        );
        let restored = cut == Cut::Superseded;
        assert_eq!(fixture.sm.unacked.len(), usize::from(!restored));
        assert_eq!(fixture.sm.outbound_h, if restored { 10 } else { 11 });
        assert_eq!(fixture.sm.acked_h, 10);
        let snapshot = fixture.snapshot();
        assert_eq!(snapshot.restored, restored);
        assert!(!snapshot.notification_attempted);
        assert_eq!(
            snapshot.summary().knowledge,
            match cut {
                Cut::Superseded => KnowledgeClass::NoCommitRequested,
                Cut::TypedAfterCommitError => KnowledgeClass::CommitCallEntered,
                _ => KnowledgeClass::ReceiptKnown,
            }
        );
        assert_eq!(fixture.port.events().contains(&"commit"), !restored);
        assert_eq!(
            fixture.port.events().contains(&"receipt"),
            cut == Cut::TypedAfterReceipt
        );
        assert_eq!(fixture.port.events().contains(&"shrink"), restored);
    }
}
