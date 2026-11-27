use super::*;

#[test]
fn lower_versions_and_duplicates_are_covered_in_flushing_and_idle() {
    let gate = RosterSyncGate::default();
    let requested = AtomicBool::new(false);
    let annotations = AtomicBool::new(false);
    let offer = |version: i64| {
        gate.route(
            &requested,
            &annotations,
            version,
            version.to_string(),
            None,
            |_| unreachable!(),
        )
    };
    let permit = gate.begin(&requested, &annotations, false).unwrap();
    assert_eq!(offer(12), RosterPushDisposition::Buffered);
    assert_eq!(
        gate.start_flush(permit, 11),
        RosterFlushBatch::Batch(vec![(12, "12".into())])
    );
    assert_eq!(offer(10), RosterPushDisposition::Covered);
    assert_eq!(offer(12), RosterPushDisposition::Buffered);
    assert!(gate.accept_flushed(permit, 12));
    assert_eq!(offer(11), RosterPushDisposition::Covered);
    assert_eq!(offer(12), RosterPushDisposition::Covered);
    assert_eq!(gate.next_flush_batch(permit), RosterFlushBatch::Complete);
    assert_eq!(offer(11), RosterPushDisposition::Covered);
    assert_eq!(offer(12), RosterPushDisposition::Covered);
}

#[test]
fn a_get_behind_the_delivered_cursor_requests_a_full_snapshot() {
    let gate = RosterSyncGate::default();
    let requested = AtomicBool::new(false);
    let annotations = AtomicBool::new(false);
    let first = gate.begin(&requested, &annotations, false).unwrap();
    assert_eq!(first.requested_version(Some(9)), Some(9));
    assert_eq!(gate.start_flush(first, 10), RosterFlushBatch::Complete);
    assert_eq!(
        gate.route(&requested, &annotations, 11, "v11".into(), None, |_| true),
        RosterPushDisposition::Delivered
    );
    let second = gate.begin(&requested, &annotations, false).unwrap();
    assert_eq!(second.requested_version(Some(10)), None);
    assert_eq!(second.requested_version(Some(11)), Some(11));
}

#[test]
fn idle_gap_repairs_the_missing_prefix_before_draining_the_original_push() {
    let gate = RosterSyncGate::default();
    let requested = AtomicBool::new(false);
    let annotations = AtomicBool::new(false);
    let sync = gate.begin(&requested, &annotations, false).unwrap();
    let (scheduled, repair) = std::sync::mpsc::channel();
    gate.set_repair_scheduler(sync, move |permit| scheduled.send(permit).unwrap());
    assert_eq!(gate.start_flush(sync, 10), RosterFlushBatch::Complete);
    assert_eq!(
        gate.route(
            &requested,
            &annotations,
            12,
            "original".into(),
            None,
            |_| unreachable!()
        ),
        RosterPushDisposition::Buffered
    );
    let permit = repair.try_recv().unwrap();
    let gap = RosterGap {
        after: RosterVersion(10),
        through: RosterVersion(12),
    };
    assert_eq!(gate.next_flush_batch(permit), RosterFlushBatch::Repair(gap));
    let batch = gate
        .repair_batch(
            permit,
            gap,
            Some(vec![(11, "missing".into()), (12, "reconstructed".into())]),
        )
        .unwrap();
    assert_eq!(batch, vec![(11, "missing".into()), (12, "original".into())]);
    for (version, _) in batch {
        assert!(gate.accept_flushed(permit, version));
    }
    assert_eq!(gate.next_flush_batch(permit), RosterFlushBatch::Complete);
    assert_eq!(
        gate.route(
            &requested,
            &annotations,
            11,
            "late".into(),
            None,
            |_| unreachable!()
        ),
        RosterPushDisposition::Covered
    );
}

#[test]
fn a_missing_or_incomplete_proof_requires_resync() {
    for proof in [None, Some(vec![(11, "wrong".into()), (13, "gap".into())])] {
        let gate = RosterSyncGate::default();
        let requested = AtomicBool::new(false);
        let annotations = AtomicBool::new(false);
        let permit = gate.begin(&requested, &annotations, false).unwrap();
        assert_eq!(
            gate.route(
                &requested,
                &annotations,
                13,
                "new".into(),
                None,
                |_| unreachable!()
            ),
            RosterPushDisposition::Buffered
        );
        let RosterFlushBatch::Repair(gap) = gate.start_flush(permit, 10) else {
            panic!("expected a gap")
        };
        assert_eq!(gate.repair_batch(permit, gap, proof), None);
        assert!(gate.fail(permit));
        assert_eq!(gate.next_flush_batch(permit), RosterFlushBatch::Failed);
    }
}
