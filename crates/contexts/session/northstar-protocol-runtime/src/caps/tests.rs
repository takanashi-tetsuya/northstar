//! Unit tests of the caps cache, the federated caps gate and the caps effect dispatcher.

use super::*;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use uuid::Uuid;

#[test]
fn cancelled_gate_waiter_releases_registry() {
    let index = FederatedCapsGateIndex::new();
    let resource = "alice@remote.test/Phone";
    let mut context = Context::from_waker(Waker::noop());

    for (label, cancel_holder_first) in [
        ("cancel waiter while held", false),
        ("cancel last participant after unlock", true),
    ] {
        let mut acquisition = Box::pin(index.lock(resource));
        let Poll::Ready(holder) = acquisition.as_mut().poll(&mut context) else {
            panic!("{label}: uncontended lock must be ready");
        };
        let slot = Arc::clone(&holder.participant.as_ref().unwrap().slot);
        assert_eq!(holder.resource(), resource, "{label}");
        assert_eq!(index.len(), 1, "{label}");
        assert_eq!(index.participants(resource), 1, "{label}");

        let mut waiter = Box::pin(index.lock(resource));
        assert!(waiter.as_mut().poll(&mut context).is_pending(), "{label}");
        assert_eq!(index.len(), 1, "{label}");
        assert_eq!(index.participants(resource), 2, "{label}");
        assert!(
            Arc::ptr_eq(index.entries.get(resource).unwrap().value(), &slot),
            "{label}"
        );

        // A different full JID has an independent lifecycle gate.
        let mut independent = Box::pin(index.lock("alice@remote.test/Laptop"));
        let Poll::Ready(other) = independent.as_mut().poll(&mut context) else {
            panic!("{label}: another resource must not wait");
        };
        assert_eq!(index.len(), 2, "{label}");
        drop(other);
        assert_eq!(index.len(), 1, "{label}");

        if cancel_holder_first {
            drop(holder);
            assert_eq!(index.participants(resource), 1, "{label}");
            drop(waiter);
        } else {
            drop(waiter);
            assert_eq!(index.participants(resource), 1, "{label}");
            assert!(slot.gate.try_lock().is_err(), "{label}");
            drop(holder);
        }
        assert_eq!(index.participants(resource), 0, "{label}");
        assert!(index.is_empty(), "{label}");
        assert!(slot.gate.try_lock().is_ok(), "{label}");

        // A retired slot cannot be reused by a later resource lifecycle.
        let mut replacement = Box::pin(index.lock(resource));
        let Poll::Ready(holder) = replacement.as_mut().poll(&mut context) else {
            panic!("{label}: replacement lock must be ready");
        };
        let replacement_slot = Arc::clone(&holder.participant.as_ref().unwrap().slot);
        assert!(!Arc::ptr_eq(&replacement_slot, &slot), "{label}");
        let mut successor = Box::pin(index.lock(resource));
        assert!(
            successor.as_mut().poll(&mut context).is_pending(),
            "{label}"
        );
        assert_eq!(index.participants(resource), 2, "{label}");
        drop(holder);
        assert_eq!(index.participants(resource), 1, "{label}");
        let Poll::Ready(successor) = successor.as_mut().poll(&mut context) else {
            panic!("{label}: waiter must acquire after holder drops");
        };
        assert!(Arc::ptr_eq(
            &replacement_slot,
            &successor.participant.as_ref().unwrap().slot,
        ));
        assert_eq!(successor.resource(), resource, "{label}");
        drop(successor);
        assert!(index.is_empty(), "{label}");
    }
}

#[test]
fn saturated_caps_queue_rescans_without_loss() {
    let now = Instant::now();
    let nodes = (0..200)
        .map(|index| format!("urn:test:node:{index}"))
        .collect::<Vec<_>>();
    let mut storage = String::new();
    let ranges = nodes
        .iter()
        .map(|node| {
            let start = u32::try_from(storage.len()).unwrap();
            storage.push_str(node);
            (start, u32::try_from(storage.len()).unwrap())
        })
        .collect();
    let summary = Arc::new(VerifiedCapsSummary::new(false, false, storage, ranges));
    let charge = summary.resident_charge();
    let key = |node: &str| CapsKey {
        algorithm: "sha-1".to_owned(),
        node: node.to_owned(),
        version: "verified-version".to_owned(),
    };
    let first_key = key("first");
    let second_key = key("second");
    let third_key = key("third");

    for (label, max_entries, raw_budget, summary_budget, expected_bytes) in [
        (
            "raw overflow retains summaries",
            3,
            4,
            3 * charge,
            (4, 3 * charge),
        ),
        (
            "summary overflow rejects admission",
            3,
            12,
            2 * charge,
            (8, 2 * charge),
        ),
        (
            "entry limit evicts least recently used",
            2,
            12,
            3 * charge,
            (8, 2 * charge),
        ),
    ] {
        let cache = CapsCacheIndex::with_budgets(
            max_entries,
            raw_budget,
            summary_budget,
            Duration::from_secs(60),
        );
        cache.insert(
            first_key.clone(),
            "aaaa".to_owned(),
            Arc::clone(&summary),
            now,
        );
        cache.insert(
            second_key.clone(),
            "bbbb".to_owned(),
            Arc::clone(&summary),
            now + Duration::from_secs(1),
        );
        // Touch the older entry so eviction must choose the second key.
        assert!(
            cache
                .query(&first_key, now + Duration::from_secs(2))
                .is_some(),
            "{label}"
        );
        cache.insert(
            third_key.clone(),
            "cccc".to_owned(),
            Arc::clone(&summary),
            now + Duration::from_secs(3),
        );
        assert_eq!(cache.charged_bytes(), expected_bytes, "{label}");
        assert_eq!(cache.len(), expected_bytes.1 / charge, "{label}");
        if raw_budget == 4 {
            for key in [&first_key, &second_key] {
                assert!(
                    cache.raw_query(key, now + Duration::from_secs(4)).is_none(),
                    "{label}"
                );
            }
            assert_eq!(
                cache
                    .raw_query(&third_key, now + Duration::from_secs(4))
                    .as_deref(),
                Some("cccc"),
                "{label}"
            );
            for key in [&first_key, &second_key, &third_key] {
                assert_eq!(
                    cache
                        .query(key, now + Duration::from_secs(4))
                        .unwrap()
                        .notify_nodes()
                        .collect::<Vec<_>>(),
                    nodes.iter().map(String::as_str).collect::<Vec<_>>(),
                    "{label}"
                );
            }
        } else if max_entries == 2 {
            for (key, retained) in [(&first_key, true), (&second_key, false), (&third_key, true)] {
                assert_eq!(
                    cache.query(key, now + Duration::from_secs(4)).is_some(),
                    retained,
                    "{label}"
                );
            }
        } else {
            assert!(
                cache
                    .query(&third_key, now + Duration::from_secs(4))
                    .is_none(),
                "{label}"
            );
        }
        cache.sweep(now + Duration::from_secs(64));
        assert!(cache.is_empty(), "{label}");
        assert_eq!(cache.charged_bytes(), (0, 0), "{label}");
    }

    let epoch = LocalCapsEpoch {
        connection_id: Uuid::from_u128(1),
        generation: 7,
    };
    let limited = CapsResourceIndex::with_budgets(2, 2, charge);
    for resource in ["alice@example.test/One", "alice@example.test/Two"] {
        limited.observe_local(
            resource.to_owned(),
            epoch,
            Some(first_key.clone()),
            Some(Arc::clone(&summary)),
            now,
        );
    }
    assert_eq!(limited.summary_bytes(), charge, "observation byte limit");
    assert!(limited.summary("alice@example.test/One").is_some());
    assert!(limited.summary("alice@example.test/Two").is_none());
    assert_eq!(
        limited.mark_cached_verified(
            "alice@example.test/Two",
            CapsObservationOwner::Local(epoch),
            &first_key,
            Arc::clone(&summary),
        ),
        CapsVerificationCommit::ResourceLimited,
    );
    assert_eq!(limited.len(), 2, "byte pressure retains observations");
    let job = limited
        .claim_effects("alice@example.test/Two", now)
        .unwrap();
    assert!(job.effects.contains(CapsEffects::DISCO_QUERY));
    assert!(!limited.complete_effects(&job, CapsEffects::default(), now));
    limited.remove_local_epoch("alice@example.test/One", epoch);
    assert_eq!(limited.summary_bytes(), 0, "removal releases exact charge");
    assert_eq!(
        limited.mark_cached_verified(
            "alice@example.test/Two",
            CapsObservationOwner::Local(epoch),
            &first_key,
            Arc::clone(&summary),
        ),
        CapsVerificationCommit::Applied,
    );
    assert_eq!(
        limited.summary_bytes(),
        charge,
        "freed bytes admit verification"
    );
    assert_eq!(
        limited
            .snapshot("alice@example.test/Two")
            .unwrap()
            .into_notify_nodes(),
        nodes
    );
    limited.remove_local_epoch("alice@example.test/Two", epoch);
    assert_eq!(limited.summary_bytes(), 0);

    let observations = CapsResourceIndex::with_budgets(2, 2, 4 * charge);
    let dispatcher = CapsEffectDispatcher::with_limits(1, 1);
    let resources = [
        ("alice@example.test/One", true),
        ("alice@example.test/Two", true),
        ("bob@remote.test/One", false),
        ("bob@remote.test/Two", false),
    ];
    for (resource, local) in resources {
        if local {
            observations.observe_local(
                resource.to_owned(),
                epoch,
                Some(first_key.clone()),
                Some(Arc::clone(&summary)),
                now,
            );
        } else {
            assert!(observations
                .observe_federated(
                    resource.to_owned(),
                    Uuid::from_u128(2),
                    "remote.test".to_owned(),
                    Some(first_key.clone()),
                    Some(Arc::clone(&summary)),
                    now,
                )
                .is_some());
        }
    }
    assert_eq!(observations.summary_bytes(), 4 * charge);
    assert_eq!(observations.federated_counts("remote.test"), (2, 2));
    for (label, resource, local, expected) in [
        (
            "local queued",
            resources[0].0,
            true,
            CapsEffectAdmission::Queued,
        ),
        (
            "local coalesced",
            resources[0].0,
            true,
            CapsEffectAdmission::Coalesced,
        ),
        (
            "federated queued",
            resources[2].0,
            false,
            CapsEffectAdmission::Queued,
        ),
        (
            "federated coalesced",
            resources[2].0,
            false,
            CapsEffectAdmission::Coalesced,
        ),
    ] {
        assert_eq!(
            dispatcher.enqueue_hint(resource.to_owned(), local),
            expected,
            "{label}: independent hint budgets"
        );
    }
    let mut context = Context::from_waker(Waker::noop());
    {
        let mut wake = Box::pin(dispatcher.wake().notified());
        assert!(
            wake.as_mut().poll(&mut context).is_ready(),
            "admission wakes dispatcher"
        );
    }
    {
        let mut wake = Box::pin(dispatcher.wake().notified());
        assert!(wake.as_mut().poll(&mut context).is_pending());
        for (resource, local) in [resources[1], resources[3]] {
            assert_eq!(
                dispatcher.enqueue_hint(resource.to_owned(), local),
                CapsEffectAdmission::Saturated,
                "{resource}: independent hint budgets"
            );
        }
        assert!(
            wake.as_mut().poll(&mut context).is_ready(),
            "saturation wakes dispatcher"
        );
    }

    let mut completed = Vec::new();
    for pass in 0..2 {
        assert!(
            dispatcher.begin_rescan(),
            "pass {pass}: reconstruction requested"
        );
        assert!(
            !dispatcher.begin_rescan(),
            "pass {pass}: request consumed once"
        );
        let mut ready = observations.ready_observations(now);
        ready.sort();
        for (resource, local) in ready {
            let _ = dispatcher.enqueue_hint(resource, local);
        }
        {
            let queue = dispatcher.queue.lock().unwrap();
            assert_eq!(queue.local_ready.len(), 1, "pass {pass}: local bound");
            assert_eq!(
                queue.federated_ready.len(),
                1,
                "pass {pass}: federated bound"
            );
            assert_eq!(queue.local_queued.len(), 1);
            assert_eq!(queue.federated_queued.len(), 1);
        }
        for expected_local in [true, false] {
            let (resource, local) = dispatcher.next().expect("reconstructed hint");
            assert_eq!(local, expected_local, "pass {pass}: classes alternate");
            let job = observations
                .claim_effects(&resource, now)
                .expect("pending work survives saturation");
            assert_eq!(job.full_jid, resource);
            assert_eq!(job.owner.is_local(), local);
            assert_eq!(job.key.as_ref(), Some(&first_key));
            assert_eq!(
                job.effects,
                CapsEffects::EXPLICIT_PEP_LAST_ITEMS | CapsEffects::AUTOMATIC_PEP_LAST_ITEMS
            );
            assert_eq!(
                observations
                    .snapshot(&resource)
                    .unwrap()
                    .into_notify_nodes(),
                nodes,
                "{resource}: every notify node survives"
            );
            assert!(!observations.complete_effects(&job, CapsEffects::default(), now));
            completed.push(resource);
        }
        assert!(dispatcher.next().is_none());
    }
    completed.sort();
    assert_eq!(
        completed,
        resources.map(|(resource, _)| resource.to_owned())
    );
    assert!(observations.ready_observations(now).is_empty());
    assert_eq!(
        observations.len(),
        4,
        "dispatch retains authoritative observations"
    );
    assert_eq!(observations.summary_bytes(), 4 * charge);
    {
        let mut wake = Box::pin(dispatcher.wake().notified());
        assert!(wake.as_mut().poll(&mut context).is_ready());
    }
    let mut wake = Box::pin(dispatcher.wake().notified());
    assert!(wake.as_mut().poll(&mut context).is_pending());
    dispatcher.request_rescan();
    assert!(
        wake.as_mut().poll(&mut context).is_ready(),
        "rescan wakes dispatcher"
    );
    assert!(dispatcher.begin_rescan());
    assert!(!dispatcher.begin_rescan());
}

#[test]
fn caps_snapshot_local_epoch_distinguishes_local_and_federated_owners() {
    let epoch = LocalCapsEpoch {
        connection_id: Uuid::new_v4(),
        generation: 7,
    };
    let mut snapshot = CapsObservationSnapshot {
        owner: CapsObservationOwner::Local(epoch),
        key: None,
        summary: None,
    };
    assert_eq!(snapshot.local_epoch(), Some(epoch));

    snapshot.owner = CapsObservationOwner::Federated {
        connection_id: Uuid::new_v4(),
        observation_id: Uuid::new_v4(),
    };
    assert_eq!(snapshot.local_epoch(), None);
}

#[test]
fn caps_snapshot_notify_nodes_without_summary_is_empty() {
    let snapshot = CapsObservationSnapshot {
        owner: CapsObservationOwner::Local(LocalCapsEpoch {
            connection_id: Uuid::new_v4(),
            generation: 7,
        }),
        key: None,
        summary: None,
    };
    assert!(snapshot.into_notify_nodes().is_empty());
}

#[test]
fn caps_snapshot_notify_nodes_keeps_all_nodes_in_order() {
    let snapshot = CapsObservationSnapshot {
        owner: CapsObservationOwner::Local(LocalCapsEpoch {
            connection_id: Uuid::new_v4(),
            generation: 7,
        }),
        key: None,
        summary: Some(Arc::new(VerifiedCapsSummary::new(
            false,
            false,
            "firstsecondthird".to_owned(),
            vec![(5, 11), (0, 5), (11, 16), (5, 11)],
        ))),
    };
    assert_eq!(
        snapshot.into_notify_nodes(),
        vec!["second", "first", "third", "second"]
    );
}

#[test]
fn remove_local_caps_epoch_removes_both_indexes_and_preserves_other_epochs() {
    let pending = PendingCapsIndex::new();
    let observations = CapsResourceIndex::new();
    let epoch = LocalCapsEpoch {
        connection_id: Uuid::new_v4(),
        generation: 7,
    };
    let other_epoch = LocalCapsEpoch {
        generation: 8,
        ..epoch
    };
    let full_jid = "alice@example.test/fixture";
    let other_jid = "alice@example.test/other";
    let now = Instant::now();
    for (id, jid, owner) in [
        ("target", full_jid, epoch),
        ("newer", full_jid, other_epoch),
        ("other", other_jid, other_epoch),
    ] {
        assert!(pending.insert(
            id.to_owned(),
            jid.to_owned(),
            CapsKey {
                algorithm: "sha-1".to_owned(),
                node: id.to_owned(),
                version: "v1".to_owned(),
            },
            CapsObservationOwner::Local(owner),
            now + PENDING_TTL,
        ));
    }
    observations.observe_local(full_jid.to_owned(), epoch, None, None, now);
    observations.observe_local(other_jid.to_owned(), other_epoch, None, None, now);

    remove_local_caps_epoch(&pending, &observations, full_jid, epoch);

    assert!(!pending.entries.contains_key("target"));
    assert!(observations.snapshot(full_jid).is_none());
    assert!(pending.entries.contains_key("newer"));
    assert!(pending.entries.contains_key("other"));
    assert_eq!(
        observations.owner(other_jid),
        Some(CapsObservationOwner::Local(other_epoch))
    );

    observations.observe_local(full_jid.to_owned(), other_epoch, None, None, now);
    remove_local_caps_epoch(&pending, &observations, full_jid, epoch);

    assert!(pending.entries.contains_key("newer"));
    assert_eq!(
        observations.owner(full_jid),
        Some(CapsObservationOwner::Local(other_epoch))
    );
}
