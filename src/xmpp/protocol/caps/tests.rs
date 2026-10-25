use super::*;
use roxmltree::Document;

fn key(seed: u16) -> CapsKey {
    CapsKey {
        algorithm: "sha-1".to_owned(),
        node: format!("node-{seed}"),
        version: format!("version-{seed}"),
    }
}

fn summary(feature: &str) -> Arc<VerifiedCapsSummary> {
    Arc::new(VerifiedCapsSummary {
        mix_core: feature == "urn:xmpp:mix:core:1",
        mix_pam: feature == "urn:xmpp:mix:pam:2",
        notify_storage: feature.to_owned(),
        notify_ranges: vec![(0, u32::try_from(feature.len()).unwrap())],
    })
}

fn federated_owner(connection_id: uuid::Uuid, observation_id: uuid::Uuid) -> CapsObservationOwner {
    CapsObservationOwner::Federated {
        connection_id,
        observation_id,
    }
}

#[tokio::test]
async fn federated_gate_serializes_and_self_cleans_after_waiters_leave() {
    let index = Arc::new(FederatedCapsGateIndex::new());
    let resource = "alice@remote.test/Phone";
    let first = index.lock(resource).await;
    let waiter_index = Arc::clone(&index);
    let waiter = tokio::spawn(async move {
        let _guard = waiter_index.lock(resource).await;
    });
    for _ in 0..100 {
        if index.participants(resource) == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(index.participants(resource), 2);
    drop(first);
    waiter.await.unwrap();
    assert_eq!(index.len(), 0);
}

#[test]
fn verified_summary_keeps_every_notify_feature_within_parser_bounds() {
    let features = (0..200)
        .map(|index| format!("<feature var='urn:test:{index}+notify'/>"))
        .collect::<String>();
    let xml = format!("<query xmlns='{DISCO_INFO_NS}'>{features}</query>");
    assert!(xml.len() < MAX_DISCO_PAYLOAD_BYTES);
    let document = Document::parse(&xml).unwrap();
    let query = document.root_element();
    verification_string(query).expect("bounded payload verifies");
    let summary = verified_caps_summary(query, &xml).expect("bounded summary parses");
    assert_eq!(summary.notify_ranges.len(), 200);
    assert!(summary.wants_node("urn:test:199"));
}

#[test]
fn raw_cache_eviction_does_not_change_observation_interest() {
    let now = Instant::now();
    let cache = CapsCacheIndex::with_limits(1, Duration::from_secs(60));
    let observations = CapsResourceIndex::with_limits(4, 4);
    let first_key = key(1);
    let first_summary = summary("urn:test:first");
    cache.insert(
        first_key.clone(),
        "<query first='true'/>".to_owned(),
        Arc::clone(&first_summary),
        now,
    );
    assert_eq!(cache.len(), 1);
    observations.observe_local(
        "alice@example.test/Phone".to_owned(),
        LocalCapsEpoch {
            connection_id: uuid::Uuid::nil(),
            generation: 1,
        },
        Some(first_key.clone()),
        Some(first_summary),
        now,
    );
    cache.insert(
        key(2),
        "<query second='true'/>".to_owned(),
        summary("urn:test:second"),
        now + Duration::from_millis(1),
    );
    assert!(cache
        .raw_query(&first_key, now + Duration::from_millis(2))
        .is_none());
    assert!(observations
        .summary("alice@example.test/Phone")
        .is_some_and(|summary| summary.wants_node("urn:test:first")));
    observations.observe_local(
        "alice@example.test/Phone".to_owned(),
        LocalCapsEpoch {
            connection_id: uuid::Uuid::nil(),
            generation: 2,
        },
        Some(first_key),
        None,
        now + Duration::from_millis(3),
    );
    assert!(observations
        .summary("alice@example.test/Phone")
        .is_some_and(|summary| summary.wants_node("urn:test:first")));
}

#[test]
fn raw_cache_has_an_exact_byte_budget_and_evicts_only_responder_xml() {
    let now = Instant::now();
    let cache = CapsCacheIndex::with_budgets(4, 24, 64 * 1024, Duration::from_secs(60));
    let first_key = key(10);
    let second_key = key(11);
    cache.insert(
        first_key.clone(),
        "1234567890123456".to_owned(),
        summary("urn:test:first"),
        now,
    );
    cache.insert(
        second_key.clone(),
        "abcdefghijklmnop".to_owned(),
        summary("urn:test:second"),
        now + Duration::from_millis(1),
    );
    let (raw_bytes, semantic_bytes) = cache.charged_bytes();
    assert!(raw_bytes <= 24);
    assert!(semantic_bytes <= 64 * 1024);
    assert!(cache
        .raw_query(&first_key, now + Duration::from_millis(2))
        .is_none());
    assert!(cache
        .query(&first_key, now + Duration::from_millis(2))
        .is_some());
    assert!(cache
        .raw_query(&second_key, now + Duration::from_millis(2))
        .is_some());
}

#[test]
fn summary_budget_preserves_pending_verification_and_releases_exactly() {
    let now = Instant::now();
    let verified = summary("urn:test:large+notify");
    let charge = verified.resident_charge();
    let index = CapsResourceIndex::with_budgets(4, 4, charge);
    let first = "alice@example.test/One";
    let second = "alice@example.test/Two";
    index.observe_local(
        first.to_owned(),
        LocalCapsEpoch {
            connection_id: uuid::Uuid::new_v4(),
            generation: 1,
        },
        Some(key(20)),
        Some(Arc::clone(&verified)),
        now,
    );
    index.observe_local(
        second.to_owned(),
        LocalCapsEpoch {
            connection_id: uuid::Uuid::new_v4(),
            generation: 1,
        },
        Some(key(21)),
        Some(Arc::clone(&verified)),
        now,
    );
    assert_eq!(index.summary_bytes(), charge);
    assert!(index.summary(first).is_some());
    assert!(index.summary(second).is_none());
    assert!(index
        .ready_observations(now)
        .iter()
        .any(|(resource, _)| resource == second));

    let first_connection = match index.owner(first).unwrap() {
        CapsObservationOwner::Local(epoch) => epoch.connection_id,
        CapsObservationOwner::Federated { .. } => unreachable!(),
    };
    index.remove_local_resource(first, first_connection);
    assert_eq!(index.summary_bytes(), 0);
    index.observe_local(
        second.to_owned(),
        LocalCapsEpoch {
            connection_id: uuid::Uuid::new_v4(),
            generation: 2,
        },
        Some(key(21)),
        Some(verified),
        now,
    );
    assert!(index.summary(second).is_some());
    assert_eq!(index.summary_bytes(), charge);
}

#[test]
fn local_replacement_never_exposes_an_absent_observation() {
    let index = Arc::new(CapsResourceIndex::with_limits(4, 4));
    let resource = "alice@example.test/Phone";
    let connection_id = uuid::Uuid::new_v4();
    index.observe_local(
        resource.to_owned(),
        LocalCapsEpoch {
            connection_id,
            generation: 1,
        },
        None,
        None,
        Instant::now(),
    );
    let start = Arc::new(std::sync::Barrier::new(2));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_index = Arc::clone(&index);
    let reader_start = Arc::clone(&start);
    let reader_done = Arc::clone(&done);
    let reader = std::thread::spawn(move || {
        reader_start.wait();
        loop {
            assert!(reader_index.snapshot(resource).is_some());
            if reader_done.load(Ordering::Acquire) {
                break;
            }
        }
    });
    start.wait();
    for generation in 2..=2_000 {
        index.observe_local(
            resource.to_owned(),
            LocalCapsEpoch {
                connection_id,
                generation,
            },
            None,
            None,
            Instant::now(),
        );
    }
    done.store(true, Ordering::Release);
    reader.join().unwrap();
    assert!(index.snapshot(resource).is_some());
}

#[test]
fn same_connection_federated_readvertisement_is_aba_fenced() {
    let index = CapsResourceIndex::with_limits(4, 4);
    let connection_id = uuid::Uuid::new_v4();
    let resource = "alice@remote.test/Phone";
    let first = index
        .observe_federated(
            resource.to_owned(),
            connection_id,
            "remote.test".to_owned(),
            None,
            None,
            Instant::now(),
        )
        .unwrap();
    let old_job = index.claim_effects(resource, Instant::now()).unwrap();
    let second = index
        .observe_federated(
            resource.to_owned(),
            connection_id,
            "remote.test".to_owned(),
            None,
            None,
            Instant::now(),
        )
        .unwrap();
    assert_ne!(first, second);
    assert!(!index.complete_effects(&old_job, CapsEffects::default(), Instant::now()));
    assert_eq!(index.owner(resource), Some(second));
    assert_eq!(
        index.claim_effects(resource, Instant::now()).unwrap().owner,
        second
    );
}

#[test]
fn failed_effect_bits_are_rearmed_until_success() {
    let index = CapsResourceIndex::with_limits(4, 4);
    let resource = "alice@remote.test/Phone";
    index
        .observe_federated(
            resource.to_owned(),
            uuid::Uuid::new_v4(),
            "remote.test".to_owned(),
            None,
            None,
            Instant::now(),
        )
        .unwrap();
    let job = index.claim_effects(resource, Instant::now()).unwrap();
    index.complete_effects(&job, job.effects, Instant::now());
    let retry = index
        .claim_effects(resource, Instant::now() + CAPS_EFFECT_RETRY_MAX)
        .expect("failed work remains authoritative");
    assert_eq!(retry.owner, job.owner);
    assert_eq!(retry.effects, job.effects);
}

#[test]
fn dispatcher_drop_rearms_claimed_effects_and_requests_rescan() {
    let observations = CapsResourceIndex::with_limits(4, 4);
    let dispatcher = CapsEffectDispatcher::with_limits(1, 1);
    let resource = "alice@remote.test/Phone";
    observations
        .observe_federated(
            resource.to_owned(),
            uuid::Uuid::new_v4(),
            "remote.test".to_owned(),
            None,
            None,
            Instant::now(),
        )
        .unwrap();
    let claimed = observations
        .claim_effects(resource, Instant::now())
        .unwrap();
    assert!(observations
        .claim_effects(resource, Instant::now())
        .is_none());
    assert!(!dispatcher.begin_rescan());

    drop(CapsEffectRunGuard {
        observations: &observations,
        dispatcher: dispatcher.as_ref(),
    });

    assert!(dispatcher.begin_rescan());
    let retry = observations
        .claim_effects(resource, Instant::now())
        .unwrap();
    assert_eq!(retry.owner, claimed.owner);
    assert_eq!(retry.effects, claimed.effects);
}

#[test]
fn saturated_ready_queue_is_reconstructible_from_observations() {
    let coalesced = std::sync::atomic::AtomicU64::new(0);
    let queue_saturated = std::sync::atomic::AtomicU64::new(0);
    let failures = std::sync::atomic::AtomicU64::new(0);
    let latency = northstar_telemetry::metrics::DurationHistogram::default();
    let telemetry = CapsEffectTelemetry::new(&coalesced, &queue_saturated, &failures, &latency);
    let dispatcher = CapsEffectDispatcher::with_limits(1, 1);
    let index = CapsResourceIndex::with_limits(4, 4);
    for (resource, seed) in [("a@remote.test/One", 1_u16), ("b@remote.test/Two", 2_u16)] {
        index
            .observe_federated(
                resource.to_owned(),
                uuid::Uuid::new_v4(),
                "remote.test".to_owned(),
                Some(key(seed)),
                None,
                Instant::now(),
            )
            .unwrap();
    }
    let local_resource = "local@example.test/Phone";
    index.observe_local(
        local_resource.to_owned(),
        LocalCapsEpoch {
            connection_id: uuid::Uuid::new_v4(),
            generation: 1,
        },
        None,
        None,
        Instant::now(),
    );
    assert_eq!(
        dispatcher.hint("a@remote.test/One".to_owned(), false, &telemetry),
        CapsEffectAdmission::Queued
    );
    assert_eq!(
        dispatcher.hint("b@remote.test/Two".to_owned(), false, &telemetry),
        CapsEffectAdmission::Saturated
    );
    assert_eq!(queue_saturated.load(Ordering::Relaxed), 1);
    assert!(
        dispatcher.begin_rescan(),
        "saturation requests reconstruction"
    );
    assert_eq!(
        dispatcher.hint(local_resource.to_owned(), true, &telemetry),
        CapsEffectAdmission::Queued,
        "federated saturation has an independent local hint budget"
    );
    assert_eq!(dispatcher.take_hint().as_deref(), Some(local_resource));
    assert!(index
        .claim_effects(local_resource, Instant::now())
        .is_some_and(|job| job.owner.is_local()));
    assert_eq!(dispatcher.take_hint().as_deref(), Some("a@remote.test/One"));
    let ready = index.ready_observations(Instant::now());
    assert!(ready.iter().any(|(jid, _)| jid == "b@remote.test/Two"));
    assert_eq!(
        dispatcher.hint("b@remote.test/Two".to_owned(), false, &telemetry),
        CapsEffectAdmission::Queued
    );
}

#[test]
fn federated_admission_counters_are_exact_across_replace_and_teardown() {
    let index = CapsResourceIndex::with_limits(2, 1);
    let first_connection = uuid::Uuid::new_v4();
    let second_connection = uuid::Uuid::new_v4();
    let resource = "alice@remote.test/Phone";
    index
        .observe_federated(
            resource.to_owned(),
            first_connection,
            "remote.test".to_owned(),
            None,
            None,
            Instant::now(),
        )
        .unwrap();
    assert_eq!(index.federated_counts("remote.test"), (1, 1));
    index
        .observe_federated(
            resource.to_owned(),
            second_connection,
            "remote.test".to_owned(),
            None,
            None,
            Instant::now(),
        )
        .unwrap();
    assert_eq!(index.federated_counts("remote.test"), (1, 1));
    assert!(!index.remove_federated_resource_if_connection(resource, first_connection));
    assert_eq!(index.federated_counts("remote.test"), (1, 1));
    assert!(index.remove_federated_resource_if_connection(resource, second_connection));
    assert_eq!(index.federated_counts("remote.test"), (0, 0));
    assert_eq!(index.len(), 0);
}

#[test]
fn distinct_federated_observation_ids_are_part_of_pending_authority() {
    let connection_id = uuid::Uuid::new_v4();
    let first = federated_owner(connection_id, uuid::Uuid::new_v4());
    let second = federated_owner(connection_id, uuid::Uuid::new_v4());
    assert_ne!(first, second);
    assert_eq!(first.federated_connection(), second.federated_connection());

    let pending = PendingCapsIndex::new();
    assert!(pending.insert(
        "one".to_owned(),
        "alice@remote.test/Phone".to_owned(),
        key(1),
        first,
        Instant::now() + Duration::from_secs(1),
    ));
    assert!(pending.insert(
        "two".to_owned(),
        "alice@remote.test/Phone".to_owned(),
        key(2),
        second,
        Instant::now() + Duration::from_secs(1),
    ));
    assert_eq!(pending.len(), 2);
    assert_eq!(pending.take("one").unwrap().owner, first);
    assert_eq!(pending.take("two").unwrap().owner, second);
}

#[test]
fn pending_caps_single_flights_one_query_per_semantic_key() {
    let pending = PendingCapsIndex::new();
    let shared_key = key(30);
    let first = federated_owner(uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let second = federated_owner(uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    assert!(pending.insert(
        "leader".to_owned(),
        "one@remote.test/Phone".to_owned(),
        shared_key.clone(),
        first,
        Instant::now() + Duration::from_secs(30),
    ));
    assert!(!pending.insert(
        "follower".to_owned(),
        "two@remote.test/Phone".to_owned(),
        shared_key,
        second,
        Instant::now() + Duration::from_secs(30),
    ));
    assert_eq!(pending.len(), 1);
}
