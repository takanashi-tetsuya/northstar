//! Roster commands and per-resource push ordering.
//!
//! The repository owns authorization and atomic persistence. RosterSyncGate
//! handles the initial-result/push race without retaining a database connection.
//! Safety Invariants: MAX_BUFFERED_ROSTER_CHANGES, RosterSyncState::Flushing

use anyhow::Result;
use northstar_roster_application::{
    validate_roster_get_command, validate_roster_remove_command, validate_roster_upsert_command,
    RosterGetCommand, RosterRemoveCommand, RosterRepository, RosterUpsertCommand,
};
use northstar_roster_core::{
    RosterAuthorization, RosterChange, RosterReadSnapshot, RosterRemovalTransition,
};

#[derive(Clone)]
pub(crate) struct RosterService<R> {
    repository: R,
}

impl<R: RosterRepository<Error = anyhow::Error>> RosterService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn execute_roster_get(
        &self,
        command: RosterGetCommand,
    ) -> Result<RosterAuthorization<RosterReadSnapshot>> {
        if validate_roster_get_command(&command).is_err() {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.repository.get_roster(&command).await
    }

    pub(crate) async fn execute_roster_upsert(
        &self,
        command: RosterUpsertCommand,
    ) -> Result<RosterAuthorization<RosterChange>> {
        if validate_roster_upsert_command(&command).is_err() {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.repository.upsert_item(&command).await
    }

    pub(crate) async fn execute_roster_remove(
        &self,
        command: RosterRemoveCommand<'_>,
    ) -> Result<RosterAuthorization<Option<RosterRemovalTransition>>> {
        if validate_roster_remove_command(&command).is_err() {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.repository.remove_item(&command).await
    }
}

#[cfg(test)]
mod tests {
    use northstar_roster_application::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DenyingRepository {
        calls: std::sync::atomic::AtomicUsize,
        failed: AtomicBool,
        owner: uuid::Uuid,
    }

    impl DenyingRepository {
        fn reject<T>(
            &self,
            owner: uuid::Uuid,
            generation: i64,
        ) -> anyhow::Result<RosterAuthorization<T>> {
            assert_eq!(owner, self.owner);
            assert_eq!(generation, 7);
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.failed.load(Ordering::SeqCst) {
                anyhow::bail!("repository unavailable");
            }
            Ok(RosterAuthorization::Unauthorized)
        }
    }

    impl RosterRepository for DenyingRepository {
        type Error = anyhow::Error;

        async fn get_roster(
            &self,
            command: &RosterGetCommand,
        ) -> anyhow::Result<RosterAuthorization<RosterReadSnapshot>> {
            self.reject(command.owner_id, command.expected_auth_generation)
        }

        async fn upsert_item(
            &self,
            command: &RosterUpsertCommand,
        ) -> anyhow::Result<RosterAuthorization<RosterChange>> {
            self.reject(command.owner_id, command.expected_auth_generation)
        }

        async fn remove_item(
            &self,
            command: &RosterRemoveCommand<'_>,
        ) -> anyhow::Result<RosterAuthorization<Option<RosterRemovalTransition>>> {
            let RosterRemovalRoute::Remote {
                target_domain,
                policy,
                ..
            } = command.route
            else {
                panic!("expected remote notification in the same command");
            };
            assert_eq!(target_domain, "remote.test");
            assert_eq!(policy.max_rows, 20);
            self.reject(command.owner_id, command.expected_auth_generation)
        }
    }

    #[tokio::test]
    async fn repository_denials_and_failures_preserve_authority() {
        let owner = uuid::Uuid::new_v4();
        let service = super::RosterService::new(DenyingRepository {
            calls: std::sync::atomic::AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            owner,
        });
        let get = RosterGetCommand {
            owner_id: owner,
            expected_auth_generation: 7,
            requested_version: Some(-1),
            annotations_requested: false,
        };
        assert_eq!(
            service.execute_roster_get(get.clone()).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        assert_eq!(service.repository.calls.load(Ordering::SeqCst), 0);
        let get = RosterGetCommand {
            requested_version: None,
            ..get
        };
        assert_eq!(
            service.execute_roster_get(get.clone()).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        let upsert = RosterUpsertCommand {
            owner_id: owner,
            expected_auth_generation: 7,
            jid: "bob@remote.test".into(),
            name: None,
            groups: vec![],
        };
        assert_eq!(
            service.execute_roster_upsert(upsert.clone()).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        let remove = RosterRemoveCommand {
            owner_id: owner,
            expected_auth_generation: 7,
            jid: "bob@remote.test",
            route: RosterRemovalRoute::Remote {
                target_domain: "remote.test",
                unsubscribe_stanza: "<presence/>",
                unsubscribed_stanza: "<presence/>",
                bounce_to: None,
                policy: RemoteRemovalPolicy {
                    ttl_seconds: 60,
                    max_rows: 20,
                    max_bytes: 10240,
                    max_per_domain: 10,
                },
            },
        };
        assert_eq!(
            service.execute_roster_remove(remove).await.unwrap(),
            RosterAuthorization::Unauthorized
        );
        service.repository.failed.store(true, Ordering::SeqCst);
        assert_eq!(
            service
                .execute_roster_get(get)
                .await
                .unwrap_err()
                .to_string(),
            "repository unavailable"
        );
        assert_eq!(
            service
                .execute_roster_upsert(upsert)
                .await
                .unwrap_err()
                .to_string(),
            "repository unavailable"
        );
        assert_eq!(
            service
                .execute_roster_remove(remove)
                .await
                .unwrap_err()
                .to_string(),
            "repository unavailable"
        );
        assert_eq!(service.repository.calls.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn synchronization_buffers_orders_and_atomically_exits() {
        let gate = RosterSyncGate::default();
        let requested = AtomicBool::new(false);
        let annotations = AtomicBool::new(false);
        let permit = gate.begin(&requested, &annotations, true).unwrap();
        assert!(requested.load(Ordering::Acquire));
        assert!(annotations.load(Ordering::Acquire));
        assert_eq!(
            gate.route(&requested, &annotations, 13, "v13".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.route(&requested, &annotations, 12, "v12".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.start_flush(permit, 11),
            RosterFlushBatch::Batch(vec![(12, "v12".to_owned()), (13, "v13".to_owned())])
        );
        assert_eq!(
            gate.route(&requested, &annotations, 14, "v14".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.next_flush_batch(permit),
            RosterFlushBatch::Batch(vec![(14, "v14".to_owned())])
        );
        assert_eq!(gate.next_flush_batch(permit), RosterFlushBatch::Complete);
        assert_eq!(
            gate.route(&requested, &annotations, 15, "v15".to_owned(), None),
            RosterPushDisposition::Deliver("v15".to_owned())
        );
    }

    #[test]
    fn mutation_between_gate_entry_and_snapshot_is_delivered_exactly_once() {
        let gate = RosterSyncGate::default();
        let requested = AtomicBool::new(false);
        let annotations = AtomicBool::new(false);
        let permit = gate.begin(&requested, &annotations, false).unwrap();
        // Version 20 committed before the RR snapshot and is represented by
        // the result; version 21 committed after it and must be flushed.
        assert_eq!(
            gate.route(&requested, &annotations, 20, "v20".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.route(&requested, &annotations, 21, "v21".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.start_flush(permit, 20),
            RosterFlushBatch::Batch(vec![(21, "v21".to_owned())])
        );
    }

    #[test]
    fn represented_versions_are_not_replayed_and_overflow_fails_closed() {
        let gate = RosterSyncGate::default();
        let requested = AtomicBool::new(false);
        let annotations = AtomicBool::new(false);
        let permit = gate.begin(&requested, &annotations, false).unwrap();
        for version in 1..=MAX_BUFFERED_ROSTER_CHANGES as i64 {
            assert_eq!(
                gate.route(
                    &requested,
                    &annotations,
                    version,
                    format!("v{version}"),
                    None
                ),
                RosterPushDisposition::Buffered
            );
        }
        assert_eq!(
            gate.route(
                &requested,
                &annotations,
                10_000,
                "overflow".to_owned(),
                None,
            ),
            RosterPushDisposition::Overflow
        );
        assert_eq!(gate.start_flush(permit, 500), RosterFlushBatch::Failed);
        assert_eq!(
            gate.begin(&requested, &annotations, false),
            Err(BeginRosterSyncError::Failed)
        );
        assert_eq!(
            gate.route(
                &requested,
                &annotations,
                10_001,
                "after-failure".to_owned(),
                None,
            ),
            RosterPushDisposition::Overflow
        );
    }

    #[test]
    fn stale_flush_permits_preserve_idle_and_current_generations() {
        let gate = RosterSyncGate::default();
        let requested = AtomicBool::new(false);
        let annotations = AtomicBool::new(false);

        assert_eq!(
            gate.start_flush(RosterSyncPermit { generation: 99 }, 0),
            RosterFlushBatch::Superseded
        );
        let permit = gate.begin(&requested, &annotations, false).unwrap();
        assert_eq!(
            gate.route(&requested, &annotations, 4, "v4".to_owned(), None),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.start_flush(
                RosterSyncPermit {
                    generation: permit.generation + 1,
                },
                3,
            ),
            RosterFlushBatch::Superseded
        );
        assert_eq!(
            gate.start_flush(permit, 3),
            RosterFlushBatch::Batch(vec![(4, "v4".to_owned())])
        );
        assert_eq!(
            gate.start_flush(
                RosterSyncPermit {
                    generation: permit.generation + 1,
                },
                4,
            ),
            RosterFlushBatch::Superseded
        );
        assert_eq!(gate.next_flush_batch(permit), RosterFlushBatch::Complete);
        assert_eq!(gate.start_flush(permit, 4), RosterFlushBatch::Superseded);
        assert!(gate.begin(&requested, &annotations, false).is_ok());
    }

    #[test]
    fn annotation_selection_and_gate_entry_share_one_critical_section() {
        use std::sync::mpsc;
        use std::time::Duration;

        let gate = std::sync::Arc::new(RosterSyncGate::default());
        let requested = std::sync::Arc::new(AtomicBool::new(false));
        let annotations = std::sync::Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let begin_gate = std::sync::Arc::clone(&gate);
        let begin_requested = std::sync::Arc::clone(&requested);
        let begin_annotations = std::sync::Arc::clone(&annotations);
        let begin = std::thread::spawn(move || {
            begin_gate
                .begin_with_hook(&begin_requested, &begin_annotations, true, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })
                .unwrap()
        });
        entered_rx.recv().unwrap();

        let (route_started_tx, route_started_rx) = mpsc::channel();
        let (route_done_tx, route_done_rx) = mpsc::channel();
        let route_gate = std::sync::Arc::clone(&gate);
        let route_requested = std::sync::Arc::clone(&requested);
        let route_annotations = std::sync::Arc::clone(&annotations);
        let route = std::thread::spawn(move || {
            route_started_tx.send(()).unwrap();
            let disposition = route_gate.route(
                &route_requested,
                &route_annotations,
                8,
                "plain".to_owned(),
                Some("annotated".to_owned()),
            );
            route_done_tx.send(disposition).unwrap();
        });
        route_started_rx.recv().unwrap();
        assert!(route_done_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err());

        release_tx.send(()).unwrap();
        let permit = begin.join().unwrap();
        route.join().unwrap();
        assert_eq!(
            route_done_rx.recv().unwrap(),
            RosterPushDisposition::Buffered
        );
        assert_eq!(
            gate.start_flush(permit, 7),
            RosterFlushBatch::Batch(vec![(8, "annotated".to_owned())])
        );
    }

    #[test]
    fn two_resources_select_different_cluster_renderings() {
        let plain_gate = RosterSyncGate::default();
        let annotated_gate = RosterSyncGate::default();
        let plain_requested = AtomicBool::new(false);
        let annotated_requested = AtomicBool::new(false);
        let plain_preference = AtomicBool::new(false);
        let annotated_preference = AtomicBool::new(false);
        let plain_permit = plain_gate
            .begin(&plain_requested, &plain_preference, false)
            .unwrap();
        let annotated_permit = annotated_gate
            .begin(&annotated_requested, &annotated_preference, true)
            .unwrap();
        assert_eq!(
            plain_gate.start_flush(plain_permit, 3),
            RosterFlushBatch::Complete
        );
        assert_eq!(
            annotated_gate.start_flush(annotated_permit, 3),
            RosterFlushBatch::Complete
        );
        assert_eq!(
            plain_gate.route(
                &plain_requested,
                &plain_preference,
                4,
                "plain".to_owned(),
                Some("annotated".to_owned()),
            ),
            RosterPushDisposition::Deliver("plain".to_owned())
        );
        assert_eq!(
            annotated_gate.route(
                &annotated_requested,
                &annotated_preference,
                4,
                "plain".to_owned(),
                Some("annotated".to_owned()),
            ),
            RosterPushDisposition::Deliver("annotated".to_owned())
        );
    }
}
