//! RFC 6121/XEP-0237 roster application boundary.
//!
//! PostgreSQL reads and mutations live behind `RosterService`.  The per-
//! resource [`RosterSyncGate`] closes the initial-result/push race without
//! holding a database transaction across transport backpressure.
//!
//! Safety Invariants: MAX_BUFFERED_ROSTER_CHANGES, RosterSyncState::Flushing

use crate::db;
use anyhow::Result;
use northstar_roster_application::{
    validate_roster_get_command, validate_roster_remove_command, validate_roster_upsert_command,
    RosterGetCommand, RosterRemovalRoute, RosterRemoveCommand, RosterUpsertCommand,
};
use northstar_roster_core::{
    RosterAuthorization, RosterChange, RosterReadSnapshot, RosterRemovalTransition,
};
use sqlx::PgPool;
use uuid::Uuid;

fn removal_route_to_db<'a>(route: RosterRemovalRoute<'a>) -> db::RosterRemovalRoute<'a> {
    match route {
        RosterRemovalRoute::Local {
            owner_jid,
            contact_username,
        } => db::RosterRemovalRoute::Local {
            owner_jid,
            contact_username,
        },
        RosterRemovalRoute::Remote {
            target_domain,
            unsubscribe_stanza,
            unsubscribed_stanza,
            bounce_to,
            policy,
        } => db::RosterRemovalRoute::Remote {
            target_domain,
            unsubscribe_stanza,
            unsubscribed_stanza,
            bounce_to,
            policy: crate::db::S2sOutboxPolicy {
                ttl_seconds: policy.ttl_seconds,
                max_rows: policy.max_rows,
                max_bytes: policy.max_bytes,
                max_per_domain: policy.max_per_domain,
            },
        },
    }
}

#[derive(Clone)]
pub(crate) struct RosterService {
    pool: PgPool,
}

impl RosterService {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn execute_roster_get(
        &self,
        command: RosterGetCommand,
    ) -> Result<RosterAuthorization<RosterReadSnapshot>> {
        if let Err(_err) = validate_roster_get_command(&command) {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.read_snapshot(
            command.owner_id,
            command.expected_auth_generation,
            command.requested_version,
            command.annotations_requested,
        )
        .await
    }

    pub(crate) async fn execute_roster_upsert(
        &self,
        command: RosterUpsertCommand,
    ) -> Result<RosterAuthorization<RosterChange>> {
        if let Err(_err) = validate_roster_upsert_command(&command) {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.upsert(
            command.owner_id,
            command.expected_auth_generation,
            &command.jid,
            command.name.as_deref(),
            &command.groups,
        )
        .await
    }

    pub(crate) async fn execute_roster_remove(
        &self,
        command: RosterRemoveCommand<'_>,
    ) -> Result<RosterAuthorization<Option<RosterRemovalTransition>>> {
        if let Err(_err) = validate_roster_remove_command(&command) {
            return Ok(RosterAuthorization::Unauthorized);
        }
        self.remove(
            command.owner_id,
            command.expected_auth_generation,
            command.jid,
            removal_route_to_db(command.route),
        )
        .await
    }

    pub(crate) async fn read_snapshot(
        &self,
        owner_id: Uuid,
        expected_auth_generation: i64,
        requested_version: Option<i64>,
        annotations_requested: bool,
    ) -> Result<RosterAuthorization<RosterReadSnapshot>> {
        Ok(
            match db::roster_read_snapshot(
                &self.pool,
                owner_id,
                expected_auth_generation,
                requested_version,
                annotations_requested,
            )
            .await?
            {
                Some(snapshot) => RosterAuthorization::Authorized(snapshot),
                None => RosterAuthorization::Unauthorized,
            },
        )
    }

    pub(crate) async fn upsert(
        &self,
        owner_id: Uuid,
        expected_auth_generation: i64,
        jid: &str,
        name: Option<&str>,
        groups: &[String],
    ) -> Result<RosterAuthorization<RosterChange>> {
        Ok(
            match db::upsert_roster_authorized(
                &self.pool,
                owner_id,
                expected_auth_generation,
                jid,
                name,
                groups,
            )
            .await?
            {
                Some(change) => RosterAuthorization::Authorized(change),
                None => RosterAuthorization::Unauthorized,
            },
        )
    }

    pub(crate) async fn remove(
        &self,
        owner_id: Uuid,
        expected_auth_generation: i64,
        jid: &str,
        route: db::RosterRemovalRoute<'_>,
    ) -> Result<RosterAuthorization<Option<RosterRemovalTransition>>> {
        Ok(
            match db::remove_roster_item_authorized(
                &self.pool,
                owner_id,
                expected_auth_generation,
                jid,
                route,
            )
            .await?
            {
                db::AuthorizedRosterRemoval::Unauthorized => RosterAuthorization::Unauthorized,
                db::AuthorizedRosterRemoval::Missing => RosterAuthorization::Authorized(None),
                db::AuthorizedRosterRemoval::Removed(transition) => {
                    RosterAuthorization::Authorized(Some(*transition))
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use northstar_roster_application::*;
    use std::sync::atomic::{AtomicBool, Ordering};

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
