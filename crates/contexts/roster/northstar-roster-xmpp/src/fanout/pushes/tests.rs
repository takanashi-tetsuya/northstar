use super::*;
use crate::fanout::tests::policy_routes::{ObservableJournal, TestJournal};
use northstar_roster_application::blocklist_revisions::{BlocklistAction, BlocklistChange};
use northstar_stream::{local_routes::session::test_online_session, outbound::OutboundItem};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

struct Resource {
    actor: RosterActor,
    table: LocalSessionTable,
    session: OnlineSession,
    output: mpsc::Receiver<OutboundItem>,
}

impl Resource {
    fn new() -> Self {
        let actor = RosterActor {
            account_id: Uuid::new_v4(),
            auth_generation: 9,
            connection_id: Uuid::new_v4(),
            full_jid: "alice@example.test/Desk".into(),
        };
        let (session, output) = test_online_session(
            actor.account_id,
            actor.auth_generation,
            actor.connection_id,
            "Desk",
            4,
        );
        let table = LocalSessionTable::default();
        table.insert(actor.full_jid.clone(), session.clone());
        Self {
            actor,
            table,
            session,
            output,
        }
    }

    fn begin(&self) -> u64 {
        let epoch = self.session.blocklist_observation.begin_snapshot();
        self.session
            .blocklist_requested
            .store(true, Ordering::Release);
        epoch
    }

    async fn drain(&self, journal: &TestJournal, epoch: u64, after: i64) -> Option<bool> {
        deliver_journal_batch(journal, &self.table, &self.actor, epoch, after)
            .await
            .unwrap()
    }
}

fn journal() -> TestJournal {
    TestJournal {
        revision: 2,
        changes: [BlocklistAction::Block, BlocklistAction::Unblock]
            .into_iter()
            .enumerate()
            .map(|(index, action)| BlocklistChange {
                revision: i64::try_from(index).unwrap() + 1,
                action,
                patterns: vec!["bob@example.test".into()],
            })
            .collect(),
    }
}

#[tokio::test]
async fn push_before_get_result_waits_and_only_delivers_changes_after_the_snapshot() {
    let mut resource = Resource::new();
    let epoch = resource.begin();
    assert!(resource.session.signal_blocklist_revision(2));
    assert_eq!(resource.drain(&journal(), epoch, 1).await, None);
    assert!(resource.output.try_recv().is_err());
    resource
        .session
        .sender
        .try_send("get-result".into())
        .unwrap();
    assert!(resource
        .session
        .blocklist_observation
        .finish_snapshot(epoch, 1));
    assert_eq!(resource.drain(&journal(), epoch, 1).await, Some(false));
    assert_eq!(resource.output.try_recv().unwrap().stanza, "get-result");
    assert!(resource
        .output
        .try_recv()
        .unwrap()
        .stanza
        .contains("<unblock"));
    assert!(resource.output.try_recv().is_err());
}

#[tokio::test]
async fn get_before_subscribe_recovers_a_change_even_without_a_wake() {
    let mut resource = Resource::new();
    let epoch = resource.begin();
    assert!(resource.session.signal_blocklist_revision(2));
    let wake = resource.session.blocklist_observation.subscribe();
    assert!(!wake.has_changed().unwrap());
    assert!(resource
        .session
        .blocklist_observation
        .finish_snapshot(epoch, 1));
    assert_eq!(resource.drain(&journal(), epoch, 1).await, Some(false));
    assert!(resource
        .output
        .try_recv()
        .unwrap()
        .stanza
        .contains("<unblock"));
    assert!(resource.output.try_recv().is_err());
}

#[tokio::test]
async fn a_new_snapshot_fences_off_older_pushes_still_in_the_transport_queue() {
    let mut resource = Resource::new();
    let first = resource.begin();
    assert!(resource
        .session
        .blocklist_observation
        .finish_snapshot(first, 0));
    assert!(send_blocklist_revision(
        &resource.table,
        &resource.actor,
        first,
        1,
        "superseded".into()
    )
    .await
    .unwrap());
    let second = resource.begin();
    assert!(resource
        .session
        .blocklist_observation
        .finish_snapshot(second, 1));
    assert_eq!(resource.drain(&journal(), second, 1).await, Some(false));
    assert_eq!(
        resource
            .output
            .try_recv()
            .unwrap()
            .snapshot_push_is_current(),
        Some(false)
    );
    let current = resource.output.try_recv().unwrap();
    assert_eq!(current.snapshot_push_is_current(), Some(true));
    assert!(current.stanza.contains("<unblock"));
}

#[tokio::test]
async fn inverse_and_duplicate_wakes_repair_the_gap_and_never_repeat_a_push() {
    let mut resource = Resource::new();
    let epoch = resource.begin();
    assert!(resource
        .session
        .blocklist_observation
        .finish_snapshot(epoch, 0));
    let mut wake = resource.session.blocklist_observation.subscribe();
    assert!(resource.session.signal_blocklist_revision(2));
    wake.changed().await.unwrap();
    assert_eq!(resource.drain(&journal(), epoch, 0).await, Some(false));
    assert!(resource
        .output
        .try_recv()
        .unwrap()
        .stanza
        .contains("<block"));
    assert!(resource
        .output
        .try_recv()
        .unwrap()
        .stanza
        .contains("<unblock"));
    assert!(resource.session.signal_blocklist_revision(1));
    assert!(resource.session.signal_blocklist_revision(2));
    assert!(!wake.has_changed().unwrap());
    assert_eq!(resource.drain(&journal(), epoch, 2).await, Some(false));
    assert!(resource.output.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn periodic_reconciliation_delivers_a_final_revision_with_no_notification() {
    let mut resource = Resource::new();
    let epoch = resource.begin();
    assert!(resource
        .session
        .blocklist_observation
        .finish_snapshot(epoch, 0));
    let (first_read, read_done) = oneshot::channel();
    let repository = Arc::new(ObservableJournal {
        journal: Mutex::new(TestJournal {
            revision: 0,
            changes: Vec::new(),
        }),
        first_read: Mutex::new(Some(first_read)),
    });
    let observer_repository = Arc::clone(&repository);
    let table = resource.table.clone();
    let actor = resource.actor.clone();
    let wake = resource.session.blocklist_observation.subscribe();
    let observer = tokio::spawn(async move {
        run_blocklist_observer(
            observer_repository.as_ref(),
            &table,
            &actor,
            epoch,
            wake,
            PostAcceptFailureTelemetry::new(Arc::default()),
        )
        .await;
    });
    read_done.await.unwrap();
    *repository.journal.lock().unwrap() = journal();
    assert!(resource.output.try_recv().is_err());
    tokio::time::advance(BLOCKLIST_RECONCILE_INTERVAL).await;
    for element in ["<block", "<unblock"] {
        let push = tokio::time::timeout(Duration::from_secs(1), resource.output.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(push.stanza.contains(element));
    }
    assert_eq!(
        resource.session.blocklist_observation.cursor(epoch),
        Some(2)
    );
    observer.abort();
}

#[tokio::test]
async fn an_unrepairable_gap_disconnects_only_the_exact_incarnation() {
    let resource = Resource::new();
    let epoch = resource.begin();
    assert!(resource
        .session
        .blocklist_observation
        .finish_snapshot(epoch, 0));
    let mut missing = journal();
    missing.changes.remove(0);
    assert!(
        deliver_journal_batch(&missing, &resource.table, &resource.actor, epoch, 0)
            .await
            .unwrap_err()
            .to_string()
            .contains("gap")
    );
    for wrong in [
        RosterActor {
            connection_id: Uuid::new_v4(),
            ..resource.actor.clone()
        },
        RosterActor {
            account_id: Uuid::new_v4(),
            ..resource.actor.clone()
        },
        RosterActor {
            auth_generation: 10,
            ..resource.actor.clone()
        },
    ] {
        assert!(
            !send_blocklist_revision(&resource.table, &wrong, epoch, 1, "stale".into())
                .await
                .unwrap()
        );
        assert!(!resynchronize_blocklist(&resource.table, &wrong, epoch));
    }
    assert!(!resource.session.disconnect.is_cancelled());
    assert!(resynchronize_blocklist(
        &resource.table,
        &resource.actor,
        epoch
    ));
    assert!(resource.session.disconnect.is_cancelled());
}
