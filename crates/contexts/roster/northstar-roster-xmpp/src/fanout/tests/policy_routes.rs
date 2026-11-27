use super::{RosterActor, Routes};
use crate::{fanout::PolicyPushLocalRoutes, PostAcceptFailureTelemetry};
use northstar_roster_application::blocklist_revisions::{
    BlocklistAction, BlocklistChange, BlocklistJournal, BlocklistRevisionRepository,
    BlocklistSnapshot,
};
use northstar_stream::local_routes::{session::OnlineSession, session_table::LocalSessionTable};
use std::sync::Mutex;
use tokio::sync::oneshot;
use uuid::Uuid;

impl PolicyPushLocalRoutes for Routes {
    fn policy_sessions(&self) -> LocalSessionTable {
        let table = LocalSessionTable::default();
        for (full, session) in &self.sessions {
            table.insert(full.clone(), session.clone());
        }
        table
    }
}

pub(super) fn actor(resource: &str, connection_id: Uuid) -> RosterActor {
    RosterActor {
        account_id: Uuid::from_u128(1),
        auth_generation: 7,
        connection_id,
        full_jid: format!("alice@example.test/{resource}"),
    }
}

#[derive(Clone)]
pub(in crate::fanout) struct TestJournal {
    pub(in crate::fanout) revision: i64,
    pub(in crate::fanout) changes: Vec<BlocklistChange>,
}

impl TestJournal {
    pub(super) fn unblock_all() -> Self {
        Self {
            revision: 1,
            changes: vec![BlocklistChange {
                revision: 1,
                action: BlocklistAction::UnblockAll,
                patterns: vec!["bob@example.test".into()],
            }],
        }
    }
}

impl BlocklistRevisionRepository for TestJournal {
    async fn blocklist_snapshot(
        &self,
        _: &RosterActor,
    ) -> anyhow::Result<Option<BlocklistSnapshot>> {
        unreachable!("these tests stage the snapshot explicitly")
    }

    async fn blocklist_journal(
        &self,
        _: &RosterActor,
        after: Option<i64>,
    ) -> anyhow::Result<Option<BlocklistJournal>> {
        let after = after.unwrap_or(self.revision - 1);
        Ok(Some(BlocklistJournal {
            revision: self.revision,
            changes: self
                .changes
                .iter()
                .filter(|change| change.revision > after)
                .cloned()
                .collect(),
        }))
    }
}

pub(in crate::fanout) struct ObservableJournal {
    pub(in crate::fanout) journal: Mutex<TestJournal>,
    pub(in crate::fanout) first_read: Mutex<Option<oneshot::Sender<()>>>,
}

impl BlocklistRevisionRepository for ObservableJournal {
    async fn blocklist_snapshot(
        &self,
        _: &RosterActor,
    ) -> anyhow::Result<Option<BlocklistSnapshot>> {
        unreachable!("these tests stage the snapshot explicitly")
    }

    async fn blocklist_journal(
        &self,
        actor: &RosterActor,
        after: Option<i64>,
    ) -> anyhow::Result<Option<BlocklistJournal>> {
        let snapshot = self.journal.lock().unwrap().clone();
        if let Some(first_read) = self.first_read.lock().unwrap().take() {
            first_read.send(()).unwrap();
        }
        snapshot.blocklist_journal(actor, after).await
    }
}

pub(super) fn start_observer(
    routes: &Routes,
    session: &OnlineSession,
    actor: &RosterActor,
    journal: TestJournal,
) {
    let epoch = session.blocklist_observation.begin_snapshot();
    assert!(session.blocklist_observation.finish_snapshot(epoch, 0));
    let wake = session.blocklist_observation.subscribe();
    let table = routes.policy_sessions();
    let actor = actor.clone();
    let telemetry = PostAcceptFailureTelemetry::new(routes.failures.clone());
    drop(tokio::spawn(async move {
        crate::fanout::run_blocklist_observer(&journal, &table, &actor, epoch, wake, telemetry)
            .await;
    }));
}
