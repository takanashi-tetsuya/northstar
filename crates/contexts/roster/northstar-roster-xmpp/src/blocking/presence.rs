use super::BlockingSession;
use northstar_roster_application::blocking_mutation::CommittedBlockingChange;

pub(super) async fn notify_blocking_presence<S: BlockingSession>(
    session: &S,
    change: CommittedBlockingChange,
) {
    session.blocking_presence_change(change).await;
}
