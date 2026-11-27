use super::mutation::patterns_from_jids;
use super::BlockingSession;
use northstar_roster_application::blocklist_revisions::{BlocklistAction, BlocklistChange};
use northstar_xep_0191::{BlockingCommand, BlockingMutation};

pub(super) async fn push_blocking_change<S: BlockingSession>(session: &S) {
    if let Some(actor) = session.roster_actor() {
        session.blocking_push_change(&actor).await;
    }
}

pub(crate) fn journal_payload(change: &BlocklistChange) -> Option<String> {
    let (action, patterns) = match change.action {
        BlocklistAction::Block => ("block", change.patterns.as_slice()),
        BlocklistAction::Unblock => ("unblock", change.patterns.as_slice()),
        BlocklistAction::UnblockAll => ("unblock", &[][..]),
    };
    blocking_change_payload(action, patterns)
}

pub(super) fn blocking_change_payload(action: &str, jids: &[String]) -> Option<String> {
    let items = patterns_from_jids(jids).ok()?;
    let mutation = match action {
        "block" => BlockingMutation::Block(items),
        "unblock" if items.is_empty() => BlockingMutation::UnblockAll,
        "unblock" => BlockingMutation::Unblock(items),
        _ => return None,
    };
    Some(northstar_xep_0191::build_payload(&BlockingCommand::Mutate(
        mutation,
    )))
}
