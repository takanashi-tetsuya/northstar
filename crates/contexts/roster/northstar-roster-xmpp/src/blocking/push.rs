use super::mutation::patterns_from_jids;
use super::BlockingSession;
use northstar_roster_core::PresenceAccount;
use northstar_xep_0191::{BlockingCommand, BlockingMutation};

pub(super) async fn push_blocking_change<S: BlockingSession>(
    session: &S,
    user: &PresenceAccount,
    action: &str,
    jids: &[String],
) {
    let owner = format!("{}@{}", user.username, session.session_local_domain());
    let Some(payload) = blocking_change_payload(action, jids) else {
        tracing::error!(action, "refused unknown XEP-0191 push action");
        return;
    };
    session.blocking_push_change(&owner, &payload).await;
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
