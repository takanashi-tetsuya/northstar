use super::presence::notify_blocking_presence;
use super::push::push_blocking_change;
use super::BlockingSession;
use anyhow::Result;
use northstar_roster_application::blocking::{BlockUpdateOutcome, UnblockUpdateOutcome};
use northstar_xep_0191::{BlockPattern, BlockingCommand, BlockingMutation};
use northstar_xml_builder::stanza::{iq_error, iq_result};
use roxmltree::Node;

/// Answers an XEP-0191 block request.
pub async fn block<S: BlockingSession>(
    session: &S,
    id: &str,
    root: Node<'_, '_>,
) -> Result<String> {
    let Some(user) = session.session_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    let items = match northstar_xep_0191::parse_iq(root) {
        Ok(BlockingCommand::Mutate(BlockingMutation::Block(items))) => items,
        _ => return Ok(iq_error(id, "bad-request")),
    };
    let items = patterns_to_strings(&items);
    if items.is_empty() {
        return Ok(iq_error(id, "bad-request"));
    }
    // Resolve presence authorization before mutating the blocklist.  A
    // post-commit roster failure must not turn a durable command into a
    // transport error that the client may retry without receiving the
    // required transition.
    let roster = session.blocking_service().roster(user.id).await?;
    let changed = match session.blocking_service().block(user.id, &items).await? {
        BlockUpdateOutcome::Changed(changed) => changed,
        BlockUpdateOutcome::QuotaExceeded => {
            return Ok(iq_error(id, "resource-constraint"));
        }
        BlockUpdateOutcome::Unavailable => {
            return Ok(iq_error(id, "not-authorized"));
        }
    };
    if !changed.is_empty() {
        notify_blocking_presence(session, &user, &roster, &changed, false).await;
        push_blocking_change(session, &user, "block", &changed).await;
    }
    Ok(iq_result(id, ""))
}

/// Answers an XEP-0191 unblock request.
pub async fn unblock<S: BlockingSession>(
    session: &S,
    id: &str,
    root: Node<'_, '_>,
) -> Result<String> {
    let Some(user) = session.session_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    let mutation = match northstar_xep_0191::parse_iq(root) {
        Ok(BlockingCommand::Mutate(mutation @ BlockingMutation::Unblock(_)))
        | Ok(BlockingCommand::Mutate(mutation @ BlockingMutation::UnblockAll)) => mutation,
        _ => return Ok(iq_error(id, "bad-request")),
    };
    let items = match &mutation {
        BlockingMutation::Unblock(items) => patterns_to_strings(items),
        BlockingMutation::UnblockAll => Vec::new(),
        BlockingMutation::Block(_) => unreachable!("unblock parser returned block mutation"),
    };
    let roster = session.blocking_service().roster(user.id).await?;
    let unblock_all = items.is_empty();
    let changed = match session
        .blocking_service()
        .unblock(user.id, if unblock_all { None } else { Some(&items) })
        .await?
    {
        UnblockUpdateOutcome::Changed(changed) => changed,
        UnblockUpdateOutcome::Unavailable => {
            return Ok(iq_error(id, "not-authorized"));
        }
    };
    if !changed.is_empty() {
        notify_blocking_presence(session, &user, &roster, &changed, true).await;
        push_blocking_change(
            session,
            &user,
            "unblock",
            if unblock_all { &[] } else { &changed },
        )
        .await;
    }
    Ok(iq_result(id, ""))
}

pub(super) fn patterns_from_jids(jids: &[String]) -> Result<Vec<BlockPattern>> {
    jids.iter()
        .map(|jid| northstar_xmpp_types::jid::CanonicalJid::parse(jid).map(BlockPattern::new))
        .collect()
}

fn patterns_to_strings(patterns: &[BlockPattern]) -> Vec<String> {
    patterns
        .iter()
        .map(|pattern| pattern.jid().to_string())
        .collect()
}
