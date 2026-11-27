use super::presence::notify_blocking_presence;
use super::push::push_blocking_change;
use super::BlockingSession;
use anyhow::Result;
use northstar_roster_application::blocking_mutation::{
    BlockingMutation as Mutation, BlockingMutationOutcome,
};
use northstar_xep_0191::{BlockPattern, BlockingCommand, BlockingMutation};
use northstar_xml_builder::stanza::{iq_error, iq_result};
use roxmltree::Node;

/// Answers an XEP-0191 block request.
pub async fn block<S: BlockingSession>(
    session: &S,
    id: &str,
    root: Node<'_, '_>,
) -> Result<String> {
    let (Some(user), Some(actor)) = (session.session_account(), session.roster_actor()) else {
        return Ok(iq_error(id, "not-authorized"));
    };
    let items = match northstar_xep_0191::parse_iq(root) {
        Ok(BlockingCommand::Mutate(BlockingMutation::Block(items))) => items,
        _ => return Ok(iq_error(id, "bad-request")),
    };
    if items.is_empty() {
        return Ok(iq_error(id, "bad-request"));
    }
    let mutation = Mutation::Block(items.into_iter().map(BlockPattern::into_jid).collect());
    let change = match session.apply_blocking(actor, mutation).await? {
        BlockingMutationOutcome::Committed(change) => change,
        BlockingMutationOutcome::QuotaExceeded => {
            return Ok(iq_error(id, "resource-constraint"));
        }
        BlockingMutationOutcome::Unavailable => {
            return Ok(iq_error(id, "not-authorized"));
        }
    };
    if !change.delta.is_empty() {
        let changed = change.delta.clone();
        notify_blocking_presence(session, change).await;
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
    let (Some(user), Some(actor)) = (session.session_account(), session.roster_actor()) else {
        return Ok(iq_error(id, "not-authorized"));
    };
    let mutation = match northstar_xep_0191::parse_iq(root) {
        Ok(BlockingCommand::Mutate(mutation @ BlockingMutation::Unblock(_)))
        | Ok(BlockingCommand::Mutate(mutation @ BlockingMutation::UnblockAll)) => mutation,
        _ => return Ok(iq_error(id, "bad-request")),
    };
    let mutation = match mutation {
        BlockingMutation::Unblock(items) => {
            Mutation::Unblock(items.into_iter().map(BlockPattern::into_jid).collect())
        }
        BlockingMutation::UnblockAll => Mutation::UnblockAll,
        BlockingMutation::Block(_) => unreachable!("unblock parser returned block mutation"),
    };
    let unblock_all = matches!(mutation, Mutation::UnblockAll);
    let change = match session.apply_blocking(actor, mutation).await? {
        BlockingMutationOutcome::Committed(change) => change,
        BlockingMutationOutcome::QuotaExceeded => return Ok(iq_error(id, "resource-constraint")),
        BlockingMutationOutcome::Unavailable => {
            return Ok(iq_error(id, "not-authorized"));
        }
    };
    if !change.delta.is_empty() {
        let changed = change.delta.clone();
        notify_blocking_presence(session, change).await;
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
