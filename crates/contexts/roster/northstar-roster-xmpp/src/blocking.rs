//! XEP-0191 blocking commands.

use anyhow::Result;
use northstar_roster_application::blocking::{
    BlockUpdateOutcome, BlockingRepository, BlockingService, UnblockUpdateOutcome,
};
use northstar_roster_core::PresenceAccount;
use northstar_xep_0191::{
    BlockPattern, BlockingCommand, BlockingMutation, PresencePeer, Subscription,
};
use northstar_xml_builder::stanza::{iq_error, iq_result};
use roxmltree::Node;

/// What a client session provides to the XEP-0191 handlers.
pub trait BlockingSession: crate::SessionIdentity {
    /// The blocking service, over the repository the composition root binds.
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository>;
    /// Records that this session asked for the blocklist, which makes it a target of later pushes.
    fn blocking_mark_requested(&self);
    /// Delivers the XEP-0191 `payload` as a push to every resource of `owner` that asked for the
    /// blocklist, on this node and on the others.
    fn blocking_push_change(
        &self,
        owner: &str,
        payload: &str,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Runs the polite-blocking presence transition of `owner`'s resources towards `targets` and
    /// towards the directed-presence peers `changed_patterns` match, on this node and on the
    /// others. `available` says whether the patterns were unblocked.
    fn blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        changed_patterns: &[String],
        available: bool,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Answers an XEP-0191 blocklist request.
pub async fn blocklist<S: BlockingSession>(
    session: &S,
    id: &str,
    root: Node<'_, '_>,
) -> Result<String> {
    let Some(user) = session.session_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    if !matches!(
        northstar_xep_0191::parse_iq(root),
        Ok(BlockingCommand::GetBlocklist)
    ) {
        return Ok(iq_error(id, "bad-request"));
    }
    let items = session.blocking_service().blocked_jids(user.id).await?;
    session.blocking_mark_requested();
    let payload = northstar_xep_0191::build_blocklist_result(&patterns_from_jids(&items)?);
    Ok(iq_result(id, &payload))
}

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

async fn push_blocking_change<S: BlockingSession>(
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

async fn notify_blocking_presence<S: BlockingSession>(
    session: &S,
    user: &PresenceAccount,
    roster: &[(String, Option<String>, String, Option<String>)],
    changed_patterns: &[String],
    available: bool,
) {
    let targets = blocking_presence_targets(roster, changed_patterns);
    let owner = format!("{}@{}", user.username, session.session_local_domain());
    session
        .blocking_presence_change(&owner, &targets, changed_patterns, available)
        .await;
}

fn blocking_change_payload(action: &str, jids: &[String]) -> Option<String> {
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

fn patterns_from_jids(jids: &[String]) -> Result<Vec<BlockPattern>> {
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

fn blocking_presence_targets(
    roster: &[(String, Option<String>, String, Option<String>)],
    patterns: &[String],
) -> Vec<String> {
    let patterns = patterns
        .iter()
        .filter_map(|pattern| northstar_xmpp_types::jid::CanonicalJid::parse(pattern).ok())
        .map(BlockPattern::new)
        .collect::<Vec<_>>();
    let roster = roster
        .iter()
        .filter_map(|(jid, _, subscription, _)| {
            let jid = northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok()?;
            let subscription = match subscription.as_str() {
                "to" => Subscription::To,
                "from" => Subscription::From,
                "both" => Subscription::Both,
                _ => Subscription::None,
            };
            Some(PresencePeer { jid, subscription })
        })
        .collect::<Vec<_>>();
    northstar_xep_0191::presence_targets(&patterns, &roster, &[])
        .into_iter()
        .map(|jid| jid.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_values_cannot_escape_the_structural_builder() {
        let payload =
            blocking_change_payload("block", &["mallory@example.test/'/><injected/>".to_owned()])
                .unwrap();
        let document = roxmltree::Document::parse(&payload).unwrap();
        let root = document.root_element();
        let item = root.children().find(|node| node.is_element()).unwrap();
        assert_eq!(root.tag_name().name(), "block");
        assert_eq!(root.tag_name().namespace(), Some("urn:xmpp:blocking"));
        assert_eq!(
            item.attribute("jid"),
            Some("mallory@example.test/'/><injected/>")
        );
        assert_eq!(root.children().filter(|node| node.is_element()).count(), 1);
    }
}
