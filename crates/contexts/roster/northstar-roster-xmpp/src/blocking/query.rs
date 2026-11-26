use super::mutation::patterns_from_jids;
use super::BlockingSession;
use anyhow::Result;
use northstar_xep_0191::BlockingCommand;
use northstar_xml_builder::stanza::{iq_error, iq_result};
use roxmltree::Node;

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
