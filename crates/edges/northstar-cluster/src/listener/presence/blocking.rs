use super::super::{ListenerResponse, ListenerTurn};
use crate::{listener_blocking::ClusterListenerBlocking, ClusterAdapters};
use anyhow::Result;

pub(in super::super) async fn deliver_blocking_presence<A: ClusterAdapters>(
    blocking: &ClusterListenerBlocking<A>,
    json: &serde_json::Value,
    target: &str,
    turn: &mut ListenerTurn,
) -> Result<()> {
    let responses = &mut turn.responses;
    let owner = northstar_xmpp_types::jid::canonicalize_bare(target).ok();
    let targets = json["blocking_targets"]
        .as_array()
        .filter(|items| items.len() <= northstar_xep_0191::MAX_ITEMS)
        .and_then(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .and_then(|jid| northstar_xmpp_types::jid::canonicalize(jid).ok())
                })
                .collect::<Option<Vec<_>>>()
        });
    let patterns = json["blocking_patterns"]
        .as_array()
        .filter(|items| items.len() <= northstar_xep_0191::MAX_ITEMS)
        .and_then(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .and_then(|jid| northstar_xmpp_types::jid::canonicalize(jid).ok())
                })
                .collect::<Option<Vec<_>>>()
        });
    if let (Some(owner), Some(targets), Some(patterns)) = (owner, targets, patterns) {
        blocking
            .deliver_presence_change(
                &owner,
                &targets,
                &patterns,
                json["available"].as_bool().unwrap_or(false),
                |node_id, recipient, stanza| {
                    responses.push(ListenerResponse {
                        node_id,
                        recipient,
                        stanza,
                        presence_authority: None,
                    })
                },
            )
            .await?;
    }
    Ok(())
}
