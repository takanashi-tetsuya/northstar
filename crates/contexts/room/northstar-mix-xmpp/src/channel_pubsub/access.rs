use super::*;
use northstar_room_core::mix::{MixChannelId, MixRealJid};

pub(super) async fn get(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    max: i64,
) -> Result<String> {
    let entries = match state
        .mix_service()
        .authorized_mix_access_entries(channel.id, actor, node == NODE_BANNED, max)
        .await?
    {
        MixReadOutcome::Found(entries) => entries,
        MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
            return Ok(iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            ));
        }
    };
    let mut items = XmlElement::new("items").attr("node", node);
    for entry in &entries {
        items.push_child(XmlElement::new("item").attr("id", entry));
    }
    let payload = XmlElement::namespaced("pubsub", PUBSUB_NS)
        .child(items)
        .finish();
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &payload,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    item_count: usize,
    item_ids: &[String],
    fields: &BTreeMap<String, Vec<String>>,
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    anyhow::ensure!(
        item_count == 1 && item_ids.len() == 1,
        "MIX access publish requires one identified item"
    );
    anyhow::ensure!(
        fields.is_empty(),
        "MIX access items do not contain payloads"
    );
    let pattern =
        northstar_room_application::mix_service::canonical_mix_access_pattern(&item_ids[0])?;
    let committed = state
        .mix_service()
        .set_mix_access_entry_committed(
            &MixChannelId::new(channel.id),
            &MixRealJid::parse(actor)?,
            &pattern,
            if node == NODE_BANNED {
                MixAccessList::Banned
            } else {
                MixAccessList::Allowed
            },
            MixAccessEntryOperation::Publish { reason: None },
            federated,
        )
        .await?;
    if committed.outcome.is_none() {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    }
    for delta in &committed.roster {
        push_mix_roster_update(state, delta).await?;
    }
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &mix_empty_pubsub(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn retract(
    state: &Arc<impl MixHost>,
    request: &OwnedIq,
    channel: &MixChannel,
    actor: &str,
    reply_to: &str,
    node: &str,
    item_ids: &[String],
    federated: Option<&FederatedMixMutation>,
) -> Result<String> {
    let pattern =
        northstar_room_application::mix_service::canonical_mix_access_pattern(&item_ids[0])?;
    let Some(_) = state
        .mix_service()
        .set_mix_access_entry(
            MixAccessEntryUpdate {
                channel_id: channel.id,
                actor,
                pattern: &pattern,
                list: if node == NODE_BANNED {
                    MixAccessList::Banned
                } else {
                    MixAccessList::Allowed
                },
                operation: MixAccessEntryOperation::Retract,
            },
            federated,
        )
        .await?
    else {
        return Ok(iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            "auth",
            "forbidden",
        ));
    };
    Ok(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &mix_empty_pubsub(),
    ))
}
