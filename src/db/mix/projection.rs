//! MIX node audiences and presence and node event projection into the delivery queue.

use super::*;

pub(super) async fn mix_subscribers_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    node: &str,
) -> Result<Vec<MixParticipant>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    let rows = sqlx::query(
        "SELECT p.channel_id, p.participant_id, p.jid, p.nick, p.role, p.joined_at FROM mix_participants p JOIN mix_subscriptions s ON s.channel_id = p.channel_id AND s.participant_id = p.participant_id WHERE p.channel_id = $1 AND s.node = $2 ORDER BY p.participant_id",
    )
    .bind(channel_id)
    .bind(node)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(rows.iter().map(participant_from_row).collect())
}

pub(super) async fn mix_node_audience_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    node: &str,
) -> Result<Vec<MixParticipant>> {
    anyhow::ensure!(ALL_NODES.contains(&node), "unknown MIX node");
    if matches!(node, NODE_CONFIG | NODE_ALLOWED | NODE_BANNED | NODE_JIDMAP) {
        let rows = sqlx::query(
            "SELECT p.channel_id,p.participant_id,p.jid,p.nick,p.role,p.joined_at
               FROM mix_participants p
               JOIN mix_channel_roles r ON r.channel_id=p.channel_id AND r.jid=p.jid
              WHERE p.channel_id=$1 AND r.role IN ('owner','administrator')
              ORDER BY p.participant_id",
        )
        .bind(channel_id)
        .fetch_all(&mut **transaction)
        .await?;
        return Ok(rows.iter().map(participant_from_row).collect());
    }
    mix_subscribers_tx(transaction, channel_id, node).await
}

pub(super) fn extend_unique_mix_recipients(
    recipients: &mut Vec<MixParticipant>,
    extras: impl IntoIterator<Item = MixParticipant>,
) {
    let mut seen = recipients
        .iter()
        .map(|participant| participant.jid.clone())
        .collect::<BTreeSet<_>>();
    for participant in extras {
        if seen.insert(participant.jid.clone()) {
            recipients.push(participant);
        }
    }
    recipients.sort_by_key(|participant| participant.participant_id);
}

pub(super) struct MixPresenceProjection<'a> {
    pub(super) channel: &'a MixChannel,
    pub(super) participant: &'a MixParticipant,
    pub(super) preference: &'a MixParticipantPreference,
    pub(super) item: &'a MixPresenceItem,
    pub(super) unavailable: bool,
    pub(super) event_id: Uuid,
    pub(super) extra_recipients: Vec<MixParticipant>,
}

pub(super) async fn enqueue_mix_presence_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    projection: MixPresenceProjection<'_>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<Vec<MixParticipant>> {
    let MixPresenceProjection {
        channel,
        participant,
        preference,
        item,
        unavailable,
        event_id,
        extra_recipients,
    } = projection;
    let mut recipients = mix_node_audience_tx(transaction, channel.id, NODE_PRESENCE).await?;
    extend_unique_mix_recipients(&mut recipients, extra_recipients);
    let encoded = northstar_xmpp_types::jid::CanonicalJid::parse(&item.item_id)?;
    let resource = encoded
        .resourcepart()
        .context("stored MIX presence item has no resource")?;
    let actor_full = item
        .source_full_jid
        .clone()
        .unwrap_or_else(|| format!("{}/{}", participant.jid, resource));
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.presence_delivery_stanza(MixPresenceDelivery {
                channel,
                participant,
                preference,
                recipient,
                item_id: &item.item_id,
                actor_full: &actor_full,
                children: &item.payload,
                unavailable,
            })
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        transaction,
        fence,
        MixDeliveryProjection {
            channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    Ok(recipients)
}

pub(super) async fn reproject_mix_presence_visibility_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    old_channel: &MixChannel,
    new_channel: &MixChannel,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<()> {
    if old_channel.jid_visibility == new_channel.jid_visibility {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT e.id,e.item_id,e.payload,e.source_full_jid,
                p.participant_id,p.jid,p.nick,
                pref.jid_visibility,pref.private_messages,pref.vcard,pref.share_presence
           FROM mix_events e
           JOIN mix_participants p
             ON p.channel_id=e.channel_id AND p.participant_id=e.publisher_id
           JOIN mix_participant_preferences pref
             ON pref.channel_id=p.channel_id AND pref.participant_id=p.participant_id
          WHERE e.channel_id=$1 AND e.node=$2
          ORDER BY e.created_at,e.id FOR UPDATE OF e,p,pref",
    )
    .bind(new_channel.id)
    .bind(NODE_PRESENCE)
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let participant = MixParticipant {
            participant_id: row.get("participant_id"),
            jid: row.get("jid"),
            nick: row.get("nick"),
        };
        let preference = MixParticipantPreference {
            jid_visibility: row.get("jid_visibility"),
            private_messages: row.get("private_messages"),
            vcard: row.get("vcard"),
            share_presence: row.get("share_presence"),
        };
        if participant_jid_visible(old_channel, &preference)
            == participant_jid_visible(new_channel, &preference)
        {
            continue;
        }
        let old_item = MixPresenceItem {
            item_id: row.get("item_id"),
            payload: row.get("payload"),
            source_full_jid: row.get("source_full_jid"),
        };
        sqlx::query("DELETE FROM mix_events WHERE id=$1")
            .bind(row.get::<Uuid, _>("id"))
            .execute(&mut **transaction)
            .await?;
        enqueue_mix_presence_event_tx(
            transaction,
            fence,
            MixPresenceProjection {
                channel: old_channel,
                participant: &participant,
                preference: &preference,
                item: &old_item,
                unavailable: true,
                event_id: Uuid::new_v4(),
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
        let Some(source_full_jid) = old_item.source_full_jid.as_deref() else {
            continue;
        };
        let source = northstar_xmpp_types::jid::CanonicalJid::parse(source_full_jid)?;
        let public_resource = if participant_jid_visible(new_channel, &preference) {
            source
                .resourcepart()
                .context("MIX presence source lost its resource")?
                .to_owned()
        } else {
            Uuid::new_v4().simple().to_string()
        };
        let item_id =
            mix_presence_item_id(new_channel, participant.participant_id, &public_resource)?;
        let event_id = store_mix_event_tx(
            transaction,
            new_channel,
            NODE_PRESENCE,
            &item_id,
            Some(&participant),
            &old_item.payload,
        )
        .await?
        .context("MIX configuration presence event unexpectedly conflicted")?;
        sqlx::query(
            "UPDATE mix_events SET source_full_jid=$4
              WHERE channel_id=$1 AND node=$2 AND item_id=$3",
        )
        .bind(new_channel.id)
        .bind(NODE_PRESENCE)
        .bind(&item_id)
        .bind(source_full_jid)
        .execute(&mut **transaction)
        .await?;
        let new_item = MixPresenceItem {
            item_id,
            payload: old_item.payload,
            source_full_jid: Some(source_full_jid.to_owned()),
        };
        enqueue_mix_presence_event_tx(
            transaction,
            fence,
            MixPresenceProjection {
                channel: new_channel,
                participant: &participant,
                preference: &preference,
                item: &new_item,
                unavailable: false,
                event_id,
                extra_recipients: Vec::new(),
            },
            payloads,
        )
        .await?;
    }
    Ok(())
}

pub(super) struct MixNodeProjection<'a> {
    pub(super) channel: &'a MixChannel,
    pub(super) node: &'a str,
    pub(super) item_id: &'a str,
    pub(super) payload: Option<&'a str>,
    pub(super) retract: bool,
    pub(super) event_id: Uuid,
    pub(super) extra_recipients: Vec<MixParticipant>,
}

pub(super) async fn enqueue_mix_node_event_tx(
    transaction: &mut Transaction<'_, Postgres>,
    fence: &MixDeliveryAdmissionFence,
    projection: MixNodeProjection<'_>,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<Vec<MixParticipant>> {
    let MixNodeProjection {
        channel,
        node,
        item_id,
        payload,
        retract,
        event_id,
        extra_recipients,
    } = projection;
    let mut recipients = mix_node_audience_tx(transaction, channel.id, node).await?;
    extend_unique_mix_recipients(&mut recipients, extra_recipients);
    let stanza_template = recipients
        .first()
        .map(|recipient| {
            payloads.node_event_stanza(channel, recipient, node, item_id, payload, retract)
        })
        .transpose()?
        .unwrap_or_default();
    enqueue_mix_deliveries_tx(
        transaction,
        fence,
        MixDeliveryProjection {
            channel,
            event_id,
            recipients: &recipients,
            stanza_template: &stanza_template,
            authoritative_stanza_id: None,
            archive: false,
            encrypted: false,
        },
    )
    .await?;
    Ok(recipients)
}
