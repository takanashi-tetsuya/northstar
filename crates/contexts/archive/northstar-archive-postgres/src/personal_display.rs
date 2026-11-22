//! Ordinary personal history projection; governed evidence reads remain raw.

use northstar_message_core::retraction::{render_retraction_tombstone, RetractionEnvelope};
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{postgres::PgRow, Row};
use uuid::Uuid;

use crate::mix_source_retractions::MixSourceRetraction;

pub const PERSONAL_DISPLAY_SELECT: &str =
    "SELECT page.*, fact.action_stanza_id AS mix_action_stanza_id,
            fact.retracted_at AS mix_retracted_at FROM ";

pub const PERSONAL_DISPLAY_JOIN: &str = " AS page LEFT JOIN mix_source_retractions AS fact
      ON fact.source_by=page.source_by AND fact.target_stanza_id=page.source_stanza_id
      AND fact.first_for_target";

pub fn project_personal_archive_content(row: &PgRow) -> (String, bool) {
    let action: Option<Uuid> = row.get("mix_action_stanza_id");
    let source = action.map(|action_stanza_id| {
        (
            row.get("source_by"),
            row.get("source_stanza_id"),
            MixSourceRetraction {
                action_stanza_id,
                retracted_at: row.get("mix_retracted_at"),
            },
        )
    });
    resolve_personal_display(row.get("stanza"), row.get("encrypted"), source)
}

fn resolve_personal_display(
    raw: &str,
    encrypted: bool,
    source: Option<(&str, Uuid, MixSourceRetraction)>,
) -> (String, bool) {
    if let Some((channel, target, primary)) = source {
        return (
            render_mix_source_tombstone(raw, channel, target, &primary),
            false,
        );
    }
    (raw.to_owned(), encrypted)
}

pub fn render_mix_source_tombstone(
    raw: &str,
    channel: &str,
    target: Uuid,
    primary: &MixSourceRetraction,
) -> String {
    let target = target.to_string();
    let parsed = roxmltree::Document::parse(raw).ok();
    let envelope = parsed
        .as_ref()
        .and_then(|document| original_envelope(document.root_element(), channel, &target))
        .unwrap_or(RetractionEnvelope {
            from: Some(channel),
            to: None,
            kind: Some("groupchat"),
            id: Some(&target),
        });
    render_retraction_tombstone(
        envelope,
        [(target.as_str(), channel)],
        &primary.action_stanza_id.to_string(),
        &primary
            .retracted_at
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
    )
}

fn original_envelope<'a>(
    root: roxmltree::Node<'a, '_>,
    channel: &str,
    target: &str,
) -> Option<RetractionEnvelope<'a>> {
    let from = root.attribute("from")?;
    let sender = CanonicalJid::parse(from).ok()?;
    let to = root.attribute("to");
    if root.tag_name().name() != "message"
        || !matches!(
            root.tag_name().namespace(),
            None | Some("jabber:client" | "jabber:server")
        )
        || sender.bare() != channel
        || sender.to_string() != from
        || root.attribute("type") != Some("groupchat")
        || root.attribute("id") != Some(target)
        || to.is_some_and(|jid| CanonicalJid::parse(jid).is_err())
    {
        return None;
    }
    Some(RetractionEnvelope {
        from: Some(from),
        to,
        kind: root.attribute("type"),
        id: root.attribute("id"),
    })
}

#[cfg(test)]
mod tests;
