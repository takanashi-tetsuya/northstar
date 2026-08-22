use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, bare_jid},
};
use anyhow::Result;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) async fn mam(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let with = mam_field(query, "with");
        if let Some(form_type) = mam_field(query, "FORM_TYPE") {
            if form_type != "urn:xmpp:mam:2" {
                return Ok(Action::Send(iq_error(id, "bad-request")));
            }
        }
        let start = match mam_field(query, "start") {
            Some(value) => match chrono::DateTime::parse_from_rfc3339(value) {
                Ok(value) => Some(value.with_timezone(&chrono::Utc)),
                Err(_) => return Ok(Action::Send(iq_error(id, "bad-request"))),
            },
            None => None,
        };
        let end = match mam_field(query, "end") {
            Some(value) => match chrono::DateTime::parse_from_rfc3339(value) {
                Ok(value) => Some(value.with_timezone(&chrono::Utc)),
                Err(_) => return Ok(Action::Send(iq_error(id, "bad-request"))),
            },
            None => None,
        };
        if matches!((&start, &end), (Some(start), Some(end)) if start > end) {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let max = query
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "max"
                    && node.tag_name().namespace() == Some("http://jabber.org/protocol/rsm")
            })
            .and_then(|node| node.text())
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(100)
            .clamp(0, 100);
        let before = rsm_value(query, "before");
        let after = rsm_value(query, "after");
        if before.is_some() && after.is_some() {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let cursor = if let Some(value) = after.flatten() {
            let Ok(value) = uuid::Uuid::parse_str(value) else {
                return Ok(Action::Send(iq_error(id, "bad-request")));
            };
            db::ArchiveCursor::After(value)
        } else if let Some(Some(value)) = before {
            let Ok(value) = uuid::Uuid::parse_str(value) else {
                return Ok(Action::Send(iq_error(id, "bad-request")));
            };
            db::ArchiveCursor::Before(value)
        } else {
            db::ArchiveCursor::Latest
        };
        let Some(page) = db::archive_page(
            &self.state.pool,
            user.id,
            with.map(bare_jid),
            start,
            end,
            cursor,
            max,
        )
        .await?
        else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let mut replies = Vec::with_capacity(page.rows.len() + 1);
        let query_id = query.attribute("queryid").unwrap_or_default();
        for item in &page.rows {
            let forwarded = format!("<message xmlns='jabber:client' to='{}'><result xmlns='urn:xmpp:mam:2' id='{}' queryid='{}'><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' stamp='{}'/>{}</forwarded></result></message>",
                    attr_escape(self.full_jid.as_deref().unwrap_or_default()), item.id, attr_escape(query_id), item.created_at.format("%Y-%m-%dT%H:%M:%SZ"), item.stanza);
            replies.push(forwarded);
        }
        let first = page
            .rows
            .first()
            .map(|m| m.id.to_string())
            .unwrap_or_default();
        let last = page
            .rows
            .last()
            .map(|m| m.id.to_string())
            .unwrap_or_default();
        replies.push(iq_result(id, &format!("<fin xmlns='urn:xmpp:mam:2' complete='{}' stable='true'><set xmlns='http://jabber.org/protocol/rsm'><first index='{}'>{}</first><last>{}</last><count>{}</count></set></fin>", page.complete, page.first_index, first, last, page.total)));
        Ok(Action::SendMany(replies))
    }
}
