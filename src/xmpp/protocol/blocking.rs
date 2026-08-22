use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, bare_jid},
};
use anyhow::Result;
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl ProtocolSession {
    pub(crate) async fn blocklist(&self, id: &str) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        self.blocklist_requested.store(true, Ordering::Relaxed);
        let items = db::blocked_jids(&self.state.pool, user.id).await?;
        let mut payload = "<blocklist xmlns='urn:xmpp:blocking'>".to_owned();
        for jid in items {
            payload.push_str(&format!("<item jid='{}'/>", attr_escape(&jid)));
        }
        payload.push_str("</blocklist>");
        Ok(Action::Send(iq_result(id, &payload)))
    }

    pub(crate) async fn block(&self, id: &str, block: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(items) = blocking_items(block, self.full_jid.as_deref()) else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if items.is_empty() {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        db::block_jids(&self.state.pool, user.id, &items).await?;
        for jid in &items {
            self.notify_blocking_presence(user, jid, false).await?;
        }
        self.push_blocking_change("block", &items);
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) async fn unblock(&self, id: &str, unblock: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(items) = blocking_items(unblock, self.full_jid.as_deref()) else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let unblock_all = items.is_empty();
        let changed = if unblock_all {
            db::blocked_jids(&self.state.pool, user.id).await?
        } else {
            items
        };
        db::unblock_jids(
            &self.state.pool,
            user.id,
            if unblock_all { None } else { Some(&changed) },
        )
        .await?;
        for jid in &changed {
            self.notify_blocking_presence(user, jid, true).await?;
        }
        self.push_blocking_change("unblock", if unblock_all { &[] } else { &changed });
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) fn push_blocking_change(&self, action: &str, jids: &[String]) {
        let Some(user) = &self.authenticated else {
            return;
        };
        let owner = format!("{}@{}", user.username, self.state.config.domain);
        let mut payload = format!("<{} xmlns='urn:xmpp:blocking'>", action);
        for jid in jids {
            payload.push_str(&format!("<item jid='{}'/>", attr_escape(jid)));
        }
        payload.push_str(&format!("</{}>", action));
        for (jid, session) in self.state.session_entries_for(&owner) {
            if !session.blocklist_requested.load(Ordering::Relaxed) {
                continue;
            }
            let push = format!(
                "<iq xmlns='jabber:client' to='{}' type='set' id='block-{}'>{}</iq>",
                attr_escape(&jid),
                stream_id(),
                payload
            );
            let _ = session.sender.try_send(push);
        }
    }

    pub(crate) async fn notify_blocking_presence(
        &self,
        user: &db::User,
        blocked: &str,
        available: bool,
    ) -> Result<()> {
        let blocked_bare = bare_jid(blocked);
        let Some((_, _, subscription, _)) =
            db::roster_item(&self.state.pool, user.id, blocked_bare).await?
        else {
            return Ok(());
        };
        if !matches!(subscription.as_str(), "from" | "both") {
            return Ok(());
        }
        let owner = format!("{}@{}", user.username, self.state.config.domain);
        let recipients = self.state.session_entries_for(blocked);
        for (from, session) in self.state.session_entries_for(&owner) {
            if available && !session.available.load(Ordering::Relaxed) {
                continue;
            }
            let kind = if available { "" } else { " type='unavailable'" };
            let presence = format!(
                "<presence xmlns='jabber:client' from='{}' to='{}'{}/>",
                attr_escape(&from),
                attr_escape(blocked),
                kind
            );
            for (_, recipient) in &recipients {
                let _ = recipient.sender.try_send(presence.clone());
            }
        }
        Ok(())
    }
}
