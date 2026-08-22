use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, bare_jid, jid_domain, localpart},
};
use anyhow::Result;
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl ProtocolSession {
    pub(crate) async fn presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        if self.authenticated.is_none() {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        }
        let Some(from) = self.full_jid.clone() else {
            return Ok(Action::None);
        };
        let kind = root.attribute("type").unwrap_or("available");
        if let Some(to) = root.attribute("to") {
            if jid_domain(to).is_some_and(|domain| domain.eq_ignore_ascii_case(&self.muc_domain()))
            {
                return self.muc_presence(root, raw).await;
            }
            let user = self.authenticated.as_ref().expect("authenticated session");
            if jid_domain(to)
                .is_some_and(|domain| !domain.eq_ignore_ascii_case(&self.state.config.domain))
            {
                let domain = jid_domain(to).expect("directed presence has a remote domain");
                if !self.state.config.federation_domain_allowed(domain) {
                    return Ok(Action::Send(stanza_error(
                        root,
                        "cancel",
                        "remote-server-not-found",
                    )));
                }
                if db::is_blocked(&self.state.pool, user.id, to).await? {
                    return Ok(Action::None);
                }
                if matches!(
                    kind,
                    "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
                ) {
                    self.update_remote_presence_subscription(user, bare_jid(to), kind)
                        .await?;
                }
                self.state
                    .federation
                    .send(domain, set_from(raw, &from), Some(from.to_owned()));
                return Ok(Action::None);
            }
            if db::is_blocked(&self.state.pool, user.id, to).await? {
                return if matches!(
                    kind,
                    "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
                ) {
                    Ok(Action::None)
                } else {
                    Ok(Action::Send(blocked_stanza_error(root)))
                };
            }
            let target_name = localpart(to).to_ascii_lowercase();
            if let Some(target) = db::find_user(&self.state.pool, &target_name).await? {
                if db::is_blocked(&self.state.pool, target.id, &from).await? {
                    return Ok(Action::None);
                }
            }
            let should_route = if matches!(
                kind,
                "subscribe" | "subscribed" | "unsubscribe" | "unsubscribed"
            ) {
                self.update_presence_subscription(user, bare_jid(to), kind)
                    .await?
            } else {
                true
            };
            if should_route {
                let rewritten = set_from(raw, &from);
                for target in self.state.sessions_for(to) {
                    let _ = target.sender.try_send(rewritten.clone());
                }
            }
        } else {
            let user = self.authenticated.as_ref().expect("authenticated session");
            if let Some(available) = &self.available {
                available.store(kind == "available", Ordering::Relaxed);
            }
            let priority = if kind == "available" {
                child_text(root, "priority")
                    .and_then(|value| value.parse::<i16>().ok())
                    .filter(|value| (-128..=127).contains(value))
                    .unwrap_or(0)
            } else {
                0
            };
            self.priority.store(priority, Ordering::Relaxed);
            let roster = db::roster(&self.state.pool, user.id).await?;
            let rewritten = set_from(raw, &from);
            for (jid, _, subscription, _) in roster {
                if db::is_blocked(&self.state.pool, user.id, &jid).await? {
                    continue;
                }
                if let Some(contact) = db::find_user(&self.state.pool, localpart(&jid)).await? {
                    if db::is_blocked(&self.state.pool, contact.id, &from).await? {
                        continue;
                    }
                }
                if matches!(subscription.as_str(), "from" | "both") {
                    for target in self.state.sessions_for(&jid) {
                        let _ = target.sender.try_send(rewritten.clone());
                    }
                }
                if kind == "available" && matches!(subscription.as_str(), "to" | "both") {
                    self.send_current_availability(&jid, &from);
                }
            }

            if kind == "available" {
                let offline = db::take_offline(&self.state.pool, user.id).await?;
                for stanza in offline {
                    let _ = self.outbound.try_send(stanza);
                }
            }

            if kind == "available" {
                for requester in
                    db::pending_presence_subscriptions(&self.state.pool, user.id).await?
                {
                    let request = format!(
                        "<presence xmlns='jabber:client' from='{}@{}' to='{}' type='subscribe'/>",
                        attr_escape(&requester),
                        attr_escape(&self.state.config.domain),
                        attr_escape(&from)
                    );
                    let _ = self.outbound.try_send(request);
                }
                for requester in db::federated_presence_pending(&self.state.pool, user.id).await? {
                    let request = format!(
                        "<presence xmlns='jabber:client' from='{}' to='{}' type='subscribe'/>",
                        attr_escape(&requester),
                        attr_escape(&from)
                    );
                    let _ = self.outbound.try_send(request);
                }
            }
        }
        Ok(Action::None)
    }

    pub(crate) async fn update_remote_presence_subscription(
        &self,
        user: &db::User,
        contact: &str,
        kind: &str,
    ) -> Result<()> {
        let existing = db::roster_item(&self.state.pool, user.id, contact).await?;
        let subscription = existing
            .as_ref()
            .map(|item| item.2.as_str())
            .unwrap_or("none");
        let ask = existing.as_ref().and_then(|item| item.3.as_deref());
        let (subscription, ask) = match kind {
            "subscribe" => (subscription.to_owned(), Some("subscribe")),
            "subscribed" => (add_subscription(subscription, "from"), ask),
            "unsubscribe" => (remove_subscription(subscription, "to"), None),
            "unsubscribed" => (remove_subscription(subscription, "from"), ask),
            _ => return Ok(()),
        };
        db::update_subscription(&self.state.pool, user.id, contact, &subscription, ask).await?;
        if matches!(kind, "subscribed" | "unsubscribed") {
            db::remove_federated_presence_pending(&self.state.pool, user.id, contact).await?;
        }
        self.push_roster_item(&user.username, user.id, contact)
            .await?;
        Ok(())
    }

    pub(crate) async fn update_presence_subscription(
        &self,
        actor: &db::User,
        target_jid: &str,
        kind: &str,
    ) -> Result<bool> {
        let target_name = localpart(target_jid).to_ascii_lowercase();
        let Some(target) = db::find_user(&self.state.pool, &target_name).await? else {
            return Ok(false);
        };
        let actor_jid = format!("{}@{}", actor.username, self.state.config.domain);
        let target_jid = format!("{}@{}", target.username, self.state.config.domain);
        let actor_item = db::roster_item(&self.state.pool, actor.id, &target_jid).await?;
        let target_item = db::roster_item(&self.state.pool, target.id, &actor_jid).await?;
        let actor_subscription = actor_item
            .as_ref()
            .map(|item| item.2.as_str())
            .unwrap_or("none");
        let target_subscription = target_item
            .as_ref()
            .map(|item| item.2.as_str())
            .unwrap_or("none");

        if kind == "subscribe" {
            if matches!(actor_subscription, "to" | "both") {
                db::update_subscription(
                    &self.state.pool,
                    actor.id,
                    &target_jid,
                    actor_subscription,
                    None,
                )
                .await?;
                db::remove_pending_presence_subscription(&self.state.pool, actor.id, target.id)
                    .await?;
                self.push_roster_item(&actor.username, actor.id, &target_jid)
                    .await?;
                return Ok(false);
            }
            db::update_subscription(
                &self.state.pool,
                actor.id,
                &target_jid,
                actor_subscription,
                Some("subscribe"),
            )
            .await?;
            db::add_pending_presence_subscription(&self.state.pool, actor.id, target.id).await?;
            self.push_roster_item(&actor.username, actor.id, &target_jid)
                .await?;
            return Ok(true);
        }

        let actor_ask = actor_item.as_ref().and_then(|item| item.3.as_deref());
        let (new_actor_subscription, new_target_subscription, clear_actor_ask) = match kind {
            "subscribed" => (
                add_subscription(actor_subscription, "from"),
                add_subscription(target_subscription, "to"),
                false,
            ),
            "unsubscribe" => (
                remove_subscription(actor_subscription, "to"),
                remove_subscription(target_subscription, "from"),
                true,
            ),
            "unsubscribed" => (
                remove_subscription(actor_subscription, "from"),
                remove_subscription(target_subscription, "to"),
                false,
            ),
            _ => return Ok(false),
        };

        db::update_subscription(
            &self.state.pool,
            actor.id,
            &target_jid,
            &new_actor_subscription,
            if clear_actor_ask { None } else { actor_ask },
        )
        .await?;
        db::update_subscription(
            &self.state.pool,
            target.id,
            &actor_jid,
            &new_target_subscription,
            None,
        )
        .await?;

        match kind {
            "subscribed" | "unsubscribed" => {
                db::remove_pending_presence_subscription(&self.state.pool, target.id, actor.id)
                    .await?;
            }
            "unsubscribe" => {
                db::remove_pending_presence_subscription(&self.state.pool, actor.id, target.id)
                    .await?;
            }
            _ => {}
        }

        self.push_roster_item(&actor.username, actor.id, &target_jid)
            .await?;
        self.push_roster_item(&target.username, target.id, &actor_jid)
            .await?;
        if kind == "subscribed" {
            self.send_current_availability(&actor_jid, &target_jid);
        }
        Ok(true)
    }

    pub(crate) fn send_current_availability(&self, owner: &str, recipient: &str) {
        let recipients = self.state.sessions_for(recipient);
        if recipients.is_empty() {
            return;
        }
        let owner = owner.to_ascii_lowercase();
        for session in self.state.sessions.iter() {
            if bare_jid(session.key()) != owner
                || !session.value().available.load(Ordering::Relaxed)
            {
                continue;
            }
            let presence = format!(
                "<presence xmlns='jabber:client' from='{}' to='{}'/>",
                attr_escape(session.key()),
                attr_escape(recipient)
            );
            for recipient_session in &recipients {
                let _ = recipient_session.sender.try_send(presence.clone());
            }
        }
    }
}
