use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    abuse::AbuseAction,
    auth, db,
    state::{attr_escape, jid_domain, xml_escape},
};
use anyhow::Result;
use dashmap::mapref::entry::Entry;
use roxmltree::Node;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

impl ProtocolSession {
    pub(crate) async fn register(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        if !self.state.config.open_registration || self.state.config.invitation_required {
            return Ok(Action::Send(iq_error(id, "not-allowed")));
        }
        let actors = vec![format!("ip:{}", self.peer_ip)];
        if let Err(error) = self.state.abuse.verify_or_allow(
            AbuseAction::Registration,
            &format!("registration:{}", self.peer_ip),
            &actors,
            None,
        ) {
            self.state
                .metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Action::Send(iq_abuse_error(id, error.requirement())));
        }
        if db::registrations_last_hour(&self.state.pool).await?
            >= i64::from(self.state.config.registration_rate_per_hour)
        {
            return Ok(Action::Send(iq_error(id, "resource-constraint")));
        }
        let username = child_text(query, "username").unwrap_or_default();
        let password = child_text(query, "password").unwrap_or_default();

        if auth::validate_password(password).is_err() {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }

        match db::create_user(
            &self.state.pool,
            username,
            password,
            false,
            false,
            self.state.config.scram_iterations,
        )
        .await
        {
            Ok(user) => {
                self.state
                    .metrics
                    .registrations_total
                    .fetch_add(1, Ordering::Relaxed);
                db::audit(
                    &self.state.pool,
                    Some(user.id),
                    "user.register",
                    Some(&user.username),
                    serde_json::json!({"source":"xmpp"}),
                )
                .await?;

                Ok(Action::Send(iq_result(id, "")))
            }
            Err(error) => {
                tracing::warn!(?error, "XMPP registration failed");
                Ok(Action::Send(iq_error(id, "conflict")))
            }
        }
    }

    pub(crate) async fn change_password(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let username = child_text(query, "username").unwrap_or(&user.username);
        let Some(password) = child_text(query, "password") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if !username.eq_ignore_ascii_case(&user.username)
            || auth::validate_password(password).is_err()
        {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }
        db::change_password(
            &self.state.pool,
            user.id,
            password,
            self.state.config.scram_iterations,
        )
        .await?;
        db::audit(
            &self.state.pool,
            Some(user.id),
            "user.password.change",
            Some(&user.username),
            serde_json::json!({"source":"xmpp"}),
        )
        .await?;
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) async fn bind(&mut self, id: &str, bind: Node<'_, '_>) -> Result<Action> {
        if self.full_jid.is_some() {
            return Ok(Action::Send(iq_error(id, "unexpected-request")));
        }
        let Some(user) = self.authenticated.clone() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let generated = uuid::Uuid::new_v4().to_string();
        let resource = child_text(bind, "resource")
            .filter(|r| valid_resource(r))
            .unwrap_or(&generated);
        let jid = format!(
            "{}@{}/{}",
            user.username, self.state.config.domain, resource
        );
        let key = jid.to_ascii_lowercase();
        let available = Arc::new(AtomicBool::new(false));
        self.state
            .resumable_sessions
            .retain(|_, session| session.full_jid.to_ascii_lowercase() != key);
        match self.state.sessions.entry(key.clone()) {
            Entry::Occupied(_) => return Ok(Action::Send(iq_error(id, "conflict"))),
            Entry::Vacant(entry) => {
                entry.insert(crate::state::OnlineSession {
                    sender: self.outbound.clone(),
                    available: Arc::clone(&available),
                    carbons: Arc::clone(&self.carbons),
                    priority: Arc::clone(&self.priority),
                    blocklist_requested: Arc::clone(&self.blocklist_requested),
                    ip: Some(self.peer_ip),
                    resource: resource.to_string(),
                    connected_at: std::time::Instant::now(),
                });
            }
        }
        self.registered_key = Some(key);
        self.full_jid = Some(jid.clone());
        self.available = Some(available);
        self.state
            .metrics
            .active_sessions
            .fetch_add(1, Ordering::Relaxed);
        Ok(Action::Send(iq_result(
            id,
            &format!(
                "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>{}</jid></bind>",
                xml_escape(&jid)
            ),
        )))
    }

    pub(crate) fn set_carbons(&self, id: &str, enabled: bool) -> Result<Action> {
        if self.full_jid.is_none() {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        }
        self.carbons.store(enabled, Ordering::Relaxed);
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) async fn enable_push(
        &self,
        id: &str,
        enable: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let service_jid = enable
            .attribute("jid")
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let node = enable.attribute("node").map(str::trim).unwrap_or_default();
        if !valid_push_jid(&service_jid) || node.is_empty() || node.len() > 1024 {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let options = enable.children().find(|child| {
            child.is_element()
                && child.tag_name().name() == "x"
                && child.tag_name().namespace() == Some("jabber:x:data")
        });
        let options = options.map(|options| &raw[options.range()]);
        if options.is_some_and(|options| options.len() > 16 * 1024) {
            return Ok(Action::Send(iq_error(id, "resource-constraint")));
        }
        db::enable_push(&self.state.pool, user.id, &service_jid, node, options).await?;
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) async fn disable_push(&self, id: &str, disable: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let service_jid = disable
            .attribute("jid")
            .map(str::trim)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !valid_push_jid(&service_jid) {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        db::disable_push(
            &self.state.pool,
            user.id,
            &service_jid,
            disable.attribute("node"),
        )
        .await?;
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) async fn notify_push(&self, recipient: &db::User) -> Result<()> {
        let owner = format!("{}@{}", recipient.username, self.state.config.domain);
        for subscription in db::push_subscriptions(&self.state.pool, recipient.id).await? {
            let notification = format!(
                    "<iq xmlns='jabber:client' type='set' from='{}' to='{}' id='push-{}'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='{}'><item><notification xmlns='urn:xmpp:push:0'><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE'><value>urn:xmpp:push:summary</value></field><field var='message-count'><value>1</value></field></x></notification></item></publish></pubsub></iq>",
                    attr_escape(&owner),
                    attr_escape(&subscription.service_jid),
                    stream_id(),
                    attr_escape(&subscription.node)
                );
            let mut delivered = false;
            if jid_domain(&subscription.service_jid)
                .is_some_and(|domain| domain.eq_ignore_ascii_case(&self.state.config.domain))
            {
                for target in self.state.sessions_for(&subscription.service_jid) {
                    delivered |= target.sender.try_send(notification.clone()).is_ok();
                }
            } else if let Some(domain) = jid_domain(&subscription.service_jid) {
                if self.state.config.federation_domain_allowed(domain) {
                    self.state
                        .federation
                        .send(domain, notification.clone(), None);
                    delivered = true;
                }
            }
            if !delivered {
                tracing::debug!(
                    service = %subscription.service_jid,
                    has_options = subscription.options.is_some(),
                    "push service could not be routed"
                );
            }
        }
        Ok(())
    }
}
