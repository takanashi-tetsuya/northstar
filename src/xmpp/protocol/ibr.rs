use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{abuse::AbuseAction, db};
use anyhow::Result;
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl ProtocolSession {
    pub(crate) async fn handle_ibr_register(&mut self, _node: Node<'_, '_>) -> Result<Action> {
        if !self.state.config.open_registration || self.state.config.invitation_required {
            return Ok(Action::Send(
                "<failure xmlns='urn:xmpp:ibr:0'><not-authorized/></failure>".to_string(),
            ));
        }

        // Send the initial form
        Ok(Action::Send(
            "<challenge xmlns='urn:xmpp:ibr:0'>\
               <x xmlns='jabber:x:data' type='form'>\
                 <title>Account Registration</title>\
                 <field var='FORM_TYPE' type='hidden'>\
                   <value>urn:xmpp:ibr:0</value>\
                 </field>\
                 <field var='username' type='text-single' label='Username'><required/></field>\
                 <field var='password' type='text-private' label='Password'><required/></field>\
               </x>\
             </challenge>"
                .to_string(),
        ))
    }

    pub(crate) async fn handle_ibr_response(&mut self, node: Node<'_, '_>) -> Result<Action> {
        let x_node = node.children().find(|n| {
            n.is_element()
                && n.tag_name().name() == "x"
                && n.tag_name().namespace() == Some("jabber:x:data")
        });
        let Some(x_node) = x_node else {
            return Ok(Action::Send(
                "<failure xmlns='urn:xmpp:ibr:0'><bad-request/></failure>".to_string(),
            ));
        };

        let mut username = String::new();
        let mut password = String::new();

        for field in x_node.children().filter(|n| n.has_tag_name("field")) {
            let var = field.attribute("var").unwrap_or_default();
            let value = child_text(field, "value").unwrap_or_default().to_string();
            match var {
                "username" => username = value,
                "password" => password = value,
                _ => {}
            }
        }

        if username.is_empty() || password.is_empty() {
            return Ok(Action::Send(
                "<failure xmlns='urn:xmpp:ibr:0'><bad-request/></failure>".to_string(),
            ));
        }

        let actors = vec![format!("ip:{}", self.peer_ip)];
        if self
            .state
            .abuse
            .verify_or_allow(
                AbuseAction::Registration,
                &format!("registration:{}", self.peer_ip),
                &actors,
                None,
            )
            .is_err()
            || db::registrations_last_hour(&self.state.pool).await?
                >= i64::from(self.state.config.registration_rate_per_hour)
        {
            self.state
                .metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Action::Send(
                "<failure xmlns='urn:xmpp:ibr:0'><resource-constraint/></failure>".to_string(),
            ));
        }

        if crate::auth::validate_password(&password).is_err() {
            return Ok(Action::Send(
                "<failure xmlns='urn:xmpp:ibr:0'><not-acceptable/></failure>".to_string(),
            ));
        }

        // Passwords is good, create immediately
        match db::create_user(&self.state.pool, &username, &password, false, false).await {
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
                    serde_json::json!({"source":"xep-0389"}),
                )
                .await?;
                Ok(Action::Send(
                    "<success xmlns='urn:xmpp:ibr:0'/>".to_string(),
                ))
            }
            Err(e) => {
                tracing::warn!("IBR registration failed: {}", e);
                Ok(Action::Send(
                    "<failure xmlns='urn:xmpp:ibr:0'><conflict/></failure>".to_string(),
                ))
            }
        }
    }
}
