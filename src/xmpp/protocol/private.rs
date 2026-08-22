use super::{Action, ProtocolSession};
use crate::db;
use crate::xmpp::xml_util::{iq_error, iq_result};
use anyhow::Result;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) async fn private_get(&mut self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };

        let child = match query.children().find(|n| n.is_element()) {
            Some(c) => c,
            None => return Ok(Action::Send(iq_error(id, "bad-format"))),
        };

        let name = child.tag_name().name();
        let ns = child.tag_name().namespace().unwrap_or("");
        if name.len() > 255 || ns.len() > 1024 {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }

        let xml_data = db::get_private_xml(&self.state.pool, user.id, name, ns).await?;

        let response_inner = if let Some(data) = xml_data {
            format!("<query xmlns='jabber:iq:private'>{}</query>", data)
        } else {
            let mut empty_child = format!("<{} xmlns='{}'/>", name, ns);
            if ns.is_empty() {
                empty_child = format!("<{}/>", name);
            }
            format!("<query xmlns='jabber:iq:private'>{}</query>", empty_child)
        };

        Ok(Action::Send(iq_result(id, &response_inner)))
    }

    pub(crate) async fn private_set(
        &mut self,
        id: &str,
        query: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };

        let child = match query.children().find(|n| n.is_element()) {
            Some(c) => c,
            None => return Ok(Action::Send(iq_error(id, "bad-format"))),
        };

        let name = child.tag_name().name();
        let ns = child.tag_name().namespace().unwrap_or("");

        let xml_data = &raw[child.range()];
        if name.len() > 255 || ns.len() > 1024 || xml_data.len() > 512 * 1024 {
            return Ok(Action::Send(iq_error(id, "resource-constraint")));
        }

        db::set_private_xml(&self.state.pool, user.id, name, ns, xml_data).await?;

        Ok(Action::Send(iq_result(id, "")))
    }
}
