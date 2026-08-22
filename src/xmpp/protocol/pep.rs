use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, localpart},
};
use anyhow::Result;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) async fn pep_publish(
        &self,
        id: &str,
        pubsub: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(publish) = pubsub
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "publish")
        else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let Some(node) = publish.attribute("node") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if node.len() > 512 {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }
        let items: Vec<_> = publish
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "item")
            .collect();
        if items.is_empty() {
            // XEP-0060 7.1.3.6: No item element means publish without payload
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let mut payload = String::new();
        let mut assigned_ids = Vec::new();
        for item in items {
            if item
                .attribute("id")
                .is_some_and(|item_id| item_id.len() > 1024)
            {
                return Ok(Action::Send(iq_error(id, "not-acceptable")));
            }
            let generated = item.attribute("id").is_none();
            let item_id = item
                .attribute("id")
                .map(str::to_owned)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let range = item.range();
            let item_xml = normalized_pep_item(&raw[range], &item_id, generated);
            if item_xml.len() > 512 * 1024 {
                return Ok(Action::Send(iq_error(id, "resource-constraint")));
            }
            db::publish_pep(&self.state.pool, user.id, node, &item_id, &item_xml).await?;
            payload.push_str(&item_xml);
            if generated {
                assigned_ids.push(item_id);
            }
        }

        let owner = format!("{}@{}", user.username, self.state.config.domain);
        let event = format!(
                "<message xmlns='jabber:client' from='{}' type='headline'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='{}'>{}</items></event></message>",
                attr_escape(&owner),
                attr_escape(node),
                payload
            );
        for target in self.state.sessions_for(&owner) {
            let _ = target.sender.try_send(event.clone());
        }
        for (contact, _, subscription, _) in db::roster(&self.state.pool, user.id).await? {
            if !matches!(subscription.as_str(), "from" | "both")
                || db::is_blocked(&self.state.pool, user.id, &contact).await?
            {
                continue;
            }
            if let Some(recipient) = db::find_user(&self.state.pool, localpart(&contact)).await? {
                if db::is_blocked(&self.state.pool, recipient.id, &owner).await? {
                    continue;
                }
            }
            for target in self.state.sessions_for(&contact) {
                let _ = target.sender.try_send(event.clone());
            }
        }
        if assigned_ids.is_empty() {
            Ok(Action::Send(iq_result(id, "")))
        } else {
            let items = assigned_ids
                .iter()
                .map(|item_id| format!("<item id='{}'/>", attr_escape(item_id)))
                .collect::<String>();
            Ok(Action::Send(iq_result(
                    id,
                    &format!(
                        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='{}'>{}</publish></pubsub>",
                        attr_escape(node),
                        items
                    ),
                )))
        }
    }

    pub(crate) async fn pep_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        tracing::info!(id=id, to=?iq.attribute("to"), "PEP GET received");
        let Some(requester) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(items) = pubsub
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "items")
        else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let Some(node) = items.attribute("node") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let owner_name = iq
            .attribute("to")
            .map(localpart)
            .unwrap_or(&requester.username)
            .to_ascii_lowercase();
        let Some(owner) = db::find_user(&self.state.pool, &owner_name).await? else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let requested_id = items
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "item")
            .and_then(|n| n.attribute("id"));
        let stored = db::pep_items(&self.state.pool, owner.id, node, requested_id, 100).await?;
        if stored.is_empty() {
            return Ok(Action::Send(if let Some(to) = iq.attribute("to") {
                iq_error_from(id, to, "item-not-found")
            } else {
                iq_error(id, "item-not-found")
            }));
        }
        let mut payload = format!(
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='{}'>",
            attr_escape(node)
        );
        for (_, item) in stored {
            payload.push_str(&item);
        }
        payload.push_str("</items></pubsub>");
        if let Some(to) = iq.attribute("to") {
            Ok(Action::Send(iq_result_from(id, to, &payload)))
        } else {
            Ok(Action::Send(iq_result(id, &payload)))
        }
    }
}

fn normalized_pep_item(item_xml: &str, item_id: &str, generated: bool) -> String {
    if !generated {
        return item_xml.to_owned();
    }
    let Some(tag_end) = item_xml.find('>') else {
        return item_xml.to_owned();
    };
    let insert_at = item_xml[..tag_end]
        .rfind('/')
        .filter(|slash| item_xml[*slash..tag_end].trim() == "/")
        .unwrap_or(tag_end);
    let mut normalized = item_xml.to_owned();
    normalized.insert_str(insert_at, &format!(" id='{}'", attr_escape(item_id)));
    normalized
}

#[cfg(test)]
mod tests {
    use super::normalized_pep_item;

    #[test]
    fn generated_pep_id_is_inserted_into_stored_item() {
        assert_eq!(
            normalized_pep_item("<item><value/></item>", "generated", true),
            "<item id='generated'><value/></item>"
        );
        assert_eq!(
            normalized_pep_item("<item/>", "generated", true),
            "<item id='generated'/>"
        );
    }
}
