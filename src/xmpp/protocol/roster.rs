use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, bare_jid},
};
use anyhow::Result;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) async fn roster_get(&self, id: &str) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let items = db::roster(&self.state.pool, user.id).await?;
        let mut payload = "<query xmlns='jabber:iq:roster'>".to_owned();
        for (jid, name, subscription, ask) in items {
            payload.push_str(&format!(
                "<item jid='{}' subscription='{}'{}{} />",
                attr_escape(&jid),
                attr_escape(&subscription),
                name.map(|n| format!(" name='{}'", attr_escape(&n)))
                    .unwrap_or_default(),
                ask.map(|a| format!(" ask='{}'", attr_escape(&a)))
                    .unwrap_or_default()
            ));
        }
        payload.push_str("</query>");
        Ok(Action::Send(iq_result(id, &payload)))
    }

    pub(crate) async fn roster_set(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(item) = query
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "item")
        else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let Some(jid) = item.attribute("jid") else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        if item.attribute("subscription") == Some("remove") {
            db::delete_roster(&self.state.pool, user.id, bare_jid(jid)).await?;
            self.push_roster_removal(&user.username, bare_jid(jid));
        } else {
            db::upsert_roster(
                &self.state.pool,
                user.id,
                bare_jid(jid),
                item.attribute("name"),
            )
            .await?;
            self.push_roster_item(&user.username, user.id, bare_jid(jid))
                .await?;
        }
        Ok(Action::Send(iq_result(id, "")))
    }

    pub(crate) async fn push_roster_item(
        &self,
        owner: &str,
        owner_id: uuid::Uuid,
        contact: &str,
    ) -> Result<()> {
        let Some((jid, name, subscription, ask)) =
            db::roster_item(&self.state.pool, owner_id, contact).await?
        else {
            return Ok(());
        };
        let item = format!(
            "<item jid='{}' subscription='{}'{}{} />",
            attr_escape(&jid),
            attr_escape(&subscription),
            name.map(|value| format!(" name='{}'", attr_escape(&value)))
                .unwrap_or_default(),
            ask.map(|value| format!(" ask='{}'", attr_escape(&value)))
                .unwrap_or_default()
        );
        self.push_roster(owner, &item);
        Ok(())
    }

    pub(crate) fn push_roster_removal(&self, owner: &str, contact: &str) {
        self.push_roster(
            owner,
            &format!(
                "<item jid='{}' subscription='remove'/>",
                attr_escape(contact)
            ),
        );
    }

    pub(crate) fn push_roster(&self, owner: &str, item: &str) {
        let owner_jid = format!("{}@{}", owner, self.state.config.domain);
        let push = format!(
                "<iq xmlns='jabber:client' type='set' id='roster-{}'><query xmlns='jabber:iq:roster'>{}</query></iq>",
                stream_id(),
                item
            );
        for target in self.state.sessions_for(&owner_jid) {
            let _ = target.sender.try_send(push.clone());
        }
    }
}
