use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{jid_domain, localpart},
};
use anyhow::Result;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) async fn vcard_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        let Some(requester) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let owner_name = iq
            .attribute("to")
            .map(localpart)
            .unwrap_or(&requester.username)
            .to_ascii_lowercase();
        let Some(owner) = db::find_user(&self.state.pool, &owner_name).await? else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let payload = db::vcard(&self.state.pool, owner.id)
            .await?
            .unwrap_or_else(|| "<vCard xmlns='vcard-temp'/>".to_owned());
        if let Some(to) = iq.attribute("to") {
            Ok(Action::Send(iq_result_from(id, to, &payload)))
        } else {
            Ok(Action::Send(iq_result(id, &payload)))
        }
    }

    pub(crate) async fn vcard_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        vcard: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if iq.attribute("to").is_some_and(|to| {
            !localpart(to).eq_ignore_ascii_case(&user.username)
                || !jid_domain(to)
                    .is_some_and(|domain| domain.eq_ignore_ascii_case(&self.state.config.domain))
        }) {
            return Ok(Action::Send(iq_error(id, "forbidden")));
        }
        let range = vcard.range();
        let payload = &raw[range];
        if payload.len() > 512 * 1024 {
            return Ok(Action::Send(iq_error(id, "resource-constraint")));
        }
        db::set_vcard(&self.state.pool, user.id, payload).await?;
        Ok(Action::Send(iq_result(id, "")))
    }
}
