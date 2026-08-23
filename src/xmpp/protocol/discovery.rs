use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, bare_jid, jid_domain, localpart},
};
use anyhow::Result;

impl ProtocolSession {
    pub(crate) async fn disco_info(&self, id: &str, to: Option<&str>) -> Result<Action> {
        let from = to.unwrap_or(&self.state.config.domain);
        let muc_domain = self.muc_domain();
        let upload_domain = self.upload_domain();
        if bare_jid(from).eq_ignore_ascii_case(&upload_domain) {
            let query = format!(
                    "<query xmlns='http://jabber.org/protocol/disco#info'><identity category='store' type='file' name='{} File Upload'/><feature var='urn:xmpp:http:upload:0'/><x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:http:upload:0</value></field><field var='max-file-size'><value>{}</value></field></x></query>",
                    attr_escape(&self.state.config.server_name),
                    self.state.config.upload_max_bytes
                );
            return Ok(Action::Send(iq_result_from(id, from, &query)));
        }
        if bare_jid(from).eq_ignore_ascii_case(&muc_domain) {
            let query = format!("<query xmlns='http://jabber.org/protocol/disco#info'><identity category='conference' type='text' name='{} Group Chat'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/disco#items'/><feature var='http://jabber.org/protocol/muc'/><feature var='http://jabber.org/protocol/muc#unique'/></query>", attr_escape(&self.state.config.server_name));
            return Ok(Action::Send(iq_result_from(id, from, &query)));
        }
        if jid_domain(from).is_some_and(|domain| domain.eq_ignore_ascii_case(&muc_domain)) {
            let Some(room) =
                db::muc_room(&self.state.pool, &localpart(from).to_ascii_lowercase()).await?
            else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            let mut query = format!(
                    "<query xmlns='http://jabber.org/protocol/disco#info'><identity category='conference' type='text' name='{}'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/muc'/><feature var='muc_{}'/><feature var='muc_{}'/><feature var='muc_{}'/><feature var='muc_{}'/>",
                    attr_escape(room.title.as_deref().unwrap_or(&room.localpart)),
                    if room.public { "public" } else { "hidden" },
                    if room.persistent { "persistent" } else { "temporary" },
                    if room.members_only { "membersonly" } else { "open" },
                    if room.moderated { "moderated" } else { "unmoderated" },
                );
            query.push_str(if room.non_anonymous {
                "<feature var='muc_nonanonymous'/>"
            } else {
                "<feature var='muc_semianonymous'/>"
            });
            query.push_str("<feature var='muc_unsecured'/></query>");
            return Ok(Action::Send(iq_result_from(id, from, &query)));
        }
        let mut features = vec![
            "http://jabber.org/protocol/disco#info",
            "http://jabber.org/protocol/disco#items",
            "http://jabber.org/protocol/pubsub#pep",
            "http://jabber.org/protocol/pubsub#multi-items",
            "http://jabber.org/protocol/pubsub#persistent-items",
            "http://jabber.org/protocol/pubsub#auto-create",
            "http://jabber.org/protocol/pubsub#delete-items",
            "http://jabber.org/protocol/pubsub#publish-options",
            "http://jabber.org/protocol/pubsub#retract-items",
            "http://jabber.org/protocol/pubsub#retrieve-items",
            "jabber:iq:roster",
            "jabber:iq:version",
            "urn:xmpp:ping",
            "urn:xmpp:time",
            "urn:xmpp:mam:2",
            "urn:xmpp:carbons:2",
            "urn:xmpp:sm:3",
            "urn:xmpp:blocking",
            "urn:xmpp:receipts",
            "urn:xmpp:chat-markers:0",
            "urn:xmpp:eme:0",
            "urn:xmpp:hints",
            "urn:xmpp:sce:1",
            "eu.siacs.conversations.axolotl",
            "eu.siacs.conversations.axolotl.devicelist+notify",
            "urn:xmpp:omemo:2",
            "urn:xmpp:omemo:2:devices+notify",
            "http://jabber.org/protocol/muc",
            "urn:xmpp:http:upload:0",
            "vcard-temp",
            "urn:xmpp:avatar:data",
            "urn:xmpp:avatar:metadata+notify",
            "urn:xmpp:push:0",
        ];
        let is_account = localpart(from) != from
            && jid_domain(from)
                .is_some_and(|domain| domain.eq_ignore_ascii_case(&self.state.config.domain));
        if !is_account
            && self.state.config.open_registration
            && !self.state.config.invitation_required
        {
            features.push("jabber:iq:register");
        }
        let identity = if is_account {
            "<identity category='account' type='registered'/>"
        } else {
            "<identity category='server' type='im' name='Rust XMPP Server'/>"
        };
        let mut query = format!(
                "<query xmlns='http://jabber.org/protocol/disco#info'>{}<identity category='pubsub' type='pep' name='Personal Eventing Protocol'/>",
                identity
            );
        for feature in features {
            query.push_str(&format!("<feature var='{}'/>", attr_escape(feature)));
        }

        if jid_domain(from)
            .is_some_and(|domain| domain.eq_ignore_ascii_case(&self.state.config.domain))
        {
            if let Some(owner) = db::find_user(&self.state.pool, localpart(from)).await? {
                let requester_jid = self.authenticated.as_ref().map(|requester| {
                    format!("{}@{}", requester.username, self.state.config.domain)
                });
                for node in db::pep_nodes(&self.state.pool, owner.id).await? {
                    let allowed = if let Some(requester_jid) = &requester_jid {
                        super::pep::pep_access_allowed(
                            &self.state.pool,
                            &owner,
                            &self.state.config.domain,
                            &node,
                            requester_jid,
                        )
                        .await?
                    } else {
                        db::pep_node(&self.state.pool, owner.id, &node)
                            .await?
                            .is_some_and(|config| config.access_model == "open")
                    };
                    if allowed {
                        query.push_str(&format!("<feature var='{}'/>", attr_escape(&node)));
                        query.push_str(&format!("<feature var='{}+notify'/>", attr_escape(&node)));
                    }
                }
            }
        }

        query.push_str("</query>");
        Ok(Action::Send(iq_result_from(id, from, &query)))
    }

    pub(crate) async fn disco_items(&self, id: &str, to: Option<&str>) -> Result<Action> {
        let from = to.unwrap_or(&self.state.config.domain);
        let muc_domain = self.muc_domain();
        let upload_domain = self.upload_domain();
        let mut query = "<query xmlns='http://jabber.org/protocol/disco#items'>".to_owned();
        if bare_jid(from).eq_ignore_ascii_case(&muc_domain) {
            for room in db::public_muc_rooms(&self.state.pool, 500).await? {
                query.push_str(&format!(
                    "<item jid='{}@{}' name='{}'/>",
                    attr_escape(&room.localpart),
                    attr_escape(&muc_domain),
                    attr_escape(room.title.as_deref().unwrap_or(&room.localpart))
                ));
            }
        } else if bare_jid(from).eq_ignore_ascii_case(&self.state.config.domain) {
            query.push_str(&format!(
                "<item jid='{}' name='{} Group Chat'/>",
                attr_escape(&muc_domain),
                attr_escape(&self.state.config.server_name)
            ));
            query.push_str(&format!(
                "<item jid='{}' name='{} File Upload'/>",
                attr_escape(&upload_domain),
                attr_escape(&self.state.config.server_name)
            ));
        }
        query.push_str("</query>");
        Ok(Action::Send(iq_result_from(id, from, &query)))
    }
}
