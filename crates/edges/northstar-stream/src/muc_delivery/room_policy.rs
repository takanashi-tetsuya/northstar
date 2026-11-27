use super::{
    OnlineSession, PrivacyStanzaKind, RoomPolicyLiveSession, RoomPolicyRoute, RoomPolicySubject,
};

impl RoomPolicyLiveSession for OnlineSession {
    fn room_policy_route(&self) -> RoomPolicyRoute {
        RoomPolicyRoute {
            account_id: self.user_id,
            auth_generation: Some(self.auth_generation),
            subject: RoomPolicySubject::Connection {
                id: self.connection_id,
                expects_active: self.privacy_active_snapshot().is_some(),
            },
        }
    }
}

pub(super) struct StanzaPolicyFacts {
    pub(super) visible_peer: String,
    pub(super) real_peer: Option<String>,
    pub(super) kind: PrivacyStanzaKind,
}

pub(super) fn stanza_policy_facts(stanza: &str) -> Option<StanzaPolicyFacts> {
    const MUC_USER: &str = "http://jabber.org/protocol/muc#user";
    let document = roxmltree::Document::parse(stanza).ok()?;
    let root = document.root_element();
    let kind = match root.tag_name().name() {
        "message" => PrivacyStanzaKind::Message,
        "iq" => PrivacyStanzaKind::Iq,
        "presence" => PrivacyStanzaKind::PresenceIn,
        _ => return None,
    };
    if root.attribute("type") == Some("error")
        || (kind == PrivacyStanzaKind::PresenceIn
            && root.children().any(|extension| {
                extension.has_tag_name((MUC_USER, "x"))
                    && extension.children().any(|control| {
                        control.has_tag_name((MUC_USER, "destroy"))
                            || (control.has_tag_name((MUC_USER, "status"))
                                && control.attribute("code") == Some("110"))
                    })
            }))
    {
        return None;
    }
    let visible_peer = northstar_xmpp_types::jid::canonicalize(root.attribute("from")?).ok()?;
    let real_peer = (kind == PrivacyStanzaKind::PresenceIn)
        .then(|| {
            root.children()
                .filter(|node| node.has_tag_name((MUC_USER, "x")))
                .flat_map(|node| node.children())
                .find(|node| node.has_tag_name((MUC_USER, "item")))
                .and_then(|node| node.attribute("jid"))
                .and_then(|jid| northstar_xmpp_types::jid::canonicalize(jid).ok())
        })
        .flatten();
    Some(StanzaPolicyFacts {
        visible_peer,
        real_peer,
        kind,
    })
}

#[cfg(test)]
mod tests;
