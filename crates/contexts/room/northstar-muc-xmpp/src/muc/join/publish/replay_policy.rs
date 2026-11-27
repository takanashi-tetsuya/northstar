use super::*;
use northstar_room_application::room_delivery_policy::{
    PrivacyStanzaKind, RoomDeliveryDecision, RoomDeliveryPolicyQuery, RoomDeliveryPolicyReader,
    RoomPolicyLiveSession, RoomPolicySubject,
};
use std::collections::HashSet;

#[derive(Default)]
pub(in crate::muc::join) struct ReplayPolicy {
    items: Vec<ReplayItem>,
}

struct ReplayItem {
    nick: Option<String>,
    visible_peer: String,
    real_peer: String,
    stanza: String,
}

impl ReplayPolicy {
    pub(in crate::muc::join) fn presence(
        &mut self,
        room: &str,
        occupant: &northstar_room_application::muc_service::SerializableMucOccupant,
        stanza: String,
    ) {
        self.items.push(ReplayItem {
            nick: Some(occupant.nick.clone()),
            visible_peer: format!("{room}/{}", occupant.nick),
            real_peer: occupant.full_jid.clone(),
            stanza,
        });
    }

    pub(in crate::muc::join) fn history(
        &mut self,
        room: &str,
        archived: &str,
        sender: &str,
        stanza: String,
    ) {
        let visible_peer = roxmltree::Document::parse(archived)
            .ok()
            .and_then(|document| document.root_element().attribute("from").map(str::to_owned))
            .unwrap_or_else(|| room.to_owned());
        self.items.push(ReplayItem {
            nick: None,
            visible_peer,
            real_peer: sender.to_owned(),
            stanza,
        });
    }

    pub(in crate::muc::join) async fn replies(
        self,
        session: &impl MucSession,
        account_id: uuid::Uuid,
        full_jid: &str,
        self_presence: String,
        history_request: MucHistoryRequest,
        subject: String,
    ) -> Vec<String> {
        let host = session.host();
        let route = || {
            host.session_entries_for(full_jid)
                .into_iter()
                .find_map(|(_, target)| {
                    let route = RoomPolicyLiveSession::room_policy_route(&target);
                    (route.account_id == account_id
                        && matches!(route.subject, RoomPolicySubject::Connection { id, .. }
                        if id == session.connection_id()))
                    .then_some(route)
                })
        };
        if self.items.is_empty() {
            return vec![self_presence, subject];
        }
        let Some(sampled) = route() else {
            return vec![self_presence, subject];
        };
        let queries = self
            .items
            .iter()
            .map(|item| RoomDeliveryPolicyQuery {
                route: sampled,
                visible_peer: &item.visible_peer,
                real_peer: Some(&item.real_peer),
                kind: Some(if item.nick.is_some() {
                    PrivacyStanzaKind::PresenceIn
                } else {
                    PrivacyStanzaKind::Message
                }),
                recipient_jid: full_jid,
            })
            .collect::<Vec<_>>();
        let decisions =
            match RoomDeliveryPolicyReader::read_room_delivery_policies(host, &queries).await {
                Ok(decisions) if decisions.len() == queries.len() => decisions,
                result => {
                    tracing::warn!(error = ?result.err(), "MUC replay policy unavailable");
                    return vec![self_presence, subject];
                }
            };
        if route() != Some(sampled) {
            return vec![self_presence, subject];
        }
        drop(queries);
        render_replay(
            self.items.into_iter().zip(decisions),
            self_presence,
            history_request,
            subject,
        )
    }
}

fn render_replay(
    items: impl IntoIterator<Item = (ReplayItem, RoomDeliveryDecision)>,
    self_presence: String,
    history_request: MucHistoryRequest,
    subject: String,
) -> Vec<String> {
    let mut roster_nicks = HashSet::new();
    let mut replies = Vec::new();
    let mut history = Vec::new();
    for (item, decision) in items {
        if !decision.allows() {
            continue;
        }
        if let Some(nick) = item.nick {
            if roster_nicks.insert(nick) {
                replies.push(item.stanza);
            }
        } else {
            history.push(item.stanza);
        }
    }
    replies.push(self_presence);
    replies.extend(apply_muc_history_bounds(history, history_request));
    replies.push(subject);
    replies
}

#[cfg(test)]
mod tests;
