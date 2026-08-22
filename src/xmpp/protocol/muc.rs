use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, bare_jid, jid_domain, localpart, xml_escape},
};
use anyhow::Result;
use roxmltree::Node;
use std::sync::atomic::Ordering;

fn can_retrieve_muc_affiliation_list(
    requester_affiliation: &str,
    requested_affiliation: &str,
    members_only: bool,
    non_anonymous: bool,
) -> bool {
    if !matches!(
        requested_affiliation,
        "owner" | "admin" | "member" | "outcast"
    ) {
        return false;
    }

    if matches!(requester_affiliation, "owner" | "admin") {
        return true;
    }

    // XEP-0045 recommends making the member list available to members of a
    // members-only room. OMEMO clients also need the owner and admin lists so
    // that offline affiliates are included as encryption recipients. Limit
    // that wider visibility to members-only, non-anonymous rooms where real
    // JIDs are intentionally visible to every member.
    requester_affiliation == "member"
        && members_only
        && non_anonymous
        && matches!(requested_affiliation, "owner" | "admin" | "member")
}

impl ProtocolSession {
    pub(crate) async fn muc_message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        let Some(from) = self.full_jid.as_deref() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(to) = root.attribute("to") else {
            return Ok(Action::Send(stanza_error(root, "modify", "jid-malformed")));
        };
        let room_jid = bare_jid(to).to_ascii_lowercase();
        let Some(own_nick) = self.joined_rooms.get(&room_jid) else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-acceptable")));
        };
        let own_key = muc_occupant_key(&room_jid, own_nick);
        let Some(own) = self
            .state
            .muc_occupants
            .get(&own_key)
            .map(|entry| entry.value().clone())
        else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-acceptable")));
        };

        if own.role == "visitor" {
            return Ok(Action::Send(stanza_error(root, "auth", "forbidden")));
        }
        if to.contains('/') {
            if !matches!(
                root.attribute("type").unwrap_or("normal"),
                "chat" | "normal"
            ) {
                return Ok(Action::Send(stanza_error(root, "modify", "bad-request")));
            }
            let target_nick = to.split_once('/').map(|(_, nick)| nick).unwrap_or_default();
            let target_key = muc_occupant_key(&room_jid, target_nick);
            let Some(target) = self
                .state
                .muc_occupants
                .get(&target_key)
                .map(|entry| entry.value().clone())
            else {
                return Ok(Action::Send(stanza_error(root, "cancel", "item-not-found")));
            };
            let rewritten = set_to(
                &set_from(raw, &format!("{room_jid}/{}", own.nick)),
                &target.full_jid,
            );
            let _ = target.sender.try_send(rewritten);
            return Ok(Action::None);
        }

        if root.attribute("type") != Some("groupchat") {
            let mut has_invites = false;
            if let Some(room) = db::muc_room(&self.state.pool, localpart(&room_jid)).await? {
                for x in root.children().filter(|n| {
                    n.is_element()
                        && n.tag_name().name() == "x"
                        && n.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
                }) {
                    for invite in x
                        .children()
                        .filter(|n| n.is_element() && n.tag_name().name() == "invite")
                    {
                        if let Some(invitee_jid) = invite.attribute("to") {
                            has_invites = true;
                            if own.role == "visitor"
                                || (room.members_only
                                    && !matches!(
                                        own.affiliation.as_str(),
                                        "owner" | "admin" | "member"
                                    ))
                            {
                                return Ok(Action::Send(stanza_error(root, "auth", "forbidden")));
                            }
                            if room.members_only {
                                tracing::info!(room_id = %room.id, invitee = %localpart(invitee_jid), "MUC mediated invite: granting member affiliation");
                                db::set_muc_affiliation(
                                    &self.state.pool,
                                    room.id,
                                    localpart(invitee_jid),
                                    "member",
                                )
                                .await?;
                            }

                            let reason = child_text(invite, "reason");
                            let mut x_out = format!(
                                "<x xmlns='http://jabber.org/protocol/muc#user'><invite from='{}'>",
                                attr_escape(from)
                            );
                            if let Some(r) = reason {
                                x_out.push_str(&format!("<reason>{}</reason>", xml_escape(r)));
                            }
                            x_out.push_str("</invite></x>");

                            let forwarded = format!(
                                "<message from='{}' to='{}' type='normal'>{}</message>",
                                attr_escape(&room_jid),
                                attr_escape(invitee_jid),
                                x_out
                            );

                            let domain = jid_domain(invitee_jid).unwrap_or_default();
                            if domain.eq_ignore_ascii_case(&self.state.config.domain) {
                                let mut targets = self.state.session_entries_for(invitee_jid);
                                if !invitee_jid.contains('/') {
                                    targets.retain(|(_, session)| {
                                        session.available.load(Ordering::Relaxed)
                                            && session.priority.load(Ordering::Relaxed) >= 0
                                    });
                                    targets.sort_by(|(left_jid, left), (right_jid, right)| {
                                        right
                                            .priority
                                            .load(Ordering::Relaxed)
                                            .cmp(&left.priority.load(Ordering::Relaxed))
                                            .then_with(|| left_jid.cmp(right_jid))
                                    });
                                }
                                let mut delivered = false;
                                for (_, target) in targets {
                                    if target.sender.try_send(forwarded.clone()).is_ok() {
                                        delivered = true;
                                        break;
                                    }
                                }
                                if !delivered {
                                    if let Ok(Some(recipient)) =
                                        db::find_user(&self.state.pool, localpart(invitee_jid))
                                            .await
                                    {
                                        let _ = db::store_offline(
                                            &self.state.pool,
                                            recipient.id,
                                            &room_jid,
                                            &forwarded,
                                            false,
                                        )
                                        .await;
                                    }
                                }
                            } else {
                                self.state.federation.send(
                                    domain,
                                    forwarded,
                                    Some(room_jid.clone()),
                                );
                            }
                        }
                    }
                }
            }
            if has_invites {
                return Ok(Action::None);
            }
            return Ok(Action::Send(stanza_error(root, "modify", "bad-request")));
        }
        let Some(room) = db::muc_room(&self.state.pool, localpart(&room_jid)).await? else {
            return Ok(Action::Send(stanza_error(root, "cancel", "item-not-found")));
        };
        if root.children().any(|node| {
            node.is_element()
                && node.tag_name().name() == "subject"
                && node
                    .tag_name()
                    .namespace()
                    .is_none_or(|ns| ns == "jabber:client")
        }) {
            if own.role != "moderator" {
                return Ok(Action::Send(stanza_error(root, "auth", "forbidden")));
            }
            db::set_muc_subject(
                &self.state.pool,
                room.id,
                child_text(root, "subject").unwrap_or_default(),
            )
            .await?;
        }
        let room_from = format!("{room_jid}/{}", own.nick);
        let rewritten = set_to(&set_from(raw, &room_from), &room_jid);
        let encrypted = is_encrypted(root);
        if !has_no_store_hint(root) && (encrypted || !self.state.config.require_encrypted_archive) {
            let archive = if encrypted {
                encrypted_archive_stanza(&rewritten)
            } else {
                rewritten.clone()
            };
            db::archive_muc_message(
                &self.state.pool,
                room.id,
                from,
                &own.nick,
                &archive,
                encrypted,
            )
            .await?;
        }
        for (_, occupant) in self.state.muc_occupants_for(&room_jid) {
            let delivery = set_to(&rewritten, &occupant.full_jid);
            tracing::debug!(room=%room_jid, to=%occupant.full_jid, "MUC routing stanza");
            let _ = occupant.sender.try_send(delivery);
        }
        self.state
            .metrics
            .messages_routed_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(Action::None)
    }

    pub(crate) async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(room_jid) = iq.attribute("to").map(bare_jid) else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        if !jid_domain(room_jid)
            .is_some_and(|domain| domain.eq_ignore_ascii_case(&self.muc_domain()))
            || !valid_muc_room(localpart(room_jid))
        {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        }
        let Some(room) = db::muc_room(&self.state.pool, localpart(room_jid)).await? else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if db::muc_affiliation(&self.state.pool, room.id, user.id)
            .await?
            .as_deref()
            != Some("owner")
        {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        let whois = if room.non_anonymous {
            "anyone"
        } else {
            "moderators"
        };
        let form = format!(
                "<query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='form'><title>Room configuration</title><field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/muc#roomconfig</value></field><field var='muc#roomconfig_roomname' type='text-single'><value>{}</value></field><field var='muc#roomconfig_persistentroom' type='boolean'><value>{}</value></field><field var='muc#roomconfig_membersonly' type='boolean'><value>{}</value></field><field var='muc#roomconfig_publicroom' type='boolean'><value>{}</value></field><field var='muc#roomconfig_moderatedroom' type='boolean'><value>{}</value></field><field var='muc#roomconfig_whois' type='list-single'><value>{}</value><option label='Anyone'><value>anyone</value></option><option label='Moderators only'><value>moderators</value></option></field><field var='muc#roomconfig_maxusers' type='list-single'><value>{}</value><option><value>10</value></option><option><value>20</value></option><option><value>50</value></option><option><value>100</value></option><option><value>500</value></option><option><value>1000</value></option></field></x></query>",
                xml_escape(room.title.as_deref().unwrap_or(&room.localpart)),
                bool_value(room.persistent),
                bool_value(room.members_only),
                bool_value(room.public),
                bool_value(room.moderated),
                whois,
                room.max_occupants,
            );
        Ok(Action::Send(iq_result_from(id, room_jid, &form)))
    }

    pub(crate) async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(room_jid) = iq.attribute("to").map(bare_jid) else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        if !jid_domain(room_jid)
            .is_some_and(|domain| domain.eq_ignore_ascii_case(&self.muc_domain()))
            || !valid_muc_room(localpart(room_jid))
        {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        }
        let Some(room) = db::muc_room(&self.state.pool, localpart(room_jid)).await? else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if db::muc_affiliation(&self.state.pool, room.id, user.id)
            .await?
            .as_deref()
            != Some("owner")
        {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }

        if let Some(destroy) = query.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "destroy"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#owner")
        }) {
            let alternate = destroy.attribute("jid");
            let reason = child_text(destroy, "reason");
            let occupants = self.state.muc_occupants_for(room_jid);
            for (key, occupant) in occupants {
                self.state.muc_occupants.remove(&key);
                let unavailable = muc_destroy_presence(&occupant, alternate, reason);
                let _ = occupant.sender.try_send(unavailable);
            }
            db::delete_muc_room(&self.state.pool, room.id).await?;
            return Ok(Action::Send(iq_result_from(id, room_jid, "")));
        }

        let form = query.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:data")
        });
        if form.is_some_and(|form| form.attribute("type") == Some("cancel")) {
            return Ok(Action::Send(iq_result_from(id, room_jid, "")));
        }
        if let Some(form) = form {
            if !matches!(form.attribute("type"), None | Some("submit"))
                || xdata_field(form, "FORM_TYPE")
                    .is_some_and(|value| value != "http://jabber.org/protocol/muc#roomconfig")
            {
                return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            let title = xdata_field(form, "muc#roomconfig_roomname")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(room.title.as_deref().unwrap_or(&room.localpart));
            if title.len() > 255 {
                return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
            }
            let persistent = match xdata_bool(form, "muc#roomconfig_persistentroom") {
                Ok(value) => value.unwrap_or(room.persistent),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let members_only = match xdata_bool(form, "muc#roomconfig_membersonly") {
                Ok(value) => value.unwrap_or(room.members_only),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let public = match xdata_bool(form, "muc#roomconfig_publicroom") {
                Ok(value) => value.unwrap_or(room.public),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let moderated = match xdata_bool(form, "muc#roomconfig_moderatedroom") {
                Ok(value) => value.unwrap_or(room.moderated),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let non_anonymous = match xdata_field(form, "muc#roomconfig_whois") {
                None => room.non_anonymous,
                Some("anyone") => true,
                Some("moderators") => false,
                Some(_) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let max_occupants = match xdata_field(form, "muc#roomconfig_maxusers") {
                None => room.max_occupants,
                Some(value) => match value.parse::<i32>() {
                    Ok(value @ 2..=1000) => value,
                    _ => return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable"))),
                },
            };
            db::update_muc_config(
                &self.state.pool,
                room.id,
                db::MucConfigUpdate {
                    title: Some(title),
                    persistent,
                    members_only,
                    public,
                    moderated,
                    non_anonymous,
                    max_occupants,
                },
            )
            .await?;
            if non_anonymous != room.non_anonymous {
                for (key, mut occupant) in self.state.muc_occupants_for(room_jid) {
                    occupant.room_non_anonymous = non_anonymous;
                    self.state.muc_occupants.insert(key, occupant);
                }
                let occupants = self.state.muc_occupants_for(room_jid);
                for (_, subject) in &occupants {
                    for (_, recipient) in &occupants {
                        let self_presence = subject.full_jid == recipient.full_jid;
                        let presence = muc_presence_stanza(
                            subject,
                            &recipient.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            non_anonymous || self_presence || recipient.role == "moderator",
                        );
                        let _ = recipient.sender.try_send(presence);
                    }
                }
            }
        }
        Ok(Action::Send(iq_result_from(id, room_jid, "")))
    }

    pub(crate) fn muc_domain(&self) -> String {
        format!("conference.{}", self.state.config.domain).to_ascii_lowercase()
    }

    pub(crate) async fn muc_presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        let Some(user) = self.authenticated.clone() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.clone() else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(to) = root.attribute("to") else {
            return Ok(Action::Send(stanza_error(root, "modify", "jid-malformed")));
        };
        let room_jid = bare_jid(to).to_ascii_lowercase();
        let nick = to
            .split_once('/')
            .map(|(_, nick)| nick.trim())
            .unwrap_or_default();
        if !valid_muc_room(localpart(&room_jid)) || !valid_muc_nick(nick) {
            return Ok(Action::Send(stanza_error(root, "modify", "jid-malformed")));
        }
        if root.attribute("type") == Some("unavailable") {
            let Some(joined_nick) = self.joined_rooms.remove(&room_jid) else {
                return Ok(Action::None);
            };
            let key = muc_occupant_key(&room_jid, &joined_nick);
            let Some((_, departed)) = self.state.muc_occupants.remove(&key) else {
                return Ok(Action::None);
            };
            let remaining = self.state.muc_occupants_for(&room_jid);
            for (_, target) in &remaining {
                let presence = muc_presence_stanza(
                    &departed,
                    &target.full_jid,
                    true,
                    false,
                    false,
                    None,
                    departed.room_non_anonymous || target.role == "moderator",
                );
                let _ = target.sender.try_send(presence);
            }
            let self_presence = muc_presence_stanza(
                &departed,
                &full_jid,
                true,
                true,
                false,
                root.attribute("id"),
                true,
            );
            if remaining.is_empty() {
                if let Some(room) = db::muc_room(&self.state.pool, localpart(&room_jid)).await? {
                    db::delete_temporary_muc_room(&self.state.pool, room.id).await?;
                }
            }
            return Ok(Action::Send(self_presence));
        }
        if root.attribute("type").is_some() {
            return Ok(Action::Send(stanza_error(root, "modify", "bad-request")));
        }

        if let Some(joined_nick) = self.joined_rooms.get(&room_jid).cloned() {
            if !self
                .state
                .muc_occupants
                .contains_key(&muc_occupant_key(&room_jid, &joined_nick))
            {
                self.joined_rooms.remove(&room_jid);
            } else if joined_nick.eq_ignore_ascii_case(nick) {
                return Ok(Action::None);
            } else {
                return Ok(Action::Send(stanza_error(root, "cancel", "conflict")));
            }
        }
        let key = muc_occupant_key(&room_jid, nick);
        if self.state.muc_occupants.contains_key(&key) {
            return Ok(Action::Send(stanza_error(root, "cancel", "conflict")));
        }
        let (room, created) = db::get_or_create_muc_room(
            &self.state.pool,
            &localpart(&room_jid).to_ascii_lowercase(),
            user.id,
        )
        .await?;
        let affiliation = db::muc_affiliation(&self.state.pool, room.id, user.id).await?;
        tracing::info!(
            room = %room_jid, user = %user.username, user_id = %user.id,
            room_id = %room.id, members_only = %room.members_only,
            affiliation = ?affiliation, "MUC join: affiliation check"
        );
        if affiliation.as_deref() == Some("outcast") {
            tracing::warn!(room = %room_jid, user = %user.username, "MUC join denied: user is outcast");
            return Ok(Action::Send(stanza_error(root, "auth", "forbidden")));
        }
        if room.members_only && affiliation.is_none() {
            tracing::warn!(room = %room_jid, user = %user.username, "MUC join denied: members-only and no affiliation");
            return Ok(Action::Send(stanza_error(
                root,
                "auth",
                "registration-required",
            )));
        }
        let existing = self.state.muc_occupants_for(&room_jid);
        if existing.len() >= room.max_occupants as usize {
            return Ok(Action::Send(stanza_error(
                root,
                "wait",
                "service-unavailable",
            )));
        }

        let affiliation = affiliation.unwrap_or_else(|| "none".to_owned());
        let role = if matches!(affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else if room.moderated && affiliation == "none" {
            "visitor"
        } else {
            "participant"
        }
        .to_owned();

        let mut payload = String::new();
        for child in root.children() {
            if child.is_element() {
                let ns = child.tag_name().namespace().unwrap_or_default();
                if ns != "http://jabber.org/protocol/muc" {
                    let range = child.range();
                    payload.push_str(&raw[range.start..range.end]);
                }
            }
        }

        let occupant = crate::state::MucOccupant {
            full_jid: full_jid.clone(),
            room_jid: room_jid.clone(),
            nick: nick.to_owned(),
            sender: self.outbound.clone(),
            affiliation,
            role,
            room_non_anonymous: room.non_anonymous,
            payload,
        };
        self.state.muc_occupants.insert(key, occupant.clone());
        self.joined_rooms.insert(room_jid.clone(), nick.to_owned());

        let mut replies = Vec::with_capacity(existing.len() + 24);
        for (_, present) in &existing {
            replies.push(muc_presence_stanza(
                present,
                &full_jid,
                false,
                false,
                false,
                None,
                room.non_anonymous || occupant.role == "moderator",
            ));
        }
        for (_, target) in &existing {
            let joined = muc_presence_stanza(
                &occupant,
                &target.full_jid,
                false,
                false,
                false,
                None,
                room.non_anonymous || target.role == "moderator",
            );
            let _ = target.sender.try_send(joined);
        }
        replies.push(muc_presence_stanza(
            &occupant,
            &full_jid,
            false,
            true,
            created,
            root.attribute("id"),
            true,
        ));
        let subject_str = room.subject.as_deref().unwrap_or("");
        replies.push(format!(
                "<message xmlns='jabber:client' from='{}' to='{}' type='groupchat'><subject>{}</subject></message>",
                attr_escape(&room_jid),
                attr_escape(&full_jid),
                xml_escape(subject_str)
            ));

        tracing::info!(
            room = %room_jid, user = %user.username,
            "MUC join: success"
        );

        let mut history_limit = 20;
        if let Some(x) = root.children().find(|n| {
            n.is_element()
                && n.tag_name().name() == "x"
                && n.tag_name().namespace() == Some("http://jabber.org/protocol/muc")
        }) {
            if let Some(history) = x.children().find(|n| n.tag_name().name() == "history") {
                if let Some(max) = history
                    .attribute("maxstanzas")
                    .and_then(|s| s.parse::<i64>().ok())
                {
                    history_limit = max.clamp(0, 100);
                }
            }
        }
        for message in db::muc_history(&self.state.pool, room.id, history_limit).await? {
            let history = if room.non_anonymous {
                add_muc_sender(&message.stanza, &message.sender_jid)
            } else {
                message.stanza
            };
            replies.push(set_to(&add_delay(&history, message.created_at), &full_jid));
        }
        Ok(Action::SendMany(replies))
    }

    pub(crate) async fn muc_admin_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(room_jid) = iq.attribute("to").map(bare_jid) else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        if !valid_muc_room(localpart(room_jid)) {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        }
        let Some(room) = db::muc_room(&self.state.pool, localpart(room_jid)).await? else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        let Some(item) = query
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "item")
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        };

        let Some(requested_affiliation) = item.attribute("affiliation") else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        };
        if !matches!(
            requested_affiliation,
            "owner" | "admin" | "member" | "outcast"
        ) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
        }

        let requester_affiliation = db::muc_affiliation(&self.state.pool, room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if !can_retrieve_muc_affiliation_list(
            &requester_affiliation,
            requested_affiliation,
            room.members_only,
            room.non_anonymous,
        ) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }

        let list =
            db::get_muc_affiliations(&self.state.pool, room.id, requested_affiliation).await?;
        let mut result = "<query xmlns='http://jabber.org/protocol/muc#admin'>".to_string();
        for username in list {
            let jid = format!("{}@{}", username, self.state.config.domain);
            result.push_str(&format!(
                "<item affiliation='{}' jid='{}'/>",
                attr_escape(requested_affiliation),
                attr_escape(&jid)
            ));
        }
        result.push_str("</query>");
        Ok(Action::Send(iq_result_from(id, room_jid, &result)))
    }
}

impl ProtocolSession {
    pub(crate) async fn muc_admin_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(room_jid) = iq.attribute("to").map(bare_jid) else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let Some(room) = db::muc_room(&self.state.pool, localpart(room_jid)).await? else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        let my_affiliation = db::muc_affiliation(&self.state.pool, room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if !matches!(my_affiliation.as_str(), "owner" | "admin") {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }

        for item in query
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "item")
        {
            if let (Some(target_jid), Some(new_affil)) =
                (item.attribute("jid"), item.attribute("affiliation"))
            {
                if !matches!(new_affil, "owner" | "admin" | "member" | "outcast" | "none") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
                if new_affil == "owner" && my_affiliation != "owner" {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "not-allowed")));
                }

                let target_localpart = localpart(target_jid);

                // Update DB
                tracing::info!(room = %room_jid, target = %target_localpart, affiliation = %new_affil, "MUC admin_set: setting affiliation");
                db::set_muc_affiliation(&self.state.pool, room.id, target_localpart, new_affil)
                    .await?;

                // Broadcast presence if they are in the room
                let occupants: Vec<_> = self
                    .state
                    .muc_occupants_for(room_jid)
                    .into_iter()
                    .filter(|(_, occ)| {
                        bare_jid(&occ.full_jid).eq_ignore_ascii_case(bare_jid(target_jid))
                    })
                    .collect();

                for (key, mut occupant) in occupants {
                    occupant.affiliation = new_affil.to_owned();
                    let remove_from_room =
                        new_affil == "outcast" || (new_affil == "none" && room.members_only);
                    if remove_from_room {
                        occupant.role = "none".to_owned();
                        self.state.muc_occupants.remove(&key);
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let presence = muc_presence_stanza(
                                &occupant,
                                &other.full_jid,
                                true,
                                false,
                                false,
                                None,
                                occupant.room_non_anonymous || other.role == "moderator",
                            );
                            let _ = other.sender.try_send(presence);
                        }
                        let self_presence = muc_presence_stanza(
                            &occupant,
                            &occupant.full_jid,
                            true,
                            true,
                            false,
                            None,
                            true,
                        );
                        let _ = occupant.sender.try_send(self_presence);
                    } else {
                        occupant.role = if matches!(new_affil, "owner" | "admin") {
                            "moderator"
                        } else if room.moderated && new_affil == "none" {
                            "visitor"
                        } else {
                            "participant"
                        }
                        .to_owned();
                        self.state.muc_occupants.insert(key, occupant.clone());
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let self_presence = other.full_jid == occupant.full_jid;
                            let presence = muc_presence_stanza(
                                &occupant,
                                &other.full_jid,
                                false,
                                self_presence,
                                false,
                                None,
                                occupant.room_non_anonymous
                                    || self_presence
                                    || other.role == "moderator",
                            );
                            let _ = other.sender.try_send(presence);
                        }
                    }
                }
            } else if let (Some(target_nick), Some(new_role)) =
                (item.attribute("nick"), item.attribute("role"))
            {
                if !matches!(new_role, "moderator" | "participant" | "visitor" | "none") {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
                let target_key = muc_occupant_key(room_jid, target_nick);
                if let Some(mut occupant) =
                    self.state.muc_occupants.get(&target_key).map(|v| v.clone())
                {
                    occupant.role = new_role.to_owned();
                    if new_role == "none" {
                        self.state.muc_occupants.remove(&target_key);
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let self_presence = other.full_jid == occupant.full_jid;
                            let presence = muc_presence_stanza(
                                &occupant,
                                &other.full_jid,
                                true,
                                self_presence,
                                false,
                                None,
                                occupant.room_non_anonymous
                                    || self_presence
                                    || other.role == "moderator",
                            );
                            let _ = other.sender.try_send(presence);
                        }
                        let presence = muc_presence_stanza(
                            &occupant,
                            &occupant.full_jid,
                            true,
                            true,
                            false,
                            None,
                            true,
                        );
                        let _ = occupant.sender.try_send(presence);
                    } else {
                        self.state
                            .muc_occupants
                            .insert(target_key, occupant.clone());
                        for (_, other) in self.state.muc_occupants_for(room_jid) {
                            let self_presence = other.full_jid == occupant.full_jid;
                            let presence = muc_presence_stanza(
                                &occupant,
                                &other.full_jid,
                                false,
                                self_presence,
                                false,
                                None,
                                occupant.room_non_anonymous
                                    || self_presence
                                    || other.role == "moderator",
                            );
                            let _ = other.sender.try_send(presence);
                        }
                    }
                }
            }
        }

        Ok(Action::Send(iq_result_from(id, room_jid, "")))
    }
}

#[cfg(test)]
mod tests {
    use super::can_retrieve_muc_affiliation_list;

    #[test]
    fn owners_and_admins_can_retrieve_persisted_affiliation_lists() {
        for requester in ["owner", "admin"] {
            for requested in ["owner", "admin", "member", "outcast"] {
                assert!(can_retrieve_muc_affiliation_list(
                    requester, requested, false, false
                ));
            }
        }
    }

    #[test]
    fn members_can_retrieve_omemo_recipient_lists_in_private_non_anonymous_rooms() {
        for requested in ["owner", "admin", "member"] {
            assert!(can_retrieve_muc_affiliation_list(
                "member", requested, true, true
            ));
        }
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "outcast", true, true
        ));
    }

    #[test]
    fn ordinary_members_cannot_expand_jid_visibility_in_other_room_types() {
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "member", false, true
        ));
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "member", true, false
        ));
        assert!(!can_retrieve_muc_affiliation_list(
            "none", "member", true, true
        ));
        assert!(!can_retrieve_muc_affiliation_list(
            "member", "invalid", true, true
        ));
    }
}
