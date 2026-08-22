use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    abuse::{AbuseAction, PowProof},
    db,
    state::{bare_jid, jid_domain, localpart},
};
use anyhow::Result;
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl ProtocolSession {
    pub(crate) async fn message(&self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        };
        let Some(from) = self.full_jid.as_deref() else {
            return Ok(Action::Send(stanza_error(root, "cancel", "not-authorized")));
        };
        let proof = root
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "pow"
                    && node.tag_name().namespace() == Some("urn:northstar:pow:1")
            })
            .and_then(|node| {
                Some(PowProof {
                    challenge_id: node.attribute("challenge")?.parse().ok()?,
                    nonce: node.attribute("nonce")?.to_owned(),
                })
            });
        let actors = vec![
            format!("ip:{}", self.peer_ip),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ];
        if is_abuse_rated_message(root) {
            if let Err(error) = self.state.abuse.verify_or_allow(
                AbuseAction::Message,
                &format!("message:{}", user.id),
                &actors,
                proof.as_ref(),
            ) {
                self.state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Action::Send(abuse_stanza_error(root, error.requirement())));
            }
        }
        let routed_raw = strip_pow_element(raw);
        let Some(to) = root.attribute("to") else {
            return Ok(Action::Send(stanza_error(root, "modify", "jid-malformed")));
        };
        if jid_domain(to).is_some_and(|domain| domain.eq_ignore_ascii_case(&self.muc_domain())) {
            return self.muc_message(root, &routed_raw).await;
        }

        if let Some(x) = root.children().find(|n| {
            n.is_element()
                && n.tag_name().name() == "x"
                && n.tag_name().namespace() == Some("jabber:x:conference")
        }) {
            if let Some(room_jid) = x.attribute("jid").map(bare_jid) {
                if let Ok(Some(room)) = db::muc_room(&self.state.pool, localpart(room_jid)).await {
                    if room.members_only {
                        if let Ok(Some(my_affil)) =
                            db::muc_affiliation(&self.state.pool, room.id, user.id).await
                        {
                            if matches!(my_affil.as_str(), "owner" | "admin" | "member") {
                                let _ = sqlx::query(
                                        "INSERT INTO muc_affiliations (room_id, user_id, affiliation, updated_at) 
                                         SELECT $1, id, $3, NOW() FROM users WHERE username = $2
                                         ON CONFLICT (room_id, user_id) DO NOTHING"
                                    )
                                    .bind(room.id)
                                    .bind(localpart(to))
                                    .bind("member")
                                    .execute(&self.state.pool)
                                    .await;
                            }
                        }
                    }
                }
            }
        }

        if let Some(domain) =
            jid_domain(to).filter(|domain| !domain.eq_ignore_ascii_case(&self.state.config.domain))
        {
            if !self.state.config.federation_domain_allowed(domain) {
                return Ok(Action::Send(stanza_error(
                    root,
                    "cancel",
                    "remote-server-not-found",
                )));
            }
            if db::is_blocked(&self.state.pool, user.id, to).await? {
                return Ok(Action::Send(blocked_stanza_error(root)));
            }
            let rewritten = set_from(&routed_raw, from);
            let encrypted = is_encrypted(root);
            if !has_no_store_hint(root)
                && (encrypted || !self.state.config.require_encrypted_archive)
            {
                let archive = if encrypted {
                    encrypted_archive_stanza(&rewritten)
                } else {
                    rewritten.clone()
                };
                db::archive_message(
                    &self.state.pool,
                    user.id,
                    bare_jid(to),
                    &archive,
                    encrypted,
                    root.attribute("id"),
                )
                .await?;
            }
            self.state
                .federation
                .send(domain, rewritten.clone(), Some(from.to_owned()));
            if should_carbon(root) {
                self.send_sent_carbons(from, &rewritten);
            }
            self.state
                .metrics
                .messages_routed_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(Action::None);
        }
        let recipient_local = localpart(to).to_ascii_lowercase();
        let Some(recipient) = db::find_user(&self.state.pool, &recipient_local).await? else {
            return Ok(Action::Send(stanza_error(
                root,
                "cancel",
                "service-unavailable",
            )));
        };
        if db::is_blocked(&self.state.pool, user.id, to).await? {
            return Ok(Action::Send(blocked_stanza_error(root)));
        }
        if db::is_blocked(&self.state.pool, recipient.id, from).await? {
            return Ok(Action::Send(stanza_error(
                root,
                "cancel",
                "service-unavailable",
            )));
        }
        let rewritten = set_from(&routed_raw, from);
        let encrypted = is_encrypted(root);
        let persistence_allowed = !has_no_store_hint(root);
        let archive_stanza = if encrypted {
            encrypted_archive_stanza(&rewritten)
        } else {
            rewritten.clone()
        };
        let stanza_id = root.attribute("id");
        if persistence_allowed && (encrypted || !self.state.config.require_encrypted_archive) {
            db::archive_message(
                &self.state.pool,
                user.id,
                bare_jid(to),
                &archive_stanza,
                encrypted,
                stanza_id,
            )
            .await?;
            db::archive_message(
                &self.state.pool,
                recipient.id,
                bare_jid(from),
                &archive_stanza,
                encrypted,
                stanza_id,
            )
            .await?;
        }
        let mut targets = self.state.session_entries_for(to);
        if !to.contains('/') {
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
        let mut delivered_key = None;
        for (key, target) in &targets {
            if target.sender.try_send(rewritten.clone()).is_ok() {
                delivered_key = Some(key.clone());
                break;
            }
        }
        if delivered_key.is_none() {
            if !persistence_allowed {
                // XEP-0334 explicitly forbids offline or archive storage.
            } else if encrypted || !self.state.config.require_encrypted_archive {
                db::store_offline(
                    &self.state.pool,
                    recipient.id,
                    from,
                    &archive_stanza,
                    encrypted,
                )
                .await?;
                self.notify_push(&recipient).await?;
            } else {
                return Ok(Action::Send(stanza_error(
                    root,
                    "wait",
                    "service-unavailable",
                )));
            }
        } else if should_carbon(root) {
            self.send_received_carbons(bare_jid(to), delivered_key.as_deref(), &rewritten);
        }
        if should_carbon(root) {
            self.send_sent_carbons(from, &rewritten);
        }
        self.state
            .metrics
            .messages_routed_total
            .fetch_add(1, Ordering::Relaxed);
        Ok(Action::None)
    }

    pub(crate) fn send_sent_carbons(&self, from: &str, forwarded: &str) {
        let current = from.to_ascii_lowercase();
        for (jid, session) in self.state.session_entries_for(bare_jid(from)) {
            if jid == current || !session.carbons.load(Ordering::Relaxed) {
                continue;
            }
            let carbon = carbon_message("sent", bare_jid(from), &jid, forwarded);
            let _ = session.sender.try_send(carbon);
        }
    }

    pub(crate) fn send_received_carbons(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        for (jid, session) in self.state.session_entries_for(recipient) {
            if delivered == Some(jid.as_str()) || !session.carbons.load(Ordering::Relaxed) {
                continue;
            }
            let carbon = carbon_message("received", recipient, &jid, forwarded);
            let _ = session.sender.try_send(carbon);
        }
    }
}
