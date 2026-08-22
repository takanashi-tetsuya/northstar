use crate::state::{attr_escape, bare_jid, jid_domain};
use crate::xmpp::protocol::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use anyhow::{Context, Result};
use roxmltree::{Document, Node};
use std::sync::atomic::Ordering;

impl ProtocolSession {
    pub async fn handle(&mut self, xml: &str) -> Result<Action> {
        self.state
            .metrics
            .stanzas_in_total
            .fetch_add(1, Ordering::Relaxed);
        if xml.starts_with("<stream:stream") || xml.starts_with("<open") {
            return Ok(Action::Send(self.open_stream()));
        }
        if xml.starts_with("</stream:stream") || xml.starts_with("<close") {
            self.sm_resume_allowed = false;
            return Ok(Action::Close);
        }
        if xml.starts_with("<starttls") {
            if self.websocket || self.tls || self.authenticated.is_some() {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-tls",
                    "unexpected-request",
                )));
            }
            return Ok(Action::StartTls);
        }
        let doc = Document::parse(xml).context("malformed XML stanza")?;
        let root = doc.root_element();
        if root.tag_name().namespace() == Some("urn:xmpp:sm:3") {
            return self.stream_management(root).await;
        }
        let counted = matches!(root.tag_name().name(), "iq" | "message" | "presence");
        let action = match root.tag_name().name() {
            "auth" => self.authenticate(root).await,
            "response" => {
                if root.tag_name().namespace() == Some("urn:xmpp:ibr:0") {
                    self.handle_ibr_response(root).await
                } else {
                    self.sasl_response(root).await
                }
            }
            "register" if root.tag_name().namespace() == Some("urn:xmpp:ibr:0") => {
                self.handle_ibr_register(root).await
            }
            "iq" => self.iq(root, xml).await,
            "message" => self.message(root, xml).await,
            "presence" => self.presence(root, xml).await,
            _ => Ok(Action::Send(stream_error("unsupported-stanza-type"))),
        }?;
        if counted && self.sm_enabled {
            self.sm_inbound_h = self.sm_inbound_h.wrapping_add(1);
        }
        Ok(action)
    }

    pub(crate) async fn iq(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        let id = root.attribute("id").unwrap_or_default();
        let kind = root.attribute("type").unwrap_or("get");
        let child = root.children().find(|n| n.is_element());
        let Some(child) = child else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let muc_domain = self.muc_domain();
        let upload_domain = self.upload_domain();
        if let Some(to) = root.attribute("to") {
            if let Some(domain) = jid_domain(to) {
                if domain.eq_ignore_ascii_case(&self.state.config.domain) && to.contains('/') {
                    let from = self.full_jid.as_deref().unwrap_or("");
                    let rewritten = set_from(raw, from);
                    let targets = self.state.session_entries_for(to);
                    let mut delivered = false;
                    for (_, target) in targets {
                        if target.sender.try_send(rewritten.clone()).is_ok() {
                            delivered = true;
                            break;
                        }
                    }
                    if delivered {
                        return Ok(Action::None);
                    } else {
                        if kind == "get" || kind == "set" {
                            return Ok(Action::Send(iq_error(id, "service-unavailable")));
                        } else {
                            return Ok(Action::None);
                        }
                    }
                } else if domain.eq_ignore_ascii_case(&muc_domain) && to.contains('/') {
                    let room_jid = bare_jid(to).to_ascii_lowercase();
                    let target_nick = to.split_once('/').map(|(_, nick)| nick).unwrap_or_default();
                    let target_key =
                        crate::xmpp::xml_util::muc_occupant_key(&room_jid, target_nick);
                    let Some(target) = self
                        .state
                        .muc_occupants
                        .get(&target_key)
                        .map(|entry| entry.value().clone())
                    else {
                        if kind == "get" || kind == "set" {
                            return Ok(Action::Send(iq_error(id, "item-not-found")));
                        } else {
                            return Ok(Action::None);
                        }
                    };
                    let Some(own_nick) = self.joined_rooms.get(&room_jid) else {
                        if kind == "get" || kind == "set" {
                            return Ok(Action::Send(iq_error(id, "not-acceptable")));
                        } else {
                            return Ok(Action::None);
                        }
                    };
                    let rewritten = set_to(
                        &set_from(raw, &format!("{}/{}", room_jid, own_nick)),
                        &target.full_jid,
                    );
                    tracing::debug!(room=%room_jid, from=%own_nick, to=%target.full_jid, "MUC routing IQ");
                    let _ = target.sender.try_send(rewritten);
                    return Ok(Action::None);
                }
            }
        }

        if let Some(domain) = root.attribute("to").and_then(jid_domain).filter(|domain| {
            !domain.eq_ignore_ascii_case(&self.state.config.domain)
                && !domain.eq_ignore_ascii_case(&muc_domain)
                && !domain.eq_ignore_ascii_case(&upload_domain)
        }) {
            let Some(from) = self.full_jid.as_deref() else {
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            };
            if !self.state.config.federation_domain_allowed(domain) {
                return Ok(Action::Send(iq_error(id, "remote-server-not-found")));
            }
            self.state
                .federation
                .send(domain, set_from(raw, from), Some(from.to_owned()));
            return Ok(Action::None);
        }
        let ns = child.tag_name().namespace().unwrap_or_default();
        match (child.tag_name().name(), ns, kind) {
                ("query", "jabber:iq:register", "get") if self.authenticated.is_none() => {
                    if self.state.config.open_registration
                        && !self.state.config.invitation_required
                    {
                        Ok(Action::Send(format!("<iq xmlns='jabber:client' type='result' id='{}'><query xmlns='jabber:iq:register'><instructions>Choose a username and a password of at least 10 characters.</instructions><username/><password/></query></iq>", attr_escape(id))))
                    } else {
                        Ok(Action::Send(iq_error(id, "not-allowed")))
                    }
                }
                ("query", "jabber:iq:register", "set") if self.authenticated.is_none() => self.register(id, child).await,
                ("query", "jabber:iq:register", "set") => self.change_password(id, child).await,
                ("bind", "urn:ietf:params:xml:ns:xmpp-bind", "set") => self.bind(id, child).await,
                ("session", "urn:ietf:params:xml:ns:xmpp-session", "set") => Ok(Action::Send(iq_result(id, ""))),
                ("query", "jabber:iq:roster", "get") => self.roster_get(id).await,
                ("query", "jabber:iq:roster", "set") => self.roster_set(id, child).await,
                ("unique", "http://jabber.org/protocol/muc#unique", "get") => {
                    Ok(Action::Send(iq_result_from(
                        id,
                        root.attribute("to").unwrap_or(&muc_domain),
                        &format!("<unique xmlns='http://jabber.org/protocol/muc#unique'>{}</unique>", uuid::Uuid::new_v4()),
                    )))
                }
                ("query", "http://jabber.org/protocol/muc#owner", "get") => {
                    self.muc_owner_get(id, root).await
                }
                ("query", "http://jabber.org/protocol/muc#owner", "set") => {
                    self.muc_owner_set(id, root, child).await
                }
                ("query", "http://jabber.org/protocol/muc#admin", "get") => {
                    self.muc_admin_get(id, root, child).await
                }
                ("query", "http://jabber.org/protocol/muc#admin", "set") => {
                    self.muc_admin_set(id, root, child).await
                }
                ("query", "http://jabber.org/protocol/disco#info", "get") => {
                    self.disco_info(id, root.attribute("to")).await
                }
                ("query", "http://jabber.org/protocol/disco#items", "get") => {
                    self.disco_items(id, root.attribute("to")).await
                }
                ("ping", "urn:xmpp:ping", "get") => Ok(Action::Send(iq_result(id, ""))),
                ("time", "urn:xmpp:time", "get") => {
                    let now = chrono::Utc::now();
                    let payload = format!("<time xmlns='urn:xmpp:time'><tzo>+00:00</tzo><utc>{}</utc></time>", now.format("%Y-%m-%dT%H:%M:%SZ"));
                    Ok(Action::Send(iq_result(id, &payload)))
                }
                ("query", "jabber:iq:version", "get") => Ok(Action::Send(iq_result(id, "<query xmlns='jabber:iq:version'><name>Rust XMPP Server</name><version>0.1.0</version><os>Linux</os></query>"))),
                ("vCard", "vcard-temp", "get") => self.vcard_get(id, root).await,
                ("vCard", "vcard-temp", "set") => self.vcard_set(id, root, child, raw).await,
                ("enable", "urn:xmpp:push:0", "set") => self.enable_push(id, child, raw).await,
                ("disable", "urn:xmpp:push:0", "set") => self.disable_push(id, child).await,
                ("request", "urn:xmpp:http:upload:0", "get") => {
                    self.http_upload_slot(id, root.attribute("to"), child).await
                }
                ("query", "urn:xmpp:mam:2", "set") => self.mam(id, child).await,
                ("query", "urn:xmpp:mam:2", "get") => Ok(Action::Send(iq_result(id, mam_form()))),
                ("prefs", "urn:xmpp:mam:2", "get") => Ok(Action::Send(iq_result(
                    id,
                    "<prefs xmlns='urn:xmpp:mam:2' default='always'/>",
                ))),
                ("prefs", "urn:xmpp:mam:2", "set") => Ok(Action::Send(iq_result(id, ""))),
                ("enable", "urn:xmpp:carbons:2", "set") => self.set_carbons(id, true),
                ("disable", "urn:xmpp:carbons:2", "set") => self.set_carbons(id, false),
                ("blocklist", "urn:xmpp:blocking", "get") => self.blocklist(id).await,
                ("block", "urn:xmpp:blocking", "set") => self.block(id, child).await,
                ("unblock", "urn:xmpp:blocking", "set") => self.unblock(id, child).await,
                ("pubsub", "http://jabber.org/protocol/pubsub", "set") => self.pep_publish(id, child, raw).await,
                ("pubsub", "http://jabber.org/protocol/pubsub", "get") => self.pep_get(id, root, child).await,
                ("pubsub", "http://jabber.org/protocol/pubsub#owner", "get") |
                ("pubsub", "http://jabber.org/protocol/pubsub#owner", "set") => {
                    Ok(Action::Send(iq_result(id, "")))
                }
                ("query", "jabber:iq:private", "get") => self.private_get(id, child).await,
                ("query", "jabber:iq:private", "set") => self.private_set(id, child, raw).await,
                _ => {
                    tracing::debug!(
                        element = child.tag_name().name(),
                        namespace = ns,
                        iq_type = kind,
                        iq_id = id,
                        "unsupported IQ"
                    );
                    Ok(Action::Send(iq_error(id, "feature-not-implemented")))
                }
            }
    }
}
