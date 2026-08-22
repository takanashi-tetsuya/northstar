use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{db, state::attr_escape};
use anyhow::Result;
use dashmap::mapref::entry::Entry;
use roxmltree::Node;
use std::{
    sync::{atomic::Ordering, Arc},
    time::Instant,
};

impl ProtocolSession {
    pub(crate) async fn stream_management(&mut self, root: Node<'_, '_>) -> Result<Action> {
        match root.tag_name().name() {
            "enable" => {
                if self.full_jid.is_none() || self.sm_enabled {
                    return Ok(Action::Send(sm_failed("unexpected-request")));
                }
                self.sm_enabled = true;
                self.sm_resume_allowed = root.attribute("resume") == Some("true");
                self.sm_inbound_h = 0;
                self.sm_outbound_h = 0;
                self.sm_acked_h = 0;
                self.sm_unacked.clear();
                if self.sm_resume_allowed {
                    let id = uuid::Uuid::new_v4().to_string();
                    self.sm_resume_id = Some(id.clone());
                    Ok(Action::Send(format!(
                        "<enabled xmlns='urn:xmpp:sm:3' id='{}' resume='true' max='{}'/>",
                        attr_escape(&id),
                        self.state.config.sm_resume_timeout_seconds
                    )))
                } else {
                    self.sm_resume_id = None;
                    Ok(Action::Send(
                        "<enabled xmlns='urn:xmpp:sm:3' resume='false'/>".into(),
                    ))
                }
            }
            "r" if self.sm_enabled => Ok(Action::Send(format!(
                "<a xmlns='urn:xmpp:sm:3' h='{}'/>",
                self.sm_inbound_h
            ))),
            "a" if self.sm_enabled => {
                let Some(h) = root
                    .attribute("h")
                    .and_then(|value| value.parse::<u32>().ok())
                else {
                    return Ok(Action::Send(sm_failed("bad-request")));
                };
                if !self.acknowledge(h) {
                    self.sm_resume_allowed = false;
                    return Ok(Action::Send(sm_failed("undefined-condition")));
                }
                Ok(Action::None)
            }
            "resume" => self.resume(root).await,
            _ => Ok(Action::Send(sm_failed("unexpected-request"))),
        }
    }

    pub(crate) async fn resume(&mut self, root: Node<'_, '_>) -> Result<Action> {
        if self.sm_enabled || self.full_jid.is_some() {
            return Ok(Action::Send(sm_failed("unexpected-request")));
        }
        let Some(current_user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(sm_failed("not-authorized")));
        };
        let Some(previd) = root.attribute("previd") else {
            return Ok(Action::Send(sm_failed("bad-request")));
        };
        let Some(client_h) = root
            .attribute("h")
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return Ok(Action::Send(sm_failed("bad-request")));
        };
        let Some((_, resumable)) = self.state.resumable_sessions.remove(previd) else {
            return Ok(Action::Send(sm_failed("item-not-found")));
        };
        if resumable.expires_at <= Instant::now() || resumable.user.id != current_user.id {
            return Ok(Action::Send(sm_failed("item-not-found")));
        }
        let key = resumable.full_jid.to_ascii_lowercase();
        let mut unacked = resumable.unacked;
        let delta = client_h.wrapping_sub(resumable.acked_h) as usize;
        if delta > unacked.len() {
            return Ok(Action::Send(sm_failed("undefined-condition")));
        }
        for _ in 0..delta {
            unacked.pop_front();
        }
        match self.state.sessions.entry(key.clone()) {
            Entry::Occupied(_) => return Ok(Action::Send(sm_failed("conflict"))),
            Entry::Vacant(entry) => {
                entry.insert(crate::state::OnlineSession {
                    sender: self.outbound.clone(),
                    available: Arc::clone(&resumable.available),
                    carbons: Arc::clone(&resumable.carbons),
                    priority: Arc::clone(&resumable.priority),
                    blocklist_requested: Arc::clone(&resumable.blocklist_requested),
                });
            }
        }
        self.authenticated = Some(resumable.user);
        self.full_jid = Some(resumable.full_jid);
        self.registered_key = Some(key);
        self.available = Some(resumable.available);
        self.carbons = resumable.carbons;
        self.priority = resumable.priority;
        self.blocklist_requested = resumable.blocklist_requested;
        self.sm_enabled = true;
        self.sm_resume_id = Some(previd.to_owned());
        self.sm_resume_allowed = true;
        self.sm_inbound_h = resumable.inbound_h;
        self.sm_outbound_h = resumable.outbound_h;
        self.sm_acked_h = client_h;
        self.sm_unacked = unacked;
        self.state
            .metrics
            .active_sessions
            .fetch_add(1, Ordering::Relaxed);

        let offline = db::take_offline(
            &self.state.pool,
            self.authenticated.as_ref().expect("resumed user").id,
        )
        .await?;
        for stanza in offline {
            let _ = self.outbound.send(stanza).await;
        }
        Ok(Action::Resume {
            control: format!(
                "<resumed xmlns='urn:xmpp:sm:3' h='{}' previd='{}'/>",
                self.sm_inbound_h,
                attr_escape(previd)
            ),
            replay: self.sm_unacked.iter().cloned().collect(),
        })
    }

    pub(crate) fn acknowledge(&mut self, h: u32) -> bool {
        let delta = h.wrapping_sub(self.sm_acked_h) as usize;
        if delta > self.sm_unacked.len() {
            return false;
        }
        for _ in 0..delta {
            self.sm_unacked.pop_front();
        }
        self.sm_acked_h = h;
        true
    }
}
