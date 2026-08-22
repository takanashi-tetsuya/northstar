pub(crate) mod blocking;
pub(crate) mod discovery;
pub(crate) mod dispatch;
pub(crate) mod ibr;
pub(crate) mod mam;
pub(crate) mod messaging;
pub(crate) mod misc;
pub(crate) mod muc;
pub(crate) mod pep;
pub(crate) mod presence;
pub(crate) mod private;
pub(crate) mod roster;
pub(crate) mod sm;
pub(crate) mod upload;
pub(crate) mod vcard;

use super::xml_util::*;
use crate::{
    db,
    state::{attr_escape, AppState},
};
use anyhow::Result;

use roxmltree::Node;
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{atomic::AtomicBool, atomic::AtomicI16, atomic::Ordering, Arc},
};
use tokio::sync::mpsc;

pub enum Action {
    Send(String),
    SendMany(Vec<String>),
    Resume {
        control: String,
        replay: Vec<String>,
    },
    StartTls,
    Close,
    None,
}

pub struct ProtocolSession {
    pub(crate) state: Arc<AppState>,
    pub(crate) outbound: mpsc::Sender<String>,
    pub tls: bool,
    pub(crate) websocket: bool,
    pub(crate) peer_ip: IpAddr,
    pub(crate) authenticated: Option<db::User>,
    pub(crate) full_jid: Option<String>,
    pub(crate) registered_key: Option<String>,
    pub(crate) available: Option<Arc<AtomicBool>>,
    pub(crate) carbons: Arc<AtomicBool>,
    pub(crate) priority: Arc<AtomicI16>,
    pub(crate) blocklist_requested: Arc<AtomicBool>,
    pub(crate) joined_rooms: HashMap<String, String>,
    pub(crate) sm_enabled: bool,
    pub(crate) sm_resume_id: Option<String>,
    pub(crate) sm_resume_allowed: bool,
    pub(crate) sm_inbound_h: u32,
    pub(crate) sm_outbound_h: u32,
    pub(crate) sm_acked_h: u32,
    pub(crate) sm_unacked: VecDeque<String>,
    pub(crate) sasl_state: Option<Box<dyn crate::auth::SaslMechanism>>,
}

impl ProtocolSession {
    pub fn new(
        state: Arc<AppState>,
        outbound: mpsc::Sender<String>,
        tls: bool,
        websocket: bool,
        peer_ip: IpAddr,
    ) -> Self {
        Self {
            state,
            outbound,
            tls,
            websocket,
            peer_ip,
            authenticated: None,
            full_jid: None,
            registered_key: None,
            available: None,
            carbons: Arc::new(AtomicBool::new(false)),
            priority: Arc::new(AtomicI16::new(0)),
            blocklist_requested: Arc::new(AtomicBool::new(false)),
            joined_rooms: HashMap::new(),
            sm_enabled: false,
            sm_resume_id: None,
            sm_resume_allowed: false,
            sm_inbound_h: 0,
            sm_outbound_h: 0,
            sm_acked_h: 0,
            sm_unacked: VecDeque::new(),
            sasl_state: None,
        }
    }

    pub fn record_outbound(&mut self, stanza: &str) {
        self.state
            .metrics
            .stanzas_out_total
            .fetch_add(1, Ordering::Relaxed);
        if self.sm_enabled && is_counted_stanza(stanza) {
            self.sm_outbound_h = self.sm_outbound_h.wrapping_add(1);
            self.sm_unacked.push_back(stanza.to_owned());
        }
    }

    pub fn record_replayed(&self) {
        self.state
            .metrics
            .stanzas_out_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn open_stream(&self) -> String {
        if self.websocket {
            let _ = self.outbound.try_send(self.features());
            format!("<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' from='{}' id='{}' version='1.0'/>",
                    attr_escape(&self.state.config.domain), stream_id())
        } else {
            format!("<stream:stream from='{}' id='{}' version='1.0' xml:lang='en' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>{}",
                    attr_escape(&self.state.config.domain), stream_id(), self.features())
        }
    }

    pub(crate) fn features(&self) -> String {
        if self.authenticated.is_some() {
            return "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><session xmlns='urn:ietf:params:xml:ns:xmpp-session'><optional/></session><sm xmlns='urn:xmpp:sm:3'/></stream:features>".into();
        }
        if !self.tls && !self.websocket {
            return "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>".into();
        }
        let register =
            if self.state.config.open_registration && !self.state.config.invitation_required {
                "<register xmlns='http://jabber.org/features/iq-register'/>"
            } else {
                ""
            };
        format!("<stream:features xmlns:stream='http://etherx.jabber.org/streams'><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-256</mechanism><mechanism>PLAIN</mechanism></mechanisms>{register}</stream:features>")
    }

    pub(crate) async fn authenticate(&mut self, root: Node<'_, '_>) -> Result<Action> {
        if !self.tls && !self.websocket {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "encryption-required",
            )));
        }

        let mechanism = root.attribute("mechanism").unwrap_or("");
        let payload = root.text().unwrap_or_default();

        let mut sasl_mech: Box<dyn crate::auth::SaslMechanism> = match mechanism {
            "PLAIN" => Box::new(crate::auth::PlainMechanism::new(
                self.state.config.domain.clone(),
            )),
            "SCRAM-SHA-256" => Box::new(crate::auth::ScramSha256Mechanism::new(
                self.state.config.domain.clone(),
            )),
            _ => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "invalid-mechanism",
                )));
            }
        };

        let step = sasl_mech.initial_response(payload);
        self.process_sasl_step(sasl_mech, step).await
    }

    pub(crate) async fn sasl_response(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let payload = root.text().unwrap_or_default();

        let mut sasl_mech = match self.sasl_state.take() {
            Some(mech) => mech,
            None => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "not-authorized",
                )));
            }
        };

        let step = sasl_mech.response(payload);
        self.process_sasl_step(sasl_mech, step).await
    }

    async fn process_sasl_step(
        &mut self,
        mut sasl_mech: Box<dyn crate::auth::SaslMechanism>,
        mut step: crate::auth::SaslStep,
    ) -> Result<Action> {
        if let crate::auth::SaslStep::NeedsCredentials(ref username) = step {
            match db::get_scram_credentials(&self.state.pool, username).await {
                Ok(Some(creds)) => {
                    step = sasl_mech.provide_credentials(
                        creds.salt,
                        creds.iterations,
                        creds.stored_key,
                        creds.server_key,
                    );
                }
                Ok(None) => {
                    step = crate::auth::SaslStep::Failure("not-authorized".into());
                }
                Err(error) => {
                    return Ok(self.authentication_backend_failure(
                        sasl_mech.name(),
                        username,
                        "load SCRAM verifier",
                        &error,
                    ));
                }
            }
        }

        match step {
            crate::auth::SaslStep::Success(username, data_opt) => {
                let user_result = if sasl_mech.name() == "PLAIN" {
                    if let Some(password) = data_opt.as_ref() {
                        db::authenticate(
                            &self.state.pool,
                            &username,
                            password,
                            self.state.config.scram_iterations,
                        )
                        .await
                    } else {
                        Ok(None)
                    }
                } else {
                    db::find_user(&self.state.pool, &username)
                        .await
                        .map(|user| user.filter(|user| !user.is_disabled))
                };
                let user = match user_result {
                    Ok(user) => user,
                    Err(error) => {
                        return Ok(self.authentication_backend_failure(
                            sasl_mech.name(),
                            &username,
                            "complete authentication",
                            &error,
                        ));
                    }
                };

                match user {
                    Some(user) => {
                        tracing::info!(username = %user.username, "XMPP authentication succeeded");
                        self.authenticated = Some(user);
                        let success_xml = if sasl_mech.name() == "SCRAM-SHA-256" {
                            if let Some(server_final) = data_opt {
                                use base64::Engine;
                                let b64 =
                                    base64::engine::general_purpose::STANDARD.encode(server_final);
                                format!("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</success>", b64)
                            } else {
                                "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".into()
                            }
                        } else {
                            "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".into()
                        };
                        Ok(Action::Send(success_xml))
                    }
                    None => {
                        self.state
                            .metrics
                            .authentication_failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        Ok(Action::Send(failure(
                            "urn:ietf:params:xml:ns:xmpp-sasl",
                            "not-authorized",
                        )))
                    }
                }
            }
            crate::auth::SaslStep::Challenge(challenge_data) => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(challenge_data);
                self.sasl_state = Some(sasl_mech);
                Ok(Action::Send(format!(
                    "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</challenge>",
                    b64
                )))
            }
            crate::auth::SaslStep::Failure(err) => {
                tracing::warn!("SASL authentication failed: {}", err);
                self.sasl_state = None;
                self.state
                    .metrics
                    .authentication_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "not-authorized",
                )))
            }
            crate::auth::SaslStep::NeedsCredentials(_) => {
                unreachable!("NeedsCredentials should be handled above")
            }
        }
    }

    fn authentication_backend_failure(
        &mut self,
        mechanism: &str,
        username: &str,
        operation: &str,
        error: &anyhow::Error,
    ) -> Action {
        self.sasl_state = None;
        self.state
            .metrics
            .authentication_backend_failures_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            %mechanism,
            %username,
            %operation,
            ?error,
            "XMPP authentication backend failed"
        );
        Action::Send(failure(
            "urn:ietf:params:xml:ns:xmpp-sasl",
            "temporary-auth-failure",
        ))
    }
}

impl Drop for ProtocolSession {
    fn drop(&mut self) {
        for (room_jid, nick) in std::mem::take(&mut self.joined_rooms) {
            let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &nick);
            let Some((_, departed)) = self.state.muc_occupants.remove(&key) else {
                continue;
            };
            let remaining = self.state.muc_occupants_for(&room_jid);
            for (_, target) in &remaining {
                let presence = crate::xmpp::xml_util::muc_presence_stanza(
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
            if remaining.is_empty() {
                let state = Arc::clone(&self.state);
                tokio::spawn(async move {
                    let Ok(Some(room)) =
                        db::muc_room(&state.pool, crate::state::localpart(&room_jid)).await
                    else {
                        return;
                    };
                    let _ = db::delete_temporary_muc_room(&state.pool, room.id).await;
                });
            }
        }
        if let Some(key) = self.registered_key.take() {
            self.state.sessions.remove(&key);
            self.state
                .metrics
                .active_sessions
                .fetch_sub(1, Ordering::Relaxed);
            if self.sm_enabled && self.sm_resume_allowed {
                if let (Some(resume_id), Some(user), Some(full_jid), Some(available)) = (
                    self.sm_resume_id.clone(),
                    self.authenticated.clone(),
                    self.full_jid.clone(),
                    self.available.clone(),
                ) {
                    self.state.resumable_sessions.insert(
                        resume_id.clone(),
                        crate::state::ResumableSession {
                            user,
                            full_jid,
                            available,
                            carbons: Arc::clone(&self.carbons),
                            priority: Arc::clone(&self.priority),
                            blocklist_requested: Arc::clone(&self.blocklist_requested),
                            inbound_h: self.sm_inbound_h,
                            outbound_h: self.sm_outbound_h,
                            acked_h: self.sm_acked_h,
                            unacked: std::mem::take(&mut self.sm_unacked),
                            expires_at: std::time::Instant::now()
                                + std::time::Duration::from_secs(
                                    self.state.config.sm_resume_timeout_seconds,
                                ),
                        },
                    );
                }
            } else if let Some(available) = self.available.take() {
                available.store(false, Ordering::Relaxed);
                if let Some(user) = &self.authenticated {
                    let state = Arc::clone(&self.state);
                    let user_id = user.id;
                    let full_jid_clone = self.full_jid.clone().unwrap_or_default();
                    tokio::spawn(async move {
                        let Ok(roster) = db::roster(&state.pool, user_id).await else {
                            return;
                        };
                        let presence = format!(
                            "<presence xmlns='jabber:client' from='{}' type='unavailable'/>",
                            crate::state::attr_escape(&full_jid_clone)
                        );
                        for (jid, _, subscription, _) in roster {
                            if !matches!(subscription.as_str(), "from" | "both") {
                                continue;
                            }
                            for target in state.sessions_for(&jid) {
                                let _ = target.sender.try_send(presence.clone());
                            }
                        }
                    });
                }
            }
        }
    }
}
