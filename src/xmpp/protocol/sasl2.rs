use crate::auth;
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::valid_language_tag;
use anyhow::{Context, Result};
use roxmltree::{Document, Node};
use uuid::{Uuid, Variant};
use zeroize::Zeroizing;

use super::{Action, ProtocolSession};

mod authentication;
mod parsing;

pub(crate) use self::authentication::{authentication_feature_xml, failure_xml};
use self::authentication::{
    fast_token_xml, inline_resume_envelope_reservation_bytes, sasl2_success_xml,
};
pub(crate) use self::parsing::is_tcp_stream_opening;
pub(super) use self::parsing::normalize_base64_payload;
use self::parsing::{
    attr_is, direct_text, normalize_sasl2_base64_payload, parse_authenticate, singleton_text,
    structural_text_is_empty,
};
#[cfg(test)]
use self::parsing::{parse_stream_open, ParsedStreamOpen, StreamOpenError};

pub(crate) const SASL2_NS: &str = "urn:xmpp:sasl:2";
pub(crate) const BIND2_NS: &str = "urn:xmpp:bind:0";
pub(crate) const FAST_NS: &str = "urn:xmpp:fast:0";

#[derive(Clone, Debug, Default)]
pub(crate) struct Bind2Request {
    pub tag: Option<String>,
    pub carbons: bool,
    pub sm: Option<SmInlineRequest>,
    pub csi_active: Option<bool>,
}

#[derive(Clone, Debug)]
pub(crate) struct SmInlineRequest {
    pub resume: bool,
    pub max: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct FastRequest {
    /// XEP-0484 requires a monotonically increasing count only for TLS 0-RTT.
    /// Northstar does not advertise or accept early data, so ordinary FAST
    /// clients may omit it. A supplied value is still enforced atomically.
    pub count: Option<i64>,
    pub invalidate: bool,
}

pub(crate) struct SmResumeRequest {
    pub previd: Zeroizing<String>,
    pub h: u32,
}

pub(crate) struct Sasl2Request {
    pub mechanism: String,
    pub initial_response: Option<Zeroizing<String>>,
    pub user_agent_id: Option<Uuid>,
    pub bind: Option<Bind2Request>,
    pub request_token: Option<String>,
    pub fast: Option<FastRequest>,
    pub resume: Option<SmResumeRequest>,
}

pub(crate) struct Sasl2Context {
    pub request: Sasl2Request,
    pub fast_should_rotate: bool,
    pub awaiting_initial_response: bool,
    pub fast_token_id: Option<Uuid>,
    pub fast_token_was_new: bool,
    pub fast_invalidate: bool,
    pub authenticated_generation: Option<i64>,
    pub inherited_fast_chain:
        Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
}

impl std::fmt::Debug for SmResumeRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SmResumeRequest")
            .field("previd", &"[REDACTED]")
            .field("h", &self.h)
            .finish()
    }
}

impl std::fmt::Debug for Sasl2Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sasl2Request")
            .field("mechanism", &self.mechanism)
            .field(
                "initial_response",
                &self.initial_response.as_ref().map(|_| "[REDACTED]"),
            )
            .field("user_agent_id", &self.user_agent_id)
            .field("bind", &self.bind)
            .field("request_token", &self.request_token)
            .field("fast", &self.fast)
            .field("resume", &self.resume)
            .finish()
    }
}

impl std::fmt::Debug for Sasl2Context {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sasl2Context")
            .field("request", &self.request)
            .field("fast_should_rotate", &self.fast_should_rotate)
            .field("awaiting_initial_response", &self.awaiting_initial_response)
            .field("fast_token_id", &self.fast_token_id.map(|_| "[REDACTED]"))
            .field("fast_token_was_new", &self.fast_token_was_new)
            .field("fast_invalidate", &self.fast_invalidate)
            .field("authenticated_generation", &self.authenticated_generation)
            .field("inherited_fast_chain", &self.inherited_fast_chain)
            .finish()
    }
}

/// Test-only access to the production success builder, with no bearer or
/// additional-data extension admitted by the closed Stage4 profile.
#[cfg(test)]
pub(crate) fn stage4_saved_success_xml(authorization_identifier: &str) -> Result<String> {
    sasl2_success_xml(None, authorization_identifier, &[])
}

/// roxmltree requires a complete document. TCP XMPP supplies only the inbound
/// opening tag at this point, so synthesize a closing tag exclusively for the
/// local parser input. This string is never written to any transport.
fn complete_inbound_stream_opening_for_parser(xml: &str) -> String {
    let closing = "</stream:stream>";
    let mut parser_input = String::with_capacity(xml.len() + closing.len());
    parser_input.push_str(xml);
    parser_input.push_str(closing);
    parser_input
}

impl ProtocolSession {
    pub(crate) async fn authenticate2(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let _authentication_timer = self.state.sasl2_authentication_timer();
        if !self.secure_transport {
            return Ok(Action::Send(failure_xml("encryption-required", None)));
        }
        if self.authenticated.is_some() {
            return Ok(Action::Send(crate::xmpp::xml_util::stream_error(
                "not-authorized",
            )));
        }
        if self.sasl_state.is_some() || self.sasl2_state.is_some() {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        self.sasl_scram_fence = None;
        let mut request = match parse_authenticate(root) {
            Ok(request) => request,
            Err(condition) => return Ok(Action::Send(failure_xml(condition, None))),
        };
        if (request.resume.is_some() || request.bind.as_ref().is_some_and(|bind| bind.sm.is_some()))
            && !self
                .state
                .xmpp_extension_enabled(northstar_xep_0198::XEP_ID)
        {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        if request
            .bind
            .as_ref()
            .is_some_and(|bind| bind.csi_active.is_some())
            && !self
                .state
                .xmpp_extension_enabled(northstar_xep_0352::XEP_ID)
        {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        if request.request_token.is_some() && request.user_agent_id.is_none() {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        if request
            .request_token
            .as_deref()
            .is_some_and(|mechanism| !self.fast_mechanism_available(mechanism))
        {
            return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
        }
        if auth::is_fast_mechanism(&request.mechanism) {
            if !self.fast_mechanism_available(&request.mechanism) {
                return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
            }
            if request
                .request_token
                .as_ref()
                .is_some_and(|mechanism| mechanism != &request.mechanism)
            {
                return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
            }
            return self.authenticate_fast(request).await;
        }
        if request.fast.is_some() {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }

        let mut mechanism: Box<dyn auth::SaslMechanism> = match request.mechanism.as_str() {
            "EXTERNAL" if !self.client_certificate_identities.is_empty() => Box::new(
                auth::ExternalMechanism::new(self.client_certificate_identities.clone()),
            ),
            "PLAIN" => Box::new(auth::PlainMechanism::new(
                self.state.local_domain().to_owned(),
            )),
            "SCRAM-SHA-256" => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        auth::ScramSha256Mechanism::new_with_channel_binding_support(
                            self.state.local_domain().to_owned(),
                        ),
                    )
                } else {
                    Box::new(auth::ScramSha256Mechanism::new(
                        self.state.local_domain().to_owned(),
                    ))
                }
            }
            "SCRAM-SHA-256-PLUS" => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
                };
                Box::new(auth::ScramSha256Mechanism::new_plus(
                    self.state.local_domain().to_owned(),
                    bindings,
                ))
            }
            "SCRAM-SHA-1" if self.state.c2s_scram_sha1_enabled() => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        auth::ScramSha256Mechanism::new_sha1_with_channel_binding_support(
                            self.state.local_domain().to_owned(),
                        ),
                    )
                } else {
                    Box::new(auth::ScramSha256Mechanism::new_sha1(
                        self.state.local_domain().to_owned(),
                    ))
                }
            }
            "SCRAM-SHA-1-PLUS" if self.state.c2s_scram_sha1_enabled() => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure_xml("invalid-mechanism", None)));
                };
                Box::new(auth::ScramSha256Mechanism::new_sha1_plus(
                    self.state.local_domain().to_owned(),
                    bindings,
                ))
            }
            _ => return Ok(Action::Send(failure_xml("invalid-mechanism", None))),
        };
        let awaiting_initial_response = request.initial_response.is_none();
        let initial_response = request.initial_response.take();
        let step = initial_response
            .as_deref()
            .map(|payload| mechanism.initial_response(payload))
            .unwrap_or_else(|| auth::SaslStep::Challenge(String::new()));
        self.sasl2_state = Some(Sasl2Context {
            request,
            fast_should_rotate: false,
            awaiting_initial_response,
            fast_token_id: None,
            fast_token_was_new: false,
            fast_invalidate: false,
            authenticated_generation: None,
            inherited_fast_chain: None,
        });
        self.process_sasl_step(mechanism, step).await
    }

    pub(crate) async fn sasl2_response(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let _authentication_timer = self.state.sasl2_authentication_timer();
        if root.tag_name().namespace() != Some(SASL2_NS)
            || root.tag_name().name() != "response"
            || !attr_is(root, &[])
            || root.children().any(|child| child.is_element())
        {
            return Ok(self.fail_sasl2_exchange("malformed-request"));
        }
        if self.sasl2_state.is_none() {
            return Ok(self.fail_sasl2_exchange("not-authorized"));
        }
        let payload = direct_text(root);
        if payload.len() > 64 * 1024 {
            return Ok(self.fail_sasl2_exchange("malformed-request"));
        }
        let payload = match normalize_sasl2_base64_payload(payload) {
            Ok(payload) => Zeroizing::new(payload),
            Err(condition) => return Ok(self.fail_sasl2_exchange(condition)),
        };
        let Some(mut mechanism) = self.sasl_state.take() else {
            return Ok(self.fail_sasl2_exchange("not-authorized"));
        };
        let awaiting_initial = self
            .sasl2_state
            .as_mut()
            .map(|context| std::mem::take(&mut context.awaiting_initial_response))
            .unwrap_or(false);
        let step = if awaiting_initial {
            mechanism.initial_response(&payload)
        } else {
            mechanism.response(&payload)
        };
        self.process_sasl_step(mechanism, step).await
    }

    pub(crate) fn sasl2_abort(&mut self, root: Node<'_, '_>) -> Action {
        let _authentication_timer = self.state.sasl2_authentication_timer();
        if root.tag_name().namespace() != Some(SASL2_NS)
            || !attr_is(root, &[])
            || !structural_text_is_empty(root)
        {
            return self.fail_sasl2_exchange("malformed-request");
        }
        if self.sasl2_state.is_none() {
            return self.fail_sasl2_exchange("not-authorized");
        }
        let mut text_seen = false;
        for child in root.children().filter(|child| child.is_element()) {
            if child.tag_name().namespace() == Some(SASL2_NS) && child.tag_name().name() == "text" {
                if text_seen || singleton_text(child, 1024).is_err() {
                    return self.fail_sasl2_exchange("malformed-request");
                }
                text_seen = true;
            }
            // Unknown extension elements are deliberately ignored: abort is
            // extensible and has no state-changing inline operations.
        }
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.sasl2_state = None;
        Action::Send(failure_xml("aborted", None))
    }

    fn fail_sasl2_exchange(&mut self, condition: &str) -> Action {
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.sasl2_state = None;
        Action::Send(failure_xml(condition, None))
    }

    pub(crate) async fn complete_sasl2(
        &mut self,
        user: crate::services::authentication::AuthenticatedAccount,
        sasl_data: Option<Zeroizing<Vec<u8>>>,
        authenticated_with_external: bool,
    ) -> Result<Action> {
        let Some(context) = self.sasl2_state.take() else {
            return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
        };
        let expected_auth_generation = context
            .authenticated_generation
            .unwrap_or(user.auth_generation);
        if expected_auth_generation != user.auth_generation {
            self.sasl_state = None;
            return Ok(Action::Send(failure_xml("credentials-expired", None)));
        }
        match self
            .state
            .authentication_service()
            .revalidate_generation(user.id, expected_auth_generation)
            .await
        {
            crate::services::authentication::AuthenticationResult::Authenticated(()) => {}
            crate::services::authentication::AuthenticationResult::Disabled
            | crate::services::authentication::AuthenticationResult::StaleGeneration
            | crate::services::authentication::AuthenticationResult::ExpiredCredentials
            | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("credentials-expired", None)));
            }
            crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("not-authorized", None)));
            }
            crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                self.state
                    .sasl2_authentication_telemetry()
                    .integrity_failed();
                tracing::error!(user_id = %user.id, "credential integrity failure during SASL2 revalidation");
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
            }
            crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                self.state.sasl2_authentication_telemetry().backend_failed();
                tracing::error!(?error, user_id = %user.id, "could not revalidate SASL2 credentials");
                self.sasl_state = None;
                return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
            }
        }
        self.user_agent_id = context.request.user_agent_id;
        if self
            .negotiation
            .stream_from()
            .is_some_and(|from| from != user.username)
        {
            self.sasl_state = None;
            self.user_agent_id = None;
            return Ok(Action::Send(failure_xml("not-authorized", None)));
        }
        let bind_plan = if let Some(bind) = context.request.bind.clone() {
            let tag = match bind.tag.as_deref() {
                Some(tag) if !tag.is_empty() => match crate::jid::prepare_resourcepart(tag) {
                    Ok(tag) => Some(tag),
                    Err(_) => {
                        self.user_agent_id = None;
                        return Ok(Action::Send(failure_xml("malformed-request", None)));
                    }
                },
                _ => None,
            };
            let generated = Uuid::new_v4().simple().to_string();
            let resource = tag
                .map(|tag| format!("{tag}/{generated}"))
                .unwrap_or(generated);
            let boundaries = match self
                .state
                .authentication_service()
                .bind2_archive_boundaries(user.id, expected_auth_generation)
                .await
            {
                crate::services::authentication::AuthenticationResult::Authenticated(
                    boundaries,
                ) => boundaries,
                crate::services::authentication::AuthenticationResult::Disabled
                | crate::services::authentication::AuthenticationResult::StaleGeneration
                | crate::services::authentication::AuthenticationResult::ExpiredCredentials
                | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("credentials-expired", None)));
                }
                crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("not-authorized", None)));
                }
                crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                    self.state
                        .sasl2_authentication_telemetry()
                        .integrity_failed();
                    tracing::error!(user_id = %user.id, "credential integrity failure during Bind2 preflight");
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                }
                crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                    self.state.sasl2_authentication_telemetry().backend_failed();
                    tracing::error!(?error, "could not preflight Bind 2 MAM metadata");
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                }
            };
            Some((bind, resource, boundaries))
        } else {
            None
        };
        let fast_plan = self.sasl2_fast_commit_plan(&context);
        let mut unbound_state_committed = false;
        let mut token_xml = if bind_plan.is_none() && context.request.resume.is_none() {
            match self
                .commit_sasl2_unbound_state(&fast_plan, &user, expected_auth_generation)
                .await?
            {
                Ok((token_xml, receipt, credential_attempt)) => {
                    unbound_state_committed = true;
                    self.retain_credential_commit(receipt, credential_attempt)?;
                    token_xml
                }
                Err(condition) => {
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml(condition, None)));
                }
            }
        } else {
            String::new()
        };
        // Keep the guard provisional until the entire SASL2 outcome (including
        // inline resume/bind) is known.  It is already present in the live CRL
        // registry before either inline operation begins, but automatically
        // unregisters if a later fallible step turns the exchange into a SASL
        // failure.  A subsequent password/FAST retry can therefore never
        // inherit an EXTERNAL-only drain registration.
        let mut certificate_session =
            if authenticated_with_external && self._certificate_session.is_none() {
                Some(self.external_certificate_session()?)
            } else {
                None
            };
        if self.disconnect.is_cancelled() {
            self.sasl_state = None;
            self.user_agent_id = None;
            return Ok(Action::Close);
        }
        self.authenticated = Some(user.clone());
        self.authenticated_at = Some(std::time::Instant::now());
        let mut resume_xml = String::new();
        if let Some(resume) = context.request.resume.as_ref() {
            match self
                .resume_values_with_fast(&resume.previd, resume.h, Some(&fast_plan), true)
                .await
            {
                Ok((Action::Resume(mut payload), issued)) => {
                    if let Some(issued) = issued {
                        token_xml = fast_token_xml(&issued);
                    }
                    let authorization_identifier = self
                        .full_jid
                        .as_deref()
                        .unwrap_or_else(|| {
                            self.authenticated = None;
                            ""
                        })
                        .to_owned();
                    if authorization_identifier.is_empty() {
                        self.sasl_state = None;
                        return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                    }
                    let features = self.features();
                    let envelope_reservation = inline_resume_envelope_reservation_bytes(
                        sasl_data.as_ref().map(|data| data.as_slice()),
                        &authorization_identifier,
                        payload.control(),
                        &token_xml,
                        &features,
                    )
                    .context("SASL2 inline resume envelope allocation overflow")?;
                    let envelope_capacity = self
                        .state
                        .sm_memory_governor()
                        .try_reserve_transient(envelope_reservation)
                        .context("SASL2 inline resume transport memory capacity reached")?;
                    let success = sasl2_success_xml(
                        sasl_data.as_ref().map(|data| data.as_slice()),
                        &authorization_identifier,
                        &[payload.control(), &token_xml],
                    )?;
                    let post_control = vec![features];
                    payload.replace_envelope(
                        success,
                        post_control,
                        envelope_reservation,
                        envelope_capacity,
                    )?;
                    if self.disconnect.is_cancelled() {
                        self.sm.resume_allowed = false;
                        self.sasl_state = None;
                        return Ok(Action::Close);
                    }
                    if let Some(guard) = certificate_session.take() {
                        self._certificate_session = Some(guard);
                    }
                    self.sasl_state = None;
                    // XEP-0388 requires fresh stream features immediately
                    // after every SASL2 success, including an inline SM
                    // resumption which skips Bind2. Reframing preserves the
                    // original replay reservation and adds the envelope lease.
                    payload.activate_route = true;
                    self.seal_resume_authentication(&mut payload)?;
                    return Ok(Action::Resume(payload));
                }
                Ok((Action::Send(failed), _)) => resume_xml = failed,
                Ok((Action::Close, _)) if self.pending_credential_commit.is_some() => {
                    self.sasl_state = None;
                    return Ok(Action::Close);
                }
                Ok(_) => resume_xml = crate::xmpp::xml_util::sm_failed("undefined-condition"),
                Err(error)
                    if self.pending_credential_commit.is_some()
                        || crate::xmpp::auth_publication::credential_handoff_failed(&error) =>
                {
                    // An actual receipt was retained or its same-attempt
                    // ownership handoff failed. Neither that contradiction nor
                    // a compensation or post-commit staging failure can be
                    // converted into an ordinary inline-resume failure and
                    // must never fall through to the unbound FAST commit.
                    tracing::error!(
                        ?error,
                        user_id = %user.id,
                        "inline SM resumption failed with retained receipt or invalid ownership handoff; closing"
                    );
                    self.sm.resume_allowed = false;
                    self.sasl_state = None;
                    return Ok(Action::Close);
                }
                Err(error) => {
                    tracing::error!(?error, user_id = %user.id, "inline SM resumption backend failed");
                    resume_xml = crate::xmpp::xml_util::sm_failed("internal-server-error");
                }
            }
        }
        if bind_plan.is_none() && !unbound_state_committed {
            token_xml = match self
                .commit_sasl2_unbound_state(&fast_plan, &user, expected_auth_generation)
                .await?
            {
                Ok((token_xml, receipt, credential_attempt)) => {
                    self.retain_credential_commit(receipt, credential_attempt)?;
                    token_xml
                }
                Err(condition) => {
                    self.authenticated = None;
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml(condition, None)));
                }
            };
        }
        if bind_plan.is_some() {
            self.user_agent_epoch = None;
        }
        let mut bound_inner = String::new();
        let mut bound_xml = String::new();
        let authorization_identifier = if let Some((bind, resource, boundaries)) = bind_plan {
            let jid = match self
                .bind_resource_sasl2_internal(&user, resource, Some(&fast_plan), self.user_agent_id)
                .await
            {
                Ok(Ok((jid, issued))) => {
                    if let Some(issued) = issued {
                        token_xml = fast_token_xml(&issued);
                    }
                    jid
                }
                Ok(Err(super::misc::ResourceBindingFailure::CommittedRouteLost))
                    if self.pending_credential_commit.is_some() =>
                {
                    self.sasl_state = None;
                    return Ok(Action::Close);
                }
                Ok(Err(failure)) => {
                    tracing::warn!(
                        user_id = %user.id,
                        ?failure,
                        "Bind2 resource publication was rejected before credential commit"
                    );
                    self.authenticated = None;
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml(failure.sasl_condition(), None)));
                }
                Err(error) => {
                    tracing::error!(?error, user_id = %user.id, "Bind 2 resource registration failed");
                    self.authenticated = None;
                    self.sasl_state = None;
                    self.user_agent_id = None;
                    return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
                }
            };
            let (archive_start, archive_end) = boundaries;
            if archive_start.is_some() || archive_end.is_some() {
                let mut metadata = XmlElement::namespaced("metadata", "urn:xmpp:mam:2");
                if let Some(boundary) = archive_start {
                    metadata.push_child(
                        XmlElement::new("start").attr("id", boundary.id).attr(
                            "timestamp",
                            boundary
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                if let Some(boundary) = archive_end {
                    metadata.push_child(
                        XmlElement::new("end").attr("id", boundary.id).attr(
                            "timestamp",
                            boundary
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ),
                    );
                }
                bound_inner.push_str(&metadata.finish());
            }
            if bind.carbons {
                self.carbons
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            if let Some(active) = bind.csi_active {
                self.set_csi_active(active);
            }
            if let Some(sm) = bind.sm {
                match self.enable_sm_inline(sm.resume, sm.max).await {
                    Ok(enabled) => bound_inner.push_str(&enabled),
                    Err(condition) => bound_inner.push_str(
                        &XmlElement::namespaced("failed", "urn:xmpp:sm:3")
                            .child(
                                XmlElement::dynamic(condition)
                                    .expect("SM failure condition must be a valid QName")
                                    .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
                            )
                            .finish(),
                    ),
                }
            }
            self.bind2_mam_catchup = true;
            // This queue only duplicates MAM for Bind 2. Defer its deletion
            // until the resource is successfully active, and never convert a
            // post-acceptance cleanup outage into a false SASL failure.
            let replay_service = self.state.replay_service().clone();
            let user_id = user.id;
            let outbound = self.outbound.clone();
            let replay_full_jid = jid.clone();
            self.defer_after_transport("bind2-offline-replay", async move {
                super::replay::replay_bind2_offline(
                    replay_service,
                    outbound,
                    user_id,
                    replay_full_jid,
                )
                .await;
            })?;
            bound_xml = XmlElement::namespaced("bound", BIND2_NS)
                .validated_fragment(&bound_inner)?
                .finish();
            jid
        } else {
            format!("{}@{}", user.username, self.state.local_domain())
        };

        let success = sasl2_success_xml(
            sasl_data.as_ref().map(|data| data.as_slice()),
            &authorization_identifier,
            &[&resume_xml, &bound_xml, &token_xml],
        )?;
        if self.disconnect.is_cancelled() {
            self.sm.resume_allowed = false;
            self.sasl_state = None;
            return Ok(Action::Close);
        }
        if let Some(guard) = certificate_session.take() {
            self._certificate_session = Some(guard);
        }
        self.sasl_state = None;
        // The local/cluster route was reserved before the PostgreSQL commit,
        // but stanza delivery stays gated until the SASL2 success outcome is
        // fully constructed and no remaining inline operation can fail it.
        if self.registered_key.is_some() || self.pending_credential_commit.is_some() {
            self.auth_replies(vec![success, self.features()])
        } else {
            Ok(Action::SendMany(vec![success, self.features()]))
        }
    }

    async fn commit_sasl2_unbound_state(
        &self,
        plan: &crate::services::authentication::FastCommitPlan,
        user: &crate::services::authentication::AuthenticatedAccount,
        expected_auth_generation: i64,
    ) -> Result<
        std::result::Result<
            (
                String,
                crate::services::authentication::CredentialCommitReceipt,
                crate::xmpp::auth_publication::CredentialAttempt,
            ),
            &'static str,
        >,
    > {
        let credential_attempt = self.prepare_credential_attempt(
            crate::services::authentication::publication::CredentialKind::UnboundFast,
        )?;
        match self
            .state
            .authentication_service()
            .commit_fast_with_login_epoch_observed(
                user.id,
                expected_auth_generation,
                plan,
                // Without Bind2 there is no live installation session yet.
                // Allocate its replacement epoch later, in the RFC resource-bind
                // transaction, so a client that authenticates but never binds
                // cannot evict an established device session.
                None,
                self.connection_id,
                credential_attempt.prepared(),
            )
            .await
        {
            crate::services::authentication::AuthenticationResult::Authenticated(mut receipt) => {
                let token_xml = receipt
                    .take_issued_fast()
                    .as_ref()
                    .map(fast_token_xml)
                    .unwrap_or_default();
                Ok(Ok((token_xml, receipt, credential_attempt)))
            }
            crate::services::authentication::AuthenticationResult::Disabled
            | crate::services::authentication::AuthenticationResult::StaleGeneration
            | crate::services::authentication::AuthenticationResult::ExpiredCredentials
            | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                Ok(Err("credentials-expired"))
            }
            crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                Ok(Err("not-authorized"))
            }
            crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                self.state
                    .sasl2_authentication_telemetry()
                    .integrity_failed();
                tracing::error!(
                    user_id = %user.id,
                    "SASL2 credential commit integrity failure"
                );
                Ok(Err("temporary-auth-failure"))
            }
            crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
                self.state.sasl2_authentication_telemetry().backend_failed();
                tracing::error!(?error, "atomic SASL2 credential/session commit failed");
                Ok(Err("temporary-auth-failure"))
            }
        }
    }
}

#[cfg(test)]
mod tests;
