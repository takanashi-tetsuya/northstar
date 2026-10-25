//! Run legacy SASL authentication, certificate admission, abuse handling and authentication replies.

use super::*;

impl ProtocolSession {
    pub(in crate::xmpp) fn auth_replies(&mut self, replies: Vec<String>) -> Result<Action> {
        let control = replies
            .first()
            .context("auth action has no terminal control")?;
        let holder = self.seal_auth_control(control, false)?;
        Ok(Action::SendManyThenActivate(
            super::super::auth_publication::AuthReplies { replies, holder },
        ))
    }

    pub(in crate::xmpp) fn seal_resume_authentication(
        &mut self,
        payload: &mut ResumePayload,
    ) -> Result<()> {
        anyhow::ensure!(
            payload.activate_route && payload.auth_publication.is_none(),
            "resume authentication seal is not pending"
        );
        payload.auth_publication = Some(self.seal_auth_control(&payload.control, true)?);
        Ok(())
    }

    pub(super) fn external_certificate_session(
        &self,
    ) -> Result<crate::security::tls::CertificateSessionGuard> {
        self.state.tls_context().register_certificate_session(
            self.connection_id,
            crate::security::tls::CertificateSessionKind::C2s,
            self.client_certificate_chain.clone(),
            self.tls_generation,
            self.disconnect.clone(),
        )
    }

    pub(super) fn register_external_certificate_session(&mut self) -> Result<()> {
        if self._certificate_session.is_none() {
            self._certificate_session = Some(self.external_certificate_session()?);
        }
        Ok(())
    }

    pub(crate) fn begin_sasl_attempt(&mut self) -> Option<Action> {
        if !self
            .negotiation
            .reserve_sasl_attempt(MAX_SASL_ATTEMPTS_PER_STREAM)
        {
            self.sasl_state = None;
            self.sasl_scram_fence = None;
            self.legacy_sasl_awaiting_initial_response = false;
            self.sasl2_state = None;
            return Some(Action::CloseWith(stream_error("policy-violation")));
        }
        None
    }

    pub(crate) async fn authenticate(&mut self, root: Node<'_, '_>) -> Result<Action> {
        if !self.secure_transport {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "encryption-required",
            )));
        }

        if self.authenticated.is_some() || self.sasl_state.is_some() || self.sasl2_state.is_some() {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "malformed-request",
            )));
        }
        self.sasl_scram_fence = None;
        let (mechanism, payload) = match legacy_sasl_auth(root) {
            Some(request) => request,
            None => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "malformed-request",
                )));
            }
        };

        let mut sasl_mech: Box<dyn northstar_auth_core::SaslMechanism> = match mechanism.as_str() {
            "EXTERNAL" if !self.client_certificate_identities.is_empty() => {
                Box::new(northstar_auth_core::ExternalMechanism::new(
                    self.client_certificate_identities.clone(),
                ))
            }
            "PLAIN" => Box::new(northstar_auth_core::PlainMechanism::new(
                self.state.local_domain().to_owned(),
            )),
            "SCRAM-SHA-256" => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        northstar_auth_core::ScramSha256Mechanism::new_with_channel_binding_support(
                            self.state.local_domain().to_owned(),
                        ),
                    )
                } else {
                    Box::new(northstar_auth_core::ScramSha256Mechanism::new(
                        self.state.local_domain().to_owned(),
                    ))
                }
            }
            "SCRAM-SHA-256-PLUS" => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        "invalid-mechanism",
                    )));
                };
                Box::new(northstar_auth_core::ScramSha256Mechanism::new_plus(
                    self.state.local_domain().to_owned(),
                    bindings,
                ))
            }
            "SCRAM-SHA-1" if self.state.c2s_scram_sha1_enabled() => {
                if self.channel_bindings.is_some() {
                    Box::new(
                        northstar_auth_core::ScramSha256Mechanism::new_sha1_with_channel_binding_support(
                            self.state.local_domain().to_owned(),
                        ),
                    )
                } else {
                    Box::new(northstar_auth_core::ScramSha256Mechanism::new_sha1(
                        self.state.local_domain().to_owned(),
                    ))
                }
            }
            "SCRAM-SHA-1-PLUS" if self.state.c2s_scram_sha1_enabled() => {
                let Some(bindings) = self.channel_bindings.clone() else {
                    return Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        "invalid-mechanism",
                    )));
                };
                Box::new(northstar_auth_core::ScramSha256Mechanism::new_sha1_plus(
                    self.state.local_domain().to_owned(),
                    bindings,
                ))
            }
            _ => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    "invalid-mechanism",
                )));
            }
        };
        self.legacy_sasl_awaiting_initial_response = false;

        let Some(payload) = payload else {
            self.legacy_sasl_awaiting_initial_response = true;
            return self
                .process_sasl_step(
                    sasl_mech,
                    northstar_auth_core::SaslStep::Challenge(String::new()),
                )
                .await;
        };
        let payload = match sasl2::normalize_base64_payload(payload) {
            Ok(payload) => payload,
            Err(condition) => {
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    condition,
                )));
            }
        };
        let step = sasl_mech.initial_response(&payload);
        self.process_sasl_step(sasl_mech, step).await
    }

    pub(crate) async fn sasl_response(&mut self, root: Node<'_, '_>) -> Result<Action> {
        let Some(payload) = legacy_sasl_payload(root) else {
            self.sasl_state = None;
            self.sasl_scram_fence = None;
            self.legacy_sasl_awaiting_initial_response = false;
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "malformed-request",
            )));
        };

        if self.sasl_state.is_none() {
            return Ok(Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "not-authorized",
            )));
        }
        let payload = match sasl2::normalize_base64_payload(payload) {
            Ok(payload) => payload,
            Err(condition) => {
                self.sasl_state = None;
                self.sasl_scram_fence = None;
                self.legacy_sasl_awaiting_initial_response = false;
                return Ok(Action::Send(failure(
                    "urn:ietf:params:xml:ns:xmpp-sasl",
                    condition,
                )));
            }
        };
        let mut sasl_mech = self
            .sasl_state
            .take()
            .expect("SASL exchange presence checked above");

        let step = if std::mem::take(&mut self.legacy_sasl_awaiting_initial_response) {
            sasl_mech.initial_response(&payload)
        } else {
            sasl_mech.response(&payload)
        };
        self.process_sasl_step(sasl_mech, step).await
    }

    pub(crate) fn sasl_abort(&mut self, root: Node<'_, '_>) -> Action {
        if !legacy_sasl_payload(root).is_some_and(|payload| payload.trim().is_empty())
            || self.sasl_state.is_none()
            || self.sasl2_state.is_some()
        {
            self.sasl_state = None;
            self.sasl_scram_fence = None;
            self.legacy_sasl_awaiting_initial_response = false;
            return Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "malformed-request",
            ));
        }
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.legacy_sasl_awaiting_initial_response = false;
        Action::Send(failure("urn:ietf:params:xml:ns:xmpp-sasl", "aborted"))
    }

    pub(super) async fn process_sasl_step(
        &mut self,
        mut sasl_mech: Box<dyn northstar_auth_core::SaslMechanism>,
        mut step: northstar_auth_core::SaslStep,
    ) -> Result<Action> {
        if let northstar_auth_core::SaslStep::NeedsCredentials(ref username) = step {
            let algorithm = sasl_mech
                .scram_algorithm()
                .expect("only SCRAM mechanisms request stored credentials");
            match self.sasl_login_is_limited(username).await {
                Ok(true) => {
                    self.sasl_state = None;
                    return Ok(self.sasl_rate_limit_failure());
                }
                Ok(false) => {}
                Err(error) => {
                    return Ok(self.authentication_backend_failure(
                        sasl_mech.name(),
                        username,
                        "load login abuse state",
                        &error,
                    ));
                }
            }
            match self
                .state
                .authentication_service()
                .scram_credentials(username, algorithm)
                .await
            {
                crate::services::authentication::AuthenticationResult::Authenticated(creds) => {
                    let (fence, salt, iterations, stored_key, server_key) =
                        creds.into_mechanism_parts();
                    self.sasl_scram_fence = Some(Some(fence));
                    step = sasl_mech.provide_credentials(salt, iterations, stored_key, server_key);
                }
                crate::services::authentication::AuthenticationResult::UnknownCredentials
                | crate::services::authentication::AuthenticationResult::Disabled
                | crate::services::authentication::AuthenticationResult::StaleGeneration
                | crate::services::authentication::AuthenticationResult::ExpiredCredentials
                | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                    self.sasl_scram_fence = Some(None);
                    let (salt, iterations, stored_key, server_key) = self
                        .state
                        .authentication_service()
                        .dummy_scram_credentials(username, algorithm);
                    step = sasl_mech.provide_credentials(salt, iterations, stored_key, server_key);
                }
                crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                    self.state.c2s_authentication_telemetry().integrity_failed();
                    tracing::error!("credential integrity failure while loading SCRAM verifier");
                    return Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        "temporary-auth-failure",
                    )));
                }
                crate::services::authentication::AuthenticationResult::BackendFailure(error) => {
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
            northstar_auth_core::SaslStep::Success(username, mut data_opt) => {
                let authenticated_with_external = sasl_mech.name() == "EXTERNAL";
                self.legacy_sasl_awaiting_initial_response = false;
                match self.sasl_login_is_limited(&username).await {
                    Ok(true) => {
                        if let Some(password) =
                            data_opt.as_mut().filter(|_| sasl_mech.name() == "PLAIN")
                        {
                            password.zeroize();
                        }
                        self.sasl_state = None;
                        return Ok(self.sasl_rate_limit_failure());
                    }
                    Ok(false) => {}
                    Err(error) => {
                        if let Some(password) = data_opt.as_mut() {
                            password.zeroize();
                        }
                        return Ok(self.authentication_backend_failure(
                            sasl_mech.name(),
                            &username,
                            "load login abuse state",
                            &error,
                        ));
                    }
                }
                let legacy_stream_identity_mismatch = self.sasl2_state.is_none()
                    && self
                        .negotiation
                        .stream_from()
                        .is_some_and(|stream_from| stream_from != username);
                let user_result = if sasl_mech.name() == "PLAIN" {
                    let password = data_opt.take();
                    if let Some(password) = password.as_deref() {
                        self.state
                            .authentication_service()
                            .authenticate_plain(&username, password)
                            .await
                    } else {
                        crate::services::authentication::AuthenticationResult::UnknownCredentials
                    }
                } else if sasl_mech.name().starts_with("SCRAM-") {
                    let fence = self.sasl_scram_fence.take().flatten();
                    self.state
                        .authentication_service()
                        .complete_scram(&username, fence)
                        .await
                } else {
                    self.state
                        .authentication_service()
                        .authenticate_external(&username)
                        .await
                };
                let user_result = if legacy_stream_identity_mismatch
                    && matches!(
                        &user_result,
                        crate::services::authentication::AuthenticationResult::Authenticated(_)
                    ) {
                    crate::services::authentication::AuthenticationResult::UnknownCredentials
                } else {
                    user_result
                };
                let user = match user_result {
                    crate::services::authentication::AuthenticationResult::Authenticated(user) => {
                        Some(user)
                    }
                    crate::services::authentication::AuthenticationResult::UnknownCredentials => {
                        None
                    }
                    crate::services::authentication::AuthenticationResult::Disabled => {
                        tracing::debug!(%username, mechanism = sasl_mech.name(), "authentication rejected for a disabled account");
                        None
                    }
                    crate::services::authentication::AuthenticationResult::StaleGeneration
                    | crate::services::authentication::AuthenticationResult::ExpiredCredentials
                    | crate::services::authentication::AuthenticationResult::ReplayedCredentials => {
                        tracing::debug!(%username, mechanism = sasl_mech.name(), "authentication rejected by a stale credential fence");
                        None
                    }
                    crate::services::authentication::AuthenticationResult::IntegrityFailure => {
                        self.state.c2s_authentication_telemetry().integrity_failed();
                        tracing::error!(
                            "credential integrity failure while completing authentication"
                        );
                        return Ok(Action::Send(failure(
                            "urn:ietf:params:xml:ns:xmpp-sasl",
                            "temporary-auth-failure",
                        )));
                    }
                    crate::services::authentication::AuthenticationResult::BackendFailure(
                        error,
                    ) => {
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
                        self.sasl_scram_fence = None;
                        tracing::info!(username = %user.username, "XMPP authentication succeeded");
                        if self.sasl2_state.is_some() {
                            let additional_data = if sasl_mech.name().starts_with("SCRAM-") {
                                data_opt.map(|value| Zeroizing::new(value.as_bytes().to_vec()))
                            } else {
                                None
                            };
                            return self
                                .complete_sasl2(user, additional_data, authenticated_with_external)
                                .await;
                        }
                        if authenticated_with_external {
                            self.register_external_certificate_session()?;
                            if self.disconnect.is_cancelled() {
                                self.sasl_state = None;
                                return Ok(Action::Close);
                            }
                        }
                        self.authenticated = Some(user);
                        self.authenticated_at = Some(std::time::Instant::now());
                        // RFC 6120 legacy SASL success resets the stream. Bind
                        // and all other post-authentication traffic must wait
                        // for a fresh client stream opening. SASL2 is handled
                        // above and deliberately keeps the stream open.
                        self.negotiation.require_new_stream();
                        let mut success =
                            XmlElement::namespaced("success", "urn:ietf:params:xml:ns:xmpp-sasl");
                        if sasl_mech.name().starts_with("SCRAM-") {
                            if let Some(server_final) = data_opt {
                                use base64::Engine;
                                success = success.text(
                                    base64::engine::general_purpose::STANDARD
                                        .encode(server_final.as_bytes()),
                                );
                            }
                        }
                        let success_xml = success.finish();
                        Ok(Action::Send(success_xml))
                    }
                    None => {
                        self.sasl_scram_fence = None;
                        if let Err(error) = self.record_sasl_failure(Some(&username)).await {
                            return Ok(self.authentication_backend_failure(
                                sasl_mech.name(),
                                &username,
                                "record failed login",
                                &error,
                            ));
                        }
                        self.state
                            .c2s_authentication_telemetry()
                            .authentication_failed();
                        self.sasl_state = None;
                        self.legacy_sasl_awaiting_initial_response = false;
                        if self.sasl2_state.take().is_some() {
                            Ok(Action::Send(sasl2::failure_xml("not-authorized", None)))
                        } else {
                            Ok(Action::Send(failure(
                                "urn:ietf:params:xml:ns:xmpp-sasl",
                                "not-authorized",
                            )))
                        }
                    }
                }
            }
            northstar_auth_core::SaslStep::Challenge(challenge_data) => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(challenge_data);
                self.sasl_state = Some(sasl_mech);
                let namespace = if self.sasl2_state.is_some() {
                    sasl2::SASL2_NS
                } else {
                    "urn:ietf:params:xml:ns:xmpp-sasl"
                };
                Ok(Action::Send(
                    XmlElement::new("challenge")
                        .attr("xmlns", namespace)
                        .text(b64)
                        .finish(),
                ))
            }
            northstar_auth_core::SaslStep::Failure(err) => {
                tracing::warn!("SASL authentication failed: {}", err);
                let condition = err.condition();
                let attempted_username = sasl_mech.attempted_username().map(str::to_owned);
                if let Err(error) = self
                    .record_sasl_failure(attempted_username.as_deref())
                    .await
                {
                    return Ok(self.authentication_backend_failure(
                        sasl_mech.name(),
                        attempted_username.as_deref().unwrap_or("[unparsed]"),
                        "record malformed login",
                        &error,
                    ));
                }
                self.sasl_state = None;
                self.sasl_scram_fence = None;
                self.legacy_sasl_awaiting_initial_response = false;
                self.state
                    .c2s_authentication_telemetry()
                    .authentication_failed();
                if self.sasl2_state.take().is_some() {
                    Ok(Action::Send(sasl2::failure_xml(condition, None)))
                } else {
                    Ok(Action::Send(failure(
                        "urn:ietf:params:xml:ns:xmpp-sasl",
                        condition,
                    )))
                }
            }
            northstar_auth_core::SaslStep::NeedsCredentials(_) => {
                unreachable!("NeedsCredentials should be handled above")
            }
        }
    }

    pub(super) fn sasl_abuse_actors(&self, username: Option<&str>) -> Vec<String> {
        username
            .and_then(|username| crate::api::login_abuse_identity(self.peer_ip, username))
            .map(|(_, actors)| actors)
            .unwrap_or_else(|| vec![crate::api::ip_actor(self.peer_ip)])
    }

    pub(super) async fn sasl_login_is_limited(&self, username: &str) -> Result<bool> {
        let actors = self.sasl_abuse_actors(Some(username));
        self.state
            .sasl_login_abuse_service()
            .is_limited(&actors)
            .await
    }

    pub(super) async fn record_sasl_failure(&self, username: Option<&str>) -> Result<()> {
        let actors = self.sasl_abuse_actors(username);
        self.state
            .sasl_login_abuse_service()
            .record_failure(&actors)
            .await
    }

    pub(super) fn sasl_rate_limit_failure(&mut self) -> Action {
        self.legacy_sasl_awaiting_initial_response = false;
        self.sasl_scram_fence = None;
        self.state.c2s_authentication_telemetry().rate_limited();
        if self.sasl2_state.take().is_some() {
            Action::Send(sasl2::failure_xml(
                "temporary-auth-failure",
                Some("login rate limit active; retry after cooldown"),
            ))
        } else {
            Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "temporary-auth-failure",
            ))
        }
    }

    pub(super) fn authentication_backend_failure(
        &mut self,
        mechanism: &str,
        username: &str,
        operation: &str,
        error: &anyhow::Error,
    ) -> Action {
        self.legacy_sasl_awaiting_initial_response = false;
        self.sasl_state = None;
        self.sasl_scram_fence = None;
        self.state.c2s_authentication_telemetry().backend_failed();
        tracing::error!(
            %mechanism,
            %username,
            %operation,
            integrity_failure = northstar_auth_core::is_password_verifier_integrity_error(error),
            ?error,
            "XMPP authentication backend failed"
        );
        if self.sasl2_state.take().is_some() {
            Action::Send(sasl2::failure_xml("temporary-auth-failure", None))
        } else {
            Action::Send(failure(
                "urn:ietf:params:xml:ns:xmpp-sasl",
                "temporary-auth-failure",
            ))
        }
    }
}

pub(super) fn legacy_sasl_auth(root: Node<'_, '_>) -> Option<(String, Option<Zeroizing<String>>)> {
    if root.tag_name().name() != "auth"
        || root.tag_name().namespace() != Some("urn:ietf:params:xml:ns:xmpp-sasl")
        || root
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "mechanism")
        || root.children().any(|child| child.is_element())
    {
        return None;
    }
    let mechanism = root.attribute("mechanism")?;
    let text_nodes = root
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect::<Vec<_>>();
    let payload = (!text_nodes.is_empty()).then(|| Zeroizing::new(text_nodes.concat()));
    if mechanism.is_empty()
        || mechanism.len() > 128
        || payload
            .as_ref()
            .is_some_and(|payload| payload.len() > 65_536)
    {
        return None;
    }
    Some((mechanism.to_owned(), payload))
}

pub(super) fn legacy_sasl_payload(root: Node<'_, '_>) -> Option<Zeroizing<String>> {
    if root.attributes().len() != 0 || root.children().any(|child| child.is_element()) {
        return None;
    }
    let payload = root
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .collect::<String>();
    (payload.len() <= 65_536).then(|| Zeroizing::new(payload))
}
