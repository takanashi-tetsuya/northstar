//! Render authentication features and handle FAST proofs, rotation planning, and mechanism availability.

use super::*;

pub(crate) fn authentication_feature_xml(session: &ProtocolSession) -> String {
    let fast_policy = session.state.sasl2_fast_token_policy();
    let mut mechanism_names = Vec::with_capacity(6);
    if !session.client_certificate_identities.is_empty() {
        mechanism_names.push("EXTERNAL");
    }
    if session.channel_bindings.is_some() {
        mechanism_names.push("SCRAM-SHA-256-PLUS");
    }
    mechanism_names.push("SCRAM-SHA-256");
    if session.state.c2s_scram_sha1_enabled() {
        if session.channel_bindings.is_some() {
            mechanism_names.push("SCRAM-SHA-1-PLUS");
        }
        mechanism_names.push("SCRAM-SHA-1");
    }
    mechanism_names.push("PLAIN");

    let mut fast_mechanism_names = Vec::with_capacity(3);
    if fast_policy.enabled {
        if let Some(bindings) = session.channel_bindings.as_ref() {
            if bindings.get("tls-server-end-point").is_some() {
                fast_mechanism_names.push("HT-SHA-256-ENDP");
            }
            if bindings.get("tls-exporter").is_some() {
                fast_mechanism_names.push("HT-SHA-256-EXPR");
            }
        }
        fast_mechanism_names.push("HT-SHA-256-NONE");
    }

    let mut authentication = XmlElement::namespaced("authentication", SASL2_NS);
    for mechanism in mechanism_names {
        authentication.push_child(XmlElement::new("mechanism").text(mechanism));
    }
    let mut bind_inline = XmlElement::new("inline")
        .child(XmlElement::new("feature").attr("var", "urn:xmpp:carbons:2"));
    if session
        .state
        .xmpp_extension_enabled(northstar_xep_0352::XEP_ID)
    {
        bind_inline
            .push_child(XmlElement::new("feature").attr("var", northstar_xep_0352::NAMESPACE));
    }
    if session
        .state
        .xmpp_extension_enabled(northstar_xep_0198::XEP_ID)
    {
        bind_inline
            .push_child(XmlElement::new("feature").attr("var", northstar_xep_0198::NAMESPACE));
    }
    let mut inline = XmlElement::new("inline");
    if session
        .state
        .xmpp_extension_enabled(northstar_xep_0198::XEP_ID)
    {
        inline.push_child(XmlElement::namespaced("sm", northstar_xep_0198::NAMESPACE));
    }
    inline.push_child(XmlElement::namespaced("bind", BIND2_NS).child(bind_inline));
    if fast_policy.enabled {
        let mut fast = XmlElement::namespaced("fast", FAST_NS);
        for mechanism in fast_mechanism_names {
            fast.push_child(XmlElement::new("mechanism").text(mechanism));
        }
        inline.push_child(fast);
    }
    authentication.child(inline).finish()
}

impl ProtocolSession {
    pub(super) async fn authenticate_fast(&mut self, mut request: Sasl2Request) -> Result<Action> {
        use base64::Engine;
        let Some(fast) = request.fast.clone() else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        let Some(user_agent_id) = request.user_agent_id else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        let Some(stream_username) = self.negotiation.stream_from() else {
            return Ok(Action::Send(failure_xml("not-authorized", None)));
        };
        let Some(initial_response) = request.initial_response.as_deref() else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        let decoded = match base64::engine::general_purpose::STANDARD.decode(initial_response) {
            Ok(decoded) => Zeroizing::new(decoded),
            Err(_) => return Ok(Action::Send(failure_xml("incorrect-encoding", None))),
        };
        let Some(separator) = decoded.iter().position(|byte| *byte == 0) else {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        };
        if decoded[separator + 1..].len() != 32 {
            return Ok(Action::Send(failure_xml("malformed-request", None)));
        }
        let authcid = match std::str::from_utf8(&decoded[..separator])
            .ok()
            .and_then(|value| auth::normalize_username(value).ok())
        {
            Some(authcid) if authcid == stream_username => authcid,
            _ => return Ok(Action::Send(failure_xml("not-authorized", None))),
        };
        match self.sasl_login_is_limited(&authcid).await {
            Ok(true) => return Ok(self.sasl_rate_limit_failure()),
            Ok(false) => {}
            Err(error) => {
                return Ok(self.authentication_backend_failure(
                    &request.mechanism,
                    &authcid,
                    "load FAST login abuse state",
                    &error,
                ));
            }
        }
        let channel_binding: &[u8] = match request.mechanism.as_str() {
            "HT-SHA-256-NONE" => &[],
            mechanism => match self
                .channel_bindings
                .as_ref()
                .and_then(|bindings| bindings.for_fast_mechanism(mechanism))
            {
                Some(binding) => binding,
                None => return Ok(Action::Send(failure_xml("invalid-mechanism", None))),
            },
        };
        let verified = self
            .state
            .authentication_service()
            .authenticate_fast(
                northstar_auth_application::authentication::FastProofRequest {
                    username: &authcid,
                    device_id: user_agent_id,
                    mechanism: &request.mechanism,
                    counter: fast.count,
                    initiator_proof: &decoded[separator + 1..],
                    channel_binding,
                    invalidate: fast.invalidate,
                    rotate_within_days: self.state.sasl2_fast_token_policy().rotation_days,
                },
            )
            .await;
        let (
            user,
            responder,
            should_rotate,
            fast_token_id,
            fast_token_was_new,
            authenticated_generation,
            strong_auth_at,
            chain_expires_at,
        ) = match verified {
            northstar_auth_application::authentication::AuthenticationResult::Authenticated(verified) => {
                verified.into_parts()
            }
            northstar_auth_application::authentication::AuthenticationResult::UnknownCredentials
            | northstar_auth_application::authentication::AuthenticationResult::Disabled
            | northstar_auth_application::authentication::AuthenticationResult::ReplayedCredentials => {
                if let Err(error) = self.record_sasl_failure(Some(&authcid)).await {
                    return Ok(self.authentication_backend_failure(
                        &request.mechanism,
                        &authcid,
                        "record invalid FAST login",
                        &error,
                    ));
                }
                return Ok(Action::Send(failure_xml("not-authorized", None)));
            }
            northstar_auth_application::authentication::AuthenticationResult::StaleGeneration
            | northstar_auth_application::authentication::AuthenticationResult::ExpiredCredentials => {
                return Ok(Action::Send(failure_xml("credentials-expired", None)));
            }
            northstar_auth_application::authentication::AuthenticationResult::BackendFailure(error) => {
                return Ok(self.authentication_backend_failure(
                    &request.mechanism,
                    &authcid,
                    "verify FAST token",
                    &error,
                ));
            }
            northstar_auth_application::authentication::AuthenticationResult::IntegrityFailure => {
                self.state
                    .sasl2_authentication_telemetry()
                    .integrity_failed();
                tracing::error!(
                    device_id = %user_agent_id,
                    mechanism = %request.mechanism,
                    "FAST credential derivation integrity failure"
                );
                return Ok(Action::Send(failure_xml("temporary-auth-failure", None)));
            }
        };
        request.initial_response = None;
        self.sasl2_state = Some(Sasl2Context {
            request,
            fast_should_rotate: should_rotate,
            awaiting_initial_response: false,
            fast_token_id: Some(fast_token_id),
            fast_token_was_new,
            fast_invalidate: fast.invalidate,
            authenticated_generation: Some(authenticated_generation),
            inherited_fast_chain: Some((strong_auth_at, chain_expires_at)),
        });
        self.complete_sasl2(user, Some(responder), false).await
    }

    /// Commit FAST rotation/invalidation and any mandatory replacement token
    /// before Bind 2 publishes a routable resource. The proof counter is
    /// consumed during verification; every other credential side effect is
    /// staged here while authentication is still externally invisible.
    pub(super) fn sasl2_fast_commit_plan(
        &self,
        context: &Sasl2Context,
    ) -> northstar_auth_application::authentication::FastCommitPlan {
        let fast_policy = self.state.sasl2_fast_token_policy();
        let mechanism = if context.fast_should_rotate {
            context
                .request
                .request_token
                .as_deref()
                .or(Some(context.request.mechanism.as_str()))
        } else {
            context.request.request_token.as_deref()
        };
        let issue = mechanism
            .filter(|mechanism| self.fast_mechanism_available(mechanism))
            .zip(context.request.user_agent_id)
            .map(|(mechanism, device_id)| {
                northstar_auth_application::authentication::FastTokenIssue {
                    device_id,
                    mechanism: mechanism.to_owned(),
                    ttl_days: fast_policy.ttl_days,
                    strong_reauth_max_days: fast_policy.strong_reauth_max_days,
                    inherited_chain: context.inherited_fast_chain,
                }
            });
        northstar_auth_application::authentication::FastCommitPlan {
            token_id: context.fast_token_id,
            token_was_new: context.fast_token_was_new,
            invalidate: context.fast_invalidate,
            issue,
        }
    }

    pub(super) fn fast_mechanism_available(&self, mechanism: &str) -> bool {
        if !self.state.sasl2_fast_token_policy().enabled {
            return false;
        }
        match mechanism {
            "HT-SHA-256-NONE" => true,
            mechanism => self
                .channel_bindings
                .as_ref()
                .and_then(|bindings| bindings.for_fast_mechanism(mechanism))
                .is_some(),
        }
    }
}
