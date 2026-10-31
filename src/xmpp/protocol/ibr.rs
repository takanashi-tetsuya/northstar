use super::{Action, ProtocolSession};
use crate::services::xml_util::*;
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use northstar_abuse_policy::{AbuseAction, PowChallenge, PowIntent, WorkRequirement};
use northstar_auth_application::account::{RegistrationOutcome, RegistrationRequest};
use northstar_auth_xmpp::ibr::*;
use roxmltree::Node;

enum IbrCompletion {
    Created(String),
    Retry(String),
    Failed(&'static str),
}

impl ProtocolSession {
    pub(crate) async fn handle_ibr_register(&mut self, node: Node<'_, '_>) -> Result<Action> {
        if !self.registration_transport_allowed() {
            return Ok(Action::CloseWith(stream_error("not-authorized")));
        }
        if !valid_flow_selection(node) {
            return Ok(Action::CloseWith(invalid_flow_stream_error()));
        }
        if self.ibr_flow.is_some() {
            return Ok(Action::CloseWith(stream_error("unexpected-request")));
        }
        self.ibr_flow = Some(IbrFlowTransport::Stream);
        self.ibr_pow_enabled = pow_flow_selected(node);
        Ok(Action::Send(self.ibr_challenge(None, None)))
    }

    pub(crate) async fn handle_ibr_response(&mut self, node: Node<'_, '_>) -> Result<Action> {
        if self.ibr_flow != Some(IbrFlowTransport::Stream) || !self.registration_transport_allowed()
        {
            self.ibr_flow = None;
            return Ok(Action::CloseWith(stream_error("unexpected-request")));
        }
        self.ibr_flow = None;
        let submission = match parse_response(node) {
            Ok(submission) => submission,
            Err(_) => return Ok(Action::Send(ibr_cancel())),
        };
        match self.complete_ibr_registration(submission).await {
            IbrCompletion::Created(username) => {
                self.negotiation.mark_registration_completed();
                Ok(Action::Send(ibr_success(
                    &username,
                    self.state.local_domain(),
                )))
            }
            IbrCompletion::Retry(challenge) => {
                self.ibr_flow = Some(IbrFlowTransport::Stream);
                Ok(Action::Send(challenge))
            }
            IbrCompletion::Failed(condition) => {
                tracing::debug!(condition, "XEP-0389 stream registration cancelled");
                Ok(Action::Send(ibr_cancel()))
            }
        }
    }

    pub(crate) fn handle_ibr_cancel(&mut self, node: Node<'_, '_>) -> Action {
        if !valid_empty_element(node, "cancel", IBR2_NS)
            || self.ibr_flow != Some(IbrFlowTransport::Stream)
        {
            return Action::CloseWith(stream_error("unexpected-request"));
        }
        self.ibr_flow = None;
        Action::None
    }

    pub(crate) fn ibr_flows_iq(&self, id: &str, node: Node<'_, '_>) -> Action {
        if !valid_empty_element(node, "register", IBR2_NS) {
            return Action::Send(iq_error(id, "bad-request"));
        }
        if !self.secure_transport {
            return Action::Send(iq_error(id, "not-allowed"));
        }
        let payload = if self.registration_transport_allowed() {
            ibr_flow_list()
        } else {
            ibr_empty_flow_list()
        };
        Action::Send(iq_result(id, &payload))
    }

    pub(crate) async fn select_ibr_flow_iq(
        &mut self,
        id: &str,
        node: Node<'_, '_>,
    ) -> Result<Action> {
        if !self.secure_transport {
            return Ok(Action::Send(iq_error(id, "not-allowed")));
        }
        if !self.registration_transport_allowed() {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        }
        if !valid_flow_selection(node) {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        }
        if self.ibr_flow.is_some() {
            return Ok(Action::Send(iq_error(id, "unexpected-request")));
        }
        self.ibr_flow = Some(IbrFlowTransport::Iq);
        self.ibr_pow_enabled = pow_flow_selected(node);
        Ok(Action::Send(iq_result(id, &self.ibr_challenge(None, None))))
    }

    pub(crate) async fn handle_ibr_response_iq(
        &mut self,
        id: &str,
        node: Node<'_, '_>,
    ) -> Result<Action> {
        if self.ibr_flow != Some(IbrFlowTransport::Iq) || !self.registration_transport_allowed() {
            self.ibr_flow = None;
            return Ok(Action::Send(iq_error(id, "unexpected-request")));
        }
        self.ibr_flow = None;
        let submission = match parse_response(node) {
            Ok(submission) => submission,
            Err(_) => return Ok(Action::Send(iq_error(id, "bad-request"))),
        };
        match self.complete_ibr_registration(submission).await {
            IbrCompletion::Created(username) => {
                self.negotiation.mark_registration_completed();
                let success_id = format!("ibr-success-{}", uuid::Uuid::new_v4());
                let success_payload = ibr_success(&username, self.state.local_domain());
                let success = XmlElement::namespaced("iq", "jabber:client")
                    .attr("type", "set")
                    .attr("id", &success_id)
                    .validated_fragment(&success_payload)?
                    .finish();
                Ok(Action::SendMany(vec![iq_result(id, ""), success]))
            }
            IbrCompletion::Retry(challenge) => {
                self.ibr_flow = Some(IbrFlowTransport::Iq);
                Ok(Action::Send(iq_result(id, &challenge)))
            }
            IbrCompletion::Failed(condition) => Ok(Action::Send(iq_error(id, condition))),
        }
    }

    pub(crate) fn handle_ibr_cancel_iq(&mut self, id: &str, node: Node<'_, '_>) -> Action {
        if !valid_empty_element(node, "cancel", IBR2_NS)
            || self.ibr_flow != Some(IbrFlowTransport::Iq)
        {
            return Action::Send(iq_error(id, "unexpected-request"));
        }
        self.ibr_flow = None;
        Action::Send(iq_result(id, ""))
    }

    fn registration_transport_allowed(&self) -> bool {
        self.secure_transport
            && self.authenticated.is_none()
            && !self.negotiation.registration_completed()
            && !self.state.registration_is_closed()
    }

    fn ibr_challenge(
        &self,
        challenge: Option<&PowChallenge>,
        wait: Option<&WorkRequirement>,
    ) -> String {
        let invitation = if self.state.registration_requires_invitation() {
            XmlElement::new("field")
                .attr("var", "urn:northstar:invite:token")
                .attr("type", "text-private")
                .attr("label", "Invitation token")
                .child(XmlElement::new("required"))
        } else {
            XmlElement::new("field")
                .attr("var", "urn:northstar:invite:token")
                .attr("type", "text-private")
                .attr("label", "Invitation token (optional)")
        };
        let instructions = if challenge.is_some() {
            "The previous attempt reached a metered step. Retry the exact same username, password and invitation, then solve the body-bound proof-of-work challenge.".to_owned()
        } else if let Some(requirement) = wait {
            format!(
                "Too many registration attempts. Wait at least {} seconds before trying again.",
                super::misc::registration_retry_seconds(requirement)
            )
        } else {
            "Choose a username and a password of at least 10 UTF-8 octets.".to_owned()
        };
        let mut form = XmlElement::namespaced("x", "jabber:x:data")
            .attr("type", "form")
            .child(XmlElement::new("title").text("Account Registration"))
            .child(XmlElement::new("instructions").text(instructions))
            .child(xdata_value_field("FORM_TYPE", "hidden", IBR2_NS))
            .child(
                XmlElement::new("field")
                    .attr("var", "username")
                    .attr("type", "text-single")
                    .attr("label", "Username")
                    .child(XmlElement::new("required")),
            )
            .child(
                XmlElement::new("field")
                    .attr("var", "password")
                    .attr("type", "text-private")
                    .attr("label", "Password")
                    .child(XmlElement::new("required")),
            )
            .child(invitation);
        if let Some(challenge) = challenge {
            for (variable, kind, value) in [
                (
                    "urn:northstar:pow:challenge-id",
                    "hidden",
                    challenge.challenge_id.to_string(),
                ),
                (
                    "urn:northstar:pow:version",
                    "fixed",
                    challenge.version.to_string(),
                ),
                (
                    "urn:northstar:pow:prefix",
                    "fixed",
                    challenge.prefix.clone(),
                ),
                (
                    "urn:northstar:pow:work-factor",
                    "fixed",
                    challenge.requirement.work_factor.to_string(),
                ),
                (
                    "urn:northstar:pow:max-work-factor",
                    "fixed",
                    challenge.requirement.max_work_factor.to_string(),
                ),
                (
                    "urn:northstar:pow:hard-wait-seconds",
                    "fixed",
                    challenge.requirement.hard_wait_seconds.to_string(),
                ),
                (
                    "urn:northstar:pow:max-device-seconds",
                    "fixed",
                    challenge
                        .requirement
                        .approximate_max_device_seconds
                        .to_string(),
                ),
            ] {
                form.push_child(xdata_value_field(variable, kind, value));
            }
            if let Some(intent) = challenge.intent.as_ref() {
                form.push_child(xdata_value_field(
                    "urn:northstar:pow:intent-body-sha256",
                    "fixed",
                    intent.body_sha256.clone(),
                ));
            }
            form.push_child(
                XmlElement::new("field")
                    .attr("var", "urn:northstar:pow:nonce")
                    .attr("type", "text-single")
                    .attr("label", "Proof-of-work nonce")
                    .child(XmlElement::new("required")),
            );
        }
        XmlElement::namespaced("challenge", IBR2_NS)
            .attr(
                "type",
                if challenge.is_some() {
                    POW_NS
                } else {
                    "jabber:x:data"
                },
            )
            .child(form)
            .finish()
    }

    async fn complete_ibr_registration(&self, submission: RegistrationSubmission) -> IbrCompletion {
        if !self.ibr_pow_enabled && submission.proof.is_some() {
            return IbrCompletion::Failed("bad-request");
        }
        if northstar_auth_core::normalize_username(&submission.username).is_err()
            || northstar_auth_core::validate_password(&submission.password).is_err()
        {
            return IbrCompletion::Failed("not-acceptable");
        }
        let intent = PowIntent::xmpp_registration(
            &submission.username,
            &submission.password,
            submission.invitation_token.as_deref(),
        );
        let actors = vec![format!("ip:{}", self.peer_ip)];
        let subject = format!("registration:{}", self.peer_ip);
        let outcome = match self
            .state
            .account_service()
            .register(RegistrationRequest {
                username: &submission.username,
                password: &submission.password,
                invitation_token: submission.invitation_token.as_deref(),
                proof: submission.proof.as_ref(),
                intent: &intent,
                subject: &subject,
                actors: &actors,
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(?error, "XEP-0389 registration backend failed");
                self.state.registration_telemetry().backend_failed();
                return IbrCompletion::Failed("internal-server-error");
            }
        };
        match outcome {
            RegistrationOutcome::Created(user) => {
                self.state.registration_telemetry().registered();
                IbrCompletion::Created(user.username)
            }
            RegistrationOutcome::AbuseDenied(requirement) => {
                self.state.registration_telemetry().rate_limited();
                if !self.ibr_pow_enabled {
                    return IbrCompletion::Retry(self.ibr_challenge(None, Some(&requirement)));
                }
                match self
                    .state
                    .challenge_issue_service()
                    .issue(
                        northstar_abuse_application::challenge::ChallengeIssueRequest {
                            action: AbuseAction::Registration,
                            subject: &subject,
                            actors: &actors,
                            intent: Some(&intent),
                        },
                    )
                    .await
                {
                    Ok(challenge) => {
                        IbrCompletion::Retry(self.ibr_challenge(Some(&challenge), None))
                    }
                    Err(error) => {
                        tracing::warn!(?error, "XEP-0389 v2 challenge issuance failed");
                        self.state.registration_telemetry().backend_failed();
                        IbrCompletion::Failed("resource-constraint")
                    }
                }
            }
            RegistrationOutcome::InvalidUsername | RegistrationOutcome::InvitationRejected => {
                IbrCompletion::Failed("not-acceptable")
            }
            RegistrationOutcome::UsernameTaken => IbrCompletion::Failed("conflict"),
            RegistrationOutcome::RateLimited => IbrCompletion::Failed("resource-constraint"),
            RegistrationOutcome::CapacityExhausted => {
                self.state.registration_telemetry().capacity_rejected();
                IbrCompletion::Failed("resource-constraint")
            }
            RegistrationOutcome::PasswordWorkOverloaded => {
                IbrCompletion::Failed("resource-constraint")
            }
            RegistrationOutcome::Closed => IbrCompletion::Failed("not-allowed"),
        }
    }
}
