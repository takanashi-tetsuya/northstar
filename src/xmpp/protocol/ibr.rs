use super::{Action, ProtocolSession};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use crate::{
    abuse::{AbuseAction, PowChallenge, PowIntent, PowProof},
    services::account::{RegistrationOutcome, RegistrationRequest},
};
use anyhow::Result;
use roxmltree::Node;
use std::sync::atomic::Ordering;
use zeroize::Zeroize;

pub(crate) const IBR2_NS: &str = "urn:xmpp:register:0";
const FLOW_ID: &str = "northstar";
const INVITATION_TOKEN_MAX_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IbrFlowTransport {
    Stream,
    Iq,
}

struct RegistrationSubmission {
    username: String,
    password: String,
    invitation_token: Option<String>,
    proof: Option<PowProof>,
}

enum IbrCompletion {
    Created(String),
    Retry(String),
    Failed(&'static str),
}

impl Drop for RegistrationSubmission {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(invitation_token) = self.invitation_token.as_mut() {
            invitation_token.zeroize();
        }
    }
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
        Ok(Action::Send(self.ibr_challenge(None)))
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
            Err(()) => return Ok(Action::Send(ibr_cancel())),
        };
        match self.complete_ibr_registration(submission).await {
            IbrCompletion::Created(username) => {
                self.registration_completed = true;
                Ok(Action::Send(ibr_success(
                    &username,
                    &self.state.config.domain,
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
        Ok(Action::Send(iq_result(id, &self.ibr_challenge(None))))
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
            Err(()) => return Ok(Action::Send(iq_error(id, "bad-request"))),
        };
        match self.complete_ibr_registration(submission).await {
            IbrCompletion::Created(username) => {
                self.registration_completed = true;
                let success_id = format!("ibr-success-{}", uuid::Uuid::new_v4());
                let success_payload = ibr_success(&username, &self.state.config.domain);
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
            && !self.registration_completed
            && !self.state.registration_is_closed()
    }

    fn ibr_challenge(&self, challenge: Option<&PowChallenge>) -> String {
        let invitation = if self.state.config.invitation_required {
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
            "The previous attempt reached a metered step. Retry the exact same username, password and invitation, then solve the body-bound proof-of-work challenge."
        } else {
            "Choose a username and a password of at least 10 UTF-8 octets. A normal registration needs no proof of work; a metered retry returns a body-bound challenge."
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
            .attr("type", "jabber:x:data")
            .child(form)
            .finish()
    }

    async fn complete_ibr_registration(&self, submission: RegistrationSubmission) -> IbrCompletion {
        if crate::auth::normalize_username(&submission.username).is_err()
            || crate::auth::validate_password(&submission.password).is_err()
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
            .register(
                &self.state.abuse,
                RegistrationRequest {
                    username: &submission.username,
                    password: &submission.password,
                    invitation_token: submission.invitation_token.as_deref(),
                    proof: submission.proof.as_ref(),
                    intent: &intent,
                    subject: &subject,
                    actors: &actors,
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(?error, "XEP-0389 registration backend failed");
                self.state
                    .metrics
                    .anti_abuse_backend_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return IbrCompletion::Failed("internal-server-error");
            }
        };
        match outcome {
            RegistrationOutcome::Created(user) => {
                self.state
                    .metrics
                    .registrations_total
                    .fetch_add(1, Ordering::Relaxed);
                IbrCompletion::Created(user.username)
            }
            RegistrationOutcome::AbuseDenied(_) => {
                self.state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
                match self
                    .state
                    .abuse
                    .issue_v2(AbuseAction::Registration, &subject, &actors, &intent)
                    .await
                {
                    Ok(challenge) => IbrCompletion::Retry(self.ibr_challenge(Some(&challenge))),
                    Err(error) => {
                        tracing::warn!(?error, "XEP-0389 v2 challenge issuance failed");
                        self.state
                            .metrics
                            .anti_abuse_backend_failures_total
                            .fetch_add(1, Ordering::Relaxed);
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
                self.state
                    .metrics
                    .capacity_reservations_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                IbrCompletion::Failed("resource-constraint")
            }
            RegistrationOutcome::PasswordWorkOverloaded => {
                IbrCompletion::Failed("resource-constraint")
            }
            RegistrationOutcome::Closed => IbrCompletion::Failed("not-allowed"),
        }
    }
}

pub(crate) fn ibr_stream_feature() -> String {
    XmlElement::namespaced("register", IBR2_NS)
        .child(
            XmlElement::new("flow")
                .attr("id", "northstar")
                .child(
                    XmlElement::new("name")
                        .attr("xml:lang", "en")
                        .text("Account registration"),
                )
                .child(XmlElement::new("challenge").attr("type", "jabber:x:data")),
        )
        .finish()
}

fn ibr_flow_list() -> String {
    ibr_stream_feature()
}

fn ibr_empty_flow_list() -> String {
    XmlElement::namespaced("register", IBR2_NS).finish()
}

fn parse_response(node: Node<'_, '_>) -> std::result::Result<RegistrationSubmission, ()> {
    if node.tag_name().name() != "response"
        || node.tag_name().namespace() != Some(IBR2_NS)
        || node.attributes().len() != 0
        || node.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(());
    }
    let children = node
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if children.len() != 1 {
        return Err(());
    }
    let fields = strict_xdata_submit(
        children[0],
        IBR2_NS,
        &[
            "username",
            "password",
            "urn:northstar:invite:token",
            "urn:northstar:pow:challenge-id",
            "urn:northstar:pow:version",
            "urn:northstar:pow:prefix",
            "urn:northstar:pow:work-factor",
            "urn:northstar:pow:max-work-factor",
            "urn:northstar:pow:hard-wait-seconds",
            "urn:northstar:pow:max-device-seconds",
            "urn:northstar:pow:intent-body-sha256",
            "urn:northstar:pow:nonce",
        ],
    )?;
    let username = fields.get("username").cloned().ok_or(())?;
    let password = fields.get("password").cloned().ok_or(())?;
    let invitation_token = fields
        .get("urn:northstar:invite:token")
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned());
    if invitation_token
        .as_ref()
        .is_some_and(|value| value.len() > INVITATION_TOKEN_MAX_BYTES)
    {
        return Err(());
    }
    let challenge_id = fields
        .get("urn:northstar:pow:challenge-id")
        .map(|value| value.parse::<uuid::Uuid>())
        .transpose()
        .map_err(|_| ())?;
    let proof = match (challenge_id, fields.get("urn:northstar:pow:nonce")) {
        (Some(challenge_id), Some(nonce)) if !nonce.is_empty() => {
            if nonce.len() > 64 || !nonce.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(());
            }
            Some(PowProof {
                challenge_id,
                nonce: nonce.to_owned(),
            })
        }
        (Some(_), Some(_)) | (Some(_), None) | (None, None) => None,
        (None, Some(_)) => return Err(()),
    };
    Ok(RegistrationSubmission {
        username,
        password,
        invitation_token,
        proof,
    })
}

fn valid_flow_selection(node: Node<'_, '_>) -> bool {
    if node.tag_name().name() != "register"
        || node.tag_name().namespace() != Some(IBR2_NS)
        || node.attributes().len() != 0
        || node.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    let children = node
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    let [flow] = children.as_slice() else {
        return false;
    };
    flow.tag_name().name() == "flow"
        && flow.tag_name().namespace() == Some(IBR2_NS)
        && flow.attribute("id") == Some(FLOW_ID)
        && flow.attributes().all(|attribute| attribute.name() == "id")
        && !flow.children().any(|child| child.is_element())
        && flow.text().is_none_or(|text| text.trim().is_empty())
}

fn valid_empty_element(node: Node<'_, '_>, name: &str, namespace: &str) -> bool {
    node.tag_name().name() == name
        && node.tag_name().namespace() == Some(namespace)
        && node.attributes().len() == 0
        && !node.children().any(|child| child.is_element())
        && node.text().is_none_or(|text| text.trim().is_empty())
}

fn invalid_flow_stream_error() -> String {
    crate::xmpp::xml_builder::XmlElement::new("stream:error")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .child(crate::xmpp::xml_builder::XmlElement::namespaced(
            "undefined-condition",
            "urn:ietf:params:xml:ns:xmpp-streams",
        ))
        .child(crate::xmpp::xml_builder::XmlElement::namespaced(
            "invalid-flow",
            IBR2_NS,
        ))
        .finish()
}

fn ibr_success(username: &str, domain: &str) -> String {
    crate::xmpp::xml_builder::XmlElement::namespaced("success", IBR2_NS)
        .child(
            crate::xmpp::xml_builder::XmlElement::new("jid").text(format!("{username}@{domain}")),
        )
        .child(crate::xmpp::xml_builder::XmlElement::new("username").text(username))
        .finish()
}

fn ibr_cancel() -> String {
    crate::xmpp::xml_builder::XmlElement::namespaced("cancel", IBR2_NS).finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn flow_selection_is_exact() {
        let valid = Document::parse(
            "<register xmlns='urn:xmpp:register:0'><flow id='northstar'/></register>",
        )
        .unwrap();
        assert!(valid_flow_selection(valid.root_element()));
        for xml in [
            "<register xmlns='urn:xmpp:register:0'/>",
            "<register xmlns='urn:xmpp:register:0'><flow id='other'/></register>",
            "<register xmlns='urn:xmpp:register:0'><flow id='northstar'/><flow id='northstar'/></register>",
            "<register xmlns='urn:xmpp:register:0'><flow id='northstar'><name>x</name></flow></register>",
        ] {
            let doc = Document::parse(xml).unwrap();
            assert!(!valid_flow_selection(doc.root_element()), "{xml}");
        }
    }

    #[test]
    fn response_rejects_ambiguous_values() {
        let valid = "<response xmlns='urn:xmpp:register:0'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:register:0</value></field><field var='username'><value>alice</value></field><field var='password'><value>correct-horse-battery</value></field></x></response>";
        let doc = Document::parse(valid).unwrap();
        assert!(parse_response(doc.root_element()).is_ok());

        let duplicate = valid.replace(
            "<field var='username'><value>alice</value></field>",
            "<field var='username'><value>alice</value></field><field var='username'><value>mallory</value></field>",
        );
        let doc = Document::parse(&duplicate).unwrap();
        assert!(parse_response(doc.root_element()).is_err());

        let nested = valid.replace("<value>alice</value>", "<value><b>alice</b></value>");
        let doc = Document::parse(&nested).unwrap();
        assert!(parse_response(doc.root_element()).is_err());

        let orphan_nonce = valid.replace(
            "</x>",
            "<field var='urn:northstar:pow:nonce'><value>123</value></field></x>",
        );
        let doc = Document::parse(&orphan_nonce).unwrap();
        assert!(parse_response(doc.root_element()).is_err());

        let challenge_without_work = valid.replace(
            "</x>",
            "<field var='urn:northstar:pow:challenge-id'><value>de305d54-75b4-431b-adb2-eb6b9e546013</value></field><field var='urn:northstar:pow:nonce'><value></value></field></x>",
        );
        let doc = Document::parse(&challenge_without_work).unwrap();
        assert!(parse_response(doc.root_element()).is_ok());
    }

    #[test]
    fn success_contains_required_escaped_identity() {
        assert_eq!(
            ibr_success("alice", "example.test"),
            "<success xmlns='urn:xmpp:register:0'><jid>alice@example.test</jid><username>alice</username></success>"
        );
    }

    #[test]
    fn unavailable_iq_flow_list_is_a_successful_empty_register_element() {
        let flow = ibr_empty_flow_list();
        let document = Document::parse(&flow).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().name(), "register");
        assert_eq!(root.tag_name().namespace(), Some(IBR2_NS));
        assert!(!root.children().any(|child| child.is_element()));
    }
}
