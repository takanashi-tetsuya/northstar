//! XEP-0077 in-band registration and account management.

use super::super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_abuse_policy::stanza::strip_pow_element;
use northstar_abuse_policy::{AbuseAction, PowChallenge, PowIntent, PowProof, WorkRequirement};
use northstar_auth_application::account::{
    DeletionQuiesceOutcome, DeletionQuiesceRequest, PasswordChangeOutcome, PasswordChangeRequest,
    RegistrationOutcome, RegistrationRequest,
};
use northstar_auth_core as auth;
use northstar_xml_builder::stanza::{iq_result, stanza_error_type};
use northstar_xml_builder::stream::stream_error;
use northstar_xml_builder::xdata::xdata_value_field;
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use zeroize::Zeroizing;

impl<H: SessionHost> ProtocolSession<H> {
    pub async fn registration_form(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        if !self.secure_transport {
            return Ok(Action::Send(iq_registration_error(id, "not-authorized")));
        }
        if !valid_empty_register_query(query) {
            return Ok(Action::Send(iq_registration_error(id, "bad-request")));
        }
        if let Some(user) = self.authenticated.as_ref() {
            let payload = XmlElement::namespaced("query", "jabber:iq:register")
                .child(XmlElement::new("registered"))
                .child(XmlElement::new("username").text(user.username.clone()))
                .child(XmlElement::new("password"))
                .finish();
            return Ok(Action::Send(iq_result(id, &payload)));
        }
        if self.host.registration_is_closed() {
            return Ok(Action::Send(iq_registration_error(
                id,
                "service-unavailable",
            )));
        }
        if self.negotiation.registration_completed() {
            return Ok(Action::Send(iq_registration_error(id, "not-acceptable")));
        }
        let invitation = if self.host.registration_requires_invitation() {
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
        // When the invitation is mandatory, XEP-0077 recommends returning a
        // data form plus instructions without legacy fields that cannot carry
        // the required extension. This prevents an old client from assuming a
        // username/password-only submission can succeed.
        let mut form = XmlElement::namespaced("x", "jabber:x:data")
            .attr("type", "form")
            .child(xdata_value_field(
                "FORM_TYPE",
                "hidden",
                "jabber:iq:register",
            ))
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
        // Ordinary form clients echo 0. A capable client must explicitly
        // select version 2 before the server issues a computational challenge.
        form.push_child(xdata_value_field(
            "urn:northstar:pow:version",
            "hidden",
            "0",
        ));
        let mut query = XmlElement::namespaced("query", "jabber:iq:register").child(
            XmlElement::new("instructions").text("Choose a username and a password of at least 10 UTF-8 octets. If registration is rate limited, wait before trying again."),
        );
        if !self.host.registration_requires_invitation() {
            query.push_child(XmlElement::new("username"));
            query.push_child(XmlElement::new("password"));
        }
        query.push_child(form);
        let payload = query.finish();
        Ok(Action::Send(iq_result(id, &payload)))
    }

    pub async fn register(&mut self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        if !self.secure_transport {
            return Ok(Action::Send(iq_registration_error(id, "not-authorized")));
        }
        if self.host.registration_is_closed() {
            return Ok(Action::Send(iq_registration_error(id, "not-allowed")));
        }
        if self.negotiation.registration_completed() {
            return Ok(Action::Send(iq_registration_error(id, "not-acceptable")));
        }
        if query.tag_name().name() != "query"
            || query.tag_name().namespace() != Some("jabber:iq:register")
            || query.attributes().len() != 0
            || query.children().any(|child| {
                !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return Ok(Action::Send(iq_registration_error(id, "bad-request")));
        }
        let mut form_nodes = query.children().filter(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:data")
        });
        let form = form_nodes.next();
        if form.is_some() && form_nodes.next().is_some() {
            return Ok(Action::Send(iq_registration_error(id, "bad-request")));
        }

        let (username, password, invitation_token, pow_challenge_id, pow_nonce, pow_enabled) =
            if let Some(x_form) = form {
                if query.children().filter(|node| node.is_element()).count() != 1 {
                    return Ok(Action::Send(iq_registration_error(id, "bad-request")));
                }
                let fields = match northstar_xml_builder::xdata::strict_xdata_submit(
                    x_form,
                    "jabber:iq:register",
                    &[
                        "username",
                        "password",
                        "urn:northstar:invite:token",
                        "urn:northstar:pow:version",
                        "urn:northstar:pow:challenge-id",
                        "urn:northstar:pow:nonce",
                    ],
                ) {
                    Ok(fields) => fields,
                    Err(_) => return Ok(Action::Send(iq_registration_error(id, "bad-request"))),
                };

                let pow_enabled = match fields.get("urn:northstar:pow:version").map(String::as_str)
                {
                    None | Some("0") => false,
                    Some("2") => true,
                    _ => return Ok(Action::Send(iq_registration_error(id, "bad-request"))),
                };
                if !pow_enabled
                    && (fields.contains_key("urn:northstar:pow:challenge-id")
                        || fields.contains_key("urn:northstar:pow:nonce"))
                {
                    return Ok(Action::Send(iq_registration_error(id, "bad-request")));
                }
                (
                    fields.get("username").cloned().unwrap_or_default(),
                    fields.get("password").cloned().unwrap_or_default(),
                    fields.get("urn:northstar:invite:token").cloned(),
                    fields
                        .get("urn:northstar:pow:challenge-id")
                        .and_then(|value| value.parse().ok()),
                    fields.get("urn:northstar:pow:nonce").cloned(),
                    pow_enabled,
                )
            } else {
                match parse_legacy_register(query) {
                    Ok((username, password)) => (username, password, None, None, None, false),
                    Err(_) => return Ok(Action::Send(iq_registration_error(id, "bad-request"))),
                }
            };

        let password = Zeroizing::new(password);
        let invitation_token = invitation_token
            .map(|token| token.trim().to_owned())
            .filter(|token| !token.is_empty())
            .map(Zeroizing::new);
        if username.is_empty() || password.is_empty() {
            return Ok(Action::Send(iq_registration_error(id, "not-acceptable")));
        }
        let proof = match (pow_challenge_id, pow_nonce) {
            (Some(challenge_id), Some(nonce)) if !nonce.is_empty() => Some(PowProof {
                challenge_id,
                nonce,
            }),
            _ => None,
        };

        if auth::validate_password(&password).is_err() {
            return Ok(Action::Send(iq_registration_error(id, "not-acceptable")));
        }
        let intent = PowIntent::xmpp_registration(
            &username,
            &password,
            invitation_token.as_deref().map(String::as_str),
        );
        let actors = vec![format!("ip:{}", self.peer_ip)];
        let subject = format!("registration:{}", self.peer_ip);
        let outcome = match self
            .host
            .account_service()
            .register(RegistrationRequest {
                username: &username,
                password: &password,
                invitation_token: invitation_token.as_deref().map(String::as_str),
                proof: proof.as_ref(),
                intent: &intent,
                subject: &subject,
                actors: &actors,
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(?error, "XEP-0077 registration backend failed");
                self.host.registration_telemetry().backend_failed();
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "internal-server-error",
                )));
            }
        };
        match outcome {
            RegistrationOutcome::Created(_) => {
                self.negotiation.mark_registration_completed();
                self.host.registration_telemetry().registered();
                Ok(Action::Send(iq_result(id, "")))
            }
            RegistrationOutcome::AbuseDenied(requirement) => {
                self.host.registration_telemetry().rate_limited();
                if !pow_enabled {
                    return Ok(Action::Send(iq_registration_abuse_error(
                        id,
                        &requirement,
                        None,
                    )));
                }
                let challenge = match self
                    .host
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
                    Ok(challenge) => Some(challenge),
                    Err(error) => {
                        tracing::warn!(?error, "XEP-0077 v2 challenge issuance failed");
                        self.host.registration_telemetry().backend_failed();
                        None
                    }
                };
                Ok(Action::Send(iq_registration_abuse_error(
                    id,
                    &requirement,
                    challenge.as_ref(),
                )))
            }
            RegistrationOutcome::InvalidUsername => {
                Ok(Action::Send(iq_registration_error(id, "not-acceptable")))
            }
            RegistrationOutcome::InvitationRejected => {
                Ok(Action::Send(iq_registration_error(id, "not-acceptable")))
            }
            RegistrationOutcome::UsernameTaken => {
                Ok(Action::Send(iq_registration_error(id, "conflict")))
            }
            RegistrationOutcome::RateLimited => Ok(Action::Send(iq_registration_error(
                id,
                "resource-constraint",
            ))),
            RegistrationOutcome::CapacityExhausted => {
                self.host.registration_telemetry().capacity_rejected();
                Ok(Action::Send(iq_registration_error(
                    id,
                    "resource-constraint",
                )))
            }
            RegistrationOutcome::PasswordWorkOverloaded => Ok(Action::Send(iq_registration_error(
                id,
                "resource-constraint",
            ))),
            RegistrationOutcome::Closed => {
                Ok(Action::Send(iq_registration_error(id, "not-allowed")))
            }
        }
    }
}

impl<H: SessionHost> ProtocolSession<H> {
    pub async fn change_password(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        if query.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "remove"
                && child.tag_name().namespace() == Some("jabber:iq:register")
        }) {
            return self.remove_account(id, query).await;
        }
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_registration_error(id, "not-authorized")));
        };
        let powless_query = query
            .document()
            .input_text()
            .get(query.range())
            .map(strip_pow_element)
            .ok_or_else(|| anyhow::anyhow!("password-change query range is invalid"))?;
        let (username, password, proof) = match parse_password_change(query, &user.username) {
            Ok(values) => values,
            Err(()) => return Ok(Action::Send(iq_registration_error(id, "bad-request"))),
        };
        let password = Zeroizing::new(password);
        if !northstar_xmpp_types::jid::prepare_localpart(&username)
            .is_ok_and(|username| username == user.username)
            || auth::validate_password(&password).is_err()
        {
            return Ok(Action::Send(iq_registration_error(id, "not-acceptable")));
        }
        let actors = vec![
            format!("ip:{}", self.peer_ip),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ];
        let subject = format!("password_change:{}", user.id);
        let intent = northstar_abuse_policy::PowIntent::xmpp(
            AbuseAction::PasswordChange,
            "/xmpp/password-change",
            powless_query.as_bytes(),
        );
        let changed = self
            .host
            .account_service()
            .change_password(PasswordChangeRequest {
                subject: &subject,
                actors: &actors,
                proof: proof.as_ref(),
                intent: &intent,
                user_id: user.id,
                expected_auth_generation: user.auth_generation,
                password: &password,
            })
            .await;
        match changed {
            Ok(PasswordChangeOutcome::Changed) => {}
            Ok(PasswordChangeOutcome::AbuseDenied(requirement)) => {
                self.host.account_abuse_telemetry().rate_limited();
                return Ok(Action::Send(iq_registration_abuse_error(
                    id,
                    &requirement,
                    None,
                )));
            }
            Ok(PasswordChangeOutcome::PasswordWorkOverloaded) => {
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "resource-constraint",
                )));
            }
            Err(error) => {
                tracing::error!(?error, user_id = %user.id, "XEP-0077 password change failed");
                self.host.account_abuse_telemetry().backend_failed();
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "internal-server-error",
                )));
            }
        }
        // Revoke other local and resumable sessions before acknowledging the
        // credential change. The terminal action then delivers this IQ result
        // and closes the initiating stream without a detached crash window.
        let account = format!("{}@{}", user.username, self.host.local_domain());
        self.host.disconnect_account(user.id, &account).await;
        Ok(Action::SendManyAndClose(vec![iq_result(id, "")]))
    }

    async fn remove_account(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_registration_error(
                id,
                "registration-required",
            )));
        };
        let proof = match parse_account_remove(query) {
            Ok(proof) => proof,
            Err(()) => return Ok(Action::Send(iq_registration_error(id, "bad-request"))),
        };
        let powless_query = query
            .document()
            .input_text()
            .get(query.range())
            .map(strip_pow_element)
            .ok_or_else(|| anyhow::anyhow!("account-removal query range is invalid"))?;

        let actors = vec![
            format!("ip:{}", self.peer_ip),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ];
        let intent = northstar_abuse_policy::PowIntent::xmpp(
            AbuseAction::PasswordChange,
            "/xmpp/account-remove",
            powless_query.as_bytes(),
        );
        let subject = format!("account_remove:{}", user.id);
        // Consume the one-use proof and establish the fail-closed deletion
        // boundary atomically. New enable/resume attempts serialize after the
        // user lock and then fail the disabled/generation checks.
        match self
            .host
            .account_service()
            .quiesce_for_deletion(DeletionQuiesceRequest {
                subject: &subject,
                actors: &actors,
                proof: proof.as_ref(),
                intent: &intent,
                user_id: user.id,
                expected_auth_generation: user.auth_generation,
            })
            .await
        {
            Ok(DeletionQuiesceOutcome::Quiesced) => {}
            Ok(DeletionQuiesceOutcome::Missing) => {
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "registration-required",
                )));
            }
            Ok(DeletionQuiesceOutcome::AbuseDenied(requirement)) => {
                self.host.account_abuse_telemetry().rate_limited();
                return Ok(Action::Send(iq_registration_abuse_error(
                    id,
                    &requirement,
                    None,
                )));
            }
            Err(error) => {
                tracing::error!(?error, user_id = %user.id, "XEP-0077 guarded account quiesce failed");
                self.host.account_abuse_telemetry().backend_failed();
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "internal-server-error",
                )));
            }
        }
        match self
            .host
            .finalize_account_deletion(user.id, &user.username)
            .await
        {
            Ok(northstar_auth_application::account_teardown::FinalizeAccountDeletion::Deleted) => {}
            Ok(northstar_auth_application::account_teardown::FinalizeAccountDeletion::Missing) => {
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "registration-required",
                )));
            }
            Err(error) => {
                tracing::error!(?error, user_id = %user.id, "XEP-0077 account deletion failed");
                return Ok(Action::Send(iq_registration_error(
                    id,
                    if error.to_string().contains("upload storage capacity busy") {
                        "resource-constraint"
                    } else {
                        "internal-server-error"
                    },
                )));
            }
        }
        Ok(Action::SendManyAndClose(vec![
            iq_result(id, ""),
            stream_error("not-authorized"),
        ]))
    }
}

fn valid_empty_register_query(query: Node<'_, '_>) -> bool {
    query.tag_name().name() == "query"
        && query.tag_name().namespace() == Some("jabber:iq:register")
        && query.attributes().len() == 0
        && !query.children().any(|child| child.is_element())
        && query.text().is_none_or(|text| text.trim().is_empty())
}

/// XEP-0077 section 9 requires both the legacy HTTP-style code and the
/// RFC 6120 stanza condition. Keep this compatibility surface scoped to
/// `jabber:iq:register` instead of reintroducing deprecated codes globally.
pub(super) fn iq_registration_error(id: &str, condition: &str) -> String {
    let code = match condition {
        "bad-request" | "jid-malformed" | "unexpected-request" => 400,
        "not-authorized" => 401,
        "forbidden" => 403,
        "item-not-found" | "recipient-unavailable" => 404,
        "not-allowed" => 405,
        "not-acceptable" => 406,
        "registration-required" | "subscription-required" => 407,
        "conflict" => 409,
        "remote-server-timeout" => 504,
        "service-unavailable" => 503,
        _ => 500,
    };
    let error_type = stanza_error_type(condition);
    let condition = XmlElement::dynamic(condition)
        .unwrap_or_else(|_| XmlElement::new("undefined-condition"))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("code", code)
                .attr("type", error_type)
                .child(condition),
        )
        .finish()
}

pub(crate) fn registration_retry_seconds(requirement: &WorkRequirement) -> u64 {
    requirement
        .cooldown_seconds
        .max(requirement.hard_wait_seconds)
        .max(requirement.retry_after_seconds)
        .max(1)
}

pub(super) fn iq_registration_abuse_error(
    id: &str,
    requirement: &WorkRequirement,
    challenge: Option<&PowChallenge>,
) -> String {
    let mut pow = XmlElement::namespaced("pow-required", "urn:northstar:pow:2")
        .attr("version", 2)
        .attr("step", requirement.step)
        .attr("work-factor", requirement.work_factor)
        .attr("max-work-factor", requirement.max_work_factor)
        .attr(
            "retry-after",
            requirement
                .hard_wait_seconds
                .max(requirement.retry_after_seconds),
        )
        .attr("cooldown", requirement.cooldown_seconds)
        .attr(
            "max-device-seconds",
            requirement.approximate_max_device_seconds,
        );
    if let Some(challenge) = challenge {
        pow = pow
            .attr("challenge", challenge.challenge_id)
            .attr("prefix", challenge.prefix.clone())
            .attr("key-id", challenge.key_id.clone())
            .attr("issued-at", challenge.issued_at.to_rfc3339())
            .attr("expires-at", challenge.expires_at.to_rfc3339())
            .attr("expires-in", challenge.expires_in_seconds)
            .attr("server-nonce", challenge.server_nonce.clone());
        if let Some(intent) = challenge.intent.as_ref() {
            pow = pow
                .attr("intent-method", intent.method.clone())
                .attr("intent-path", intent.path.clone())
                .attr("intent-body-sha256", intent.body_sha256.clone());
        }
    }
    let mut error = XmlElement::new("error")
        .attr("code", "500")
        .attr("type", "wait")
        .child(XmlElement::namespaced(
            "resource-constraint",
            "urn:ietf:params:xml:ns:xmpp-stanzas",
        ))
        .child(
            XmlElement::namespaced("text", "urn:ietf:params:xml:ns:xmpp-stanzas")
                .attr("xml:lang", "en")
                .text(format!(
                    "Too many requests. Wait at least {} seconds before trying again.",
                    registration_retry_seconds(requirement)
                )),
        );
    if challenge.is_some() {
        error.push_child(pow);
    }
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .child(error)
        .finish()
}

pub(crate) fn parse_legacy_register(
    query: Node<'_, '_>,
) -> std::result::Result<(String, String), ()> {
    if query.tag_name().name() != "query"
        || query.tag_name().namespace() != Some("jabber:iq:register")
        || query.attributes().len() != 0
        || query.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(());
    }
    let mut username = String::new();
    let mut password = String::new();
    let mut username_count = 0;
    let mut password_count = 0;
    for child in query.children().filter(|n| n.is_element()) {
        if child.tag_name().namespace() != Some("jabber:iq:register")
            || child.attributes().len() != 0
            || child.children().any(|nested| nested.is_element())
        {
            return Err(());
        }
        let value = child
            .children()
            .filter_map(|node| node.text())
            .collect::<String>();
        if value.len() > 4_096 {
            return Err(());
        }
        match child.tag_name().name() {
            "username" => {
                username_count += 1;
                username = value;
            }
            "password" => {
                password_count += 1;
                password = value;
            }
            _ => return Err(()),
        }
    }
    if username_count != 1 || password_count != 1 {
        return Err(());
    }
    Ok((username, password))
}

pub(super) fn parse_password_change(
    query: Node<'_, '_>,
    default_username: &str,
) -> std::result::Result<(String, String, Option<PowProof>), ()> {
    if query.tag_name().name() != "query"
        || query.tag_name().namespace() != Some("jabber:iq:register")
        || query.attributes().len() != 0
        || query.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(());
    }
    let mut username = None;
    let mut password = None;
    let mut proof = None;
    for child in query.children().filter(|child| child.is_element()) {
        if child.tag_name().name() == "pow"
            && child.tag_name().namespace() == Some("urn:northstar:pow:1")
        {
            if proof.is_some()
                || child.attributes().any(|attribute| {
                    attribute.namespace().is_some()
                        || !matches!(attribute.name(), "challenge" | "nonce")
                })
                || child.children().any(|nested| {
                    nested.is_element() || nested.text().is_some_and(|text| !text.trim().is_empty())
                })
            {
                return Err(());
            }
            proof = Some(PowProof {
                challenge_id: child
                    .attribute("challenge")
                    .ok_or(())?
                    .parse()
                    .map_err(|_| ())?,
                nonce: child.attribute("nonce").ok_or(())?.to_owned(),
            });
            continue;
        }
        if child.tag_name().namespace() != Some("jabber:iq:register")
            || child.attributes().len() != 0
            || child.children().any(|nested| nested.is_element())
        {
            return Err(());
        }
        let value = child
            .children()
            .filter_map(|node| node.text())
            .collect::<String>();
        if value.len() > 4_096 {
            return Err(());
        }
        match child.tag_name().name() {
            "username" if username.is_none() => username = Some(value),
            "password" if password.is_none() => password = Some(value),
            _ => return Err(()),
        }
    }
    Ok((
        username.unwrap_or_else(|| default_username.to_owned()),
        password.ok_or(())?,
        proof,
    ))
}

pub(super) fn parse_account_remove(
    query: Node<'_, '_>,
) -> std::result::Result<Option<PowProof>, ()> {
    if query.tag_name().name() != "query"
        || query.tag_name().namespace() != Some("jabber:iq:register")
        || query.attributes().len() != 0
        || query.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(());
    }
    let mut remove_seen = false;
    let mut proof = None;
    for child in query.children().filter(|child| child.is_element()) {
        if child.tag_name().name() == "remove"
            && child.tag_name().namespace() == Some("jabber:iq:register")
        {
            if remove_seen
                || child.attributes().len() != 0
                || child.children().any(|nested| nested.is_element())
                || child.text().is_some_and(|text| !text.trim().is_empty())
            {
                return Err(());
            }
            remove_seen = true;
            continue;
        }
        if child.tag_name().name() == "pow"
            && child.tag_name().namespace() == Some("urn:northstar:pow:1")
        {
            if proof.is_some()
                || child.attributes().any(|attribute| {
                    attribute.namespace().is_some()
                        || !matches!(attribute.name(), "challenge" | "nonce")
                })
                || child.children().any(|nested| {
                    nested.is_element() || nested.text().is_some_and(|text| !text.trim().is_empty())
                })
            {
                return Err(());
            }
            proof = Some(PowProof {
                challenge_id: child
                    .attribute("challenge")
                    .ok_or(())?
                    .parse()
                    .map_err(|_| ())?,
                nonce: child.attribute("nonce").ok_or(())?.to_owned(),
            });
            continue;
        }
        return Err(());
    }
    if !remove_seen {
        return Err(());
    }
    Ok(proof)
}
