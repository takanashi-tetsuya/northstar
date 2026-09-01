use super::{Action, ProtocolSession};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use crate::{
    abuse::{AbuseAction, PowChallenge, PowIntent, PowProof, WorkRequirement},
    auth,
    services::{
        account::{
            DeletionQuiesceOutcome, DeletionQuiesceRequest, PasswordChangeOutcome,
            PasswordChangeRequest, RegistrationOutcome, RegistrationRequest,
        },
        push::{PushEnableOutcome, PushResponseKind, PushResponseOutcome},
        sm::{BindingFinalizationOutcome, BindingReservationOutcome},
    },
    state::bare_jid,
};
use anyhow::Result;
use dashmap::mapref::entry::Entry;
use roxmltree::Node;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceBindingFailure {
    UnexpectedRequest,
    JidMalformed,
    CredentialsExpired,
    Conflict,
    CapacityExhausted,
    /// PostgreSQL credential/session finalization committed, but the exact
    /// non-routable in-memory/cluster route was lost before a success could be
    /// emitted. Callers must close; they may not manufacture a rollback or a
    /// contradictory ordinary failure.
    CommittedRouteLost,
}

impl ResourceBindingFailure {
    fn iq_condition(self) -> &'static str {
        match self {
            Self::UnexpectedRequest => "unexpected-request",
            Self::JidMalformed => "jid-malformed",
            Self::CredentialsExpired => "not-authorized",
            Self::Conflict => "conflict",
            Self::CapacityExhausted => "resource-constraint",
            Self::CommittedRouteLost => "internal-server-error",
        }
    }

    pub(crate) fn sasl_condition(self) -> &'static str {
        match self {
            Self::UnexpectedRequest | Self::JidMalformed => "malformed-request",
            Self::CredentialsExpired => "credentials-expired",
            Self::Conflict | Self::CapacityExhausted => "temporary-auth-failure",
            Self::CommittedRouteLost => "temporary-auth-failure",
        }
    }
}

impl ProtocolSession {
    pub(crate) async fn registration_form(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
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
        if self.state.registration_is_closed() {
            return Ok(Action::Send(iq_registration_error(
                id,
                "service-unavailable",
            )));
        }
        if self.registration_completed {
            return Ok(Action::Send(iq_registration_error(id, "not-acceptable")));
        }
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
        // Registration is free at the ordinary allowance. If a metered step
        // is reached, the error response contains a v2 challenge committed to
        // the submitted values; the client retries those exact values here.
        // Issuing an unbound challenge in this initial form was the last v1
        // compatibility dependency and made v2-only deployments unusable.
        form.push_child(
            XmlElement::new("field")
                .attr("var", "urn:northstar:pow:challenge-id")
                .attr("type", "text-single")
                .attr(
                    "label",
                    "Proof-of-work challenge (only after a retry request)",
                ),
        );
        form.push_child(
            XmlElement::new("field")
                .attr("var", "urn:northstar:pow:nonce")
                .attr("type", "text-single")
                .attr("label", "Proof-of-work nonce"),
        );
        let mut query = XmlElement::namespaced("query", "jabber:iq:register").child(
            XmlElement::new("instructions").text("Choose a username and a password of at least 10 UTF-8 octets. A normal registration needs no proof of work. If the server returns a body-bound challenge, retry the same values with its challenge ID and the solved nonce."),
        );
        if !self.state.config.invitation_required {
            query.push_child(XmlElement::new("username"));
            query.push_child(XmlElement::new("password"));
        }
        query.push_child(form);
        let payload = query.finish();
        Ok(Action::Send(iq_result(id, &payload)))
    }

    pub(crate) async fn register(&mut self, id: &str, query: Node<'_, '_>) -> Result<Action> {
        if !self.secure_transport {
            return Ok(Action::Send(iq_registration_error(id, "not-authorized")));
        }
        if self.state.registration_is_closed() {
            return Ok(Action::Send(iq_registration_error(id, "not-allowed")));
        }
        if self.registration_completed {
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

        let (username, password, invitation_token, pow_challenge_id, pow_nonce) =
            if let Some(x_form) = form {
                if query.children().filter(|node| node.is_element()).count() != 1 {
                    return Ok(Action::Send(iq_registration_error(id, "bad-request")));
                }
                let fields = match strict_xdata_submit(
                    x_form,
                    "jabber:iq:register",
                    &[
                        "username",
                        "password",
                        "urn:northstar:invite:token",
                        "urn:northstar:pow:challenge-id",
                        "urn:northstar:pow:nonce",
                    ],
                ) {
                    Ok(fields) => fields,
                    Err(_) => return Ok(Action::Send(iq_registration_error(id, "bad-request"))),
                };

                (
                    fields.get("username").cloned().unwrap_or_default(),
                    fields.get("password").cloned().unwrap_or_default(),
                    fields.get("urn:northstar:invite:token").cloned(),
                    fields
                        .get("urn:northstar:pow:challenge-id")
                        .and_then(|value| value.parse().ok()),
                    fields.get("urn:northstar:pow:nonce").cloned(),
                )
            } else {
                match parse_legacy_register(query) {
                    Ok((username, password)) => (username, password, None, None, None),
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
            .state
            .account_service()
            .register(
                &self.state.abuse,
                RegistrationRequest {
                    username: &username,
                    password: &password,
                    invitation_token: invitation_token.as_deref().map(String::as_str),
                    proof: proof.as_ref(),
                    intent: &intent,
                    subject: &subject,
                    actors: &actors,
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(?error, "XEP-0077 registration backend failed");
                self.state
                    .metrics
                    .anti_abuse_backend_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "internal-server-error",
                )));
            }
        };
        match outcome {
            RegistrationOutcome::Created(_) => {
                self.registration_completed = true;
                self.state
                    .metrics
                    .registrations_total
                    .fetch_add(1, Ordering::Relaxed);
                Ok(Action::Send(iq_result(id, "")))
            }
            RegistrationOutcome::AbuseDenied(requirement) => {
                self.state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
                let challenge = match self
                    .state
                    .abuse
                    .issue_v2(AbuseAction::Registration, &subject, &actors, &intent)
                    .await
                {
                    Ok(challenge) => Some(challenge),
                    Err(error) => {
                        tracing::warn!(?error, "XEP-0077 v2 challenge issuance failed");
                        self.state
                            .metrics
                            .anti_abuse_backend_failures_total
                            .fetch_add(1, Ordering::Relaxed);
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
                self.state
                    .metrics
                    .capacity_reservations_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
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

    pub(crate) async fn change_password(&self, id: &str, query: Node<'_, '_>) -> Result<Action> {
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
        if !crate::jid::prepare_localpart(&username).is_ok_and(|username| username == user.username)
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
        let intent = crate::abuse::PowIntent::xmpp(
            AbuseAction::PasswordChange,
            "/xmpp/password-change",
            powless_query.as_bytes(),
        );
        let changed = self
            .state
            .account_service()
            .change_password(
                &self.state.abuse,
                PasswordChangeRequest {
                    subject: &subject,
                    actors: &actors,
                    proof: proof.as_ref(),
                    intent: &intent,
                    user_id: user.id,
                    expected_auth_generation: user.auth_generation,
                    password: &password,
                },
            )
            .await;
        match changed {
            Ok(PasswordChangeOutcome::Changed) => {}
            Ok(PasswordChangeOutcome::AbuseDenied(requirement)) => {
                self.state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
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
                self.state
                    .metrics
                    .anti_abuse_backend_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "internal-server-error",
                )));
            }
        }
        // Revoke other local and resumable sessions before acknowledging the
        // credential change. The terminal action then delivers this IQ result
        // and closes the initiating stream without a detached crash window.
        let account = format!("{}@{}", user.username, self.state.config.domain);
        self.state.disconnect_account(user.id, &account).await;
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
        let intent = crate::abuse::PowIntent::xmpp(
            AbuseAction::PasswordChange,
            "/xmpp/account-remove",
            powless_query.as_bytes(),
        );
        let subject = format!("account_remove:{}", user.id);
        // Consume the one-use proof and establish the fail-closed deletion
        // boundary atomically. New enable/resume attempts serialize after the
        // user lock and then fail the disabled/generation checks.
        match self
            .state
            .account_service()
            .quiesce_for_deletion(
                &self.state.abuse,
                DeletionQuiesceRequest {
                    subject: &subject,
                    actors: &actors,
                    proof: proof.as_ref(),
                    intent: &intent,
                    user_id: user.id,
                    expected_auth_generation: user.auth_generation,
                },
            )
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
                self.state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Action::Send(iq_registration_abuse_error(
                    id,
                    &requirement,
                    None,
                )));
            }
            Err(error) => {
                tracing::error!(?error, user_id = %user.id, "XEP-0077 guarded account quiesce failed");
                self.state
                    .metrics
                    .anti_abuse_backend_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Action::Send(iq_registration_error(
                    id,
                    "internal-server-error",
                )));
            }
        }
        match crate::account_recovery::finalize(&self.state, user.id, &user.username).await {
            Ok(crate::account_recovery::FinalizeAccountDeletion::Deleted) => {}
            Ok(crate::account_recovery::FinalizeAccountDeletion::Missing) => {
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

    pub(crate) async fn bind(&mut self, id: &str, bind: Node<'_, '_>) -> Result<Action> {
        if self.full_jid.is_some() {
            return Ok(Action::Send(iq_error(id, "unexpected-request")));
        }
        let Some(user) = self.authenticated.clone() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let generated = uuid::Uuid::new_v4().to_string();
        let resource = match child_text(bind, "resource") {
            Some(resource) => match crate::jid::prepare_resourcepart(resource) {
                Ok(resource) => resource,
                Err(_) => return Ok(Action::Send(iq_error(id, "bad-request"))),
            },
            None => generated,
        };
        let jid = match self.bind_resource_internal(&user, resource).await? {
            Ok(jid) => jid,
            Err(ResourceBindingFailure::CommittedRouteLost) => return Ok(Action::Close),
            Err(failure) => return Ok(Action::Send(iq_error(id, failure.iq_condition()))),
        };
        let payload = XmlElement::namespaced("bind", "urn:ietf:params:xml:ns:xmpp-bind")
            .child(XmlElement::new("jid").text(jid))
            .finish();
        Ok(Action::SendManyThenActivate(vec![iq_result(id, &payload)]))
    }

    /// Registers one authenticated resource. Both RFC 6120 IQ binding and
    /// XEP-0386 Bind 2 call this path so session limits, cluster ownership and
    /// cleanup cannot drift between authentication generations.
    pub(crate) async fn bind_resource_internal(
        &mut self,
        user: &crate::services::authentication::AuthenticatedAccount,
        resource: String,
    ) -> Result<std::result::Result<String, ResourceBindingFailure>> {
        let result = self
            .bind_resource_sasl2_internal(user, resource, None, self.user_agent_id)
            .await?;
        let (jid, _) = match result {
            Ok(result) => result,
            Err(failure) => return Ok(Err(failure)),
        };
        Ok(Ok(jid))
    }

    /// Bind a SASL2 resource using a bounded durable reservation followed by
    /// an exact finalization fence. PostgreSQL transactions never cross the
    /// Redis/in-memory route publication awaits, and the installed route stays
    /// non-routable until both durable finalization and transport success.
    pub(crate) async fn bind_resource_sasl2_internal(
        &mut self,
        user: &crate::services::authentication::AuthenticatedAccount,
        resource: String,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
        login_device: Option<uuid::Uuid>,
    ) -> Result<
        std::result::Result<
            (
                String,
                Option<crate::services::authentication::IssuedFastToken>,
            ),
            ResourceBindingFailure,
        >,
    > {
        if self.full_jid.is_some() {
            return Ok(Err(ResourceBindingFailure::UnexpectedRequest));
        }
        let jid = format!(
            "{}@{}/{}",
            user.username, self.state.config.domain, resource
        );
        let key = match crate::jid::canonical_session_key(&jid) {
            Ok(key) => key,
            Err(_) => return Ok(Err(ResourceBindingFailure::JidMalformed)),
        };
        let resource = crate::jid::CanonicalJid::parse(&key)
            .expect("canonical session key must parse")
            .resourcepart()
            .expect("canonical session key must contain a resource")
            .to_owned();
        let jid = key.clone();
        // The PostgreSQL lease reservation below is the sole deployment-wide
        // per-account authority. A local in-memory precheck would disagree
        // across nodes during an epoch-fenced rolling limit change and would
        // count only this process's resources.
        match self
            .state
            .sm_service()
            .reserve_binding(
                self.connection_id,
                user.id,
                user.auth_generation,
                &key,
                self.state.config.capacity_session_lease_seconds,
            )
            .await?
        {
            BindingReservationOutcome::Reserved => {}
            BindingReservationOutcome::CredentialsExpired => {
                return Ok(Err(ResourceBindingFailure::CredentialsExpired));
            }
            BindingReservationOutcome::Conflict => {
                return Ok(Err(ResourceBindingFailure::Conflict));
            }
            BindingReservationOutcome::CapacityExhausted => {
                self.state
                    .metrics
                    .capacity_reservations_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(Err(ResourceBindingFailure::CapacityExhausted));
            }
        }
        let available = Arc::new(AtomicBool::new(false));
        match self.state.sessions.entry(key.clone()) {
            Entry::Occupied(_) => {
                self.state
                    .sm_service()
                    .release_live_session(self.connection_id)
                    .await?;
                return Ok(Err(ResourceBindingFailure::Conflict));
            }
            Entry::Vacant(entry) => {
                entry.insert(crate::state::OnlineSession {
                    user_id: user.id,
                    auth_generation: user.auth_generation,
                    user_agent_epoch: None,
                    connection_id: self.connection_id,
                    route_incarnation: crate::state::RouteIncarnationSignal::new(
                        self.connection_id,
                    ),
                    lifecycle: Arc::clone(&self.route_lifecycle),
                    metrics_counted: Arc::new(AtomicBool::new(true)),
                    routable: Arc::new(AtomicBool::new(false)),
                    sender: self.outbound.clone(),
                    available: Arc::clone(&available),
                    mix_presence_gate: Arc::clone(&self.mix_presence_gate),
                    mix_presence_fallback_suppressed: Arc::clone(
                        &self.mix_presence_fallback_suppressed,
                    ),
                    caps_observation_generation: Arc::clone(&self.caps_observation_generation),
                    carbons: Arc::clone(&self.carbons),
                    priority: Arc::clone(&self.priority),
                    show: Arc::clone(&self.show),
                    blocklist_requested: Arc::clone(&self.blocklist_requested),
                    roster_requested: Arc::clone(&self.roster_requested),
                    roster_sync: Arc::clone(&self.roster_sync),
                    mix_roster_annotations: Arc::clone(&self.mix_roster_annotations),
                    privacy_active: Arc::clone(&self.privacy_active),
                    privacy_requested: Arc::clone(&self.privacy_requested),
                    directed_presence: Arc::clone(&self.directed_presence),
                    last_presence: Arc::clone(&self.last_presence),
                    ip: Some(self.peer_ip),
                    resource: resource.clone(),
                    user_agent_id: self.user_agent_id,
                    sm_session_id: Arc::clone(&self.sm_session_id_shared),
                    muc_memberships: Arc::clone(&self.joined_rooms),
                    connected_at: std::time::Instant::now(),
                    last_activity: Arc::clone(&self.last_activity),
                    disconnect: self.disconnect.clone(),
                });
            }
        }
        self.registered_key = Some(key.clone());
        self.full_jid = Some(jid.clone());
        self.available = Some(available);
        self.state
            .metrics
            .active_sessions
            .fetch_add(1, Ordering::Relaxed);

        match self
            .state
            .cluster
            .try_register_session(
                &key,
                self.connection_id,
                crate::services::sm::SessionRouteClaimProof::Binding,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                self.state
                    .sm_service()
                    .release_live_session(self.connection_id)
                    .await?;
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Ok(Err(ResourceBindingFailure::Conflict));
            }
            Err(error) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                if let Err(release_error) = self
                    .state
                    .sm_service()
                    .release_live_session(self.connection_id)
                    .await
                {
                    tracing::warn!(
                        ?release_error,
                        connection_id = %self.connection_id,
                        "failed to release a rejected binding reservation; TTL cleanup will retry"
                    );
                }
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Err(error);
            }
        }
        // Keep the reserved route explicitly non-routable until the
        // authentication/FAST transaction commits. In particular, do not
        // revoke an older suspended SM epoch yet: that teardown has durable
        // and externally visible side effects which cannot be rolled back if
        // FAST issuance or the login transaction fails below.
        let finalized = self
            .state
            .finalize_resource_binding(
                self.connection_id,
                user.id,
                user.auth_generation,
                &key,
                login_device,
                fast_plan,
            )
            .await;
        let mut receipt = match finalized {
            Ok(BindingFinalizationOutcome::Committed { receipt }) => receipt,
            Ok(BindingFinalizationOutcome::CredentialsExpired) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .state
                    .cluster
                    .unregister_session(&key, self.connection_id)
                    .await;
                let _ = self
                    .state
                    .sm_service()
                    .release_live_session(self.connection_id)
                    .await;
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Ok(Err(ResourceBindingFailure::CredentialsExpired));
            }
            Ok(BindingFinalizationOutcome::ReservationLost) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .state
                    .cluster
                    .unregister_session(&key, self.connection_id)
                    .await;
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Ok(Err(ResourceBindingFailure::Conflict));
            }
            Err(error) => {
                self.state
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .state
                    .cluster
                    .unregister_session(&key, self.connection_id)
                    .await;
                let _ = self
                    .state
                    .sm_service()
                    .release_live_session(self.connection_id)
                    .await;
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Err(error);
            }
        };
        let issued_fast = receipt.take_issued_fast();
        self.pending_credential_commit = Some(receipt);
        let route_is_current = self.state.sessions.get_mut(&key).is_some_and(|session| {
            session.connection_id == self.connection_id
                && session.user_id == user.id
                && session.auth_generation == user.auth_generation
                && Arc::ptr_eq(&session.lifecycle, &self.route_lifecycle)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        });
        if !route_is_current {
            self.state
                .remove_session_if_connection(&key, self.connection_id);
            let _ = self
                .state
                .cluster
                .unregister_session(&key, self.connection_id)
                .await;
            self.registered_key = None;
            self.full_jid = None;
            self.available = None;
            let _ = self
                .state
                .sm_service()
                .release_live_session(self.connection_id)
                .await;
            return Ok(Err(ResourceBindingFailure::CommittedRouteLost));
        }
        // A replacement claim deliberately leaves the previous resumable SM
        // row intact until the terminal bind success reaches the transport.
        // Publication transfers its stable live-session lease; the old SM row
        // then becomes non-resumable and the existing expiry/teardown worker
        // performs idempotent presence/MUC cleanup. Never revoke by full JID
        // here: Bind2 may create the replacement SM row before publication.
        Ok(Ok((jid, issued_fast)))
    }

    pub(crate) fn set_carbons(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        control: Node<'_, '_>,
        enabled: bool,
    ) -> Result<Action> {
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let own_bare = bare_jid(full_jid);
        let addressed_error =
            |condition| Action::Send(set_to(&iq_error_from(id, own_bare, condition), full_jid));
        if control.attributes().len() != 0
            || control.children().any(|child| child.is_element())
            || control.text().is_some_and(|text| !text.trim().is_empty())
        {
            return Ok(addressed_error("bad-request"));
        }
        let valid_from = iq.attribute("from").is_none_or(|from| {
            crate::jid::canonicalize(from).is_ok_and(|from| from.as_str() == full_jid)
        });
        let valid_to = iq.attribute("to").is_none_or(|to| {
            crate::jid::canonicalize(to).is_ok_and(|to| {
                to.as_str() == full_jid
                    || to.as_str() == own_bare
                    || to.as_str() == self.state.config.domain.as_str()
            })
        });
        if !valid_from || !valid_to {
            return Ok(addressed_error("not-allowed"));
        }
        let Some(route) = self
            .state
            .sessions
            .get(full_jid)
            .filter(|route| route.connection_id == self.connection_id)
        else {
            // Never acknowledge a session-local capability unless the exact
            // bound route that fanout will inspect was updated. This also
            // closes a replacement/resumption race where the protocol actor
            // could otherwise mutate a detached Arc and return success.
            return Ok(addressed_error("service-unavailable"));
        };
        // The IQ handler and message fanout can run on different Tokio
        // tasks. Publish the per-resource selection before acknowledging the
        // control IQ so subsequent routing observes it.
        route.carbons.store(enabled, Ordering::Release);
        self.carbons.store(enabled, Ordering::Release);
        drop(route);
        // XEP-0280 examples 4 and 7 require the account bare JID as the
        // responder and the enabling resource's full JID as the result
        // target. The connection itself is not a substitute for the wire
        // addressing because clients use it to reject forged IQ results.
        Ok(Action::Send(set_to(
            &iq_result_from(id, own_bare, ""),
            full_jid,
        )))
    }

    pub(crate) async fn enable_push(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        enable: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(stanza_error(iq, "auth", "not-authorized")));
        };
        let own_bare = format!("{}@{}", user.username, self.state.config.domain);
        if !push_iq_targets_account(iq, &own_bare) {
            return Ok(Action::Send(stanza_error(iq, "cancel", "not-allowed")));
        }
        let (service_jid, node, options_node) = match parse_push_enable(enable) {
            Ok(parsed) => parsed,
            Err(condition) => return Ok(Action::Send(stanza_error(iq, "modify", condition))),
        };
        let options = options_node.map(|options| &raw[options.range()]);
        match self
            .state
            .push_service()
            .enable(user.id, &service_jid, &node, options)
            .await?
        {
            PushEnableOutcome::Enabled => Ok(Action::Send(iq_result_from(id, &own_bare, ""))),
            PushEnableOutcome::QuotaExceeded => Ok(Action::Send(stanza_error(
                iq,
                "wait",
                "resource-constraint",
            ))),
            PushEnableOutcome::RateLimited => {
                self.state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
                self.state
                    .metrics
                    .push_subscriptions_rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
                Ok(Action::Send(stanza_error(
                    iq,
                    "wait",
                    "resource-constraint",
                )))
            }
        }
    }

    pub(crate) async fn disable_push(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        disable: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(stanza_error(iq, "auth", "not-authorized")));
        };
        let own_bare = format!("{}@{}", user.username, self.state.config.domain);
        if !push_iq_targets_account(iq, &own_bare) {
            return Ok(Action::Send(stanza_error(iq, "cancel", "not-allowed")));
        }
        let (service_jid, node) = match parse_push_disable(disable) {
            Ok(parsed) => parsed,
            Err(condition) => return Ok(Action::Send(stanza_error(iq, "modify", condition))),
        };
        self.state
            .push_service()
            .disable(user.id, &service_jid, node.as_deref())
            .await?;
        Ok(Action::Send(iq_result_from(id, &own_bare, "")))
    }

    pub(crate) async fn notify_push(&self, recipient_id: uuid::Uuid) -> Result<()> {
        send_push_notification(&self.state, recipient_id).await
    }

    pub(crate) async fn handle_push_response(
        &self,
        id: &str,
        kind: &str,
        root: Node<'_, '_>,
    ) -> Result<bool> {
        let Some(from) = root.attribute("from").or(self.full_jid.as_deref()) else {
            return Ok(false);
        };
        handle_push_delivery_response(&self.state, id, kind, from).await
    }

    pub(crate) async fn push_disable_message(
        &self,
        root: Node<'_, '_>,
        from: &str,
        to: &str,
    ) -> Result<bool> {
        handle_push_disable(&self.state, root, from, to).await
    }
}

pub(crate) async fn send_push_notification(
    state: &crate::state::AppState,
    recipient_id: uuid::Uuid,
) -> Result<()> {
    let batch = state.push_service().claim_batch(recipient_id).await?;
    for subscription in batch.deliveries {
        let request_id = format!("push-{}", subscription.request_id);
        let summary = XmlElement::namespaced("x", "jabber:x:data")
            .attr("type", "form")
            .child(xdata_value_field(
                "FORM_TYPE",
                "hidden",
                "urn:xmpp:push:summary",
            ))
            .child(xdata_value_field(
                "message-count",
                "text-single",
                batch.message_count,
            ))
            .child(xdata_value_field(
                "pending-subscription-count",
                "text-single",
                batch.pending_subscription_count,
            ));
        let publish =
            XmlElement::new("publish")
                .optional_attr(
                    "node",
                    (!subscription.node.is_empty()).then_some(subscription.node.as_str()),
                )
                .child(XmlElement::new("item").child(
                    XmlElement::namespaced("notification", "urn:xmpp:push:0").child(summary),
                ));
        let mut pubsub =
            XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub").child(publish);
        if let Some(form) = subscription.options.as_deref() {
            pubsub.push_child(XmlElement::new("publish-options").validated_fragment(form)?);
        }
        let notification = XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "set")
            .attr("from", &state.config.domain)
            .attr("to", &subscription.service_jid)
            .attr("id", &request_id)
            .child(pubsub)
            .finish();
        let mut delivered = false;
        let service = crate::jid::CanonicalJid::parse_bare(&subscription.service_jid).ok();
        if service
            .as_ref()
            .is_some_and(|jid| jid.domainpart() == state.config.domain)
        {
            let mut local_targets = state.session_entries_for(&subscription.service_jid);
            // A local bare push-service JID follows the same RFC 6121 routing
            // rule as any other IQ addressed to a local account: unavailable
            // and negative-priority resources are ineligible, and the
            // highest-priority available resource wins.  The full JID is a
            // stable tie-breaker so routing does not depend on DashMap order.
            local_targets.retain(|(_, session)| {
                session.available.load(Ordering::Relaxed)
                    && session.priority.load(Ordering::Relaxed) >= 0
            });
            local_targets.sort_by(|(left_jid, left), (right_jid, right)| {
                right
                    .priority
                    .load(Ordering::Relaxed)
                    .cmp(&left.priority.load(Ordering::Relaxed))
                    .then_with(|| left_jid.cmp(right_jid))
            });
            let local_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            for (_, target) in local_targets {
                if tokio::time::timeout_at(local_deadline, target.sender.send(notification.clone()))
                    .await
                    .is_ok_and(|result| result.is_ok())
                {
                    delivered = true;
                    break;
                }
            }
            if !delivered {
                let mut nodes = state
                    .cluster
                    .lookup_nodes(&subscription.service_jid)
                    .await
                    .unwrap_or_default();
                nodes.sort();
                for node_id in nodes {
                    if node_id != state.cluster.node_id {
                        delivered = state
                            .cluster
                            .send_to_node_primary(
                                &node_id,
                                &subscription.service_jid,
                                &notification,
                            )
                            .await
                            .is_ok_and(|receipt| receipt.delivered);
                        if delivered {
                            break;
                        }
                    }
                }
            }
        } else if let Some(domain) = service.as_ref().map(|jid| jid.domainpart()) {
            if state.federation_domain_allowed(domain) {
                delivered = state
                    .federation
                    .send(domain, notification.clone(), None)
                    .await;
            }
        }
        if !delivered {
            state
                .push_service()
                .mark_unroutable(subscription.request_id)
                .await?;
            state
                .metrics
                .push_notifications_failed_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                service = %subscription.service_jid,
                has_options = subscription.options.is_some(),
                "push service could not be routed"
            );
        } else {
            state
                .metrics
                .push_notifications_routed_total
                .fetch_add(1, Ordering::Relaxed);
        }
        state
            .metrics
            .push_notifications_attempted_total
            .fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Consume a local or federated Push Service IQ response.  PostgreSQL is the
/// authority, so correlation remains correct across process restarts and
/// cluster nodes.
pub(crate) async fn handle_push_delivery_response(
    state: &crate::state::AppState,
    id: &str,
    kind: &str,
    from: &str,
) -> Result<bool> {
    let Some(request_id) = id
        .strip_prefix("push-")
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
    else {
        return Ok(false);
    };
    let Ok(sender) = crate::jid::canonical_bare_key(from) else {
        return Ok(false);
    };
    let response_kind = if kind == "result" {
        PushResponseKind::Success
    } else if kind == "error" {
        PushResponseKind::PermanentError
    } else {
        return Ok(false);
    };
    let outcome = state
        .push_service()
        .complete_response(request_id, &sender, response_kind)
        .await?;
    match outcome {
        PushResponseOutcome::Unknown | PushResponseOutcome::SenderMismatch => Ok(false),
        PushResponseOutcome::Completed => Ok(true),
        PushResponseOutcome::SubscriptionDisabled => {
            state
                .metrics
                .push_notifications_failed_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(service = %sender, "push service rejected notifications repeatedly or permanently; subscription disabled");
            Ok(true)
        }
    }
}

pub(crate) async fn handle_push_disable(
    state: &crate::state::AppState,
    root: Node<'_, '_>,
    from: &str,
    to: &str,
) -> Result<bool> {
    if !matches!(
        root.attribute("type").unwrap_or("normal"),
        "normal" | "headline"
    ) {
        return Ok(false);
    }
    let elements = root
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if elements.len() != 1 {
        return Ok(false);
    }
    let pubsub = elements[0];
    if pubsub.tag_name().name() != "pubsub"
        || pubsub.tag_name().namespace() != Some("http://jabber.org/protocol/pubsub")
        || pubsub
            .attributes()
            .any(|attribute| attribute.name() != "node")
        || pubsub.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Ok(false);
    }
    let Some(node) = pubsub
        .attribute("node")
        .filter(|node| valid_push_node(node))
    else {
        return Ok(false);
    };
    let affiliations = pubsub
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if affiliations.len() != 1 {
        return Ok(false);
    }
    let affiliation = affiliations[0];
    if affiliation.tag_name().name() != "affiliation"
        || affiliation.tag_name().namespace() != Some("http://jabber.org/protocol/pubsub")
        || affiliation.attribute("affiliation") != Some("none")
        || affiliation
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "jid" | "affiliation"))
        || affiliation.children().any(|child| {
            child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Ok(false);
    }
    let Ok(target) = crate::jid::CanonicalJid::parse_bare(to) else {
        return Ok(false);
    };
    let target = target.bare();
    if affiliation
        .attribute("jid")
        .is_none_or(|jid| !crate::jid::canonical_bare_key(jid).is_ok_and(|jid| jid == target))
    {
        return Ok(false);
    }
    let target_jid = crate::jid::CanonicalJid::parse_bare(&target)?;
    if target_jid.domainpart() != state.config.domain {
        return Ok(false);
    }
    let Some(target_username) = target_jid.localpart() else {
        return Ok(false);
    };
    let service = crate::jid::canonical_bare_key(from)?;
    if !state
        .push_service()
        .disable_from_service(target_username, &service, node)
        .await?
    {
        return Ok(false);
    }
    tracing::info!(%service, user = %target, %node, "push subscription disabled by service");
    Ok(true)
}

fn push_iq_targets_account(iq: Node<'_, '_>, own_bare: &str) -> bool {
    iq.attribute("to").is_none_or(|to| {
        crate::jid::CanonicalJid::parse_bare(to).is_ok_and(|target| target.to_string() == own_bare)
    })
}

fn valid_push_node(node: &str) -> bool {
    !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
}

fn parse_push_enable<'a, 'input>(
    enable: Node<'a, 'input>,
) -> std::result::Result<(String, String, Option<Node<'a, 'input>>), &'static str> {
    if enable.attributes().any(|attribute| {
        attribute.namespace().is_some() || !matches!(attribute.name(), "jid" | "node")
    }) || enable.children().any(|child| {
        !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
    }) {
        return Err("bad-request");
    }
    let service = enable.attribute("jid").ok_or("bad-request")?;
    let service = crate::jid::canonicalize_bare(service).map_err(|_| "jid-malformed")?;
    let node = match enable.attribute("node") {
        None => String::new(),
        Some(node) if valid_push_node(node) => node.to_owned(),
        Some(_) => return Err("bad-request"),
    };
    let children = enable
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if children.len() > 1 {
        return Err("bad-request");
    }
    let options = children.first().copied();
    if options.is_some_and(|form| form.range().len() > 16 * 1_024) {
        return Err("resource-constraint");
    }
    if options.is_some_and(|form| !valid_push_options(form)) {
        return Err("bad-request");
    }
    Ok((service, node, options))
}

fn parse_push_disable(
    disable: Node<'_, '_>,
) -> std::result::Result<(String, Option<String>), &'static str> {
    if disable.attributes().any(|attribute| {
        attribute.namespace().is_some() || !matches!(attribute.name(), "jid" | "node")
    }) || disable
        .children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("bad-request");
    }
    let service = disable.attribute("jid").ok_or("bad-request")?;
    let service = crate::jid::canonicalize_bare(service).map_err(|_| "jid-malformed")?;
    let node = disable.attribute("node");
    if node.is_some_and(|node| !valid_push_node(node)) {
        return Err("bad-request");
    }
    Ok((service, node.map(str::to_owned)))
}

fn valid_push_options(form: Node<'_, '_>) -> bool {
    if form.tag_name().name() != "x"
        || form.tag_name().namespace() != Some("jabber:x:data")
        || form.attribute("type") != Some("submit")
        || form
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "type")
        || form.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    let fields = form
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if fields.is_empty() || fields.len() > 64 {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    let mut form_type = false;
    for field in fields {
        if field.tag_name().name() != "field"
            || field.tag_name().namespace() != Some("jabber:x:data")
            || field.attributes().any(|attribute| {
                attribute.namespace().is_some()
                    || !matches!(attribute.name(), "var" | "type" | "label")
            })
            || field.children().any(|child| {
                !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return false;
        }
        let Some(var) = field.attribute("var").filter(|var| {
            !var.is_empty() && var.len() <= 256 && !var.chars().any(char::is_control)
        }) else {
            return false;
        };
        if !seen.insert(var) {
            return false;
        }
        let values = field
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if values.is_empty()
            || values.len() > 16
            || values.iter().any(|value| {
                value.tag_name().name() != "value"
                    || value.tag_name().namespace() != Some("jabber:x:data")
                    || value.attributes().len() != 0
                    || value.children().any(|child| child.is_element())
                    || value.text().is_some_and(|text| text.len() > 4_096)
            })
        {
            return false;
        }
        if var == "FORM_TYPE" {
            if values.len() != 1
                || values[0].text().map(str::trim)
                    != Some("http://jabber.org/protocol/pubsub#publish-options")
            {
                return false;
            }
            form_type = true;
        }
    }
    form_type
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
fn iq_registration_error(id: &str, condition: &str) -> String {
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

fn iq_registration_abuse_error(
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
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("code", "500")
                .attr("type", "wait")
                .child(XmlElement::namespaced(
                    "resource-constraint",
                    "urn:ietf:params:xml:ns:xmpp-stanzas",
                ))
                .child(pow),
        )
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

fn parse_password_change(
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

fn parse_account_remove(query: Node<'_, '_>) -> std::result::Result<Option<PowProof>, ()> {
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

#[cfg(test)]
mod legacy_tests {
    use super::*;
    use roxmltree::Document;
    use std::time::Duration;

    #[test]
    fn binding_failures_preserve_internal_cause_and_use_valid_wire_conditions() {
        assert_eq!(
            ResourceBindingFailure::CredentialsExpired.iq_condition(),
            "not-authorized"
        );
        assert_eq!(
            ResourceBindingFailure::CredentialsExpired.sasl_condition(),
            "credentials-expired"
        );
        assert_eq!(
            ResourceBindingFailure::CapacityExhausted.iq_condition(),
            "resource-constraint"
        );
        assert_eq!(
            ResourceBindingFailure::CapacityExhausted.sasl_condition(),
            "temporary-auth-failure"
        );
        assert_ne!(
            ResourceBindingFailure::Conflict,
            ResourceBindingFailure::CommittedRouteLost
        );
    }

    #[test]
    fn test_legacy_register() {
        let xml = "<query xmlns='jabber:iq:register'><username>user1</username><password>pass1</password></query>";
        let doc = Document::parse(xml).unwrap();
        let res = parse_legacy_register(doc.root_element());
        assert_eq!(res, Ok(("user1".to_string(), "pass1".to_string())));

        let xml = "<query xmlns='jabber:iq:register'><username>user1</username><username>user2</username><password>pass1</password></query>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_legacy_register(doc.root_element()).is_err());

        let xml = "<query xmlns='jabber:iq:register'><username>user1</username><password>pass1</password><bad xmlns='other'/></query>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_legacy_register(doc.root_element()).is_err());

        let xml = "<query xmlns='jabber:iq:register'><username><value>user1</value></username><password>pass1</password></query>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_legacy_register(doc.root_element()).is_err());
    }

    #[test]
    fn password_change_is_unambiguous() {
        let doc = Document::parse(
            "<query xmlns='jabber:iq:register'><username>alice</username><password>correct-horse</password></query>",
        )
        .unwrap();
        let (username, password, proof) =
            parse_password_change(doc.root_element(), "alice").unwrap();
        assert_eq!(username, "alice");
        assert_eq!(password, "correct-horse");
        assert!(proof.is_none());
        let doc = Document::parse(
            "<query xmlns='jabber:iq:register'><password>one</password><password>two</password></query>",
        )
        .unwrap();
        assert!(parse_password_change(doc.root_element(), "alice").is_err());
    }

    #[test]
    fn account_removal_accepts_one_strict_bound_proof() {
        let doc = Document::parse(
            "<query xmlns='jabber:iq:register'><remove/><pow xmlns='urn:northstar:pow:1' challenge='018f25df-7fd1-7a36-8cef-112233445566' nonce='42'/></query>",
        )
        .unwrap();
        let proof = parse_account_remove(doc.root_element()).unwrap().unwrap();
        assert_eq!(proof.nonce, "42");

        let duplicate =
            Document::parse("<query xmlns='jabber:iq:register'><remove/><remove/></query>")
                .unwrap();
        assert!(parse_account_remove(duplicate.root_element()).is_err());
    }

    #[test]
    fn xep_0077_errors_include_legacy_and_modern_conditions() {
        for (condition, code) in [
            ("bad-request", "400"),
            ("not-authorized", "401"),
            ("not-acceptable", "406"),
            ("registration-required", "407"),
            ("conflict", "409"),
            ("service-unavailable", "503"),
        ] {
            let xml = iq_registration_error("reg1", condition);
            let document = Document::parse(&xml).unwrap();
            let error = document
                .root_element()
                .children()
                .find(|child| child.is_element() && child.tag_name().name() == "error")
                .unwrap();
            assert_eq!(error.attribute("code"), Some(code));
            assert!(error.children().any(|child| {
                child.is_element()
                    && child.tag_name().name() == condition
                    && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
            }));
        }
    }

    #[tokio::test]
    async fn metered_registration_error_carries_a_parseable_bound_v2_challenge() {
        let guard = crate::abuse::AbuseGuard::new(crate::abuse::AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 256,
            window: Duration::from_secs(300),
            cooldown_step: Duration::from_secs(30),
            max_wait: Duration::from_secs(8),
            message_free_burst: 5,
            approximate_max_device_seconds: 8,
        });
        let intent = PowIntent::xmpp_registration(
            "alice",
            "correct horse battery staple",
            Some("invite-token"),
        );
        let actors = vec!["ip:192.0.2.10".to_owned()];
        let challenge = guard
            .issue_v2(
                AbuseAction::Registration,
                "registration:192.0.2.10",
                &actors,
                &intent,
            )
            .await
            .unwrap();
        let xml = iq_registration_abuse_error(
            "registration-metered",
            &challenge.requirement,
            Some(&challenge),
        );
        let document = Document::parse(&xml).unwrap();
        let pow = document
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "pow-required"
                    && node.tag_name().namespace() == Some("urn:northstar:pow:2")
            })
            .expect("v2 challenge element");
        assert_eq!(pow.attribute("version"), Some("2"));
        let challenge_id = challenge.challenge_id.to_string();
        assert_eq!(pow.attribute("challenge"), Some(challenge_id.as_str()));
        assert_eq!(pow.attribute("intent-method"), Some("XMPP"));
        assert_eq!(pow.attribute("intent-path"), Some("/xmpp/register"));
        assert!(pow
            .attribute("intent-body-sha256")
            .is_some_and(|digest| !digest.is_empty()));
    }
}

#[cfg(test)]
mod push_tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn enable_requires_bare_service_and_unambiguous_optional_node_and_options() {
        let valid = Document::parse(
            "<enable xmlns='urn:xmpp:push:0' jid='Push.Example.test' node='device-1'>\
               <x xmlns='jabber:x:data' type='submit'>\
                 <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
                 <field var='secret'><value>opaque</value></field>\
               </x>\
             </enable>",
        )
        .unwrap();
        let (service, node, options) = parse_push_enable(valid.root_element()).unwrap();
        assert_eq!(service, "push.example.test");
        assert_eq!(node, "device-1");
        assert!(options.is_some());

        let omitted =
            Document::parse("<enable xmlns='urn:xmpp:push:0' jid='push.example.test'/>").unwrap();
        let (_, omitted_node, options) = parse_push_enable(omitted.root_element()).unwrap();
        assert!(omitted_node.is_empty());
        assert!(options.is_none());
        assert_eq!(
            XmlElement::new("publish")
                .optional_attr(
                    "node",
                    (!omitted_node.is_empty()).then_some(omitted_node.as_str()),
                )
                .finish(),
            "<publish/>"
        );
        assert_eq!(
            XmlElement::new("publish")
                .optional_attr("node", Some("device&amp;1"))
                .finish(),
            "<publish node='device&amp;amp;1'/>"
        );

        for xml in [
            "<enable xmlns='urn:xmpp:push:0' jid='push.example.test/Resource' node='device'/>",
            "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node=''/>",
            "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'><unknown/></enable>",
            "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>wrong</value></field></x></enable>",
            "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field></x></enable>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(parse_push_enable(document.root_element()).is_err(), "{xml}");
        }
    }

    #[test]
    fn disable_is_strict_but_allows_service_wide_removal() {
        let all =
            Document::parse("<disable xmlns='urn:xmpp:push:0' jid='push.example.test'/>").unwrap();
        assert_eq!(
            parse_push_disable(all.root_element()),
            Ok(("push.example.test".to_owned(), None))
        );
        let one = Document::parse(
            "<disable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'/>",
        )
        .unwrap();
        assert_eq!(
            parse_push_disable(one.root_element()),
            Ok(("push.example.test".to_owned(), Some("device".to_owned())))
        );
        let malformed = Document::parse(
            "<disable xmlns='urn:xmpp:push:0' jid='push.example.test'><x/></disable>",
        )
        .unwrap();
        assert!(parse_push_disable(malformed.root_element()).is_err());
    }

    #[test]
    fn explicit_push_target_must_be_the_owners_bare_jid() {
        let omitted = Document::parse("<iq type='set' id='1'/>").unwrap();
        assert!(push_iq_targets_account(
            omitted.root_element(),
            "alice@example.test"
        ));
        let own = Document::parse("<iq type='set' id='1' to='Alice@Example.test'/>").unwrap();
        assert!(push_iq_targets_account(
            own.root_element(),
            "alice@example.test"
        ));
        let other = Document::parse("<iq type='set' id='1' to='bob@example.test'/>").unwrap();
        assert!(!push_iq_targets_account(
            other.root_element(),
            "alice@example.test"
        ));
    }
}
