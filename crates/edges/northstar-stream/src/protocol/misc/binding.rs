//! RFC 6120 and Bind 2 resource binding.

use super::super::{Action, ProtocolSession, SessionHost};
use anyhow::Result;
use northstar_session_application::sm::{BindingFinalizationOutcome, BindingReservationOutcome};
use northstar_xml_builder::stanza::{child_text, iq_error, iq_result};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use std::sync::{atomic::AtomicBool, atomic::AtomicU64, Arc};

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
    pub(super) fn iq_condition(self) -> &'static str {
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

impl<H: SessionHost> ProtocolSession<H> {
    pub async fn bind(&mut self, id: &str, bind: Node<'_, '_>) -> Result<Action> {
        if self.full_jid.is_some() {
            return Ok(Action::Send(iq_error(id, "unexpected-request")));
        }
        let Some(user) = self.authenticated.clone() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let generated = uuid::Uuid::new_v4().to_string();
        let resource = match child_text(bind, "resource") {
            Some(resource) => match northstar_xmpp_types::jid::prepare_resourcepart(resource) {
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
        self.auth_replies(vec![iq_result(id, &payload)])
    }

    /// Registers one authenticated resource. Both RFC 6120 IQ binding and
    /// XEP-0386 Bind 2 call this path so session limits, cluster ownership and
    /// cleanup cannot drift between authentication generations.
    pub(crate) async fn bind_resource_internal(
        &mut self,
        user: &northstar_auth_application::authentication::AuthenticatedAccount,
        resource: String,
    ) -> Result<std::result::Result<String, ResourceBindingFailure>> {
        let result = self
            .bind_resource_sasl2_internal(user, resource, None, self.user_agent_id, false)
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
        user: &northstar_auth_application::authentication::AuthenticatedAccount,
        resource: String,
        fast_plan: Option<&northstar_auth_application::authentication::FastCommitPlan>,
        login_device: Option<uuid::Uuid>,
        bind2_mam_catchup: bool,
    ) -> Result<
        std::result::Result<
            (
                String,
                Option<northstar_auth_application::authentication::IssuedFastToken>,
            ),
            ResourceBindingFailure,
        >,
    > {
        if self.full_jid.is_some() {
            return Ok(Err(ResourceBindingFailure::UnexpectedRequest));
        }
        let jid = format!(
            "{}@{}/{}",
            user.username,
            self.host.local_domain(),
            resource
        );
        let key = match northstar_xmpp_types::jid::canonical_session_key(&jid) {
            Ok(key) => key,
            Err(_) => return Ok(Err(ResourceBindingFailure::JidMalformed)),
        };
        let resource = northstar_xmpp_types::jid::CanonicalJid::parse(&key)
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
            .live_session_ownership
            .attempt(self.host.sm_service().reserve_binding(
                self.connection_id,
                user.id,
                user.auth_generation,
                &key,
                self.host.capacity_session_lease_seconds(),
            ))
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
                self.host.session_bind_telemetry().capacity_rejected();
                return Ok(Err(ResourceBindingFailure::CapacityExhausted));
            }
        }
        let available = Arc::new(AtomicBool::new(false));
        let locally_reserved = self.host.try_stage_bound_session(
            key.clone(),
            crate::local_routes::session::OnlineSession {
                user_id: user.id,
                auth_generation: user.auth_generation,
                user_agent_epoch: None,
                connection_id: self.connection_id,
                route_incarnation: northstar_session_application::RouteIncarnationSignal::new(
                    self.connection_id,
                ),
                lifecycle: Arc::clone(&self.route_lifecycle),
                metrics_counted: Arc::new(AtomicBool::new(true)),
                routable: Arc::new(AtomicBool::new(false)),
                sender: self.outbound.clone(),
                available: Arc::clone(&available),
                availability_generation: Arc::clone(&self.presence.availability_generation),
                post_actions: self.post_actions.clone(),
                recovery_replay_inflight_epoch: Arc::new(AtomicU64::new(0)),
                recovery_replay_completed_epoch: Arc::new(AtomicU64::new(0)),
                bind2_mam_catchup,
                mix_presence_gate: Arc::clone(&self.presence.mix_presence_gate),
                mix_presence_fallback_suppressed: Arc::clone(
                    &self.presence.mix_presence_fallback_suppressed,
                ),
                caps_observation_generation: Arc::clone(&self.presence.caps_observation_generation),
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
                sm_session_id: Arc::clone(&self.sm.session_id_shared),
                muc_memberships: Arc::clone(&self.joined_rooms),
                connected_at: std::time::Instant::now(),
                last_activity: Arc::clone(&self.last_activity),
                disconnect: self.disconnect.clone(),
                pending_subscription_delivery: Arc::default(),
                blocklist_observation: Arc::default(),
            },
        );
        // Release the entry guard before touching PostgreSQL on a collision.
        if !locally_reserved {
            self.host
                .sm_service()
                .release_live_session(self.connection_id)
                .await?;
            return Ok(Err(ResourceBindingFailure::Conflict));
        }
        self.registered_key = Some(key.clone());
        self.full_jid = Some(jid.clone());
        self.available = Some(available);
        self.host.session_bind_telemetry().staged_route_installed();

        match self
            .host
            .claim_staged_binding_route(&key, self.connection_id)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                self.host
                    .sm_service()
                    .release_live_session(self.connection_id)
                    .await?;
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Ok(Err(ResourceBindingFailure::Conflict));
            }
            Err(error) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                if let Err(release_error) = self
                    .host
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
        let credential_attempt = self.prepare_credential_attempt(
            northstar_auth_application::authentication::publication::CredentialKind::Binding,
        )?;
        let finalized = self
            .host
            .finalize_resource_binding(
                self.connection_id,
                user.id,
                user.auth_generation,
                &key,
                login_device,
                fast_plan,
                credential_attempt.prepared(),
            )
            .await;
        let mut receipt = match finalized {
            Ok(BindingFinalizationOutcome::Committed { receipt }) => receipt,
            Ok(BindingFinalizationOutcome::CredentialsExpired) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .host
                    .release_staged_binding_route(&key, self.connection_id)
                    .await;
                let _ = self
                    .host
                    .sm_service()
                    .release_live_session(self.connection_id)
                    .await;
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Ok(Err(ResourceBindingFailure::CredentialsExpired));
            }
            Ok(BindingFinalizationOutcome::ReservationLost) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .host
                    .release_staged_binding_route(&key, self.connection_id)
                    .await;
                self.registered_key = None;
                self.full_jid = None;
                self.available = None;
                return Ok(Err(ResourceBindingFailure::Conflict));
            }
            Err(error) => {
                self.host
                    .remove_session_if_connection(&key, self.connection_id);
                let _ = self
                    .host
                    .release_staged_binding_route(&key, self.connection_id)
                    .await;
                let _ = self
                    .host
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
        self.retain_credential_commit(receipt, credential_attempt)?;
        let route_is_current = self.host.staged_session_is_current(
            &key,
            self.connection_id,
            user.id,
            user.auth_generation,
            &self.route_lifecycle,
        );
        if !route_is_current {
            self.host
                .remove_session_if_connection(&key, self.connection_id);
            let _ = self
                .host
                .release_staged_binding_route(&key, self.connection_id)
                .await;
            self.registered_key = None;
            self.full_jid = None;
            self.available = None;
            let _ = self
                .host
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
}
