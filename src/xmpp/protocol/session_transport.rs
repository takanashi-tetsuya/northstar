//! Define transport-facing actions, connection handling, stream rendering, observations and deadlines.

use super::*;

pub(super) fn stream_features_element() -> XmlElement {
    XmlElement::new("stream:features").attr("xmlns:stream", "http://etherx.jabber.org/streams")
}

pub(super) fn push_generated_feature(parent: &mut XmlElement, feature: &str, label: &'static str) {
    if feature.is_empty() {
        return;
    }
    if let Err(error) = parent.push_validated_fragment(feature) {
        // Every current producer uses XmlElement itself. Keep this validation
        // boundary because feature providers live in separate protocol
        // modules and may later carry data restored from durable storage.
        tracing::error!(
            ?error,
            feature = label,
            "refused malformed generated stream feature"
        );
    }
}

pub enum Action {
    Send(String),
    SendMany(Vec<String>),
    /// Ordered outbound items deferred by CSI. Unlike ordinary protocol
    /// replies these may carry a durable-delivery fence which the transport
    /// must complete only at its negotiated recovery boundary (SM h, BOSH
    /// response ack, or the explicit non-SM socket-write fallback).
    SendManyItems(Vec<crate::xmpp::outbound::OutboundItem>),
    /// The first frame is the terminal authentication success. Publish the
    /// staged login epoch and already-committed route only after that frame
    /// reaches the transport.
    SendManyThenActivate(super::super::auth_publication::AuthReplies),
    /// Send each terminal payload in order and then close the XML stream.
    /// Unlike ordinary outbound stanzas these frames are not added to an SM
    /// resume queue: the operation producing them has already revoked the
    /// authenticated session and resumption must be impossible.
    SendManyAndClose(Vec<String>),
    Resume(ResumePayload),
    StartTls,
    CloseWith(String),
    Close,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientTransport {
    Tcp,
    WebSocket,
    Bosh,
}

/// Limits the owning transport can actually enforce on a native XML stream.
/// HTTP binding leaves this absent because its request and inactivity limits
/// are negotiated independently by XEP-0124.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamLimits {
    pub max_bytes: usize,
    pub negotiation_idle: std::time::Duration,
    pub authenticated_idle: std::time::Duration,
}

impl StreamLimits {
    pub(crate) fn idle_timeout(self, authenticated: bool) -> std::time::Duration {
        if authenticated {
            self.authenticated_idle
        } else {
            self.negotiation_idle
        }
    }
}

pub(crate) struct TlsSessionEvidence {
    pub channel_bindings: Option<crate::auth::ChannelBindings>,
    pub client_certificate_identities: Vec<String>,
    pub client_certificate_chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>,
    pub generation: u64,
}

pub(super) fn client_stream_limits_feature(
    limits: Option<StreamLimits>,
    authenticated: bool,
) -> String {
    let Some(limits) = limits else {
        return String::new();
    };
    XmlElement::namespaced("limits", "urn:xmpp:stream-limits:0")
        .child(XmlElement::new("max-bytes").text(limits.max_bytes.to_string()))
        .child(
            XmlElement::new("idle-seconds")
                .text(limits.idle_timeout(authenticated).as_secs().to_string()),
        )
        .finish()
}

impl SessionTerminationSignals {
    pub(crate) async fn revoked(&self) {
        self.policy_revoke.cancelled().await;
    }

    pub(crate) async fn backpressured(&self) {
        self.backpressure.cancelled().await;
    }

    pub(crate) fn is_revoked(&self) -> bool {
        self.policy_revoke.is_cancelled()
    }

    pub(crate) fn is_backpressured(&self) -> bool {
        self.backpressure.is_cancelled()
    }
}

impl ProtocolSession {
    pub(in crate::xmpp) fn enter_frame_stage(&self, stage: super::super::frame_execution::Stage) {
        self.frame_executions.enter(stage);
    }

    pub(in crate::xmpp) fn message_operation(
        &self,
    ) -> Option<crate::services::message_admission::witness::DirectOperationHandle> {
        self.frame_executions.direct_operation()
    }

    pub(crate) fn local_domain(&self) -> &str {
        self.state.local_domain()
    }

    pub(crate) fn record_bosh_session_closed(&self) {
        self.state.record_bosh_session_closed();
    }

    pub(crate) fn record_backpressure_disconnect(&self) {
        self.state.record_c2s_backpressure_disconnect();
    }

    pub(crate) fn activate_tls(&mut self, evidence: TlsSessionEvidence) {
        self.channel_bindings = evidence.channel_bindings;
        self.client_certificate_identities = evidence.client_certificate_identities;
        self.client_certificate_chain = evidence.client_certificate_chain;
        self.tls_generation = evidence.generation;
        self.secure_transport = true;
    }

    /// Transport adapters may inspect stream state, but only protocol handling
    /// may change the negotiation lifecycle.
    pub(crate) fn is_stream_open(&self) -> bool {
        self.negotiation.is_open()
    }

    /// Transport deadlines and response fences need only this fact, not the
    /// authenticated account or a mutable authentication capability.
    pub(crate) fn is_authenticated(&self) -> bool {
        self.authenticated.is_some()
    }

    pub(crate) fn termination_signals(&self) -> SessionTerminationSignals {
        SessionTerminationSignals {
            policy_revoke: self.disconnect.clone(),
            backpressure: self.outbound.backpressure_disconnect(),
        }
    }

    /// The authentication clock belongs to the session. Transports keep
    /// their own polling cadence and decide how to close an expired stream.
    pub(crate) fn unauthenticated_timed_out(&self, now: std::time::Instant) -> bool {
        unauthenticated_timed_out_for(
            self.is_authenticated(),
            self.connected_at,
            self.state.unauthenticated_timeout(),
            now,
        )
    }

    pub(crate) fn uses_websocket_framing(&self) -> bool {
        self.transport == ClientTransport::WebSocket
    }

    pub fn new(
        state: Arc<AppState>,
        outbound: crate::xmpp::outbound::OutboundSender,
        secure_transport: bool,
        transport: ClientTransport,
        stream_limits: Option<StreamLimits>,
        peer_ip: IpAddr,
    ) -> Self {
        let sm_runtime_policy = SmRuntimePolicy::from_state(&state);
        Self {
            state,
            sm_runtime_policy,
            outbound,
            secure_transport,
            transport,
            frame_executions: super::super::frame_execution::SessionExecutions::default(),
            stream_limits,
            peer_ip,
            connected_at: std::time::Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(std::time::Instant::now())),
            negotiation: northstar_session_core::StreamNegotiation::default(),
            authenticated: None,
            authenticated_at: None,
            full_jid: None,
            registered_key: None,
            available: None,
            presence: PresenceSubstate::default(),
            carbons: Arc::new(AtomicBool::new(false)),
            priority: Arc::new(AtomicI16::new(0)),
            show: Arc::new(AtomicU8::new(0)),
            blocklist_requested: Arc::new(AtomicBool::new(false)),
            roster_requested: Arc::new(AtomicBool::new(false)),
            roster_sync: Arc::new(northstar_roster_application::RosterSyncGate::default()),
            mix_roster_annotations: Arc::new(AtomicBool::new(false)),
            privacy_active: Arc::new(std::sync::RwLock::new(None)),
            privacy_requested: Arc::new(AtomicBool::new(false)),
            directed_presence: Arc::new(DashSet::new()),
            last_presence: Arc::new(std::sync::RwLock::new(None)),
            joined_rooms: Arc::new(dashmap::DashMap::new()),
            csi: csi::CsiSubstate::default(),
            bind2_mam_catchup: false,
            sm: SmSubstate::default(),
            sasl_state: None,
            sasl_scram_fence: None,
            legacy_sasl_awaiting_initial_response: false,
            sasl2_state: None,
            ibr_flow: None,
            ibr_pow_enabled: false,
            user_agent_id: None,
            user_agent_epoch: None,
            pending_credential_commit: None,
            channel_bindings: None,
            client_certificate_identities: Vec::new(),
            client_certificate_chain: Vec::new(),
            tls_generation: 0,
            _certificate_session: None,
            disconnect: tokio_util::sync::CancellationToken::new(),
            connection_id: uuid::Uuid::new_v4(),
            live_session_ownership: LiveSessionOwnership::default(),
            route_lifecycle: Arc::new(AtomicU8::new(0)),
            local_quiesced: false,
            post_actions: PostActionHandle::default(),
        }
    }

    pub(crate) fn resource_bind_deadline(&self) -> Option<std::time::Instant> {
        resource_bind_deadline_for(
            self.authenticated.is_some(),
            self.full_jid.is_some(),
            self.authenticated_at,
            self.state.c2s_resource_bind_timeout_seconds(),
        )
    }

    pub(crate) fn open_stream(&self) -> String {
        let to = self
            .negotiation
            .stream_from()
            .map(|username| format!("{}@{}", username, self.state.local_domain()));
        if self.uses_websocket_framing() {
            let _ = self.outbound.try_send(self.features());
            XmlElement::namespaced("open", "urn:ietf:params:xml:ns:xmpp-framing")
                .attr("from", self.state.local_domain())
                .optional_attr("to", to.as_deref())
                .attr("id", stream_id())
                .attr("version", "1.0")
                .attr("xml:lang", "en")
                .finish()
        } else {
            let mut opening = XmlElement::new("stream:stream")
                .attr("from", self.state.local_domain())
                .optional_attr("to", to.as_deref())
                .attr("id", stream_id())
                .attr("version", "1.0")
                .attr("xml:lang", "en")
                .attr("xmlns", "jabber:client")
                .attr("xmlns:stream", "http://etherx.jabber.org/streams")
                .open();
            opening.push_str(&self.features());
            opening
        }
    }

    pub(crate) fn features(&self) -> String {
        let limits = client_stream_limits_feature(self.stream_limits, self.authenticated.is_some());
        if self.authenticated.is_some() {
            let mut features = stream_features_element();
            if self.full_jid.is_none() {
                features.push_child(XmlElement::namespaced(
                    "bind",
                    "urn:ietf:params:xml:ns:xmpp-bind",
                ));
                features.push_child(
                    XmlElement::namespaced("session", "urn:ietf:params:xml:ns:xmpp-session")
                        .child(XmlElement::new("optional")),
                );
            }
            features.push_child(XmlElement::namespaced("ver", "urn:xmpp:features:rosterver"));
            if !self.sm.enabled
                && self
                    .state
                    .xmpp_extension_enabled(northstar_xep_0198::XEP_ID)
            {
                features.push_child(XmlElement::namespaced("sm", northstar_xep_0198::NAMESPACE));
            }
            if self
                .state
                .xmpp_extension_enabled(northstar_xep_0352::XEP_ID)
            {
                features.push_child(XmlElement::namespaced("csi", northstar_xep_0352::NAMESPACE));
            }
            push_generated_feature(&mut features, &limits, "stream limits");
            return features.finish();
        }
        if !self.secure_transport {
            return stream_features_element()
                .child(
                    XmlElement::namespaced("starttls", "urn:ietf:params:xml:ns:xmpp-tls")
                        .child(XmlElement::new("required")),
                )
                .finish();
        }
        let mut register = String::new();
        if !self.state.registration_is_closed() {
            // XEP-0077 explicitly supports required extension fields through
            // XEP-0004 data forms, including an invitation token. Legacy
            // element-only submissions remain accepted only when they satisfy
            // the configured registration policy.
            register.push_str(
                &XmlElement::namespaced("register", "http://jabber.org/features/iq-register")
                    .finish(),
            );
            register.push_str(&ibr::ibr_stream_feature());
        }
        let mut features = stream_features_element();
        if let Some(bindings) = self.channel_bindings.as_ref() {
            push_generated_feature(&mut features, &bindings.feature_xml(), "channel bindings");
        }
        let mut mechanisms =
            XmlElement::namespaced("mechanisms", "urn:ietf:params:xml:ns:xmpp-sasl");
        if !self.client_certificate_identities.is_empty() {
            mechanisms.push_child(XmlElement::new("mechanism").text("EXTERNAL"));
        }
        if self.channel_bindings.is_some() {
            mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-256-PLUS"));
        }
        mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-256"));
        if self.state.c2s_scram_sha1_enabled() {
            if self.channel_bindings.is_some() {
                mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-1-PLUS"));
            }
            mechanisms.push_child(XmlElement::new("mechanism").text("SCRAM-SHA-1"));
        }
        mechanisms.push_child(XmlElement::new("mechanism").text("PLAIN"));
        features.push_child(mechanisms);
        let sasl2 = sasl2::authentication_feature_xml(self);
        push_generated_feature(&mut features, &sasl2, "SASL2 authentication");
        push_generated_feature(&mut features, &register, "in-band registration");
        push_generated_feature(&mut features, &limits, "stream limits");
        features.finish()
    }
}

pub(super) fn unauthenticated_timed_out_for(
    authenticated: bool,
    connected_at: std::time::Instant,
    timeout: std::time::Duration,
    now: std::time::Instant,
) -> bool {
    !authenticated && now.saturating_duration_since(connected_at) >= timeout
}

pub(super) fn resource_bind_deadline_for(
    authenticated: bool,
    bound: bool,
    authenticated_at: Option<std::time::Instant>,
    timeout_seconds: u64,
) -> Option<std::time::Instant> {
    if authenticated && !bound {
        authenticated_at.map(|instant| instant + std::time::Duration::from_secs(timeout_seconds))
    } else {
        None
    }
}
