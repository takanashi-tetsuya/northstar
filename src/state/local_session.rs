//! `AppState` methods over the live C2S session table; the table operations are in `xmpp::local_routes::session_table`.

use super::*;

impl AppState {
    /// Evaluate one resource's session-local XEP-0016 selection (or the
    /// account default when no active list is selected). Callers must apply
    /// XEP-0191 first; a blocking hit is never overridden by an allow rule.
    /// Stanza paths that still hold a storage-level kind convert it at this
    /// boundary; the service layer owns the mapping.
    pub async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<crate::services::privacy::PrivacyStanzaKind>,
    ) -> anyhow::Result<bool> {
        let active = session
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.message_service
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                kind.into(),
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_resource_binding(
        &self,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        device_id: Option<uuid::Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
        observation: Option<&crate::services::authentication::publication::PreparedCredential>,
    ) -> anyhow::Result<crate::services::sm::BindingFinalizationOutcome> {
        self.sm_service
            .finalize_binding_observed(
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                self.config.capacity_session_lease_seconds,
                device_id,
                fast_plan,
                observation,
            )
            .await
    }

    pub(crate) async fn finalize_sm_resume(
        &self,
        request: crate::services::sm::SmResumeFinalizationRequest<'_>,
        observation: Option<&crate::services::authentication::publication::PreparedCredential>,
    ) -> anyhow::Result<crate::services::sm::SmResumeFinalizationOutcome> {
        self.sm_service
            .finalize_resume_observed(request, observation)
            .await
    }

    /// Reserve a non-routable bind candidate under the same map entry guard
    /// that rejects a concurrent bind or resume for this full JID.
    pub(crate) fn try_stage_bound_session(&self, key: String, session: OnlineSession) -> bool {
        try_stage_bound_session_in(&self.sessions, key, session)
    }

    pub(crate) fn staged_session_is_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
    ) -> bool {
        self.sessions.get(key).is_some_and(|session| {
            session.connection_id == connection_id
                && session.user_id == user_id
                && session.auth_generation == auth_generation
                && Arc::ptr_eq(&session.lifecycle, lifecycle)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub(crate) fn publish_user_agent_epoch_if_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        user_agent_epoch: Option<i64>,
    ) -> bool {
        publish_user_agent_epoch_if_current_in(
            &self.sessions,
            key,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
            user_agent_epoch,
        )
    }

    /// A carbon preference is session-local and must be visible to fan-out
    /// before its IQ result is sent to the same connection.
    pub(crate) fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool {
        let Some(route) = self.sessions.get(key) else {
            return false;
        };
        if route.connection_id != connection_id {
            return false;
        }
        route.carbons.store(enabled, Ordering::Release);
        true
    }

    pub(crate) fn sm_pending_route_removal_signal(
        &self,
        key: &str,
        old_connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        cancel_live_route: bool,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        let session = self.sessions.get(key)?;
        let exact_sm = session
            .sm_session_id
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|current| current == sm_session_id);
        if session.connection_id != old_connection_id || session.user_id != user_id || !exact_sm {
            return None;
        }
        if cancel_live_route {
            session.disconnect.cancel();
        }
        Some(session.route_incarnation.subscribe())
    }

    pub(crate) fn sm_presence_epoch(&self, key: &str) -> Option<SmPresenceEpoch> {
        self.sessions.get(key).map(|session| SmPresenceEpoch {
            gate: Arc::clone(&session.mix_presence_gate),
            fallback_suppressed: Arc::clone(&session.mix_presence_fallback_suppressed),
            caps_generation: Arc::clone(&session.caps_observation_generation),
        })
    }

    /// Inspect/insert inside one DashMap entry operation. The caller owns the
    /// returned gate and route-incarnation handles before any async wait.
    pub(crate) fn stage_sm_resumed_session(
        &self,
        key: String,
        candidate: OnlineSession,
        claimant_user: uuid::Uuid,
        claimed_sm_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> SmStagedRouteClaim {
        stage_sm_resumed_session_in(
            &self.sessions,
            key,
            candidate,
            claimant_user,
            claimed_sm_id,
            expected_gate,
        )
    }

    /// The command protocol receives only the delivered account identities,
    /// not mutable access to the session table.
    pub(crate) fn send_local_announcement(
        &self,
        stanza: &str,
    ) -> std::collections::BTreeSet<String> {
        let mut recipients = std::collections::BTreeSet::new();
        for entry in self.sessions.iter() {
            if entry.routable.load(Ordering::Acquire)
                && entry.available.load(Ordering::Acquire)
                && entry.priority.load(Ordering::Acquire) >= 0
                && entry.sender.try_send(stanza.to_owned()).is_ok()
            {
                if let Ok(bare) = northstar_xmpp_types::jid::canonical_bare_key(entry.key()) {
                    recipients.insert(bare);
                }
            }
        }
        recipients
    }

    pub(crate) fn local_online_bare_jids(&self) -> std::collections::BTreeSet<String> {
        self.sessions
            .iter()
            .filter(|entry| entry.routable.load(Ordering::Acquire))
            .filter_map(|entry| northstar_xmpp_types::jid::canonical_bare_key(entry.key()).ok())
            .collect()
    }

    pub(crate) fn local_activity_bare_jids(
        &self,
        idle_after: Duration,
    ) -> (
        std::collections::BTreeSet<String>,
        std::collections::BTreeSet<String>,
    ) {
        let mut online = std::collections::BTreeSet::new();
        let mut active = std::collections::BTreeSet::new();
        for entry in self.sessions.iter() {
            if !entry.routable.load(Ordering::Acquire) {
                continue;
            }
            let Ok(bare) = northstar_xmpp_types::jid::canonical_bare_key(entry.key()) else {
                continue;
            };
            online.insert(bare.clone());
            if entry
                .last_activity
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .elapsed()
                < idle_after
            {
                active.insert(bare);
            }
        }
        (online, active)
    }

    /// Initial key snapshot for an account presence probe. The protocol then
    /// rechecks each incarnation after its privacy/database awaits.
    pub(crate) fn local_presence_owner_keys(&self) -> Vec<String> {
        self.sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub(crate) fn local_presence_owner_candidate(
        &self,
        key: &str,
        user_id: uuid::Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.sessions.get(key).and_then(|session| {
            (session.routable.load(Ordering::Acquire)
                && session.user_id == user_id
                && session.auth_generation == auth_generation
                && session.available.load(Ordering::Relaxed))
            .then(|| session.value().clone())
        })
    }

    pub(crate) fn local_presence_owner_if_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: uuid::Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.sessions.get(key).and_then(|current| {
            (current.connection_id == expected.connection_id
                && Arc::ptr_eq(&current.route_incarnation, &expected.route_incarnation)
                && current.user_id == user_id
                && current.auth_generation == auth_generation
                && current.routable.load(Ordering::Acquire)
                && current.available.load(Ordering::Relaxed))
            .then(|| current.value().clone())
        })
    }

    pub(crate) fn send_presence_if_owner_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: uuid::Uuid,
        auth_generation: i64,
        recipient: &crate::xmpp::outbound::OutboundSender,
        presence: &str,
    ) -> bool {
        let Some(current) = self.sessions.get(key) else {
            return false;
        };
        if current.connection_id != expected.connection_id
            || !Arc::ptr_eq(&current.route_incarnation, &expected.route_incarnation)
            || current.user_id != user_id
            || current.auth_generation != auth_generation
            || !current.routable.load(Ordering::Acquire)
            || !current.available.load(Ordering::Relaxed)
        {
            return false;
        }
        recipient.try_send(presence.to_owned()).is_ok()
    }

    pub(crate) fn local_caps_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                expected_gate.is_none_or(|gate| Arc::ptr_eq(&session.mix_presence_gate, gate)),
                epoch,
            )
        })
    }

    pub(crate) fn local_caps_observer_connection_is_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            session.connection_id == connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, expected_gate)
                && session.routable.load(Ordering::Acquire)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub(crate) fn local_mix_presence_route_is_current(
        &self,
        full_jid: &str,
        expected_connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
        require_available: bool,
    ) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            session.connection_id == expected_connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, expected_gate)
                && session.routable.load(Ordering::Acquire)
                && (!require_available || session.available.load(Ordering::Acquire))
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        let Some(lookup) = session_lookup(jid) else {
            return Vec::new();
        };
        match lookup {
            SessionLookup::Full(full) => self
                .sessions
                .get(&full)
                .filter(|entry| entry.routable.load(Ordering::Acquire))
                .map(|entry| vec![entry.value().clone()])
                .unwrap_or_default(),
            SessionLookup::Bare(bare) => self
                .sessions
                .iter()
                .filter(|entry| {
                    bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
                })
                .map(|entry| entry.value().clone())
                .collect(),
        }
    }

    pub fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.sessions, jid)
    }

    /// Publish only the exact staged route incarnation that survived every
    /// authorization and lifecycle fence.  The DashMap write guard provides
    /// a local linearization point with account/session revocation helpers;
    /// the cancellation/lifecycle recheck after publication also closes a
    /// concurrent out-of-band transport cancellation window.
    pub(crate) fn activate_session_if_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        disconnect: &CancellationToken,
    ) -> bool {
        activate_session_if_current_in(
            &self.sessions,
            full_jid,
            connection_id,
            user_id,
            auth_generation,
            lifecycle,
            disconnect,
        )
    }

    /// Remove exactly one local route incarnation. Every rollback and Drop
    /// path must use this instead of an unconditional DashMap removal: a late
    /// old connection must never delete a newly bound/resumed replacement.
    pub fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession> {
        self.session_cleanup_local()
            .remove_session_if_connection(key, connection_id)
    }

    /// Revoke local account routes and request durable SM revocation.
    /// Remote nodes receive the generation fence over Redis, with a 30-second
    /// maintenance sweep as fallback while PostgreSQL remains available.
    pub async fn disconnect_account(&self, user_id: uuid::Uuid, bare_account_jid: &str) {
        self.account_teardown_runtime()
            .disconnect_account(user_id, bare_account_jid)
            .await;
    }

    pub async fn revoke_sm_session_with_teardown(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        if let Some(snapshot) = db::take_sm_session_for_teardown(
            &self.pool,
            id,
            self.config.sm_claim_lease_seconds.max(1),
        )
        .await?
        {
            self.perform_and_finalize_sm_teardown(snapshot).await?;
        }
        Ok(())
    }

    pub(super) async fn perform_and_finalize_sm_teardown(
        &self,
        snapshot: db::SmTeardownSnapshot,
    ) -> anyhow::Result<()> {
        let runtime = self.sm_teardown_runtime();
        crate::services::sm_teardown::SmTeardownService::new(
            db::sm_teardown_repository::PostgresSmTeardownRepository::new(self.pool.clone()),
            self.config.sm_claim_lease_seconds,
        )
        .finish(snapshot, |snapshot| async move {
            runtime.teardown_snapshot(&snapshot).await
        })
        .await
    }

    pub(super) fn sm_teardown_presence_service(
        &self,
    ) -> crate::services::sm_teardown_presence::SmTeardownPresenceService<
        db::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository,
    > {
        crate::services::sm_teardown_presence::SmTeardownPresenceService::new(
            db::sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(super) fn sm_teardown_muc_service(
        &self,
    ) -> crate::services::sm_teardown_muc::SmTeardownMucService<
        db::sm_teardown_muc_repository::PostgresSmTeardownMucRepository,
    > {
        crate::services::sm_teardown_muc::SmTeardownMucService::new(
            db::sm_teardown_muc_repository::PostgresSmTeardownMucRepository::new(self.pool.clone()),
        )
    }
}
