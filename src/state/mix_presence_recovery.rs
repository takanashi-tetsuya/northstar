//! Live-route fences and application effects for MIX presence recovery.

use super::{
    mix_presence_epoch_is_current, mix_presence_fallback_is_suppressed, session_entries_for_in,
    AppState, OnlineSession, RuntimeFederationPolicy,
};
use crate::db::room_effects::PostgresMixRepository;
use crate::s2s::FederationRouter;
use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use northstar_config::ExternalRouteDomainPolicy;
use northstar_mix_xmpp::ports::{MixPresenceRecoveryPort, MixPresenceRoutes};
use northstar_room_application::mix_service::{
    MixAccount, MixChannel, MixService, PamMembership, PresenceOutcome,
};
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub struct MixPresenceRecoveryContext {
    routes: MixPresenceRecoveryRoutes,
    service: MixService<PostgresMixRepository>,
    local_domain: String,
    static_policy: ExternalRouteDomainPolicy,
    runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    federation: FederationRouter,
}

pub struct MixPresenceRecoveryRoutes {
    sessions: Arc<DashMap<String, OnlineSession>>,
}

impl AppState {
    pub(crate) fn mix_presence_recovery_context(&self) -> MixPresenceRecoveryContext {
        MixPresenceRecoveryContext {
            routes: MixPresenceRecoveryRoutes::new(Arc::clone(&self.sessions)),
            service: self.mix_service.clone(),
            local_domain: self.config.domain.clone(),
            static_policy: self.config.external_route_domain_policy(),
            runtime_policy: Arc::clone(&self.federation_runtime_policy),
            federation: self.federation_outbox.clone(),
        }
    }
}

impl MixPresenceRecoveryRoutes {
    pub(crate) fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
        Self { sessions }
    }
}

impl MixPresenceRoutes for MixPresenceRecoveryRoutes {
    fn local_epochs(&self, participant: &str) -> Vec<(String, Uuid, u64)> {
        session_entries_for_in(&self.sessions, participant)
            .into_iter()
            .map(|(full_jid, session)| {
                (
                    full_jid,
                    session.connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                )
            })
            .collect()
    }

    fn gate(&self, full_jid: &str, connection_id: Uuid) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.sessions
            .get(full_jid)
            .filter(|session| session.connection_id == connection_id)
            .map(|session| Arc::clone(&session.mix_presence_gate))
    }

    fn epoch_state(
        &self,
        full_jid: &str,
        expected_connection_id: Uuid,
        expected_caps_generation: u64,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
        channel_jid: &str,
    ) -> Option<(bool, bool)> {
        self.sessions.get(full_jid).map(|session| {
            (
                mix_presence_epoch_is_current(
                    session.connection_id,
                    expected_connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                    expected_caps_generation,
                    session.routable.load(Ordering::Acquire),
                    session.available.load(Ordering::Acquire),
                    Arc::ptr_eq(&session.mix_presence_gate, expected_gate),
                ),
                mix_presence_fallback_is_suppressed(
                    &session.mix_presence_fallback_suppressed,
                    channel_jid,
                ),
            )
        })
    }
}

impl MixPresenceRecoveryPort for MixPresenceRecoveryContext {
    type Routes = MixPresenceRecoveryRoutes;

    fn routes(&self) -> &MixPresenceRecoveryRoutes {
        &self.routes
    }

    fn local_domain(&self) -> &str {
        &self.local_domain
    }

    fn local_mix_domain(&self) -> String {
        northstar_xmpp_types::jid::prepare_domainpart(&format!("mix.{}", self.local_domain))
            .expect("configured XMPP domain must form a valid MIX service domain")
    }

    fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = northstar_xmpp_types::jid::prepare_domainpart(domain) else {
            return false;
        };
        self.static_policy.federation_domain_allowed(&domain)
            && self.runtime_policy.load().allows_domain(&domain)
    }

    async fn send_federated(&self, domain: &str, stanza: String, source: Option<String>) {
        let _ = self.federation.send(domain, stanza, source).await;
    }

    async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        self.service.find_enabled_user(username).await
    }

    async fn wake_delivery_recipient(&self, bare_jid: &str) -> Result<()> {
        self.service.wake_mix_delivery_recipient(bare_jid).await?;
        Ok(())
    }

    async fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>> {
        self.service.pam_memberships(user_id).await
    }

    async fn mix_channel(&self, domain: &str, localpart: &str) -> Result<Option<MixChannel>> {
        self.service.mix_channel(domain, localpart).await
    }

    async fn ensure_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
    ) -> Result<PresenceOutcome> {
        self.service
            .ensure_mix_presence(channel_id, actor_bare, actor_full, "")
            .await
    }

    async fn expire_unrefreshed(&self, cutoff: DateTime<Utc>) -> Result<usize> {
        Ok(self
            .service
            .expire_unrefreshed_mix_presence(cutoff)
            .await?
            .len())
    }
}
