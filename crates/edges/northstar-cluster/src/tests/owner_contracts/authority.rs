use super::*;
use northstar_room_application::muc_service::{
    ClusterMucOccupancyMaintenanceRepository, ClusterMucOccupancyMaintenanceService,
    MucOccupancyLookup, MucResolvedOccupancy,
};
use northstar_room_core::ClusterMucOccupancyTarget;
use northstar_security::cluster_keys::ClusterReadinessAuthority;
use northstar_session_application::{
    cluster_replay_maintenance::{
        ClusterReplayMaintenanceRepository, ClusterReplayMaintenanceService,
    },
    cluster_session_route_maintenance::{
        ClusterSessionRouteMaintenanceRepository, ClusterSessionRouteMaintenanceService,
    },
    cluster_session_store::ClusterStoreFuture,
    session_authority_sweep::{
        AccountAuthState, SessionAuthoritySweepRepository, SessionAuthoritySweepService,
    },
    session_route_maintenance::{
        SessionRouteLease, SessionRouteRenewalPort, SessionRouteRenewalService,
    },
};

#[derive(Clone)]
pub(super) struct AuthorityPorts(Arc<AuthorityRecording>);

struct AuthorityRecording {
    calls: Mutex<Vec<&'static str>>,
    authority: ClusterReadinessAuthority,
    failure: &'static str,
    target: Mutex<Option<ClusterMucOccupancyTarget>>,
    renew_gate: Mutex<Option<oneshot::Receiver<()>>>,
}

impl AuthorityPorts {
    fn new(authority: ClusterReadinessAuthority, failure: &'static str) -> Self {
        Self(Arc::new(AuthorityRecording {
            calls: Mutex::new(Vec::new()),
            authority,
            failure,
            target: Mutex::new(None),
            renew_gate: Mutex::new(None),
        }))
    }

    fn enter(&self, step: &'static str) -> Result<()> {
        self.0.calls.lock().unwrap().push(step);
        anyhow::ensure!(self.0.failure != step, "injected {step} failure");
        Ok(())
    }
}

impl ClusterAuthorityRepository for AuthorityPorts {
    async fn validate_cluster_key(&self, identity: &ClusterKeyDeploymentIdentity) -> Result<()> {
        assert_eq!(identity, &self.0.authority.key_identity);
        self.enter("key")
    }

    async fn validate_peer_keys(&self, domain: &str, _: &[ExpectedClusterPeerKey]) -> Result<()> {
        assert_eq!(domain, self.0.authority.key_identity.xmpp_domain);
        self.enter("peer-validation")
    }

    async fn peer_keys(&self, _: &str, _: &[String]) -> Result<Vec<ClusterPeerKeyAuthority>> {
        self.enter("peer-keys")?;
        Ok(Vec::new())
    }

    async fn active_instances(
        &self,
        _: &str,
        nodes: &[String],
    ) -> Result<Vec<ClusterNodeInstance>> {
        self.enter("instances")?;
        let authority = &self.0.authority;
        Ok(if nodes == [authority.instance_node_id.clone()] {
            vec![ClusterNodeInstance {
                node_id: authority.instance_node_id.clone(),
                instance_uuid: authority.instance_uuid,
                instance_epoch: authority.instance_epoch,
                signing_key_id: authority.signing_key_id.clone(),
                signing_key_epoch: authority.signing_key_epoch,
                lease_remaining: Duration::from_secs(90),
            }]
        } else {
            Vec::new()
        })
    }

    async fn heartbeat_instance(
        &self,
        authority: &ClusterReadinessAuthority,
        lease: Duration,
    ) -> Result<()> {
        assert_eq!(authority, &self.0.authority);
        assert_eq!(lease, Duration::from_secs(90));
        self.enter("instance-heartbeat")
    }
}

impl ClusterReplayMaintenanceRepository for AuthorityPorts {
    async fn cleanup_replays(&self, limit: i32) -> Result<u64> {
        assert_eq!(limit, 4096);
        self.enter("replay-cleanup")?;
        Ok(0)
    }

    async fn validate_capacity_authority(&self) -> Result<()> {
        self.enter("replay-validation")
    }
}

impl ClusterSessionRouteMaintenanceRepository for AuthorityPorts {
    async fn cleanup_routes(&self, limit: i32) -> Result<u64> {
        assert_eq!(limit, 4096);
        self.enter("route-cleanup")?;
        Ok(0)
    }

    async fn validate_authority(&self) -> Result<()> {
        self.enter("route-validation")
    }
}

impl SessionAuthoritySweepRepository for AuthorityPorts {
    async fn auth_states_for_users(
        &self,
        users: &[Uuid],
    ) -> Result<HashMap<Uuid, AccountAuthState>> {
        assert!(
            users.is_empty(),
            "maintenance fixture contains only MUC projections"
        );
        Ok(HashMap::new())
    }

    async fn user_agent_login_epochs(
        &self,
        agents: &[(Uuid, Uuid)],
    ) -> Result<HashMap<(Uuid, Uuid), i64>> {
        assert!(agents.is_empty());
        Ok(HashMap::new())
    }
}

impl ClusterMucOccupancyMaintenanceRepository for AuthorityPorts {
    async fn authoritative_for_node(&self, node: &str) -> Result<Vec<ClusterMucOccupancyTarget>> {
        assert_eq!(node, self.0.authority.instance_node_id);
        self.enter("occupancy-snapshot")?;
        Ok(self.0.target.lock().unwrap().iter().cloned().collect())
    }

    async fn resolve_exact_batch(
        &self,
        _: &[MucOccupancyLookup],
        _: &str,
    ) -> Result<Vec<MucResolvedOccupancy>> {
        panic!("maintenance must use its captured snapshot");
    }

    async fn committed_terminal_exact_batch(
        &self,
        candidates: &[MucOccupancyLookup],
        node: &str,
    ) -> Result<Vec<MucOccupancyLookup>> {
        assert_eq!(node, self.0.authority.instance_node_id);
        let target = self.0.target.lock().unwrap().clone().unwrap();
        assert_eq!(
            candidates,
            [MucOccupancyLookup::new(
                "room@conference.example.test",
                &target.full_jid,
                &target.nick,
                target.occupant_incarnation,
                target.connection_uuid,
            )
            .unwrap()]
        );
        self.enter("terminal-snapshot")?;
        Ok(Vec::new())
    }

    async fn renew_exact(
        &self,
        target: &ClusterMucOccupancyTarget,
        node: &str,
        lease: Duration,
    ) -> Result<bool> {
        assert_eq!(Some(target), self.0.target.lock().unwrap().as_ref());
        assert_eq!(node, self.0.authority.instance_node_id);
        assert_eq!(lease, Duration::from_secs(90));
        self.enter("occupancy-renew")?;
        let gate = self.0.renew_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.await.unwrap();
        }
        Ok(false)
    }

    async fn renew_exact_batch(
        &self,
        _: &[ClusterMucOccupancyTarget],
        _: &str,
        _: Duration,
    ) -> Result<Vec<ClusterMucOccupancyTarget>> {
        panic!("unexpected batch renewal");
    }
}

fn manager() -> ClusterManager {
    let mut manager = listener_health_manager();
    manager.connection_uuid = Uuid::from_u128(55);
    manager.instance_epoch.store(7, Ordering::Release);
    manager
}

/// One recorded route-store call: operation, full JID, owner node, instance, epoch and connection.
type RouteCall = (String, String, String, Uuid, i64, Uuid);

struct SessionStore {
    calls: Mutex<Vec<RouteCall>>,
    renewed: std::result::Result<bool, &'static str>,
    replacement_epoch: AtomicI64,
    renewal_gate: Mutex<Option<oneshot::Receiver<()>>>,
}

impl SessionStore {
    fn record(&self, operation: &str, owner: ClusterSessionRouteOwner<'_>) {
        assert_eq!(owner.namespace, "listener-health.test");
        self.calls.lock().unwrap().push((
            operation.into(),
            owner.full_jid.into(),
            owner.owner_node_id.into(),
            owner.owner_instance_uuid,
            owner.owner_instance_epoch,
            owner.connection_uuid,
        ));
    }
}

impl ClusterSessionStore for SessionStore {
    fn claim_node_instance<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: i64,
        _: Duration,
    ) -> ClusterStoreFuture<'a, ClusterNodeInstance> {
        Box::pin(async { panic!("unused instance claim") })
    }

    fn admit_envelope_replay<'a>(
        &'a self,
        _: &'a str,
        _: &'a northstar_security::cluster_bus::SignedClusterEnvelope,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async { panic!("unused envelope admission") })
    }

    fn is_replay_validation_rejection(&self, _: &anyhow::Error) -> bool {
        panic!("unused replay classifier")
    }

    fn claim_session_route<'a>(
        &'a self,
        _: ClusterSessionRouteOwner<'a>,
        _: &'a str,
        _: northstar_session_core::SessionRouteClaimProof,
        _: Duration,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async { panic!("unused route claim") })
    }

    fn refresh_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
        lease: Duration,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async move {
            assert_eq!(lease, Duration::from_secs(900));
            self.record("renew", owner);
            let gate = self.renewal_gate.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.await.unwrap();
            }
            self.renewed.map_err(anyhow::Error::msg)
        })
    }

    fn release_session_route<'a>(
        &'a self,
        owner: ClusterSessionRouteOwner<'a>,
    ) -> ClusterStoreFuture<'a, bool> {
        Box::pin(async move {
            self.record("release", owner);
            Ok(self
                .replacement_epoch
                .compare_exchange(
                    owner.owner_instance_epoch,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok())
        })
    }

    fn session_route_authority<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> ClusterStoreFuture<
        'a,
        Option<northstar_session_application::session_termination_authority::SessionRouteAuthority>,
    > {
        Box::pin(async { panic!("unused route read") })
    }

    fn session_nodes_for_bare<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> ClusterStoreFuture<'a, Vec<String>> {
        Box::pin(async { panic!("unused route nodes") })
    }
}

fn store(renewed: std::result::Result<bool, &'static str>) -> Arc<SessionStore> {
    Arc::new(SessionStore {
        calls: Mutex::new(Vec::new()),
        renewed,
        replacement_epoch: AtomicI64::new(7),
        renewal_gate: Mutex::new(None),
    })
}

#[tokio::test]
async fn release_uses_captured_epoch_after_replacement() {
    let manager = manager();
    let store = store(Ok(true));
    manager.configure_session_store(store.clone()).unwrap();
    let redis = manager.maintenance_redis();
    let (finish, waiting) = oneshot::channel();
    *store.renewal_gate.lock().unwrap() = Some(waiting);
    let renew = redis.renew_authority("Alice@LISTENER-HEALTH.TEST/Phone", Uuid::from_u128(11));
    tokio::pin!(renew);
    assert!(futures::poll!(renew.as_mut()).is_pending());
    manager.instance_epoch.store(8, Ordering::Release);
    store.replacement_epoch.store(8, Ordering::Release);
    finish.send(()).unwrap();
    let token = renew.await.unwrap().unwrap();
    assert_eq!(
        token,
        SessionRouteAuthorityToken::Exact {
            owner_instance_epoch: 7
        }
    );
    redis
        .release_authority(
            "Alice@LISTENER-HEALTH.TEST/Phone",
            Uuid::from_u128(11),
            token,
        )
        .await
        .unwrap();
    assert_eq!(
        *store.calls.lock().unwrap(),
        [
            (
                "renew".into(),
                "alice@listener-health.test/Phone".into(),
                manager.node_id.clone(),
                Uuid::from_u128(55),
                7,
                Uuid::from_u128(11)
            ),
            (
                "release".into(),
                "alice@listener-health.test/Phone".into(),
                manager.node_id.clone(),
                Uuid::from_u128(55),
                7,
                Uuid::from_u128(11)
            ),
        ]
    );
    assert_eq!(store.replacement_epoch.load(Ordering::Acquire), 8);
    assert!(redis
        .release_session_authority(
            "alice@listener-health.test/Phone",
            Uuid::from_u128(11),
            SessionRouteAuthorityToken::NoCluster
        )
        .await
        .is_err());
    assert_eq!(store.calls.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn failed_authority_skips_soft_state() {
    for (label, renewed, cancelled, error) in [
        ("lost exact route", Ok(false), true, None),
        (
            "authority unavailable",
            Err("authority read failed"),
            false,
            Some("authority read failed"),
        ),
    ] {
        let manager = manager();
        let store = store(renewed);
        store.replacement_epoch.store(8, Ordering::Release);
        manager.configure_session_store(store.clone()).unwrap();
        let redis = manager.maintenance_redis();
        let service = SessionRouteRenewalService::new(redis.clone());
        let disconnect = CancellationToken::new();
        let attempt = service.renew_all(vec![SessionRouteLease {
            full_jid: "alice@listener-health.test/Phone".into(),
            activity_age_seconds: 13,
            connection_id: Uuid::from_u128(11),
            disconnect: disconnect.clone(),
        }]);
        tokio::pin!(attempt);
        // A Redis projection would need to acquire/connect the lazy pool and
        // make this poll pending. The failed PostgreSQL authority returns
        // immediately and never even starts a connection.
        let result = ready(futures::poll!(attempt.as_mut()), label);
        match error {
            Some(message) => assert_eq!(result.unwrap_err().to_string(), message, "{label}"),
            None => result.unwrap(),
        }
        assert_eq!(disconnect.is_cancelled(), cancelled, "{label}");
        assert_eq!(
            store.replacement_epoch.load(Ordering::Acquire),
            8,
            "{label}"
        );
        assert_eq!(
            *store.calls.lock().unwrap(),
            [(
                "renew".into(),
                "alice@listener-health.test/Phone".into(),
                manager.node_id.clone(),
                Uuid::from_u128(55),
                7,
                Uuid::from_u128(11)
            )],
            "{label}"
        );
        let state = redis.pool.as_ref().unwrap().state();
        assert_eq!(state.connections, 0, "{label}");
    }
}

#[tokio::test(start_paused = true)]
async fn muc_renew_uses_snapshot_incarnation() {
    let manager = manager();
    manager.note_listener_generation();
    let fixture = Fixture::new();
    let ports = AuthorityPorts::new(manager.readiness_authority_snapshot().unwrap(), "");
    let target = ClusterMucOccupancyTarget {
        room_id: Uuid::from_u128(4),
        room_epoch: Uuid::from_u128(5),
        occupant_incarnation: fixture.recipient.cluster_epoch,
        occupancy_epoch: 23,
        full_jid: fixture.recipient.full_jid.clone(),
        nick: fixture.recipient.nick.clone(),
        connection_uuid: fixture.recipient.connection_id,
        connection_epoch: 29,
    };
    *ports.0.target.lock().unwrap() = Some(target);
    let (finish, waiting) = oneshot::channel();
    *ports.0.renew_gate.lock().unwrap() = Some(waiting);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
        .unwrap();
    let replay = recovery_replay_wake::ClusterRecoveryReplayWake {
        sessions: Arc::default(),
        replay: northstar_session_application::replay::ReplayService::new(
            northstar_session_postgres::replay_repository::PostgresReplayRepository::new(
                pool.clone(),
            ),
            "example.test",
            30,
        ),
        admission: manager.admission(),
        store: northstar_session_postgres::replay_repository::PostgresRecoveryReplayStore::new(
            pool,
        ),
        metrics: Arc::default(),
        permits: Arc::new(tokio::sync::Semaphore::new(0)),
    };
    let mut redis = manager.maintenance_redis();
    redis.pool = None;
    let context = maintenance_context::ClusterMaintenanceContext::<Adapters> {
        control: manager.maintenance_control(),
        redis: redis.clone(),
        session_routes: SessionRouteRenewalService::new(redis),
        locals: maintenance_locals::ClusterMaintenanceLocals {
            sessions: Arc::default(),
            occupants: Arc::clone(&fixture.worker.endpoints.occupants),
            metrics: Arc::default(),
        },
        replay_wake: replay.clone(),
        direct_spool_wake: direct_spool_wake::DirectSpoolWakeConsumer::new(
            northstar_message_application::direct_spool_wake::DirectSpoolWakeService::new(
                UnusedPorts,
            ),
            replay,
        ),
        session_authority: SessionAuthoritySweepService::new(ports.clone()),
        cluster_authority: ClusterAuthorityService::new(ports.clone()),
        muc_occupancy: ClusterMucOccupancyMaintenanceService::new(ports.clone()),
    };
    let pass = workers::maintenance_once(&context);
    tokio::pin!(pass);
    assert!(futures::poll!(pass.as_mut()).is_pending());
    assert_eq!(
        ports.0.calls.lock().unwrap().last(),
        Some(&"occupancy-renew")
    );
    let mut replacement = fixture.recipient.clone();
    replacement.cluster_epoch = Uuid::from_u128(101);
    replacement.connection_id = Uuid::from_u128(102);
    let key =
        northstar_room_core::stanza::muc_occupant_key(&replacement.room_jid, &replacement.nick);
    context
        .locals
        .occupants
        .insert(key.clone(), replacement.clone());
    finish.send(()).unwrap();
    pass.await.unwrap();
    assert_eq!(
        context.locals.occupants.get(&key).unwrap().cluster_epoch,
        replacement.cluster_epoch
    );
    assert_eq!(
        context.locals.occupants.get(&key).unwrap().connection_id,
        replacement.connection_id
    );
    assert_eq!(
        *ports.0.calls.lock().unwrap(),
        [
            "peer-validation",
            "peer-keys",
            "instances",
            "occupancy-snapshot",
            "occupancy-renew",
            "terminal-snapshot"
        ]
    );
    assert_eq!(
        context
            .locals
            .metrics
            .cluster_muc_pg_reconciliations_total
            .load(Ordering::Relaxed),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn listener_old_generation_never_activates() {
    for (label, prove_replacement_first) in [
        ("same generation rotated", false),
        ("new generation proved", true),
    ] {
        let manager = manager();
        let transport = manager.pubsub_listener_transport();
        let admission = manager.listener_admission();
        let (old, old_epoch) = manager.health.begin_listener_attempt();
        let (probe, received) = oneshot::channel();
        // Hold a selected probe before entering the real transport confirmation.
        let confirmation = async {
            received.await.unwrap();
            transport.confirm_generation(old, old_epoch)
        };
        tokio::pin!(confirmation);
        assert!(
            futures::poll!(confirmation.as_mut()).is_pending(),
            "{label}"
        );
        if prove_replacement_first {
            // A competing subscription can prove the first generation while
            // the original selected probe is still delayed.
            transport.confirm_generation(old, old_epoch).unwrap();
        }
        transport.record_listener_failure(&anyhow::anyhow!("replace pending subscription"));
        let (replacement, replacement_epoch) = manager.health.begin_listener_attempt();
        assert_ne!(replacement_epoch, old_epoch, "{label}");
        if prove_replacement_first {
            assert!(replacement > old, "{label}");
            transport
                .confirm_generation(replacement, replacement_epoch)
                .unwrap();
        }
        let proven = manager.health.listener_generation.load(Ordering::Acquire);
        probe.send(()).unwrap();
        assert!(confirmation.await.is_err(), "{label}");
        assert_eq!(
            manager.health.listener_generation.load(Ordering::Acquire),
            proven,
            "{label}"
        );
        assert!(
            admission.validate_generation(old, old_epoch).is_err(),
            "{label}"
        );
        if !prove_replacement_first {
            transport
                .confirm_generation(replacement, replacement_epoch)
                .unwrap();
        }
        assert!(
            admission
                .validate_generation(replacement, replacement_epoch)
                .is_ok(),
            "{label}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn failure_supervisor_returns_before_parent_cancel() {
    for (label, failure, expected) in [
        ("local authority", "key", vec!["key"]),
        (
            "replay cleanup",
            "replay-cleanup",
            vec!["key", "instances", "instance-heartbeat", "replay-cleanup"],
        ),
        (
            "replay validation",
            "replay-validation",
            vec![
                "key",
                "instances",
                "instance-heartbeat",
                "replay-cleanup",
                "replay-validation",
            ],
        ),
        (
            "route cleanup",
            "route-cleanup",
            vec![
                "key",
                "instances",
                "instance-heartbeat",
                "replay-cleanup",
                "replay-validation",
                "route-cleanup",
            ],
        ),
        (
            "route validation",
            "route-validation",
            vec![
                "key",
                "instances",
                "instance-heartbeat",
                "replay-cleanup",
                "replay-validation",
                "route-cleanup",
                "route-validation",
            ],
        ),
    ] {
        let manager = manager();
        let authority = manager.failure_supervisor_authority();
        let ports = AuthorityPorts::new(authority.readiness_snapshot().unwrap(), failure);
        let context = Arc::new(
            failure_supervisor_context::ClusterFailureSupervisorContext::<Adapters> {
                authority,
                authority_service: ClusterAuthorityService::new(ports.clone()),
                replay_maintenance: ClusterReplayMaintenanceService::new(ports.clone()),
                route_maintenance: ClusterSessionRouteMaintenanceService::new(ports.clone()),
            },
        );
        let parent = CancellationToken::new();
        let heartbeat = HeartbeatFixture::new().await;
        let result =
            run_failure_supervisor(context, parent.clone(), heartbeat.heartbeat.clone()).await;
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("PostgreSQL cluster key/instance authority was lost"),
            "{label}: {error}"
        );
        assert!(
            error.contains(&format!("injected {failure} failure")),
            "{label}: {error}"
        );
        assert_eq!(
            manager.health.state.load(Ordering::Acquire),
            CLUSTER_SHUTDOWN_REQUIRED,
            "{label}"
        );
        assert!(
            !parent.is_cancelled(),
            "{label}: registry owns parent cancellation"
        );
        assert_eq!(*ports.0.calls.lock().unwrap(), expected, "{label}");
        heartbeat.finish().await;
    }
}
