use super::*;
use crate::startup_authority::ClusterKeyDeploymentPort;

struct RecordingInstanceReleaseRepository {
    calls: Mutex<Vec<ClusterInstanceReleaseIdentity>>,
    result: std::result::Result<bool, &'static str>,
    completion: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl ClusterInstanceReleaseRepository for &RecordingInstanceReleaseRepository {
    async fn release(&self, identity: &ClusterInstanceReleaseIdentity) -> Result<bool> {
        self.calls.lock().unwrap().push(identity.clone());
        let completion = self.completion.lock().unwrap().take();
        if let Some(completion) = completion {
            completion.await.unwrap();
        }
        self.result.map_err(anyhow::Error::msg)
    }
}

#[tokio::test(start_paused = true)]
async fn release_waits_for_publications_and_times_out_without_releasing() {
    let manager = listener_health_manager();
    manager.begin_shutdown();
    let _publication = manager.publication_gate.read().await;
    let repository = RecordingInstanceReleaseRepository {
        calls: Mutex::new(Vec::new()),
        result: Ok(true),
        completion: Mutex::new(None),
    };
    let service = ClusterInstanceReleaseService::new(&repository);

    assert!(manager
        .release_instance_after_publication_quiescence(Duration::from_millis(20), &service)
        .await
        .is_none());
    assert!(repository.calls.lock().unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn release_holds_the_publication_fence_until_the_release_finishes() {
    let manager = listener_health_manager();
    manager.begin_shutdown();
    let (finish, completion) = tokio::sync::oneshot::channel();
    let repository = RecordingInstanceReleaseRepository {
        calls: Mutex::new(Vec::new()),
        result: Ok(true),
        completion: Mutex::new(Some(completion)),
    };
    let service = ClusterInstanceReleaseService::new(&repository);
    let release =
        manager.release_instance_after_publication_quiescence(Duration::from_millis(20), &service);
    tokio::pin!(release);

    assert!(futures::poll!(release.as_mut()).is_pending());
    assert_eq!(repository.calls.lock().unwrap().len(), 1);
    assert!(manager.publication_gate.try_read().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(futures::poll!(release.as_mut()).is_pending());
    assert!(manager.publication_gate.try_read().is_err());

    finish.send(()).unwrap();
    release.await.unwrap().unwrap();
    assert!(manager.publication_gate.try_read().is_ok());
}

#[tokio::test]
async fn release_maps_committed_absent_and_error_outcomes() {
    let manager = listener_health_manager();
    manager.begin_shutdown();
    for expected in [Ok(true), Ok(false), Err("lease release failed")] {
        let repository = RecordingInstanceReleaseRepository {
            calls: Mutex::new(Vec::new()),
            result: expected,
            completion: Mutex::new(None),
        };
        let service = ClusterInstanceReleaseService::new(&repository);
        let actual = manager
            .release_instance_after_publication_quiescence(Duration::from_millis(20), &service)
            .await
            .unwrap();
        match expected {
            Ok(_) => actual.unwrap(),
            Err(message) => assert_eq!(actual.unwrap_err().to_string(), message),
        }
        assert_eq!(repository.calls.lock().unwrap().len(), 1);
        assert!(manager.publication_gate.try_read().is_ok());
    }
}

#[tokio::test]
async fn standalone_pg_muc_authority_requires_disabled_cluster() {
    let disabled = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    assert!(disabled.standalone_pg_muc_authority());

    let enabled = listener_health_manager();
    assert!(!enabled.standalone_pg_muc_authority());
}

struct RecordingStartupAuthority {
    events: Mutex<Vec<String>>,
    fail_at: Option<String>,
}

impl RecordingStartupAuthority {
    fn new(fail_at: Option<String>) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_at,
        }
    }

    fn record(&self, event: String) -> Result<()> {
        self.events.lock().unwrap().push(event.clone());
        anyhow::ensure!(
            self.fail_at.as_ref() != Some(&event),
            "startup authority failed at {event}"
        );
        Ok(())
    }
}

impl ClusterKeyDeploymentPort for RecordingStartupAuthority {
    async fn reconcile_before_instance_claim(
        &self,
        identity: &ClusterKeyDeploymentIdentity,
    ) -> Result<()> {
        self.record(format!("prepare:{}", identity.node_id))
    }

    async fn reconcile_peer(&self, peer: &ClusterKeyDeploymentIdentity) -> Result<()> {
        self.record(format!("peer:{}", peer.node_id))
    }

    async fn finalize(&self, identity: &ClusterKeyDeploymentIdentity) -> Result<()> {
        self.record(format!("finalize:{}", identity.node_id))
    }
}

impl ClusterAuthorityRepository for &RecordingStartupAuthority {
    async fn validate_cluster_key(&self, _: &ClusterKeyDeploymentIdentity) -> Result<()> {
        self.record("validate-cluster-key".into())
    }

    async fn validate_peer_keys(&self, _: &str, _: &[ExpectedClusterPeerKey]) -> Result<()> {
        self.record("refresh".into())
    }

    async fn peer_keys(&self, _: &str, _: &[String]) -> Result<Vec<ClusterPeerKeyAuthority>> {
        self.record("peer-keys".into())?;
        Ok(Vec::new())
    }

    async fn active_instances(&self, _: &str, _: &[String]) -> Result<Vec<ClusterNodeInstance>> {
        self.record("active-instances".into())?;
        Ok(Vec::new())
    }

    async fn heartbeat_instance(&self, _: &ClusterReadinessAuthority, _: Duration) -> Result<()> {
        self.record("heartbeat".into())
    }
}

fn startup_authority_manager() -> ClusterManager {
    let namespace = "startup-authority.test";
    let (security, _) = northstar_security::cluster_bus::test_configuration_pair(namespace);
    verification_manager(namespace, security)
}

#[tokio::test]
async fn startup_authority_runs_prepare_peers_claim_finalize_refresh_in_order() {
    let manager = startup_authority_manager();
    assert!(!manager.is_enabled());
    let identity = manager.key_authority_identity().unwrap();
    let peers = manager.peer_key_authority_identities();
    assert_eq!(peers.len(), 1);
    let recording = RecordingStartupAuthority::new(None);
    let authority = ClusterAuthorityService::new(&recording);

    manager
        .establish_startup_authority(&recording, &authority)
        .await
        .unwrap();

    let mut expected = vec![format!("prepare:{}", identity.node_id)];
    expected.extend(peers.iter().map(|peer| format!("peer:{}", peer.node_id)));
    expected.extend([
        format!("finalize:{}", identity.node_id),
        "refresh".into(),
        "peer-keys".into(),
        "active-instances".into(),
    ]);
    assert_eq!(*recording.events.lock().unwrap(), expected);
}

#[tokio::test]
async fn startup_authority_preparation_failure_stops_before_peers() {
    let manager = startup_authority_manager();
    let identity = manager.key_authority_identity().unwrap();
    assert!(!manager.peer_key_authority_identities().is_empty());
    let prepare = format!("prepare:{}", identity.node_id);
    let recording = RecordingStartupAuthority::new(Some(prepare.clone()));
    let authority = ClusterAuthorityService::new(&recording);

    let error = manager
        .establish_startup_authority(&recording, &authority)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "cluster signing-key authority preparation failed"
    );
    assert_eq!(
        format!("{error:#}"),
        format!("cluster signing-key authority preparation failed: startup authority failed at {prepare}")
    );
    assert_eq!(*recording.events.lock().unwrap(), vec![prepare]);
}

#[tokio::test]
async fn startup_authority_peer_failure_names_the_peer_and_stops() {
    let manager = startup_authority_manager();
    let identity = manager.key_authority_identity().unwrap();
    let peers = manager.peer_key_authority_identities();
    // The existing configuration-pair fixture provides exactly one peer.
    assert_eq!(peers.len(), 1);
    let peer = &peers[0];
    let peer_event = format!("peer:{}", peer.node_id);
    let recording = RecordingStartupAuthority::new(Some(peer_event.clone()));
    let authority = ClusterAuthorityService::new(&recording);

    let error = manager
        .establish_startup_authority(&recording, &authority)
        .await
        .unwrap_err();

    let context = format!(
        "configured cluster peer {} key authority is inconsistent",
        peer.node_id
    );
    assert_eq!(error.to_string(), context);
    assert_eq!(
        format!("{error:#}"),
        format!("{context}: startup authority failed at {peer_event}")
    );
    assert_eq!(
        *recording.events.lock().unwrap(),
        vec![format!("prepare:{}", identity.node_id), peer_event]
    );
}

#[tokio::test]
async fn startup_authority_claim_failure_stops_before_finalize() {
    let manager = listener_health_manager();
    assert!(manager.is_enabled());
    assert!(manager.session_store.get().is_none());
    let identity = manager.key_authority_identity().unwrap();
    let recording = RecordingStartupAuthority::new(None);
    let authority = ClusterAuthorityService::new(&recording);

    let error = manager
        .establish_startup_authority(&recording, &authority)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "cluster node ID is already owned by another live process"
    );
    assert_eq!(
        format!("{error:#}"),
        "cluster node ID is already owned by another live process: cluster session authority pool is unavailable"
    );
    let mut expected = vec![format!("prepare:{}", identity.node_id)];
    expected.extend(
        manager
            .peer_key_authority_identities()
            .iter()
            .map(|peer| format!("peer:{}", peer.node_id)),
    );
    assert_eq!(*recording.events.lock().unwrap(), expected);
}

#[tokio::test]
async fn startup_authority_finalize_and_refresh_failures_keep_their_context() {
    let manager = startup_authority_manager();
    let identity = manager.key_authority_identity().unwrap();
    let finalize = format!("finalize:{}", identity.node_id);
    for (fail_at, context) in [
        (
            finalize.clone(),
            "cluster signing-key authority finalization failed",
        ),
        (
            "refresh".into(),
            "could not load peer cluster instance authority",
        ),
    ] {
        let recording = RecordingStartupAuthority::new(Some(fail_at.clone()));
        let authority = ClusterAuthorityService::new(&recording);

        let error = manager
            .establish_startup_authority(&recording, &authority)
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), context);
        assert_eq!(
            format!("{error:#}"),
            format!("{context}: startup authority failed at {fail_at}")
        );
        let mut expected = vec![format!("prepare:{}", identity.node_id)];
        expected.extend(
            manager
                .peer_key_authority_identities()
                .iter()
                .map(|peer| format!("peer:{}", peer.node_id)),
        );
        expected.push(finalize.clone());
        if fail_at == "refresh" {
            expected.push("refresh".into());
        }
        assert_eq!(*recording.events.lock().unwrap(), expected);
    }
}

#[tokio::test]
async fn startup_authority_without_identity_only_activates() {
    let disabled = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    assert!(!disabled.is_enabled());
    assert!(disabled.key_authority_identity().is_none());
    let recording = RecordingStartupAuthority::new(None);
    let authority = ClusterAuthorityService::new(&recording);

    disabled
        .establish_startup_authority(&recording, &authority)
        .await
        .unwrap();
    assert!(recording.events.lock().unwrap().is_empty());

    let mut enabled = listener_health_manager();
    enabled.security = None;
    enabled.instance_epoch.store(0, Ordering::Release);
    assert!(enabled.is_enabled());
    assert!(enabled.key_authority_identity().is_none());

    let error = enabled
        .establish_startup_authority(&recording, &authority)
        .await
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "failed to publish the initial signed cluster node lease"
    );
    assert_eq!(
        format!("{error:#}"),
        "failed to publish the initial signed cluster node lease: cluster node instance authority was not claimed"
    );
    assert!(recording.events.lock().unwrap().is_empty());
}
