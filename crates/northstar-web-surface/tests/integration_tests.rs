//! Comprehensive integration tests for `northstar-web-surface`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use northstar_web_surface::{
    default_static_assets, resolve_web_surface, AdjustmentReason, AdminSecurityContext, AssetScope,
    CapabilityId, DownloadCeiling, ListenerConfiguration, ListenerRole, RegistrationDependencyLock,
    RegistrationMode, RegistrationTransitionError, RequestedWebCapabilities, ResolutionError,
    StaticAsset, SurfaceId, UploadMode, UploadRuntimeFacts,
};

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

fn v6(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
}

#[test]
fn test_default_capability_graph() {
    let req = RequestedWebCapabilities::default();
    let res = resolve_web_surface(&req).expect("default capabilities must resolve successfully");

    // All surfaces active by default
    assert!(res.user_rest);
    assert!(res.websocket);
    assert!(res.bosh);
    assert!(res.web_client);
    assert!(res.web_admin);
    assert_eq!(res.upload_mode, UploadMode::Enabled);
    assert!(res.observability);
    assert_eq!(res.registration_mode(), RegistrationMode::Closed);
    assert!(!res.is_registration_locked());

    for surface in SurfaceId::ALL {
        assert!(
            res.is_surface_enabled(surface),
            "Surface {:?} should be enabled by default",
            surface
        );
    }

    // Default listeners
    assert!(res.listeners.public.is_some());
    assert_eq!(
        res.listeners.public.as_ref().unwrap().bind_addr,
        v4(0, 0, 0, 0, 5280)
    );
    assert!(res.listeners.admin.is_some());
    assert_eq!(
        res.listeners.admin.as_ref().unwrap().bind_addr,
        v4(127, 0, 0, 1, 8081)
    );
    assert!(res.listeners.observability.is_none());

    // Upload subsystems
    let upload = res.upload_subsystems();
    assert!(upload.slot_admission);
    assert!(upload.put);
    assert!(upload.get);
    assert!(upload.cleanup_worker);
    assert!(upload.reconciliation_worker);
    assert!(upload.xmpp_advertisement);

    // No adjustments in default graph
    assert!(!res.has_adjustments());
    assert_eq!(res.adjustments().len(), 0);
}

#[test]
fn test_upload_mode_lifecycle_and_subsystem_permissions() {
    // 1. Enabled mode: everything active
    let req_enabled = RequestedWebCapabilities::default().with_upload_mode(UploadMode::Enabled);
    let res_enabled = req_enabled.resolve().unwrap();
    let up = res_enabled.upload_subsystems();
    assert!(up.slot_admission);
    assert!(up.put);
    assert!(up.get);
    assert!(up.cleanup_worker);
    assert!(up.reconciliation_worker);
    assert!(up.xmpp_advertisement);
    assert!(res_enabled.is_surface_enabled(SurfaceId::HttpUpload));

    // 2. DrainReadOnly mode: reject new uploads & disco, retain GET and cleanup/reconciliation workers
    let req_drain = RequestedWebCapabilities::default()
        .with_upload_mode(UploadMode::DrainReadOnly)
        .with_upload_ceiling(DownloadCeiling::with_concurrency(200 * 1024 * 1024, 32));
    let res_drain = req_drain.resolve().unwrap();
    let up_drain = res_drain.upload_subsystems();
    assert!(!up_drain.slot_admission);
    assert!(!up_drain.put);
    assert!(up_drain.get);
    assert!(up_drain.cleanup_worker);
    assert!(up_drain.reconciliation_worker);
    assert!(!up_drain.xmpp_advertisement);
    assert_eq!(up_drain.download_ceiling.max_bytes, 200 * 1024 * 1024);
    assert_eq!(up_drain.download_ceiling.max_concurrent_streams, Some(32));
    assert!(res_drain.is_surface_enabled(SurfaceId::HttpUpload));
    assert!(res_drain
        .adjustments()
        .iter()
        .any(|a| a.capability == CapabilityId::HttpUpload
            && a.reason == AdjustmentReason::UploadDrainingReadOnly));

    // 3. Disabled mode with unproven facts produces a pending startup plan;
    // AppState must prove the durable and object-store authorities clean.
    let req_dis_unknown = RequestedWebCapabilities::default()
        .with_upload_mode(UploadMode::Disabled)
        .with_upload_facts(UploadRuntimeFacts::unknown());
    let pending = req_dis_unknown.resolve().unwrap();
    assert_eq!(pending.upload_mode, UploadMode::Disabled);
    assert!(pending.upload_disable_requires_runtime_proof);
    assert!(!pending.is_surface_enabled(SurfaceId::HttpUpload));

    let req_dis_retained = RequestedWebCapabilities::default()
        .with_upload_mode(UploadMode::Disabled)
        .with_upload_facts(UploadRuntimeFacts::with_counts(5, 0, 0));
    let err_retained = req_dis_retained.resolve().unwrap_err();
    assert!(matches!(
        err_retained,
        ResolutionError::CannotDisableUploadWithRetainedData {
            retained_objects: Some(5),
            pending_jobs: Some(0),
            backlog: Some(0),
            ..
        }
    ));

    // 4. Disabled mode with proven clean facts -> succeeds with all subsystems inactive
    let req_dis_clean = RequestedWebCapabilities::default()
        .with_upload_mode(UploadMode::Disabled)
        .with_upload_facts(UploadRuntimeFacts::empty());
    let res_dis_clean = req_dis_clean.resolve().unwrap();
    let up_clean = res_dis_clean.upload_subsystems();
    assert!(!up_clean.slot_admission);
    assert!(!up_clean.put);
    assert!(!up_clean.get);
    assert!(!up_clean.cleanup_worker);
    assert!(!up_clean.reconciliation_worker);
    assert!(!up_clean.xmpp_advertisement);
    assert!(!res_dis_clean.is_surface_enabled(SurfaceId::HttpUpload));
    assert!(res_dis_clean
        .adjustments()
        .iter()
        .any(|a| a.capability == CapabilityId::HttpUpload
            && a.reason == AdjustmentReason::UploadFullyDisabled));
}

#[test]
fn test_registration_authority_and_runtime_transition_lock() {
    // When WebClient is disabled while InvitationOnly was requested:
    let req = RequestedWebCapabilities::default()
        .with_web_client(false)
        .with_registration(RegistrationMode::InvitationOnly);

    let res = req.resolve().expect("must resolve fail-closed");
    assert_eq!(res.registration_mode(), RegistrationMode::Closed);
    assert!(res.is_registration_locked());

    // Proof: Admin/runtime cannot bypass fail-closed lock by transitioning to Open
    let err_open = res
        .validate_registration_transition(RegistrationMode::Open)
        .unwrap_err();
    assert!(matches!(
        err_open,
        RegistrationTransitionError::LockedByMissingDependency {
            current: RegistrationMode::Closed,
            attempted: RegistrationMode::Open,
            lock: RegistrationDependencyLock::LockedWebClientDisabled,
            ..
        }
    ));

    // Proof: Admin/runtime cannot transition to InvitationOnly either
    let err_inv = res
        .validate_registration_transition(RegistrationMode::InvitationOnly)
        .unwrap_err();
    assert!(matches!(
        err_inv,
        RegistrationTransitionError::LockedByMissingDependency {
            current: RegistrationMode::Closed,
            attempted: RegistrationMode::InvitationOnly,
            lock: RegistrationDependencyLock::LockedWebClientDisabled,
            ..
        }
    ));

    // Clamping to Closed is valid
    let closed = res
        .validate_registration_transition(RegistrationMode::Closed)
        .expect("clamping to Closed is permitted");
    assert_eq!(closed.mode, RegistrationMode::Closed);
    assert!(closed.lock.is_locked());

    // Normal case: WebClient enabled + InvitationOnly -> Unlocked
    let req_normal = RequestedWebCapabilities::default()
        .with_web_client(true)
        .with_registration(RegistrationMode::InvitationOnly);
    let res_normal = req_normal.resolve().unwrap();
    assert_eq!(
        res_normal.registration_mode(),
        RegistrationMode::InvitationOnly
    );
    assert!(!res_normal.is_registration_locked());

    let runtime_open = res_normal
        .validate_registration_transition(RegistrationMode::Open)
        .expect("unlocked transition to Open is allowed");
    assert_eq!(runtime_open.mode, RegistrationMode::Open);
}

#[test]
fn test_impossible_client_combinations_are_typed_errors() {
    // Impossible 1: WebClient requested, but UserRest false
    let req = RequestedWebCapabilities::default()
        .with_user_rest(false)
        .with_web_client(true);
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::MissingWebClientDependency {
            missing: CapabilityId::UserRest,
            detail: "Web client requires end-user REST API to be enabled",
        }
    );

    // Impossible 2: WebClient requested, but WebSocket false
    let req = RequestedWebCapabilities::default()
        .with_websocket(false)
        .with_web_client(true);
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::MissingWebClientDependency {
            missing: CapabilityId::WebSocket,
            detail: "Web client requires WebSocket transport to be enabled",
        }
    );
}

#[test]
fn test_bind_address_collisions() {
    // 1. Public and Admin collide
    let collision_addr = v4(127, 0, 0, 1, 9000);
    let req = RequestedWebCapabilities::default()
        .with_listeners(ListenerConfiguration::new(collision_addr, collision_addr));
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::ListenerAddressCollision {
            first: ListenerRole::Public,
            second: ListenerRole::Admin,
            addr: collision_addr,
        }
    );

    // 2. Public and Dedicated Observability collide
    let pub_addr = v4(0, 0, 0, 0, 5280);
    let req = RequestedWebCapabilities::default()
        .with_listeners(ListenerConfiguration::default().with_observability_addr(Some(pub_addr)));
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::ListenerAddressCollision {
            first: ListenerRole::Public,
            second: ListenerRole::Observability,
            addr: pub_addr,
        }
    );

    // 3. Admin and Dedicated Observability collide
    let adm_addr = v4(127, 0, 0, 1, 8081);
    let req = RequestedWebCapabilities::default()
        .with_listeners(ListenerConfiguration::default().with_observability_addr(Some(adm_addr)));
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::ListenerAddressCollision {
            first: ListenerRole::Admin,
            second: ListenerRole::Observability,
            addr: adm_addr,
        }
    );
}

#[test]
fn test_non_loopback_admin_requirements() {
    let non_loopback = v4(10, 0, 1, 5, 8081);

    // 1. Non-loopback with no security -> fails
    let req = RequestedWebCapabilities::default().with_listeners(ListenerConfiguration::new(
        v4(0, 0, 0, 0, 5280),
        non_loopback,
    ));
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::UnsafeNonLoopbackAdminExposure {
            bind_addr: non_loopback,
            missing_trusted_proxy: false,
            missing_gateway_credential: false,
        }
    );

    // 2. Non-loopback with proxy only -> fails
    let req = RequestedWebCapabilities::default().with_listeners(
        ListenerConfiguration::new(v4(0, 0, 0, 0, 5280), non_loopback)
            .with_admin_security(AdminSecurityContext::new(true, false)),
    );
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::UnsafeNonLoopbackAdminExposure {
            bind_addr: non_loopback,
            missing_trusted_proxy: false,
            missing_gateway_credential: false,
        }
    );

    // 3. Non-loopback with credential only -> fails
    let req = RequestedWebCapabilities::default().with_listeners(
        ListenerConfiguration::new(v4(0, 0, 0, 0, 5280), non_loopback)
            .with_admin_security(AdminSecurityContext::new(false, true)),
    );
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::UnsafeNonLoopbackAdminExposure {
            bind_addr: non_loopback,
            missing_trusted_proxy: false,
            missing_gateway_credential: false,
        }
    );

    // 4. Proxy assertions and an application credential do not make a
    // plaintext non-loopback listener equivalent to a local control plane.
    let req = RequestedWebCapabilities::default().with_listeners(
        ListenerConfiguration::new(v4(0, 0, 0, 0, 5280), non_loopback)
            .with_admin_security(AdminSecurityContext::new(true, true)),
    );
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::UnsafeNonLoopbackAdminExposure {
            bind_addr: non_loopback,
            missing_trusted_proxy: false,
            missing_gateway_credential: false,
        }
    );

    // 5. IPv6 loopback [::1] succeeds without special credentials
    let req_v6 = RequestedWebCapabilities::default()
        .with_listeners(ListenerConfiguration::new(v4(0, 0, 0, 0, 5280), v6(8081)));
    assert!(req_v6.resolve().is_ok());
}

#[test]
fn test_asset_scope_segregation_and_route_conflicts() {
    let mut assets = default_static_assets();
    assets.push(StaticAsset::new(
        "/styles.css",
        AssetScope::Shared,
        "text/css",
    ));
    let req = RequestedWebCapabilities::default().with_assets(assets);
    let err = req.resolve().unwrap_err();
    assert_eq!(
        err,
        ResolutionError::AmbiguousAssetRoute {
            path: "/styles.css".into(),
            surface: SurfaceId::WebClientAssets,
        }
    );

    let res = RequestedWebCapabilities::default().resolve().unwrap();
    let client_paths = res.assets.client_visible_paths();
    let admin_paths = res.assets.admin_visible_paths();

    assert!(!client_paths.contains(&"/admin.css"));
    assert!(!client_paths.contains(&"/admin/index.html"));
    assert!(!client_paths.contains(&"/admin/admin.js"));

    assert!(client_paths.contains(&"/client.js"));
    assert!(client_paths.contains(&"/styles.css"));

    assert!(admin_paths.contains(&"/admin.css"));
    assert!(admin_paths.contains(&"/styles.css"));
    assert!(!admin_paths.contains(&"/client.js"));
}
