//! Deterministic web surface dependency resolution and capability validation engine.

use std::collections::BTreeSet;

use crate::asset::{AssetScope, ResolvedAssets};
use crate::capability::{
    AdjustmentReason, CapabilityId, EffectiveAdjustment, RegistrationDependencyLock,
    RegistrationMode, RequestedWebCapabilities, ResolvedRegistrationPolicy,
    ResolvedWebCapabilities, UploadMode, UploadSubsystems,
};
use crate::error::ResolutionError;
use crate::listener::{ListenerRole, ResolvedListener, ResolvedListeners};
use crate::surface::SurfaceId;

/// Deterministically resolves requested web capabilities, validating dependencies,
/// upload safety invariants, listener bind collisions, non-loopback security provenance,
/// and asset boundaries.
pub fn resolve_web_surface(
    requested: &RequestedWebCapabilities,
) -> Result<ResolvedWebCapabilities, ResolutionError> {
    // 1. Dependency validation: Web client requires end-user REST and WebSocket.
    // Explicit impossible combinations return a typed error, never silently enabled.
    if requested.web_client {
        if !requested.user_rest {
            return Err(ResolutionError::MissingWebClientDependency {
                missing: CapabilityId::UserRest,
                detail: "Web client requires end-user REST API to be enabled",
            });
        }
        if !requested.websocket {
            return Err(ResolutionError::MissingWebClientDependency {
                missing: CapabilityId::WebSocket,
                detail: "Web client requires WebSocket transport to be enabled",
            });
        }
    }

    // 2. Upload mode resolution and safety facts verification.
    let mut adjustments = Vec::new();

    let effective_upload_mode =
        if !requested.upload_protocol && requested.upload_mode == UploadMode::Enabled {
            adjustments.push(EffectiveAdjustment::new(
                CapabilityId::HttpUpload,
                true,
                true,
                AdjustmentReason::UploadProtocolDisabled,
            ));
            UploadMode::DrainReadOnly
        } else {
            requested.upload_mode
        };

    let mut upload_disable_requires_runtime_proof = false;
    let upload_subsystems = match effective_upload_mode {
        UploadMode::Enabled => {
            UploadSubsystems::from_mode(UploadMode::Enabled, requested.upload_ceiling)
        }
        UploadMode::DrainReadOnly => {
            adjustments.push(EffectiveAdjustment::new(
                CapabilityId::HttpUpload,
                true,
                true,
                AdjustmentReason::UploadDrainingReadOnly,
            ));
            UploadSubsystems::from_mode(UploadMode::DrainReadOnly, requested.upload_ceiling)
        }
        UploadMode::Disabled => {
            // Disabled is ONLY resolvable when explicit runtime facts prove no retained
            // objects, pending jobs, or backlog remain.
            let has_known_retained_data = requested
                .upload_facts
                .retained_objects_count
                .is_some_and(|count| count != 0)
                || requested
                    .upload_facts
                    .pending_jobs_count
                    .is_some_and(|count| count != 0)
                || requested
                    .upload_facts
                    .backlog_count
                    .is_some_and(|count| count != 0);
            if has_known_retained_data {
                return Err(ResolutionError::CannotDisableUploadWithRetainedData {
                    retained_objects: requested.upload_facts.retained_objects_count,
                    pending_jobs: requested.upload_facts.pending_jobs_count,
                    backlog: requested.upload_facts.backlog_count,
                    recommendation: "Use UploadMode::DrainReadOnly to safely drain retained historical attachments without data loss or dangling references.",
                });
            }
            upload_disable_requires_runtime_proof = !requested.upload_facts.has_proven_clean();
            adjustments.push(EffectiveAdjustment::new(
                CapabilityId::HttpUpload,
                false,
                false,
                AdjustmentReason::UploadFullyDisabled,
            ));
            UploadSubsystems::from_mode(UploadMode::Disabled, requested.upload_ceiling)
        }
    };

    // 3. Administration is a local control-plane surface.  A forwarded
    // scheme assertion and an application token cannot make a plaintext
    // non-loopback socket equivalent to a local socket or mTLS/Unix-domain
    // transport, so this release refuses every non-loopback bind.
    if requested.web_admin {
        let admin_ip = requested.listeners.admin_addr.ip();
        if !admin_ip.is_loopback() {
            return Err(ResolutionError::UnsafeNonLoopbackAdminExposure {
                bind_addr: requested.listeners.admin_addr,
                missing_trusted_proxy: false,
                missing_gateway_credential: false,
            });
        }
    }

    // 4. Listener collision validation across all active listeners.
    let upload_surface_active =
        upload_subsystems.put || upload_subsystems.get || upload_subsystems.slot_admission;

    let public_active = requested.user_rest
        || requested.websocket
        || requested.bosh
        || requested.web_client
        || upload_surface_active
        || (requested.observability && requested.listeners.observability_addr.is_none());

    let admin_active = requested.web_admin;
    let obs_dedicated_active =
        requested.observability && requested.listeners.observability_addr.is_some();

    if public_active
        && admin_active
        && socket_addresses_overlap(
            requested.listeners.public_addr,
            requested.listeners.admin_addr,
        )
    {
        return Err(ResolutionError::ListenerAddressCollision {
            first: ListenerRole::Public,
            second: ListenerRole::Admin,
            addr: requested.listeners.public_addr,
        });
    }

    if let Some(obs_addr) = requested.listeners.observability_addr {
        if obs_dedicated_active {
            if public_active && socket_addresses_overlap(requested.listeners.public_addr, obs_addr)
            {
                return Err(ResolutionError::ListenerAddressCollision {
                    first: ListenerRole::Public,
                    second: ListenerRole::Observability,
                    addr: obs_addr,
                });
            }
            if admin_active && socket_addresses_overlap(requested.listeners.admin_addr, obs_addr) {
                return Err(ResolutionError::ListenerAddressCollision {
                    first: ListenerRole::Admin,
                    second: ListenerRole::Observability,
                    addr: obs_addr,
                });
            }
        }
    }

    // 5. Static asset ownership and route ambiguity validation.
    let mut client_assets = Vec::new();
    let mut admin_assets = Vec::new();
    let mut shared_assets = Vec::new();

    let mut client_paths = BTreeSet::new();
    let mut admin_paths = BTreeSet::new();

    for asset in &requested.assets {
        match asset.scope {
            AssetScope::ClientOnly => {
                if !client_paths.insert(&asset.uri_path) {
                    return Err(ResolutionError::AmbiguousAssetRoute {
                        path: asset.uri_path.clone(),
                        surface: SurfaceId::WebClientAssets,
                    });
                }
                client_assets.push(asset.clone());
            }
            AssetScope::AdminOnly => {
                if !admin_paths.insert(&asset.uri_path) {
                    return Err(ResolutionError::AmbiguousAssetRoute {
                        path: asset.uri_path.clone(),
                        surface: SurfaceId::WebAdmin,
                    });
                }
                admin_assets.push(asset.clone());
            }
            AssetScope::Shared => {
                if !client_paths.insert(&asset.uri_path) {
                    return Err(ResolutionError::AmbiguousAssetRoute {
                        path: asset.uri_path.clone(),
                        surface: SurfaceId::WebClientAssets,
                    });
                }
                if !admin_paths.insert(&asset.uri_path) {
                    return Err(ResolutionError::AmbiguousAssetRoute {
                        path: asset.uri_path.clone(),
                        surface: SurfaceId::WebAdmin,
                    });
                }
                shared_assets.push(asset.clone());
            }
        }
    }

    // 6. Registration single authority resolution with immutable dependency lock.
    let registration_policy =
        if requested.registration == RegistrationMode::InvitationOnly && !requested.web_client {
            // IMPORTANT security rule: if invitation-only registration was requested
            // but Web client is disabled, do NOT turn it into open registration.
            // Automatically clamp to Closed with an immutable dependency lock.
            adjustments.push(EffectiveAdjustment::new(
                CapabilityId::Registration,
                true,
                false,
                AdjustmentReason::InvitationRegistrationClosedBecauseWebClientDisabled,
            ));
            ResolvedRegistrationPolicy::new(
                RegistrationMode::Closed,
                RegistrationDependencyLock::LockedWebClientDisabled,
            )
        } else {
            ResolvedRegistrationPolicy::new(
                requested.registration,
                RegistrationDependencyLock::Unlocked,
            )
        };

    if !requested.web_admin {
        adjustments.push(EffectiveAdjustment::new(
            CapabilityId::WebAdmin,
            false,
            false,
            AdjustmentReason::AdminDeactivated,
        ));
    }

    // 7. Build resolved listeners.
    let mut resolved_public = None;
    if public_active {
        let mut public_surfaces = Vec::new();
        if requested.user_rest {
            public_surfaces.push(SurfaceId::UserRest);
        }
        if requested.websocket {
            public_surfaces.push(SurfaceId::WebSocket);
        }
        if requested.bosh {
            public_surfaces.push(SurfaceId::Bosh);
        }
        if requested.web_client {
            public_surfaces.push(SurfaceId::WebClientAssets);
        }
        if upload_surface_active {
            public_surfaces.push(SurfaceId::HttpUpload);
        }
        if requested.observability && requested.listeners.observability_addr.is_none() {
            public_surfaces.push(SurfaceId::Observability);
        }
        resolved_public = Some(ResolvedListener {
            role: ListenerRole::Public,
            bind_addr: requested.listeners.public_addr,
            surfaces: public_surfaces,
        });
    }

    let mut resolved_admin = None;
    if admin_active {
        resolved_admin = Some(ResolvedListener {
            role: ListenerRole::Admin,
            bind_addr: requested.listeners.admin_addr,
            surfaces: vec![SurfaceId::WebAdmin],
        });
    }

    let mut resolved_obs = None;
    if obs_dedicated_active {
        resolved_obs = Some(ResolvedListener {
            role: ListenerRole::Observability,
            bind_addr: requested
                .listeners
                .observability_addr
                .expect("obs address present"),
            surfaces: vec![SurfaceId::Observability],
        });
    }

    let resolved_listeners = ResolvedListeners {
        public: resolved_public,
        admin: resolved_admin,
        observability: resolved_obs,
    };

    let resolved_assets = ResolvedAssets {
        client_assets,
        admin_assets,
        shared_assets,
    };

    Ok(ResolvedWebCapabilities {
        user_rest: requested.user_rest,
        websocket: requested.websocket,
        bosh: requested.bosh,
        web_client: requested.web_client,
        web_admin: requested.web_admin,
        upload_mode: effective_upload_mode,
        upload: upload_subsystems,
        upload_disable_requires_runtime_proof,
        observability: requested.observability,
        registration: registration_policy,
        listeners: resolved_listeners,
        assets: resolved_assets,
        adjustments,
    })
}

/// Conservative pre-bind overlap check.  Unspecified addresses own every
/// address of their family, and IPv6 unspecified is treated as dual-stack
/// because the platform's `IPV6_V6ONLY` default is not portable.
fn socket_addresses_overlap(left: std::net::SocketAddr, right: std::net::SocketAddr) -> bool {
    // Port zero delegates selection to the kernel for each independent bind.
    // It is not a shared concrete endpoint, so treating two `:0` requests as
    // a collision would reject the child-owned listener pattern used by
    // hermetic test fixtures before either listener can obtain its own port.
    if left.port() == 0 || right.port() == 0 {
        return false;
    }
    if left.port() != right.port() {
        return false;
    }
    if left.ip() == right.ip() {
        return true;
    }
    if left.ip().is_unspecified() || right.ip().is_unspecified() {
        return match (left.ip(), right.ip()) {
            (std::net::IpAddr::V4(_), std::net::IpAddr::V6(_))
            | (std::net::IpAddr::V6(_), std::net::IpAddr::V4(_)) => {
                left.ip().is_ipv6() && left.ip().is_unspecified()
                    || right.ip().is_ipv6() && right.ip().is_unspecified()
            }
            _ => true,
        };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::{default_static_assets, StaticAsset};
    use crate::capability::{DownloadCeiling, UploadRuntimeFacts};
    use crate::listener::{AdminSecurityContext, ListenerConfiguration};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    #[test]
    fn test_default_graph_resolves_all_enabled() {
        let requested = RequestedWebCapabilities::default();
        let resolved = resolve_web_surface(&requested).expect("default config must resolve");

        assert!(resolved.user_rest);
        assert!(resolved.websocket);
        assert!(resolved.bosh);
        assert!(resolved.web_client);
        assert!(resolved.web_admin);
        assert_eq!(resolved.upload_mode, UploadMode::Enabled);
        assert!(resolved.observability);
        assert_eq!(resolved.registration_mode(), RegistrationMode::Closed);
        assert!(!resolved.is_registration_locked());

        assert!(resolved.is_surface_enabled(SurfaceId::UserRest));
        assert!(resolved.is_surface_enabled(SurfaceId::WebSocket));
        assert!(resolved.is_surface_enabled(SurfaceId::Bosh));
        assert!(resolved.is_surface_enabled(SurfaceId::WebClientAssets));
        assert!(resolved.is_surface_enabled(SurfaceId::WebAdmin));
        assert!(resolved.is_surface_enabled(SurfaceId::HttpUpload));
        assert!(resolved.is_surface_enabled(SurfaceId::Observability));

        let upload_subsystems = resolved.upload_subsystems();
        assert!(upload_subsystems.slot_admission);
        assert!(upload_subsystems.put);
        assert!(upload_subsystems.get);
        assert!(upload_subsystems.cleanup_worker);
        assert!(upload_subsystems.reconciliation_worker);
        assert!(upload_subsystems.xmpp_advertisement);

        assert!(resolved.listeners.public.is_some());
        assert!(resolved.listeners.admin.is_some());
        assert!(resolved.listeners.observability.is_none()); // multiplexed on public

        assert_eq!(resolved.adjustments.len(), 0);
    }

    #[test]
    fn test_upload_modes_and_fail_closed_disable() {
        // 1. UploadMode::Enabled
        let req_enabled = RequestedWebCapabilities::default().with_upload_mode(UploadMode::Enabled);
        let res_enabled = resolve_web_surface(&req_enabled).unwrap();
        let up_enabled = res_enabled.upload_subsystems();
        assert!(up_enabled.slot_admission);
        assert!(up_enabled.put);
        assert!(up_enabled.get);
        assert!(up_enabled.cleanup_worker);
        assert!(up_enabled.reconciliation_worker);
        assert!(up_enabled.xmpp_advertisement);
        assert!(res_enabled.is_surface_enabled(SurfaceId::HttpUpload));

        // 2. UploadMode::DrainReadOnly
        let req_drain = RequestedWebCapabilities::default()
            .with_upload_mode(UploadMode::DrainReadOnly)
            .with_upload_ceiling(DownloadCeiling::with_concurrency(50 * 1024 * 1024, 10));
        let res_drain = resolve_web_surface(&req_drain).unwrap();
        let up_drain = res_drain.upload_subsystems();
        assert!(!up_drain.slot_admission, "must reject new slots");
        assert!(!up_drain.put, "must reject PUT");
        assert!(
            up_drain.get,
            "must preserve bounded GET for historical attachments"
        );
        assert!(up_drain.cleanup_worker, "must keep cleanup worker active");
        assert!(
            up_drain.reconciliation_worker,
            "must keep reconciliation worker active"
        );
        assert!(
            !up_drain.xmpp_advertisement,
            "must not advertise upload in disco"
        );
        assert_eq!(up_drain.download_ceiling.max_bytes, 50 * 1024 * 1024);
        assert_eq!(up_drain.download_ceiling.max_concurrent_streams, Some(10));
        assert!(res_drain.is_surface_enabled(SurfaceId::HttpUpload));

        // 3. UploadMode::Disabled with unknown facts -> construct a pending
        // startup plan that AppState must prove clean before listeners start.
        let req_disabled_unknown = RequestedWebCapabilities::default()
            .with_upload_mode(UploadMode::Disabled)
            .with_upload_facts(UploadRuntimeFacts::unknown());
        let pending = resolve_web_surface(&req_disabled_unknown).unwrap();
        assert_eq!(pending.upload_mode, UploadMode::Disabled);
        assert!(pending.upload_disable_requires_runtime_proof);
        assert!(!pending.is_surface_enabled(SurfaceId::HttpUpload));

        // 4. UploadMode::Disabled with non-empty retained objects -> fail closed
        let req_disabled_nonempty = RequestedWebCapabilities::default()
            .with_upload_mode(UploadMode::Disabled)
            .with_upload_facts(UploadRuntimeFacts::with_counts(12, 0, 0));
        let err_nonempty = resolve_web_surface(&req_disabled_nonempty).unwrap_err();
        assert!(matches!(
            err_nonempty,
            ResolutionError::CannotDisableUploadWithRetainedData {
                retained_objects: Some(12),
                pending_jobs: Some(0),
                backlog: Some(0),
                ..
            }
        ));

        // 5. UploadMode::Disabled with proven clean facts -> succeeds
        let req_disabled_clean = RequestedWebCapabilities::default()
            .with_upload_mode(UploadMode::Disabled)
            .with_upload_facts(UploadRuntimeFacts::empty());
        let res_clean = resolve_web_surface(&req_disabled_clean).unwrap();
        let up_clean = res_clean.upload_subsystems();
        assert!(!up_clean.slot_admission);
        assert!(!up_clean.put);
        assert!(!up_clean.get);
        assert!(!up_clean.cleanup_worker);
        assert!(!up_clean.reconciliation_worker);
        assert!(!up_clean.xmpp_advertisement);
        assert!(!res_clean.is_surface_enabled(SurfaceId::HttpUpload));
    }

    #[test]
    fn disabled_xep_0363_preserves_only_the_retained_object_drain_surface() {
        let requested = RequestedWebCapabilities::default().with_upload_protocol(false);
        let resolved = resolve_web_surface(&requested).expect("dependency plan");

        assert_eq!(resolved.upload_mode, UploadMode::DrainReadOnly);
        assert!(!resolved.upload.slot_admission);
        assert!(!resolved.upload.put);
        assert!(!resolved.upload.xmpp_advertisement);
        assert!(resolved.upload.get);
        assert!(resolved.upload.cleanup_worker);
        assert!(resolved.upload.reconciliation_worker);
        assert!(resolved
            .adjustments
            .iter()
            .any(|adjustment| { adjustment.reason == AdjustmentReason::UploadProtocolDisabled }));
    }

    #[test]
    fn test_registration_authority_and_transition_validator() {
        // Case 1: WebClient disabled, InvitationOnly requested -> clamped to Closed with immutable lock
        let req_inv_no_client = RequestedWebCapabilities::default()
            .with_web_client(false)
            .with_registration(RegistrationMode::InvitationOnly);

        let res = resolve_web_surface(&req_inv_no_client).expect("resolves fail-closed");
        assert_eq!(res.registration_mode(), RegistrationMode::Closed);
        assert!(res.is_registration_locked());

        // Attempting runtime transition to Open while locked MUST BE REJECTED
        let open_err = res
            .validate_registration_transition(RegistrationMode::Open)
            .unwrap_err();
        assert!(matches!(
            open_err,
            crate::error::RegistrationTransitionError::LockedByMissingDependency {
                current: RegistrationMode::Closed,
                attempted: RegistrationMode::Open,
                lock: RegistrationDependencyLock::LockedWebClientDisabled,
                ..
            }
        ));

        // Attempting runtime transition to InvitationOnly while locked MUST BE REJECTED
        let inv_err = res
            .validate_registration_transition(RegistrationMode::InvitationOnly)
            .unwrap_err();
        assert!(matches!(
            inv_err,
            crate::error::RegistrationTransitionError::LockedByMissingDependency {
                current: RegistrationMode::Closed,
                attempted: RegistrationMode::InvitationOnly,
                lock: RegistrationDependencyLock::LockedWebClientDisabled,
                ..
            }
        ));

        // Transition/clamp to Closed while locked is permitted
        let closed_res = res
            .validate_registration_transition(RegistrationMode::Closed)
            .expect("transition to Closed is allowed");
        assert_eq!(closed_res.mode, RegistrationMode::Closed);
        assert!(closed_res.lock.is_locked());

        let clamped = res.registration.clamp_to_closed();
        assert_eq!(clamped.mode, RegistrationMode::Closed);
        assert!(clamped.lock.is_locked());

        // Case 2: WebClient enabled, InvitationOnly requested -> Unlocked and InvitationOnly
        let req_inv_with_client = RequestedWebCapabilities::default()
            .with_web_client(true)
            .with_registration(RegistrationMode::InvitationOnly);
        let res_inv = resolve_web_surface(&req_inv_with_client).unwrap();
        assert_eq!(
            res_inv.registration_mode(),
            RegistrationMode::InvitationOnly
        );
        assert!(!res_inv.is_registration_locked());

        // Runtime transition to Open or Closed is permitted when unlocked
        let transitioned_open = res_inv
            .validate_registration_transition(RegistrationMode::Open)
            .expect("unlocked allows transition to Open");
        assert_eq!(transitioned_open.mode, RegistrationMode::Open);

        let transitioned_closed = res_inv
            .validate_registration_transition(RegistrationMode::Closed)
            .expect("unlocked allows transition to Closed");
        assert_eq!(transitioned_closed.mode, RegistrationMode::Closed);
    }

    #[test]
    fn test_web_client_explicit_impossible_combinations() {
        let req_no_rest = RequestedWebCapabilities::default()
            .with_user_rest(false)
            .with_web_client(true);
        let err1 = resolve_web_surface(&req_no_rest).unwrap_err();
        assert_eq!(
            err1,
            ResolutionError::MissingWebClientDependency {
                missing: CapabilityId::UserRest,
                detail: "Web client requires end-user REST API to be enabled",
            }
        );

        let req_no_ws = RequestedWebCapabilities::default()
            .with_websocket(false)
            .with_web_client(true);
        let err2 = resolve_web_surface(&req_no_ws).unwrap_err();
        assert_eq!(
            err2,
            ResolutionError::MissingWebClientDependency {
                missing: CapabilityId::WebSocket,
                detail: "Web client requires WebSocket transport to be enabled",
            }
        );

        let req_disabled_client = RequestedWebCapabilities::default()
            .with_web_client(false)
            .with_user_rest(false)
            .with_websocket(false);
        let resolved =
            resolve_web_surface(&req_disabled_client).expect("valid when client disabled");
        assert!(!resolved.web_client);
        assert!(!resolved.user_rest);
        assert!(!resolved.websocket);
    }

    #[test]
    fn test_administration_independent_and_can_be_disabled() {
        let req_no_admin = RequestedWebCapabilities::default().with_web_admin(false);
        let resolved = resolve_web_surface(&req_no_admin).expect("disabling admin is valid");

        assert!(!resolved.web_admin);
        assert!(resolved.web_client);
        assert!(resolved.user_rest);
        assert!(resolved.websocket);
        assert!(resolved.listeners.admin.is_none());
        assert!(resolved.listeners.public.is_some());

        assert!(resolved
            .adjustments
            .iter()
            .any(|adj| adj.capability == CapabilityId::WebAdmin
                && adj.reason == AdjustmentReason::AdminDeactivated));
    }

    #[test]
    fn test_listener_bind_collisions() {
        let same_addr = addr(127, 0, 0, 1, 8080);
        let req_collision = RequestedWebCapabilities::default()
            .with_listeners(ListenerConfiguration::new(same_addr, same_addr));
        let err = resolve_web_surface(&req_collision).unwrap_err();
        assert_eq!(
            err,
            ResolutionError::ListenerAddressCollision {
                first: ListenerRole::Public,
                second: ListenerRole::Admin,
                addr: same_addr,
            }
        );

        let req_no_admin = req_collision.with_web_admin(false);
        assert!(resolve_web_surface(&req_no_admin).is_ok());

        // Each `:0` bind is resolved by the kernel separately. It cannot
        // represent an accidental shared listener and is required for
        // child-owned test activation without a bind-close-launch race.
        let ephemeral = addr(127, 0, 0, 1, 0);
        let req_ephemeral = RequestedWebCapabilities::default()
            .with_listeners(ListenerConfiguration::new(ephemeral, ephemeral));
        assert!(resolve_web_surface(&req_ephemeral).is_ok());

        let obs_addr = addr(0, 0, 0, 0, 5280);
        let req_obs_collision = RequestedWebCapabilities::default().with_listeners(
            ListenerConfiguration::default().with_observability_addr(Some(obs_addr)),
        );
        let err_obs = resolve_web_surface(&req_obs_collision).unwrap_err();
        assert_eq!(
            err_obs,
            ResolutionError::ListenerAddressCollision {
                first: ListenerRole::Public,
                second: ListenerRole::Observability,
                addr: obs_addr,
            }
        );
    }

    #[test]
    fn test_non_loopback_admin_exposure_requirements() {
        let non_loopback = addr(0, 0, 0, 0, 8081);
        let loopback = addr(127, 0, 0, 1, 8081);

        let req_loopback = RequestedWebCapabilities::default()
            .with_listeners(ListenerConfiguration::new(addr(0, 0, 0, 0, 5280), loopback));
        assert!(resolve_web_surface(&req_loopback).is_ok());

        let req_non_loopback = RequestedWebCapabilities::default().with_listeners(
            ListenerConfiguration::new(addr(0, 0, 0, 0, 5280), non_loopback),
        );
        let err1 = resolve_web_surface(&req_non_loopback).unwrap_err();
        assert_eq!(
            err1,
            ResolutionError::UnsafeNonLoopbackAdminExposure {
                bind_addr: non_loopback,
                missing_trusted_proxy: false,
                missing_gateway_credential: false,
            }
        );

        let req_both = RequestedWebCapabilities::default().with_listeners(
            ListenerConfiguration::new(addr(0, 0, 0, 0, 5280), non_loopback)
                .with_admin_security(AdminSecurityContext::new(true, true)),
        );
        assert!(matches!(
            resolve_web_surface(&req_both),
            Err(ResolutionError::UnsafeNonLoopbackAdminExposure { .. })
        ));
    }

    #[test]
    fn test_asset_and_route_ownership_and_ambiguity() {
        let mut assets = default_static_assets();
        assets.push(StaticAsset::new(
            "/client.js",
            AssetScope::ClientOnly,
            "application/javascript",
        ));
        let req_dup = RequestedWebCapabilities::default().with_assets(assets);
        let err_dup = resolve_web_surface(&req_dup).unwrap_err();
        assert_eq!(
            err_dup,
            ResolutionError::AmbiguousAssetRoute {
                path: "/client.js".into(),
                surface: SurfaceId::WebClientAssets,
            }
        );

        let req_valid = RequestedWebCapabilities::default();
        let res = resolve_web_surface(&req_valid).expect("default assets are valid");
        let client_paths = res.assets.client_visible_paths();
        let admin_paths = res.assets.admin_visible_paths();

        assert!(client_paths.contains(&"/client.html"));
        assert!(client_paths.contains(&"/styles.css"));
        assert!(!client_paths.contains(&"/admin.css"));

        assert!(admin_paths.contains(&"/admin.css"));
        assert!(admin_paths.contains(&"/styles.css"));
        assert!(!admin_paths.contains(&"/client.html"));
    }

    #[test]
    fn test_every_disable_combination() {
        for i in 0..7 {
            let mut req = RequestedWebCapabilities::default();
            match i {
                0 => {
                    req.user_rest = false;
                    req.web_client = false;
                }
                1 => {
                    req.websocket = false;
                    req.web_client = false;
                }
                2 => req.bosh = false,
                3 => req.web_client = false,
                4 => req.web_admin = false,
                5 => {
                    req.upload_mode = UploadMode::Disabled;
                    req.upload_facts = UploadRuntimeFacts::empty();
                }
                6 => req.observability = false,
                _ => {}
            }
            let res = resolve_web_surface(&req).expect("valid combination");
            match i {
                0 => assert!(!res.user_rest),
                1 => assert!(!res.websocket),
                2 => assert!(!res.bosh),
                3 => assert!(!res.web_client),
                4 => assert!(!res.web_admin),
                5 => assert_eq!(res.upload_mode, UploadMode::Disabled),
                6 => assert!(!res.observability),
                _ => {}
            }
        }
    }

    #[test]
    fn test_deterministic_resolution() {
        let req1 = RequestedWebCapabilities::default();
        let req2 = RequestedWebCapabilities::default();
        let res1 = resolve_web_surface(&req1).unwrap();
        let res2 = resolve_web_surface(&req2).unwrap();
        assert_eq!(res1, res2);

        let mut assets_reversed = default_static_assets();
        assets_reversed.reverse();
        let req_rev = RequestedWebCapabilities::default().with_assets(assets_reversed);
        let res_rev = resolve_web_surface(&req_rev).unwrap();
        assert_eq!(
            res_rev.assets.client_assets.len(),
            res1.assets.client_assets.len()
        );
        assert_eq!(
            res_rev.assets.admin_assets.len(),
            res1.assets.admin_assets.len()
        );
        assert_eq!(
            res_rev.assets.shared_assets.len(),
            res1.assets.shared_assets.len()
        );
    }
}
