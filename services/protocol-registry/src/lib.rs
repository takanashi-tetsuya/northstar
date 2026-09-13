//! Protocol Registry service implementation.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 5.2, 6, 19.5).

use chrono::Utc;
use foundation_contracts::adapters::common::ErrorDetail;
use foundation_contracts::adapters::registry::{
    DiscoFeature, GetRouteSnapshotRequest, GetRouteSnapshotResponse, RegisterInstanceRequest,
    RegisterInstanceResponse, RouteEntry,
};
use sha2::{Digest, Sha256};
use std::sync::RwLock;

pub struct RegistryService {
    version: RwLock<u64>,
    routes: RwLock<Vec<RouteEntry>>,
    disco_features: RwLock<Vec<DiscoFeature>>,
}

impl Default for RegistryService {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryService {
    pub fn new() -> Self {
        Self {
            version: RwLock::new(1),
            routes: RwLock::new(Vec::new()),
            disco_features: RwLock::new(Vec::new()),
        }
    }

    pub fn with_default_routes(self) -> Self {
        let default_routes = vec![
            RouteEntry {
                namespace: "urn:ietf:params:xml:ns:xmpp-tls".to_string(),
                element: "starttls".to_string(),
                stanza: "starttls".to_string(),
                phase: "pre-auth".to_string(),
                service_id: "xmpp-edge".to_string(),
                endpoint: "local".to_string(),
            },
            RouteEntry {
                namespace: "urn:ietf:params:xml:ns:xmpp-sasl".to_string(),
                element: "auth".to_string(),
                stanza: "auth".to_string(),
                phase: "authenticating".to_string(),
                service_id: "identity".to_string(),
                endpoint: "http://identity:50051".to_string(),
            },
            RouteEntry {
                namespace: "urn:ietf:params:xml:ns:xmpp-bind".to_string(),
                element: "bind".to_string(),
                stanza: "iq".to_string(),
                phase: "binding".to_string(),
                service_id: "session-directory".to_string(),
                endpoint: "http://session-directory:50052".to_string(),
            },
            RouteEntry {
                namespace: "jabber:client".to_string(),
                element: "message".to_string(),
                stanza: "message".to_string(),
                phase: "authenticated".to_string(),
                service_id: "message-ingress".to_string(),
                endpoint: "http://message-ingress:50053".to_string(),
            },
            RouteEntry {
                namespace: "jabber:iq:roster".to_string(),
                element: "query".to_string(),
                stanza: "iq".to_string(),
                phase: "authenticated".to_string(),
                service_id: "roster-authority".to_string(),
                endpoint: "http://roster-authority:50054".to_string(),
            },
            RouteEntry {
                namespace: "jabber:client".to_string(),
                element: "presence".to_string(),
                stanza: "presence".to_string(),
                phase: "authenticated".to_string(),
                service_id: "presence-authority".to_string(),
                endpoint: "http://presence-authority:50055".to_string(),
            },
        ];

        let default_features = vec![
            DiscoFeature {
                var: "http://jabber.org/protocol/disco#info".to_string(),
                service_id: "protocol-registry".to_string(),
            },
            DiscoFeature {
                var: "urn:xmpp:ping".to_string(),
                service_id: "xep-0199-ping".to_string(),
            },
            DiscoFeature {
                var: "urn:xmpp:blocking".to_string(),
                service_id: "xep-0191-blocking".to_string(),
            },
        ];

        *self.routes.write().unwrap() = default_routes;
        *self.disco_features.write().unwrap() = default_features;
        self
    }

    pub fn get_route_snapshot(&self, _req: GetRouteSnapshotRequest) -> GetRouteSnapshotResponse {
        let routes = self.routes.read().unwrap().clone();
        let disco = self.disco_features.read().unwrap().clone();
        let version = *self.version.read().unwrap();

        // Compute SHA-256 signature over snapshot payload
        let mut hasher = Sha256::new();
        hasher.update(version.to_be_bytes());
        for r in &routes {
            hasher.update(r.namespace.as_bytes());
            hasher.update(r.element.as_bytes());
            hasher.update(r.stanza.as_bytes());
            hasher.update(r.service_id.as_bytes());
        }
        let digest = hasher.finalize().to_vec();

        GetRouteSnapshotResponse {
            snapshot_version: version,
            signature: Vec::new(),
            routes,
            disco_features: disco,
            digest,
            key_id: String::new(),
            algorithm: String::new(),
            issued_at_unix_ms: 0,
            expires_at_unix_ms: 0,
        }
    }

    pub fn register_instance(&self, req: RegisterInstanceRequest) -> RegisterInstanceResponse {
        let authorized_operator = req.operator_assertion.as_ref().is_some_and(|assertion| {
            assertion
                .validate_at(Utc::now(), "protocol-registry")
                .is_ok()
        });
        if !authorized_operator {
            return RegisterInstanceResponse {
                acknowledged: false,
                current_registry_version: *self.version.read().unwrap(),
                error: Some(ErrorDetail::new(
                    "UNAUTHENTICATED",
                    "A verified operator assertion is required",
                )),
            };
        }
        let mut ver = self.version.write().unwrap();
        *ver += 1;
        RegisterInstanceResponse {
            acknowledged: true,
            current_registry_version: *ver,
            error: None,
        }
    }

    pub fn resolve_route(
        &self,
        namespace: &str,
        element: &str,
        stanza: &str,
        phase: &str,
    ) -> Option<RouteEntry> {
        let routes = self.routes.read().unwrap();
        routes
            .iter()
            .find(|r| {
                r.namespace == namespace
                    && (r.element == element || r.element == "*")
                    && (r.stanza == stanza || r.stanza == "*")
                    && (r.phase == phase || r.phase == "*")
            })
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_generation_and_route_resolution() {
        let registry = RegistryService::new().with_default_routes();
        let snapshot = registry.get_route_snapshot(GetRouteSnapshotRequest {
            since_version: 0,
            trace: None,
        });

        assert_eq!(snapshot.snapshot_version, 1);
        assert!(!snapshot.digest.is_empty());
        assert_eq!(snapshot.routes.len(), 6);

        let resolved =
            registry.resolve_route("jabber:client", "message", "message", "authenticated");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().service_id, "message-ingress");

        let auth_route = registry.resolve_route(
            "urn:ietf:params:xml:ns:xmpp-sasl",
            "auth",
            "auth",
            "authenticating",
        );
        assert!(auth_route.is_some());
        assert_eq!(auth_route.unwrap().service_id, "identity");
    }
}
