//! Northstar Microservices Contracts.
//!
//! Provides typed definitions, error formats, and request/response models
//! for all platform and domain microservices.

pub mod common;
pub mod delivery;
pub mod events;
pub mod identity;
pub mod ingress;
pub mod registry;
pub mod session;

pub mod generated;

pub use common::*;
pub use generated::northstar;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_serialization_round_trip() {
        let auth = AuthContext::new("acc-1", "alice@example.com", 1, "us-east").with_role("user");
        let req = identity::AuthenticateRequest {
            username: "alice".to_string(),
            mechanism: "SCRAM-SHA-256".to_string(),
            auth_payload: vec![1, 2, 3],
            trace: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: identity::AuthenticateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
        assert!(auth.has_role("user"));
    }
}
