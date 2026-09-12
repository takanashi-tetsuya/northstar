//! Northstar Microservices Contracts.
//!
//! Provides the generated wire contract and explicit domain adapters.
//!
//! `generated` is the only module that is valid for RPC/event serialization.
//! The `adapters` module contains local domain values while a service is being
//! migrated; it is deliberately not re-exported at the crate root.

pub mod adapters;
pub mod generated;

pub use generated::northstar;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_serialization_round_trip() {
        let auth = adapters::common::AuthContext::new("acc-1", "alice@example.com", 1, "us-east")
            .with_role("user");
        let req = adapters::identity::AuthenticateRequest {
            username: "alice".to_string(),
            mechanism: "SCRAM-SHA-256".to_string(),
            auth_payload: vec![1, 2, 3],
            trace: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: adapters::identity::AuthenticateRequest =
            serde_json::from_str(&json).unwrap();
        assert_eq!(req, deserialized);
        assert!(auth.has_role("user"));
    }

    #[test]
    fn common_metadata_round_trip_uses_bounded_opaque_values() {
        use adapters::common::{IdempotencyKey, PageToken, RequestMetadata};
        use adapters::conversions::AdapterError;
        use prost::Message;

        let metadata = RequestMetadata::new("req-123")
            .with_idempotency_key(IdempotencyKey::new("idem-456").unwrap())
            .with_page_token(PageToken::new(vec![0x01, 0x02, 0x03]).unwrap());
        let wire: northstar::common::v1::RequestMetadata = metadata.clone().into();
        let encoded = wire.encode_to_vec();
        let decoded = northstar::common::v1::RequestMetadata::decode(encoded.as_slice()).unwrap();
        let restored = RequestMetadata::try_from(decoded).unwrap();
        assert_eq!(restored, metadata);

        let invalid = northstar::common::v1::RequestMetadata {
            request_id: String::new(),
            trace: None,
            idempotency_key: Some(northstar::common::v1::IdempotencyKey {
                value: "".to_owned(),
            }),
            page_token: None,
        };
        assert_eq!(
            RequestMetadata::try_from(invalid),
            Err(AdapterError::MissingField("request_id"))
        );
    }

    #[test]
    fn error_detail_uses_canonical_reason_domain_and_correlation_fields() {
        let domain = adapters::common::ErrorDetail::new("AUTH_FAILED", "authentication failed")
            .with_domain("identity")
            .with_correlation_id("corr-1");
        let wire: northstar::common::v1::ErrorDetail = domain.clone().into();
        assert_eq!(wire.reason, "AUTH_FAILED");
        assert_eq!(wire.domain, "identity");
        assert_eq!(wire.correlation_id, "corr-1");
        let restored: adapters::common::ErrorDetail = wire.into();
        assert_eq!(restored.reason(), "AUTH_FAILED");
        assert_eq!(restored.domain(), "identity");
        assert_eq!(restored.correlation_id(), Some("corr-1"));
    }
}
