//! Checked conversions between generated wire messages and domain adapters.
//!
//! No service should pass a generated message directly into a repository or
//! business use case.  These conversions are the narrow validation boundary
//! where required presence, bounded identifiers and safe error mappings are
//! enforced.

use super::{
    assertions::{self, AuthGrant, SessionAssertion as SecuritySessionAssertion},
    common::{
        AuthContext, ErrorContext, ErrorDetail, FieldViolation, IdempotencyKey, PageToken,
        RequestMetadata, SessionAssertion, TraceContext,
    },
    delivery::{
        DeliveryAck, DeliveryClientMessage, DeliveryServerMessage, EdgeHeartbeat, EdgeRegister,
    },
    events::EventEnvelope,
    identity::{
        AbortAuthenticationRequest, AbortAuthenticationResponse, AuthenticateRequest,
        AuthenticateResponse, ChangePasswordRequest, ChangePasswordResponse,
        ContinueAuthenticationRequest, ContinueAuthenticationResponse, GetIdentityRequest,
        GetIdentityResponse, RegisterRequest, RegisterResponse, RevokeCredentialsRequest,
        RevokeCredentialsResponse, StartAuthenticationRequest, StartAuthenticationResponse,
    },
    ingress::{CanonicalMessageInput, SubmitMessageRequest, SubmitMessageResponse},
    registry::{
        DiscoFeature, GetRouteSnapshotRequest, GetRouteSnapshotResponse, RegisterInstanceRequest,
        RegisterInstanceResponse, RouteEntry, WatchSnapshotsRequest,
    },
    session::{
        BindSessionRequest, BindSessionResponse, CloseSessionRequest, CloseSessionResponse,
        CommitResumeRequest, CommitResumeResponse, PrepareResumeRequest, PrepareResumeResponse,
        RenewLeaseRequest, RenewLeaseResponse, ResolveTargetsRequest, ResolveTargetsResponse,
        ResumeFenceRequest, ResumeFenceResponse, RevokeAccountSessionsRequest,
        RevokeAccountSessionsResponse, SessionTarget, ValidateAssertionRequest,
        ValidateAssertionResponse,
    },
};
use crate::northstar::{
    common::v1 as wire_common, delivery::v1 as wire_delivery, events::v1 as wire_events,
    identity::v1 as wire_identity, ingress::v1 as wire_ingress, registry::v1 as wire_registry,
    security::v1 as wire_security, session::v1 as wire_session,
};
use chrono::{DateTime, Utc};
use prost_types::{Duration, Timestamp};
use thiserror::Error;

const MAX_IDENTIFIER_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdapterError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("field exceeds the maximum length: {0}")]
    FieldTooLong(&'static str),
    #[error("invalid enum or oneof value: {0}")]
    InvalidValue(&'static str),
}

fn required(value: String, field: &'static str) -> Result<String, AdapterError> {
    if value.trim().is_empty() {
        return Err(AdapterError::MissingField(field));
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(AdapterError::FieldTooLong(field));
    }
    Ok(value)
}

fn required_with_limit(
    value: String,
    field: &'static str,
    max_bytes: usize,
) -> Result<String, AdapterError> {
    if value.trim().is_empty() {
        return Err(AdapterError::MissingField(field));
    }
    if value.len() > max_bytes {
        return Err(AdapterError::FieldTooLong(field));
    }
    Ok(value)
}

fn sanitize_safe_message(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if lower.contains("postgres://")
        || lower.contains("postgresql://")
        || lower.contains("select ")
        || lower.contains("insert ")
        || lower.contains("update ")
        || lower.contains("delete ")
        || lower.contains("password=")
        || lower.contains("secret=")
        || lower.contains("authorization=")
    {
        return "request could not be completed".to_owned();
    }

    input
        .split_whitespace()
        .map(|token| {
            if token.contains('@') {
                "[redacted-jid]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn optional_trace(value: Option<wire_common::TraceContext>) -> Option<TraceContext> {
    value.map(|trace| TraceContext {
        traceparent: trace.traceparent,
        tracestate: (!trace.tracestate.is_empty()).then_some(trace.tracestate),
        correlation_id: (!trace.correlation_id.is_empty()).then_some(trace.correlation_id),
        causation_id: (!trace.causation_id.is_empty()).then_some(trace.causation_id),
    })
}

fn wire_trace(value: Option<TraceContext>) -> Option<wire_common::TraceContext> {
    value.map(|trace| wire_common::TraceContext {
        traceparent: trace.traceparent,
        tracestate: trace.tracestate.unwrap_or_default(),
        correlation_id: trace.correlation_id.unwrap_or_default(),
        causation_id: trace.causation_id.unwrap_or_default(),
    })
}

fn wire_duration(milliseconds: Option<u64>) -> Option<Duration> {
    milliseconds.map(|value| Duration {
        seconds: (value / 1_000) as i64,
        nanos: ((value % 1_000) * 1_000_000) as i32,
    })
}

fn duration_milliseconds(value: Option<Duration>) -> Option<u64> {
    value.and_then(|duration| {
        if duration.seconds < 0 || duration.nanos < 0 {
            return None;
        }
        Some((duration.seconds as u64).saturating_mul(1_000) + (duration.nanos as u64 / 1_000_000))
    })
}

fn wire_timestamp(value: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos() as i32,
    }
}

fn domain_timestamp(
    value: Option<Timestamp>,
    field: &'static str,
) -> Result<DateTime<Utc>, assertions::AssertionValidationError> {
    let value = value.ok_or(assertions::AssertionValidationError::MissingField(field))?;
    if !(0..1_000_000_000).contains(&value.nanos) {
        return Err(assertions::AssertionValidationError::InvalidField(field));
    }
    DateTime::<Utc>::from_timestamp(value.seconds, value.nanos as u32)
        .ok_or(assertions::AssertionValidationError::InvalidField(field))
}

impl From<AuthGrant> for wire_security::AuthGrant {
    fn from(value: AuthGrant) -> Self {
        Self {
            iss: value.issuer,
            aud: value.audience,
            iat: Some(wire_timestamp(value.issued_at)),
            nbf: Some(wire_timestamp(value.not_before)),
            exp: Some(wire_timestamp(value.expires_at)),
            jti: value.jwt_id,
            schema_version: value.schema_version,
            account_id: value.account_id,
            bare_jid: value.bare_jid,
            credential_generation: value.credential_generation,
            auth_method: value.auth_method,
            auth_strength: value.auth_strength,
            channel_binding: value.channel_binding,
            key_id: value.key_id,
            alg: value.algorithm,
            signature: value.signature,
            scopes: value.scopes,
        }
    }
}

impl TryFrom<wire_security::AuthGrant> for AuthGrant {
    type Error = assertions::AssertionValidationError;

    fn try_from(value: wire_security::AuthGrant) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: required_assertion(value.iss, "issuer")?,
            audience: required_assertion(value.aud, "audience")?,
            issued_at: domain_timestamp(value.iat, "iat")?,
            not_before: domain_timestamp(value.nbf, "nbf")?,
            expires_at: domain_timestamp(value.exp, "exp")?,
            jwt_id: required_assertion(value.jti, "jti")?,
            schema_version: value.schema_version,
            account_id: required_assertion(value.account_id, "account_id")?,
            bare_jid: required_assertion(value.bare_jid, "bare_jid")?,
            credential_generation: value.credential_generation,
            auth_method: required_assertion(value.auth_method, "auth_method")?,
            auth_strength: required_assertion(value.auth_strength, "auth_strength")?,
            channel_binding: value.channel_binding,
            key_id: required_assertion(value.key_id, "key_id")?,
            algorithm: required_assertion(value.alg, "alg")?,
            signature: value.signature,
            scopes: value.scopes,
        })
    }
}

impl From<SecuritySessionAssertion> for wire_security::SessionAssertion {
    fn from(value: SecuritySessionAssertion) -> Self {
        Self {
            iss: value.issuer,
            aud: value.audience,
            iat: Some(wire_timestamp(value.issued_at)),
            nbf: Some(wire_timestamp(value.not_before)),
            exp: Some(wire_timestamp(value.expires_at)),
            jti: value.jwt_id,
            schema_version: value.schema_version,
            account_id: value.account_id,
            bare_jid: value.bare_jid,
            full_jid: value.full_jid,
            connection_id: value.connection_id,
            edge_instance_id: value.edge_instance_id,
            session_epoch: value.session_epoch,
            credential_generation: value.credential_generation,
            home_region: value.home_region,
            region_epoch: value.region_epoch,
            key_id: value.key_id,
            alg: value.algorithm,
            signature: value.signature,
            scopes: value.scopes,
            roles: value.roles,
        }
    }
}

impl TryFrom<wire_security::SessionAssertion> for SecuritySessionAssertion {
    type Error = assertions::AssertionValidationError;

    fn try_from(value: wire_security::SessionAssertion) -> Result<Self, Self::Error> {
        Ok(Self {
            issuer: required_assertion(value.iss, "issuer")?,
            audience: required_assertion(value.aud, "audience")?,
            issued_at: domain_timestamp(value.iat, "iat")?,
            not_before: domain_timestamp(value.nbf, "nbf")?,
            expires_at: domain_timestamp(value.exp, "exp")?,
            jwt_id: required_assertion(value.jti, "jti")?,
            schema_version: value.schema_version,
            account_id: required_assertion(value.account_id, "account_id")?,
            bare_jid: required_assertion(value.bare_jid, "bare_jid")?,
            full_jid: required_assertion(value.full_jid, "full_jid")?,
            connection_id: required_assertion(value.connection_id, "connection_id")?,
            edge_instance_id: required_assertion(value.edge_instance_id, "edge_instance_id")?,
            session_epoch: value.session_epoch,
            credential_generation: value.credential_generation,
            home_region: required_assertion(value.home_region, "home_region")?,
            region_epoch: value.region_epoch,
            key_id: required_assertion(value.key_id, "key_id")?,
            algorithm: required_assertion(value.alg, "alg")?,
            signature: value.signature,
            scopes: value.scopes,
            roles: value.roles,
        })
    }
}

fn required_assertion(
    value: String,
    field: &'static str,
) -> Result<String, assertions::AssertionValidationError> {
    if value.trim().is_empty() {
        return Err(assertions::AssertionValidationError::MissingField(field));
    }
    if value.len() > 512 {
        return Err(assertions::AssertionValidationError::InvalidField(field));
    }
    Ok(value)
}

impl From<ErrorDetail> for wire_common::ErrorDetail {
    fn from(value: ErrorDetail) -> Self {
        let ErrorDetail {
            code,
            retryable,
            safe_message,
            current_version,
            violations,
            retry_after_ms,
            context,
        } = value;
        Self {
            code,
            retryable,
            safe_message: sanitize_safe_message(&safe_message),
            current_version,
            violations: violations.into_iter().map(Into::into).collect(),
            retry_after: wire_duration(retry_after_ms),
            reason: context.reason,
            domain: context.domain,
            correlation_id: context.correlation_id.unwrap_or_default(),
        }
    }
}

impl From<FieldViolation> for wire_common::FieldViolation {
    fn from(value: FieldViolation) -> Self {
        Self {
            field: value.field,
            description: value.description,
        }
    }
}

impl From<wire_common::ErrorDetail> for ErrorDetail {
    fn from(value: wire_common::ErrorDetail) -> Self {
        let reason = if value.reason.is_empty() {
            value.code.clone()
        } else {
            value.reason.clone()
        };
        let code = if value.code.is_empty() {
            reason.clone()
        } else {
            value.code
        };
        Self {
            code,
            retryable: value.retryable,
            safe_message: sanitize_safe_message(&value.safe_message),
            current_version: value.current_version,
            violations: value.violations.into_iter().map(Into::into).collect(),
            retry_after_ms: duration_milliseconds(value.retry_after),
            context: Box::new(ErrorContext {
                reason,
                domain: value.domain,
                correlation_id: (!value.correlation_id.is_empty()).then_some(value.correlation_id),
            }),
        }
    }
}

impl From<wire_common::FieldViolation> for FieldViolation {
    fn from(value: wire_common::FieldViolation) -> Self {
        Self {
            field: value.field,
            description: value.description,
        }
    }
}

impl TryFrom<wire_events::EventEnvelope> for EventEnvelope {
    type Error = AdapterError;

    fn try_from(value: wire_events::EventEnvelope) -> Result<Self, Self::Error> {
        if value.payload.len() > 1_048_576 {
            return Err(AdapterError::FieldTooLong("payload"));
        }
        if value.schema_version != 1 {
            return Err(AdapterError::InvalidValue("schema_version"));
        }
        Ok(Self {
            event_id: required(value.event_id, "event_id")?,
            producer_service: required(value.producer_service, "producer_service")?,
            producer_instance: required(value.producer_instance, "producer_instance")?,
            schema: required(value.schema, "schema")?,
            schema_version: value.schema_version,
            aggregate_type: required(value.aggregate_type, "aggregate_type")?,
            aggregate_id: required(value.aggregate_id, "aggregate_id")?,
            aggregate_version: value.aggregate_version,
            partition_key: required(value.partition_key, "partition_key")?,
            event_type: required(value.event_type, "event_type")?,
            payload: value.payload,
            payload_type: required(value.payload_type, "payload_type")?,
            correlation_id: (!value.correlation_id.is_empty()).then_some(value.correlation_id),
            causation_id: (!value.causation_id.is_empty()).then_some(value.causation_id),
            trace: optional_trace(value.trace),
            classification: required(value.classification, "classification")?,
            created_at_unix_ms: value.created_at_unix_ms,
        })
    }
}

impl From<EventEnvelope> for wire_events::EventEnvelope {
    fn from(value: EventEnvelope) -> Self {
        Self {
            event_id: value.event_id,
            producer_service: value.producer_service,
            producer_instance: value.producer_instance,
            schema: value.schema,
            schema_version: value.schema_version,
            aggregate_type: value.aggregate_type,
            aggregate_id: value.aggregate_id,
            aggregate_version: value.aggregate_version,
            partition_key: value.partition_key,
            event_type: value.event_type,
            payload: value.payload,
            payload_type: value.payload_type,
            correlation_id: value.correlation_id.unwrap_or_default(),
            causation_id: value.causation_id.unwrap_or_default(),
            trace: wire_trace(value.trace),
            classification: value.classification,
            created_at_unix_ms: value.created_at_unix_ms,
        }
    }
}

impl From<IdempotencyKey> for wire_common::IdempotencyKey {
    fn from(value: IdempotencyKey) -> Self {
        Self {
            value: value.as_str().to_owned(),
        }
    }
}

impl TryFrom<wire_common::IdempotencyKey> for IdempotencyKey {
    type Error = AdapterError;

    fn try_from(value: wire_common::IdempotencyKey) -> Result<Self, Self::Error> {
        let value = required_with_limit(value.value, "idempotency_key", 256)?;
        IdempotencyKey::new(value).ok_or(AdapterError::InvalidValue("idempotency_key"))
    }
}

impl From<PageToken> for wire_common::PageToken {
    fn from(value: PageToken) -> Self {
        Self {
            value: value.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<wire_common::PageToken> for PageToken {
    type Error = AdapterError;

    fn try_from(value: wire_common::PageToken) -> Result<Self, Self::Error> {
        if value.value.is_empty() {
            return Err(AdapterError::MissingField("page_token"));
        }
        if value.value.len() > 4096 {
            return Err(AdapterError::FieldTooLong("page_token"));
        }
        PageToken::new(value.value).ok_or(AdapterError::InvalidValue("page_token"))
    }
}

impl From<RequestMetadata> for wire_common::RequestMetadata {
    fn from(value: RequestMetadata) -> Self {
        Self {
            trace: wire_trace(value.trace),
            idempotency_key: value.idempotency_key.map(Into::into),
            page_token: value.page_token.map(Into::into),
            request_id: value.request_id,
        }
    }
}

impl TryFrom<wire_common::RequestMetadata> for RequestMetadata {
    type Error = AdapterError;

    fn try_from(value: wire_common::RequestMetadata) -> Result<Self, Self::Error> {
        Ok(Self {
            request_id: required_with_limit(value.request_id, "request_id", 256)?,
            trace: optional_trace(value.trace),
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            page_token: value.page_token.map(TryFrom::try_from).transpose()?,
        })
    }
}

impl From<AuthContext> for wire_common::AuthContext {
    fn from(value: AuthContext) -> Self {
        Self {
            account_id: value.account_id,
            canonical_jid: value.canonical_jid,
            credential_generation: value.credential_generation,
            roles: value.roles,
            home_region: value.home_region,
        }
    }
}

impl TryFrom<wire_common::AuthContext> for AuthContext {
    type Error = AdapterError;

    fn try_from(value: wire_common::AuthContext) -> Result<Self, Self::Error> {
        // Roles are authority claims, not caller-controlled data.  Until the
        // signed assertion envelope lands, accepting them from a generic wire
        // message would let an untrusted peer manufacture an administrator
        // context.  Internal issuers use `From<AuthContext>`; inbound callers
        // must use the future verified-assertion path instead.
        if !value.roles.is_empty() {
            return Err(AdapterError::InvalidValue("roles"));
        }
        Ok(Self {
            account_id: required(value.account_id, "account_id")?,
            canonical_jid: required(value.canonical_jid, "canonical_jid")?,
            credential_generation: value.credential_generation,
            roles: value.roles,
            home_region: required(value.home_region, "home_region")?,
        })
    }
}

impl From<SessionAssertion> for wire_common::SessionAssertion {
    fn from(value: SessionAssertion) -> Self {
        Self {
            account_id: value.account_id,
            canonical_bare_jid: value.canonical_bare_jid,
            full_jid: value.full_jid,
            connection_id: value.connection_id,
            edge_instance_id: value.edge_instance_id,
            session_epoch: value.session_epoch,
            credential_generation: value.credential_generation,
            home_region: value.home_region,
            region_epoch: value.region_epoch,
            issued_at_ms: value.issued_at_ms,
            expires_at_ms: value.expires_at_ms,
            audience: value.audience,
            nonce: value.nonce,
            key_id: value.key_id,
            signature: value.signature,
        }
    }
}

impl TryFrom<wire_common::SessionAssertion> for SessionAssertion {
    type Error = AdapterError;

    fn try_from(value: wire_common::SessionAssertion) -> Result<Self, Self::Error> {
        if value.expires_at_ms <= value.issued_at_ms {
            return Err(AdapterError::InvalidValue("assertion validity window"));
        }
        if value.signature.is_empty() {
            return Err(AdapterError::MissingField("signature"));
        }
        Ok(Self {
            account_id: required(value.account_id, "account_id")?,
            canonical_bare_jid: required(value.canonical_bare_jid, "canonical_bare_jid")?,
            full_jid: required(value.full_jid, "full_jid")?,
            connection_id: required(value.connection_id, "connection_id")?,
            edge_instance_id: required(value.edge_instance_id, "edge_instance_id")?,
            session_epoch: value.session_epoch,
            credential_generation: value.credential_generation,
            home_region: required(value.home_region, "home_region")?,
            region_epoch: value.region_epoch,
            issued_at_ms: value.issued_at_ms,
            expires_at_ms: value.expires_at_ms,
            audience: required(value.audience, "audience")?,
            nonce: required(value.nonce, "nonce")?,
            key_id: required(value.key_id, "key_id")?,
            signature: value.signature,
        })
    }
}

impl From<AuthenticateRequest> for wire_identity::AuthenticateRequest {
    fn from(value: AuthenticateRequest) -> Self {
        Self {
            username: value.username,
            mechanism: value.mechanism,
            auth_payload: value.auth_payload,
            trace: wire_trace(value.trace),
        }
    }
}

impl TryFrom<wire_identity::AuthenticateRequest> for AuthenticateRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::AuthenticateRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            username: required(value.username, "username")?,
            mechanism: required(value.mechanism, "mechanism")?,
            auth_payload: value.auth_payload,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<AuthenticateResponse> for wire_identity::AuthenticateResponse {
    fn from(value: AuthenticateResponse) -> Self {
        Self {
            success: value.success,
            auth_context: value.auth_context.map(Into::into),
            challenge_or_response: value.challenge_or_response,
            error: value.error.map(Into::into),
            auth_grant: value.auth_grant.map(Into::into),
        }
    }
}

impl TryFrom<wire_identity::AuthenticateResponse> for AuthenticateResponse {
    type Error = AdapterError;

    fn try_from(value: wire_identity::AuthenticateResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            success: value.success,
            auth_context: value.auth_context.map(TryInto::try_into).transpose()?,
            challenge_or_response: value.challenge_or_response,
            error: value.error.map(Into::into),
            auth_grant: value
                .auth_grant
                .map(|grant| {
                    grant
                        .try_into()
                        .map_err(|_| AdapterError::InvalidValue("auth grant"))
                })
                .transpose()?,
        })
    }
}

impl From<StartAuthenticationRequest> for wire_identity::StartAuthenticationRequest {
    fn from(value: StartAuthenticationRequest) -> Self {
        Self {
            username: value.username,
            mechanism: value.mechanism,
            client_first: value.client_first.expose_for_authorized_use().to_vec(),
            channel_binding: value.channel_binding,
            channel_binding_data: value
                .channel_binding_data
                .map(|binding| binding.expose_for_authorized_use().to_vec()),
            trace: wire_trace(value.trace),
        }
    }
}

impl TryFrom<wire_identity::StartAuthenticationRequest> for StartAuthenticationRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::StartAuthenticationRequest) -> Result<Self, Self::Error> {
        if value.client_first.is_empty() || value.client_first.len() > 8 * 1024 {
            return Err(AdapterError::InvalidValue("client_first"));
        }
        if value
            .channel_binding_data
            .as_ref()
            .is_some_and(|binding| binding.len() > 4 * 1024)
        {
            return Err(AdapterError::InvalidValue("channel_binding_data"));
        }
        Ok(Self {
            username: required(value.username, "username")?,
            mechanism: required(value.mechanism, "mechanism")?,
            client_first: foundation_security::SecretBytes::new(value.client_first),
            channel_binding: value.channel_binding,
            channel_binding_data: value
                .channel_binding_data
                .map(foundation_security::SecretBytes::new),
            trace: optional_trace(value.trace),
        })
    }
}

impl From<StartAuthenticationResponse> for wire_identity::StartAuthenticationResponse {
    fn from(value: StartAuthenticationResponse) -> Self {
        Self {
            success: value.success,
            exchange_id: value
                .exchange_id
                .map(|token| token.expose_for_authorized_transport().to_owned())
                .unwrap_or_default(),
            server_first: value.server_first,
            exchange_ttl_seconds: value.exchange_ttl_seconds,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_identity::StartAuthenticationResponse> for StartAuthenticationResponse {
    type Error = AdapterError;

    fn try_from(value: wire_identity::StartAuthenticationResponse) -> Result<Self, Self::Error> {
        if value.exchange_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(AdapterError::FieldTooLong("exchange_id"));
        }
        if value.success && value.exchange_id.is_empty() {
            return Err(AdapterError::MissingField("exchange_id"));
        }
        if value.server_first.len() > 8 * 1024 {
            return Err(AdapterError::InvalidValue("server_first"));
        }
        Ok(Self {
            success: value.success,
            exchange_id: (!value.exchange_id.is_empty())
                .then(|| foundation_security::OpaqueToken::new(value.exchange_id)),
            server_first: value.server_first,
            exchange_ttl_seconds: value.exchange_ttl_seconds,
            error: value.error.map(Into::into),
        })
    }
}

impl From<ContinueAuthenticationRequest> for wire_identity::ContinueAuthenticationRequest {
    fn from(value: ContinueAuthenticationRequest) -> Self {
        Self {
            exchange_id: value
                .exchange_id
                .expose_for_authorized_transport()
                .to_owned(),
            client_final: value.client_final.expose_for_authorized_use().to_vec(),
            trace: wire_trace(value.trace),
        }
    }
}

impl TryFrom<wire_identity::ContinueAuthenticationRequest> for ContinueAuthenticationRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::ContinueAuthenticationRequest) -> Result<Self, Self::Error> {
        if value.client_final.is_empty() || value.client_final.len() > 8 * 1024 {
            return Err(AdapterError::InvalidValue("client_final"));
        }
        Ok(Self {
            exchange_id: foundation_security::OpaqueToken::new(required(
                value.exchange_id,
                "exchange_id",
            )?),
            client_final: foundation_security::SecretBytes::new(value.client_final),
            trace: optional_trace(value.trace),
        })
    }
}

impl From<ContinueAuthenticationResponse> for wire_identity::ContinueAuthenticationResponse {
    fn from(value: ContinueAuthenticationResponse) -> Self {
        Self {
            success: value.success,
            server_final: value.server_final,
            auth_grant: value.auth_grant.map(Into::into),
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_identity::ContinueAuthenticationResponse> for ContinueAuthenticationResponse {
    type Error = AdapterError;

    fn try_from(value: wire_identity::ContinueAuthenticationResponse) -> Result<Self, Self::Error> {
        if value.server_final.len() > 8 * 1024 {
            return Err(AdapterError::InvalidValue("server_final"));
        }
        Ok(Self {
            success: value.success,
            server_final: value.server_final,
            auth_grant: value
                .auth_grant
                .map(|grant| {
                    grant
                        .try_into()
                        .map_err(|_| AdapterError::InvalidValue("auth grant"))
                })
                .transpose()?,
            error: value.error.map(Into::into),
        })
    }
}

impl From<AbortAuthenticationRequest> for wire_identity::AbortAuthenticationRequest {
    fn from(value: AbortAuthenticationRequest) -> Self {
        Self {
            exchange_id: value
                .exchange_id
                .expose_for_authorized_transport()
                .to_owned(),
            reason: value.reason,
            trace: wire_trace(value.trace),
        }
    }
}

impl TryFrom<wire_identity::AbortAuthenticationRequest> for AbortAuthenticationRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::AbortAuthenticationRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            exchange_id: foundation_security::OpaqueToken::new(required(
                value.exchange_id,
                "exchange_id",
            )?),
            reason: required_with_limit(value.reason, "reason", 512)?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<AbortAuthenticationResponse> for wire_identity::AbortAuthenticationResponse {
    fn from(value: AbortAuthenticationResponse) -> Self {
        Self {
            success: value.success,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_identity::AbortAuthenticationResponse> for AbortAuthenticationResponse {
    type Error = AdapterError;

    fn try_from(value: wire_identity::AbortAuthenticationResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            success: value.success,
            error: value.error.map(Into::into),
        })
    }
}

impl From<RegisterRequest> for wire_identity::RegisterRequest {
    fn from(value: RegisterRequest) -> Self {
        let password_secret = value
            .password
            .expose_for_authorized_use()
            .as_bytes()
            .to_vec();
        Self {
            username: value.username,
            password: String::new(),
            invitation_code: value.invitation_code,
            trace: wire_trace(value.trace),
            password_secret,
        }
    }
}

impl TryFrom<wire_identity::RegisterRequest> for RegisterRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::RegisterRequest) -> Result<Self, Self::Error> {
        let password = if !value.password_secret.is_empty() {
            String::from_utf8(value.password_secret)
                .map_err(|_| AdapterError::InvalidValue("password_secret"))?
        } else {
            required(value.password, "password")?
        };
        Ok(Self {
            username: required(value.username, "username")?,
            password: foundation_security::SecretString::new(password),
            invitation_code: value.invitation_code,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<RegisterResponse> for wire_identity::RegisterResponse {
    fn from(value: RegisterResponse) -> Self {
        Self {
            success: value.success,
            account_id: value.account_id,
            canonical_jid: value.canonical_jid,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_identity::RegisterResponse> for RegisterResponse {
    fn from(value: wire_identity::RegisterResponse) -> Self {
        Self {
            success: value.success,
            account_id: value.account_id,
            canonical_jid: value.canonical_jid,
            error: value.error.map(Into::into),
        }
    }
}

impl From<ChangePasswordRequest> for wire_identity::ChangePasswordRequest {
    fn from(value: ChangePasswordRequest) -> Self {
        let old_password_secret = value
            .old_password
            .expose_for_authorized_use()
            .as_bytes()
            .to_vec();
        let new_password_secret = value
            .new_password
            .expose_for_authorized_use()
            .as_bytes()
            .to_vec();
        Self {
            account_id: value.account_id,
            old_password: String::new(),
            new_password: String::new(),
            trace: wire_trace(value.trace),
            old_password_secret,
            new_password_secret,
        }
    }
}

impl TryFrom<wire_identity::ChangePasswordRequest> for ChangePasswordRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::ChangePasswordRequest) -> Result<Self, Self::Error> {
        let old_password = if !value.old_password_secret.is_empty() {
            String::from_utf8(value.old_password_secret)
                .map_err(|_| AdapterError::InvalidValue("old_password_secret"))?
        } else {
            required(value.old_password, "old_password")?
        };
        let new_password = if !value.new_password_secret.is_empty() {
            String::from_utf8(value.new_password_secret)
                .map_err(|_| AdapterError::InvalidValue("new_password_secret"))?
        } else {
            required(value.new_password, "new_password")?
        };
        Ok(Self {
            account_id: required(value.account_id, "account_id")?,
            old_password: foundation_security::SecretString::new(old_password),
            new_password: foundation_security::SecretString::new(new_password),
            trace: optional_trace(value.trace),
        })
    }
}

impl From<ChangePasswordResponse> for wire_identity::ChangePasswordResponse {
    fn from(value: ChangePasswordResponse) -> Self {
        Self {
            success: value.success,
            new_credential_generation: value.new_credential_generation,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_identity::ChangePasswordResponse> for ChangePasswordResponse {
    fn from(value: wire_identity::ChangePasswordResponse) -> Self {
        Self {
            success: value.success,
            new_credential_generation: value.new_credential_generation,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_identity::GetIdentityRequest> for GetIdentityRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::GetIdentityRequest) -> Result<Self, Self::Error> {
        use wire_identity::get_identity_request::Identifier;
        match value.identifier {
            Some(Identifier::AccountId(value)) => Ok(Self::ById(required(value, "account_id")?)),
            Some(Identifier::Username(value)) => Ok(Self::ByUsername(required(value, "username")?)),
            Some(Identifier::CanonicalJid(value)) => {
                Ok(Self::ByJid(required(value, "canonical_jid")?))
            }
            None => Err(AdapterError::MissingField("identifier")),
        }
    }
}

impl From<GetIdentityResponse> for wire_identity::GetIdentityResponse {
    fn from(value: GetIdentityResponse) -> Self {
        Self {
            found: value.found,
            identity: value.identity.map(Into::into),
            account_status: value.account_status,
        }
    }
}

impl TryFrom<wire_identity::GetIdentityResponse> for GetIdentityResponse {
    type Error = AdapterError;

    fn try_from(value: wire_identity::GetIdentityResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            found: value.found,
            identity: value.identity.map(TryInto::try_into).transpose()?,
            account_status: value.account_status,
        })
    }
}

impl From<RevokeCredentialsRequest> for wire_identity::RevokeCredentialsRequest {
    fn from(value: RevokeCredentialsRequest) -> Self {
        Self {
            account_id: value.account_id,
            reason: value.reason,
            trace: wire_trace(value.trace),
        }
    }
}

impl TryFrom<wire_identity::RevokeCredentialsRequest> for RevokeCredentialsRequest {
    type Error = AdapterError;

    fn try_from(value: wire_identity::RevokeCredentialsRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            account_id: required(value.account_id, "account_id")?,
            reason: required(value.reason, "reason")?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<RevokeCredentialsResponse> for wire_identity::RevokeCredentialsResponse {
    fn from(value: RevokeCredentialsResponse) -> Self {
        Self {
            success: value.success,
            new_credential_generation: value.new_credential_generation,
        }
    }
}

impl From<wire_identity::RevokeCredentialsResponse> for RevokeCredentialsResponse {
    fn from(value: wire_identity::RevokeCredentialsResponse) -> Self {
        Self {
            success: value.success,
            new_credential_generation: value.new_credential_generation,
        }
    }
}

impl TryFrom<wire_session::BindSessionRequest> for BindSessionRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::BindSessionRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            auth: value
                .auth
                .ok_or(AdapterError::MissingField("auth"))?
                .try_into()?,
            auth_grant: value
                .auth_grant
                .map(|grant| {
                    grant
                        .try_into()
                        .map_err(|_| AdapterError::InvalidValue("auth grant"))
                })
                .transpose()?,
            desired_resource: required(value.desired_resource, "desired_resource")?,
            edge_instance_id: required(value.edge_instance_id, "edge_instance_id")?,
            connection_id: required(value.connection_id, "connection_id")?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<BindSessionRequest> for wire_session::BindSessionRequest {
    fn from(value: BindSessionRequest) -> Self {
        Self {
            auth: Some(value.auth.into()),
            desired_resource: value.desired_resource,
            edge_instance_id: value.edge_instance_id,
            connection_id: value.connection_id,
            trace: wire_trace(value.trace),
            auth_grant: value.auth_grant.map(Into::into),
        }
    }
}

impl From<BindSessionResponse> for wire_session::BindSessionResponse {
    fn from(value: BindSessionResponse) -> Self {
        Self {
            success: value.success,
            full_jid: value.full_jid,
            session_epoch: value.session_epoch,
            error: value.error.map(Into::into),
            assertion: value.assertion.map(Into::into),
        }
    }
}

impl TryFrom<wire_session::BindSessionResponse> for BindSessionResponse {
    type Error = AdapterError;

    fn try_from(value: wire_session::BindSessionResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            success: value.success,
            full_jid: value.full_jid,
            session_epoch: value.session_epoch,
            error: value.error.map(Into::into),
            assertion: value
                .assertion
                .map(TryInto::try_into)
                .transpose()
                .map_err(|_| AdapterError::InvalidValue("session assertion"))?,
        })
    }
}

impl TryFrom<wire_session::ResumeFenceRequest> for ResumeFenceRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::ResumeFenceRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            full_jid: required(value.full_jid, "full_jid")?,
            expected_epoch: value.expected_epoch,
            new_edge_instance_id: required(value.new_edge_instance_id, "new_edge_instance_id")?,
            new_connection_id: required(value.new_connection_id, "new_connection_id")?,
            expected_region_epoch: value.expected_region_epoch,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<ResumeFenceRequest> for wire_session::ResumeFenceRequest {
    fn from(value: ResumeFenceRequest) -> Self {
        Self {
            full_jid: value.full_jid,
            expected_epoch: value.expected_epoch,
            new_edge_instance_id: value.new_edge_instance_id,
            new_connection_id: value.new_connection_id,
            trace: wire_trace(value.trace),
            expected_region_epoch: value.expected_region_epoch,
            idempotency_key: value.idempotency_key.map(Into::into),
        }
    }
}

impl From<ResumeFenceResponse> for wire_session::ResumeFenceResponse {
    fn from(value: ResumeFenceResponse) -> Self {
        Self {
            success: value.success,
            new_epoch: value.new_epoch,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_session::ResumeFenceResponse> for ResumeFenceResponse {
    fn from(value: wire_session::ResumeFenceResponse) -> Self {
        Self {
            success: value.success,
            new_epoch: value.new_epoch,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_session::ResolveTargetsRequest> for ResolveTargetsRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::ResolveTargetsRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            bare_or_full_jid: required(value.bare_or_full_jid, "bare_or_full_jid")?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<ResolveTargetsRequest> for wire_session::ResolveTargetsRequest {
    fn from(value: ResolveTargetsRequest) -> Self {
        Self {
            bare_or_full_jid: value.bare_or_full_jid,
            trace: wire_trace(value.trace),
        }
    }
}

impl From<SessionTarget> for wire_session::SessionTarget {
    fn from(value: SessionTarget) -> Self {
        Self {
            full_jid: value.full_jid,
            edge_instance_id: value.edge_instance_id,
            connection_id: value.connection_id,
            session_epoch: value.session_epoch,
            route_incarnation: value.route_incarnation,
            expires_at_unix_ms: value.expires_at_unix_ms,
        }
    }
}

impl From<wire_session::SessionTarget> for SessionTarget {
    fn from(value: wire_session::SessionTarget) -> Self {
        Self {
            full_jid: value.full_jid,
            edge_instance_id: value.edge_instance_id,
            connection_id: value.connection_id,
            session_epoch: value.session_epoch,
            route_incarnation: value.route_incarnation,
            expires_at_unix_ms: value.expires_at_unix_ms,
        }
    }
}

impl From<ResolveTargetsResponse> for wire_session::ResolveTargetsResponse {
    fn from(value: ResolveTargetsResponse) -> Self {
        Self {
            targets: value.targets.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<wire_session::ResolveTargetsResponse> for ResolveTargetsResponse {
    fn from(value: wire_session::ResolveTargetsResponse) -> Self {
        Self {
            targets: value.targets.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<wire_session::CloseSessionRequest> for CloseSessionRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::CloseSessionRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            full_jid: required(value.full_jid, "full_jid")?,
            session_epoch: value.session_epoch,
            reason: required(value.reason, "reason")?,
            expected_region_epoch: value.expected_region_epoch,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<CloseSessionRequest> for wire_session::CloseSessionRequest {
    fn from(value: CloseSessionRequest) -> Self {
        Self {
            full_jid: value.full_jid,
            session_epoch: value.session_epoch,
            reason: value.reason,
            trace: wire_trace(value.trace),
            expected_region_epoch: value.expected_region_epoch,
            idempotency_key: value.idempotency_key.map(Into::into),
        }
    }
}

impl From<CloseSessionResponse> for wire_session::CloseSessionResponse {
    fn from(value: CloseSessionResponse) -> Self {
        Self {
            success: value.success,
        }
    }
}

impl From<wire_session::CloseSessionResponse> for CloseSessionResponse {
    fn from(value: wire_session::CloseSessionResponse) -> Self {
        Self {
            success: value.success,
        }
    }
}

impl TryFrom<wire_session::RenewLeaseRequest> for RenewLeaseRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::RenewLeaseRequest) -> Result<Self, Self::Error> {
        if !(1..=3_600).contains(&value.lease_ttl_seconds) {
            return Err(AdapterError::InvalidValue("lease_ttl_seconds"));
        }
        Ok(Self {
            full_jid: required(value.full_jid, "full_jid")?,
            expected_session_epoch: value.expected_session_epoch,
            expected_region_epoch: value.expected_region_epoch,
            lease_ttl_seconds: value.lease_ttl_seconds,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<RenewLeaseRequest> for wire_session::RenewLeaseRequest {
    fn from(value: RenewLeaseRequest) -> Self {
        Self {
            full_jid: value.full_jid,
            expected_session_epoch: value.expected_session_epoch,
            expected_region_epoch: value.expected_region_epoch,
            lease_ttl_seconds: value.lease_ttl_seconds,
            idempotency_key: value.idempotency_key.map(Into::into),
            trace: wire_trace(value.trace),
        }
    }
}

impl From<RenewLeaseResponse> for wire_session::RenewLeaseResponse {
    fn from(value: RenewLeaseResponse) -> Self {
        Self {
            success: value.success,
            session_epoch: value.session_epoch,
            lease_expires_at_unix_ms: value.lease_expires_at_unix_ms,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_session::RenewLeaseResponse> for RenewLeaseResponse {
    fn from(value: wire_session::RenewLeaseResponse) -> Self {
        Self {
            success: value.success,
            session_epoch: value.session_epoch,
            lease_expires_at_unix_ms: value.lease_expires_at_unix_ms,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_session::PrepareResumeRequest> for PrepareResumeRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::PrepareResumeRequest) -> Result<Self, Self::Error> {
        if value.resume_token_hash.is_empty() || value.resume_token_hash.len() > 128 {
            return Err(AdapterError::InvalidValue("resume_token_hash"));
        }
        Ok(Self {
            full_jid: required(value.full_jid, "full_jid")?,
            resume_token_hash: foundation_security::SecretBytes::new(value.resume_token_hash),
            expected_session_epoch: value.expected_session_epoch,
            new_edge_instance_id: required(value.new_edge_instance_id, "new_edge_instance_id")?,
            new_connection_id: required(value.new_connection_id, "new_connection_id")?,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<PrepareResumeRequest> for wire_session::PrepareResumeRequest {
    fn from(value: PrepareResumeRequest) -> Self {
        Self {
            full_jid: value.full_jid,
            resume_token_hash: value.resume_token_hash.expose_for_authorized_use().to_vec(),
            expected_session_epoch: value.expected_session_epoch,
            new_edge_instance_id: value.new_edge_instance_id,
            new_connection_id: value.new_connection_id,
            idempotency_key: value.idempotency_key.map(Into::into),
            trace: wire_trace(value.trace),
        }
    }
}

impl From<PrepareResumeResponse> for wire_session::PrepareResumeResponse {
    fn from(value: PrepareResumeResponse) -> Self {
        Self {
            success: value.success,
            resume_id: value
                .resume_id
                .map(|token| token.expose_for_authorized_transport().to_owned())
                .unwrap_or_default(),
            session_epoch: value.session_epoch,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_session::PrepareResumeResponse> for PrepareResumeResponse {
    type Error = AdapterError;

    fn try_from(value: wire_session::PrepareResumeResponse) -> Result<Self, Self::Error> {
        if value.success && value.resume_id.is_empty() {
            return Err(AdapterError::MissingField("resume_id"));
        }
        if value.resume_id.len() > MAX_IDENTIFIER_BYTES {
            return Err(AdapterError::FieldTooLong("resume_id"));
        }
        Ok(Self {
            success: value.success,
            resume_id: (!value.resume_id.is_empty())
                .then(|| foundation_security::OpaqueToken::new(value.resume_id)),
            session_epoch: value.session_epoch,
            error: value.error.map(Into::into),
        })
    }
}

impl TryFrom<wire_session::CommitResumeRequest> for CommitResumeRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::CommitResumeRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            resume_id: foundation_security::OpaqueToken::new(required(
                value.resume_id,
                "resume_id",
            )?),
            expected_session_epoch: value.expected_session_epoch,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<CommitResumeRequest> for wire_session::CommitResumeRequest {
    fn from(value: CommitResumeRequest) -> Self {
        Self {
            resume_id: value.resume_id.expose_for_authorized_transport().to_owned(),
            expected_session_epoch: value.expected_session_epoch,
            idempotency_key: value.idempotency_key.map(Into::into),
            trace: wire_trace(value.trace),
        }
    }
}

impl From<CommitResumeResponse> for wire_session::CommitResumeResponse {
    fn from(value: CommitResumeResponse) -> Self {
        Self {
            success: value.success,
            new_session_epoch: value.new_session_epoch,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_session::CommitResumeResponse> for CommitResumeResponse {
    fn from(value: wire_session::CommitResumeResponse) -> Self {
        Self {
            success: value.success,
            new_session_epoch: value.new_session_epoch,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_session::ValidateAssertionRequest> for ValidateAssertionRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::ValidateAssertionRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            assertion: value
                .assertion
                .ok_or(AdapterError::MissingField("assertion"))?
                .try_into()
                .map_err(|_| AdapterError::InvalidValue("assertion"))?,
            expected_audience: required(value.expected_audience, "expected_audience")?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<ValidateAssertionResponse> for wire_session::ValidateAssertionResponse {
    fn from(value: ValidateAssertionResponse) -> Self {
        Self {
            valid: value.valid,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_session::ValidateAssertionResponse> for ValidateAssertionResponse {
    fn from(value: wire_session::ValidateAssertionResponse) -> Self {
        Self {
            valid: value.valid,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_session::RevokeAccountSessionsRequest> for RevokeAccountSessionsRequest {
    type Error = AdapterError;

    fn try_from(value: wire_session::RevokeAccountSessionsRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            account_id: required(value.account_id, "account_id")?,
            expected_credential_generation: value.expected_credential_generation,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            reason: required_with_limit(value.reason, "reason", 512)?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<RevokeAccountSessionsRequest> for wire_session::RevokeAccountSessionsRequest {
    fn from(value: RevokeAccountSessionsRequest) -> Self {
        Self {
            account_id: value.account_id,
            expected_credential_generation: value.expected_credential_generation,
            idempotency_key: value.idempotency_key.map(Into::into),
            reason: value.reason,
            trace: wire_trace(value.trace),
        }
    }
}

impl From<RevokeAccountSessionsResponse> for wire_session::RevokeAccountSessionsResponse {
    fn from(value: RevokeAccountSessionsResponse) -> Self {
        Self {
            success: value.success,
            revoked_count: value.revoked_count,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_session::RevokeAccountSessionsResponse> for RevokeAccountSessionsResponse {
    fn from(value: wire_session::RevokeAccountSessionsResponse) -> Self {
        Self {
            success: value.success,
            revoked_count: value.revoked_count,
            error: value.error.map(Into::into),
        }
    }
}

impl TryFrom<wire_ingress::SubmitMessageRequest> for SubmitMessageRequest {
    type Error = AdapterError;

    fn try_from(value: wire_ingress::SubmitMessageRequest) -> Result<Self, Self::Error> {
        if value.raw_stanza.len() > 1_048_576 {
            return Err(AdapterError::FieldTooLong("raw_stanza"));
        }
        Ok(Self {
            from_full_jid: required(value.from_full_jid, "from_full_jid")?,
            to_jid: required(value.to_jid, "to_jid")?,
            stanza_id: required(value.stanza_id, "stanza_id")?,
            message_type: required(value.message_type, "message_type")?,
            raw_stanza: value.raw_stanza,
            auth: value
                .auth
                .ok_or(AdapterError::MissingField("auth"))?
                .try_into()?,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            session_assertion: value
                .session_assertion
                .map(TryInto::try_into)
                .transpose()
                .map_err(|_| AdapterError::InvalidValue("session_assertion"))?,
            canonical_input: value.canonical_input.map(TryFrom::try_from).transpose()?,
            trace: optional_trace(value.trace),
        })
    }
}

impl TryFrom<wire_ingress::CanonicalMessageInput> for CanonicalMessageInput {
    type Error = AdapterError;

    fn try_from(value: wire_ingress::CanonicalMessageInput) -> Result<Self, Self::Error> {
        if value.payload.len() > 1_048_576 {
            return Err(AdapterError::FieldTooLong("canonical_input.payload"));
        }
        if value.schema_version != 1 {
            return Err(AdapterError::InvalidValue("canonical_input.schema_version"));
        }
        Ok(Self {
            from_full_jid: required(value.from_full_jid, "canonical_input.from_full_jid")?,
            to_jid: required(value.to_jid, "canonical_input.to_jid")?,
            stanza_id: required(value.stanza_id, "canonical_input.stanza_id")?,
            message_type: required(value.message_type, "canonical_input.message_type")?,
            payload: value.payload,
            origin_id: required(value.origin_id, "canonical_input.origin_id")?,
            schema_version: value.schema_version,
        })
    }
}

impl From<CanonicalMessageInput> for wire_ingress::CanonicalMessageInput {
    fn from(value: CanonicalMessageInput) -> Self {
        Self {
            from_full_jid: value.from_full_jid,
            to_jid: value.to_jid,
            stanza_id: value.stanza_id,
            message_type: value.message_type,
            payload: value.payload,
            origin_id: value.origin_id,
            schema_version: value.schema_version,
        }
    }
}

impl From<SubmitMessageRequest> for wire_ingress::SubmitMessageRequest {
    fn from(value: SubmitMessageRequest) -> Self {
        Self {
            from_full_jid: value.from_full_jid,
            to_jid: value.to_jid,
            stanza_id: value.stanza_id,
            message_type: value.message_type,
            raw_stanza: value.raw_stanza,
            auth: Some(value.auth.into()),
            trace: wire_trace(value.trace),
            idempotency_key: value.idempotency_key.map(Into::into),
            session_assertion: value.session_assertion.map(Into::into),
            canonical_input: value.canonical_input.map(Into::into),
        }
    }
}

impl From<SubmitMessageResponse> for wire_ingress::SubmitMessageResponse {
    fn from(value: SubmitMessageResponse) -> Self {
        Self {
            accepted: value.accepted,
            server_message_id: value.server_message_id,
            admission_timestamp_ms: value.admission_timestamp_ms,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_ingress::SubmitMessageResponse> for SubmitMessageResponse {
    fn from(value: wire_ingress::SubmitMessageResponse) -> Self {
        Self {
            accepted: value.accepted,
            server_message_id: value.server_message_id,
            admission_timestamp_ms: value.admission_timestamp_ms,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_delivery::EdgeRegister> for EdgeRegister {
    fn from(value: wire_delivery::EdgeRegister) -> Self {
        Self {
            edge_instance_id: value.edge_instance_id,
            protocol_version: value.protocol_version,
            attestation: value.attestation,
        }
    }
}

impl From<EdgeRegister> for wire_delivery::EdgeRegister {
    fn from(value: EdgeRegister) -> Self {
        Self {
            edge_instance_id: value.edge_instance_id,
            protocol_version: value.protocol_version,
            attestation: value.attestation,
        }
    }
}

impl From<wire_delivery::EdgeHeartbeat> for EdgeHeartbeat {
    fn from(value: wire_delivery::EdgeHeartbeat) -> Self {
        Self {
            edge_instance_id: value.edge_instance_id,
            observed_at_unix_ms: value.observed_at_unix_ms,
            active_connections: value.active_connections,
        }
    }
}

impl From<EdgeHeartbeat> for wire_delivery::EdgeHeartbeat {
    fn from(value: EdgeHeartbeat) -> Self {
        Self {
            edge_instance_id: value.edge_instance_id,
            observed_at_unix_ms: value.observed_at_unix_ms,
            active_connections: value.active_connections,
        }
    }
}

impl From<wire_delivery::DeliveryAck> for DeliveryAck {
    fn from(value: wire_delivery::DeliveryAck) -> Self {
        Self {
            delivery_id: value.delivery_id,
            delivered: value.delivered,
            error_reason: value.error_reason,
            target_connection_id: value.target_connection_id,
            target_full_jid: value.target_full_jid,
            session_epoch: value.session_epoch,
            stage: value.stage,
        }
    }
}

impl From<DeliveryAck> for wire_delivery::DeliveryAck {
    fn from(value: DeliveryAck) -> Self {
        Self {
            delivery_id: value.delivery_id,
            delivered: value.delivered,
            error_reason: value.error_reason,
            target_connection_id: value.target_connection_id,
            target_full_jid: value.target_full_jid,
            session_epoch: value.session_epoch,
            stage: value.stage,
        }
    }
}

impl TryFrom<wire_delivery::OpenDeliveryStreamRequest> for DeliveryClientMessage {
    type Error = AdapterError;

    fn try_from(value: wire_delivery::OpenDeliveryStreamRequest) -> Result<Self, Self::Error> {
        use wire_delivery::open_delivery_stream_request::Payload;
        match value.payload {
            Some(Payload::Register(value)) => {
                if value.edge_instance_id.trim().is_empty()
                    || value.edge_instance_id.len() > MAX_IDENTIFIER_BYTES
                    || value.protocol_version.len() > 64
                    || value.attestation.len() > 16 * 1024
                {
                    return Err(AdapterError::InvalidValue("edge_register"));
                }
                Ok(Self::Register(value.into()))
            }
            Some(Payload::Ack(value)) => {
                if value.delivery_id.trim().is_empty() || value.delivery_id.len() > 256 {
                    return Err(AdapterError::InvalidValue("delivery_id"));
                }
                if value.stage.len() > 64
                    || value.target_connection_id.len() > MAX_IDENTIFIER_BYTES
                    || value.target_full_jid.len() > MAX_IDENTIFIER_BYTES
                {
                    return Err(AdapterError::InvalidValue("delivery_ack"));
                }
                Ok(Self::Ack(value.into()))
            }
            Some(Payload::Heartbeat(value)) => {
                if value.edge_instance_id.trim().is_empty()
                    || value.edge_instance_id.len() > MAX_IDENTIFIER_BYTES
                {
                    return Err(AdapterError::InvalidValue("edge_heartbeat"));
                }
                Ok(Self::Heartbeat(value.into()))
            }
            None => Err(AdapterError::MissingField("payload")),
        }
    }
}

impl From<wire_delivery::OpenDeliveryStreamResponse> for DeliveryServerMessage {
    fn from(value: wire_delivery::OpenDeliveryStreamResponse) -> Self {
        Self {
            delivery_id: value.delivery_id,
            target_connection_id: value.target_connection_id,
            target_full_jid: value.target_full_jid,
            stanza: value.stanza,
            trace: optional_trace(value.trace),
            server_message_id: value.server_message_id,
            delivery_attempt: value.delivery_attempt,
            session_epoch: value.session_epoch,
        }
    }
}

impl TryFrom<wire_registry::GetRouteSnapshotRequest> for GetRouteSnapshotRequest {
    type Error = AdapterError;

    fn try_from(value: wire_registry::GetRouteSnapshotRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            since_version: value.since_version,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<GetRouteSnapshotRequest> for wire_registry::GetRouteSnapshotRequest {
    fn from(value: GetRouteSnapshotRequest) -> Self {
        Self {
            since_version: value.since_version,
            trace: wire_trace(value.trace),
        }
    }
}

impl TryFrom<wire_registry::WatchSnapshotsRequest> for WatchSnapshotsRequest {
    type Error = AdapterError;

    fn try_from(value: wire_registry::WatchSnapshotsRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            after_version: value.after_version,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<WatchSnapshotsRequest> for wire_registry::WatchSnapshotsRequest {
    fn from(value: WatchSnapshotsRequest) -> Self {
        Self {
            after_version: value.after_version,
            trace: wire_trace(value.trace),
        }
    }
}

impl From<wire_registry::RouteEntry> for RouteEntry {
    fn from(value: wire_registry::RouteEntry) -> Self {
        Self {
            namespace: value.namespace,
            element: value.element,
            stanza: value.stanza,
            phase: value.phase,
            service_id: value.service_id,
            endpoint: value.endpoint,
        }
    }
}

impl From<RouteEntry> for wire_registry::RouteEntry {
    fn from(value: RouteEntry) -> Self {
        Self {
            namespace: value.namespace,
            element: value.element,
            stanza: value.stanza,
            phase: value.phase,
            service_id: value.service_id,
            endpoint: value.endpoint,
        }
    }
}

impl From<wire_registry::DiscoFeature> for DiscoFeature {
    fn from(value: wire_registry::DiscoFeature) -> Self {
        Self {
            var: value.var,
            service_id: value.service_id,
        }
    }
}

impl From<DiscoFeature> for wire_registry::DiscoFeature {
    fn from(value: DiscoFeature) -> Self {
        Self {
            var: value.var,
            service_id: value.service_id,
        }
    }
}

impl From<GetRouteSnapshotResponse> for wire_registry::GetRouteSnapshotResponse {
    fn from(value: GetRouteSnapshotResponse) -> Self {
        Self {
            snapshot_version: value.snapshot_version,
            signature: value.signature,
            routes: value.routes.into_iter().map(Into::into).collect(),
            disco_features: value.disco_features.into_iter().map(Into::into).collect(),
            digest: value.digest,
            key_id: value.key_id,
            alg: value.algorithm,
            issued_at_unix_ms: value.issued_at_unix_ms,
            expires_at_unix_ms: value.expires_at_unix_ms,
        }
    }
}

impl From<wire_registry::GetRouteSnapshotResponse> for GetRouteSnapshotResponse {
    fn from(value: wire_registry::GetRouteSnapshotResponse) -> Self {
        Self {
            snapshot_version: value.snapshot_version,
            signature: value.signature,
            routes: value.routes.into_iter().map(Into::into).collect(),
            disco_features: value.disco_features.into_iter().map(Into::into).collect(),
            digest: value.digest,
            key_id: value.key_id,
            algorithm: value.alg,
            issued_at_unix_ms: value.issued_at_unix_ms,
            expires_at_unix_ms: value.expires_at_unix_ms,
        }
    }
}

impl TryFrom<wire_registry::RegisterInstanceRequest> for RegisterInstanceRequest {
    type Error = AdapterError;

    fn try_from(value: wire_registry::RegisterInstanceRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            service_id: required(value.service_id, "service_id")?,
            instance_id: required(value.instance_id, "instance_id")?,
            endpoint: required(value.endpoint, "endpoint")?,
            weight: value.weight,
            operator_assertion: value
                .operator_assertion
                .map(TryInto::try_into)
                .transpose()
                .map_err(|_| AdapterError::InvalidValue("operator_assertion"))?,
            idempotency_key: value.idempotency_key.map(TryFrom::try_from).transpose()?,
            trace: optional_trace(value.trace),
        })
    }
}

impl From<RegisterInstanceRequest> for wire_registry::RegisterInstanceRequest {
    fn from(value: RegisterInstanceRequest) -> Self {
        Self {
            service_id: value.service_id,
            instance_id: value.instance_id,
            endpoint: value.endpoint,
            weight: value.weight,
            operator_assertion: value.operator_assertion.map(Into::into),
            idempotency_key: value.idempotency_key.map(Into::into),
            trace: wire_trace(value.trace),
        }
    }
}

impl From<RegisterInstanceResponse> for wire_registry::RegisterInstanceResponse {
    fn from(value: RegisterInstanceResponse) -> Self {
        Self {
            acknowledged: value.acknowledged,
            current_registry_version: value.current_registry_version,
            error: value.error.map(Into::into),
        }
    }
}

impl From<wire_registry::RegisterInstanceResponse> for RegisterInstanceResponse {
    fn from(value: wire_registry::RegisterInstanceResponse) -> Self {
        Self {
            acknowledged: value.acknowledged,
            current_registry_version: value.current_registry_version,
            error: value.error.map(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn protobuf_binary_round_trip_enters_domain_only_after_validation() {
        let wire = wire_identity::AuthenticateRequest {
            username: "alice".to_owned(),
            mechanism: "SCRAM-SHA-256".to_owned(),
            auth_payload: vec![1, 2, 3],
            trace: Some(wire_common::TraceContext {
                traceparent: "00-abc-def-01".to_owned(),
                tracestate: String::new(),
                correlation_id: "corr-1".to_owned(),
                causation_id: String::new(),
            }),
        };
        let encoded = wire.encode_to_vec();
        let decoded = wire_identity::AuthenticateRequest::decode(encoded.as_slice()).unwrap();
        let domain = AuthenticateRequest::try_from(decoded).unwrap();

        assert_eq!(domain.username, "alice");
        assert_eq!(domain.mechanism, "SCRAM-SHA-256");
        assert_eq!(domain.auth_payload, vec![1, 2, 3]);
        assert_eq!(
            domain.trace.unwrap().correlation_id.as_deref(),
            Some("corr-1")
        );
    }

    #[test]
    fn scram_exchange_wire_round_trip_redacts_secrets_and_bounds_payloads() {
        use foundation_security::{OpaqueToken, SecretBytes};

        let request = StartAuthenticationRequest {
            username: "alice".to_owned(),
            mechanism: "SCRAM-SHA-256".to_owned(),
            client_first: SecretBytes::new(b"n,,n=alice,r=nonce".to_vec()),
            channel_binding: None,
            channel_binding_data: None,
            trace: None,
        };
        let wire: wire_identity::StartAuthenticationRequest = request.into();
        let encoded = wire.encode_to_vec();
        let decoded =
            wire_identity::StartAuthenticationRequest::decode(encoded.as_slice()).unwrap();
        let restored = StartAuthenticationRequest::try_from(decoded).unwrap();
        assert_eq!(restored.username, "alice");
        assert_eq!(
            restored.client_first.expose_for_authorized_use(),
            b"n,,n=alice,r=nonce"
        );
        assert_eq!(
            format!("{:?}", restored.client_first),
            "SecretBytes([REDACTED])"
        );

        let response = StartAuthenticationResponse {
            success: true,
            exchange_id: Some(OpaqueToken::new("exchange-1")),
            server_first: b"r=nonce-server,s=c2FsdA==,i=4096".to_vec(),
            exchange_ttl_seconds: 60,
            error: None,
        };
        let response_wire: wire_identity::StartAuthenticationResponse = response.into();
        let restored_response = StartAuthenticationResponse::try_from(response_wire).unwrap();
        assert_eq!(
            restored_response
                .exchange_id
                .unwrap()
                .expose_for_authorized_transport(),
            "exchange-1"
        );
    }

    #[test]
    fn session_fencing_wire_keeps_hash_epoch_and_idempotency_fields() {
        let wire = wire_session::PrepareResumeRequest {
            full_jid: "alice@example.com/desktop".to_owned(),
            resume_token_hash: vec![0xabu8; 32],
            expected_session_epoch: 9,
            new_edge_instance_id: "edge-2".to_owned(),
            new_connection_id: "conn-2".to_owned(),
            idempotency_key: Some(wire_common::IdempotencyKey {
                value: "resume-1".to_owned(),
            }),
            trace: None,
        };
        let encoded = wire.encode_to_vec();
        let decoded = wire_session::PrepareResumeRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.resume_token_hash, vec![0xabu8; 32]);
        assert_eq!(decoded.expected_session_epoch, 9);
        assert_eq!(decoded.idempotency_key.unwrap().value, "resume-1");
    }

    #[test]
    fn missing_authenticated_principal_is_rejected() {
        let wire = wire_ingress::SubmitMessageRequest {
            from_full_jid: "alice@example.com/r1".to_owned(),
            to_jid: "bob@example.com".to_owned(),
            stanza_id: "m-1".to_owned(),
            message_type: "chat".to_owned(),
            raw_stanza: b"<message/>".to_vec(),
            auth: None,
            idempotency_key: None,
            session_assertion: None,
            canonical_input: None,
            trace: None,
        };

        assert_eq!(
            SubmitMessageRequest::try_from(wire),
            Err(AdapterError::MissingField("auth"))
        );
    }

    #[test]
    fn caller_supplied_authority_roles_are_rejected() {
        let wire = wire_common::AuthContext {
            account_id: "acc-1".to_owned(),
            canonical_jid: "alice@example.com".to_owned(),
            credential_generation: 1,
            roles: vec!["administrator".to_owned()],
            home_region: "local".to_owned(),
        };

        assert_eq!(
            AuthContext::try_from(wire),
            Err(AdapterError::InvalidValue("roles"))
        );
    }

    #[test]
    fn unsigned_or_inverted_session_assertions_are_rejected() {
        let wire = wire_common::SessionAssertion {
            account_id: "acc-1".to_owned(),
            canonical_bare_jid: "alice@example.com".to_owned(),
            full_jid: "alice@example.com/r1".to_owned(),
            connection_id: "conn-1".to_owned(),
            edge_instance_id: "edge-1".to_owned(),
            session_epoch: 2,
            credential_generation: 3,
            home_region: "local".to_owned(),
            region_epoch: 4,
            issued_at_ms: 100,
            expires_at_ms: 99,
            audience: "message-ingress".to_owned(),
            nonce: "nonce".to_owned(),
            key_id: "key-1".to_owned(),
            signature: Vec::new(),
        };
        assert_eq!(
            SessionAssertion::try_from(wire),
            Err(AdapterError::InvalidValue("assertion validity window"))
        );
    }

    #[test]
    fn error_detail_duration_round_trip_is_bounded_and_lossless_to_milliseconds() {
        let domain = ErrorDetail::new("RETRY", "try again")
            .retryable(true)
            .with_version(7)
            .with_violation("jid", "invalid")
            .with_violation("body", "too large");
        let mut domain = domain;
        domain.retry_after_ms = Some(1_234);

        let wire: wire_common::ErrorDetail = domain.clone().into();
        let restored: ErrorDetail = wire.into();
        assert_eq!(restored, domain);
    }

    #[test]
    fn error_detail_redacts_internal_sql_credentials_and_jids() {
        let domain = ErrorDetail::new(
            "INTERNAL",
            "SELECT password=secret from postgres://user:pass@db.local alice@example.com",
        );
        let wire: wire_common::ErrorDetail = domain.into();
        assert_eq!(wire.safe_message, "request could not be completed");
        assert!(!wire.safe_message.contains("postgres://"));
        assert!(!wire.safe_message.contains("alice@example.com"));
    }

    #[test]
    fn signed_auth_grant_round_trip_and_lifetime_validation() {
        let issued_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let grant = AuthGrant {
            issuer: "identity".to_owned(),
            audience: "message-ingress".to_owned(),
            issued_at,
            not_before: issued_at,
            expires_at: DateTime::<Utc>::from_timestamp(1_700_000_120, 0).unwrap(),
            jwt_id: "grant-1".to_owned(),
            schema_version: 1,
            account_id: "acc-1".to_owned(),
            bare_jid: "alice@example.com".to_owned(),
            credential_generation: 4,
            auth_method: "SCRAM-SHA-256".to_owned(),
            auth_strength: "password".to_owned(),
            channel_binding: "tls-exporter".to_owned(),
            key_id: "identity-2026-09".to_owned(),
            algorithm: "Ed25519".to_owned(),
            signature: vec![7; 64],
            scopes: vec!["message.submit".to_owned()],
        };
        grant
            .validate_at(
                DateTime::<Utc>::from_timestamp(1_700_000_060, 0).unwrap(),
                "message-ingress",
            )
            .unwrap();
        grant.require_known_key(&["identity-2026-09"]).unwrap();
        assert_eq!(
            grant.require_known_key(&["identity-2026-08"]),
            Err(assertions::AssertionValidationError::InvalidField("key_id"))
        );
        let original_payload = grant.canonical_bytes_without_signature();
        let mut tampered = grant.clone();
        tampered.account_id = "acc-attacker".to_owned();
        assert_ne!(
            tampered.canonical_bytes_without_signature(),
            original_payload,
            "every signed claim must participate in the canonical payload"
        );
        let wire: wire_security::AuthGrant = grant.clone().into();
        let encoded = wire.encode_to_vec();
        let decoded = wire_security::AuthGrant::decode(encoded.as_slice()).unwrap();
        let restored = AuthGrant::try_from(decoded).unwrap();
        assert_eq!(restored, grant);
        assert!(!grant.canonical_bytes_without_signature().is_empty());
    }

    #[test]
    fn signed_assertion_rejects_audience_expiry_and_unknown_key_shape() {
        let issued_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let mut assertion = SecuritySessionAssertion {
            issuer: "session-authority".to_owned(),
            audience: "xmpp-edge".to_owned(),
            issued_at,
            not_before: issued_at,
            expires_at: DateTime::<Utc>::from_timestamp(1_700_000_600, 0).unwrap(),
            jwt_id: "session-1".to_owned(),
            schema_version: 1,
            account_id: "acc-1".to_owned(),
            bare_jid: "alice@example.com".to_owned(),
            full_jid: "alice@example.com/r1".to_owned(),
            connection_id: "conn-1".to_owned(),
            edge_instance_id: "edge-1".to_owned(),
            session_epoch: 2,
            credential_generation: 4,
            home_region: "local".to_owned(),
            region_epoch: 1,
            key_id: "unknown-key".to_owned(),
            algorithm: "Ed25519".to_owned(),
            signature: vec![9; 64],
            scopes: vec!["session.resume".to_owned()],
            roles: vec!["user".to_owned()],
        };
        assert_eq!(
            assertion.validate_at(
                DateTime::<Utc>::from_timestamp(1_700_000_010, 0).unwrap(),
                "xmpp-edge",
            ),
            Err(assertions::AssertionValidationError::LifetimeTooLong)
        );
        assertion.expires_at = DateTime::<Utc>::from_timestamp(1_700_000_120, 0).unwrap();
        assert_eq!(
            assertion.validate_at(
                DateTime::<Utc>::from_timestamp(1_700_000_010, 0).unwrap(),
                "delivery-router",
            ),
            Err(assertions::AssertionValidationError::AudienceMismatch)
        );
        assertion.audience = "xmpp-edge".to_owned();
        assertion.expires_at = DateTime::<Utc>::from_timestamp(1_700_000_005, 0).unwrap();
        assert_eq!(
            assertion.validate_at(
                DateTime::<Utc>::from_timestamp(1_700_000_010, 0).unwrap(),
                "xmpp-edge",
            ),
            Err(assertions::AssertionValidationError::NotCurrentlyValid)
        );
        assertion.key_id.clear();
        let wire: wire_security::SessionAssertion = assertion.into();
        assert_eq!(
            SecuritySessionAssertion::try_from(wire),
            Err(assertions::AssertionValidationError::MissingField("key_id"))
        );
    }
}
