//! Method-level authorization for internal RPCs.
//!
//! Policies are explicit data, not handler conventions.  A request must have
//! a verified workload identity and (when the method represents a user action)
//! a verified user principal.  Unknown methods are denied by construction.

use crate::workload_identity::VerifiedWorkload;
use foundation_security::VerifiedPrincipal;
use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcMethodPolicy {
    service: String,
    method: String,
    allowed_workload_services: BTreeSet<String>,
    required_scope: Option<String>,
    required_role: Option<String>,
    reason_required: bool,
}

impl RpcMethodPolicy {
    pub fn new(
        service: impl Into<String>,
        method: impl Into<String>,
    ) -> Result<Self, AuthorizationError> {
        let service = service.into();
        let method = method.into();
        if !valid_token(&service) || !valid_token(&method) {
            return Err(AuthorizationError::InvalidPolicy);
        }
        Ok(Self {
            service,
            method,
            allowed_workload_services: BTreeSet::new(),
            required_scope: None,
            required_role: None,
            reason_required: false,
        })
    }

    pub fn allow_workload_service(
        mut self,
        service: impl Into<String>,
    ) -> Result<Self, AuthorizationError> {
        let service = service.into();
        if !valid_token(&service) {
            return Err(AuthorizationError::InvalidPolicy);
        }
        self.allowed_workload_services.insert(service);
        Ok(self)
    }

    pub fn require_scope(mut self, scope: impl Into<String>) -> Result<Self, AuthorizationError> {
        let scope = scope.into();
        if !valid_token(&scope) {
            return Err(AuthorizationError::InvalidPolicy);
        }
        self.required_scope = Some(scope);
        Ok(self)
    }

    pub fn require_role(mut self, role: impl Into<String>) -> Result<Self, AuthorizationError> {
        let role = role.into();
        if !valid_token(&role) {
            return Err(AuthorizationError::InvalidPolicy);
        }
        self.required_role = Some(role);
        Ok(self)
    }

    pub fn require_reason(mut self) -> Self {
        self.reason_required = true;
        self
    }

    pub fn key(&self) -> String {
        format!("{}/{}", self.service, self.method)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub service: String,
    pub method: String,
    pub caller_service: String,
    pub allowed: bool,
}

#[derive(Debug)]
pub struct AuthorizationInput {
    pub service: String,
    pub method: String,
    pub workload: VerifiedWorkload,
    pub principal: Option<VerifiedPrincipal>,
    pub reason: Option<String>,
    pub now: SystemTime,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("RPC method is not registered")]
    UnregisteredMethod,
    #[error("authorization policy is invalid")]
    InvalidPolicy,
    #[error("workload identity is missing or expired")]
    MissingWorkload,
    #[error("workload service is not allowed for this RPC")]
    WorkloadNotAllowed,
    #[error("user principal is required")]
    MissingPrincipal,
    #[error("user principal does not have the required scope")]
    MissingScope,
    #[error("user principal does not have the required role")]
    MissingRole,
    #[error("an operator reason is required")]
    MissingReason,
}

#[derive(Debug, Default, Clone)]
pub struct AuthorizationRegistry {
    policies: BTreeMap<String, RpcMethodPolicy>,
}

impl AuthorizationRegistry {
    pub fn register(&mut self, policy: RpcMethodPolicy) -> Result<(), AuthorizationError> {
        let key = policy.key();
        if self.policies.contains_key(&key) {
            return Err(AuthorizationError::InvalidPolicy);
        }
        self.policies.insert(key, policy);
        Ok(())
    }

    pub fn authorize(
        &self,
        service: &str,
        method: &str,
        workload: Option<&VerifiedWorkload>,
        principal: Option<&VerifiedPrincipal>,
        reason: Option<&str>,
        now: SystemTime,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        let policy = self
            .policies
            .get(&format!("{service}/{method}"))
            .ok_or(AuthorizationError::UnregisteredMethod)?;
        let workload = workload.ok_or(AuthorizationError::MissingWorkload)?;
        workload
            .validate_at(now)
            .map_err(|_| AuthorizationError::MissingWorkload)?;
        let caller_service = workload.identity().service();
        if !policy.allowed_workload_services.is_empty()
            && !policy.allowed_workload_services.contains(caller_service)
        {
            return Err(AuthorizationError::WorkloadNotAllowed);
        }
        if let Some(scope) = policy.required_scope.as_deref() {
            let principal = principal.ok_or(AuthorizationError::MissingPrincipal)?;
            if !principal.has_scope(scope) {
                return Err(AuthorizationError::MissingScope);
            }
        }
        if let Some(role) = policy.required_role.as_deref() {
            let principal = principal.ok_or(AuthorizationError::MissingPrincipal)?;
            if !principal.has_role(role) {
                return Err(AuthorizationError::MissingRole);
            }
        }
        if policy.reason_required && reason.is_none_or(|value| value.trim().is_empty()) {
            return Err(AuthorizationError::MissingReason);
        }
        Ok(AuthorizationDecision {
            service: policy.service.clone(),
            method: policy.method.clone(),
            caller_service: caller_service.to_owned(),
            allowed: true,
        })
    }

    /// Authorize a Tonic request and install only verified identities in its
    /// extensions.  Handlers do not receive or inspect caller-supplied auth
    /// fields from the request message.
    pub fn authorize_request<T>(
        &self,
        mut request: tonic::Request<T>,
        input: AuthorizationInput,
    ) -> Result<(tonic::Request<T>, AuthorizationDecision), AuthorizationError> {
        let decision = self.authorize(
            &input.service,
            &input.method,
            Some(&input.workload),
            input.principal.as_ref(),
            input.reason.as_deref(),
            input.now,
        )?;
        request.extensions_mut().insert(input.workload);
        if let Some(principal) = input.principal {
            request.extensions_mut().insert(principal);
        }
        request.extensions_mut().insert(decision.clone());
        Ok((request, decision))
    }

    pub fn len(&self) -> usize {
        self.policies.len()
    }
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_identity::{SpiffeId, TrustDomain};

    fn workload(service: &str) -> VerifiedWorkload {
        let id = SpiffeId::new(
            TrustDomain::new("northstar.test").unwrap(),
            service,
            "r1",
            "prod",
        )
        .unwrap();
        VerifiedWorkload::new(
            id,
            SystemTime::now() + std::time::Duration::from_secs(30),
            "1",
        )
        .unwrap()
    }

    #[test]
    fn unknown_and_wrong_workload_methods_fail_closed() {
        let mut registry = AuthorizationRegistry::default();
        registry
            .register(
                RpcMethodPolicy::new("message-ingress", "SubmitMessage")
                    .unwrap()
                    .allow_workload_service("xmpp-edge")
                    .unwrap(),
            )
            .unwrap();
        let now = SystemTime::now();
        assert_eq!(
            registry.authorize(
                "message-ingress",
                "Unknown",
                Some(&workload("xmpp-edge")),
                None,
                None,
                now
            ),
            Err(AuthorizationError::UnregisteredMethod)
        );
        assert_eq!(
            registry.authorize(
                "message-ingress",
                "SubmitMessage",
                Some(&workload("identity")),
                None,
                None,
                now
            ),
            Err(AuthorizationError::WorkloadNotAllowed)
        );
    }

    #[test]
    fn scope_role_and_reason_are_checked_before_allow() {
        let mut registry = AuthorizationRegistry::default();
        registry
            .register(
                RpcMethodPolicy::new("admin", "Revoke")
                    .unwrap()
                    .allow_workload_service("admin-api")
                    .unwrap()
                    .require_scope("admin:revoke")
                    .unwrap()
                    .require_role("security-admin")
                    .unwrap()
                    .require_reason(),
            )
            .unwrap();
        let result = registry.authorize(
            "admin",
            "Revoke",
            Some(&workload("admin-api")),
            None,
            None,
            SystemTime::now(),
        );
        assert_eq!(result, Err(AuthorizationError::MissingPrincipal));
    }

    #[test]
    fn authorized_request_contains_only_verified_extensions() {
        let mut registry = AuthorizationRegistry::default();
        registry
            .register(
                RpcMethodPolicy::new("message-ingress", "SubmitMessage")
                    .unwrap()
                    .allow_workload_service("xmpp-edge")
                    .unwrap(),
            )
            .unwrap();
        let request = tonic::Request::new(());
        let (request, decision) = registry
            .authorize_request(
                request,
                AuthorizationInput {
                    service: "message-ingress".to_owned(),
                    method: "SubmitMessage".to_owned(),
                    workload: workload("xmpp-edge"),
                    principal: None,
                    reason: None,
                    now: SystemTime::now(),
                },
            )
            .unwrap();
        assert!(decision.allowed);
        assert!(request.extensions().get::<VerifiedWorkload>().is_some());
        assert!(request
            .extensions()
            .get::<AuthorizationDecision>()
            .is_some());
        assert!(request.extensions().get::<VerifiedPrincipal>().is_none());
    }

    #[test]
    fn duplicate_registration_cannot_replace_a_policy() {
        let mut registry = AuthorizationRegistry::default();
        let first = RpcMethodPolicy::new("svc", "Method")
            .unwrap()
            .allow_workload_service("first")
            .unwrap();
        let second = RpcMethodPolicy::new("svc", "Method")
            .unwrap()
            .allow_workload_service("second")
            .unwrap();
        registry.register(first).unwrap();
        assert_eq!(
            registry.register(second),
            Err(AuthorizationError::InvalidPolicy)
        );
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.authorize(
                "svc",
                "Method",
                Some(&workload("second")),
                None,
                None,
                SystemTime::now()
            ),
            Err(AuthorizationError::WorkloadNotAllowed)
        );
    }
}
