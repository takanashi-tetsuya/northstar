//! Identity microservice implementation.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 8, 19.1, 19.2, 19.4).

use foundation_contracts::common::{AuthContext, ErrorDetail};
use foundation_contracts::identity::{
    AuthenticateRequest, AuthenticateResponse, ChangePasswordRequest, ChangePasswordResponse,
    GetIdentityRequest, GetIdentityResponse, RegisterRequest, RegisterResponse,
    RevokeCredentialsRequest, RevokeCredentialsResponse,
};
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct StoredAccount {
    pub account_id: String,
    pub username: String,
    pub canonical_jid: String,
    pub password_hash: String,
    pub credential_generation: u64,
    pub status: String,
    pub home_region: String,
}

pub struct IdentityService {
    domain: String,
    accounts: RwLock<HashMap<String, StoredAccount>>, // username -> account
    outbox: InMemoryOutbox,
}

impl IdentityService {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            accounts: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"salt_northstar_v2:");
        hasher.update(password.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn register(&self, req: RegisterRequest) -> RegisterResponse {
        let username = req.username.to_lowercase();
        if username.trim().is_empty() || username.contains('@') {
            return RegisterResponse {
                success: false,
                account_id: String::new(),
                canonical_jid: String::new(),
                error: Some(ErrorDetail::new(
                    "INVALID_USERNAME",
                    "Username contains invalid characters",
                )),
            };
        }

        let mut accounts = self.accounts.write().unwrap();
        if accounts.contains_key(&username) {
            return RegisterResponse {
                success: false,
                account_id: String::new(),
                canonical_jid: String::new(),
                error: Some(ErrorDetail::new("CONFLICT", "Username already exists")),
            };
        }

        let account_id = Uuid::new_v4().to_string();
        let canonical_jid = format!("{username}@{}", self.domain);
        let password_hash = Self::hash_password(&req.password);

        let account = StoredAccount {
            account_id: account_id.clone(),
            username: username.clone(),
            canonical_jid: canonical_jid.clone(),
            password_hash,
            credential_generation: 1,
            status: "active".to_string(),
            home_region: "local".to_string(),
        };

        // Transactional Outbox: stage event in the same transaction
        let outbox_payload =
            serde_json::to_vec(&foundation_contracts::events::AccountCreatedEventPayload {
                account_id: account_id.clone(),
                username: username.clone(),
                canonical_jid: canonical_jid.clone(),
                credential_generation: 1,
                home_region: "local".to_string(),
            })
            .unwrap_or_default();

        let event = OutboxEvent::new(
            "account",
            &account_id,
            1,
            "identity.account.created.v1",
            outbox_payload,
        );
        self.outbox.stage(event);

        accounts.insert(username, account);

        RegisterResponse {
            success: true,
            account_id,
            canonical_jid,
            error: None,
        }
    }

    pub fn authenticate(&self, req: AuthenticateRequest) -> AuthenticateResponse {
        let username = req.username.to_lowercase();
        let accounts = self.accounts.read().unwrap();

        let Some(account) = accounts.get(&username) else {
            return AuthenticateResponse {
                success: false,
                auth_context: None,
                challenge_or_response: Vec::new(),
                error: Some(ErrorDetail::new(
                    "NOT_AUTHORIZED",
                    "Invalid username or credentials",
                )),
            };
        };

        if account.status != "active" {
            return AuthenticateResponse {
                success: false,
                auth_context: None,
                challenge_or_response: Vec::new(),
                error: Some(ErrorDetail::new(
                    "ACCOUNT_DISABLED",
                    "Account is not active",
                )),
            };
        }

        let expected_hash = &account.password_hash;
        let incoming_password = String::from_utf8_lossy(&req.auth_payload);
        let incoming_hash = Self::hash_password(&incoming_password);

        if &incoming_hash != expected_hash {
            return AuthenticateResponse {
                success: false,
                auth_context: None,
                challenge_or_response: Vec::new(),
                error: Some(ErrorDetail::new(
                    "NOT_AUTHORIZED",
                    "Invalid username or credentials",
                )),
            };
        }

        let auth_context = AuthContext::new(
            &account.account_id,
            &account.canonical_jid,
            account.credential_generation,
            &account.home_region,
        )
        .with_role("user");

        AuthenticateResponse {
            success: true,
            auth_context: Some(auth_context),
            challenge_or_response: Vec::new(),
            error: None,
        }
    }

    pub fn change_password(&self, req: ChangePasswordRequest) -> ChangePasswordResponse {
        let mut accounts = self.accounts.write().unwrap();
        let account = accounts
            .values_mut()
            .find(|a| a.account_id == req.account_id);

        let Some(account) = account else {
            return ChangePasswordResponse {
                success: false,
                new_credential_generation: 0,
                error: Some(ErrorDetail::new("NOT_FOUND", "Account does not exist")),
            };
        };

        let old_hash = Self::hash_password(&req.old_password);
        if old_hash != account.password_hash {
            return ChangePasswordResponse {
                success: false,
                new_credential_generation: 0,
                error: Some(ErrorDetail::new(
                    "NOT_AUTHORIZED",
                    "Incorrect current password",
                )),
            };
        }

        account.password_hash = Self::hash_password(&req.new_password);
        account.credential_generation += 1;
        let new_generation = account.credential_generation;

        // Stage outbox event for credential generation change
        let event = OutboxEvent::new(
            "account",
            &account.account_id,
            new_generation,
            "identity.credential.revoked.v1",
            new_generation.to_be_bytes().to_vec(),
        );
        self.outbox.stage(event);

        ChangePasswordResponse {
            success: true,
            new_credential_generation: new_generation,
            error: None,
        }
    }

    pub fn revoke_credentials(&self, req: RevokeCredentialsRequest) -> RevokeCredentialsResponse {
        let mut accounts = self.accounts.write().unwrap();
        let account = accounts
            .values_mut()
            .find(|a| a.account_id == req.account_id);

        if let Some(account) = account {
            account.credential_generation += 1;
            let gen = account.credential_generation;

            let event = OutboxEvent::new(
                "account",
                &account.account_id,
                gen,
                "identity.credential.revoked.v1",
                gen.to_be_bytes().to_vec(),
            );
            self.outbox.stage(event);

            RevokeCredentialsResponse {
                success: true,
                new_credential_generation: gen,
            }
        } else {
            RevokeCredentialsResponse {
                success: false,
                new_credential_generation: 0,
            }
        }
    }

    pub fn get_identity(&self, req: GetIdentityRequest) -> GetIdentityResponse {
        let accounts = self.accounts.read().unwrap();
        let found = match req {
            GetIdentityRequest::ById(id) => accounts.values().find(|a| a.account_id == id),
            GetIdentityRequest::ByUsername(u) => accounts.get(&u.to_lowercase()),
            GetIdentityRequest::ByJid(j) => accounts.values().find(|a| a.canonical_jid == j),
        };

        if let Some(account) = found {
            let auth = AuthContext::new(
                &account.account_id,
                &account.canonical_jid,
                account.credential_generation,
                &account.home_region,
            )
            .with_role("user");

            GetIdentityResponse {
                found: true,
                identity: Some(auth),
                account_status: account.status.clone(),
            }
        } else {
            GetIdentityResponse {
                found: false,
                identity: None,
                account_status: String::new(),
            }
        }
    }

    pub fn pending_outbox(&self) -> Vec<OutboxEvent> {
        self.outbox.pending()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_authentication_and_revocation_lifecycle() {
        let identity = IdentityService::new("example.com");

        // 1. Register account
        let reg = identity.register(RegisterRequest {
            username: "bob".to_string(),
            password: "SecretPassword123!".to_string(),
            invitation_code: None,
            trace: None,
        });
        assert!(reg.success);
        assert_eq!(reg.canonical_jid, "bob@example.com");

        // Outbox event was staged atomically
        let pending = identity.pending_outbox();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_type, "identity.account.created.v1");

        // 2. Authenticate successfully
        let auth = identity.authenticate(AuthenticateRequest {
            username: "bob".to_string(),
            mechanism: "PLAIN".to_string(),
            auth_payload: b"SecretPassword123!".to_vec(),
            trace: None,
        });
        assert!(auth.success);
        let ctx = auth.auth_context.unwrap();
        assert_eq!(ctx.credential_generation, 1);

        // 3. Authenticate with wrong password fails
        let fail_auth = identity.authenticate(AuthenticateRequest {
            username: "bob".to_string(),
            mechanism: "PLAIN".to_string(),
            auth_payload: b"WrongPassword".to_vec(),
            trace: None,
        });
        assert!(!fail_auth.success);

        // 4. Revoke credentials bumps generation
        let revoke = identity.revoke_credentials(RevokeCredentialsRequest {
            account_id: reg.account_id.clone(),
            reason: "logout all".to_string(),
            trace: None,
        });
        assert!(revoke.success);
        assert_eq!(revoke.new_credential_generation, 2);

        // Outbox contains revocation event
        let pending_revoked = identity.pending_outbox();
        assert_eq!(pending_revoked.len(), 2);
    }
}
