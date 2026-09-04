//! Identity microservice implementation.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 8, 19.1, 19.2, 19.4)
//! and `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, 2.1).

use foundation_contracts::common::{AuthContext, ErrorDetail};
use foundation_contracts::identity::{
    AuthenticateRequest, AuthenticateResponse, ChangePasswordRequest, ChangePasswordResponse,
    GetIdentityRequest, GetIdentityResponse, RegisterRequest, RegisterResponse,
    RevokeCredentialsRequest, RevokeCredentialsResponse,
};
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use northstar_auth_core::{
    compute_scram_sha256, constant_time_bytes_eq, generate_scram_salt, normalize_username,
    validate_password, MIN_SCRAM_ITERATIONS,
};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct StoredAccount {
    pub account_id: String,
    pub username: String,
    pub canonical_jid: String,
    pub scram_salt: Vec<u8>,
    pub scram_iterations: u32,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
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

    pub fn register(&self, req: RegisterRequest) -> RegisterResponse {
        let username = match normalize_username(&req.username) {
            Ok(u) if !u.is_empty() && !u.contains('@') => u,
            _ => {
                return RegisterResponse {
                    success: false,
                    account_id: String::new(),
                    canonical_jid: String::new(),
                    error: Some(ErrorDetail::new(
                        "INVALID_USERNAME",
                        "Username is invalid or contains forbidden characters",
                    )),
                };
            }
        };

        if let Err(_err) = validate_password(&req.password) {
            return RegisterResponse {
                success: false,
                account_id: String::new(),
                canonical_jid: String::new(),
                error: Some(ErrorDetail::new(
                    "WEAK_PASSWORD",
                    "Password does not meet length or complexity policy",
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
        let salt = generate_scram_salt();
        let iterations = MIN_SCRAM_ITERATIONS; // 4096 default for microservice prototype
        let (stored_key, server_key) = compute_scram_sha256(&req.password, &salt, iterations);

        let account = StoredAccount {
            account_id: account_id.clone(),
            username: username.clone(),
            canonical_jid: canonical_jid.clone(),
            scram_salt: salt,
            scram_iterations: iterations,
            stored_key,
            server_key,
            credential_generation: 1,
            status: "active".to_string(),
            home_region: "local".to_string(),
        };

        // Transactional Outbox: stage event in the same atomic unit
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
        let username =
            normalize_username(&req.username).unwrap_or_else(|_| req.username.to_lowercase());
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

        let incoming_password = String::from_utf8_lossy(&req.auth_payload);
        let (computed_stored, _) = compute_scram_sha256(
            &incoming_password,
            &account.scram_salt,
            account.scram_iterations,
        );

        if !constant_time_bytes_eq(&computed_stored, &account.stored_key) {
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
        if let Err(_err) = validate_password(&req.new_password) {
            return ChangePasswordResponse {
                success: false,
                new_credential_generation: 0,
                error: Some(ErrorDetail::new(
                    "WEAK_PASSWORD",
                    "New password does not meet complexity policy",
                )),
            };
        }

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

        let (computed_stored, _) = compute_scram_sha256(
            &req.old_password,
            &account.scram_salt,
            account.scram_iterations,
        );
        if !constant_time_bytes_eq(&computed_stored, &account.stored_key) {
            return ChangePasswordResponse {
                success: false,
                new_credential_generation: 0,
                error: Some(ErrorDetail::new(
                    "NOT_AUTHORIZED",
                    "Incorrect current password",
                )),
            };
        }

        let new_salt = generate_scram_salt();
        let (new_stored, new_server) =
            compute_scram_sha256(&req.new_password, &new_salt, account.scram_iterations);

        account.scram_salt = new_salt;
        account.stored_key = new_stored;
        account.server_key = new_server;
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
            GetIdentityRequest::ByUsername(u) => {
                let norm = normalize_username(&u).unwrap_or_else(|_| u.to_lowercase());
                accounts.get(&norm)
            }
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

        // 1. Register account with compliant password
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

        // 2. Authenticate successfully using SCRAM key verification
        let auth = identity.authenticate(AuthenticateRequest {
            username: "bob".to_string(),
            mechanism: "PLAIN".to_string(),
            auth_payload: b"SecretPassword123!".to_vec(),
            trace: None,
        });
        assert!(auth.success);
        let ctx = auth.auth_context.unwrap();
        assert_eq!(ctx.credential_generation, 1);

        // 3. Authenticate with wrong password fails in constant time
        let fail_auth = identity.authenticate(AuthenticateRequest {
            username: "bob".to_string(),
            mechanism: "PLAIN".to_string(),
            auth_payload: b"WrongPassword123!".to_vec(),
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
