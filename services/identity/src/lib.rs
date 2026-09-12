//! Identity microservice implementation.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 8, 19.1, 19.2, 19.4)
//! and `northstar_progress_and_next_plan_2026-09-04.md` (Milestone 1, 2.1).

use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration as ChronoDuration, Utc};
use foundation_contracts::adapters::assertions::AuthGrant;
use foundation_contracts::adapters::common::{AuthContext, ErrorDetail};
use foundation_contracts::adapters::identity::{
    AbortAuthenticationRequest, AbortAuthenticationResponse, AuthenticateRequest,
    AuthenticateResponse, ChangePasswordRequest, ChangePasswordResponse,
    ContinueAuthenticationRequest, ContinueAuthenticationResponse, GetIdentityRequest,
    GetIdentityResponse, RegisterRequest, RegisterResponse, RevokeCredentialsRequest,
    RevokeCredentialsResponse, StartAuthenticationRequest, StartAuthenticationResponse,
};
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use hmac::{Hmac, Mac};
use northstar_auth_core::{
    compute_scram_sha256, constant_time_bytes_eq, generate_scram_salt, normalize_username,
    validate_password, ChannelBindings, SaslMechanism, SaslStep, ScramSha256Mechanism,
    MIN_SCRAM_ITERATIONS,
};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

const AUTH_EXCHANGE_TTL: Duration = Duration::from_secs(60);
const AUTH_EXCHANGE_TTL_SECONDS: u32 = AUTH_EXCHANGE_TTL.as_secs() as u32;
const MAX_PENDING_AUTH_EXCHANGES: usize = 1_024;

struct PendingAuthentication {
    mechanism: ScramSha256Mechanism,
    username: String,
    channel_binding: String,
    expires_at: Instant,
}

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
    exchanges: Mutex<HashMap<String, PendingAuthentication>>,
    grant_signing_key: Vec<u8>,
}

impl IdentityService {
    pub fn new(domain: impl Into<String>) -> Self {
        let key_a = Uuid::new_v4();
        let key_b = Uuid::new_v4();
        Self {
            domain: domain.into(),
            accounts: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
            exchanges: Mutex::new(HashMap::new()),
            // The production deployment injects a KMS-backed signing key.
            // The in-memory service keeps a per-process key so tests never
            // accidentally treat a hard-coded key as a deployable secret.
            grant_signing_key: key_a
                .as_bytes()
                .iter()
                .copied()
                .chain(key_b.as_bytes().iter().copied())
                .collect(),
        }
    }

    /// Constructs the service with an explicit signing key for integration
    /// tests or a secret-manager adapter. Keys are copied once and never
    /// exposed through logs or public fields.
    pub fn with_grant_signing_key(domain: impl Into<String>, key: impl AsRef<[u8]>) -> Self {
        let mut service = Self::new(domain);
        service.grant_signing_key = key.as_ref().to_vec();
        service
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

        if let Err(_err) = validate_password(req.password.expose_for_authorized_use()) {
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
        let (stored_key, server_key) =
            compute_scram_sha256(req.password.expose_for_authorized_use(), &salt, iterations);

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
        let outbox_payload = serde_json::to_vec(
            &foundation_contracts::adapters::events::AccountCreatedEventPayload {
                account_id: account_id.clone(),
                username: username.clone(),
                canonical_jid: canonical_jid.clone(),
                credential_generation: 1,
                home_region: "local".to_string(),
            },
        )
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
                auth_grant: None,
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
                auth_grant: None,
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
                auth_grant: None,
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
            auth_grant: None,
            challenge_or_response: Vec::new(),
            error: None,
        }
    }

    fn authentication_failed() -> ErrorDetail {
        ErrorDetail::new("AUTHENTICATION_FAILED", "Authentication failed").with_domain("identity")
    }

    /// Starts a bounded, multi-round SCRAM exchange. Unknown and disabled
    /// accounts receive deterministic dummy credentials so this response does
    /// not become an account-enumeration oracle.
    pub fn start_authentication(
        &self,
        req: StartAuthenticationRequest,
    ) -> StartAuthenticationResponse {
        let mechanism_name = req.mechanism.trim().to_ascii_uppercase();
        let mut mechanism = match mechanism_name.as_str() {
            "SCRAM-SHA-256" => {
                ScramSha256Mechanism::new_with_channel_binding_support(self.domain.clone())
            }
            "SCRAM-SHA-256-PLUS" => {
                let Some(binding_name) = req.channel_binding.as_deref() else {
                    return StartAuthenticationResponse {
                        success: false,
                        exchange_id: None,
                        server_first: Vec::new(),
                        exchange_ttl_seconds: 0,
                        error: Some(Self::authentication_failed()),
                    };
                };
                let Some(binding) = req.channel_binding_data.as_ref() else {
                    return StartAuthenticationResponse {
                        success: false,
                        exchange_id: None,
                        server_first: Vec::new(),
                        exchange_ttl_seconds: 0,
                        error: Some(Self::authentication_failed()),
                    };
                };
                let available = match binding_name {
                    "tls-server-end-point" => ChannelBindings::from_available(
                        Some(binding.expose_for_authorized_use().to_vec()),
                        None,
                    ),
                    "tls-exporter" => ChannelBindings::from_available(
                        None,
                        Some(binding.expose_for_authorized_use().to_vec()),
                    ),
                    _ => Err(anyhow::anyhow!("unsupported channel binding")),
                };
                let Ok(Some(bindings)) = available else {
                    return StartAuthenticationResponse {
                        success: false,
                        exchange_id: None,
                        server_first: Vec::new(),
                        exchange_ttl_seconds: 0,
                        error: Some(Self::authentication_failed()),
                    };
                };
                ScramSha256Mechanism::new_plus(self.domain.clone(), bindings)
            }
            _ => {
                return StartAuthenticationResponse {
                    success: false,
                    exchange_id: None,
                    server_first: Vec::new(),
                    exchange_ttl_seconds: 0,
                    error: Some(Self::authentication_failed()),
                }
            }
        };

        let client_first =
            match String::from_utf8(req.client_first.expose_for_authorized_use().to_vec()) {
                Ok(value) => value,
                Err(_) => {
                    return StartAuthenticationResponse {
                        success: false,
                        exchange_id: None,
                        server_first: Vec::new(),
                        exchange_ttl_seconds: 0,
                        error: Some(Self::authentication_failed()),
                    }
                }
            };
        let username = match mechanism.initial_response(&STANDARD.encode(client_first)) {
            SaslStep::NeedsCredentials(username) => username,
            _ => {
                return StartAuthenticationResponse {
                    success: false,
                    exchange_id: None,
                    server_first: Vec::new(),
                    exchange_ttl_seconds: 0,
                    error: Some(Self::authentication_failed()),
                }
            }
        };
        let requested_username = normalize_username(&req.username).ok();
        if requested_username.as_deref() != Some(username.as_str()) {
            return StartAuthenticationResponse {
                success: false,
                exchange_id: None,
                server_first: Vec::new(),
                exchange_ttl_seconds: 0,
                error: Some(Self::authentication_failed()),
            };
        }

        let accounts = self.accounts.read().unwrap();
        let credentials = accounts
            .get(&username)
            .filter(|account| account.status == "active");
        let (salt, iterations, stored_key, server_key) = credentials
            .map(|account| {
                (
                    account.scram_salt.clone(),
                    account.scram_iterations,
                    account.stored_key.clone(),
                    account.server_key.clone(),
                )
            })
            .unwrap_or_else(|| {
                let (salt, stored_key, server_key) = northstar_auth_core::dummy_scram_credentials(
                    &[0x42; 32],
                    &username,
                    northstar_auth_core::ScramAlgorithm::Sha256,
                    MIN_SCRAM_ITERATIONS,
                );
                (salt, MIN_SCRAM_ITERATIONS, stored_key, server_key)
            });
        drop(accounts);

        let server_first =
            match mechanism.provide_credentials(salt, iterations, stored_key, server_key) {
                SaslStep::Challenge(challenge) => challenge.into_bytes(),
                _ => {
                    return StartAuthenticationResponse {
                        success: false,
                        exchange_id: None,
                        server_first: Vec::new(),
                        exchange_ttl_seconds: 0,
                        error: Some(Self::authentication_failed()),
                    }
                }
            };

        let mut exchanges = self.exchanges.lock().unwrap();
        let now = Instant::now();
        exchanges.retain(|_, exchange| exchange.expires_at > now);
        if exchanges.len() >= MAX_PENDING_AUTH_EXCHANGES {
            return StartAuthenticationResponse {
                success: false,
                exchange_id: None,
                server_first: Vec::new(),
                exchange_ttl_seconds: 0,
                error: Some(Self::authentication_failed().retryable(true)),
            };
        }
        let exchange_id = Uuid::new_v4().to_string();
        exchanges.insert(
            exchange_id.clone(),
            PendingAuthentication {
                mechanism,
                username,
                channel_binding: req.channel_binding.unwrap_or_else(|| "none".to_string()),
                expires_at: now + AUTH_EXCHANGE_TTL,
            },
        );
        StartAuthenticationResponse {
            success: true,
            exchange_id: Some(foundation_security::OpaqueToken::new(exchange_id)),
            server_first,
            exchange_ttl_seconds: AUTH_EXCHANGE_TTL_SECONDS,
            error: None,
        }
    }

    /// Consumes the exchange before processing the client-final message. This
    /// makes retries and nonce replays fail closed even if the verifier panics
    /// or the caller concurrently submits the same exchange id.
    pub fn continue_authentication(
        &self,
        req: ContinueAuthenticationRequest,
    ) -> ContinueAuthenticationResponse {
        let exchange_id = req.exchange_id.expose_for_authorized_transport().to_owned();
        let pending = self.exchanges.lock().unwrap().remove(&exchange_id);
        let Some(mut pending) = pending else {
            return ContinueAuthenticationResponse {
                success: false,
                server_final: Vec::new(),
                auth_grant: None,
                error: Some(Self::authentication_failed()),
            };
        };
        if pending.expires_at <= Instant::now() {
            return ContinueAuthenticationResponse {
                success: false,
                server_final: Vec::new(),
                auth_grant: None,
                error: Some(Self::authentication_failed()),
            };
        }
        let step = pending
            .mechanism
            .response(&STANDARD.encode(req.client_final.expose_for_authorized_use()));
        let SaslStep::Success(username, server_final) = step else {
            return ContinueAuthenticationResponse {
                success: false,
                server_final: Vec::new(),
                auth_grant: None,
                error: Some(Self::authentication_failed()),
            };
        };
        if username != pending.username {
            return ContinueAuthenticationResponse {
                success: false,
                server_final: Vec::new(),
                auth_grant: None,
                error: Some(Self::authentication_failed()),
            };
        }
        let accounts = self.accounts.read().unwrap();
        let Some(account) = accounts
            .get(&username)
            .filter(|account| account.status == "active")
        else {
            return ContinueAuthenticationResponse {
                success: false,
                server_final: Vec::new(),
                auth_grant: None,
                error: Some(Self::authentication_failed()),
            };
        };
        let grant = self.issue_auth_grant(account, &pending.channel_binding);
        ContinueAuthenticationResponse {
            success: true,
            server_final: server_final
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default(),
            auth_grant: Some(grant),
            error: None,
        }
    }

    fn issue_auth_grant(&self, account: &StoredAccount, channel_binding: &str) -> AuthGrant {
        let now = Utc::now();
        let mut grant = AuthGrant {
            issuer: format!("identity.{}", self.domain),
            audience: "northstar.session-directory".to_string(),
            issued_at: now,
            not_before: now,
            expires_at: now + ChronoDuration::minutes(5),
            jwt_id: Uuid::new_v4().to_string(),
            schema_version: 1,
            account_id: account.account_id.clone(),
            bare_jid: account.canonical_jid.clone(),
            credential_generation: account.credential_generation,
            auth_method: "SCRAM-SHA-256".to_string(),
            auth_strength: "password".to_string(),
            channel_binding: channel_binding.to_string(),
            key_id: "identity-process".to_string(),
            algorithm: "HMAC-SHA256".to_string(),
            signature: Vec::new(),
            scopes: vec!["xmpp:bind".to_string(), "xmpp:session".to_string()],
        };
        let mut signer = Hmac::<Sha256>::new_from_slice(&self.grant_signing_key)
            .expect("a UUID-derived signing key is non-empty");
        signer.update(&grant.canonical_bytes_without_signature());
        grant.signature = signer.finalize().into_bytes().to_vec();
        grant
    }

    /// Aborting an unknown exchange is intentionally idempotent: the caller
    /// cannot use this endpoint to probe whether an exchange id exists.
    pub fn abort_authentication(
        &self,
        req: AbortAuthenticationRequest,
    ) -> AbortAuthenticationResponse {
        self.exchanges
            .lock()
            .unwrap()
            .remove(req.exchange_id.expose_for_authorized_transport());
        AbortAuthenticationResponse {
            success: true,
            error: None,
        }
    }

    pub fn change_password(&self, req: ChangePasswordRequest) -> ChangePasswordResponse {
        if let Err(_err) = validate_password(req.new_password.expose_for_authorized_use()) {
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
            req.old_password.expose_for_authorized_use(),
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
        let (new_stored, new_server) = compute_scram_sha256(
            req.new_password.expose_for_authorized_use(),
            &new_salt,
            account.scram_iterations,
        );

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
    use foundation_security::{OpaqueToken, SecretBytes, SecretString};

    #[test]
    fn registration_authentication_and_revocation_lifecycle() {
        let identity = IdentityService::new("example.com");

        // 1. Register account with compliant password
        let reg = identity.register(RegisterRequest {
            username: "bob".to_string(),
            password: SecretString::new("SecretPassword123!"),
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

    #[test]
    fn scram_exchange_is_bounded_and_single_use() {
        let identity = IdentityService::with_grant_signing_key("example.com", [0x11; 32]);
        let registration = identity.register(RegisterRequest {
            username: "bob".to_string(),
            password: SecretString::new("SecretPassword123!"),
            invitation_code: None,
            trace: None,
        });
        assert!(registration.success);

        let started = identity.start_authentication(StartAuthenticationRequest {
            username: "bob".to_string(),
            mechanism: "SCRAM-SHA-256".to_string(),
            client_first: SecretBytes::new(b"n,,n=bob,r=clientnonce".to_vec()),
            channel_binding: None,
            channel_binding_data: None,
            trace: None,
        });
        assert!(started.success);
        assert_eq!(started.exchange_ttl_seconds, AUTH_EXCHANGE_TTL_SECONDS);
        assert!(!started.server_first.is_empty());
        let exchange_id = started.exchange_id.expect("exchange id");

        // A malformed final consumes the exchange and returns only the
        // uniform public failure, never parser or account details.
        let failed = identity.continue_authentication(ContinueAuthenticationRequest {
            exchange_id: exchange_id.clone(),
            client_final: SecretBytes::new(b"c=biws".to_vec()),
            trace: None,
        });
        assert!(!failed.success);
        assert_eq!(
            failed.error.as_ref().map(|error| error.code.as_str()),
            Some("AUTHENTICATION_FAILED")
        );

        let replay = identity.continue_authentication(ContinueAuthenticationRequest {
            exchange_id,
            client_final: SecretBytes::new(b"c=biws".to_vec()),
            trace: None,
        });
        assert!(!replay.success);
        assert_eq!(
            replay.error.as_ref().map(|error| error.code.as_str()),
            Some("AUTHENTICATION_FAILED")
        );
    }

    #[test]
    fn scram_exchange_verifies_a_valid_proof_and_issues_a_grant() {
        use hmac::Mac as _;
        use pbkdf2::pbkdf2;
        use sha2::{Digest, Sha256};

        let identity = IdentityService::with_grant_signing_key("example.com", [0x33; 32]);
        let registration = identity.register(RegisterRequest {
            username: "bob".to_string(),
            password: SecretString::new("SecretPassword123!"),
            invitation_code: None,
            trace: None,
        });
        assert!(registration.success);
        let client_first_bare = "n=bob,r=clientnonce";
        let started = identity.start_authentication(StartAuthenticationRequest {
            username: "bob".to_string(),
            mechanism: "SCRAM-SHA-256".to_string(),
            client_first: SecretBytes::new(format!("n,,{client_first_bare}").into_bytes()),
            channel_binding: None,
            channel_binding_data: None,
            trace: None,
        });
        assert!(started.success);
        let exchange_id = started.exchange_id.unwrap();
        let server_first = String::from_utf8(started.server_first).unwrap();
        let fields = server_first
            .split(',')
            .map(|part| part.split_once('=').unwrap())
            .collect::<HashMap<_, _>>();
        let nonce = fields["r"];
        let salt = STANDARD.decode(fields["s"]).unwrap();
        let iterations = fields["i"].parse::<u32>().unwrap();
        let mut salted_password = [0_u8; 32];
        pbkdf2::<Hmac<Sha256>>(
            b"SecretPassword123!",
            &salt,
            iterations,
            &mut salted_password,
        )
        .unwrap();
        let mut client_key_mac = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        client_key_mac.update(b"Client Key");
        let client_key = client_key_mac.finalize().into_bytes();
        let stored_key = Sha256::digest(client_key);
        let client_final_bare = format!("c=biws,r={nonce}");
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");
        let mut signature_mac = Hmac::<Sha256>::new_from_slice(&stored_key).unwrap();
        signature_mac.update(auth_message.as_bytes());
        let signature = signature_mac.finalize().into_bytes();
        let proof: Vec<u8> = client_key
            .iter()
            .zip(signature.iter())
            .map(|(key, sig)| key ^ sig)
            .collect();
        let client_final = format!("{client_final_bare},p={}", STANDARD.encode(proof));
        let completed = identity.continue_authentication(ContinueAuthenticationRequest {
            exchange_id,
            client_final: SecretBytes::new(client_final.into_bytes()),
            trace: None,
        });
        assert!(completed.success);
        assert!(!completed.server_final.is_empty());
        let grant = completed.auth_grant.unwrap();
        assert_eq!(grant.bare_jid, "bob@example.com");
        assert_eq!(grant.credential_generation, 1);
        assert!(!grant.signature.is_empty());
        grant
            .validate_at(Utc::now(), "northstar.session-directory")
            .unwrap();
    }

    #[test]
    fn unknown_accounts_receive_a_challenge_but_never_a_grant() {
        let identity = IdentityService::with_grant_signing_key("example.com", [0x22; 32]);
        let started = identity.start_authentication(StartAuthenticationRequest {
            username: "missing".to_string(),
            mechanism: "SCRAM-SHA-256".to_string(),
            client_first: SecretBytes::new(b"n,,n=missing,r=clientnonce".to_vec()),
            channel_binding: None,
            channel_binding_data: None,
            trace: None,
        });
        assert!(started.success);
        let result = identity.continue_authentication(ContinueAuthenticationRequest {
            exchange_id: started.exchange_id.unwrap(),
            client_final: SecretBytes::new(
                b"c=biws,r=clientnonce,p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_vec(),
            ),
            trace: None,
        });
        assert!(!result.success);
        assert!(result.auth_grant.is_none());
    }

    #[test]
    fn abort_is_idempotent_and_does_not_reveal_exchange_state() {
        let identity = IdentityService::new("example.com");
        let token = OpaqueToken::new("does-not-exist");
        let first = identity.abort_authentication(AbortAuthenticationRequest {
            exchange_id: token.clone(),
            reason: "client cancelled".to_string(),
            trace: None,
        });
        let second = identity.abort_authentication(AbortAuthenticationRequest {
            exchange_id: token,
            reason: "client cancelled".to_string(),
            trace: None,
        });
        assert!(first.success && second.success);
    }
}
