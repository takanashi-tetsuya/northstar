use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub(crate) fn relying_party(public_url: &str) -> Result<Webauthn> {
    let url = Url::parse(public_url).context("invalid Passkeys origin")?;
    let host = url.host_str().context("Passkeys origin has no host")?;
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && host == "localhost"),
        "Passkeys require HTTPS (except localhost)"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "invalid Passkeys origin"
    );
    WebauthnBuilder::new(host, &url)
        .context("invalid Passkeys relying party")?
        .rp_name("Northstar")
        .build()
        .context("could not build Passkeys relying party")
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Registration {
    pub state: PasskeyRegistration,
    pub label: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Login {
    pub state: PasskeyAuthentication,
    pub device_id: Uuid,
    pub credentials: Vec<CredentialVersion>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CredentialVersion {
    pub id: Uuid,
    pub revision: Uuid,
    pub passkey: Passkey,
}

#[derive(Clone, Copy)]
pub(crate) struct PasskeyActor<'a> {
    pub id: Uuid,
    pub username: &'a str,
    pub auth_generation: i64,
    pub session_token: &'a str,
}

pub(crate) struct PasskeyAccount {
    pub id: Uuid,
    pub auth_generation: i64,
}

pub(crate) struct StoredCredential {
    pub id: Uuid,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub credential: serde_json::Value,
    pub revision: Uuid,
}

pub(crate) struct StoredChallenge {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub state: serde_json::Value,
}

#[derive(Serialize)]
pub(crate) struct PasskeySummary {
    pub id: Uuid,
    pub label: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub(crate) struct PasskeyOptions<T> {
    pub challenge_id: Uuid,
    pub options: T,
}

pub(crate) struct PasskeyLoginOutcome {
    pub session: PasskeyLoginSession,
    pub jid: String,
    pub device_id: Uuid,
}

pub(crate) struct PasskeyLoginCommit<'a> {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub credential_id: Uuid,
    pub credential_revision: Uuid,
    pub credential: &'a serde_json::Value,
    pub counter: u32,
    pub device_id: Uuid,
    pub fast_token_ttl_days: i64,
    pub fast_strong_reauth_max_days: i64,
    pub session_ttl_hours: i64,
}

pub(crate) struct PasskeyLoginSession {
    pub token: zeroize::Zeroizing<String>,
    pub username: String,
    pub is_admin: bool,
    pub fast_token: zeroize::Zeroizing<String>,
    pub fast_expires_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) trait PasskeyRepository: Send + Sync {
    fn account(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = Result<Option<PasskeyAccount>>> + Send;
    fn credentials(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Vec<StoredCredential>>> + Send;
    fn authorized_credentials(
        &self,
        actor: &PasskeyActor<'_>,
    ) -> impl std::future::Future<Output = Result<Option<Vec<StoredCredential>>>> + Send;
    fn verify_password(
        &self,
        actor: &PasskeyActor<'_>,
        password: &str,
        iterations: u32,
        sha1: bool,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn challenge(
        &self,
        user: Uuid,
        generation: i64,
        kind: &str,
        session_hash: Option<&[u8]>,
        state: &serde_json::Value,
    ) -> impl std::future::Future<Output = Result<Option<Uuid>>> + Send;
    fn consume(
        &self,
        id: Uuid,
        kind: &str,
        session_hash: Option<&[u8]>,
    ) -> impl std::future::Future<Output = Result<Option<StoredChallenge>>> + Send;
    fn register(
        &self,
        actor: &PasskeyActor<'_>,
        credential_id: &[u8],
        credential: &serde_json::Value,
        label: &str,
    ) -> impl std::future::Future<Output = Result<Option<Uuid>>> + Send;
    /// Credential acceptance, FAST issuance and the API session share one commit.
    fn complete_login(
        &self,
        command: PasskeyLoginCommit<'_>,
    ) -> impl std::future::Future<Output = Result<Option<PasskeyLoginSession>>> + Send;
    fn remove(
        &self,
        actor: &PasskeyActor<'_>,
        id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<i64>>> + Send;
}

pub(crate) struct PasskeyConfig {
    pub enabled: bool,
    pub public_url: String,
    pub domain: String,
    pub scram_iterations: u32,
    pub scram_sha1_enabled: bool,
    pub fast_token_ttl_days: i64,
    pub fast_strong_reauth_max_days: i64,
    pub session_ttl_hours: i64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PasskeyError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("Passkeys are unavailable")]
    Disabled,
    #[error("Passkeys are unavailable for this origin")]
    InvalidOrigin,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("too many unfinished Passkey requests")]
    Busy,
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

impl From<serde_json::Error> for PasskeyError {
    fn from(error: serde_json::Error) -> Self {
        Self::Backend(error.into())
    }
}

pub(crate) struct PasskeyService<R> {
    repository: R,
    config: PasskeyConfig,
}

impl<R: PasskeyRepository> PasskeyService<R> {
    pub(crate) fn new(repository: R, config: PasskeyConfig) -> Self {
        Self { repository, config }
    }

    fn party(&self) -> Result<Webauthn, PasskeyError> {
        if !self.config.enabled {
            return Err(PasskeyError::Disabled);
        }
        relying_party(&self.config.public_url).map_err(|_| PasskeyError::InvalidOrigin)
    }

    pub(crate) fn allowed_origin(&self) -> Result<String, PasskeyError> {
        Ok(self.party()?.get_allowed_origins()[0]
            .origin()
            .ascii_serialization())
    }

    pub(crate) async fn list(
        &self,
        actor: PasskeyActor<'_>,
    ) -> Result<Vec<PasskeySummary>, PasskeyError> {
        let credentials = self
            .repository
            .authorized_credentials(&actor)
            .await?
            .ok_or(PasskeyError::Unauthorized)?;
        Ok(credentials
            .into_iter()
            .map(|key| PasskeySummary {
                id: key.id,
                label: key.label,
                created_at: key.created_at,
                last_used_at: key.last_used_at,
            })
            .collect())
    }

    async fn verify_password(
        &self,
        actor: &PasskeyActor<'_>,
        password: &str,
    ) -> Result<(), PasskeyError> {
        if password.is_empty()
            || password.len() > 1024
            || !self
                .repository
                .verify_password(
                    actor,
                    password,
                    self.config.scram_iterations,
                    self.config.scram_sha1_enabled,
                )
                .await?
        {
            return Err(PasskeyError::Unauthorized);
        }
        Ok(())
    }

    pub(crate) async fn register_start(
        &self,
        actor: PasskeyActor<'_>,
        password: &str,
        label: String,
    ) -> Result<PasskeyOptions<CreationChallengeResponse>, PasskeyError> {
        let party = self.party()?;
        if label.trim().is_empty()
            || label.chars().count() > 64
            || label.chars().any(char::is_control)
        {
            return Err(PasskeyError::Invalid(
                "Passkey name must contain 1 to 64 characters",
            ));
        }
        self.verify_password(&actor, password).await?;
        let keys = self.repository.credentials(actor.id).await?;
        if keys.len() >= 10 {
            return Err(PasskeyError::Invalid(
                "An account can have at most 10 Passkeys",
            ));
        }
        let excluded = keys
            .into_iter()
            .map(|key| {
                serde_json::from_value::<Passkey>(key.credential).map(|key| key.cred_id().clone())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let (options, registration) = party
            .start_passkey_registration(actor.id, actor.username, actor.username, Some(excluded))
            .map_err(anyhow::Error::from)?;
        let stored = serde_json::to_value(Registration {
            state: registration,
            label,
        })?;
        let id = self
            .repository
            .challenge(
                actor.id,
                actor.auth_generation,
                "register",
                Some(&crate::auth::token_hash(actor.session_token)),
                &stored,
            )
            .await?
            .ok_or(PasskeyError::Busy)?;
        Ok(PasskeyOptions {
            challenge_id: id,
            options,
        })
    }

    pub(crate) async fn register_finish(
        &self,
        actor: PasskeyActor<'_>,
        challenge_id: Uuid,
        credential: RegisterPublicKeyCredential,
    ) -> Result<Uuid, PasskeyError> {
        let party = self.party()?;
        let session = crate::auth::token_hash(actor.session_token);
        let challenge = self
            .repository
            .consume(challenge_id, "register", Some(&session))
            .await?
            .ok_or(PasskeyError::Unauthorized)?;
        if challenge.user_id != actor.id || challenge.auth_generation != actor.auth_generation {
            return Err(PasskeyError::Unauthorized);
        }
        let registration: Registration = serde_json::from_value(challenge.state)?;
        let key = party
            .finish_passkey_registration(&credential, &registration.state)
            .map_err(|_| PasskeyError::Unauthorized)?;
        let stored = serde_json::to_value(&key)?;
        self.repository
            .register(&actor, key.cred_id().as_ref(), &stored, &registration.label)
            .await?
            .ok_or(PasskeyError::Invalid(
                "Passkey could not be added; start again",
            ))
    }

    pub(crate) async fn login_start(
        &self,
        username: &str,
        device_id: Uuid,
    ) -> Result<PasskeyOptions<RequestChallengeResponse>, PasskeyError> {
        let party = self.party()?;
        if device_id.get_version_num() != 4 {
            return Err(PasskeyError::Invalid("Invalid device ID"));
        }
        let user = self
            .repository
            .account(username)
            .await?
            .ok_or(PasskeyError::Unauthorized)?;
        let credentials = self
            .repository
            .credentials(user.id)
            .await?
            .into_iter()
            .map(|key| {
                Ok(CredentialVersion {
                    id: key.id,
                    revision: key.revision,
                    passkey: serde_json::from_value(key.credential)?,
                })
            })
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()?;
        if credentials.is_empty() {
            return Err(PasskeyError::Unauthorized);
        }
        let keys = credentials
            .iter()
            .map(|key| key.passkey.clone())
            .collect::<Vec<_>>();
        let (options, login) = party
            .start_passkey_authentication(&keys)
            .map_err(anyhow::Error::from)?;
        let stored = serde_json::to_value(Login {
            state: login,
            device_id,
            credentials,
        })?;
        let id = self
            .repository
            .challenge(user.id, user.auth_generation, "login", None, &stored)
            .await?
            .ok_or(PasskeyError::Busy)?;
        Ok(PasskeyOptions {
            challenge_id: id,
            options,
        })
    }

    pub(crate) async fn login_finish(
        &self,
        challenge_id: Uuid,
        credential: PublicKeyCredential,
    ) -> Result<PasskeyLoginOutcome, PasskeyError> {
        let party = self.party()?;
        let challenge = self
            .repository
            .consume(challenge_id, "login", None)
            .await?
            .ok_or(PasskeyError::Unauthorized)?;
        let login: Login = serde_json::from_value(challenge.state)?;
        let result = party
            .finish_passkey_authentication(&credential, &login.state)
            .map_err(|_| PasskeyError::Unauthorized)?;
        let mut key = login
            .credentials
            .into_iter()
            .find(|key| key.passkey.cred_id() == result.cred_id())
            .ok_or(PasskeyError::Unauthorized)?;
        key.passkey
            .update_credential(&result)
            .ok_or(PasskeyError::Unauthorized)?;
        let stored = serde_json::to_value(&key.passkey)?;
        let session = self
            .repository
            .complete_login(PasskeyLoginCommit {
                user_id: challenge.user_id,
                auth_generation: challenge.auth_generation,
                credential_id: key.id,
                credential_revision: key.revision,
                credential: &stored,
                counter: result.counter(),
                device_id: login.device_id,
                fast_token_ttl_days: self.config.fast_token_ttl_days,
                fast_strong_reauth_max_days: self.config.fast_strong_reauth_max_days,
                session_ttl_hours: self.config.session_ttl_hours,
            })
            .await?
            .ok_or(PasskeyError::Unauthorized)?;
        Ok(PasskeyLoginOutcome {
            jid: format!("{}@{}", session.username, self.config.domain),
            device_id: login.device_id,
            session,
        })
    }

    pub(crate) async fn remove(
        &self,
        actor: PasskeyActor<'_>,
        password: &str,
        id: Uuid,
    ) -> Result<i64, PasskeyError> {
        self.party()?;
        self.verify_password(&actor, password).await?;
        self.repository
            .remove(&actor, id)
            .await?
            .ok_or(PasskeyError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const ORIGIN: &str = "https://chat.example.test";

    fn client_data(kind: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"type":kind,"challenge":challenge,"origin":origin,"crossOrigin":false}),
        )
        .unwrap()
    }

    fn authenticator_data(flags: u8, counter: u32) -> Vec<u8> {
        let mut data = Sha256::digest(b"chat.example.test").to_vec();
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        data
    }

    fn registration(
        key: &EcdsaKeyPair,
        id: &[u8],
        challenge: &str,
        origin: &str,
        flags: u8,
    ) -> RegisterPublicKeyCredential {
        let public = key.public_key().as_ref();
        let mut data = authenticator_data(flags | 0x40, 0);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        data.extend_from_slice(id);
        // COSE EC2 / ES256 public key, encoded as a small CBOR fixture.
        data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        data.extend_from_slice(&public[1..33]);
        data.extend_from_slice(&[0x22, 0x58, 0x20]);
        data.extend_from_slice(&public[33..65]);
        let mut attestation = vec![0xa3, 0x63];
        attestation.extend_from_slice(b"fmt");
        attestation.push(0x64);
        attestation.extend_from_slice(b"none");
        attestation.push(0x68);
        attestation.extend_from_slice(b"authData");
        attestation.extend_from_slice(&[0x58, u8::try_from(data.len()).unwrap()]);
        attestation.extend_from_slice(&data);
        attestation.push(0x67);
        attestation.extend_from_slice(b"attStmt");
        attestation.push(0xa0);
        serde_json::from_value(json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),
            "type":"public-key","extensions":{},"response":{
                "attestationObject":URL_SAFE_NO_PAD.encode(attestation),
                "clientDataJSON":URL_SAFE_NO_PAD.encode(client_data("webauthn.create",challenge,origin)),"transports":["internal"]}})).unwrap()
    }

    fn assertion(
        key: &EcdsaKeyPair,
        id: &[u8],
        challenge: &str,
        origin: &str,
        flags: u8,
        counter: u32,
    ) -> PublicKeyCredential {
        let data = authenticator_data(flags, counter);
        let client = client_data("webauthn.get", challenge, origin);
        let mut signed = data.clone();
        signed.extend_from_slice(&Sha256::digest(&client));
        let signature = key.sign(&ring::rand::SystemRandom::new(), &signed).unwrap();
        serde_json::from_value(json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),
            "type":"public-key","extensions":{},"response":{
                "authenticatorData":URL_SAFE_NO_PAD.encode(data),"clientDataJSON":URL_SAFE_NO_PAD.encode(client),
                "signature":URL_SAFE_NO_PAD.encode(signature.as_ref()),"userHandle":null}})).unwrap()
    }

    #[test]
    fn passkeys_bind_origin_challenge_signature_and_user_verification() {
        let party = relying_party(ORIGIN).unwrap();
        let random = ring::rand::SystemRandom::new();
        let generated =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, generated.as_ref(), &random)
                .unwrap();
        let id = Sha256::digest(key.public_key().as_ref());
        let (options, registration_state) = party
            .start_passkey_registration(Uuid::new_v4(), "alice", "Alice", None)
            .unwrap();
        let options = serde_json::to_value(options).unwrap();
        let challenge = options["publicKey"]["challenge"].as_str().unwrap();
        for (origin, flags) in [
            ("https://evil.example.test", 5),
            ("https://child.chat.example.test", 5),
            (ORIGIN, 1),
        ] {
            assert!(party
                .finish_passkey_registration(
                    &registration(&key, &id, challenge, origin, flags),
                    &registration_state
                )
                .is_err());
        }
        let registered = party
            .finish_passkey_registration(
                &registration(&key, &id, challenge, ORIGIN, 5),
                &registration_state,
            )
            .unwrap();
        let (options, state) = party.start_passkey_authentication(&[registered]).unwrap();
        let options = serde_json::to_value(options).unwrap();
        let challenge = options["publicKey"]["challenge"].as_str().unwrap();
        for (origin, proof_challenge, flags) in [
            ("https://evil.example.test", challenge, 5),
            ("https://chat.example.test:8443", challenge, 5),
            (ORIGIN, "different-challenge", 5),
            (ORIGIN, challenge, 1),
        ] {
            assert!(party
                .finish_passkey_authentication(
                    &assertion(&key, &id, proof_challenge, origin, flags, 1),
                    &state
                )
                .is_err());
        }
        let valid = assertion(&key, &id, challenge, ORIGIN, 5, 1);
        assert_eq!(
            party
                .finish_passkey_authentication(&valid, &state)
                .unwrap()
                .counter(),
            1
        );
        let mut tampered = serde_json::to_value(valid).unwrap();
        tampered["response"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
        assert!(party
            .finish_passkey_authentication(&serde_json::from_value(tampered).unwrap(), &state)
            .is_err());
        assert!(relying_party("http://chat.example.test").is_err());
        assert!(relying_party("http://localhost:8080").is_ok());
    }
}
