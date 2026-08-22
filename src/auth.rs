use anyhow::Result;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub fn normalize_username(value: &str) -> Result<String> {
    let username = value.trim().to_ascii_lowercase();
    if username.len() < 3 || username.len() > 64 {
        anyhow::bail!("username must contain 3 to 64 characters");
    }
    if !username
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        anyhow::bail!("username contains unsupported characters");
    }
    Ok(username)
}

pub fn validate_password(value: &str) -> Result<()> {
    if value.len() < 10 || value.len() > 1024 {
        anyhow::bail!("password must contain 10 to 1024 characters");
    }
    Ok(())
}

pub fn generate_scram_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill(&mut salt[..]);
    salt
}

pub fn compute_scram_sha256(password: &str, salt: &[u8], iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let mut salted_password = vec![0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut salted_password)
        .expect("pbkdf2 should not fail");

    let mut mac_client = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
    mac_client.update(b"Client Key");
    let client_key = mac_client.finalize().into_bytes();

    let stored_key = Sha256::digest(client_key).to_vec();

    let mut mac_server = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
    mac_server.update(b"Server Key");
    let server_key = mac_server.finalize().into_bytes().to_vec();

    (stored_key, server_key)
}

pub struct PasswordCredentials {
    pub hash: String,
    pub scram_salt: Vec<u8>,
    pub scram_iterations: u32,
    pub scram_stored_key: Vec<u8>,
    pub scram_server_key: Vec<u8>,
}

pub fn hash_password(value: &str, validate: bool) -> Result<PasswordCredentials> {
    if validate {
        validate_password(value)?;
    }
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(value.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("password hashing failed: {error}"))?;

    let scram_salt = generate_scram_salt();
    let scram_iterations = 4096;
    let (scram_stored_key, scram_server_key) =
        compute_scram_sha256(value, &scram_salt, scram_iterations);

    Ok(PasswordCredentials {
        hash,
        scram_salt,
        scram_iterations,
        scram_stored_key,
        scram_server_key,
    })
}

pub fn verify_password(hash: &str, candidate: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .and_then(|parsed| {
            Argon2::default()
                .verify_password(candidate.as_bytes(), &parsed)
                .ok()
        })
        .is_some()
}

pub fn verify_against_dummy_hash(candidate: &str) {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    let hash = DUMMY_HASH.get_or_init(|| {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"northstar-dummy-authentication-secret", &salt)
            .expect("dummy password hashing should succeed")
            .to_string()
    });
    let _ = verify_password(hash, candidate);
}

pub fn new_session_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

use std::collections::HashMap;

/// Result of a SASL exchange step
pub enum SaslStep {
    /// Authentication succeeded. Contains the authenticated username.
    Success(String, Option<String>), // (username, optional success-data for SCRAM)
    /// Need to send a challenge to the client and wait for response.
    Challenge(String), // base64-encoded challenge
    /// Need credentials for the given username to proceed (SCRAM)
    NeedsCredentials(String),
    /// Authentication failed.
    Failure(String), // error condition
}

/// Trait for SASL mechanism implementations
pub trait SaslMechanism: Send + Sync {
    /// Process the initial client response (from <auth> element)
    fn initial_response(&mut self, data: &str) -> SaslStep;
    /// Process a subsequent client response (from <response> element)
    fn response(&mut self, data: &str) -> SaslStep;
    /// Provide credentials retrieved from the database (for SCRAM)
    fn provide_credentials(
        &mut self,
        _salt: Vec<u8>,
        _iters: u32,
        _stored_key: Vec<u8>,
        _server_key: Vec<u8>,
    ) -> SaslStep {
        SaslStep::Failure("Credentials not expected".into())
    }
    /// Get the mechanism name
    fn name(&self) -> &'static str;
}

/// PLAIN mechanism - only allowed inside TLS
pub struct PlainMechanism {
    domain: String,
}

impl PlainMechanism {
    pub fn new(domain: String) -> Self {
        Self { domain }
    }
}

impl SaslMechanism for PlainMechanism {
    fn initial_response(&mut self, data: &str) -> SaslStep {
        let bytes = match STANDARD.decode(data.trim()) {
            Ok(b) => b,
            Err(_) => return SaslStep::Failure("Invalid base64".into()),
        };
        let value = match String::from_utf8(bytes) {
            Ok(v) => v,
            Err(_) => return SaslStep::Failure("Invalid UTF-8".into()),
        };
        let mut fields = value.split('\0');
        let authz = fields.next().unwrap_or_default();
        let authc = match fields.next() {
            Some(a) => a,
            None => return SaslStep::Failure("Missing username".into()),
        };
        let pass = match fields.next() {
            Some(p) => p,
            None => return SaslStep::Failure("Missing password".into()),
        };
        if fields.next().is_some() {
            return SaslStep::Failure("Invalid PLAIN payload".into());
        }
        let username = match normalize_username(authc) {
            Ok(username) => username,
            Err(_) => return SaslStep::Failure("Invalid authentication identity".into()),
        };
        if !authz.is_empty() {
            if authz.contains('/') {
                return SaslStep::Failure("Invalid authorization identity".into());
            }
            let (authorization_localpart, authorization_domain) = match authz.split_once('@') {
                Some((localpart, domain)) => (localpart, Some(domain)),
                None => (authz, None),
            };
            if normalize_username(authorization_localpart).ok().as_deref() != Some(&username)
                || authorization_domain
                    .is_some_and(|domain| !domain.eq_ignore_ascii_case(&self.domain))
            {
                return SaslStep::Failure(
                    "Authorization identity does not match authentication identity".into(),
                );
            }
        }

        SaslStep::Success(username, Some(pass.to_string()))
    }

    fn response(&mut self, _data: &str) -> SaslStep {
        SaslStep::Failure("PLAIN does not support multi-step".into())
    }

    fn name(&self) -> &'static str {
        "PLAIN"
    }
}

enum ScramState {
    WaitingForClientFirst,
    WaitingForCredentials,
    WaitingForClientFinal,
    Completed,
}

/// SCRAM-SHA-256 mechanism
pub struct ScramSha256Mechanism {
    state: ScramState,
    _domain: String,
    gs2_header: String,
    server_nonce: String,
    client_first_bare: String,
    auth_message: String,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
    username: String,
    iteration_count: u32,
    salt: Vec<u8>,
}

impl ScramSha256Mechanism {
    pub fn new(domain: String) -> Self {
        let server_nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        Self {
            state: ScramState::WaitingForClientFirst,
            _domain: domain,
            gs2_header: String::new(),
            server_nonce,
            client_first_bare: String::new(),
            auth_message: String::new(),
            stored_key: Vec::new(),
            server_key: Vec::new(),
            username: String::new(),
            iteration_count: 0,
            salt: Vec::new(),
        }
    }

    fn parse_client_first(data: &str) -> Result<(String, String, String), &'static str> {
        let parts: Vec<&str> = data.splitn(3, ',').collect();
        if parts.len() < 3 || !matches!(parts[0], "n" | "y") || !parts[1].is_empty() {
            return Err("Invalid SCRAM GS2 header");
        }
        let bare = parts[2];
        let attrs = Self::parse_attributes(bare)?;
        if attrs.contains_key("m") {
            return Err("Unsupported mandatory SCRAM extension");
        }
        let user = Self::unescape_username(attrs.get("n").ok_or("Missing username")?)?;
        let user = normalize_username(&user).map_err(|_| "Invalid SCRAM username")?;
        let nonce = attrs.get("r").ok_or("Missing nonce")?.to_string();
        if nonce.is_empty() || nonce.contains(',') || nonce.chars().any(char::is_control) {
            return Err("Invalid SCRAM nonce");
        }

        Ok((user, nonce, format!("{},,", parts[0])))
    }

    fn parse_attributes(data: &str) -> Result<HashMap<String, String>, &'static str> {
        let mut map = HashMap::new();
        for kv in data.split(',') {
            let bytes = kv.as_bytes();
            if bytes.len() < 3 || bytes[1] != b'=' || !bytes[0].is_ascii_alphabetic() {
                return Err("Invalid attribute format");
            }
            let k = char::from(bytes[0]).to_string();
            let v = kv[2..].to_string();
            if map.insert(k, v).is_some() {
                return Err("Duplicate SCRAM attribute");
            }
        }
        Ok(map)
    }

    fn unescape_username(value: &str) -> Result<String, &'static str> {
        let mut output = String::with_capacity(value.len());
        let mut chars = value.chars();
        while let Some(character) = chars.next() {
            if character != '=' {
                output.push(character);
                continue;
            }
            match (chars.next(), chars.next()) {
                (Some('2'), Some('C')) => output.push(','),
                (Some('3'), Some('D')) => output.push('='),
                _ => return Err("Invalid SCRAM username escape"),
            }
        }
        Ok(output)
    }
}

impl SaslMechanism for ScramSha256Mechanism {
    fn initial_response(&mut self, data: &str) -> SaslStep {
        if !matches!(self.state, ScramState::WaitingForClientFirst) {
            return SaslStep::Failure("Unexpected initial response".into());
        }

        let decoded = match STANDARD.decode(data) {
            Ok(d) => d,
            Err(_) => return SaslStep::Failure("Invalid base64".into()),
        };
        let decoded_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return SaslStep::Failure("Invalid UTF-8".into()),
        };

        match Self::parse_client_first(&decoded_str) {
            Ok((user, nonce, gs2_header)) => {
                // Keep client_first_bare for the auth message
                // The bare part is everything after the GS2 header "n,,"
                let parts: Vec<&str> = decoded_str.splitn(3, ',').collect();
                self.client_first_bare = parts[2].to_string();

                self.username = user.clone();
                self.gs2_header = gs2_header;
                // Append server nonce to client nonce
                self.server_nonce = format!("{}{}", nonce, self.server_nonce);

                self.state = ScramState::WaitingForCredentials;
                SaslStep::NeedsCredentials(user)
            }
            Err(e) => SaslStep::Failure(e.into()),
        }
    }

    fn provide_credentials(
        &mut self,
        salt: Vec<u8>,
        iters: u32,
        stored_key: Vec<u8>,
        server_key: Vec<u8>,
    ) -> SaslStep {
        if !matches!(self.state, ScramState::WaitingForCredentials) {
            return SaslStep::Failure("Not expecting credentials".into());
        }

        if iters == 0 || stored_key.len() != 32 || server_key.len() != 32 {
            return SaslStep::Failure("Invalid stored SCRAM credentials".into());
        }
        self.salt = salt;
        self.iteration_count = iters;
        self.stored_key = stored_key;
        self.server_key = server_key;

        let salt_b64 = STANDARD.encode(&self.salt);
        let server_first = format!(
            "r={},s={},i={}",
            self.server_nonce, salt_b64, self.iteration_count
        );

        self.auth_message = format!("{},{}", self.client_first_bare, server_first);

        self.state = ScramState::WaitingForClientFinal;
        SaslStep::Challenge(server_first)
    }

    fn response(&mut self, data: &str) -> SaslStep {
        if !matches!(self.state, ScramState::WaitingForClientFinal) {
            return SaslStep::Failure("Unexpected response".into());
        }

        let decoded = match STANDARD.decode(data) {
            Ok(d) => d,
            Err(_) => return SaslStep::Failure("Invalid base64".into()),
        };
        let decoded_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return SaslStep::Failure("Invalid UTF-8".into()),
        };

        let attrs = match Self::parse_attributes(&decoded_str) {
            Ok(a) => a,
            Err(e) => return SaslStep::Failure(e.into()),
        };

        let Some((client_final_bare, proof_suffix)) = decoded_str.rsplit_once(",p=") else {
            return SaslStep::Failure("Missing proof".into());
        };
        if client_final_bare.is_empty() || proof_suffix.is_empty() || proof_suffix.contains(',') {
            return SaslStep::Failure("Invalid client-final message".into());
        }
        let Some(channel_binding) = attrs.get("c") else {
            return SaslStep::Failure("Missing channel binding".into());
        };
        let decoded_binding = match STANDARD.decode(channel_binding) {
            Ok(binding) => binding,
            Err(_) => return SaslStep::Failure("Invalid channel binding".into()),
        };
        if decoded_binding != self.gs2_header.as_bytes() {
            return SaslStep::Failure("Channel binding does not match GS2 header".into());
        }
        if attrs.get("r").map(String::as_str) != Some(self.server_nonce.as_str()) {
            return SaslStep::Failure("SCRAM nonce does not match".into());
        }
        self.auth_message.push(',');
        self.auth_message.push_str(client_final_bare);

        let proof_b64 = match attrs.get("p") {
            Some(p) => p,
            None => return SaslStep::Failure("Missing proof".into()),
        };
        let client_proof = match STANDARD.decode(proof_b64) {
            Ok(p) => p,
            Err(_) => return SaslStep::Failure("Invalid proof base64".into()),
        };
        if client_proof.len() != 32 {
            return SaslStep::Failure("Invalid proof length".into());
        }

        // Compute ClientSignature = HMAC(StoredKey, AuthMessage)
        let mut mac = match Hmac::<Sha256>::new_from_slice(&self.stored_key) {
            Ok(m) => m,
            Err(_) => return SaslStep::Failure("HMAC error".into()),
        };
        mac.update(self.auth_message.as_bytes());
        let client_signature = mac.finalize().into_bytes();

        // ClientKey = ClientProof XOR ClientSignature
        let mut client_key = vec![0u8; 32];
        for i in 0..32 {
            client_key[i] = client_proof[i] ^ client_signature[i];
        }

        // StoredKey = SHA-256(ClientKey)
        let expected_stored_key = Sha256::digest(client_key).to_vec();

        let difference = expected_stored_key
            .iter()
            .zip(&self.stored_key)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            });
        if difference != 0 {
            return SaslStep::Failure("Authentication failed".into());
        }

        // Generate ServerSignature = HMAC(ServerKey, AuthMessage)
        let mut mac_server = match Hmac::<Sha256>::new_from_slice(&self.server_key) {
            Ok(m) => m,
            Err(_) => return SaslStep::Failure("HMAC error".into()),
        };
        mac_server.update(self.auth_message.as_bytes());
        let server_signature = mac_server.finalize().into_bytes();
        let server_signature_b64 = STANDARD.encode(server_signature);

        let server_final = format!("v={}", server_signature_b64);

        self.state = ScramState::Completed;
        // Return success with server-final-message as success-data
        SaslStep::Success(self.username.clone(), Some(server_final))
    }

    fn name(&self) -> &'static str {
        "SCRAM-SHA-256"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let creds = hash_password("correct horse battery staple", true).unwrap();
        assert!(verify_password(&creds.hash, "correct horse battery staple"));
        assert!(!verify_password(&creds.hash, "wrong password"));
    }

    #[test]
    fn usernames_are_normalized() {
        assert_eq!(normalize_username(" Alice_1 ").unwrap(), "alice_1");
        assert!(normalize_username("bad name").is_err());
    }

    #[test]
    fn plain_rejects_authorization_as_another_account() {
        let mut mechanism = PlainMechanism::new("example.test".into());
        let payload = STANDARD.encode("mallory@example.test\0alice\0secret");
        assert!(matches!(
            mechanism.initial_response(&payload),
            SaslStep::Failure(_)
        ));
    }

    #[test]
    fn scram_sha256_accepts_a_valid_exchange() {
        let password = "correct horse battery staple";
        let salt = vec![7_u8; 32];
        let iterations = 4096;
        let (stored_key, server_key) = compute_scram_sha256(password, &salt, iterations);
        let mut mechanism = ScramSha256Mechanism::new("example.test".into());

        let client_first_bare = "n=alice,r=clientnonce";
        let initial = STANDARD.encode(format!("n,,{client_first_bare}"));
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(ref username) if username == "alice"
        ));

        let server_first = match mechanism.provide_credentials(
            salt.clone(),
            iterations,
            stored_key.clone(),
            server_key,
        ) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM did not produce a server-first challenge"),
        };
        let nonce = server_first
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let client_final_bare = format!("c=biws,r={nonce}");
        let auth_message = format!("{client_first_bare},{server_first},{client_final_bare}");

        let mut salted_password = vec![0_u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, iterations, &mut salted_password)
            .unwrap();
        let mut client_key_mac = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        client_key_mac.update(b"Client Key");
        let client_key = client_key_mac.finalize().into_bytes();
        let mut signature_mac = Hmac::<Sha256>::new_from_slice(&stored_key).unwrap();
        signature_mac.update(auth_message.as_bytes());
        let client_signature = signature_mac.finalize().into_bytes();
        let proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature)
            .map(|(key, signature)| key ^ signature)
            .collect();
        let client_final =
            STANDARD.encode(format!("{client_final_bare},p={}", STANDARD.encode(proof)));

        assert!(matches!(
            mechanism.response(&client_final),
            SaslStep::Success(ref username, Some(ref final_data))
                if username == "alice" && final_data.starts_with("v=")
        ));
    }

    #[test]
    fn scram_sha256_rejects_wrong_channel_binding() {
        let salt = vec![9_u8; 32];
        let (stored_key, server_key) = compute_scram_sha256("password1234", &salt, 4096);
        let mut mechanism = ScramSha256Mechanism::new("example.test".into());
        let initial = STANDARD.encode("n,,n=alice,r=clientnonce");
        assert!(matches!(
            mechanism.initial_response(&initial),
            SaslStep::NeedsCredentials(_)
        ));
        let challenge = match mechanism.provide_credentials(salt, 4096, stored_key, server_key) {
            SaslStep::Challenge(challenge) => challenge,
            _ => panic!("SCRAM did not produce a server-first challenge"),
        };
        let nonce = challenge
            .split(',')
            .find_map(|attribute| attribute.strip_prefix("r="))
            .unwrap();
        let final_message = STANDARD.encode(format!(
            "c=eSws,r={nonce},p={}",
            STANDARD.encode([0_u8; 32])
        ));

        assert!(matches!(
            mechanism.response(&final_message),
            SaslStep::Failure(ref error) if error.contains("Channel binding")
        ));
    }
}
