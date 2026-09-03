use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::Rng;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MIN_SCRAM_ITERATIONS: u32 = 4_096;
pub const DEFAULT_SCRAM_ITERATIONS: u32 = 600_000;
pub const MAX_SCRAM_ITERATIONS: u32 = 10_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScramAlgorithm {
    Sha256,
    Sha1,
}

impl ScramAlgorithm {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha1 => 20,
        }
    }

    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::Sha256 => b"SCRAM-SHA-256",
            Self::Sha1 => b"SCRAM-SHA-1",
        }
    }
}

pub fn generate_scram_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill(&mut salt[..]);
    salt
}

pub fn compute_scram_sha256(password: &str, salt: &[u8], iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let mut salted_password = Zeroizing::new(vec![0u8; 32]);
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut salted_password)
        .expect("pbkdf2 should not fail");

    // Keep HMAC state in the smallest possible scope. The reusable derived
    // bytes which remain outside that scope are explicitly zeroized.
    let client_key = Zeroizing::new({
        let mut mac_client = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        mac_client.update(b"Client Key");
        mac_client.finalize().into_bytes().to_vec()
    });

    let stored_key = Sha256::digest(&*client_key).to_vec();

    let server_key = {
        let mut mac_server = Hmac::<Sha256>::new_from_slice(&salted_password).unwrap();
        mac_server.update(b"Server Key");
        mac_server.finalize().into_bytes().to_vec()
    };

    (stored_key, server_key)
}

pub fn compute_scram_sha1(password: &str, salt: &[u8], iterations: u32) -> (Vec<u8>, Vec<u8>) {
    let mut salted_password = Zeroizing::new(vec![0u8; 20]);
    pbkdf2::<Hmac<Sha1>>(password.as_bytes(), salt, iterations, &mut salted_password)
        .expect("pbkdf2 should not fail");

    let client_key = Zeroizing::new({
        let mut mac_client = Hmac::<Sha1>::new_from_slice(&salted_password).unwrap();
        mac_client.update(b"Client Key");
        mac_client.finalize().into_bytes().to_vec()
    });
    let stored_key = Sha1::digest(&*client_key).to_vec();

    let server_key = {
        let mut mac_server = Hmac::<Sha1>::new_from_slice(&salted_password).unwrap();
        mac_server.update(b"Server Key");
        mac_server.finalize().into_bytes().to_vec()
    };
    (stored_key, server_key)
}

/// Select a deployment-stable dummy iteration profile for an unknown or
/// disabled account. The caller supplies the bounded, sorted set of every
/// live verifier cost plus the RFC floor and configured profile, so historical
/// accounts remain plausible dummy responses rather than an enumeration bit.
pub fn dummy_scram_iterations(
    secret: &[u8],
    username: &str,
    algorithm: ScramAlgorithm,
    iteration_profiles: &[u32],
) -> u32 {
    assert!(
        !iteration_profiles.is_empty()
            && iteration_profiles.iter().all(|iterations| {
                (MIN_SCRAM_ITERATIONS..=MAX_SCRAM_ITERATIONS).contains(iterations)
            }),
        "dummy SCRAM iteration profiles must be validated at startup"
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC accepts the deployment dummy-auth secret");
    mac.update(b"northstar/dummy-scram-iterations/v1\0");
    mac.update(algorithm.label());
    mac.update(b"\0");
    mac.update(username.as_bytes());
    let selector = mac.finalize().into_bytes()[0] as usize;
    iteration_profiles[selector % iteration_profiles.len()]
}

/// Build account-specific credentials for an unknown or disabled account.
/// The material is keyed by the independent mounted dummy-SCRAM secret, so it
/// is stable across restarts and nodes without coupling account-obfuscation
/// identity to FAST token rotation. Database corruption never uses this path.
pub fn dummy_scram_credentials(
    secret: &[u8],
    username: &str,
    algorithm: ScramAlgorithm,
    iterations: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let derive = |purpose: &[u8], length: usize| {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret)
            .expect("HMAC accepts the deployment dummy-auth secret");
        mac.update(b"northstar/dummy-scram-material/v1\0");
        mac.update(algorithm.label());
        mac.update(b"\0");
        mac.update(purpose);
        mac.update(b"\0");
        mac.update(&iterations.to_be_bytes());
        mac.update(b"\0");
        mac.update(username.as_bytes());
        mac.finalize().into_bytes()[..length].to_vec()
    };
    (
        derive(b"salt", 32),
        derive(b"stored-key", algorithm.key_len()),
        derive(b"server-key", algorithm.key_len()),
    )
}

pub fn scram_hmac(algorithm: ScramAlgorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    match algorithm {
        ScramAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("valid HMAC key");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        ScramAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("valid HMAC key");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_scram_material_is_account_and_family_specific() {
        let key = [0x5a; 32];
        let alice256 = dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha256, 4096);
        let alice256_again = dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha256, 4096);
        let bob256 = dummy_scram_credentials(&key, "bob", ScramAlgorithm::Sha256, 4096);
        let alice1 = dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha1, 4096);
        let alice256_stronger =
            dummy_scram_credentials(&key, "alice", ScramAlgorithm::Sha256, 600_000);
        assert_eq!(alice256, alice256_again);
        assert_ne!(alice256.0, bob256.0);
        assert_ne!(alice256.0, alice1.0);
        assert_ne!(alice256.0, alice256_stronger.0);
        assert_eq!(alice256.1.len(), 32);
        assert_eq!(alice1.1.len(), 20);
        let selected = dummy_scram_iterations(
            &key,
            "alice",
            ScramAlgorithm::Sha256,
            &[MIN_SCRAM_ITERATIONS, DEFAULT_SCRAM_ITERATIONS],
        );
        assert!(matches!(
            selected,
            MIN_SCRAM_ITERATIONS | DEFAULT_SCRAM_ITERATIONS
        ));
    }
}
