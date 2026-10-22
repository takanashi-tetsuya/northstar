use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

pub const FAST_MECHANISMS: [&str; 3] = ["HT-SHA-256-ENDP", "HT-SHA-256-EXPR", "HT-SHA-256-NONE"];

pub fn is_fast_mechanism(mechanism: &str) -> bool {
    FAST_MECHANISMS.contains(&mechanism)
}

pub fn fast_channel_binding_name(mechanism: &str) -> Option<&'static str> {
    match mechanism {
        "HT-SHA-256-ENDP" => Some("tls-server-end-point"),
        "HT-SHA-256-EXPR" => Some("tls-exporter"),
        "HT-SHA-256-NONE" => Some("none"),
        _ => None,
    }
}

/// Derive a FAST bearer token without storing it in PostgreSQL. `nonce` is
/// public per-row diversification; secrecy comes exclusively from the
/// deployment master key. Every identity/binding field is length-delimited
/// to avoid ambiguous concatenations.
pub fn derive_fast_token(
    master_key: &[u8],
    token_id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    mechanism: &str,
    nonce: &[u8],
) -> Result<String> {
    if master_key.len() < 32 || nonce.len() != 32 || !is_fast_mechanism(mechanism) {
        anyhow::bail!("invalid FAST token derivation input");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key)
        .map_err(|_| anyhow::anyhow!("invalid FAST master key"))?;
    mac.update(b"northstar/xmpp-fast-token/v1\0");
    mac.update(token_id.as_bytes());
    mac.update(user_id.as_bytes());
    mac.update(device_id.as_bytes());
    mac.update(&(mechanism.len() as u32).to_be_bytes());
    mac.update(mechanism.as_bytes());
    mac.update(nonce);
    let secret = mac.finalize().into_bytes();
    Ok(URL_SAFE_NO_PAD.encode(secret))
}

pub fn fast_proof(token: &str, responder: bool, channel_binding: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .expect("HMAC accepts arbitrary token sizes");
    mac.update(if responder {
        b"Responder"
    } else {
        b"Initiator"
    });
    mac.update(channel_binding);
    mac.finalize().into_bytes().to_vec()
}

/// HMAC verification is constant-time for equal-length candidate tags.
pub fn verify_fast_proof(
    token: &str,
    responder: bool,
    channel_binding: &[u8],
    candidate: &[u8],
) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .expect("HMAC accepts arbitrary token sizes");
    mac.update(if responder {
        b"Responder"
    } else {
        b"Initiator"
    });
    mac.update(channel_binding);
    mac.verify_slice(candidate).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_mechanism_checks_and_channel_bindings() {
        assert!(is_fast_mechanism("HT-SHA-256-ENDP"));
        assert!(is_fast_mechanism("HT-SHA-256-EXPR"));
        assert!(is_fast_mechanism("HT-SHA-256-NONE"));
        assert!(!is_fast_mechanism("PLAIN"));
        assert!(!is_fast_mechanism("SCRAM-SHA-256"));

        assert_eq!(
            fast_channel_binding_name("HT-SHA-256-ENDP"),
            Some("tls-server-end-point")
        );
        assert_eq!(
            fast_channel_binding_name("HT-SHA-256-EXPR"),
            Some("tls-exporter")
        );
        assert_eq!(fast_channel_binding_name("HT-SHA-256-NONE"), Some("none"));
        assert_eq!(fast_channel_binding_name("OTHER"), None);
    }

    #[test]
    fn fast_ht_proofs_are_directional_and_binding_specific() {
        let token = "opaque-fast-token";
        let endpoint = [0x11_u8; 32];
        let exporter = [0x22_u8; 32];
        let initiator = fast_proof(token, false, &endpoint);
        let responder = fast_proof(token, true, &endpoint);
        assert_ne!(initiator, responder);
        assert!(verify_fast_proof(token, false, &endpoint, &initiator));
        assert!(!verify_fast_proof(token, true, &endpoint, &initiator));
        assert!(!verify_fast_proof(token, false, &exporter, &initiator));
        assert!(!verify_fast_proof(
            "other-token",
            false,
            &endpoint,
            &initiator
        ));
    }

    #[test]
    fn fast_tokens_are_bound_to_every_identity_dimension() {
        let key = [0x33_u8; 32];
        let id = Uuid::from_u128(1);
        let user = Uuid::from_u128(2);
        let device = Uuid::from_u128(3);
        let nonce = [0x44_u8; 32];
        let original =
            derive_fast_token(&key, id, user, device, "HT-SHA-256-ENDP", &nonce).unwrap();
        assert_ne!(
            original,
            derive_fast_token(
                &key,
                id,
                user,
                Uuid::from_u128(4),
                "HT-SHA-256-ENDP",
                &nonce,
            )
            .unwrap()
        );
        assert_ne!(
            original,
            derive_fast_token(&key, id, user, device, "HT-SHA-256-NONE", &nonce,).unwrap()
        );
    }
}
