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
