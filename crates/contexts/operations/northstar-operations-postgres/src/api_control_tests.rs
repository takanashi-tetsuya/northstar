use super::*;

fn request<'a>(key: &'a str, body: &[u8]) -> IdempotencyRequest<'a> {
    IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: Some(Uuid::nil()),
        principal_scope: b"user:00000000-0000-0000-0000-000000000000",
        capacity_scope: b"user:00000000-0000-0000-0000-000000000000",
        target_scope: b"",
        principal_kind: ApiPrincipalKind::User,
        method: "POST",
        route: "/api/v1/example",
        idempotency_key: key,
        request_fingerprint: api_request_fingerprint("application/json", body),
        ttl_seconds: 3600,
        lease_seconds: 30,
    }
}

#[test]
fn scope_and_keyed_fingerprint_bind_request_without_persisting_raw_identity() {
    let keys = ApiControlKeyring::new(b"0123456789abcdef0123456789abcdef", None).unwrap();
    let first = request("request-key-0001", br#"{"value":1}"#);
    let second = request("request-key-0002", br#"{"value":1}"#);
    let first_hash = keys.scope_hashes(&first).0;
    assert_ne!(first_hash, keys.scope_hashes(&second).0);

    let mut other_route = request("request-key-0001", br#"{"value":1}"#);
    other_route.route = "/api/v1/other";
    assert_ne!(first_hash, keys.scope_hashes(&other_route).0);

    let first_fingerprint = keys.request_fingerprints(&first).0;
    assert_ne!(first_fingerprint, first.request_fingerprint);
    let different_body = request("request-key-0001", br#"{"value":2}"#);
    assert_ne!(
        first_fingerprint,
        keys.request_fingerprints(&different_body).0
    );
    let mut different_target = request("request-key-0001", br#"{"value":1}"#);
    different_target.target_scope = b"report:00000000-0000-0000-0000-000000000001";
    assert_eq!(first_hash, keys.scope_hashes(&different_target).0);
    assert_ne!(
        first_fingerprint,
        keys.request_fingerprints(&different_target).0
    );
}

#[test]
fn replay_aead_detects_ciphertext_and_context_tampering() {
    let keys = ApiControlKeyring::new(b"0123456789abcdef0123456789abcdef", None).unwrap();
    let id = Uuid::new_v4();
    let scope = [1_u8; 32];
    let fingerprint = [2_u8; 32];
    let nonce = [3_u8; 12];
    let aad = replay_aad(id, &scope, &fingerprint, 201);
    let mut ciphertext = br#"{"token":"secret"}"#.to_vec();
    seal_replay(&keys.current, nonce, aad.clone(), &mut ciphertext).unwrap();
    assert!(!String::from_utf8_lossy(&ciphertext).contains("secret"));
    let mut valid = ciphertext.clone();
    open_replay(&keys.current, nonce, aad, &mut valid).unwrap();
    assert_eq!(valid, br#"{"token":"secret"}"#);

    ciphertext[0] ^= 1;
    assert!(open_replay(
        &keys.current,
        nonce,
        replay_aad(id, &scope, &fingerprint, 201),
        &mut ciphertext,
    )
    .is_err());
}
