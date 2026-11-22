use super::*;

const PLAINTEXT: &str = "<message><body>original</body></message>";
const CIPHERTEXT: &str = "<message><encrypted xmlns='urn:xmpp:omemo:2'/></message>";
const PLAIN_ROW: &str = r#"{"resource_type":"muc_archive","record_id":"00000000-0000-0000-0000-000000000004","subject_id":"00000000-0000-0000-0000-000000000005","encrypted":false,"record_created_at":"1970-01-01T00:00:00Z","server_visible_payload":"<message><body>original</body></message>","payload_disposition":"server_plaintext"}"#;
const ENCRYPTED_ROW: &str = r#"{"resource_type":"muc_archive","record_id":"00000000-0000-0000-0000-000000000004","subject_id":"00000000-0000-0000-0000-000000000005","encrypted":true,"record_created_at":"1970-01-01T00:00:00Z","server_visible_payload":"<message><encrypted xmlns='urn:xmpp:omemo:2'/></message>","payload_disposition":"ciphertext"}"#;
const ANNOTATION: &str = r#"{"kind":"muc_moderation","actor":"mod@example.test","changed_at":"1970-01-01T00:00:01Z","reason":"Off topic","action_id":"00000000-0000-0000-0000-000000000006"}"#;
const V3: ExportMode = ExportMode::V3 {
    max_display_sequence: Some(0),
};

fn row(payload: &str, encrypted: bool) -> HeldRecordHashPayload<'_> {
    HeldRecordHashPayload {
        resource_type: "muc_archive",
        record_id: Uuid::from_u128(4),
        subject_id: Uuid::from_u128(5),
        encrypted,
        record_created_at: DateTime::UNIX_EPOCH,
        server_visible_payload: Some(payload),
        payload_disposition: if encrypted {
            "ciphertext"
        } else {
            "server_plaintext"
        },
    }
}

fn annotation() -> HeldArchiveDisplayChange {
    HeldArchiveDisplayChange {
        kind: HeldArchiveDisplayChangeKind::MucModeration,
        actor: "mod@example.test".into(),
        changed_at: DateTime::from_timestamp(1, 0).unwrap(),
        reason: Some("Off topic".into()),
        action_id: Uuid::from_u128(6).to_string(),
    }
}

fn genesis(mode: ExportMode, domain: &[u8]) -> [u8; 32] {
    let bytes = [
        domain,
        &1_u128.to_be_bytes(),
        &2_u128.to_be_bytes(),
        &3_u128.to_be_bytes(),
        &0_i64.to_be_bytes(),
    ]
    .concat();
    let expected: [u8; 32] = Sha256::digest(bytes).into();
    let actual = legal_hold_chain_genesis(
        mode,
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        Uuid::from_u128(3),
        DateTime::UNIX_EPOCH,
    );
    assert_eq!(actual, expected);
    actual
}

fn root_vector(genesis: [u8; 32], expected: &str, actual: &[u8]) -> [u8; 32] {
    assert_eq!(actual, expected.as_bytes());
    let length = (expected.len() as u64).to_be_bytes();
    let expected: [u8; 32] =
        Sha256::digest([genesis.as_slice(), &length, expected.as_bytes()].concat()).into();
    let actual = chain_next(genesis, actual);
    assert_eq!(actual, expected);
    actual
}

#[test]
fn legal_hold_v2_hash_is_unchanged() {
    let mode = ExportMode::V2;
    assert_eq!(mode.format(), "northstar-legal-hold-chain-v2");
    let genesis = genesis(mode, b"northstar/legal-hold-export/v2\0");
    for (payload, encrypted, expected) in [
        (PLAINTEXT, false, PLAIN_ROW),
        (CIPHERTEXT, true, ENCRYPTED_ROW),
    ] {
        let canonical = mode
            .canonical_row(row(payload, encrypted), Some(&annotation()))
            .unwrap();
        root_vector(genesis, expected, &canonical);
    }
}

#[test]
fn legal_hold_v3_hash_commits_original_and_display_change() {
    assert_eq!(V3.format(), "northstar-legal-hold-chain-v3");
    let genesis = genesis(V3, b"northstar/legal-hold-export/v3\0");
    let absent = V3.canonical_row(row(PLAINTEXT, false), None).unwrap();
    let expected = format!(
        r#"{},"display_change":null}}"#,
        PLAIN_ROW.trim_end_matches('}')
    );
    let absent_hash = root_vector(genesis, &expected, &absent);
    for (payload, encrypted, fixture) in [
        (PLAINTEXT, false, PLAIN_ROW),
        (CIPHERTEXT, true, ENCRYPTED_ROW),
    ] {
        let change = annotation();
        let canonical = V3
            .canonical_row(row(payload, encrypted), Some(&change))
            .unwrap();
        let expected = format!(
            r#"{},"display_change":{ANNOTATION}}}"#,
            fixture.trim_end_matches('}')
        );
        let original_hash = root_vector(genesis, &expected, &canonical);
        assert_ne!(original_hash, absent_hash);
        for altered in [
            HeldArchiveDisplayChange {
                actor: "other@example.test".into(),
                ..annotation()
            },
            HeldArchiveDisplayChange {
                kind: HeldArchiveDisplayChangeKind::MucRetraction,
                ..annotation()
            },
            HeldArchiveDisplayChange {
                action_id: Uuid::from_u128(7).to_string(),
                ..annotation()
            },
            HeldArchiveDisplayChange {
                changed_at: DateTime::UNIX_EPOCH,
                ..annotation()
            },
            HeldArchiveDisplayChange {
                reason: None,
                ..annotation()
            },
        ] {
            let canonical = V3
                .canonical_row(row(payload, encrypted), Some(&altered))
                .unwrap();
            assert_ne!(original_hash, chain_next(genesis, &canonical));
        }
        let canonical = V3
            .canonical_row(row("<message/>", encrypted), Some(&change))
            .unwrap();
        assert_ne!(original_hash, chain_next(genesis, &canonical));
    }
}
