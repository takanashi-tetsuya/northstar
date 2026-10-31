use super::*;

#[test]
fn terminal_moderation_states_cannot_be_silently_reopened() {
    assert!(valid_moderation_transition(
        ModerationKind::Report,
        "submitted",
        "reviewing"
    ));
    assert!(valid_moderation_transition(
        ModerationKind::Appeal,
        "reviewing",
        "upheld"
    ));
    assert!(!valid_moderation_transition(
        ModerationKind::Report,
        "closed",
        "submitted"
    ));
    assert!(!valid_moderation_transition(
        ModerationKind::Appeal,
        "denied",
        "reviewing"
    ));
    assert!(!valid_moderation_transition(
        ModerationKind::Report,
        "closed",
        "closed"
    ));
}

#[test]
fn plaintext_evidence_uses_archive_body_and_omemo_is_explicitly_unverified() {
    let plaintext = "<message xmlns='jabber:client' from='peer@example.test/phone'><body>server copy</body></message>";
    let (_, body, source) = evidence_from_archive(plaintext, false, "forged copy").unwrap();
    assert_eq!(body, "server copy");
    assert_eq!(source, "server_verified_plaintext");

    let encrypted = "<message xmlns='jabber:client' from='peer@example.test/phone'><encrypted xmlns='urn:xmpp:omemo:2'/><body>This message is encrypted</body></message>";
    let (_, body, source) = evidence_from_archive(encrypted, true, "user decrypted text").unwrap();
    assert_eq!(body, "user decrypted text");
    assert_eq!(source, "user_decrypted_omemo_unverified");
}
