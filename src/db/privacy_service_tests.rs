//! PostgreSQL-backed tests of the privacy service over the root-wired repository.

use crate::db;
use northstar_roster_application::privacy::*;
use uuid::Uuid;

#[test]
fn stanza_kind_conversions_preserve_every_stanza_classification() {
    let mappings = [
        (PrivacyStanzaKind::Message, db::PrivacyStanzaKind::Message),
        (PrivacyStanzaKind::Iq, db::PrivacyStanzaKind::Iq),
        (
            PrivacyStanzaKind::PresenceIn,
            db::PrivacyStanzaKind::PresenceIn,
        ),
        (
            PrivacyStanzaKind::PresenceOut,
            db::PrivacyStanzaKind::PresenceOut,
        ),
    ];
    for (kind, storage) in mappings {
        assert_eq!(kind, storage);
        assert_eq!(storage, kind);
    }
}

/// End-to-end guard for the boundary conversion: for every stanza kind the
/// service must deny and allow exactly what the repository produced while
/// the stanza layer passed hardcoded storage kinds. Ignored like the
/// repository tests because it needs a disposable database.
#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn privacy_service_boundary_preserves_stanza_kind_allow_deny_results() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a disposable random-schema xmpp_test URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let service = PrivacyService::new(db::privacy::PostgresPrivacyRepository::new(pool.clone()));
    let messaging = crate::services::messaging::MessageService::new(
        crate::db::messaging::PostgresMessageRepository::new(
            pool.clone(),
            northstar_abuse_application::guard::test_personal_message_content_keyring(),
            "example.test",
            100,
            8_000_000,
            30,
        ),
        false,
    );
    let owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(owner_id)
        .bind(format!("privacysvc{}", owner_id.simple()))
        .execute(&pool)
        .await
        .unwrap();

    // First match wins: the deny covers messages only, so the later
    // unfiltered allow never fires for Message but does for the rest.
    let list = PrivacyList {
        name: "boundary".to_owned(),
        items: vec![
            PrivacyItem {
                order: 10,
                action: PrivacyAction::Deny,
                match_type: Some(PrivacyMatchType::Jid),
                match_value: Some("bob@example.test".to_owned()),
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            },
            PrivacyItem {
                order: 20,
                action: PrivacyAction::Allow,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            },
        ],
    };
    assert_eq!(
        service.replace_list(owner_id, &list).await.unwrap(),
        PrivacyListMutationOutcome::Stored
    );
    assert_eq!(
        service
            .select_default(owner_id, Some("boundary"), 1, false)
            .await
            .unwrap(),
        PrivacySelectionOutcome::Updated
    );

    for kind in [
        PrivacyStanzaKind::Message,
        PrivacyStanzaKind::Iq,
        PrivacyStanzaKind::PresenceIn,
        PrivacyStanzaKind::PresenceOut,
    ] {
        let expected_denied = matches!(kind, PrivacyStanzaKind::Message);
        assert_eq!(
            service
                .denies(owner_id, None, "bob@example.test/Phone", kind)
                .await
                .unwrap(),
            expected_denied,
            "account-scoped evaluation drifted for {kind:?}"
        );
        let connection_id = Uuid::new_v4();
        assert_eq!(
            service
                .select_active(owner_id, connection_id, Some("boundary"))
                .await
                .unwrap(),
            PrivacySelectionOutcome::Updated
        );
        assert_eq!(
            messaging
                .privacy_allows_session(
                    owner_id,
                    connection_id,
                    Some("boundary"),
                    "bob@example.test/Phone",
                    kind
                )
                .await
                .unwrap(),
            !expected_denied,
            "session-scoped evaluation drifted for {kind:?}"
        );
        assert_eq!(
            messaging
                .privacy_allows_session(
                    owner_id,
                    connection_id,
                    None,
                    "bob@example.test/Phone",
                    kind
                )
                .await
                .unwrap(),
            !expected_denied,
            "default-list fallback drifted for {kind:?}"
        );
    }

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
}
