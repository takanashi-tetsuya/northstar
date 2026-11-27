use northstar_auth_postgres::users::{create_user, User};
use northstar_pubsub_application::{
    profile::{
        ProfileAudienceSnapshot, ProfilePepWrite, ProfilePublishStatus, ProfileRepository, VCARD4,
    },
    PresenceReplayAdmission, PresenceReplayAdmissionOutcome, PresenceReplayAdmissionRequest,
    PubSubOutboxRepository, PubSubPresenceReplayQueryRepository,
};
use northstar_pubsub_core::{
    PepOutboxAuthorizationMode, PepOutboxAuthorizationOutcome, PepOutboxDropReason,
    PepOutboxEventKind, PresenceReplayPage, PresenceReplayQuery, PubSubAccount, PubSubAddress,
    PubSubBareJid,
};
use northstar_roster_application::notification_admission::{
    NotificationAdmission, NotificationRecipient, NotificationSource,
};
use northstar_roster_postgres::{
    privacy::{
        replace_privacy_list, set_active_privacy_list, set_default_privacy_list,
        ReplacePrivacyListOutcome,
    },
    roster::block_jids,
};
use northstar_time::{DateTime, Utc};
use northstar_workflows::{
    identity_migration::migrate_for_tests,
    profile::PostgresProfileRepository,
    pubsub_repository::PostgresPubSubRepository,
    roster::{update_subscription_with_approval, upsert_roster},
};
use northstar_xep_0016::{PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType};
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use uuid::Uuid;

mod routing;

const DOMAIN: &str = "example.test";
const SERVICE: &str = "pubsub.example.test";
const READER: &str = "reader@example.test/phone";
const PUBLISHER: &str = "publisher@example.test";

struct Database {
    admin: PgPool,
    pool: PgPool,
    schema: String,
}

impl Database {
    async fn create() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("set the isolated TEST_DATABASE_URL");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("notification_admission_{}", Uuid::new_v4().simple());
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(AssertSqlSafe(statement.as_str()))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        migrate_for_tests(&pool).await.unwrap();
        Self {
            admin,
            pool,
            schema,
        }
    }

    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}

async fn user(pool: &PgPool, username: &str) -> User {
    create_user(
        pool,
        username,
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap()
}

fn recipient<'a>(
    reader: &User,
    connection_id: Uuid,
    active_list: Option<&'a str>,
) -> NotificationRecipient<'a> {
    NotificationRecipient {
        full_jid: READER,
        account_id: reader.id,
        auth_generation: reader.auth_generation,
        connection_id,
        active_list,
    }
}

fn rule(
    order: u32,
    action: PrivacyAction,
    matcher: Option<(PrivacyMatchType, &str)>,
) -> PrivacyItem {
    PrivacyItem {
        order,
        action,
        match_type: matcher.map(|(kind, _)| kind),
        match_value: matcher.map(|(_, value)| value.to_owned()),
        message: true,
        iq: false,
        presence_in: false,
        presence_out: false,
    }
}

async fn store_list(pool: &PgPool, account: Uuid, name: &str, items: Vec<PrivacyItem>) {
    assert_eq!(
        replace_privacy_list(
            pool,
            account,
            &PrivacyList {
                name: name.to_owned(),
                items,
            },
        )
        .await
        .unwrap(),
        ReplacePrivacyListOutcome::Stored,
    );
}

async fn install_recipient_lists(pool: &PgPool, reader: &User, connection: Uuid) {
    store_list(
        pool,
        reader.id,
        "default-deny",
        vec![rule(1, PrivacyAction::Deny, None)],
    )
    .await;
    store_list(
        pool,
        reader.id,
        "active-allow",
        vec![rule(1, PrivacyAction::Allow, None)],
    )
    .await;
    assert!(
        set_default_privacy_list(pool, reader.id, Some("default-deny"))
            .await
            .unwrap()
    );
    assert!(
        set_active_privacy_list(pool, reader.id, connection, Some("active-allow"))
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn live_active_allow_overrides_default_deny_and_expired_selection_stays_expired() {
    let database = Database::create().await;
    let reader = user(&database.pool, "reader").await;
    let repository = PostgresPubSubRepository::new(database.pool.clone(), DOMAIN);
    let connection = Uuid::new_v4();
    let default_only = Uuid::new_v4();
    install_recipient_lists(&database.pool, &reader, connection).await;

    let publisher = NotificationSource::PepPublisher(PUBLISHER);
    let same_account = NotificationSource::PepPublisher("reader@example.test");
    assert!(!repository
        .authorize_notification(recipient(&reader, default_only, None), publisher)
        .await
        .unwrap());
    assert!(repository
        .authorize_notification(
            recipient(&reader, connection, Some("active-allow")),
            publisher
        )
        .await
        .unwrap());
    assert!(repository
        .authorize_notification(recipient(&reader, default_only, None), same_account)
        .await
        .unwrap());
    let expired: DateTime<Utc> = sqlx::query_scalar(
        "UPDATE privacy_active_sessions SET expires_at=NOW()-INTERVAL '1 hour'
          WHERE owner_id=$1 AND connection_id=$2 RETURNING expires_at",
    )
    .bind(reader.id)
    .bind(connection)
    .fetch_one(&database.pool)
    .await
    .unwrap();
    // A permissive default makes accidental fallback after expiry observable.
    assert!(set_default_privacy_list(&database.pool, reader.id, None)
        .await
        .unwrap());
    for source in [publisher, same_account] {
        assert!(!repository
            .authorize_notification(recipient(&reader, connection, Some("active-allow")), source)
            .await
            .unwrap());
    }
    let request = PresenceReplayAdmissionRequest {
        recipient_id: reader.id,
        expected_auth_generation: Some(reader.auth_generation),
        connection_id: connection,
        active_privacy_list: Some("active-allow".to_owned()),
        service: PubSubBareJid::parse(SERVICE).unwrap(),
    };
    assert_eq!(
        repository
            .admit_presence_replay(request.clone())
            .await
            .unwrap(),
        PresenceReplayAdmissionOutcome::Blocked,
    );
    assert!(matches!(
        repository
            .presence_replay_page(&PresenceReplayQuery {
                recipient: PubSubAddress::parse(READER).unwrap(),
                recipient_id: reader.id,
                expected_auth_generation: request.expected_auth_generation,
                connection_id: connection,
                active_privacy_list: request.active_privacy_list,
                service: request.service,
                show: "online".into(),
                after: None,
                limit: 10,
            })
            .await
            .unwrap(),
        PresenceReplayPage::Denied,
    ));
    let observed: DateTime<Utc> = sqlx::query_scalar(
        "SELECT expires_at FROM privacy_active_sessions WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(reader.id)
    .bind(connection)
    .fetch_one(&database.pool)
    .await
    .unwrap();
    assert_eq!(observed, expired);
    assert!(
        set_active_privacy_list(&database.pool, reader.id, connection, None)
            .await
            .unwrap()
    );
    assert!(!repository
        .authorize_notification(
            recipient(&reader, connection, Some("active-allow")),
            publisher
        )
        .await
        .unwrap());
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pep_handoff_rechecks_blocks_and_never_delivers_to_a_recreated_account() {
    let database = Database::create().await;
    let reader = user(&database.pool, "reader").await;
    let publisher = user(&database.pool, "publisher").await;
    let repository = PostgresPubSubRepository::new(database.pool.clone(), DOMAIN);
    let stanza = concat!(
        "<message xmlns='jabber:client' type='headline' from='publisher@example.test'",
        " to='reader@example.test/phone'><event xmlns='http://jabber.org/protocol/pubsub#event'>",
        "<items node='urn:test:news'/></event></message>",
    );
    let row = northstar_pubsub_postgres::PubSubOutboxInsert::new_pep_stanza(
        Uuid::new_v4(),
        publisher.id,
        PUBLISHER,
        None,
        READER,
        Some(reader.id),
        PepOutboxEventKind::Publish,
        PepOutboxAuthorizationMode::CausalAudience,
        stanza,
        "urn:test:news",
        DOMAIN,
        Utc::now(),
    )
    .unwrap();
    let mut transaction = database.pool.begin().await.unwrap();
    northstar_pubsub_postgres::enqueue_pubsub_outbox_in_transaction(&mut transaction, &[row])
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    let item = repository
        .claim_pubsub_outbox(1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let connection = Uuid::new_v4();
    install_recipient_lists(&database.pool, &reader, connection).await;
    assert_eq!(
        repository
            .authorize_pep_outbox_delivery(&item)
            .await
            .unwrap(),
        PepOutboxAuthorizationOutcome::Deliver,
    );
    let (context, mut output) =
        routing::context(&database.pool, &reader, connection, Some("active-allow"));
    context
        .route_message(PUBLISHER, READER, stanza.into(), None, Some(reader.id))
        .await
        .unwrap();
    assert_eq!(output.try_recv().unwrap().stanza, stanza);

    // Keep the claim's authorization result while a block commits before enqueue.
    block_jids(&database.pool, reader.id, &[PUBLISHER.to_owned()])
        .await
        .unwrap();
    context
        .route_message(PUBLISHER, READER, stanza.into(), None, Some(reader.id))
        .await
        .unwrap();
    assert!(output.try_recv().is_err());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(reader.id)
        .execute(&database.pool)
        .await
        .unwrap();
    let replacement = user(&database.pool, "reader").await;
    assert_ne!(replacement.id, reader.id);
    assert_eq!(
        repository
            .authorize_pep_outbox_delivery(&item)
            .await
            .unwrap(),
        PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::RecipientUnavailable),
    );
    let (replacement_context, mut replacement_output) =
        routing::context(&database.pool, &replacement, Uuid::new_v4(), None);
    replacement_context
        .route_message(PUBLISHER, READER, stanza.into(), None, Some(reader.id))
        .await
        .unwrap();
    assert!(replacement_output.try_recv().is_err());
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn notification_policy_checks_current_roster_rules_and_auth_generation() {
    let database = Database::create().await;
    let reader = user(&database.pool, "reader").await;
    let repository = PostgresPubSubRepository::new(database.pool.clone(), DOMAIN);
    let connection = Uuid::new_v4();
    let source = NotificationSource::PepPublisher("publisher@remote.test");
    store_list(
        &database.pool,
        reader.id,
        "roster",
        vec![
            rule(
                1,
                PrivacyAction::Deny,
                Some((PrivacyMatchType::Group, "denied")),
            ),
            rule(
                2,
                PrivacyAction::Allow,
                Some((PrivacyMatchType::Subscription, "to")),
            ),
            rule(3, PrivacyAction::Deny, None),
        ],
    )
    .await;
    assert!(
        set_default_privacy_list(&database.pool, reader.id, Some("roster"))
            .await
            .unwrap()
    );
    let peer = "publisher@remote.test";
    upsert_roster(
        &database.pool,
        reader.id,
        peer,
        None,
        &["denied".to_owned()],
    )
    .await
    .unwrap();
    update_subscription_with_approval(&database.pool, reader.id, peer, "to", None, None)
        .await
        .unwrap();
    assert!(!repository
        .authorize_notification(recipient(&reader, connection, None), source)
        .await
        .unwrap());
    upsert_roster(
        &database.pool,
        reader.id,
        peer,
        None,
        &["allowed".to_owned()],
    )
    .await
    .unwrap();
    assert!(repository
        .authorize_notification(recipient(&reader, connection, None), source)
        .await
        .unwrap());
    update_subscription_with_approval(&database.pool, reader.id, peer, "none", None, None)
        .await
        .unwrap();
    assert!(!repository
        .authorize_notification(recipient(&reader, connection, None), source)
        .await
        .unwrap());

    assert!(set_default_privacy_list(&database.pool, reader.id, None)
        .await
        .unwrap());
    assert!(repository
        .authorize_notification(recipient(&reader, connection, None), source)
        .await
        .unwrap());
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(reader.id)
        .execute(&database.pool)
        .await
        .unwrap();
    assert!(!repository
        .authorize_notification(recipient(&reader, connection, None), source)
        .await
        .unwrap());
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn profile_explicit_audience_uses_to_and_none_groups_without_implicit_delivery() {
    let database = Database::create().await;
    let publisher = user(&database.pool, "publisher").await;
    let owner = PubSubAccount {
        id: publisher.id,
        username: publisher.username.clone(),
        auth_generation: publisher.auth_generation,
    };
    let mut config = northstar_pubsub_postgres::default_pep_node_config(VCARD4);
    config.access_model = "open".into();
    assert!(matches!(
        northstar_pubsub_postgres::create_pep_node(&database.pool, &owner, VCARD4, &config, 10)
            .await
            .unwrap(),
        northstar_pubsub_postgres::PepCreateOutcome::Created,
    ));
    for (peer, subscription, group, explicit) in [
        ("denied-to@remote.test", "to", "denied", true),
        ("denied-none@remote.test", "none", "denied", true),
        ("explicit@remote.test", "to", "allowed", true),
        ("implicit@remote.test", "from", "allowed", false),
        ("non-subscriber@remote.test", "none", "allowed", false),
    ] {
        upsert_roster(&database.pool, owner.id, peer, None, &[group.to_owned()])
            .await
            .unwrap();
        update_subscription_with_approval(&database.pool, owner.id, peer, subscription, None, None)
            .await
            .unwrap();
        if explicit {
            assert!(northstar_pubsub_postgres::subscribe_pep_node(
                &database.pool,
                owner.id,
                VCARD4,
                peer,
                10
            )
            .await
            .unwrap()
            .is_some());
        }
    }
    store_list(
        &database.pool,
        owner.id,
        "groups",
        vec![rule(
            1,
            PrivacyAction::Deny,
            Some((PrivacyMatchType::Group, "denied")),
        )],
    )
    .await;
    assert!(
        set_default_privacy_list(&database.pool, owner.id, Some("groups"))
            .await
            .unwrap()
    );

    let repository = PostgresProfileRepository::new(database.pool.clone(), DOMAIN.to_owned());
    let config = config.into();
    let connection_id = Uuid::new_v4();
    let saw_audience = std::sync::atomic::AtomicBool::new(false);
    let render = |audience: &ProfileAudienceSnapshot| {
        saw_audience.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(audience.explicit_jids, ["explicit@remote.test"]);
        assert_eq!(audience.roster_jids, ["implicit@remote.test"]);
        Ok(Vec::new())
    };
    let result = repository.publish_profile_items(
        ProfilePepWrite {
            user_id: owner.id,
            auth_generation: owner.auth_generation,
            connection_id,
            node: VCARD4,
            requested: &config,
            enforce_preconditions: false,
            items: &[("profile", "<item id='profile'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Test</text></fn></vcard></item>")],
            max_nodes: 10,
            max_storage_bytes: 1_000_000,
        },
        &render,
        true,
    ).await.unwrap();
    assert_eq!(result.status, ProfilePublishStatus::Published);
    assert!(saw_audience.into_inner());

    assert!(
        set_active_privacy_list(&database.pool, owner.id, connection_id, Some("groups"))
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE privacy_active_sessions SET expires_at=NOW()-INTERVAL '1 hour'
          WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(owner.id)
    .bind(connection_id)
    .execute(&database.pool)
    .await
    .unwrap();
    let expired_audience = |audience: &ProfileAudienceSnapshot| {
        assert!(audience.roster_jids.is_empty());
        assert!(audience.explicit_jids.is_empty());
        Ok(Vec::new())
    };
    let result = repository.publish_profile_items(
        ProfilePepWrite {
            user_id: owner.id,
            auth_generation: owner.auth_generation,
            connection_id,
            node: VCARD4,
            requested: &config,
            enforce_preconditions: false,
            items: &[("next", "<item id='next'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Next</text></fn></vcard></item>")],
            max_nodes: 10,
            max_storage_bytes: 1_000_000,
        },
        &expired_audience,
        false,
    ).await.unwrap();
    assert_eq!(result.status, ProfilePublishStatus::Published);
    database.finish().await;
}
