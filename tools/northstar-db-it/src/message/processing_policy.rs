use super::message_repository::drop_isolated_message_pool;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_message_application::messaging::{
    ArchiveCandidate, ArchiveDirection, ArchiveWrite, DurableAdmissionOutcome, MessageService,
};
use northstar_message_core::processing_policy::{
    classify_message_effects, MessageDirection, MessageEffects,
};
use northstar_message_core::{
    FederationDelivery, LocalDelivery, PersonalMessageDestination, ValidatedPersonalMessage,
};
use northstar_workflows::message_repository::PostgresMessageRepository;
use roxmltree::Document;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const SENDER: Uuid = Uuid::from_u128(1);
const RECIPIENT: Uuid = Uuid::from_u128(2);
const LOCAL_SENDER: &str = "alice@local.test/phone";
const REMOTE_SENDER: &str = "carol@remote.test/phone";
const LOCAL_TARGET: &str = "bob@local.test";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn processing_policy_restricts_outbox_spool_and_history_admission() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("message_processing_policy_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::support::migrate(&pool).await.unwrap();

    for (owner_id, username) in [(SENDER, "alice"), (RECIPIENT, "bob")] {
        let auth_generation: i64 = sqlx::query_scalar(
            "INSERT INTO users(id, username, password_hash) VALUES($1,$2,'test') RETURNING auth_generation",
        )
        .bind(owner_id)
        .bind(username)
        .fetch_one(&pool)
        .await
        .unwrap();
        northstar_archive_postgres::set_mam_preferences(
            &pool,
            &northstar_archive_core::MamLocalAuthority {
                id: owner_id,
                username: username.to_owned(),
                auth_generation,
            },
            &northstar_archive_postgres::MamPreferences {
                default_policy: "always".to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let service = MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            northstar_abuse_application::guard::test_personal_message_content_keyring(),
            "local.test",
            100,
            8192,
            30,
        ),
        false,
    );
    let routes = [
        (
            MessageDirection::Local { healthy: true },
            REMOTE_SENDER,
            LOCAL_TARGET,
        ),
        (
            MessageDirection::Federation { healthy: true },
            LOCAL_SENDER,
            "carol@remote.test",
        ),
        (
            MessageDirection::Component { healthy: true },
            LOCAL_SENDER,
            "room@component.test",
        ),
    ];
    for (direction, from, to) in routes {
        for (kind, payload) in [
            ("chat", "<body>volatile</body><no-store xmlns='urn:xmpp:hints'/>"),
            ("chat", "<received xmlns='urn:xmpp:receipts' id='earlier'/>"),
            ("chat", "<acknowledged xmlns='urn:xmpp:chat-markers:0' id='earlier'/>"),
            ("error", "<body>bounce</body><store xmlns='urn:xmpp:hints'/><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>"),
        ] {
            let raw = stanza(kind, from, to, payload);
            admit_by_policy(&service, direction, from, to, &raw).await;
        }
    }
    assert!(stored_stanzas(&pool, "SELECT stanza FROM s2s_outbox")
        .await
        .is_empty());
    assert!(stored_stanzas(&pool, "SELECT stanza FROM offline_messages")
        .await
        .is_empty());
    assert!(stored_stanzas(&pool, "SELECT stanza FROM message_archive")
        .await
        .is_empty());

    let mut outbox = Vec::new();
    let mut spool = Vec::new();
    let mut history = Vec::new();
    for (direction, from, to) in routes {
        let raw = stanza("chat", from, to, "<body>ordinary durable content</body>");
        admit_by_policy(&service, direction, from, to, &raw).await;
        history.push(raw.clone());
        if matches!(direction, MessageDirection::Local { .. }) {
            spool.push(raw);
        } else {
            outbox.push(raw);
        }
    }
    outbox.sort();
    assert_eq!(stored_outbox_payloads(&pool).await, outbox);
    for (statement, mut expected) in [
        ("SELECT stanza FROM offline_messages", spool),
        ("SELECT stanza FROM message_archive", history),
    ] {
        expected.sort();
        assert_eq!(stored_stanzas(&pool, statement).await, expected);
    }
    drop_isolated_message_pool(admin, pool, schema).await;
}

fn stanza(kind: &str, from: &str, to: &str, payload: &str) -> String {
    format!(
        "<message xmlns='jabber:client' from='{from}' to='{to}' type='{kind}'>{payload}</message>"
    )
}

async fn stored_stanzas(pool: &PgPool, statement: &str) -> Vec<String> {
    let mut rows = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(statement))
        .fetch_all(pool)
        .await
        .unwrap();
    rows.sort();
    rows
}

async fn stored_outbox_payloads(pool: &PgPool) -> Vec<String> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, stanza FROM s2s_outbox")
        .fetch_all(pool)
        .await
        .unwrap();
    let mut payloads = Vec::new();
    for (id, mut stored) in rows {
        let stamp_range = {
            let document = Document::parse(&stored).unwrap();
            let mut stamps = document
                .root_element()
                .children()
                .filter(|child| child.has_tag_name(("urn:xmpp:sid:0", "stanza-id")));
            let stamp = stamps
                .next()
                .expect("ordinary durable message has an outbox stamp");
            assert_eq!(stamp.attribute("id"), Some(id.to_string().as_str()));
            assert_eq!(stamp.attribute("by"), Some("alice@local.test"));
            assert!(stamps.next().is_none());
            stamp.range()
        };
        stored.replace_range(stamp_range, "");
        payloads.push(stored);
    }
    payloads.sort();
    payloads
}

async fn admit_by_policy(
    service: &MessageService<PostgresMessageRepository>,
    direction: MessageDirection,
    from: &str,
    to: &str,
    raw: &str,
) {
    let document = Document::parse(raw).unwrap();
    let MessageEffects::Persist { permanent } =
        classify_message_effects(document.root_element(), direction)
    else {
        return;
    };
    let delivery_id = Uuid::new_v4();
    let (local_actor_id, destination, owner_id, archive_direction, peer_jid) = match direction {
        MessageDirection::Local { .. } => (
            None,
            PersonalMessageDestination::Local(LocalDelivery {
                delivery_id,
                recipient_id: RECIPIENT,
                recipient_bare_jid: to,
                sender_jid: from,
                stanza: raw,
                encrypted: false,
            }),
            RECIPIENT,
            ArchiveDirection::Inbound,
            from,
        ),
        MessageDirection::Federation { .. } | MessageDirection::Component { .. } => (
            Some(SENDER),
            PersonalMessageDestination::Federation(FederationDelivery {
                local_actor_id: SENDER,
                target_domain: to.split_once('@').unwrap().1,
                stanza: raw,
                bounce_to: Some(from),
                limits: S2sOutboxPolicy::new(300, 10, 8192, 10),
            }),
            SENDER,
            ArchiveDirection::Outbound,
            to,
        ),
    };
    let candidate = permanent.then_some(ArchiveCandidate {
        direction: archive_direction,
        projection: ArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid,
            stanza: raw,
            encrypted: false,
            stanza_id: None,
        },
    });
    let outcome = service
        .admit_personal_message(&ValidatedPersonalMessage {
            local_actor_id,
            local_actor_fence: None,
            policy: None,
            identity: None,
            archives: candidate.as_slice(),
            destination,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, DurableAdmissionOutcome::Stored { .. }));
}
