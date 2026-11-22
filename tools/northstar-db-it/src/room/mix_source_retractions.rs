//! MIX source authority, snapshot interleavings and the raw evidence boundary.

use northstar_archive_core::{MamArchiveQuery, MamLocalAuthority, MamRsmPage};
use northstar_archive_postgres::{
    mam_account_is_current, mam_user_archive_page, mam_user_archive_page_in_transaction,
    ArchivePage,
};
use northstar_operations_application::api_queries::{ApiQueryRepository, ApiReadAuthority};
use northstar_operations_application::governance::{HeldRecordExport, LegalHoldTarget};
use northstar_operations_application::reports::ReportEvidenceInput;
use northstar_operations_postgres::data_lifecycle::{
    create_legal_hold_in_tx, export_legal_hold_page_in_tx, release_legal_hold_in_tx,
    CreateLegalHold, GOVERNANCE_SNAPSHOT_ISOLATION_SQL,
};
use northstar_operations_postgres::reports::{create_report_in_tx, ReportCreateError};
use northstar_room_application::mix_service::{
    MixDeliveryRepository, MixPayloads, MixPublisherIdentity, MixReflectionKind,
    ReflectedMixArchiveOutcome, VerifiedMixReflection,
};
use northstar_room_postgres::mix::{
    create_mix_channel, mix_channel_by_id, mix_participant, prune_empty_mix_delivery_events,
    prune_empty_mix_delivery_sequences, reconcile_mix_delivery_capacity_committed,
    retract_mix_message, store_mix_event_tx, CreateChannelOutcome, MixBusinessIdentity,
    RetractMixMessageAdmission, RetractMixMessageOutcome, NODE_MESSAGES,
};
use northstar_time::{DateTime, TimeDelta, Utc};
use northstar_workflows::{
    api_pages::history_page,
    api_queries::PostgresApiQueryRepository,
    mix_archive::{archive_mix_message_once, SourceArchiveAdmission},
    retention::{purge_resolved_retention_batch, RetentionStore},
    room_effects::{PostgresMixRepository, WorkflowRoomEffects},
};
use sha2::{Digest, Sha256};
use sqlx::{
    postgres::{PgConnectOptions, PgListener, PgPoolOptions},
    PgPool, Postgres, Transaction,
};
use std::time::Duration;
use uuid::Uuid;

const SERVICE: &str = "mix.example.test";
const ACTOR: &str = "owner@remote.test";
const FORMER: &str = "former@example.test";
const WAKE: &str = "northstar_mix_delivery_v1";
const BEFORE: &str = "source-fence-original";
const AFTER: &str = "source-fence-retraction";
const TIMEOUT: Duration = Duration::from_secs(5);

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    options: PgConnectOptions,
    schema: String,
    channel: Uuid,
    source: String,
    publisher: MixPublisherIdentity,
    target: Uuid,
    action: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let owner = PgPool::connect(&url).await.unwrap();
        let schema = format!("mix_source_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&owner)
            .await
            .unwrap();
        let options = url.parse::<PgConnectOptions>().unwrap().options([
            ("search_path", schema.as_str()),
            ("statement_timeout", "15000"),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(options.clone())
            .await
            .unwrap();
        crate::support::migrate(&pool).await.unwrap();
        let (created, _) = create_mix_channel(
            &WorkflowRoomEffects,
            &pool,
            SERVICE,
            Some("room"),
            ACTOR,
            100,
            &MixPayloads,
            None,
        )
        .await
        .unwrap();
        let CreateChannelOutcome::Created(channel) = created else {
            panic!("MIX channel not created")
        };
        sqlx::query("UPDATE mix_channels SET jid_visibility='visible' WHERE id=$1")
            .bind(channel)
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        for jid in [ACTOR, FORMER] {
            let participant = Uuid::new_v4();
            sqlx::query("INSERT INTO mix_participant_identities(channel_id,participant_id,jid) VALUES($1,$2,$3)")
                .bind(channel).bind(participant).bind(jid).execute(&mut *tx).await.unwrap();
            sqlx::query(
                "INSERT INTO mix_participants(channel_id,participant_id,jid) VALUES($1,$2,$3)",
            )
            .bind(channel)
            .bind(participant)
            .bind(jid)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO mix_subscriptions(channel_id,participant_id,node) VALUES($1,$2,$3)",
            )
            .bind(channel)
            .bind(participant)
            .bind(NODE_MESSAGES)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        let room = mix_channel_by_id(&pool, channel).await.unwrap().unwrap();
        let participant = mix_participant(&mut *tx, channel, ACTOR)
            .await
            .unwrap()
            .unwrap();
        let target = Uuid::new_v4();
        assert!(store_mix_event_tx(
            &mut tx,
            &room,
            NODE_MESSAGES,
            &target.to_string(),
            Some(&participant),
            "<message><body>channel original</body></message>"
        )
        .await
        .unwrap()
        .is_some());
        tx.commit().await.unwrap();
        Self {
            owner,
            pool,
            options,
            schema,
            channel,
            source: room.jid(),
            publisher: MixPublisherIdentity::from_state(&room, &participant),
            target,
            action: Uuid::new_v4(),
        }
    }

    async fn close(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.owner)
        .await
        .unwrap();
        self.owner.close().await;
    }

    async fn tagged_pool(&self, tag: &str) -> PgPool {
        PgPoolOptions::new()
            .max_connections(1)
            .connect_with(self.options.clone().application_name(tag))
            .await
            .unwrap()
    }

    async fn retraction(
        &self,
        pool: &PgPool,
        actor: &str,
        target: Uuid,
        publisher: &MixPublisherIdentity,
    ) -> anyhow::Result<RetractMixMessageAdmission> {
        let tombstone = format!("<message id='{target}'><retracted xmlns='urn:xmpp:mix:misc:0' by='{actor}' time='2026-11-20T10:05:00Z'/></message>");
        let action = format!(
            "<message id='{}'><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/></message>",
            self.action
        );
        retract_mix_message(
            pool,
            self.channel,
            actor,
            target,
            self.action,
            &tombstone,
            &action,
            Some(MixBusinessIdentity {
                client_id: "source-fence-client",
                semantic_key_id: "fixture-key-0001",
                semantic_mac: &[7; 32],
            }),
            publisher,
            Some(actor),
            &WorkflowRoomEffects,
            &MixPayloads,
        )
        .await
    }

    async fn listener(&self) -> PgListener {
        let mut listener = PgListener::connect_with(&self.pool).await.unwrap();
        listener.listen(WAKE).await.unwrap();
        listener
    }

    async fn wakes(&self, listener: &mut PgListener) -> usize {
        let marker = Uuid::new_v4().to_string();
        sqlx::query("SELECT pg_notify($1,$2)")
            .bind(WAKE)
            .bind(&marker)
            .execute(&self.pool)
            .await
            .unwrap();
        tokio::time::timeout(TIMEOUT, async {
            let mut count = 0;
            loop {
                let notification = listener.recv().await.unwrap();
                if notification.payload() == marker {
                    return count;
                }
                count += usize::from(notification.payload() == self.schema);
            }
        })
        .await
        .unwrap()
    }
}

async fn account(pool: &PgPool, name: &str, admin: bool) -> MamLocalAuthority {
    let id = Uuid::new_v4();
    let auth_generation = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash,is_admin)
        VALUES($1,$2,'test-only',$3) RETURNING auth_generation",
    )
    .bind(id)
    .bind(name)
    .bind(admin)
    .fetch_one(pool)
    .await
    .unwrap();
    MamLocalAuthority {
        id,
        username: name.to_owned(),
        auth_generation,
    }
}

fn query() -> MamArchiveQuery {
    MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: vec![],
        page: MamRsmPage::First,
        max: 20,
    }
}

fn original(channel: &str, target: Uuid, username: &str) -> String {
    format!("<message xmlns='jabber:client' from='{channel}/publisher' to='{username}@example.test' id='{target}' type='groupchat'><body>personal original</body><encrypted xmlns='urn:xmpp:omemo:2'/></message>")
}

async fn archive(pool: &PgPool, owner: Uuid, channel: &str, target: Uuid, xml: &str) -> Uuid {
    let id = Uuid::new_v4();
    assert_eq!(
        archive_mix_message_once(
            pool,
            id,
            owner,
            channel,
            target,
            xml,
            true,
            Some(&target.to_string())
        )
        .await
        .unwrap(),
        SourceArchiveAdmission::Stored(id)
    );
    id
}

type RawCopy = (String, bool, Option<String>, DateTime<Utc>, Vec<u8>);

async fn raw_copy(pool: &PgPool, id: Uuid) -> RawCopy {
    sqlx::query_as(
        "SELECT stanza, encrypted, stanza_id, created_at, source_payload_digest
                    FROM message_archive WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn page(pool: &PgPool, owner: Uuid) -> ArchivePage {
    mam_user_archive_page(pool, owner, &query())
        .await
        .unwrap()
        .unwrap()
}

fn assert_tombstone(stanza: &str, channel: &str, target: Uuid, action: Uuid) {
    let document = roxmltree::Document::parse(stanza).unwrap();
    let root = document.root_element();
    let children: Vec<_> = root
        .children()
        .filter(roxmltree::Node::is_element)
        .collect();
    assert_eq!(root.attribute("id"), Some(target.to_string().as_str()));
    assert_eq!(children.len(), 2);
    assert!(children[0].has_tag_name(("urn:xmpp:sid:0", "stanza-id")));
    assert_eq!(children[0].attribute("id"), root.attribute("id"));
    assert_eq!(children[0].attribute("by"), Some(channel));
    assert!(children[1].has_tag_name(("urn:xmpp:message-retract:1", "retracted")));
    assert_eq!(
        children[1].attribute("id"),
        Some(action.to_string().as_str())
    );
    assert!(children[1].attribute("stamp").unwrap().ends_with('Z'));
}

async fn channel_payload(pool: &PgPool, channel: Uuid, item: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT payload FROM mix_events WHERE channel_id=$1 AND node=$2 AND item_id=$3",
    )
    .bind(channel)
    .bind(NODE_MESSAGES)
    .bind(item.to_string())
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn local_retraction_projects_every_copy_without_rewriting_history() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let current = account(pool, "current", false).await;
    let former = account(pool, "former", false).await;
    sqlx::query(
        "DELETE FROM mix_subscriptions s USING mix_participants p
                 WHERE s.channel_id=p.channel_id AND s.participant_id=p.participant_id
                   AND p.channel_id=$1 AND p.jid=$2",
    )
    .bind(fixture.channel)
    .bind(FORMER)
    .execute(pool)
    .await
    .unwrap();
    let xml = original(&fixture.source, fixture.target, &current.username);
    let first = archive(pool, current.id, &fixture.source, fixture.target, &xml).await;
    let second = archive(
        pool,
        former.id,
        &fixture.source,
        fixture.target,
        &original(&fixture.source, fixture.target, &former.username),
    )
    .await;
    let unrelated_source = "other@mix.example.test";
    let unrelated = archive(
        pool,
        current.id,
        unrelated_source,
        fixture.target,
        &original(unrelated_source, fixture.target, &current.username),
    )
    .await;
    let direct = Uuid::new_v4();
    northstar_archive_postgres::archive_message(
        pool,
        direct,
        current.id,
        &fixture.source,
        "<message><body>direct</body></message>",
        false,
        Some(&fixture.target.to_string()),
    )
    .await
    .unwrap();
    let [before_first, before_second] = [raw_copy(pool, first).await, raw_copy(pool, second).await];
    let mut listener = fixture.listener().await;
    let mut read = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *read)
        .await
        .unwrap();
    assert!(mam_account_is_current(&mut read, &current).await.unwrap());
    let admission = fixture
        .retraction(pool, ACTOR, fixture.target, &fixture.publisher)
        .await
        .unwrap();
    assert_eq!(admission.outcome, RetractMixMessageOutcome::Retracted);
    assert_eq!(
        admission
            .recipients
            .iter()
            .map(|p| p.jid.as_str())
            .collect::<Vec<_>>(),
        [ACTOR]
    );
    assert_eq!(fixture.wakes(&mut listener).await, 1);
    let before = mam_user_archive_page_in_transaction(&mut read, current.id, &query())
        .await
        .unwrap()
        .unwrap();
    read.commit().await.unwrap();
    assert_eq!(
        before
            .rows
            .iter()
            .find(|row| row.id == first)
            .unwrap()
            .stanza,
        xml
    );
    let after = page(pool, current.id).await;
    assert_eq!(
        (before.total, before.first_index, before.complete),
        (after.total, after.first_index, after.complete)
    );
    for (old, new) in before.rows.iter().zip(&after.rows) {
        assert_eq!(
            (old.id, old.created_at, &old.stanza_id),
            (new.id, new.created_at, &new.stanza_id)
        );
        if new.id == first {
            assert!(!new.encrypted);
            assert_tombstone(&new.stanza, &fixture.source, fixture.target, fixture.action);
        } else {
            assert!([direct, unrelated].contains(&new.id));
            assert_eq!(old, new);
        }
    }
    let former_page = page(pool, former.id).await;
    assert_eq!(former_page.rows[0].id, second);
    assert_tombstone(
        &former_page.rows[0].stanza,
        &fixture.source,
        fixture.target,
        fixture.action,
    );
    assert_eq!(raw_copy(pool, first).await, before_first);
    assert_eq!(raw_copy(pool, second).await, before_second);
    assert!(channel_payload(pool, fixture.channel, fixture.target)
        .await
        .contains("<retracted xmlns='urn:xmpp:mix:misc:0'"));
    assert!(channel_payload(pool, fixture.channel, fixture.action)
        .await
        .contains("<retract xmlns='urn:xmpp:mix:misc:0'"));
    let recipients: Vec<String> =
        sqlx::query_scalar("SELECT recipient_jid FROM mix_delivery_recipients WHERE event_id=$1")
            .bind(fixture.action)
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(recipients, [ACTOR]);
    drop(listener);
    fixture.close().await;
}

async fn backend(tx: &mut Transaction<'_, Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

async fn wait_on(pool: &PgPool, blocker: i32, tag: &str, statement: &str) -> i32 {
    let waiter = crate::support::blocked_backend(pool, blocker).await;
    let (tag_found, query, event): (String, String, String) = sqlx::query_as(
        "SELECT application_name,query,wait_event FROM pg_stat_activity WHERE pid=$1",
    )
    .bind(waiter)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(tag_found, tag);
    assert!(query.contains(statement), "unexpected wait: {query}");
    assert_eq!(event, "advisory");
    waiter
}

async fn test_barrier(pool: &PgPool) -> (Transaction<'_, Postgres>, i32) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(('message_archive'::regclass)::oid::int4, 687)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let pid = backend(&mut tx).await;
    (tx, pid)
}

async fn install_pause(pool: &PgPool) {
    sqlx::raw_sql(
        "CREATE FUNCTION source_fence_pause() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF current_setting('application_name') = TG_ARGV[0] THEN
            PERFORM pg_advisory_xact_lock(('message_archive'::regclass)::oid::int4, 687);
          END IF;
          RETURN NEW;
        END $$;
        CREATE TRIGGER source_fence_archive_pause AFTER INSERT ON message_archive
          FOR EACH ROW EXECUTE FUNCTION source_fence_pause('source-fence-original');
        CREATE TRIGGER source_fence_fact_pause AFTER INSERT ON mix_source_retractions
          FOR EACH ROW EXECUTE FUNCTION source_fence_pause('source-fence-retraction');",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn source_fence_serializes_original_admission_in_both_orders() {
    for original_first in [true, false] {
        let fixture = std::sync::Arc::new(Fixture::new().await);
        let pool = &fixture.pool;
        let user = account(pool, "recipient", false).await;
        let owner_id = user.id;
        let xml = original(&fixture.source, fixture.target, &user.username);
        install_pause(pool).await;
        let original_pool = fixture
            .tagged_pool(if original_first {
                BEFORE
            } else {
                "waiting-original"
            })
            .await;
        let retract_pool = fixture
            .tagged_pool(if original_first {
                "waiting-retraction"
            } else {
                AFTER
            })
            .await;
        let mut listener = fixture.listener().await;
        let (pause, blocker) = test_barrier(pool).await;
        let admit = || {
            let (fixture, xml) = (fixture.clone(), xml.clone());
            tokio::spawn(async move {
                archive(
                    &original_pool,
                    owner_id,
                    &fixture.source,
                    fixture.target,
                    &xml,
                )
                .await
            })
        };
        let retract = || {
            let fixture = fixture.clone();
            tokio::spawn(async move {
                fixture
                    .retraction(&retract_pool, ACTOR, fixture.target, &fixture.publisher)
                    .await
                    .unwrap()
                    .outcome
            })
        };
        let (admitting, retracting) = if original_first {
            let admitting = admit();
            let locked = wait_on(pool, blocker, BEFORE, "INSERT INTO message_archive").await;
            let retracting = retract();
            wait_on(pool, locked, "waiting-retraction", "pg_advisory_xact_lock(").await;
            (admitting, retracting)
        } else {
            let retracting = retract();
            let locked = wait_on(pool, blocker, AFTER, "INSERT INTO mix_source_retractions").await;
            let admitting = admit();
            wait_on(
                pool,
                locked,
                "waiting-original",
                "pg_advisory_xact_lock_shared(",
            )
            .await;
            (admitting, retracting)
        };
        pause.commit().await.unwrap();
        let id = tokio::time::timeout(TIMEOUT, admitting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tokio::time::timeout(TIMEOUT, retracting)
                .await
                .unwrap()
                .unwrap(),
            RetractMixMessageOutcome::Retracted
        );
        let stored = raw_copy(pool, id).await;
        assert_eq!(stored.1, original_first);
        let result = page(pool, user.id).await;
        assert!(!result.rows[0].encrypted);
        assert_tombstone(
            &result.rows[0].stanza,
            &fixture.source,
            fixture.target,
            fixture.action,
        );
        assert_eq!(
            &stored.0,
            if original_first {
                &xml
            } else {
                &result.rows[0].stanza
            }
        );
        let client_id = fixture.target.to_string();
        let before = write_state(pool).await;
        assert_eq!(
            archive_mix_message_once(
                pool,
                Uuid::new_v4(),
                user.id,
                &fixture.source,
                fixture.target,
                &xml,
                true,
                Some(&client_id)
            )
            .await
            .unwrap(),
            SourceArchiveAdmission::Replay(id)
        );
        let altered = xml.replace("personal original", "different");
        for (raw, encrypted, client) in [
            (altered.as_str(), true, client_id.as_str()),
            (xml.as_str(), false, client_id.as_str()),
            (xml.as_str(), true, "changed-client-id"),
        ] {
            assert!(archive_mix_message_once(
                pool,
                Uuid::new_v4(),
                user.id,
                &fixture.source,
                fixture.target,
                raw,
                encrypted,
                Some(client)
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicting MIX source"));
        }
        assert_eq!(result, page(pool, user.id).await);
        assert_eq!(before, write_state(pool).await);
        assert_eq!(fixture.wakes(&mut listener).await, 1);
        drop(listener);
        std::sync::Arc::try_unwrap(fixture)
            .unwrap_or_else(|_| panic!("fixture is still shared"))
            .close()
            .await;
    }
}

async fn write_state(pool: &PgPool) -> serde_json::Value {
    sqlx::query_scalar::<_, sqlx::types::Json<serde_json::Value>>("SELECT jsonb_build_array(
        (SELECT count(*) FROM message_archive), (SELECT count(*) FROM mix_events),
        (SELECT count(*) FROM mix_business_intents), (SELECT count(*) FROM mix_source_retractions),
        (SELECT count(*) FROM mix_delivery_events), (SELECT count(*) FROM mix_delivery_recipients),
        (SELECT jsonb_agg(to_jsonb(s) ORDER BY s.recipient_jid) FROM mix_delivery_recipient_sequences s),
        (SELECT jsonb_agg(jsonb_build_array(queued_rows,queued_bytes) ORDER BY bucket) FROM mix_delivery_capacity),
        (SELECT count(*) FROM s2s_outbox))").fetch_one(pool).await.unwrap().0
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn failed_channel_retraction_rolls_back_source_and_delivery() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let user = account(pool, "recipient", false).await;
    let xml = original(&fixture.source, fixture.target, &user.username);
    archive(pool, user.id, &fixture.source, fixture.target, &xml).await;
    let before = write_state(pool).await;
    let channel_xml = channel_payload(pool, fixture.channel, fixture.target).await;
    let mut listener = fixture.listener().await;
    sqlx::raw_sql("CREATE FUNCTION source_fence_reject_projection() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NOT EXISTS (SELECT FROM mix_source_retractions WHERE action_stanza_id=NEW.event_id) THEN
            RAISE EXCEPTION 'source fact was not staged before enqueue';
          END IF;
          RAISE EXCEPTION 'fixture declines MIX projection';
        END $$;
        CREATE TRIGGER source_fence_reject_projection AFTER INSERT ON mix_delivery_recipients
          FOR EACH ROW EXECUTE FUNCTION source_fence_reject_projection();")
        .execute(pool).await.unwrap();
    let error = fixture
        .retraction(pool, ACTOR, fixture.target, &fixture.publisher)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("fixture declines MIX projection"),
        "{error:#}"
    );
    let mut stale = fixture.publisher.clone();
    stale.archive_jid_visible = false;
    for (actor, target, publisher, expected) in [
        (
            ACTOR,
            fixture.target,
            &stale,
            RetractMixMessageOutcome::IdentityPolicyChanged,
        ),
        (
            FORMER,
            fixture.target,
            &fixture.publisher,
            RetractMixMessageOutcome::Forbidden,
        ),
        (
            ACTOR,
            Uuid::new_v4(),
            &fixture.publisher,
            RetractMixMessageOutcome::NotFound,
        ),
    ] {
        let outcome = fixture
            .retraction(pool, actor, target, publisher)
            .await
            .unwrap();
        assert_eq!(outcome.outcome, expected);
        assert!(outcome.recipients.is_empty());
        assert_eq!(before, write_state(pool).await);
    }
    assert_eq!(
        channel_payload(pool, fixture.channel, fixture.target).await,
        channel_xml
    );
    assert_eq!(page(pool, user.id).await.rows[0].stanza, xml);
    assert_eq!(fixture.wakes(&mut listener).await, 0);
    drop(listener);
    fixture.close().await;
}

fn action_xml(source: &str, owner: &str, target: Uuid, action: Uuid, actor: &str) -> String {
    format!("<message xmlns='jabber:client' from='{source}/{actor}' to='{owner}@example.test' id='{action}' type='groupchat'><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/><mix xmlns='urn:xmpp:mix:core:1'/><stanza-id xmlns='urn:xmpp:sid:0' by='{source}' id='{action}'/></message>")
}

async fn admit_action(
    pool: &PgPool,
    owner: &MamLocalAuthority,
    source: &str,
    target: Uuid,
    action: Uuid,
    actor: &str,
) -> ReflectedMixArchiveOutcome {
    PostgresMixRepository::new(pool.clone())
        .archive_verified_mix_reflection(VerifiedMixReflection {
            personal_archive_id: Uuid::new_v4(),
            owner_id: owner.id,
            channel_jid: source,
            authoritative_stanza_id: action,
            stanza: &action_xml(source, &owner.username, target, action, actor),
            encrypted: false,
            kind: MixReflectionKind::Retraction {
                target_id: target,
                source_participant: actor,
            },
        })
        .await
        .unwrap()
}

async fn primary(pool: &PgPool, source: &str, target: Uuid) -> (Uuid, DateTime<Utc>) {
    let rows = sqlx::query_as(
        "SELECT action_stanza_id,retracted_at FROM mix_source_retractions
                              WHERE source_by=$1 AND target_stanza_id=$2 AND first_for_target",
    )
    .bind(source)
    .bind(target)
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    rows[0]
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn verified_reflection_converges_action_before_original_and_rejects_rebinding() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let source = "channel@mix.remote.test";
    let alice = account(pool, "alice", false).await;
    let bob = account(pool, "bob", false).await;
    let (target, action) = (fixture.target, fixture.action);
    let mut listener = fixture.listener().await;
    let before = write_state(pool).await;
    let ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Stored(action_row)) =
        admit_action(pool, &alice, source, target, action, "publisher").await
    else {
        panic!("verified action did not commit");
    };
    let first = primary(pool, source, target).await;
    assert_eq!(first.0, action);
    assert_eq!(page(pool, alice.id).await.rows[0].id, action_row);
    let input = original(source, target, &bob.username);
    let original_id = Uuid::new_v4();
    let owner = PostgresMixRepository::new(pool.clone());
    let original_request = VerifiedMixReflection {
        personal_archive_id: original_id,
        owner_id: bob.id,
        channel_jid: source,
        authoritative_stanza_id: target,
        stanza: &input,
        encrypted: true,
        kind: MixReflectionKind::Original,
    };
    assert_eq!(
        owner
            .archive_verified_mix_reflection(original_request)
            .await
            .unwrap(),
        ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Stored(original_id))
    );
    let stored = raw_copy(pool, original_id).await;
    assert!(!stored.1);
    assert_tombstone(&stored.0, source, target, action);
    assert_eq!(
        admit_action(pool, &alice, source, target, action, "publisher").await,
        ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Replay(action_row))
    );
    let committed = write_state(pool).await;
    for (other_target, other_actor) in [(Uuid::new_v4(), "publisher"), (target, "different")] {
        assert_eq!(
            admit_action(pool, &bob, source, other_target, action, other_actor).await,
            ReflectedMixArchiveOutcome::Conflict
        );
    }
    let impostor = original(source, action, &bob.username);
    assert_eq!(
        owner
            .archive_verified_mix_reflection(VerifiedMixReflection {
                authoritative_stanza_id: action,
                stanza: &impostor,
                ..original_request
            })
            .await
            .unwrap(),
        ReflectedMixArchiveOutcome::Conflict
    );
    assert_eq!(write_state(pool).await, committed);
    assert_eq!(primary(pool, source, target).await, first);

    let conflict_action = Uuid::new_v4();
    archive(
        pool,
        alice.id,
        source,
        conflict_action,
        &original(source, conflict_action, &alice.username),
    )
    .await;
    let prior_conflict = write_state(pool).await;
    assert_eq!(
        admit_action(
            pool,
            &alice,
            source,
            Uuid::new_v4(),
            conflict_action,
            "publisher"
        )
        .await,
        ReflectedMixArchiveOutcome::Conflict
    );
    assert_eq!(write_state(pool).await, prior_conflict);

    let (historic_target, historic_action, historic_row) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let historic_xml = action_xml(
        source,
        &alice.username,
        historic_target,
        historic_action,
        "publisher",
    );
    assert_eq!(
        archive_mix_message_once(
            pool,
            historic_row,
            alice.id,
            source,
            historic_action,
            &historic_xml,
            false,
            Some(&historic_action.to_string())
        )
        .await
        .unwrap(),
        SourceArchiveAdmission::Stored(historic_row)
    );
    assert_eq!(
        admit_action(
            pool,
            &alice,
            source,
            historic_target,
            historic_action,
            "publisher"
        )
        .await,
        ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Replay(historic_row))
    );
    assert_eq!(
        primary(pool, source, historic_target).await.0,
        historic_action
    );

    install_pause(pool).await;
    for reverse in [false, true] {
        let mut source_ids = [Uuid::new_v4(), Uuid::new_v4()];
        let (barrier, blocker, first_tag) = if reverse {
            let keys: Vec<i32> = sqlx::query_scalar(
                "SELECT pg_catalog.hashtext($1::text || ':' || source_id::text)
                 FROM pg_catalog.unnest($2::uuid[]) WITH ORDINALITY AS ids(source_id, ord) ORDER BY ord",
            ).bind(source).bind(source_ids.as_slice()).fetch_all(pool).await.unwrap();
            assert_ne!(keys[0], keys[1], "fixture UUIDs share an advisory key");
            if keys[0] < keys[1] {
                source_ids.swap(0, 1);
            }
            let mut barrier = pool.begin().await.unwrap();
            sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(('mix_source_retractions'::regclass)::oid::int4, $1)")
                .bind(keys[0].max(keys[1])).execute(&mut *barrier).await.unwrap();
            let blocker = backend(&mut barrier).await;
            (barrier, blocker, "source-fence-first-action")
        } else {
            let (barrier, blocker) = test_barrier(pool).await;
            (barrier, blocker, AFTER)
        };
        let [first_target, first_action] = source_ids;
        let (second_target, second_action) = if reverse {
            (first_action, first_target)
        } else {
            (first_target, Uuid::new_v4())
        };
        let first_pool = fixture.tagged_pool(first_tag).await;
        let first_owner = alice.clone();
        let first_writer = tokio::spawn(async move {
            admit_action(
                &first_pool,
                &first_owner,
                source,
                first_target,
                first_action,
                "publisher",
            )
            .await
        });
        let statement = if reverse {
            "pg_advisory_xact_lock("
        } else {
            "INSERT INTO mix_source_retractions"
        };
        let holding = wait_on(pool, blocker, first_tag, statement).await;
        let second_pool = fixture.tagged_pool("source-fence-second-action").await;
        let second_owner = bob.clone();
        let second_writer = tokio::spawn(async move {
            admit_action(
                &second_pool,
                &second_owner,
                source,
                second_target,
                second_action,
                "publisher",
            )
            .await
        });
        wait_on(
            pool,
            holding,
            "source-fence-second-action",
            "pg_advisory_xact_lock(",
        )
        .await;
        barrier.commit().await.unwrap();
        for writer in [first_writer, second_writer] {
            assert!(matches!(
                tokio::time::timeout(TIMEOUT, writer)
                    .await
                    .unwrap()
                    .unwrap(),
                ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Stored(_))
            ));
        }
        let winning = primary(pool, source, first_target).await;
        assert_eq!(winning.0, first_action);
        assert!(matches!(
            admit_action(
                pool,
                &bob,
                source,
                second_target,
                second_action,
                "publisher"
            )
            .await,
            ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Replay(_))
        ));
        assert_eq!(primary(pool, source, first_target).await, winning);
        if reverse {
            assert_eq!(primary(pool, source, second_target).await.0, second_action);
        }
    }
    let after = write_state(pool).await;
    for index in [1, 2, 4, 5, 6, 7, 8] {
        assert_eq!(before[index], after[index]);
    }
    assert_eq!(fixture.wakes(&mut listener).await, 0);
    drop(listener);
    fixture.close().await;
}

fn held_hash(previous: [u8; 32], record: &HeldRecordExport) -> [u8; 32] {
    let canonical = format!(concat!("{{\"resource_type\":{},\"record_id\":{},\"subject_id\":{},",
        "\"encrypted\":{},\"record_created_at\":{},\"server_visible_payload\":{},\"payload_disposition\":{}}}"),
        serde_json::to_string(&record.resource_type).unwrap(), serde_json::to_string(&record.record_id).unwrap(),
        serde_json::to_string(&record.subject_id).unwrap(), record.encrypted,
        serde_json::to_string(&record.record_created_at).unwrap(),
        serde_json::to_string(&record.server_visible_payload).unwrap(),
        serde_json::to_string(&record.payload_disposition).unwrap());
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn held_source_retraction_preserves_raw_evidence_and_survives_retention() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let exact = account(pool, "exact", false).await;
    let scope = account(pool, "scope", false).await;
    let admin = account(pool, "admin", true).await;
    let xml = original(&fixture.source, fixture.target, &exact.username);
    let scope_xml = original(&fixture.source, fixture.target, &scope.username);
    let first = archive(pool, exact.id, &fixture.source, fixture.target, &xml).await;
    let second = archive(pool, scope.id, &fixture.source, fixture.target, &scope_xml).await;
    let now = Utc::now();
    for (id, age) in [(first, 91), (second, 90)] {
        sqlx::query("UPDATE message_archive SET created_at=$2 WHERE id=$1")
            .bind(id)
            .bind(now - TimeDelta::days(age))
            .execute(pool)
            .await
            .unwrap();
    }
    let raw_first = raw_copy(pool, first).await;
    let raw_second = raw_copy(pool, second).await;
    let evidence = [ReportEvidenceInput {
        archive_id: first,
        client_message_id: raw_first.2.clone(),
        body_text: "reporter supplied evidence".to_owned(),
    }];
    let mut report = pool.begin().await.unwrap();
    create_report_in_tx(
        &mut report,
        exact.id,
        &fixture.source,
        "spam",
        "before source retraction",
        &evidence,
        None,
    )
    .await
    .unwrap();
    report.rollback().await.unwrap();

    let hold = Uuid::new_v4();
    let mut transaction = pool.begin().await.unwrap();
    create_legal_hold_in_tx(
        &mut transaction,
        admin.id,
        &CreateLegalHold {
            id: hold,
            title: "MIX evidence",
            authority_reference: "fixture-case",
            reason: "preserve raw stanzas",
            targets: &[
                LegalHoldTarget::PersonalArchive(first),
                LegalHoldTarget::PersonalArchiveOwner(scope.id),
            ],
            request_id: Uuid::new_v4(),
        },
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    let mut export_tx = pool.begin().await.unwrap();
    sqlx::query(GOVERNANCE_SNAPSHOT_ISOLATION_SQL)
        .execute(&mut *export_tx)
        .await
        .unwrap();
    let export_id = Uuid::new_v4();
    let before = export_legal_hold_page_in_tx(
        &mut export_tx,
        admin.id,
        hold,
        1,
        export_id,
        None,
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    export_tx.commit().await.unwrap();
    assert!(!before.complete);
    assert_eq!(before.records[0].record_id, first);
    assert_eq!(
        before.records[0].server_visible_payload.as_deref(),
        Some(xml.as_str())
    );
    assert_eq!(before.records[0].previous_hash, before.chain_start_sha256);

    let mut listener = fixture.listener().await;
    let mut archive_lock = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE message_archive IN SHARE MODE")
        .execute(&mut *archive_lock)
        .await
        .unwrap();
    let admission = tokio::time::timeout(
        TIMEOUT,
        fixture.retraction(pool, ACTOR, fixture.target, &fixture.publisher),
    )
    .await
    .expect("retraction waited for an archive write lock")
    .unwrap();
    assert_eq!(admission.outcome, RetractMixMessageOutcome::Retracted);
    archive_lock.commit().await.unwrap();
    assert_eq!(fixture.wakes(&mut listener).await, 1);
    assert_eq!(raw_copy(pool, first).await, raw_first);
    assert_eq!(raw_copy(pool, second).await, raw_second);

    let rest = PostgresApiQueryRepository::new(pool.clone());
    for (account, id, raw) in [(&exact, first, &raw_first), (&scope, second, &raw_second)] {
        let mam = page(pool, account.id).await;
        assert_eq!(
            (
                mam.rows[0].id,
                mam.rows[0].created_at,
                &mam.rows[0].stanza_id
            ),
            (id, raw.3, &raw.2)
        );
        assert_tombstone(
            &mam.rows[0].stanza,
            &fixture.source,
            fixture.target,
            fixture.action,
        );
        assert!(!mam.rows[0].encrypted);
        let token = northstar_auth_postgres::users::create_api_session(pool, account.id, 1)
            .await
            .unwrap();
        let http = rest
            .history(
                ApiReadAuthority {
                    user_id: account.id,
                    auth_generation: account.auth_generation,
                    session_token: &token,
                },
                &query(),
            )
            .await
            .unwrap()
            .unwrap()
            .value
            .unwrap();
        assert_eq!(http, mam);
        let history = history_page(pool, account.id, Some(&fixture.source), None, 10)
            .await
            .unwrap();
        assert_eq!(
            (
                history.rows[0].id,
                &history.rows[0].stanza,
                history.rows[0].encrypted
            ),
            (id, &mam.rows[0].stanza, false)
        );
        let pie = northstar_data_tools::pie::export_mam_for_test(pool, account.id)
            .await
            .unwrap();
        assert!(pie.contains(&format!("id='{id}'")));
        assert!(pie.contains(&raw.3.to_rfc3339()));
        assert!(pie.contains(mam.rows[0].stanza.as_str()));
        assert!(!pie.contains("personal original"));
    }

    let cursor = before.next.unwrap();
    let mut export_tx = pool.begin().await.unwrap();
    sqlx::query(GOVERNANCE_SNAPSHOT_ISOLATION_SQL)
        .execute(&mut *export_tx)
        .await
        .unwrap();
    let after = export_legal_hold_page_in_tx(
        &mut export_tx,
        admin.id,
        hold,
        1,
        export_id,
        Some(cursor.clone()),
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    export_tx.commit().await.unwrap();
    assert!(after.complete);
    let record = &after.records[0];
    assert_eq!(record.record_id, second);
    assert!(record.encrypted);
    assert_eq!(
        record.server_visible_payload.as_deref(),
        Some(scope_xml.as_str())
    );
    assert_eq!(before.records[0].entry_hash, before.chain_root_sha256);
    assert_eq!(after.chain_start_sha256, before.chain_root_sha256);
    assert_eq!(record.previous_hash, before.chain_root_sha256);
    let entry_hash: String = held_hash(cursor.chain_root, record)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(record.entry_hash, entry_hash);
    assert_eq!(after.chain_root_sha256, entry_hash);

    let mut report = pool.begin().await.unwrap();
    assert!(matches!(
        create_report_in_tx(
            &mut report,
            exact.id,
            &fixture.source,
            "spam",
            "after source retraction",
            &evidence,
            None
        )
        .await,
        Err(ReportCreateError::InvalidEvidence(_))
    ));
    report.rollback().await.unwrap();
    assert_eq!(
        purge_resolved_retention_batch(pool, RetentionStore::PersonalMam, now, 30, 100)
            .await
            .unwrap(),
        0
    );
    let mut transaction = pool.begin().await.unwrap();
    release_legal_hold_in_tx(
        &mut transaction,
        admin.id,
        hold,
        "fixture concluded",
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(
        purge_resolved_retention_batch(pool, RetentionStore::PersonalMam, now, 30, 100)
            .await
            .unwrap(),
        2
    );

    sqlx::query("DELETE FROM mix_delivery_recipients WHERE event_id=$1")
        .bind(fixture.action)
        .execute(pool)
        .await
        .unwrap();
    reconcile_mix_delivery_capacity_committed(pool)
        .await
        .unwrap();
    prune_empty_mix_delivery_events(pool, 100).await.unwrap();
    prune_empty_mix_delivery_sequences(pool, 100).await.unwrap();
    sqlx::query("DELETE FROM mix_channels WHERE id=$1")
        .bind(fixture.channel)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(exact.id)
        .execute(pool)
        .await
        .unwrap();
    let replacement = account(pool, &exact.username, false).await;
    assert_ne!(exact.id, replacement.id);
    let replacement_id = archive(pool, replacement.id, &fixture.source, fixture.target, &xml).await;
    let stored = raw_copy(pool, replacement_id).await;
    assert!(!stored.1);
    assert_tombstone(&stored.0, &fixture.source, fixture.target, fixture.action);
    assert_eq!(
        primary(pool, &fixture.source, fixture.target).await.0,
        fixture.action
    );
    drop(listener);
    fixture.close().await;
}
