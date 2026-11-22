//! Lock-ordered coverage of the federated MAM enqueue fence.

use super::mam_read_authority_tests::{query, room_message, viewer, Fixture};
use crate::support::blocked_backend;
use northstar_archive_application::{
    FederatedMamAdmissionOutcome as Outcome, FederatedMamOutboxLimits, FederatedMamStreamRequest,
    MamService,
};
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_postgres::{
    effects::RoomEffects, mam_authorization::FederatedMamRoomGuard,
    muc::set_federated_muc_affiliation,
};
use northstar_workflows::{
    mam_repository::{
        test_support::{
            claim_due_s2s_outbox_for_domains, complete_s2s_outbox, expire_s2s_outbox,
            FederatedMamPausePoint::{AfterRender, BeforeRetry},
        },
        PostgresMamRepository,
    },
    room_effects::WorkflowRoomEffects,
};
use serde_json::Value;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinHandle, time::timeout};
use uuid::Uuid;

const WINNER: &str = "winner-room";
const LOSER: &str = "losing-room";
const DOMAIN: &str = "alpha.test";
const OTHER_DOMAIN: &str = "bravo.test";
const OUTBOX_ADVISORY_LOCK: i64 = 0x4e53_5332_534f_5554;
const TIMEOUT: Duration = Duration::from_secs(10);
const LIMITS: FederatedMamOutboxLimits = FederatedMamOutboxLimits {
    ttl_seconds: 300,
    max_rows: 100,
    max_bytes: 1024 * 1024,
    max_per_domain: 100,
};
const WRITER_POLICY: S2sOutboxPolicy = S2sOutboxPolicy {
    ttl_seconds: LIMITS.ttl_seconds,
    max_rows: LIMITS.max_rows,
    max_bytes: LIMITS.max_bytes,
    max_per_domain: LIMITS.max_per_domain,
};

async fn seed_room(pool: &PgPool, room: &str, legacy: bool) -> (Uuid, Uuid) {
    let mut connection = pool.acquire().await.unwrap();
    let room_id = sqlx::query_scalar(
        "INSERT INTO muc_rooms(id,localpart,occupant_id_secret)
         VALUES(gen_random_uuid(),$1,$2) RETURNING id",
    )
    .bind(room)
    .bind((!legacy).then(|| vec![7_u8; 32]))
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    (room_id, room_message(&mut connection, room_id).await)
}

fn result_stanza(room: &str, domain: &str, id: Uuid) -> String {
    let domain = domain.to_ascii_lowercase();
    format!("<message xmlns='jabber:server' from='{room}@conference.local.test' to='viewer@{domain}/Phone'><result xmlns='urn:xmpp:mam:2' id='{id}'/></message>")
}

fn fin_stanza(room: &str) -> String {
    format!(
        "<iq xmlns='jabber:server' type='result' id='{room}'><fin xmlns='urn:xmpp:mam:2'/></iq>"
    )
}

type RenderedPages = Vec<Vec<Uuid>>;

fn start_room(
    repository: PostgresMamRepository,
    limits: FederatedMamOutboxLimits,
    room: &'static str,
    domain: &'static str,
) -> (JoinHandle<(Outcome, RenderedPages)>, mpsc::Receiver<()>) {
    let (wake, receiver) = mpsc::channel(4);
    let service = MamService::new(repository, limits, wake);
    let task = tokio::spawn(async move {
        let mut rendered = Vec::new();
        let authority = viewer(&format!("viewer@{domain}/Phone"), None);
        let query = query();
        let outcome = service
            .admit_federated_room_stream(
                FederatedMamStreamRequest::new(domain, room, &authority, &query),
                |page| {
                    let ids: Vec<_> = page.rows().iter().map(|row| row.id()).collect();
                    let responses = ids
                        .iter()
                        .map(|&id| result_stanza(room, domain, id))
                        .chain(std::iter::once(fin_stanza(room)))
                        .collect();
                    rendered.push(ids);
                    Ok(responses)
                },
            )
            .await
            .unwrap();
        (outcome, rendered)
    });
    (task, receiver)
}

async fn finish(task: JoinHandle<(Outcome, RenderedPages)>) -> (Outcome, RenderedPages) {
    timeout(TIMEOUT, task).await.unwrap().unwrap()
}

fn assert_wakes(receiver: &mut mpsc::Receiver<()>, count: usize) {
    for _ in 0..count {
        assert_eq!(receiver.try_recv(), Ok(()));
    }
    assert!(receiver.try_recv().is_err(), "unexpected MAM outbox wake");
}

async fn stage_writer(transaction: &mut Transaction<'_, Postgres>, stanza: &str) -> Uuid {
    WorkflowRoomEffects
        .enqueue_federated_stanza(transaction, DOMAIN, stanza, None, WRITER_POLICY)
        .await
        .unwrap()
}

async fn pid(connection: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await
        .unwrap()
}

async fn advisory_waiter(pool: &PgPool, blocker: i32) -> i32 {
    let waiter = blocked_backend(pool, blocker).await;
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)",
    )
    .bind(waiter)
    .fetch_one(pool)
    .await
    .unwrap());
    waiter
}

async fn generation(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT generation FROM s2s_outbox_enqueue_generation WHERE singleton")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct OutboxRow {
    id: Uuid,
    enqueue_sequence: i64,
    target_domain: String,
    stanza: String,
    bytes: i32,
}

async fn outbox(pool: &PgPool) -> Vec<OutboxRow> {
    sqlx::query_as(
        "SELECT id,enqueue_sequence,target_domain,stanza,octet_length(stanza) AS bytes
           FROM s2s_outbox ORDER BY enqueue_sequence",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn assert_stream(rows: &[OutboxRow], room: &str, domain: &str, ids: &[Uuid]) {
    assert_eq!(rows.len(), ids.len() + 1);
    for (row, id) in rows.iter().zip(ids) {
        assert_eq!(row.target_domain, domain);
        let document = roxmltree::Document::parse(&row.stanza).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().name(), "message");
        let sender = format!("{room}@conference.local.test");
        assert_eq!(root.attribute("from"), Some(sender.as_str()));
        let result = root
            .children()
            .find(|node| node.has_tag_name(("urn:xmpp:mam:2", "result")));
        assert_eq!(
            result.unwrap().attribute("id"),
            Some(id.to_string().as_str())
        );
        let stamp = root
            .children()
            .find(|node| node.has_tag_name(("urn:xmpp:sid:0", "stanza-id")));
        assert_eq!(
            stamp.unwrap().attribute("id"),
            Some(row.id.to_string().as_str())
        );
    }
    let fin = rows.last().unwrap();
    assert_eq!(fin.target_domain, domain);
    assert_eq!(fin.stanza, fin_stanza(room));
    assert!(rows
        .windows(2)
        .all(|pair| pair[0].enqueue_sequence < pair[1].enqueue_sequence));
}

async fn history_state(pool: &PgPool) -> Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_array(
             (SELECT jsonb_agg(to_jsonb(msg) ORDER BY id) FROM muc_messages msg),
             (SELECT count(*) FROM message_archive),
             (SELECT count(*) FROM personal_retraction_intents),
             (SELECT count(*) FROM personal_retraction_action_projections),
             (SELECT count(*) FROM cluster_muc_event_delivery_items),
             (SELECT count(*) FROM cluster_muc_delivery_handoffs))",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn assert_legacy_secret_missing(pool: &PgPool, room_id: Uuid) {
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT occupant_id_secret IS NULL FROM muc_rooms WHERE id=$1",
    )
    .bind(room_id)
    .fetch_one(pool)
    .await
    .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn different_rooms_cannot_overadmit_global_rows_bytes_or_domain_rows() {
    for dimension in ["rows", "bytes", "domain"] {
        let fixture = Fixture::new().await;
        let pool = &fixture.pool;
        let (_, winner_id) = seed_room(pool, WINNER, false).await;
        let (_, loser_id) = seed_room(pool, LOSER, false).await;
        let before = history_state(pool).await;
        let repository = PostgresMamRepository::new(pool.clone());
        let mut rendered = repository.pause_admission_at(1, AfterRender);
        let mut retry = repository.pause_admission_at(1, BeforeRetry);
        let mut limits = LIMITS;
        let mut sequence_offset = 0;
        let mut prefix_bytes = 0;
        let loser_domain = match dimension {
            "rows" => {
                limits.max_rows = 3;
                OTHER_DOMAIN
            }
            "bytes" => {
                let mut calibration = pool.begin().await.unwrap();
                let id = stage_writer(
                    &mut calibration,
                    &result_stanza(LOSER, OTHER_DOMAIN, loser_id),
                )
                .await;
                (sequence_offset, prefix_bytes) = sqlx::query_as(
                    "SELECT enqueue_sequence,octet_length(stanza) FROM s2s_outbox WHERE id=$1",
                )
                .bind(id)
                .fetch_one(&mut *calibration)
                .await
                .unwrap();
                calibration.rollback().await.unwrap();
                assert_eq!(generation(pool).await, 0);
                limits.max_bytes = 2 * i64::from(prefix_bytes) + fin_stanza(WINNER).len() as i64;
                OTHER_DOMAIN
            }
            "domain" => {
                limits.max_per_domain = 3;
                "ALPHA.TEST"
            }
            _ => unreachable!(),
        };

        sqlx::raw_sql(
            "CREATE FUNCTION pause_quota_winner() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN
                 PERFORM pg_advisory_xact_lock(68801);
                 RETURN NEW;
               END;
             $$;
             CREATE TRIGGER pause_quota_winner BEFORE INSERT ON s2s_outbox
               FOR EACH ROW WHEN (NEW.stanza LIKE '%winner-room@conference.local.test%')
               EXECUTE FUNCTION pause_quota_winner();",
        )
        .execute(pool)
        .await
        .unwrap();
        let mut gate = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(68801)")
            .execute(&mut *gate)
            .await
            .unwrap();
        let (loser, mut loser_wake) = start_room(repository, limits, LOSER, loser_domain);
        rendered.wait().await;
        let (winner, mut winner_wake) = start_room(
            PostgresMamRepository::new(pool.clone()),
            limits,
            WINNER,
            DOMAIN,
        );
        let winner_pid = advisory_waiter(pool, pid(&mut gate).await).await;
        rendered.release();
        advisory_waiter(pool, winner_pid).await;
        gate.commit().await.unwrap();

        assert_eq!(
            finish(winner).await,
            (Outcome::Queued, vec![vec![winner_id]])
        );
        assert_wakes(&mut winner_wake, 1);
        retry.wait().await;
        let winner_rows = outbox(pool).await;
        assert_stream(&winner_rows, WINNER, DOMAIN, &[winner_id]);
        assert_eq!(winner_rows[0].enqueue_sequence, sequence_offset + 1);
        assert_eq!(winner_rows[1].enqueue_sequence, sequence_offset + 2);
        if dimension == "bytes" {
            let winner_bytes: i64 = winner_rows.iter().map(|row| i64::from(row.bytes)).sum();
            assert_eq!(winner_bytes + i64::from(prefix_bytes), limits.max_bytes);
        }

        retry.release();
        assert_eq!(
            finish(loser).await,
            (Outcome::OutboxRejected, vec![vec![loser_id]; 2])
        );
        assert_wakes(&mut loser_wake, 0);
        assert_eq!(outbox(pool).await, winner_rows);
        assert_eq!(generation(pool).await, 2);
        let sequence: i64 =
            sqlx::query_scalar("SELECT last_value FROM s2s_outbox_enqueue_sequence_seq")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(
            sequence,
            sequence_offset + 3,
            "retry must roll back an admitted prefix"
        );
        assert_eq!(history_state(pool).await, before);
        fixture.cleanup().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn read_committed_winner_forces_fresh_room_authorization_and_render() {
    for revoke in [false, true] {
        let fixture = Fixture::new().await;
        let pool = &fixture.pool;
        let (room_id, first_id) = seed_room(pool, LOSER, false).await;
        let repository = PostgresMamRepository::new(pool.clone());
        let mut rendered = repository.pause_admission_at(1, AfterRender);
        let mut retry = repository.pause_admission_at(1, BeforeRetry);
        let (reader, mut wake) = start_room(repository, LIMITS, LOSER, OTHER_DOMAIN);
        rendered.wait().await;

        let mut writer = pool.begin().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SHOW transaction_isolation")
                .fetch_one(&mut *writer)
                .await
                .unwrap(),
            "read committed"
        );
        let winner_id = stage_writer(&mut writer, "<iq id='independent-winner'/>").await;
        rendered.release();
        advisory_waiter(pool, pid(&mut writer).await).await;
        writer.commit().await.unwrap();

        retry.wait().await;
        assert_wakes(&mut wake, 0);
        if revoke {
            timeout(
                TIMEOUT,
                set_federated_muc_affiliation(pool, room_id, "viewer@bravo.test", "outcast"),
            )
            .await
            .expect("attempt retained the room guard before retry")
            .unwrap();
            let expected_history = history_state(pool).await;
            retry.release();
            assert_eq!(
                finish(reader).await,
                (Outcome::Forbidden, vec![vec![first_id]])
            );
            assert_eq!(outbox(pool).await.len(), 1);
            assert_eq!(generation(pool).await, 1);
            assert_wakes(&mut wake, 0);
            assert_eq!(history_state(pool).await, expected_history);
        } else {
            let fresh_id = {
                let mut connection = pool.acquire().await.unwrap();
                room_message(&mut connection, room_id).await
            };
            let fresh_ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM muc_messages WHERE room_id=$1 ORDER BY created_at,id",
            )
            .bind(room_id)
            .fetch_all(pool)
            .await
            .unwrap();
            assert!(fresh_ids.contains(&fresh_id));
            assert_eq!(fresh_ids.len(), 2);
            let expected_history = history_state(pool).await;
            retry.release();
            assert_eq!(
                finish(reader).await,
                (Outcome::Queued, vec![vec![first_id], fresh_ids.clone()])
            );
            let rows = outbox(pool).await;
            assert_eq!(rows[0].id, winner_id);
            assert_eq!(
                rows.iter()
                    .map(|row| row.enqueue_sequence)
                    .collect::<Vec<_>>(),
                [1, 2, 3, 4]
            );
            assert_stream(&rows[1..], LOSER, OTHER_DOMAIN, &fresh_ids);
            assert_eq!(generation(pool).await, 4);
            assert_wakes(&mut wake, 1);
            assert_eq!(history_state(pool).await, expected_history);
        }
        assert_eq!(outbox(pool).await[0].id, winner_id);
        assert_actual_serialization_state(pool).await;
        fixture.cleanup().await;
    }
}

async fn assert_actual_serialization_state(pool: &PgPool) {
    let before = generation(pool).await;
    let mut stale = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *stale)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM s2s_outbox")
            .fetch_one(&mut *stale)
            .await
            .unwrap(),
        before,
    );
    let mut writer = pool.begin().await.unwrap();
    stage_writer(&mut writer, "<iq id='raw-rc-winner'/>").await;
    let enqueue = tokio::spawn(async move {
        let result = WorkflowRoomEffects
            .enqueue_federated_stanza(
                &mut stale,
                OTHER_DOMAIN,
                "<iq id='raw-stale'/>",
                None,
                WRITER_POLICY,
            )
            .await;
        stale.rollback().await.unwrap();
        result
    });
    advisory_waiter(pool, pid(&mut writer).await).await;
    writer.commit().await.unwrap();
    let error = timeout(TIMEOUT, enqueue)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    let state = error.chain().find_map(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()?
            .as_database_error()?
            .code()
    });
    assert_eq!(state.as_deref(), Some("40001"));
    assert_eq!(generation(pool).await, before + 1);
    assert_eq!(outbox(pool).await.len() as i64, before + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn second_serialization_conflict_rolls_back_without_wake() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let (room_id, archive_id) = seed_room(pool, LOSER, true).await;
    let before = history_state(pool).await;
    let repository = PostgresMamRepository::new(pool.clone());
    let first = repository.pause_admission_at(1, AfterRender);
    let second = repository.pause_admission_at(2, AfterRender);
    let (reader, mut wake) = start_room(repository, LIMITS, LOSER, OTHER_DOMAIN);
    let mut winners = Vec::new();
    for (mut rendered, stanza) in [
        (first, "<iq id='first-winner'/>"),
        (second, "<iq id='second-winner'/>"),
    ] {
        rendered.wait().await;
        assert_legacy_secret_missing(pool, room_id).await;
        let mut writer = pool.begin().await.unwrap();
        winners.push(stage_writer(&mut writer, stanza).await);
        rendered.release();
        advisory_waiter(pool, pid(&mut writer).await).await;
        writer.commit().await.unwrap();
    }

    assert_eq!(
        finish(reader).await,
        (Outcome::OutboxRejected, vec![vec![archive_id]; 2])
    );
    assert_wakes(&mut wake, 0);
    assert_legacy_secret_missing(pool, room_id).await;
    assert_eq!(generation(pool).await, 2);
    let rows = outbox(pool).await;
    assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), winners);
    assert_eq!(
        rows.iter()
            .map(|row| row.enqueue_sequence)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(history_state(pool).await, before);
    let guard = timeout(TIMEOUT, FederatedMamRoomGuard::acquire(pool, LOSER))
        .await
        .expect("exhausted attempt retained the room guard")
        .unwrap()
        .unwrap();
    assert!(guard.release().await);
    fixture.cleanup().await;
}

async fn hold_advisory_lock(pool: &PgPool) -> Transaction<'static, Postgres> {
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(OUTBOX_ADVISORY_LOCK)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker
}

async fn seed_expiring(pool: &PgPool, ttl_seconds: u64) -> Uuid {
    let mut transaction = pool.begin().await.unwrap();
    let id = WorkflowRoomEffects
        .enqueue_federated_stanza(
            &mut transaction,
            DOMAIN,
            "<iq id='expiring'/>",
            None,
            S2sOutboxPolicy {
                ttl_seconds,
                ..WRITER_POLICY
            },
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    id
}

async fn wait_for_expiry(pool: &PgPool, id: Uuid) {
    timeout(TIMEOUT, async {
        while !sqlx::query_scalar::<_, bool>(
            "SELECT expires_at <= clock_timestamp() FROM s2s_outbox WHERE id=$1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("outbox row did not expire on the database clock");
}

async fn complete_fifo_head(pool: &PgPool, expected: Uuid) {
    let claims = claim_due_s2s_outbox_for_domains(pool, 10, 60, &[OTHER_DOMAIN.to_owned()])
        .await
        .unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].id, expected);
    assert!(complete_s2s_outbox(pool, expected, claims[0].lock_token)
        .await
        .unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn expiry_and_completion_do_not_advance_or_lock_the_generation() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let (_, archive_id) = seed_room(pool, LOSER, false).await;
    let before_history = history_state(pool).await;
    let expired = seed_expiring(pool, 1).await;
    wait_for_expiry(pool, expired).await;
    let expiring = seed_expiring(pool, 5).await;
    let mut blocker = hold_advisory_lock(pool).await;
    let repository = PostgresMamRepository::new(pool.clone());
    let short_limit = FederatedMamOutboxLimits {
        max_rows: 2,
        ..LIMITS
    };
    let (reader, mut wake) = start_room(repository, short_limit, LOSER, OTHER_DOMAIN);
    let reader_pid = advisory_waiter(pool, pid(&mut blocker).await).await;
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT activity.xact_start < outbox.expires_at AND clock_timestamp() < outbox.expires_at
           FROM pg_stat_activity activity CROSS JOIN s2s_outbox outbox
          WHERE activity.pid=$1 AND outbox.id=$2",
    )
    .bind(reader_pid)
    .bind(expiring)
    .fetch_one(pool)
    .await
    .unwrap());
    wait_for_expiry(pool, expiring).await;
    blocker.rollback().await.unwrap();
    assert_eq!(
        finish(reader).await,
        (Outcome::Queued, vec![vec![archive_id]])
    );
    assert_wakes(&mut wake, 1);
    let initial = outbox(pool).await;
    assert_eq!(initial.len(), 4);
    assert_eq!([initial[0].id, initial[1].id], [expired, expiring]);
    assert_stream(&initial[2..], LOSER, OTHER_DOMAIN, &[archive_id]);
    assert_eq!(generation(pool).await, 4);

    let roomy_limit = FederatedMamOutboxLimits {
        max_rows: 4,
        ..LIMITS
    };
    for (head, expected_outcome, expected_generation) in [
        (initial[2].id, Outcome::Queued, 6),
        (initial[3].id, Outcome::OutboxRejected, 6),
    ] {
        let repository = PostgresMamRepository::new(pool.clone());
        let mut rendered = repository.pause_admission_at(1, AfterRender);
        let (reader, mut wake) = start_room(repository, roomy_limit, LOSER, OTHER_DOMAIN);
        rendered.wait().await;
        let mut blocker = hold_advisory_lock(pool).await;
        let previous_generation: i64 = sqlx::query_scalar(
            "SELECT generation FROM s2s_outbox_enqueue_generation WHERE singleton FOR NO KEY UPDATE",
        )
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
        rendered.release();
        advisory_waiter(pool, pid(&mut blocker).await).await;
        timeout(TIMEOUT, complete_fifo_head(pool, head))
            .await
            .expect("claim or completion took an enqueue lock");
        let swept = timeout(TIMEOUT, expire_s2s_outbox(pool, 10))
            .await
            .expect("expiry sweep took an enqueue lock")
            .unwrap();
        if expected_outcome == Outcome::Queued {
            assert_eq!(swept.len(), 2);
            assert!(swept.iter().any(|row| row.id == expired));
            assert!(swept.iter().any(|row| row.id == expiring));
        } else {
            assert!(swept.is_empty());
        }
        assert_eq!(generation(pool).await, previous_generation);
        blocker.rollback().await.unwrap();
        assert_eq!(
            finish(reader).await,
            (expected_outcome, vec![vec![archive_id]])
        );
        assert_wakes(&mut wake, usize::from(expected_outcome == Outcome::Queued));
        assert_eq!(generation(pool).await, expected_generation);
    }

    let remaining = outbox(pool).await;
    assert_stream(&remaining, LOSER, OTHER_DOMAIN, &[archive_id]);
    assert_eq!(remaining[0].enqueue_sequence, 5);
    assert_eq!(remaining[1].enqueue_sequence, 6);
    let (reader, mut wake) = start_room(
        PostgresMamRepository::new(pool.clone()),
        roomy_limit,
        LOSER,
        OTHER_DOMAIN,
    );
    assert_eq!(
        finish(reader).await,
        (Outcome::Queued, vec![vec![archive_id]])
    );
    assert_wakes(&mut wake, 1);
    let rows = outbox(pool).await;
    assert_eq!(rows.len(), 4);
    assert_eq!(&rows[..2], remaining.as_slice());
    assert_stream(&rows[2..], LOSER, OTHER_DOMAIN, &[archive_id]);
    assert_eq!(generation(pool).await, 8);
    assert_eq!(history_state(pool).await, before_history);
    fixture.cleanup().await;
}
