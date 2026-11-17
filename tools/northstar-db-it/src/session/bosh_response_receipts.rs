use crate::support::delivery::{bosh_bind, bosh_operation, seed_c2s, seed_mix};
use chrono::{DateTime, TimeDelta, Utc};
use northstar_delivery_core::{
    bosh_ownership::{
        response::{self, BindKnowledge, BoshResponseOwnership, DeletedSource, Knowledge},
        Operation,
    },
    DurableDelivery, MixDelivery, TransportOwnershipSource as Source,
};
use northstar_session_application::replay::ReplayRepository;
use northstar_session_postgres::{replay as db, replay_repository::PostgresReplayRepository};
use sqlx::{PgConnection, PgPool};
use std::sync::Arc;
use uuid::Uuid;

async fn pair(
    pool: &PgPool,
    user: Uuid,
    session: Uuid,
    base: u128,
) -> (Uuid, DurableDelivery, MixDelivery) {
    let c2s = DurableDelivery {
        recipient_id: user,
        message_id: Uuid::from_u128(base + 5),
        claim_id: Some(Uuid::from_u128(base + 6)),
    };
    seed_c2s(pool, c2s).await;
    let (event, source) = seed_mix(pool, base).await;
    let operation = bosh_operation(session, 240);
    let request = operation.begin_transfer(source).unwrap();
    let current = northstar_room_postgres::mix::transfer_mix_delivery_to_bosh(pool, &request)
        .await
        .unwrap();
    request.returned(current).unwrap();
    (event, c2s, current)
}

async fn bind_pair(
    repository: &PostgresReplayRepository,
    session: Uuid,
    rid: u64,
    c2s: DurableDelivery,
    mix: MixDelivery,
) -> BoshResponseOwnership {
    let operation = bosh_operation(session, 180);
    let request = bosh_bind(&operation, rid, vec![Source::Mix(mix), Source::C2s(c2s)]);
    let ownership = repository
        .bind_bosh_response_sources(&request)
        .await
        .unwrap();
    request.returned(ownership.clone()).unwrap();
    ownership
}

async fn prepare_ack(
    repository: &PostgresReplayRepository,
    session: Uuid,
    rid: u64,
) -> (Operation, response::AckRequest) {
    let operation = bosh_operation(session, 180);
    let renewal = operation.begin_renew(None).unwrap();
    repository.renew_bosh_fences(&renewal).await.unwrap();
    let request = renewal.returned().unwrap().begin_ack(rid).unwrap();
    (operation, request)
}

async fn state(connection: &mut PgConnection, user: Uuid, mix_ids: &[Uuid]) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
             'offline',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id)
                        FROM offline_messages o WHERE recipient_id=$1),
             'c2s_fences',(SELECT jsonb_agg(to_jsonb(f) ORDER BY message_id)
                           FROM bosh_delivery_fences f WHERE recipient_id=$1),
             'mix',(SELECT jsonb_agg(to_jsonb(m) ORDER BY delivery_id)
                    FROM mix_delivery_recipients m WHERE delivery_id=ANY($2)),
             'mix_fences',(SELECT jsonb_agg(to_jsonb(f) ORDER BY delivery_id)
                           FROM mix_bosh_delivery_fences f WHERE delivery_id=ANY($2)))",
    )
    .bind(user)
    .bind(mix_ids)
    .fetch_one(connection)
    .await
    .unwrap()
}

async fn cleanup(pool: &PgPool, user: Uuid, events: &[Uuid]) {
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mix_delivery_events WHERE event_id=ANY($1)")
        .bind(events)
        .execute(pool)
        .await
        .unwrap();
    northstar_room_postgres::mix::reconcile_mix_delivery_capacity_committed(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn bosh_bind_receipts_match_exact_membership() {
    let pool = crate::support::operation_mutation_pool().await;
    let repository = PostgresReplayRepository::new(pool.clone());
    let user = Uuid::from_u128(0x581_0600);
    let session = Uuid::from_u128(0x581_0601);
    let other_session = Uuid::from_u128(0x581_0602);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'bosh-bind-receipts','test')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let (event, c2s, mix) = pair(&pool, user, session, 0x581_0610).await;
    let second_c2s = DurableDelivery {
        message_id: Uuid::from_u128(0x581_0620),
        claim_id: Some(Uuid::from_u128(0x581_0621)),
        ..c2s
    };
    seed_c2s(&pool, second_c2s).await;
    let sources = vec![Source::Mix(mix), Source::C2s(second_c2s), Source::C2s(c2s)];
    let mut observer = pool.acquire().await.unwrap();
    let before = state(&mut observer, user, &[mix.delivery_id]).await;
    for (label, rid, retired) in [
        ("foreign pending owner", 101, false),
        ("retired request", 101, true),
        ("RID exceeds bigint", u64::MAX, false),
    ] {
        let operation = bosh_operation(
            if rid == u64::MAX {
                session
            } else {
                other_session
            },
            73,
        );
        let request = bosh_bind(&operation, rid, sources.clone());
        if retired {
            operation.retire(northstar_delivery_core::bosh_ownership::Terminal::Cancelled);
        }
        let Err(error) = repository.bind_bosh_response_sources(&request).await else {
            panic!("{label}: invalid response binding succeeded");
        };
        assert!(
            error.to_string().contains(if retired {
                "Retired"
            } else if rid == u64::MAX {
                "BOSH RID exceeds bigint"
            } else {
                "MIX BOSH response fence is owned by another transport"
            }),
            "{label}: {error:#}"
        );
        assert_eq!(
            operation.snapshot().responses[0].attempts[0].knowledge,
            BindKnowledge::NoCommitRequested,
            "{label}"
        );
        assert_eq!(
            state(&mut observer, user, &[mix.delivery_id]).await,
            before,
            "{label}: claims and pending fence rolled back"
        );
    }
    sqlx::query(
        "CREATE FUNCTION hold_bosh_bind_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_advisory_xact_lock(5810600::bigint); RETURN NEW; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE CONSTRAINT TRIGGER hold_bosh_bind_receipt
         AFTER INSERT ON bosh_delivery_fences DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW WHEN (NEW.session_id='{session}'::uuid)
         EXECUTE FUNCTION hold_bosh_bind_receipt()",
    )))
    .execute(&pool)
    .await
    .unwrap();
    let operation = bosh_operation(session, 73);
    let request = bosh_bind(&operation, 101, sources.clone());
    assert_eq!(request.session_id(), session);
    assert_eq!(request.rid(), 101);
    assert_eq!(request.sources(), sources);
    assert_eq!(request.ttl_seconds(), 73);
    let expected = BoshResponseOwnership {
        c2s_message_ids: vec![c2s.message_id, second_c2s.message_id],
        mix_delivery_ids: vec![mix.delivery_id],
    };
    let started: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5810600::bigint)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let worker_repository = repository.clone();
    let binding = tokio::spawn(async move {
        let result = worker_repository.bind_bosh_response_sources(&request).await;
        (request, result)
    });
    assert_ne!(
        crate::support::blocked_backend(&pool, blocker_pid).await,
        observer_pid
    );
    assert_eq!(
        operation.snapshot().responses[0].attempts[0].knowledge,
        BindKnowledge::CommitCallEntered(Arc::new(expected.clone()))
    );
    assert_eq!(
        state(&mut observer, user, &[mix.delivery_id]).await,
        before,
        "pending COMMIT has no visible bindings"
    );
    blocker.rollback().await.unwrap();
    let (request, result) = binding.await.unwrap();
    let ownership = result.unwrap();
    assert_eq!(ownership, expected);
    assert_eq!(
        operation.snapshot().responses[0].attempts[0].knowledge,
        BindKnowledge::ReceiptKnown(Arc::new(expected.clone()))
    );
    let finished: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let fences: Vec<(Uuid, Uuid, i64, DateTime<Utc>)> = sqlx::query_as(
        "SELECT message_id,session_id,response_rid,expires_at FROM bosh_delivery_fences
         WHERE recipient_id=$1 ORDER BY message_id",
    )
    .bind(user)
    .fetch_all(&mut *observer)
    .await
    .unwrap();
    assert_eq!(fences.len(), 2);
    for (row, expected_id) in fences.iter().zip(&expected.c2s_message_ids) {
        assert_eq!((row.0, row.1, row.2), (*expected_id, session, 101));
        assert!(
            row.3 >= started + TimeDelta::seconds(73) && row.3 <= finished + TimeDelta::seconds(73)
        );
    }
    let claims: Vec<Option<Uuid>> = sqlx::query_scalar(
        "SELECT delivery_claim_id FROM offline_messages WHERE recipient_id=$1 ORDER BY id",
    )
    .bind(user)
    .fetch_all(&mut *observer)
    .await
    .unwrap();
    assert_eq!(claims, vec![None, None]);
    let bound: (Uuid, Uuid, i64, bool, DateTime<Utc>) = sqlx::query_as(
        "SELECT session_id,lease_token,response_rid,bound_at IS NOT NULL,expires_at
         FROM mix_bosh_delivery_fences WHERE delivery_id=$1",
    )
    .bind(mix.delivery_id)
    .fetch_one(&mut *observer)
    .await
    .unwrap();
    assert_eq!(
        (bound.0, bound.1, bound.2, bound.3),
        (session, mix.lease_token, 101, true)
    );
    assert!(
        bound.4 >= started + TimeDelta::seconds(73) && bound.4 <= finished + TimeDelta::seconds(73)
    );
    let committed = state(&mut observer, user, &[mix.delivery_id]).await;
    let Err(error) = repository.bind_bosh_response_sources(&request).await else {
        panic!("already committed request was reused");
    };
    assert!(error.to_string().contains("State"));
    assert_eq!(
        state(&mut observer, user, &[mix.delivery_id]).await,
        committed
    );
    let bound_response = request.returned(ownership).unwrap();
    assert_eq!(bound_response.ownership().as_ref(), &expected);
    assert!(operation.snapshot().responses[0].attempts[0].return_matches);
    drop(observer);
    sqlx::query("DROP TRIGGER hold_bosh_bind_receipt ON bosh_delivery_fences")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION hold_bosh_bind_receipt()")
        .execute(&pool)
        .await
        .unwrap();
    cleanup(&pool, user, &[event]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn bosh_renew_receipts_validate_cached_membership() {
    let pool = crate::support::operation_mutation_pool().await;
    let repository = PostgresReplayRepository::new(pool.clone());
    let user = Uuid::from_u128(0x581_0700);
    let session = Uuid::from_u128(0x581_0701);
    let other_session = Uuid::from_u128(0x581_0702);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'bosh-renew-receipts','test')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let (event, c2s, mix) = pair(&pool, user, session, 0x581_0710).await;
    let expected = bind_pair(&repository, session, 201, c2s, mix).await;
    let (other_event, other_c2s, other_mix) = pair(&pool, user, other_session, 0x581_0720).await;
    bind_pair(&repository, other_session, 201, other_c2s, other_mix).await;
    let (sibling_event, sibling_c2s, sibling_mix) = pair(&pool, user, session, 0x581_0730).await;
    bind_pair(&repository, session, 202, sibling_c2s, sibling_mix).await;
    let ids = [
        mix.delivery_id,
        other_mix.delivery_id,
        sibling_mix.delivery_id,
    ];
    let mut observer = pool.acquire().await.unwrap();
    let before = state(&mut observer, user, &ids).await;
    for label in ["wrong cached RID", "missing cached C2S", "extra cached MIX"] {
        let mut supplied = expected.clone();
        let rid = if label == "wrong cached RID" {
            202
        } else {
            201
        };
        if label == "missing cached C2S" {
            supplied.c2s_message_ids.clear();
        }
        if label == "extra cached MIX" {
            supplied.mix_delivery_ids.push(other_mix.delivery_id);
        }
        let operation = bosh_operation(session, 83);
        let request = operation
            .begin_renew(Some((rid, Arc::new(supplied.clone()))))
            .unwrap();
        let Err(error) = repository.renew_bosh_fences(&request).await else {
            panic!("{label}: mismatched membership was renewed");
        };
        assert!(
            error.to_string().contains(
                "cached BOSH response no longer owns its exact durable transport sources"
            ),
            "{label}: {error:#}"
        );
        assert_eq!(
            operation.snapshot().renewals[0].knowledge,
            Knowledge::NoCommitRequested,
            "{label}"
        );
        assert_eq!(
            operation.snapshot().renewals[0].expected,
            Some((rid, Arc::new(supplied))),
            "{label}"
        );
        assert_eq!(
            state(&mut observer, user, &ids).await,
            before,
            "{label}: rollback"
        );
    }
    sqlx::query(
        "CREATE FUNCTION hold_bosh_renew_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN PERFORM pg_advisory_xact_lock(5810700::bigint); RETURN NEW; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE CONSTRAINT TRIGGER hold_bosh_renew_receipt
         AFTER UPDATE ON bosh_delivery_fences DEFERRABLE INITIALLY DEFERRED
         FOR EACH ROW WHEN (NEW.session_id='{session}'::uuid)
         EXECUTE FUNCTION hold_bosh_renew_receipt()",
    )))
    .execute(&pool)
    .await
    .unwrap();
    let operation = bosh_operation(session, 83);
    let request = operation
        .begin_renew(Some((201, Arc::new(expected.clone()))))
        .unwrap();
    let started: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5810700::bigint)")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let observer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let worker_repository = repository.clone();
    let renewing = tokio::spawn(async move {
        let result = worker_repository.renew_bosh_fences(&request).await;
        (request, result)
    });
    assert_ne!(
        crate::support::blocked_backend(&pool, blocker_pid).await,
        observer_pid
    );
    assert_eq!(
        operation.snapshot().renewals[0].knowledge,
        Knowledge::CommitCallEntered
    );
    assert_eq!(
        state(&mut observer, user, &ids).await,
        before,
        "pending renewal is not visible"
    );
    blocker.rollback().await.unwrap();
    let (request, result) = renewing.await.unwrap();
    result.unwrap();
    assert_eq!(
        operation.snapshot().renewals[0].knowledge,
        Knowledge::ReceiptKnown
    );
    assert_eq!(
        operation.snapshot().renewals[0].expected,
        Some((201, Arc::new(expected)))
    );
    request.returned().unwrap();
    assert!(operation.snapshot().renewals[0].return_matches);
    let finished: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    let expiries: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT message_id,expires_at FROM bosh_delivery_fences WHERE recipient_id=$1
         UNION ALL SELECT delivery_id,expires_at FROM mix_bosh_delivery_fences WHERE delivery_id=ANY($2)",
    ).bind(user).bind(ids).fetch_all(&mut *observer).await.unwrap();
    assert_eq!(expiries.len(), 6);
    for (id, deadline) in expiries {
        // The current adapter validates one cached response, then renews the
        // whole session, including its other cached response.
        if [
            c2s.message_id,
            mix.delivery_id,
            sibling_c2s.message_id,
            sibling_mix.delivery_id,
        ]
        .contains(&id)
        {
            assert!(
                deadline >= started + TimeDelta::seconds(83)
                    && deadline <= finished + TimeDelta::seconds(83)
            );
        }
    }
    let after = state(&mut observer, user, &ids).await;
    // Full row equality proves that another actor's matching RID was not renewed.
    for key in ["c2s_fences", "mix_fences"] {
        let find = |value: &serde_json::Value| {
            value[key]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["session_id"] == other_session.to_string())
                .unwrap()
                .clone()
        };
        assert_eq!(
            find(&after),
            find(&before),
            "{key}: independent actor unchanged"
        );
    }
    assert_eq!(after["offline"], before["offline"]);
    assert_eq!(after["mix"], before["mix"]);
    drop(observer);
    sqlx::query("DROP TRIGGER hold_bosh_renew_receipt ON bosh_delivery_fences")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION hold_bosh_renew_receipt()")
        .execute(&pool)
        .await
        .unwrap();
    cleanup(&pool, user, &[event, other_event, sibling_event]).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn bosh_ack_receipts_count_committed_sources() {
    let pool = crate::support::operation_mutation_pool().await;
    let repository = PostgresReplayRepository::new(pool.clone());
    let user = Uuid::from_u128(0x581_0800);
    let session = Uuid::from_u128(0x581_0801);
    let other_session = Uuid::from_u128(0x581_0802);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'bosh-ack-receipts','test')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let (event, c2s, mix) = pair(&pool, user, session, 0x581_0810).await;
    bind_pair(&repository, session, 301, c2s, mix).await;
    let (later_event, later_c2s, later_mix) = pair(&pool, user, session, 0x581_0820).await;
    bind_pair(&repository, session, 302, later_c2s, later_mix).await;
    let (other_event, other_c2s, other_mix) = pair(&pool, user, other_session, 0x581_0830).await;
    bind_pair(&repository, other_session, 300, other_c2s, other_mix).await;
    let ids = [
        mix.delivery_id,
        later_mix.delivery_id,
        other_mix.delivery_id,
    ];
    sqlx::query(
        "CREATE TABLE bosh_ack_receipt_guard(message_id uuid PRIMARY KEY
             REFERENCES offline_messages(id) DEFERRABLE INITIALLY DEFERRED)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut observer = pool.acquire().await.unwrap();
    let expected_deleted = vec![
        DeletedSource::C2s {
            recipient_id: user,
            message_id: c2s.message_id,
        },
        DeletedSource::Mix(mix),
    ];
    for (label, stale) in [("replaced MIX lease", true), ("COMMIT rejected", false)] {
        let (operation, request) = prepare_ack(&repository, session, 301).await;
        if stale {
            sqlx::query("UPDATE mix_delivery_recipients SET lease_token=$2 WHERE delivery_id=$1")
                .bind(mix.delivery_id)
                .bind(Uuid::from_u128(0x581_0899))
                .execute(&pool)
                .await
                .unwrap();
        } else {
            sqlx::query("INSERT INTO bosh_ack_receipt_guard VALUES($1)")
                .bind(c2s.message_id)
                .execute(&pool)
                .await
                .unwrap();
        }
        let before = state(&mut observer, user, &ids).await;
        let Err(error) = repository.acknowledge_bosh_responses(&request).await else {
            panic!("{label}: invalid ACK committed");
        };
        assert!(
            format!("{error:#}").contains(if stale {
                "MIX BOSH-owned delivery lease changed before acknowledgement"
            } else {
                "bosh_ack_receipt_guard"
            }),
            "{label}: {error:#}"
        );
        let ack = &operation.snapshot().acknowledgements[0];
        assert_eq!(ack.rid, 301, "{label}");
        assert_eq!(
            ack.knowledge,
            if stale {
                Knowledge::NoCommitRequested
            } else {
                Knowledge::CommitCallEntered
            },
            "{label}"
        );
        assert_eq!(
            ack.deleted.as_deref(),
            if stale { None } else { Some(&expected_deleted) },
            "{label}"
        );
        assert_eq!(
            state(&mut observer, user, &ids).await,
            before,
            "{label}: C2S deletion and fences rolled back"
        );
        if stale {
            sqlx::query("UPDATE mix_delivery_recipients SET lease_token=$2 WHERE delivery_id=$1")
                .bind(mix.delivery_id)
                .bind(mix.lease_token)
                .execute(&pool)
                .await
                .unwrap();
        } else {
            sqlx::query("DELETE FROM bosh_ack_receipt_guard")
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    let (operation, request) = prepare_ack(&repository, session, 301).await;
    let count = db::acknowledge_bosh_transport_responses(&pool, &request)
        .await
        .unwrap();
    assert_eq!(
        count, 2,
        "one C2S and one MIX source through the acknowledged RID"
    );
    let ack = &operation.snapshot().acknowledgements[0];
    assert_eq!(ack.knowledge, Knowledge::ReceiptKnown);
    assert_eq!(ack.deleted.as_deref(), Some(&expected_deleted));
    request.returned().unwrap();
    assert!(operation.snapshot().acknowledgements[0].return_matches);
    let remaining: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM offline_messages WHERE recipient_id=$1 ORDER BY id")
            .bind(user)
            .fetch_all(&mut *observer)
            .await
            .unwrap();
    assert_eq!(remaining, vec![later_c2s.message_id, other_c2s.message_id]);
    let mix_remaining: Vec<Uuid> = sqlx::query_scalar("SELECT delivery_id FROM mix_delivery_recipients WHERE delivery_id=ANY($1) ORDER BY delivery_id")
        .bind(ids).fetch_all(&mut *observer).await.unwrap();
    assert_eq!(
        mix_remaining,
        vec![later_mix.delivery_id, other_mix.delivery_id]
    );
    let c2s_fences: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT message_id,session_id,response_rid FROM bosh_delivery_fences WHERE recipient_id=$1 ORDER BY message_id",
    ).bind(user).fetch_all(&mut *observer).await.unwrap();
    assert_eq!(
        c2s_fences,
        vec![
            (later_c2s.message_id, session, 302),
            (other_c2s.message_id, other_session, 300)
        ]
    );
    let mix_fences: Vec<(Uuid, Uuid, i64)> = sqlx::query_as(
        "SELECT delivery_id,session_id,response_rid FROM mix_bosh_delivery_fences WHERE delivery_id=ANY($1) ORDER BY delivery_id",
    ).bind(ids).fetch_all(&mut *observer).await.unwrap();
    assert_eq!(
        mix_fences,
        vec![
            (later_mix.delivery_id, session, 302),
            (other_mix.delivery_id, other_session, 300)
        ]
    );

    for (label, rid, deleted) in [
        ("repeated ACK", 301, vec![]),
        (
            "repository ACK of later response",
            302,
            vec![
                DeletedSource::C2s {
                    recipient_id: user,
                    message_id: later_c2s.message_id,
                },
                DeletedSource::Mix(later_mix),
            ],
        ),
    ] {
        let (operation, request) = prepare_ack(&repository, session, rid).await;
        let before = state(&mut observer, user, &ids).await;
        if deleted.is_empty() {
            let count = db::acknowledge_bosh_transport_responses(&pool, &request)
                .await
                .unwrap();
            assert_eq!(count, 0, "{label}: no sources deleted twice");
        } else {
            repository
                .acknowledge_bosh_responses(&request)
                .await
                .unwrap();
        }
        let ack = &operation.snapshot().acknowledgements[0];
        assert_eq!(ack.knowledge, Knowledge::ReceiptKnown, "{label}");
        assert_eq!(ack.deleted.as_deref(), Some(&deleted), "{label}");
        request.returned().unwrap();
        let after = state(&mut observer, user, &ids).await;
        if deleted.is_empty() {
            assert_eq!(after, before, "{label}: committed empty deletion");
        } else {
            let remaining: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM offline_messages WHERE recipient_id=$1 ORDER BY id",
            )
            .bind(user)
            .fetch_all(&mut *observer)
            .await
            .unwrap();
            assert_eq!(remaining, vec![other_c2s.message_id], "{label}");
            let remaining: Vec<Uuid> = sqlx::query_scalar("SELECT delivery_id FROM mix_delivery_recipients WHERE delivery_id=ANY($1) ORDER BY delivery_id")
                .bind(ids).fetch_all(&mut *observer).await.unwrap();
            assert_eq!(remaining, vec![other_mix.delivery_id], "{label}");
        }
    }
    drop(observer);
    sqlx::query("DROP TABLE bosh_ack_receipt_guard")
        .execute(&pool)
        .await
        .unwrap();
    cleanup(&pool, user, &[event, later_event, other_event]).await;
    pool.close().await;
}
