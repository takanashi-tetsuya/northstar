use crate::support::delivery::{seed_c2s, seed_mix};
use northstar_delivery_core::{
    sm_ownership::{self as owner, Binding, CommitFact, Knowledge, Observation, Purpose, Scope},
    DurableDelivery, SmUnackedStanza, TransportOwnershipSource as Source,
};
use northstar_workflows::sm::{self as db, SmSessionSnapshot};
use sqlx::{PgConnection, PgPool};
use std::{
    future::Future,
    task::{Context, Poll},
};
use uuid::Uuid;

type QueueRow = (i32, String, Option<Uuid>, Option<Uuid>, Option<Uuid>);

fn snapshot(unacked: Vec<SmUnackedStanza>) -> SmSessionSnapshot {
    SmSessionSnapshot {
        inbound_h: 3,
        outbound_h: 2,
        acked_h: 0,
        available: true,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: None,
        privacy_requested: false,
        peer_ip: "127.0.0.1".parse().unwrap(),
        user_agent_id: None,
        joined_rooms: vec![],
        directed_presence: vec![],
        last_presence: None,
        unacked,
    }
}

fn ack_request(
    session_id: Option<Uuid>,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    acknowledged: &[SmUnackedStanza],
) -> (Observation, owner::Request) {
    let acknowledged = acknowledged
        .iter()
        .map(|entry| entry.source)
        .collect::<Vec<_>>();
    let remaining = snapshot
        .unacked
        .iter()
        .map(|entry| entry.source)
        .collect::<Vec<_>>();
    let whole = acknowledged
        .iter()
        .chain(&remaining)
        .copied()
        .collect::<Vec<_>>();
    let observation = Observation::new(Scope {
        purpose: Purpose::Acknowledge {
            h: snapshot.acked_h,
        },
        session_id,
        connection_id,
        inbound_h: snapshot.inbound_h,
        outbound_h: snapshot.outbound_h,
        acked_h: snapshot
            .acked_h
            .wrapping_sub(u32::try_from(acknowledged.len()).unwrap()),
        queued: whole.len(),
    });
    observation.h_decision(Some(acknowledged.len()));
    let request = observation
        .bind(Binding {
            session_id,
            connection_id,
            inbound_h: snapshot.inbound_h,
            outbound_h: snapshot.outbound_h,
            acked_h: snapshot.acked_h,
            whole,
            acknowledged,
            remaining,
        })
        .unwrap();
    (observation, request)
}

async fn checkpoint_state(
    connection: &mut PgConnection,
    session: Uuid,
    user: Uuid,
    mix: Uuid,
) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
             'session',(SELECT to_jsonb(s) FROM sm_resume_sessions s WHERE id=$1),
             'queue',(SELECT jsonb_agg(to_jsonb(q) ORDER BY position)
                      FROM sm_resume_stanzas q WHERE session_id=$1),
             'offline',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id)
                        FROM offline_messages o WHERE recipient_id=$2),
             'mix',(SELECT to_jsonb(m) FROM mix_delivery_recipients m WHERE delivery_id=$3))",
    )
    .bind(session)
    .bind(user)
    .bind(mix)
    .fetch_one(connection)
    .await
    .unwrap()
}

async fn source_state(connection: &mut PgConnection, user: Uuid, mix: Uuid) -> serde_json::Value {
    sqlx::query_scalar(
        "SELECT jsonb_build_object(
             'offline',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id)
                        FROM offline_messages o WHERE recipient_id=$1),
             'mix',(SELECT to_jsonb(m) FROM mix_delivery_recipients m WHERE delivery_id=$2))",
    )
    .bind(user)
    .bind(mix)
    .fetch_one(connection)
    .await
    .unwrap()
}

async fn cleanup(pool: &PgPool, user: Uuid, event: Uuid) {
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mix_delivery_events WHERE event_id=$1")
        .bind(event)
        .execute(pool)
        .await
        .unwrap();
    northstar_room_postgres::mix::reconcile_mix_delivery_capacity_committed(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn sm_checkpoint_receipts_preserve_atomic_queue() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x581_0400);
    let connection = Uuid::from_u128(0x581_0401);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'sm-receipts','test')")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let c2s = DurableDelivery {
        recipient_id: user,
        message_id: Uuid::from_u128(0x581_0402),
        claim_id: None,
    };
    seed_c2s(&pool, c2s).await;
    let acknowledged =
        SmUnackedStanza::with_source("<message id='acked'/>".into(), Some(Source::C2s(c2s)));
    let plain = SmUnackedStanza::plain("<message id='remaining'/>".into());
    let initial = snapshot(vec![acknowledged.clone(), plain.clone()]);
    let session = db::create_sm_session(
        &pool,
        &[58; 32],
        user,
        0,
        "sm-receipts@example.test/device",
        "device",
        "example.test",
        connection,
        &initial,
        300,
        300,
        8,
        64,
    )
    .await
    .unwrap();
    let (event, mix) = seed_mix(&pool, 0x581_0410).await;
    let mix_entry =
        SmUnackedStanza::with_source("<message id='mix'/>".into(), Some(Source::Mix(mix)));
    let mut next = initial.clone();
    next.outbound_h = 3;
    next.acked_h = 1;
    next.unacked = vec![plain.clone(), mix_entry];
    let mut observer = pool.acquire().await.unwrap();
    let before = checkpoint_state(&mut observer, session, user, mix.delivery_id).await;

    for label in ["changed binding", "invalid snapshot", "retired turn"] {
        let (observation, request) = ack_request(
            Some(session),
            connection,
            &next,
            std::slice::from_ref(&acknowledged),
        );
        let mut invalid = next.clone();
        if label == "changed binding" {
            invalid.inbound_h += 1;
        } else if label == "invalid snapshot" {
            invalid.last_presence = Some(String::new());
        } else {
            observation.retire(owner::Terminal::Cancelled);
        }
        // With every connection held, reaching BEGIN would suspend. Validation
        // must return its specific error on the very first manual poll.
        let held = [
            pool.acquire().await.unwrap(),
            pool.acquire().await.unwrap(),
            pool.acquire().await.unwrap(),
        ];
        let result = {
            let mut call = Box::pin(db::checkpoint_sm_session_and_acknowledge_observed(
                &pool,
                session,
                connection,
                &invalid,
                std::slice::from_ref(&acknowledged),
                300,
                300,
                64,
                65_536,
                Some(&request),
            ));
            let Poll::Ready(result) = call
                .as_mut()
                .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
            else {
                panic!("{label}: attempted database access before validation");
            };
            result
        };
        drop(held);
        let Err(error) = result else {
            panic!("{label}: invalid checkpoint succeeded");
        };
        assert!(
            error.to_string().contains(if label == "changed binding" {
                "SM database projection changed its bound cut"
            } else if label == "invalid snapshot" {
                "SM last-presence snapshot is invalid or too large"
            } else {
                "Retired"
            }),
            "{label}: {error:#}"
        );
        assert_eq!(
            observation.snapshot().knowledge,
            Knowledge::NoCommitRequested,
            "{label}"
        );
        assert_eq!(
            checkpoint_state(&mut observer, session, user, mix.delivery_id).await,
            before,
            "{label}: unchanged database"
        );
    }
    for label in ["stale connection", "queue transfer refused"] {
        let supplied_connection = if label == "stale connection" {
            Uuid::from_u128(0x581_0499)
        } else {
            connection
        };
        let mut supplied = next.clone();
        if label == "queue transfer refused" {
            supplied.unacked[1].source = Some(Source::Mix(northstar_delivery_core::MixDelivery {
                lease_token: Uuid::from_u128(0x581_0498),
                ..mix
            }));
        }
        let (observation, request) = ack_request(
            Some(session),
            supplied_connection,
            &supplied,
            std::slice::from_ref(&acknowledged),
        );
        let result = db::checkpoint_sm_session_and_acknowledge_observed(
            &pool,
            session,
            supplied_connection,
            &supplied,
            std::slice::from_ref(&acknowledged),
            300,
            300,
            64,
            65_536,
            Some(&request),
        )
        .await;
        if label == "stale connection" {
            let outcome = result.unwrap();
            assert!(!outcome.updated, "{label}");
            assert!(outcome.ownership.mix_rotations.is_empty(), "{label}");
            assert_eq!(
                observation.snapshot().knowledge,
                Knowledge::RollbackKnown,
                "{label}"
            );
            request.validate_checkpoint_return(false, &[]).unwrap();
            assert_eq!(
                observation.snapshot().returned_updated,
                Some(false),
                "{label}"
            );
        } else {
            let Err(error) = result else {
                panic!("{label}: stale MIX capability was accepted");
            };
            assert!(
                error
                    .to_string()
                    .contains("MIX delivery lease changed before SM ownership transfer"),
                "{label}: {error:#}"
            );
            assert_eq!(
                observation.snapshot().knowledge,
                Knowledge::NoCommitRequested,
                "{label}"
            );
        }
        assert_eq!(
            checkpoint_state(&mut observer, session, user, mix.delivery_id).await,
            before,
            "{label}: transaction rolled back"
        );
    }
    let (observation, request) = ack_request(
        Some(session),
        connection,
        &next,
        std::slice::from_ref(&acknowledged),
    );
    let outcome = db::checkpoint_sm_session_and_acknowledge_observed(
        &pool,
        session,
        connection,
        &next,
        std::slice::from_ref(&acknowledged),
        300,
        300,
        64,
        65_536,
        Some(&request),
    )
    .await
    .unwrap();
    assert!(outcome.updated);
    assert_eq!(outcome.ownership.mix_rotations.len(), 1);
    let rotation = outcome.ownership.mix_rotations[0];
    assert_eq!(rotation.previous, mix);
    assert_eq!(rotation.current.delivery_id, mix.delivery_id);
    let rotations = vec![owner::MixRotation {
        previous: mix,
        current: rotation.current,
    }];
    let Knowledge::ReceiptKnown(fact) = observation.snapshot().knowledge else {
        panic!("checkpoint returned without its COMMIT receipt");
    };
    assert_eq!(
        *fact,
        CommitFact::Checkpoint {
            rotations: rotations.clone(),
            settled: vec![Source::C2s(c2s)]
        }
    );
    request
        .validate_checkpoint_return(true, &rotations)
        .unwrap();
    assert_eq!(observation.snapshot().returned_updated, Some(true));
    let counters: (i64, i64, i64) =
        sqlx::query_as("SELECT inbound_h,outbound_h,acked_h FROM sm_resume_sessions WHERE id=$1")
            .bind(session)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert_eq!(counters, (3, 3, 1));
    let queue: Vec<QueueRow> = sqlx::query_as(
        "SELECT position,stanza,delivery_message_id,mix_delivery_id,mix_delivery_lease_token
         FROM sm_resume_stanzas WHERE session_id=$1 ORDER BY position",
    )
    .bind(session)
    .fetch_all(&mut *observer)
    .await
    .unwrap();
    assert_eq!(
        queue,
        vec![
            (0, plain.stanza, None, None, None),
            (
                1,
                next.unacked[1].stanza.clone(),
                None,
                Some(mix.delivery_id),
                Some(rotation.current.lease_token)
            ),
        ]
    );
    let token: Uuid =
        sqlx::query_scalar("SELECT lease_token FROM mix_delivery_recipients WHERE delivery_id=$1")
            .bind(mix.delivery_id)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert_eq!(token, rotation.current.lease_token);
    let offline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
        .bind(c2s.message_id)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    assert_eq!(
        offline, 0,
        "settled C2S source deleted in the checkpoint transaction"
    );
    drop(observer);
    cleanup(&pool, user, event).await;
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn unpersisted_sm_ack_receipts_bind_the_batch() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x581_0500);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'sm-batch-receipts','test')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let c2s = DurableDelivery {
        recipient_id: user,
        message_id: Uuid::from_u128(0x581_0501),
        claim_id: None,
    };
    let absent = DurableDelivery {
        message_id: Uuid::from_u128(0x581_0502),
        ..c2s
    };
    seed_c2s(&pool, c2s).await;
    let (event, mix) = seed_mix(&pool, 0x581_0510).await;
    let mut observer = pool.acquire().await.unwrap();
    let before = source_state(&mut observer, user, mix.delivery_id).await;
    let mut empty = snapshot(vec![]);
    empty.outbound_h = 1;
    empty.acked_h = 1;
    let plain = SmUnackedStanza::plain("<message/>".into());
    let (observation, request) = ack_request(None, Uuid::from_u128(0x581_0503), &empty, &[plain]);
    let held = [
        pool.acquire().await.unwrap(),
        pool.acquire().await.unwrap(),
        pool.acquire().await.unwrap(),
    ];
    {
        let mut call = Box::pin(db::acknowledge_transport_sources_observed(
            &pool,
            &[],
            Some(&request),
        ));
        let Poll::Ready(result) = call
            .as_mut()
            .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
        else {
            panic!("empty source batch tried to acquire a transaction");
        };
        result.unwrap();
    }
    drop(held);
    assert_eq!(observation.snapshot().knowledge, Knowledge::NoPersistence);
    request.validate_batch_return().unwrap();
    assert_eq!(
        source_state(&mut observer, user, mix.delivery_id).await,
        before
    );

    for (label, stale) in [
        ("stale mixed batch", true),
        ("committed mixed batch", false),
    ] {
        let supplied_mix = if stale {
            northstar_delivery_core::MixDelivery {
                lease_token: Uuid::from_u128(0x581_0599),
                ..mix
            }
        } else {
            mix
        };
        // Deliberately put MIX first: the database receipt records its global
        // C2S-then-MIX lock/deletion order, rather than copying the input list.
        let sources = [
            Source::Mix(supplied_mix),
            Source::C2s(absent),
            Source::C2s(c2s),
        ];
        let entries = sources
            .iter()
            .map(|source| SmUnackedStanza::with_source("<message/>".into(), Some(*source)))
            .collect::<Vec<_>>();
        let mut cut = snapshot(vec![]);
        cut.outbound_h = 3;
        cut.acked_h = 3;
        let (observation, request) = ack_request(None, Uuid::from_u128(0x581_0503), &cut, &entries);
        let result =
            db::acknowledge_transport_sources_observed(&pool, &sources, Some(&request)).await;
        if stale {
            let Err(error) = result else {
                panic!("{label}: stale MIX lease was accepted");
            };
            assert!(
                error
                    .to_string()
                    .contains("MIX delivery lease was lost before acknowledgement"),
                "{label}: {error:#}"
            );
            assert_eq!(
                observation.snapshot().knowledge,
                Knowledge::NoCommitRequested,
                "{label}"
            );
            assert_eq!(
                source_state(&mut observer, user, mix.delivery_id).await,
                before,
                "{label}: no partial deletion"
            );
        } else {
            result.unwrap();
            let Knowledge::ReceiptKnown(fact) = observation.snapshot().knowledge else {
                panic!("{label}: missing COMMIT receipt");
            };
            assert_eq!(
                *fact,
                CommitFact::UnpersistedAck {
                    deleted: vec![Source::C2s(c2s), Source::Mix(mix)],
                    absent_unclaimed: vec![absent],
                },
                "{label}"
            );
            request.validate_batch_return().unwrap();
            assert_eq!(
                observation.snapshot().summary().committed_settled,
                Some(2),
                "{label}"
            );
            assert_eq!(
                observation.snapshot().summary().committed_absent_unclaimed,
                Some(1),
                "{label}"
            );
            assert_eq!(
                source_state(&mut observer, user, mix.delivery_id).await,
                serde_json::json!({"offline": null, "mix": null}),
                "{label}"
            );
        }
    }
    drop(observer);
    cleanup(&pool, user, event).await;
    pool.close().await;
}
