use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_postgres::mix::*;
use northstar_workflows::room_effects::WorkflowRoomEffects;
use sqlx::PgPool;
use uuid::Uuid;

async fn request(
    pool: &PgPool,
    user: Uuid,
    ordinal: u128,
    leave: bool,
    reject_outbox: bool,
) -> anyhow::Result<PamOperationReplay> {
    let actor = format!("pam-conformance-{ordinal}@example.test");
    let requester = format!("{actor}/phone");
    let channel = "conformance@mix.remote.test";
    let request_id = format!("pam-request-{ordinal}");
    let client_id = format!("pam-client-{ordinal}");
    let stanza = format!(
        "<iq xmlns='jabber:server' type='set' id='{request_id}' from='{actor}' to='{channel}'/>"
    );
    let policy = S2sOutboxPolicy {
        ttl_seconds: 300,
        max_rows: 100,
        max_bytes: if reject_outbox { 1 } else { 1_048_576 },
        max_per_domain: 100,
    };
    if leave {
        begin_remote_pam_leave(
            &WorkflowRoomEffects,
            pool,
            BeginRemotePamLeave {
                user_id: user,
                actor_jid: &actor,
                channel_jid: channel,
                request_id: &request_id,
                client_request_id: &client_id,
                requester_full_jid: &requester,
                request_digest: &[7; 32],
                remote_domain: "mix.remote.test",
                outbound_stanza: &stanza,
                policy,
            },
        )
        .await
    } else {
        begin_remote_pam_join(
            &WorkflowRoomEffects,
            pool,
            BeginRemotePamJoin {
                user_id: user,
                actor_jid: &actor,
                channel_jid: channel,
                nick: Some("Original"),
                nodes: &[],
                request_id: &request_id,
                client_request_id: &client_id,
                requester_full_jid: &requester,
                request_digest: &[7; 32],
                remote_domain: "mix.remote.test",
                outbound_stanza: &stanza,
                policy,
            },
        )
        .await
    }
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn pam_join_and_leave_lock_account_and_capacity_before_business_and_roll_back_both_projections(
) {
    let pool = crate::support::operation_mutation_pool().await;
    for (ordinal, label, leave, reject_outbox) in [
        (0, "join outbox refusal", false, true),
        (1, "leave outbox refusal", true, true),
        (2, "join journal rejection", false, false),
        (3, "leave journal rejection", true, false),
    ] {
        let user = Uuid::from_u128(0x573_200100 + ordinal);
        let membership = Uuid::from_u128(0x573_200200 + ordinal);
        let actor = format!("pam-conformance-{ordinal}@example.test");
        let requester = format!("{actor}/phone");
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user)
            .bind(format!("pam-conformance-{ordinal}"))
            .execute(&pool)
            .await
            .unwrap();
        if leave {
            sqlx::query("INSERT INTO mix_pam_memberships(id,user_id,channel_jid,participant_id,state,nick) VALUES($1,$2,'conformance@mix.remote.test','stable-participant','joined','Original')")
                .bind(membership).bind(user).execute(&pool).await.unwrap();
        }
        if !reject_outbox {
            // A different client operation has already used this remote IQ
            // ID. The new outbox insert succeeds before journal uniqueness
            // rejects the command, so rollback must remove that prefix too.
            sqlx::query(
                "INSERT INTO mix_pam_operations(operation_id,user_id,channel_jid,remote_domain,operation,remote_request_id,client_request_id,requester_full_jid,
                 request_digest,request_outbox_id,deadline_at,expires_at)
                 VALUES($1,$2,'prior@mix.remote.test','mix.remote.test','join',$3,'prior-client',$4,$5,$6,clock_timestamp()+INTERVAL '1 hour',clock_timestamp()+INTERVAL '8 days')",
            ).bind(Uuid::from_u128(0x573_200300 + ordinal)).bind(user).bind(format!("pam-request-{ordinal}"))
                .bind(&requester).bind(vec![8_u8; 32]).bind(Uuid::from_u128(0x573_200400 + ordinal)).execute(&pool).await.unwrap();
        }
        let before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='mix.remote.test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("pam-membership:{user}:conformance@mix.remote.test"))
            .execute(&mut *blocker)
            .await
            .unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let writer_pool = pool.clone();
        let writer = tokio::spawn(async move {
            request(&writer_pool, user, ordinal, leave, reject_outbox).await
        });
        crate::support::blocked_backend(&pool, blocker_pid).await;
        for (lock_label, sql) in [
            ("account before membership", "SELECT id FROM users WHERE id=$1 FOR UPDATE NOWAIT"),
            ("capacity before membership", "SELECT singleton FROM mix_pam_operation_capacity WHERE singleton AND $1::uuid IS NOT NULL FOR UPDATE NOWAIT"),
        ] {
            let mut probe = pool.begin().await.unwrap();
            let result = sqlx::query(sql).bind(user).fetch_one(&mut *probe).await;
            let Err(error) = result else { panic!("{label}: {lock_label} was not held"); };
            assert_eq!(error.as_database_error().and_then(|error| error.code()).as_deref(), Some("55P03"), "{label}: {lock_label}");
            probe.rollback().await.unwrap();
        }
        blocker.rollback().await.unwrap();
        assert!(
            writer.await.unwrap().is_err(),
            "{label}: natural failure was not reached"
        );
        let mut observer = pool.acquire().await.unwrap();
        let membership: Option<(String, Option<String>)> = sqlx::query_as("SELECT state,nick FROM mix_pam_memberships WHERE user_id=$1 AND channel_jid='conformance@mix.remote.test'")
            .bind(user).fetch_optional(&mut *observer).await.unwrap();
        assert_eq!(
            membership,
            leave.then(|| ("joined".into(), Some("Original".into()))),
            "{label}: membership rolled back"
        );
        let operations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mix_pam_operations WHERE user_id=$1 AND client_request_id=$2",
        )
        .bind(user)
        .bind(format!("pam-client-{ordinal}"))
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(operations, 0, "{label}: no partial journal");
        let after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='mix.remote.test'",
        )
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(after, before, "{label}: no partial outbox");
        drop(observer);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}
