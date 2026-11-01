use northstar_room_postgres::cluster_muc::*;
use serde_json::Value;
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses connection-local temporary tables"]
async fn postgres_outbox_maintenance_is_atomic_and_snapshot_is_complete() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .max_lifetime(None)
        .idle_timeout(None)
        .after_connect(|connection, _| {
            Box::pin(async move {
                // A replacement connection must fail on absent temporary
                // tables, never resolve an application's persistent tables.
                sqlx::query("SET search_path TO pg_temp, pg_catalog")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    // Exercise the production queries and PostgreSQL statement rollback.
    // Full deployment capacity/authority triggers remain covered by the
    // migrated-schema cluster fixture, not these minimal temporary tables.
    sqlx::raw_sql(
        "CREATE TEMP TABLE cluster_muc_event_outbox (
             delivery_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
             operation_id UUID NOT NULL DEFAULT gen_random_uuid(),
             room_id UUID NOT NULL DEFAULT gen_random_uuid(),
             room_epoch UUID NOT NULL DEFAULT gen_random_uuid(),
             event_sequence BIGINT NOT NULL DEFAULT 1,
             event_id UUID NOT NULL DEFAULT gen_random_uuid(),
             target_node_id TEXT NOT NULL DEFAULT 'test-node',
             recipient_occupant_incarnation UUID NOT NULL DEFAULT gen_random_uuid(),
             payload_digest BYTEA NOT NULL DEFAULT decode(repeat('00',32),'hex'),
             capacity_shard INTEGER NOT NULL DEFAULT 0,
             attempt_count INTEGER NOT NULL DEFAULT 0,
             created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()-INTERVAL '1 minute',
             expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+INTERVAL '1 hour',
             claim_token UUID,
             lease_until TIMESTAMPTZ
         );
         CREATE TEMP TABLE cluster_muc_event_dead_letters AS
             SELECT delivery_id,operation_id,room_id,room_epoch,event_sequence,event_id,
                    target_node_id,recipient_occupant_incarnation,payload_digest,
                    capacity_shard,attempt_count,''::TEXT AS terminal_reason,created_at
               FROM cluster_muc_event_outbox WITH NO DATA;
         ALTER TABLE cluster_muc_event_dead_letters ADD PRIMARY KEY(delivery_id);
         ALTER TABLE cluster_muc_event_dead_letters ADD CONSTRAINT reject_expired
             CHECK (terminal_reason <> 'expired');",
    )
    .execute(&pool)
    .await
    .unwrap();

    let empty = cluster_muc_outbox_snapshot(&pool).await.unwrap();
    assert_eq!(empty.queued_rows, 0);
    assert_eq!(empty.expired_rows, 0);
    assert_eq!(empty.claimed_rows, 0);
    assert_eq!(empty.dead_letter_rows, 0);
    assert_eq!(empty.oldest_age_seconds, 0);
    assert_eq!(
        dead_letter_expired_cluster_muc_outbox(&pool, 10)
            .await
            .unwrap(),
        0
    );

    sqlx::query(
        "INSERT INTO cluster_muc_event_outbox(expires_at,attempt_count,claim_token,lease_until)
         VALUES (clock_timestamp()-INTERVAL '1 minute',0,NULL,NULL),
                (clock_timestamp()+INTERVAL '1 hour',16,NULL,NULL),
                (clock_timestamp()+INTERVAL '1 hour',0,gen_random_uuid(),
                 clock_timestamp()+INTERVAL '1 hour'),
                (clock_timestamp()+INTERVAL '1 hour',0,NULL,NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let error = dead_letter_expired_cluster_muc_outbox(&pool, 10)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reject_expired"));
    let unchanged = cluster_muc_outbox_snapshot(&pool).await.unwrap();
    assert_eq!(
        unchanged.queued_rows, 4,
        "failed INSERT must roll back all removals"
    );
    assert_eq!(unchanged.expired_rows, 1);
    assert_eq!(unchanged.claimed_rows, 1);
    assert_eq!(unchanged.dead_letter_rows, 0);
    assert!(unchanged.oldest_age_seconds >= 60);

    sqlx::query("ALTER TABLE cluster_muc_event_dead_letters DROP CONSTRAINT reject_expired")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        dead_letter_expired_cluster_muc_outbox(&pool, 0)
            .await
            .unwrap(),
        1
    );
    let limited = cluster_muc_outbox_snapshot(&pool).await.unwrap();
    assert_eq!(limited.queued_rows, 3);
    assert_eq!(limited.expired_rows, 0);
    assert_eq!(limited.claimed_rows, 1);
    assert_eq!(limited.dead_letter_rows, 1);
    assert_eq!(
        dead_letter_expired_cluster_muc_outbox(&pool, 10)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        dead_letter_expired_cluster_muc_outbox(&pool, 10)
            .await
            .unwrap(),
        0
    );
    let complete = cluster_muc_outbox_snapshot(&pool).await.unwrap();
    assert_eq!(complete.queued_rows, 2);
    assert_eq!(complete.claimed_rows, 1);
    assert_eq!(complete.dead_letter_rows, 2);
    let reasons: Vec<String> = sqlx::query_scalar(
        "SELECT terminal_reason FROM cluster_muc_event_dead_letters ORDER BY terminal_reason",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(reasons, ["attempt_limit", "expired"]);
    pool.close().await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; exercises 0089 claim/kick/destroy/outbox failure model"]
async fn postgres_failure_fixture_covers_cluster_muc_authority() {
    let _url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to run the isolated CLU-MUC fixture");
    // The runtime fixture is intentionally ignored in the static gate.
    // scripts/cluster-wsl.sh runs the cross-node counterpart with Redis
    // loss after the root serial production-validation phase authorizes it.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the disposable schema created by scripts/muc-db-wsl.sh"]
async fn federated_rebind_is_atomic_and_fences_the_old_connection() {
    use northstar_room_postgres::muc::get_or_create_muc_room;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("run this ignored test through scripts/muc-db-wsl.sh");
    assert!(std::env::var_os("XMPP_TEST_CREATED_SCHEMA_LOG").is_some());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let creator = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'rebind-owner','test')")
        .bind(creator)
        .execute(&pool)
        .await
        .unwrap();
    let (room, _) = get_or_create_muc_room(
        &pool,
        "federated-rebind",
        creator,
        "rebind-owner@local.test/Phone",
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE muc_rooms SET configuration_state='active',
                configuration_owner_jid=NULL,configuration_expires_at=NULL WHERE id=$1",
    )
    .bind(room.id)
    .execute(&pool)
    .await
    .unwrap();
    let config_version: i64 =
        sqlx::query_scalar("SELECT config_version FROM muc_rooms WHERE id=$1")
            .bind(room.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let old_connection = Uuid::new_v4();
    let new_connection = Uuid::new_v4();
    let principal = ClusterMucPrincipal::Federated {
        bare_jid: "bob@remote.test".into(),
        authenticated_domain: "remote.test".into(),
    };
    let joined = claim_cluster_muc_occupancy(
        &pool,
        ClusterMucJoin {
            operation_id: Uuid::new_v4(),
            room_id: room.id,
            expected_room_epoch: room.room_epoch,
            expected_config_version: config_version,
            principal,
            full_jid: "bob@remote.test/Phone",
            nick: "Bob",
            owner_node_id: "rebind-node",
            connection_uuid: old_connection,
            connection_epoch: 1,
            sm_session_id: None,
            occupant_incarnation: Uuid::new_v4(),
            presence_payload: "<x xmlns='http://jabber.org/protocol/muc'/>",
            lease: Duration::from_secs(90),
        },
    )
    .await
    .unwrap();
    let ClusterMucJoinOutcome::Joined(joined) = joined else {
        panic!("federated actor could not join");
    };
    let old_target = ClusterMucOccupancyTarget::from(&joined);
    assert!(rebind_federated_cluster_muc_occupancy(
        &pool,
        Uuid::new_v4(),
        &old_target,
        "rebind-node",
        "evil.test",
        new_connection,
        Duration::from_secs(90),
    )
    .await
    .is_err());
    sqlx::query(
        "INSERT INTO muc_external_affiliations(room_id,jid,affiliation)
         VALUES($1,'bob@remote.test','outcast')",
    )
    .bind(room.id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        rebind_federated_cluster_muc_occupancy(
            &pool,
            Uuid::new_v4(),
            &old_target,
            "rebind-node",
            "remote.test",
            new_connection,
            Duration::from_secs(90),
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Unauthorized
    );
    sqlx::query("DELETE FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2")
        .bind(room.id)
        .bind("bob@remote.test")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE muc_rooms SET members_only=TRUE WHERE id=$1")
        .bind(room.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        rebind_federated_cluster_muc_occupancy(
            &pool,
            Uuid::new_v4(),
            &old_target,
            "rebind-node",
            "remote.test",
            new_connection,
            Duration::from_secs(90),
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Unauthorized
    );
    sqlx::query("UPDATE muc_rooms SET members_only=FALSE WHERE id=$1")
        .bind(room.id)
        .execute(&pool)
        .await
        .unwrap();
    let operation_id = Uuid::new_v4();
    assert_eq!(
        rebind_federated_cluster_muc_occupancy(
            &pool,
            operation_id,
            &old_target,
            "rebind-node",
            "remote.test",
            new_connection,
            Duration::from_secs(90),
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Applied
    );
    let (connection, epoch): (Uuid, i64) = sqlx::query_as(
        "SELECT connection_uuid,connection_epoch FROM cluster_muc_occupancies
          WHERE room_id=$1 AND occupant_incarnation=$2",
    )
    .bind(room.id)
    .bind(joined.occupant_incarnation)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((connection, epoch), (new_connection, 2));
    assert_eq!(
        disconnect_cluster_muc_occupancy(&pool, Uuid::new_v4(), &old_target, "rebind-node")
            .await
            .unwrap(),
        ClusterMucTransitionOutcome::Stale
    );
    let (kind, details): (String, serde_json::Value) = sqlx::query_as(
        "SELECT operation_kind,details FROM cluster_muc_operations WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(kind, "resume");
    assert_eq!(details["connection_rebind"], true);
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the disposable schema created by scripts/muc-db-wsl.sh"]
async fn postgres_admin_batch_is_atomic_under_replay_and_failure() {
    use northstar_room_postgres::muc::{get_or_create_muc_room, MucAffiliationTarget};
    use ClusterMucAdminBatchOutcome as Outcome;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("run this ignored test through scripts/muc-db-wsl.sh");
    assert!(std::env::var_os("XMPP_TEST_CREATED_SCHEMA_LOG").is_some());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let alice_id = Uuid::new_v4();
    let bob_id = Uuid::new_v4();
    let carol_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES
          ($1,'batch-alice','test'),($2,'batch-bob','test'),($3,'batch-carol','test')",
    )
    .bind(alice_id)
    .bind(bob_id)
    .bind(carol_id)
    .execute(&pool)
    .await
    .unwrap();
    let (room, created) = get_or_create_muc_room(
        &pool,
        "admin-batch",
        alice_id,
        "batch-alice@local.test/Phone",
    )
    .await
    .unwrap();
    assert!(created);
    sqlx::query(
        "UPDATE muc_rooms SET configuration_state='active',
                configuration_owner_jid=NULL,configuration_expires_at=NULL
          WHERE id=$1",
    )
    .bind(room.id)
    .execute(&pool)
    .await
    .unwrap();
    let config_version: i64 =
        sqlx::query_scalar("SELECT config_version FROM muc_rooms WHERE id=$1")
            .bind(room.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let alice = ClusterMucPrincipal::Local {
        user_id: alice_id,
        bare_jid: "batch-alice@local.test".to_owned(),
    };
    let bob = ClusterMucPrincipal::Local {
        user_id: bob_id,
        bare_jid: "batch-bob@local.test".to_owned(),
    };
    let carol = ClusterMucPrincipal::Local {
        user_id: carol_id,
        bare_jid: "batch-carol@local.test".to_owned(),
    };
    let join = |principal: ClusterMucPrincipal, full_jid: &'static str, nick: &'static str| {
        ClusterMucJoin {
            operation_id: Uuid::new_v4(),
            room_id: room.id,
            expected_room_epoch: room.room_epoch,
            expected_config_version: config_version,
            principal,
            full_jid,
            nick,
            owner_node_id: "batch-node",
            connection_uuid: Uuid::new_v4(),
            connection_epoch: 1,
            sm_session_id: None,
            occupant_incarnation: Uuid::new_v4(),
            presence_payload: "<presence/>",
            lease: Duration::from_secs(90),
        }
    };
    let joined = |outcome| match outcome {
        ClusterMucJoinOutcome::Joined(occupancy) => ClusterMucOccupancyTarget::from(&occupancy),
        other => panic!("unexpected cluster MUC join outcome: {other:?}"),
    };
    let alice_target = joined(
        claim_cluster_muc_occupancy(
            &pool,
            join(alice.clone(), "batch-alice@local.test/Phone", "Alice"),
        )
        .await
        .unwrap(),
    );
    let bob_target = joined(
        claim_cluster_muc_occupancy(
            &pool,
            join(bob.clone(), "batch-bob@local.test/Phone", "Bob"),
        )
        .await
        .unwrap(),
    );
    let carol_target = joined(
        claim_cluster_muc_occupancy(
            &pool,
            join(carol.clone(), "batch-carol@local.test/Phone", "Carol"),
        )
        .await
        .unwrap(),
    );
    let renewed = renew_cluster_muc_occupancies_batch(
        &pool,
        &[alice_target.clone(), bob_target.clone()],
        "batch-node",
        Duration::from_secs(90),
    )
    .await
    .unwrap();
    assert_eq!(renewed.len(), 2);
    assert!(renewed.contains(&alice_target));
    assert!(renewed.contains(&bob_target));
    let lookups = [
        ClusterMucOccupancyLookup {
            room_localpart: "admin-batch".to_owned(),
            full_jid: alice_target.full_jid.clone(),
            nick: alice_target.nick.clone(),
            occupant_incarnation: alice_target.occupant_incarnation,
            connection_uuid: alice_target.connection_uuid,
        },
        ClusterMucOccupancyLookup {
            room_localpart: "admin-batch".to_owned(),
            full_jid: bob_target.full_jid.clone(),
            nick: bob_target.nick.clone(),
            occupant_incarnation: bob_target.occupant_incarnation,
            connection_uuid: bob_target.connection_uuid,
        },
    ];
    let resolved = resolve_cluster_muc_occupancies_batch(&pool, &lookups, "batch-node")
        .await
        .unwrap();
    assert_eq!(resolved.len(), 2);
    assert!(resolved.iter().any(|item| item.target == alice_target));
    assert!(resolved.iter().any(|item| item.target == bob_target));
    assert!(
        committed_terminal_cluster_muc_occupancies_batch(&pool, &lookups, "batch-node",)
            .await
            .unwrap()
            .is_empty()
    );
    let mut stale_lookup = lookups[1].clone();
    stale_lookup.connection_uuid = Uuid::new_v4();
    assert_eq!(
        resolve_cluster_muc_occupancies_batch(
            &pool,
            &[lookups[0].clone(), stale_lookup],
            "batch-node"
        )
        .await
        .unwrap(),
        vec![ClusterMucResolvedOccupancy {
            room_localpart: "admin-batch".to_owned(),
            target: alice_target.clone(),
        }]
    );
    let mut wrong_epoch = bob_target.clone();
    wrong_epoch.connection_epoch += 1;
    assert_eq!(
        renew_cluster_muc_occupancies_batch(
            &pool,
            &[alice_target.clone(), wrong_epoch],
            "batch-node",
            Duration::from_secs(90),
        )
        .await
        .unwrap(),
        vec![alice_target.clone()],
        "the omitted exact target must lose local authority"
    );
    assert!(renew_cluster_muc_occupancies_batch(
        &pool,
        &[alice_target.clone(), alice_target.clone()],
        "batch-node",
        Duration::from_secs(90),
    )
    .await
    .is_err());
    let mut command = ClusterMucAdminBatch {
        operation_id: Uuid::new_v4(),
        room_id: room.id,
        expected_room_epoch: room.room_epoch,
        expected_config_version: config_version,
        actor_target: Some(&alice_target),
        actor: &alice,
        actor_full_jid: "batch-alice@local.test/Phone",
        local_domain: "local.test",
        changes: &[],
    };
    let demote_last_owner = [ClusterMucAdminChange::Affiliation {
        target: MucAffiliationTarget::LocalUsername("batch-alice".to_owned()),
        affiliation: "member".to_owned(),
        reason: None,
    }];
    command.changes = &demote_last_owner;
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::LastOwner
    );
    let overlap = [
        ClusterMucAdminChange::Affiliation {
            target: MucAffiliationTarget::LocalUsername("batch-bob".to_owned()),
            affiliation: "member".to_owned(),
            reason: None,
        },
        ClusterMucAdminChange::Role {
            target_nick: "Bob".to_owned(),
            role: "visitor".to_owned(),
            reason: None,
        },
    ];
    command.operation_id = Uuid::new_v4();
    command.changes = &overlap;
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::DuplicateTarget
    );
    let mixed = [
        ClusterMucAdminChange::Affiliation {
            target: MucAffiliationTarget::LocalUsername("batch-carol".to_owned()),
            affiliation: "member".to_owned(),
            reason: Some("invited".to_owned()),
        },
        ClusterMucAdminChange::Role {
            target_nick: "Bob".to_owned(),
            role: "visitor".to_owned(),
            reason: Some("quiet".to_owned()),
        },
    ];
    command.operation_id = Uuid::new_v4();
    command.changes = &mixed;

    // Fail on the second item after the first affiliation and occupancy
    // updates have executed; no partial state or outbox row may survive.
    sqlx::raw_sql(
        "CREATE FUNCTION reject_bob_batch_update() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.nick='Bob' THEN RAISE EXCEPTION 'injected second item failure'; END IF;
               RETURN NEW; END $$;
         CREATE TRIGGER reject_bob_batch_update BEFORE UPDATE ON cluster_muc_occupancies
           FOR EACH ROW EXECUTE FUNCTION reject_bob_batch_update()",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(apply_cluster_muc_admin_batch(&pool, command)
        .await
        .unwrap_err()
        .to_string()
        .contains("injected second item failure"));
    sqlx::raw_sql(
        "DROP TRIGGER reject_bob_batch_update ON cluster_muc_occupancies;
         DROP FUNCTION reject_bob_batch_update()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let carol_affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2",
    )
    .bind(room.id)
    .bind(carol_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(carol_affiliation.is_none());
    let failed_operation: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cluster_muc_operations WHERE operation_id=$1)",
    )
    .bind(command.operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!failed_operation);

    // Force the operation's final outbox insert to fail and check that
    // earlier item writes and its event sequence are also rolled back.
    let outbox_failure_id = Uuid::new_v4();
    let trigger = format!(
        "CREATE FUNCTION reject_batch_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.operation_id='{outbox_failure_id}'::uuid THEN
                 RAISE EXCEPTION 'injected batch outbox failure'; END IF;
               RETURN NEW; END $$;
         CREATE TRIGGER reject_batch_outbox BEFORE INSERT ON cluster_muc_event_outbox
           FOR EACH ROW EXECUTE FUNCTION reject_batch_outbox()"
    );
    sqlx::raw_sql(&trigger).execute(&pool).await.unwrap();
    command.operation_id = outbox_failure_id;
    assert!(apply_cluster_muc_admin_batch(&pool, command)
        .await
        .unwrap_err()
        .to_string()
        .contains("injected batch outbox failure"));
    sqlx::raw_sql(
        "DROP TRIGGER reject_batch_outbox ON cluster_muc_event_outbox;
         DROP FUNCTION reject_batch_outbox()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let carol_affiliation: Option<String> = sqlx::query_scalar(
        "SELECT affiliation FROM muc_affiliations WHERE room_id=$1 AND user_id=$2",
    )
    .bind(room.id)
    .bind(carol_id)
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(carol_affiliation.is_none());

    command.operation_id = Uuid::new_v4();
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::Applied
    );
    let details: Value =
        sqlx::query_scalar("SELECT details FROM cluster_muc_operations WHERE operation_id=$1")
            .bind(command.operation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(details["request_change_count"], 2);
    assert_eq!(details["changes"].as_array().unwrap().len(), 2);
    assert_eq!(details["changes"][0]["snapshot"]["nick"], "Carol");
    assert_eq!(details["changes"][1]["snapshot"]["nick"], "Bob");
    let delivery_row = sqlx::query(
        "SELECT payload,payload_digest FROM cluster_muc_event_outbox
          WHERE operation_id=$1 AND recipient_occupant_incarnation=$2",
    )
    .bind(command.operation_id)
    .bind(bob_target.occupant_incarnation)
    .fetch_one(&pool)
    .await
    .unwrap();
    let payload: String = delivery_row.get("payload");
    let digest: Vec<u8> = delivery_row.get("payload_digest");
    let projection: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(projection["original_audience"]["nick"], "Bob");
    assert_eq!(projection["original_audience"]["role"], "participant");
    assert!(!payload.contains("presence_payload"));
    assert_eq!(digest, payload_digest(&payload));
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::Replay
    );
    sqlx::query("UPDATE muc_rooms SET description='later configuration' WHERE id=$1")
        .bind(room.id)
        .execute(&pool)
        .await
        .unwrap();
    command.expected_config_version =
        sqlx::query_scalar("SELECT config_version FROM muc_rooms WHERE id=$1")
            .bind(room.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::Replay,
        "a room configuration change cannot alter the digest of the same IQ body"
    );

    let kick = [ClusterMucAdminChange::Role {
        target_nick: "Bob".to_owned(),
        role: "none".to_owned(),
        reason: Some("removed".to_owned()),
    }];
    command.operation_id = Uuid::new_v4();
    command.changes = &kick;
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        apply_cluster_muc_admin_batch(
            &pool,
            ClusterMucAdminBatch {
                actor_target: None,
                ..command
            },
        )
        .await
        .unwrap(),
        Outcome::Replay,
        "kick replay must precede actor and target occupancy lookups"
    );
    let changed_retry = [ClusterMucAdminChange::Role {
        target_nick: "Bob".to_owned(),
        role: "participant".to_owned(),
        reason: None,
    }];
    command.changes = &changed_retry;
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::Conflict
    );
    let mut wrong_nick = lookups[1].clone();
    wrong_nick.nick = "AnotherBob".to_owned();
    let mut wrong_connection = lookups[1].clone();
    wrong_connection.connection_uuid = Uuid::new_v4();
    let mut wrong_incarnation = lookups[1].clone();
    wrong_incarnation.occupant_incarnation = Uuid::new_v4();
    let mut wrong_room = lookups[1].clone();
    wrong_room.room_localpart = "another-room".to_owned();
    assert_eq!(
        committed_terminal_cluster_muc_occupancies_batch(
            &pool,
            &[
                lookups[0].clone(),
                lookups[1].clone(),
                wrong_nick,
                wrong_connection,
                wrong_incarnation,
                wrong_room,
            ],
            "batch-node",
        )
        .await
        .unwrap(),
        vec![lookups[1].clone()],
        "only Bob's committed revoked occupancy is a safe room-only cleanup"
    );
    assert!(
        committed_terminal_cluster_muc_occupancies_batch(&pool, &lookups, "another-node",)
            .await
            .unwrap()
            .is_empty()
    );

    let owner_transfer = [
        ClusterMucAdminChange::Affiliation {
            target: MucAffiliationTarget::LocalUsername("batch-alice".to_owned()),
            affiliation: "member".to_owned(),
            reason: None,
        },
        ClusterMucAdminChange::Affiliation {
            target: MucAffiliationTarget::LocalUsername("batch-carol".to_owned()),
            affiliation: "owner".to_owned(),
            reason: None,
        },
    ];
    command.operation_id = Uuid::new_v4();
    command.changes = &owner_transfer;
    assert_eq!(
        apply_cluster_muc_admin_batch(&pool, command).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(
        apply_cluster_muc_admin_batch(
            &pool,
            ClusterMucAdminBatch {
                operation_id: Uuid::new_v4(),
                changes: &demote_last_owner,
                ..command
            }
        )
        .await
        .unwrap(),
        Outcome::Unauthorized,
        "former owner cannot use authority from before the committed transfer"
    );
    let owner_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM muc_affiliations WHERE room_id=$1 AND affiliation='owner'",
    )
    .bind(room.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner_count, 1);

    // Same stream/IQ identity with two different bodies is serialized by
    // the room row; after the bounded retry one caller must see a digest
    // conflict rather than committing a second operation.
    let role_participant = [ClusterMucAdminChange::Role {
        target_nick: "Alice".to_owned(),
        role: "participant".to_owned(),
        reason: None,
    }];
    let role_visitor = [ClusterMucAdminChange::Role {
        target_nick: "Alice".to_owned(),
        role: "visitor".to_owned(),
        reason: None,
    }];
    let same_id = Uuid::new_v4();
    let current = ClusterMucAdminBatch {
        operation_id: same_id,
        actor_target: Some(&carol_target),
        actor: &carol,
        actor_full_jid: "batch-carol@local.test/Phone",
        changes: &role_participant,
        ..command
    };
    let changed = ClusterMucAdminBatch {
        changes: &role_visitor,
        ..current
    };
    let (one, two) = tokio::join!(
        apply_cluster_muc_admin_batch(&pool, current),
        apply_cluster_muc_admin_batch(&pool, changed),
    );
    assert!(matches!(
        (one.unwrap(), two.unwrap()),
        (Outcome::Applied, Outcome::Conflict) | (Outcome::Conflict, Outcome::Applied)
    ));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cluster_muc_operations WHERE operation_id=$1")
            .bind(same_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);

    let identical_id = Uuid::new_v4();
    let identical = ClusterMucAdminBatch {
        operation_id: identical_id,
        ..current
    };
    let (one, two) = tokio::join!(
        apply_cluster_muc_admin_batch(&pool, identical),
        apply_cluster_muc_admin_batch(&pool, identical),
    );
    assert!(matches!(
        (one.unwrap(), two.unwrap()),
        (Outcome::Applied, Outcome::Replay) | (Outcome::Replay, Outcome::Applied)
    ));
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cluster_muc_operations WHERE operation_id=$1")
            .bind(identical_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);

    assert!(cluster_muc_occupancy_target_for_disconnect(
        &pool,
        "admin-batch",
        "batch-carol@local.test/Phone",
        "Carol",
        carol_target.occupant_incarnation,
        Uuid::new_v4(),
        "batch-node",
    )
    .await
    .unwrap()
    .is_none());
    let departing = cluster_muc_occupancy_target_for_disconnect(
        &pool,
        "admin-batch",
        "batch-carol@local.test/Phone",
        "Carol",
        carol_target.occupant_incarnation,
        carol_target.connection_uuid,
        "batch-node",
    )
    .await
    .unwrap()
    .expect("exact local actor remains active");
    assert_eq!(departing, carol_target);
    let leave_id = Uuid::new_v4();
    assert_eq!(
        disconnect_cluster_muc_occupancy(&pool, leave_id, &departing, "batch-node")
            .await
            .unwrap(),
        ClusterMucTransitionOutcome::Applied
    );
    let disconnect_details: serde_json::Value =
        sqlx::query_scalar("SELECT details FROM cluster_muc_operations WHERE operation_id=$1")
            .bind(leave_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(disconnect_details["status"], 333);
    let outbox_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cluster_muc_event_outbox WHERE operation_id=$1")
            .bind(leave_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(outbox_rows > 0);
    assert_eq!(
        disconnect_cluster_muc_occupancy(&pool, leave_id, &departing, "batch-node")
            .await
            .unwrap(),
        ClusterMucTransitionOutcome::Replay
    );
    let replay_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cluster_muc_event_outbox WHERE operation_id=$1")
            .bind(leave_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(replay_rows, outbox_rows);
    assert!(cluster_muc_occupancy_target_for_disconnect(
        &pool,
        "admin-batch",
        "batch-carol@local.test/Phone",
        "Carol",
        carol_target.occupant_incarnation,
        carol_target.connection_uuid,
        "batch-node",
    )
    .await
    .unwrap()
    .is_none());
    assert_eq!(
        destroy_cluster_muc_room(
            &pool,
            Uuid::new_v4(),
            room.id,
            room.room_epoch,
            None,
            "system",
            None,
            None,
            None,
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Applied
    );
    let terminal = committed_terminal_cluster_muc_occupancies_batch(&pool, &lookups, "batch-node")
        .await
        .unwrap();
    assert_eq!(terminal.len(), 2);
    assert!(terminal.contains(&lookups[0]));
    assert!(terminal.contains(&lookups[1]));
    let _ = bob_target;
    pool.close().await;
}
