use super::*;
use std::time::Duration;

fn protected_retention_fixture() -> ProtectedRetentionProjection {
    let lease = Uuid::from_u128(1);
    let owner = Uuid::from_u128(10);
    let timestamp = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let allocation = RetentionAllocation {
        shard: 3,
        created_at: timestamp,
    };
    ProtectedRetentionProjection {
        bindings: BTreeMap::from([(
            lease,
            RetentionBinding {
                connection_id: Uuid::from_u128(2),
                user_id: owner,
                full_jid: "retained@example.test/device".to_owned(),
                lease_until: timestamp,
                created_at: timestamp,
                updated_at: timestamp,
                allocation: allocation.clone(),
            },
        )]),
        shards: BTreeMap::from([(
            3,
            RetentionShard {
                used: 2,
                capacity: 2,
            },
        )]),
        owners: BTreeMap::from([(owner, 2)]),
        allocations: BTreeMap::from([
            (lease, allocation.clone()),
            (Uuid::from_u128(4), allocation),
        ]),
        owner_leases: BTreeMap::from([(lease, owner), (Uuid::from_u128(4), owner)]),
    }
}

#[test]
fn protected_retention_precheck_rejects_missing_mapping_and_shared_charge_corruption() {
    let original = protected_retention_fixture();
    assert!(original.validate_integrity().is_ok());
    let mut missing = original.clone();
    missing.allocations.remove(&Uuid::from_u128(1));
    assert!(missing.validate_integrity().is_err());
    let mut missing = original.clone();
    missing.shards.clear();
    assert!(missing.validate_integrity().is_err());
    let mut missing = original.clone();
    missing.owners.clear();
    assert!(missing.validate_integrity().is_err());
    let mut corrupt = original.clone();
    corrupt.shards.get_mut(&3).unwrap().used = 1;
    assert!(corrupt.validate_integrity().is_err());
    let mut corrupt = original.clone();
    corrupt.shards.get_mut(&3).unwrap().capacity = 1;
    assert!(corrupt.validate_integrity().is_err());
    let mut corrupt = original;
    corrupt.owners.insert(Uuid::from_u128(10), 1);
    assert!(corrupt.validate_integrity().is_err());
}

#[test]
fn protected_retention_final_rejects_changed_identity_and_protected_repair_sets() {
    let original = protected_retention_fixture();
    let empty_delta = RetentionRepairDelta::default();
    assert!(original
        .validate_final(&original, &empty_delta, 128)
        .is_ok());
    for changed_field in 0..8 {
        let mut changed = original.clone();
        let binding = changed.bindings.get_mut(&Uuid::from_u128(1)).unwrap();
        match changed_field {
            0 => binding.connection_id = Uuid::from_u128(90),
            1 => binding.user_id = Uuid::from_u128(90),
            2 => binding.full_jid = "other@example.test/device".to_owned(),
            3 => binding.lease_until += chrono::Duration::seconds(1),
            4 => binding.created_at += chrono::Duration::seconds(1),
            5 => binding.updated_at += chrono::Duration::seconds(1),
            6 => binding.allocation.shard = 4,
            _ => binding.allocation.created_at += chrono::Duration::seconds(1),
        }
        assert!(original
            .validate_final(&changed, &empty_delta, 128)
            .is_err());
    }
    let mut changed = original.clone();
    changed.bindings.clear();
    assert!(original
        .validate_final(&changed, &empty_delta, 128)
        .is_err());
    for repair_kind in 0..3 {
        let mut delta = RetentionRepairDelta::default();
        let id = Uuid::from_u128(1);
        match repair_kind {
            0 => {
                delta
                    .added_allocations
                    .insert(id, original.allocations[&id].clone());
            }
            1 => {
                delta
                    .removed_allocations
                    .insert(id, original.allocations[&id].clone());
            }
            _ => {
                delta.deleted_leases.insert(id, Uuid::from_u128(10));
            }
        }
        assert!(original.validate_final(&original, &delta, 128).is_err());
    }
}

#[test]
fn protected_retention_final_accepts_exact_neighbor_deltas_and_configured_epoch_budget() {
    let original = protected_retention_fixture();
    let neighbor = Uuid::from_u128(4);
    let replacement = Uuid::from_u128(5);
    let allocation = original.allocations[&neighbor].clone();
    let mut final_projection = original.clone();
    final_projection.allocations.remove(&neighbor);
    final_projection
        .allocations
        .insert(replacement, allocation.clone());
    final_projection.owner_leases.remove(&neighbor);
    final_projection.owners.insert(Uuid::from_u128(10), 1);
    // A non-P backfill on this shared shard belongs to another owner.
    final_projection.shards.get_mut(&3).unwrap().capacity = 3;
    let delta = RetentionRepairDelta {
        added_allocations: BTreeMap::from([(replacement, allocation.clone())]),
        removed_allocations: BTreeMap::from([(neighbor, allocation)]),
        deleted_leases: BTreeMap::from([(neighbor, Uuid::from_u128(10))]),
    };
    assert!(original
        .validate_final(&final_projection, &delta, 192)
        .is_ok());
    assert!(original
        .validate_final(&final_projection, &delta, 128)
        .is_err());
    assert!(original
        .validate_final(&final_projection, &RetentionRepairDelta::default(), 192,)
        .is_err());

    // A raw orphan allocation has no lease DELETE trigger. Its exact
    // RETURNING-based removal changes only the shared shard charge.
    let mut orphan_before = original.clone();
    orphan_before.owner_leases.remove(&neighbor);
    orphan_before.owners.insert(Uuid::from_u128(10), 1);
    let mut orphan_after = orphan_before.clone();
    orphan_after.allocations.remove(&neighbor);
    orphan_after.shards.get_mut(&3).unwrap().used = 1;
    let orphan_delta = RetentionRepairDelta {
        removed_allocations: BTreeMap::from([(neighbor, original.allocations[&neighbor].clone())]),
        ..RetentionRepairDelta::default()
    };
    assert!(orphan_before
        .validate_final(&orphan_after, &orphan_delta, 128)
        .is_ok());
    assert!(orphan_before
        .validate_final(&orphan_after, &RetentionRepairDelta::default(), 128,)
        .is_err());
}

#[test]
fn protected_retention_final_accepts_temporary_doomed_allocation_with_zero_net_charge() {
    let original = protected_retention_fixture();
    let mut before = original.clone();
    let doomed = Uuid::from_u128(6);
    let owner = Uuid::from_u128(10);
    before.owner_leases.insert(doomed, owner);
    before.owners.insert(owner, 3);
    let allocation = before.allocations[&Uuid::from_u128(1)].clone();
    let delta = RetentionRepairDelta {
        added_allocations: BTreeMap::from([(doomed, allocation.clone())]),
        removed_allocations: BTreeMap::from([(doomed, allocation)]),
        deleted_leases: BTreeMap::from([(doomed, owner)]),
    };
    assert!(before.validate_final(&original, &delta, 128).is_ok());
}

#[test]
fn protected_retention_final_rejects_unexplained_shared_accounting_changes() {
    let original = protected_retention_fixture();
    let empty_delta = RetentionRepairDelta::default();
    let mut changed = original.clone();
    changed.allocations.remove(&Uuid::from_u128(4));
    changed.shards.get_mut(&3).unwrap().used = 1;
    assert!(changed.validate_integrity().is_ok());
    assert!(original
        .validate_final(&changed, &empty_delta, 128)
        .is_err());
    let mut changed = original.clone();
    changed.owner_leases.remove(&Uuid::from_u128(4));
    changed.owners.insert(Uuid::from_u128(10), 1);
    assert!(changed.validate_integrity().is_ok());
    assert!(original
        .validate_final(&changed, &empty_delta, 128)
        .is_err());
}

#[test]
fn shard_budgets_sum_to_exact_limit() {
    for limit in [1, 63, 64, 65, 1_000, 4_096, 100_003] {
        let budgets = (0..CAPACITY_SHARDS)
            .map(|shard| shard_budget(limit, shard))
            .collect::<Vec<_>>();
        assert_eq!(budgets.iter().sum::<i64>(), limit);
        assert!(budgets.iter().all(|budget| *budget >= 0));
        assert!(budgets.iter().max().unwrap() - budgets.iter().min().unwrap() <= 1);
    }
}

#[test]
fn authority_epoch_is_monotonic_and_snapshot_fenced() {
    let current = DeploymentCapacityConfiguration {
        epoch: 7,
        accounts: 100,
        muc_rooms: 50,
        muc_rooms_per_owner: 10,
        live_sessions: 200,
        sessions_per_account: 8,
        resumable_sessions: 200,
    };
    assert!(validate_authority_transition(current, current).is_ok());
    assert!(!authority_reconciliation_required(current, current)
        .expect("an unchanged committed epoch must take the audit path"));
    assert!(validate_authority_transition(
        current,
        DeploymentCapacityConfiguration {
            epoch: 8,
            accounts: 101,
            ..current
        }
    )
    .is_ok());
    assert!(authority_reconciliation_required(
        current,
        DeploymentCapacityConfiguration {
            epoch: 8,
            accounts: 101,
            ..current
        }
    )
    .expect("the next epoch is a recovery transition"));
    assert!(validate_authority_transition(
        current,
        DeploymentCapacityConfiguration {
            accounts: 101,
            ..current
        }
    )
    .is_err());
    assert!(validate_authority_transition(
        current,
        DeploymentCapacityConfiguration {
            epoch: 6,
            ..current
        }
    )
    .is_err());
    assert!(validate_authority_transition(
        current,
        DeploymentCapacityConfiguration {
            epoch: 9,
            ..current
        }
    )
    .is_err());
    let bootstrap = DeploymentCapacityConfiguration {
        epoch: 0,
        ..current
    };
    assert!(validate_authority_transition(
        bootstrap,
        DeploymentCapacityConfiguration {
            epoch: 1,
            ..current
        }
    )
    .is_ok());
    assert!(validate_authority_transition(bootstrap, current).is_err());
    assert!(authority_reconciliation_required(
        bootstrap,
        DeploymentCapacityConfiguration {
            epoch: 1,
            ..current
        }
    )
    .expect("bootstrap must reconcile its first committed epoch"));
}

#[test]
fn capacity_error_classification_is_narrow_and_stable() {
    assert!(is_capacity_exhausted(&anyhow::anyhow!(
        "deployment live-session capacity exhausted"
    )));
    assert!(!is_capacity_exhausted(&anyhow::anyhow!(
        "database unavailable"
    )));
}

#[test]
fn destroyed_muc_rooms_release_capacity_once_and_are_not_backfilled() {
    let migration = include_str!("../../../migrations/0090_deployment_capacity_ledger.sql");
    assert!(migration.contains("northstar_muc_capacity_destroy_update"));
    assert!(migration.contains("OLD.destroyed_at IS NULL AND NEW.destroyed_at IS NOT NULL"));
    assert!(migration.contains("Do not transfer/release that owner a second time"));
    assert!(migration.contains("WHERE destroyed_at IS NULL ORDER BY id"));
    assert!(migration.contains("ELSIF OLD.destroyed_at IS NULL"));
    assert!(migration.contains("muc_rooms_deployment_capacity_destroy_update"));
}

#[test]
fn session_authorities_are_capability_only_and_secret_columns_stay_private() {
    let migration = include_str!("../../../migrations/0114_session_authority_capabilities.sql");
    let grants = include_str!("../../../deploy/postgres-init/lib/apply-northstar-grants.sql");
    assert!(!migration.contains("public."));
    for required in [
        "northstar_session_reserve_live",
        "northstar_session_transfer_sm",
        "northstar_sm_claim",
        "northstar_sm_activate",
        "northstar_sm_take_teardown",
        "northstar_session_capability_catalog_healthy",
        "REVOKE ALL ON TABLE deployment_session_leases",
    ] {
        assert!(migration.contains(required), "missing {required}");
    }
    assert!(
        grants.contains("runtime session leases and SM bearer state violate capability-only ACLs")
    );
    assert!(grants.contains("'token_hash','SELECT'"));
    assert!(grants.contains("'claim_token','SELECT'"));
    assert_eq!(
        grants
            .matches("northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)")
            .count(),
        3
    );
    assert_eq!(
        grants
            .matches("northstar_session_reserve_live(uuid,uuid,text,int8,bool)")
            .count(),
        3
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; rollback-only temporary tables and classifier-name helper schema"]
async fn postgres_capacity_audit_compares_complete_entity_and_counter_sets() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&url)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    // The production audit resolves every business table inside this one
    // connection's temporary namespace. A missing table cannot fall back
    // to a persistent schema, including one supplied through the URL.
    sqlx::raw_sql(
        "SET LOCAL search_path=pg_temp,pg_catalog;
             SET LOCAL statement_timeout='5s';
             SET LOCAL lock_timeout='1s';
             CREATE TEMP TABLE users(id UUID PRIMARY KEY) ON COMMIT DROP;
             CREATE TEMP TABLE muc_rooms(
                 id UUID PRIMARY KEY, destroyed_at TIMESTAMPTZ, owner_id UUID
             ) ON COMMIT DROP;
             CREATE TEMP TABLE deployment_session_leases(
                 lease_id UUID PRIMARY KEY, user_id UUID NOT NULL,
                 lease_until TIMESTAMPTZ NOT NULL
             ) ON COMMIT DROP;
             CREATE TEMP TABLE sm_resume_sessions(
                 id UUID PRIMARY KEY, user_id UUID NOT NULL
             ) ON COMMIT DROP;
             CREATE TEMP TABLE deployment_capacity_shards(
                 resource_kind TEXT NOT NULL, shard SMALLINT NOT NULL,
                 capacity BIGINT NOT NULL, used BIGINT NOT NULL,
                 PRIMARY KEY(resource_kind,shard)
             ) ON COMMIT DROP;
             CREATE TEMP TABLE deployment_capacity_allocations(
                 resource_kind TEXT NOT NULL, entity_id UUID NOT NULL,
                 shard SMALLINT NOT NULL, PRIMARY KEY(resource_kind,entity_id)
             ) ON COMMIT DROP;
             CREATE TEMP TABLE deployment_account_capacity(
                 resource_kind TEXT NOT NULL, owner_id UUID NOT NULL,
                 used BIGINT NOT NULL, PRIMARY KEY(resource_kind,owner_id)
             ) ON COMMIT DROP;
             INSERT INTO deployment_capacity_shards(resource_kind,shard,capacity,used)
             SELECT kind,shard,1,0
               FROM unnest(ARRAY['account','muc_room','live_session','sm_session']) kind
               CROSS JOIN generate_series(0,63) shard;",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    // This existing audit has no live leases. Its SQL now resolves the
    // production classifier name, but must never evaluate retention here.
    // PostgreSQL does not resolve functions through pg_temp; install only
    // this raising signature in a unique rollback-only helper schema.
    let helper_schema = format!("capacity_audit_helper_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA {helper_schema};
             CREATE FUNCTION {helper_schema}.northstar_session_recovery_retention(
                 requested_lease UUID,observed_at TIMESTAMPTZ
             ) RETURNS TEXT LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $audit_retention$
             BEGIN
                 RAISE EXCEPTION 'empty-lease capacity audit must not evaluate SM retention'
                     USING ERRCODE='55000';
             END;
             $audit_retention$;
             SET LOCAL search_path=pg_temp,pg_catalog,{helper_schema};"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT NOT EXISTS(SELECT 1 FROM deployment_session_leases)"
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap());
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT current_schema()=(pg_my_temp_schema()::regnamespace)::text"
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap());
    let authority = DeploymentCapacityConfiguration {
        epoch: 1,
        accounts: 64,
        muc_rooms: 64,
        muc_rooms_per_owner: 64,
        live_sessions: 64,
        sessions_per_account: 64,
        resumable_sessions: 64,
    };
    assert!(
        deployment_capacity_authority_is_consistent(&mut tx, authority)
            .await
            .unwrap()
    );
    sqlx::raw_sql(
        "INSERT INTO users(id) VALUES
                 ('00000000-0000-0000-0000-000000000001'),
                 ('00000000-0000-0000-0000-000000000002');
             INSERT INTO sm_resume_sessions(id,user_id) VALUES
                 ('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000001'),
                 ('00000000-0000-0000-0000-000000000012','00000000-0000-0000-0000-000000000001'),
                 ('00000000-0000-0000-0000-000000000013','00000000-0000-0000-0000-000000000002');
             INSERT INTO deployment_capacity_allocations(resource_kind,entity_id,shard) VALUES
                 ('account','00000000-0000-0000-0000-000000000001',0),
                 ('account','00000000-0000-0000-0000-000000000002',1),
                 ('sm_session','00000000-0000-0000-0000-000000000011',0),
                 ('sm_session','00000000-0000-0000-0000-000000000012',1),
                 ('sm_session','00000000-0000-0000-0000-000000000013',2);
             UPDATE deployment_capacity_shards
                SET used=1 WHERE (resource_kind='account' AND shard IN (0,1))
                             OR (resource_kind='sm_session' AND shard IN (0,1,2));
             INSERT INTO deployment_account_capacity(resource_kind,owner_id,used) VALUES
                 ('sm_session','00000000-0000-0000-0000-000000000001',2),
                 ('sm_session','00000000-0000-0000-0000-000000000002',1);",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    assert!(
        deployment_capacity_authority_is_consistent(&mut tx, authority)
            .await
            .unwrap()
    );
    let corruptions = [
        (
            "different entity with unchanged nonempty counts and shard usage",
            "UPDATE deployment_capacity_allocations
                    SET entity_id='00000000-0000-0000-0000-000000000099'
                  WHERE entity_id='00000000-0000-0000-0000-000000000011'",
        ),
        (
            "different kinds with unchanged per-kind counts and shard usage",
            "UPDATE deployment_capacity_allocations
                    SET resource_kind=CASE resource_kind
                        WHEN 'account' THEN 'sm_session' ELSE 'account' END
                  WHERE entity_id IN ('00000000-0000-0000-0000-000000000001',
                                      '00000000-0000-0000-0000-000000000011')",
        ),
        (
            "different owner with unchanged counter count and total usage",
            "UPDATE deployment_account_capacity
                    SET owner_id='00000000-0000-0000-0000-000000000099'
                  WHERE owner_id='00000000-0000-0000-0000-000000000001'",
        ),
        (
            "different counter usage with unchanged nonempty row count",
            "UPDATE deployment_account_capacity SET used=3
                  WHERE owner_id='00000000-0000-0000-0000-000000000001'",
        ),
        (
            "swapped owner usage with unchanged row count and total usage",
            "UPDATE deployment_account_capacity SET used=3-used",
        ),
        (
            "different counter kind with unchanged count and total usage",
            "UPDATE deployment_account_capacity SET resource_kind='live_session'",
        ),
        (
            "missing allocation with its shard counter kept consistent",
            "DELETE FROM deployment_capacity_allocations
                  WHERE entity_id='00000000-0000-0000-0000-000000000013';
                 UPDATE deployment_capacity_shards SET used=0
                  WHERE resource_kind='sm_session' AND shard=2",
        ),
        (
            "extra allocation with its shard counter kept consistent",
            "INSERT INTO deployment_capacity_allocations(resource_kind,entity_id,shard)
                 VALUES('sm_session','00000000-0000-0000-0000-000000000099',3);
                 UPDATE deployment_capacity_shards SET used=1
                  WHERE resource_kind='sm_session' AND shard=3",
        ),
        (
            "missing owner counter while both sets remain nonempty",
            "DELETE FROM deployment_account_capacity
                  WHERE owner_id='00000000-0000-0000-0000-000000000001'",
        ),
        (
            "extra owner counter while both sets remain nonempty",
            "INSERT INTO deployment_account_capacity(resource_kind,owner_id,used)
                 VALUES('sm_session','00000000-0000-0000-0000-000000000099',1)",
        ),
    ];
    for (case, mutation) in corruptions {
        sqlx::query("SAVEPOINT capacity_audit_case")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::raw_sql(mutation).execute(&mut *tx).await.unwrap();
        assert!(
            !deployment_capacity_authority_is_consistent(&mut tx, authority)
                .await
                .unwrap(),
            "audit accepted {case}"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT capacity_audit_case")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("RELEASE SAVEPOINT capacity_audit_case")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(
            deployment_capacity_authority_is_consistent(&mut tx, authority)
                .await
                .unwrap(),
            "baseline did not recover after {case}"
        );
    }
    tx.rollback().await.unwrap();
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn postgres_capacity_fixture_is_atomic_leased_and_idempotent() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("capacity_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let maintenance = crate::services::capacity_maintenance::CapacityMaintenanceService::new(
        crate::db::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository::new(
            pool.clone(),
        ),
    );
    let authority = DeploymentCapacityConfiguration {
        epoch: 1,
        accounts: 1,
        muc_rooms: 64,
        muc_rooms_per_owner: 2,
        live_sessions: 64,
        sessions_per_account: 2,
        resumable_sessions: 64,
    };
    reconcile_deployment_capacity(&pool, authority)
        .await
        .unwrap();
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'capacity-owner','test')")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let account_rejected = sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'capacity-second','test')",
    )
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(is_capacity_sqlx_error(&account_rejected));

    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    for (connection, resource) in [(first, "one"), (second, "two")] {
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            reserve_live_session_in_transaction(
                &mut tx,
                connection,
                user_id,
                &format!("capacity-owner@example.test/{resource}"),
                120,
                false,
            )
            .await
            .unwrap(),
            LiveSessionReservation::Reserved
        );
        tx.commit().await.unwrap();
    }
    let absent = Uuid::new_v4();
    assert_eq!(
        maintenance
            .renew_live_connections(&[first, second, absent], 120)
            .await
            .unwrap(),
        HashSet::from([first, second]),
    );
    let mut elected_peer = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(1314079572,4)")
        .execute(&mut *elected_peer)
        .await
        .unwrap();
    let election =
        tokio::time::timeout(Duration::from_secs(2), maintenance.try_reap_expired(10)).await;
    // Release the peer before asserting, including on a timed-out query.
    tokio::time::timeout(Duration::from_secs(5), elected_peer.rollback())
        .await
        .expect("capacity reaper fixture could not release its peer lock")
        .unwrap();
    assert_eq!(
        election
            .expect("capacity reaper election did not return promptly")
            .unwrap(),
        None
    );

    let mut rejected = pool.begin().await.unwrap();
    assert_eq!(
        reserve_live_session_in_transaction(
            &mut rejected,
            Uuid::new_v4(),
            user_id,
            "capacity-owner@example.test/three",
            120,
            false,
        )
        .await
        .unwrap(),
        LiveSessionReservation::CapacityExhausted
    );
    rejected.rollback().await.unwrap();
    let transferred = Uuid::new_v4();
    let mut transfer = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE deployment_session_leases
                SET connection_id=$2,updated_at=clock_timestamp()
              WHERE connection_id=$1",
    )
    .bind(first)
    .bind(transferred)
    .execute(&mut *transfer)
    .await
    .unwrap();
    transfer.commit().await.unwrap();
    let stable_allocation: bool = sqlx::query_scalar(
        "SELECT EXISTS(
                 SELECT 1 FROM deployment_capacity_allocations
                  WHERE resource_kind='live_session' AND entity_id=$1
             ) AND NOT EXISTS(
                 SELECT 1 FROM deployment_capacity_allocations
                  WHERE resource_kind='live_session' AND entity_id=$2
             )",
    )
    .bind(first)
    .bind(transferred)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(stable_allocation);
    assert!(!release_live_session(&pool, first).await.unwrap());
    assert!(release_live_session(&pool, transferred).await.unwrap());
    assert!(!release_live_session(&pool, transferred).await.unwrap());

    sqlx::query("UPDATE deployment_session_leases SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE connection_id=$1")
        .bind(second)
        .execute(&pool)
        .await
        .unwrap();
    assert!(maintenance
        .renew_live_connections(&[second], 120)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        maintenance
            .try_reap_expired(10)
            .await
            .unwrap()
            .expect("an isolated fixture must acquire the reaper role"),
        1
    );
    let live_owner_counter_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
                 SELECT 1 FROM deployment_account_capacity
                  WHERE resource_kind='live_session' AND owner_id=$1
             )",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!live_owner_counter_exists);

    for localpart in ["room-one", "room-two"] {
        sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id) VALUES($1,$2,$3)")
            .bind(Uuid::new_v4())
            .bind(localpart)
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
    let owner_rejected =
        sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id) VALUES($1,'room-three',$2)")
            .bind(Uuid::new_v4())
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap_err();
    assert!(is_capacity_sqlx_error(&owner_rejected));

    let snapshot = deployment_capacity_snapshot(&pool).await.unwrap();
    assert_eq!(snapshot.accounts_used, 1);
    assert_eq!(snapshot.muc_rooms_used, 2);
    assert_eq!(snapshot.live_sessions_used, 0);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let room_owner_counter_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
                 SELECT 1 FROM deployment_account_capacity
                  WHERE resource_kind='muc_room' AND owner_id=$1
             )",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!room_owner_counter_exists);
    let final_snapshot = deployment_capacity_snapshot(&pool).await.unwrap();
    assert_eq!(final_snapshot.accounts_used, 0);

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}
