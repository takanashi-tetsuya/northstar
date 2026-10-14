use super::*;

fn identity(
    epoch: i64,
    current: &str,
    previous: Option<&str>,
    staged: Option<&str>,
) -> ClusterKeyDeploymentIdentity {
    ClusterKeyDeploymentIdentity {
        xmpp_domain: "example.test".into(),
        node_id: "node-a".into(),
        epoch,
        current_key_id: current.into(),
        current_public_key_sha256: format!("{current}-sha256"),
        previous_key_id: previous.map(str::to_owned),
        previous_public_key_sha256: previous.map(|value| format!("{value}-sha256")),
        staged_next_key_id: staged.map(str::to_owned),
        staged_next_public_key_sha256: staged.map(|value| format!("{value}-sha256")),
    }
}

#[test]
fn authority_accepts_exact_state_and_one_step_overlap_only() {
    let record = ClusterKeyRecord {
        epoch: 4,
        current_key_id: "current".into(),
        current_public_key_sha256: "current-sha256".into(),
        previous_key_id: None,
        previous_public_key_sha256: None,
        staged_next_key_id: None,
        staged_next_public_key_sha256: None,
    };
    assert_eq!(
        decide_reconciliation(&record, &identity(4, "current", None, None)).unwrap(),
        Reconciliation::Compatible
    );
    assert_eq!(
        decide_reconciliation(&record, &identity(4, "current", None, Some("next"))).unwrap(),
        Reconciliation::Prepare
    );
    let prepared = ClusterKeyRecord {
        staged_next_key_id: Some("next".into()),
        staged_next_public_key_sha256: Some("next-sha256".into()),
        ..record.clone()
    };
    assert_eq!(
        decide_reconciliation(&prepared, &identity(5, "next", Some("current"), None)).unwrap(),
        Reconciliation::Activate
    );
    let activated = ClusterKeyRecord {
        epoch: 5,
        current_key_id: "next".into(),
        current_public_key_sha256: "next-sha256".into(),
        previous_key_id: Some("current".into()),
        previous_public_key_sha256: Some("current-sha256".into()),
        staged_next_key_id: None,
        staged_next_public_key_sha256: None,
    };
    assert_eq!(
        decide_reconciliation(&activated, &identity(5, "next", None, None)).unwrap(),
        Reconciliation::Retire
    );
    assert!(authority_configuration_compatible(
        &activated,
        &identity(4, "current", None, Some("next"))
    ));
    assert!(decide_reconciliation(&record, &identity(6, "next", Some("current"), None)).is_err());
    assert!(decide_reconciliation(&record, &identity(4, "other", None, None)).is_err());
}

#[test]
fn active_duplicate_node_fails_and_expired_takeover_advances_instance_epoch() {
    let now = chrono::Utc::now();
    let current = uuid::Uuid::new_v4();
    let duplicate = uuid::Uuid::new_v4();
    assert!(next_instance_epoch(
        Some((
            current,
            7,
            "current-key".into(),
            4,
            now + chrono::Duration::seconds(1),
        )),
        duplicate,
        "current-key",
        4,
        now,
    )
    .is_err());
    assert_eq!(
        next_instance_epoch(
            Some((
                current,
                7,
                "current-key".into(),
                4,
                now - chrono::Duration::seconds(1),
            )),
            duplicate,
            "current-key",
            4,
            now,
        )
        .unwrap(),
        8
    );
    assert_eq!(
        next_instance_epoch(
            Some((
                current,
                7,
                "current-key".into(),
                4,
                now + chrono::Duration::seconds(30),
            )),
            current,
            "current-key",
            4,
            now,
        )
        .unwrap(),
        7
    );
    assert!(next_instance_epoch(
        Some((
            current,
            7,
            "current-key".into(),
            4,
            now + chrono::Duration::seconds(30),
        )),
        current,
        "staged-key",
        5,
        now,
    )
    .is_err());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to a disposable PostgreSQL database; migrates and removes an isolated schema"]
async fn direct_message_fence_locks_exact_key_and_instance_through_commit() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a disposable PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    let schema = format!("direct_fence_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let domain = format!("direct-{suffix}.test");
    let node_id = format!("node-{suffix}");
    let key_identity = ClusterKeyDeploymentIdentity {
        xmpp_domain: domain.clone(),
        node_id: node_id.clone(),
        epoch: 1,
        current_key_id: "AAAAAAAAAAAAAAAA".into(),
        current_public_key_sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        previous_key_id: None,
        previous_public_key_sha256: None,
        staged_next_key_id: None,
        staged_next_public_key_sha256: None,
    };
    reconcile_cluster_key_deployment_before_instance_claim(&pool, &key_identity)
        .await
        .unwrap();
    let instance_uuid = Uuid::new_v4();
    let instance = claim_cluster_node_instance(
        &pool,
        &domain,
        &node_id,
        instance_uuid,
        &key_identity.current_key_id,
        key_identity.epoch,
        Duration::from_secs(90),
    )
    .await
    .unwrap();
    let authority = crate::cluster::ClusterReadinessAuthority {
        key_identity: key_identity.clone(),
        instance_node_id: node_id.clone(),
        instance_uuid,
        instance_epoch: instance.instance_epoch,
        signing_key_id: key_identity.current_key_id.clone(),
        signing_key_epoch: key_identity.epoch,
    };
    let mut tx = pool.begin().await.unwrap();
    fence_direct_message_authority_in_transaction(&mut tx, &authority)
        .await
        .unwrap();
    let barrier_pool = pool.clone();
    let barrier_authority = authority.clone();
    let barrier = tokio::spawn(async move {
        recovery_replay_cutoff_after_direct_commits(&barrier_pool, &barrier_authority).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !barrier.is_finished(),
        "recovery cutoff passed a held direct-message admission"
    );
    let before_commit: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let cutoff = barrier.await.unwrap().unwrap();
    assert!(cutoff >= before_commit);

    let mut tx = pool.begin().await.unwrap();
    fence_direct_message_authority_in_transaction(&mut tx, &authority)
        .await
        .unwrap();
    let release_pool = pool.clone();
    let release_domain = domain.clone();
    let release_node = node_id.clone();
    let release_key = key_identity.current_key_id.clone();
    let release = tokio::spawn(async move {
        release_cluster_node_instance(
            &release_pool,
            &release_domain,
            &release_node,
            instance_uuid,
            instance.instance_epoch,
            &release_key,
            1,
        )
        .await
        .unwrap()
    });
    let key_pool = pool.clone();
    let key_domain = domain.clone();
    let key_node = node_id.clone();
    let key_update = tokio::spawn(async move {
        sqlx::query(
            "UPDATE cluster_key_deployments SET updated_at=clock_timestamp()
                 WHERE xmpp_domain=$1 AND node_id=$2",
        )
        .bind(key_domain)
        .bind(key_node)
        .execute(&key_pool)
        .await
        .unwrap()
        .rows_affected()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !release.is_finished(),
        "instance release passed a held message fence"
    );
    assert!(
        !key_update.is_finished(),
        "key authority update passed a held message fence"
    );
    fence_direct_message_authority_in_transaction(&mut tx, &authority)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(release.await.unwrap());
    assert_eq!(key_update.await.unwrap(), 1);
    let mut stale = pool.begin().await.unwrap();
    assert!(
        fence_direct_message_authority_in_transaction(&mut stale, &authority)
            .await
            .is_err()
    );
    stale.rollback().await.unwrap();

    let mut wrong_key = authority.clone();
    wrong_key.key_identity.current_public_key_sha256 = "wrong".into();
    let mut mismatch = pool.begin().await.unwrap();
    assert!(
        fence_direct_message_authority_in_transaction(&mut mismatch, &wrong_key)
            .await
            .is_err()
    );
    mismatch.rollback().await.unwrap();
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to a disposable migrated PostgreSQL database"]
async fn postgres_fixture_fences_duplicate_rotation_release_and_stale_instance() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a disposable migrated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let domain = format!("cluster-{suffix}.test");
    let node_id = format!("node-{suffix}");
    let old_key = "AAAAAAAAAAAAAAAA";
    let next_key = "BBBBBBBBBBBBBBBB";
    let old_digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let next_digest = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let identity = |epoch,
                    current: &str,
                    current_digest: &str,
                    previous: OptionalKeyMaterial<'_>,
                    staged: OptionalKeyMaterial<'_>| {
        ClusterKeyDeploymentIdentity {
            xmpp_domain: domain.clone(),
            node_id: node_id.clone(),
            epoch,
            current_key_id: current.into(),
            current_public_key_sha256: current_digest.into(),
            previous_key_id: previous.map(|(id, _): (&str, &str)| id.to_owned()),
            previous_public_key_sha256: previous.map(|(_, digest)| digest.to_owned()),
            staged_next_key_id: staged.map(|(id, _): (&str, &str)| id.to_owned()),
            staged_next_public_key_sha256: staged.map(|(_, digest)| digest.to_owned()),
        }
    };
    let initial = identity(1, old_key, old_digest, None, None);
    reconcile_cluster_key_deployment_before_instance_claim(&pool, &initial)
        .await
        .unwrap();
    let first_uuid = uuid::Uuid::new_v4();
    let first = claim_cluster_node_instance(
        &pool,
        &domain,
        &node_id,
        first_uuid,
        old_key,
        1,
        Duration::from_secs(90),
    )
    .await
    .unwrap();
    assert_eq!(first.instance_epoch, 1);
    assert!(claim_cluster_node_instance(
        &pool,
        &domain,
        &node_id,
        uuid::Uuid::new_v4(),
        old_key,
        1,
        Duration::from_secs(90),
    )
    .await
    .is_err());

    let prepared = identity(1, old_key, old_digest, None, Some((next_key, next_digest)));
    reconcile_cluster_key_deployment_before_instance_claim(&pool, &prepared)
        .await
        .unwrap();
    let activated = identity(2, next_key, next_digest, Some((old_key, old_digest)), None);
    reconcile_cluster_key_deployment_before_instance_claim(&pool, &activated)
        .await
        .unwrap();
    assert!(claim_cluster_node_instance(
        &pool,
        &domain,
        &node_id,
        uuid::Uuid::new_v4(),
        next_key,
        2,
        Duration::from_secs(90),
    )
    .await
    .is_err());
    assert!(release_cluster_node_instance(
        &pool,
        &domain,
        &node_id,
        first_uuid,
        first.instance_epoch,
        old_key,
        1,
    )
    .await
    .unwrap());
    let second_uuid = uuid::Uuid::new_v4();
    let second = claim_cluster_node_instance(
        &pool,
        &domain,
        &node_id,
        second_uuid,
        next_key,
        2,
        Duration::from_secs(90),
    )
    .await
    .unwrap();
    assert_eq!(second.instance_epoch, 2);
    assert!(heartbeat_cluster_node_instance(
        &pool,
        ClusterNodeHeartbeat {
            xmpp_domain: &domain,
            node_id: &node_id,
            instance_uuid: first_uuid,
            instance_epoch: first.instance_epoch,
            signing_key_id: old_key,
            signing_key_epoch: 1,
            lease: Duration::from_secs(90),
        },
    )
    .await
    .is_err());

    sqlx::query(
        "UPDATE cluster_key_deployments
             SET updated_at=clock_timestamp() - INTERVAL '30 seconds'
             WHERE xmpp_domain=$1 AND node_id=$2",
    )
    .bind(&domain)
    .bind(&node_id)
    .execute(&pool)
    .await
    .unwrap();
    let retired = identity(2, next_key, next_digest, None, None);
    reconcile_cluster_key_deployment(&pool, &retired)
        .await
        .unwrap();
    validate_cluster_key_deployment(&pool, &retired)
        .await
        .unwrap();
    assert!(release_cluster_node_instance(
        &pool,
        &domain,
        &node_id,
        second_uuid,
        second.instance_epoch,
        next_key,
        2,
    )
    .await
    .unwrap());
}
