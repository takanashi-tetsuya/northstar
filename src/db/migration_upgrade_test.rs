use sqlx::postgres::PgPoolOptions;
use std::borrow::Cow;

// Exact source checksum from b588a0a. It is historical test evidence only;
// it is never accepted as a valid current migration checksum.
const MIGRATION_0132_PRE_FIX_SHA384: &str =
    "878db593eff69e873434c109ed78211f2039fedf36076026a635f69add974f6f5f43c6a062a010ce48c8a102e0cfe6d5";
// Exact corrected source checksum recorded by 6af75a6 and the repository
// ledger manifest.
const MIGRATION_0132_CURRENT_SHA384: &str =
    "3bb9cc8cbda0798d78eb1f22b99a2076bdc6ed321aa59564e7c88faaffe8fbb4b0159ff6a6cc346a1d32769a408d535d";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn migration_0132_current() -> sqlx::migrate::Migration {
    super::MIGRATOR
        .iter()
        .find(|migration| migration.version == 132)
        .cloned()
        .expect("the embedded migration chain must contain 0132")
}

fn migrator_through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            super::MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

fn pre_fix_0132_migrator() -> sqlx::migrate::Migrator {
    let mut migrations = super::MIGRATOR.iter().cloned().collect::<Vec<_>>();
    let migration = migrations
        .iter_mut()
        .find(|migration| migration.version == 132)
        .expect("the embedded migration chain must contain 0132");
    let corrected_arguments = "        migration_schema,\n        migration_schema\n";
    let historical_arguments = "        migration_schema\n";
    let historical_sql = migration
        .sql
        .replacen(corrected_arguments, historical_arguments, 1);
    assert_ne!(
        historical_sql,
        migration.sql.as_ref(),
        "migration 0132 must retain the corrected two-argument format invocation"
    );
    *migration = sqlx::migrate::Migration::new(
        migration.version,
        migration.description.clone(),
        migration.migration_type,
        Cow::Owned(historical_sql),
        migration.no_tx,
    );
    assert_eq!(
        hex_encode(migration.checksum.as_ref()),
        MIGRATION_0132_PRE_FIX_SHA384,
        "the regression fixture must remain the exact b588 pre-fix migration byte stream"
    );
    sqlx::migrate::Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable random PostgreSQL schema prepared at migration 0013"]
async fn baseline_0013_upgrades_through_the_real_domain_migrator() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to the disposable migration-upgrade schema");
    assert!(
        url.contains("/xmpp_test?") && url.contains("search_path%3Dnorthstar_mupgrade_"),
        "migration upgrade test requires its generated xmpp_test schema"
    );

    let pool = PgPoolOptions::new()
        // migrate_for_domain deliberately holds one session-level policy lock
        // while SQLx executes migrations on a second connection. Match the
        // production migrator's minimum viable pool instead of self-deadlocking.
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    super::migrate_for_domain(&pool, "example.test")
        .await
        .unwrap();

    let plaintext_admission_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
          WHERE table_schema=current_schema()
            AND table_name='personal_message_admissions'
            AND column_name='payload_value'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        plaintext_admission_columns, 0,
        "migration 0104 must irreversibly remove the exact personal-message stanza"
    );
    let keyed_identity_columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns
          WHERE table_schema=current_schema()
            AND (
                 (table_name='personal_message_admissions'
                  AND column_name IN ('payload_key_id','payload_mac'))
              OR (table_name='personal_retraction_intents'
                  AND column_name IN ('semantic_key_id','semantic_mac'))
            )",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        keyed_identity_columns, 4,
        "both durable identity tables require keyed evidence columns"
    );
    let keyed_evidence_constraints: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_catalog.pg_constraint AS constraint_definition
          JOIN pg_catalog.pg_class AS relation
            ON relation.oid=constraint_definition.conrelid
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname=current_schema()
           AND constraint_definition.conname IN (
                 'personal_message_admission_payload_evidence_check',
                 'personal_retraction_intent_semantic_evidence_check'
               )",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        keyed_evidence_constraints, 2,
        "current schema must reject partial or mixed legacy/keyed evidence"
    );
    let key_retirement_indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_catalog.pg_index AS index_definition
          JOIN pg_catalog.pg_class AS index_relation
            ON index_relation.oid=index_definition.indexrelid
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid=index_relation.relnamespace
         WHERE namespace.nspname=current_schema()
           AND index_relation.relname IN (
                 'personal_message_admission_payload_key_idx',
                 'personal_retraction_intent_semantic_key_idx'
               )
           AND index_definition.indisvalid
           AND index_definition.indisready",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        key_retirement_indexes, 2,
        "rotation retirement-fence queries require both key-generation indexes"
    );

    let (capability_signatures, _) =
        super::role_attestation::security_definer_capability_manifest().unwrap();
    let security_definers_are_schema_local: bool = sqlx::query_scalar(
        r#"
        WITH expected(signature) AS (
          SELECT signature
            FROM pg_catalog.unnest($1::pg_catalog.text[]) AS manifest(signature)
        ), namespace AS (
          SELECT oid,nspowner,nspname FROM pg_catalog.pg_namespace
           WHERE nspname=pg_catalog.current_schema()
        ), resolved AS (
          SELECT expected.signature,
                 pg_catalog.to_regprocedure(
                   pg_catalog.format('%I.%s',namespace.nspname,expected.signature)
                 ) AS oid
            FROM expected CROSS JOIN namespace
        ), protected AS (
          SELECT resolved.signature,resolved.oid,routine.proowner,routine.prosecdef,
                 routine.prokind,routine.proconfig,routine.proacl,
                 namespace.nspowner,namespace.nspname
            FROM resolved CROSS JOIN namespace
            LEFT JOIN pg_catalog.pg_proc routine
              ON routine.oid=resolved.oid
             AND routine.pronamespace=namespace.oid
        )
        SELECT (SELECT pg_catalog.count(*)=1 FROM namespace)
          AND NOT EXISTS(
            SELECT 1 FROM protected routine
             WHERE routine.oid IS NULL
                OR routine.proowner<>routine.nspowner
                OR NOT routine.prosecdef
                OR routine.prokind<>'f'
                OR routine.proconfig IS DISTINCT FROM ARRAY[
                     pg_catalog.format(
                       'search_path=pg_catalog, %I, pg_temp',routine.nspname
                     )
                   ]::pg_catalog.text[]
                OR EXISTS(
                  SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                    routine.proacl,
                    pg_catalog.acldefault('f',routine.proowner)
                  )) privilege
                   WHERE privilege.grantee=0
                     AND privilege.privilege_type='EXECUTE'
                )
          )
          AND NOT EXISTS(
            SELECT 1 FROM namespace
            JOIN pg_catalog.pg_proc actual
              ON actual.pronamespace=namespace.oid AND actual.prosecdef
            LEFT JOIN resolved expected ON expected.oid=actual.oid
             WHERE expected.oid IS NULL
          )
        "#,
    )
    .bind(&capability_signatures)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        security_definers_are_schema_local,
        "the canonical SECURITY DEFINER manifest must be exact, migrator-owned, PUBLIC-inaccessible, and pinned to pg_catalog/current_schema/pg_temp"
    );

    let projection_finalizers_are_schema_safe: bool = sqlx::query_scalar(
        r#"
        WITH expected(name) AS (
          VALUES
            ('preserve_personal_message_archive_identity'),
            ('preserve_personal_message_delivery_identity'),
            ('preserve_personal_message_s2s_identity')
        ), resolved AS (
          SELECT pg_catalog.to_regprocedure(
                   pg_catalog.format('%I.%I()', pg_catalog.current_schema(), name)
                 ) AS oid
            FROM expected
        )
        SELECT pg_catalog.count(routine.oid) = 3
           AND COALESCE(
                 pg_catalog.bool_and(namespace.nspname = pg_catalog.current_schema()),
                 false
               )
           AND COALESCE(pg_catalog.bool_and(NOT routine.prosecdef), false)
           AND COALESCE(
                 pg_catalog.bool_and(
                   routine.proconfig @> ARRAY[
                     pg_catalog.format(
                       'search_path=pg_catalog, %I, pg_temp',
                       pg_catalog.current_schema()
                     )
                   ]
                 ),
                 false
               )
          FROM resolved
          LEFT JOIN pg_catalog.pg_proc AS routine ON routine.oid = resolved.oid
          LEFT JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = routine.pronamespace
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        projection_finalizers_are_schema_safe,
        "all personal admission projection finalizers must be schema-local invokers with a fixed installation path"
    );

    let data_lifecycle_routines_are_schema_safe: bool = sqlx::query_scalar(
        r#"
        WITH expected(signature) AS (
          VALUES
            ('release_offline_message_admission_capacity()'),
            ('detach_delivered_offline_message_admission()'),
            ('preserve_held_offline_message()'),
            ('protect_held_data_record()'),
            ('protect_legal_hold_subject_delete()'),
            ('enforce_legal_hold_history()'),
            ('prevent_legal_hold_link_mutation()'),
            ('enforce_audit_log_immutability()')
        ), resolved AS (
          SELECT pg_catalog.to_regprocedure(
                   pg_catalog.format('%I.%s',pg_catalog.current_schema(),signature)
                 ) AS oid
            FROM expected
        )
        SELECT pg_catalog.count(routine.oid) = 8
           AND COALESCE(pg_catalog.bool_and(NOT routine.prosecdef),false)
           AND COALESCE(
                 pg_catalog.bool_and(
                   routine.proconfig = ARRAY[
                     pg_catalog.format(
                       'search_path=pg_catalog, %I, pg_temp',
                       pg_catalog.current_schema()
                     )
                   ]
                 ),
                 false
               )
          FROM resolved
          LEFT JOIN pg_catalog.pg_proc AS routine ON routine.oid=resolved.oid
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        data_lifecycle_routines_are_schema_safe,
        "lifecycle guards and offline-admission routines must remain invokers pinned to their isolated installation schema"
    );

    let cleanup_markers_require_relation_owner: bool = sqlx::query_scalar(
        r#"
        WITH expected(signature) AS (
          VALUES
            ('prevent_legal_hold_link_mutation()'),
            ('enforce_audit_log_immutability()'),
            ('enforce_governance_export_lease_history()'),
            ('reject_cluster_muc_operation_mutation()')
        ), resolved AS (
          SELECT pg_catalog.to_regprocedure(
                   pg_catalog.format('%I.%s',pg_catalog.current_schema(),signature)
                 ) AS oid
            FROM expected
        )
        SELECT pg_catalog.count(routine.oid)=4
           AND COALESCE(pg_catalog.bool_and(NOT routine.prosecdef),false)
           AND COALESCE(pg_catalog.bool_and(
                 pg_catalog.pg_get_userbyid(routine.proowner)=CURRENT_USER
               ),false)
           AND COALESCE(pg_catalog.bool_and(
                 pg_catalog.strpos(pg_catalog.pg_get_functiondef(routine.oid),'TG_RELID')>0
                 AND pg_catalog.strpos(pg_catalog.pg_get_functiondef(routine.oid),'relowner')>0
               ),false)
          FROM resolved
          LEFT JOIN pg_catalog.pg_proc routine ON routine.oid=resolved.oid
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        cleanup_markers_require_relation_owner,
        "all cleanup markers must remain invoker guards bound to their exact protected relation owner"
    );

    let application_functions_are_uniformly_pinned: bool = sqlx::query_scalar(
        r#"
        WITH application_functions AS (
          SELECT routine.*
            FROM pg_catalog.pg_proc routine
            JOIN pg_catalog.pg_namespace proc_namespace
              ON proc_namespace.oid=routine.pronamespace
            JOIN pg_catalog.pg_language proc_language
              ON proc_language.oid=routine.prolang
           WHERE proc_namespace.nspname=pg_catalog.current_schema()
             AND routine.prokind='f'
             AND proc_language.lanname IN ('plpgsql','sql')
             AND NOT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_depend dependency
                  WHERE dependency.classid='pg_catalog.pg_proc'::pg_catalog.regclass
                    AND dependency.objid=routine.oid
                    AND dependency.deptype='e'
             )
        )
        SELECT pg_catalog.count(*) > 0
           AND pg_catalog.bool_and(
                 pg_catalog.pg_get_userbyid(routine.proowner)=CURRENT_USER
               )
           AND pg_catalog.bool_and(
                 routine.proconfig @> ARRAY[
                   pg_catalog.format(
                     'search_path=pg_catalog, %I, pg_temp',
                     pg_catalog.current_schema()
                   )
                 ]
               )
           AND pg_catalog.bool_and(
                 (SELECT pg_catalog.count(*)=1
                    FROM pg_catalog.unnest(
                           COALESCE(
                             routine.proconfig,
                             ARRAY[]::pg_catalog.text[]
                           )
                         ) AS config(setting)
                   WHERE config.setting LIKE 'search_path=%')
               )
          FROM application_functions routine
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        application_functions_are_uniformly_pinned,
        "every non-extension application SQL/PLpgSQL function must be migrator-owned and have exactly one fixed installation search_path"
    );

    let archive_fks_set_null_without_losing_deferred_atomicity: bool = sqlx::query_scalar(
        r#"
        SELECT pg_catalog.count(*) = 2
           AND pg_catalog.bool_and(fk_constraint.confdeltype = 'n')
           AND pg_catalog.bool_and(fk_constraint.condeferrable)
           AND pg_catalog.bool_and(fk_constraint.condeferred)
          FROM pg_catalog.pg_constraint AS fk_constraint
          JOIN pg_catalog.pg_class AS relation ON relation.oid=fk_constraint.conrelid
          JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname=pg_catalog.current_schema()
           AND relation.relname='personal_message_admissions'
           AND fk_constraint.conname IN (
                 'personal_message_admissions_sender_archive_fk',
                 'personal_message_admissions_recipient_archive_fk'
               )
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        archive_fks_set_null_without_losing_deferred_atomicity,
        "personal MAM projections must use deferred ON DELETE SET NULL ownership"
    );

    let archive_projection_indexes_exist: bool = sqlx::query_scalar(
        r#"
        WITH expected(name,column_name,predicate) AS (
          VALUES
            ('personal_message_admission_sender_archive_idx',
             'sender_archive_id','(sender_archive_id IS NOT NULL)'),
            ('personal_message_admission_recipient_archive_idx',
             'recipient_archive_id','(recipient_archive_id IS NOT NULL)')
        )
        SELECT pg_catalog.count(index_relation.oid) = 2
           AND pg_catalog.bool_and(index_definition.indisvalid)
           AND pg_catalog.bool_and(index_definition.indisready)
           AND pg_catalog.bool_and(index_definition.indnkeyatts = 1)
           AND pg_catalog.bool_and(attribute.attname = expected.column_name)
           AND pg_catalog.bool_and(
                 pg_catalog.pg_get_expr(
                   index_definition.indpred,
                   index_definition.indrelid
                 ) = expected.predicate
               )
          FROM expected
          JOIN pg_catalog.pg_class AS index_relation
            ON index_relation.relname=expected.name
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid=index_relation.relnamespace
           AND namespace.nspname=pg_catalog.current_schema()
          JOIN pg_catalog.pg_index AS index_definition
            ON index_definition.indexrelid=index_relation.oid
          JOIN pg_catalog.pg_attribute AS attribute
            ON attribute.attrelid=index_definition.indrelid
           AND attribute.attnum=index_definition.indkey[0]
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        archive_projection_indexes_exist,
        "both MAM projection finalizers require valid one-column partial lookup indexes"
    );

    // Invoke the archive finalizer with a caller path that deliberately omits
    // the installation schema. TG_TABLE_SCHEMA must still bind the update to
    // the same isolated schema as the deleted archive.
    let migration_schema: String = sqlx::query_scalar("SELECT current_schema()::TEXT")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(migration_schema.starts_with("northstar_mupgrade_"));
    let archive_id = uuid::Uuid::new_v4();
    let admission_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
         VALUES($1,'00000000-0000-0000-0000-000000000001',
                'bob@example.test','bob@example.test/device','<message/>',TRUE)",
    )
    .bind(archive_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO personal_message_admissions(
             id,identity_kind,actor_scope_raw,actor_scope,target_scope,
             identity_value,identity_digest,payload_key_id,payload_mac,
             sender_archive_id
         ) VALUES(
             $1,'local-origin','alice@example.test','alice@example.test',
             'bob@example.test','isolated-projection-delete',
             decode(repeat('71',32),'hex'),'AAAAAAAAAAAAAAAA',
             decode(repeat('72',32),'hex'),$2
         )",
    )
    .bind(admission_id)
    .bind(archive_id)
    .execute(&pool)
    .await
    .unwrap();
    let offline_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted)
         VALUES($1,'00000000-0000-0000-0000-000000000002',
                'alice@example.test/device','<message/>',TRUE)",
    )
    .bind(offline_id)
    .execute(&pool)
    .await
    .unwrap();
    let quoted_schema = migration_schema.replace('"', "\"\"");
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL search_path=pg_catalog,pg_temp")
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(&format!(
        "DELETE FROM \"{quoted_schema}\".message_archive WHERE id=$1"
    ))
    .bind(archive_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    let isolated_projection_state = sqlx::query_as::<_, (Option<uuid::Uuid>, bool)>(&format!(
        "SELECT sender_archive_id,delivery_completed_at IS NOT NULL FROM \"{quoted_schema}\".personal_message_admissions WHERE id=$1"
    ))
    .bind(admission_id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(isolated_projection_state, (None, true));

    // A BEFORE UPDATE trigger must return NEW. Migration 0087 returned OLD,
    // which made UPDATE RETURNING claim success while silently discarding the
    // delivery fence that a later acknowledgement depended on.
    let claim_id = uuid::Uuid::new_v4();
    let returned_claim: Option<uuid::Uuid> = sqlx::query_scalar(&format!(
        "UPDATE \"{quoted_schema}\".offline_messages
            SET delivery_claim_id=$2,
                delivery_claim_expires_at=pg_catalog.clock_timestamp()+INTERVAL '30 seconds'
          WHERE id=$1
          RETURNING delivery_claim_id"
    ))
    .bind(offline_id)
    .bind(claim_id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(returned_claim, Some(claim_id));
    let stored_claim: Option<uuid::Uuid> = sqlx::query_scalar(&format!(
        "SELECT delivery_claim_id FROM \"{quoted_schema}\".offline_messages WHERE id=$1"
    ))
    .bind(offline_id)
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(stored_claim, Some(claim_id));
    sqlx::query(&format!(
        "DELETE FROM \"{quoted_schema}\".offline_messages WHERE id=$1"
    ))
    .bind(offline_id)
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    sqlx::query("DELETE FROM personal_message_admissions WHERE id=$1")
        .bind(admission_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable empty PostgreSQL schema"]
async fn migration_0132_pre_fix_failure_leaves_no_ledger_row_and_current_checksum_is_enforced() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to the disposable migration-0132 schema");
    assert!(
        url.contains("/xmpp_test?") && url.contains("search_path%3Dnorthstar_m0132_"),
        "migration 0132 integrity test requires its generated xmpp_test schema"
    );

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    let existing_relations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_schema()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        existing_relations, 0,
        "the migration 0132 fixture must begin with an empty isolated schema"
    );

    // Apply the exact real migration chain through 0131. This creates the
    // upgrade state that existed immediately before the faulty 0132 source was
    // introduced, without inventing a synthetic ledger entry.
    let through_0131 = migrator_through(131);
    let expected_0131_rows = i64::try_from(through_0131.iter().count()).unwrap();
    through_0131.run(&pool).await.unwrap();
    let staged_state: (i64, Option<i64>, bool) = sqlx::query_as(
        "SELECT COUNT(*),MAX(version),COALESCE(bool_and(success),FALSE) FROM _sqlx_migrations",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(staged_state, (expected_0131_rows, Some(131), true));

    let current_0132 = migration_0132_current();
    assert_eq!(
        hex_encode(current_0132.checksum.as_ref()),
        MIGRATION_0132_CURRENT_SHA384,
        "the embedded migration source and reviewed current 0132 checksum drifted"
    );
    let pre_fix = pre_fix_0132_migrator();
    let pre_fix_checksum = pre_fix
        .iter()
        .find(|migration| migration.version == 132)
        .expect("the pre-fix fixture must contain 0132")
        .checksum
        .as_ref()
        .to_vec();

    // The b588 body fails inside its normal transactional migration before
    // SQLx can insert a successful ledger record. This establishes the local
    // recovery invariant; it deliberately does not claim anything about an
    // independently administered database that has not been inspected.
    let pre_fix_error = pre_fix.run(&pool).await.unwrap_err();
    assert!(
        pre_fix_error
            .to_string()
            .contains("too few arguments for format()"),
        "the reconstructed pre-fix migration failed for an unexpected reason: {pre_fix_error}"
    );
    let failed_attempt_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version=132")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        failed_attempt_rows, 0,
        "a transactional 0132 failure must not leave a dirty or successful ledger row"
    );

    // The corrected source must then upgrade the real 0131 state, and a
    // repeated run must be a checksum-validated no-op.
    super::MIGRATOR.run(&pool).await.unwrap();
    super::MIGRATOR.run(&pool).await.unwrap();
    let final_state: (i64, Option<i64>, bool) = sqlx::query_as(
        "SELECT COUNT(*),MAX(version),COALESCE(bool_and(success),FALSE) FROM _sqlx_migrations",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        final_state,
        (
            i64::try_from(super::MIGRATOR.iter().count()).unwrap(),
            Some(132),
            true
        )
    );

    let routine_is_schema_local_invoker: bool = sqlx::query_scalar(
        r#"
        SELECT COALESCE((
          SELECT NOT routine.prosecdef
             AND routine.proconfig=ARRAY[
                   pg_catalog.format(
                     'search_path=pg_catalog, %I, pg_temp',
                     pg_catalog.current_schema()
                   )
                 ]::pg_catalog.text[]
            FROM pg_catalog.pg_proc AS routine
           WHERE routine.oid=pg_catalog.to_regprocedure(
                   pg_catalog.format(
                     '%I.check_pubsub_collection_edge()',
                     pg_catalog.current_schema()
                   )
                 )
        ),FALSE)
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        routine_is_schema_local_invoker,
        "migration 0132 must pin the PubSub collection-edge guard to its installation schema without granting definer authority"
    );

    let old_checksum_success_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM _sqlx_migrations
          WHERE version=132
            AND success
            AND pg_catalog.encode(checksum,'hex')=$1",
    )
    .bind(MIGRATION_0132_PRE_FIX_SHA384)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        old_checksum_success_rows, 0,
        "the current isolated ledger must not accept the pre-fix 0132 checksum"
    );

    // Simulate only the historical checksum in an otherwise successful
    // isolated ledger. SQLx must reject it rather than silently rewriting the
    // row, then accept an explicit restoration of the reviewed checksum.
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=132")
        .bind(&pre_fix_checksum)
        .execute(&pool)
        .await
        .unwrap();
    let mismatch = super::MIGRATOR.run(&pool).await.unwrap_err();
    assert!(
        matches!(mismatch, sqlx::migrate::MigrateError::VersionMismatch(132)),
        "the current migrator must reject a successful 0132 row with the pre-fix checksum: {mismatch}"
    );
    sqlx::query("UPDATE _sqlx_migrations SET checksum=$1 WHERE version=132")
        .bind(current_0132.checksum.as_ref())
        .execute(&pool)
        .await
        .unwrap();
    super::MIGRATOR.run(&pool).await.unwrap();
}
