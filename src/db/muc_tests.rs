use super::{
    admit_federated_muc_invite, admit_local_muc_invite, admit_muc_discussion,
    authorized_muc_admin_affiliation_list, authorized_muc_admin_role_list, cancel_locked_muc_room,
    delete_expired_locked_muc_room, get_or_create_muc_room, hash_muc_password,
    install_muc_authorization_test_pause, muc_history_since, muc_origin_digest, muc_reserved_nick,
    muc_room, public_muc_room_page, register_local_muc_member,
    retract_muc_message_and_archive_action, set_federated_muc_affiliation, set_local_muc_subject,
    set_muc_affiliation, set_muc_affiliations_batch, unregister_local_muc_member,
    update_muc_config, verify_muc_password, DurableMucInviteOutcome, MucActorAuthority,
    MucActorPrincipal, MucAdminSnapshot, MucAffiliationBatchOutcome, MucAffiliationChange,
    MucAffiliationOutcome, MucAffiliationTarget, MucConfigUpdate, MucConfigurationOutcome,
    MucDiscussion, MucDiscussionAdmission, MucRegistrationOutcome, MucRetractionKind,
    MucRetractionMutation, MucRetractionOutcome, MucSubjectMutation, MucSubjectOutcome,
};
use crate::db::{OfflineStorePolicy, S2sOutboxPolicy};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use uuid::Uuid;

fn register_isolated_schema_for_harness(schema: &str, owner_token: &str) {
    let log_path = std::env::var_os("XMPP_TEST_CREATED_SCHEMA_LOG").expect(
        "run this ignored database test through scripts/muc-db-wsl.sh so its schema can be recovered after interruption",
    );
    let mut log = OpenOptions::new()
        .append(true)
        .open(log_path)
        .expect("open the harness-owned schema recovery log");
    let record = format!("{schema} {owner_token}\n");
    log.write_all(record.as_bytes())
        .expect("record the isolated MUC test schema");
    log.sync_all()
        .expect("durably flush the isolated MUC test schema record");
}

async fn create_harness_owned_schema(admin: &sqlx::PgPool, schema: &str) {
    let owner_token = Uuid::new_v4().simple().to_string();
    register_isolated_schema_for_harness(schema, &owner_token);
    let mut transaction = admin.begin().await.unwrap();
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query(&format!(
        "CREATE TABLE {schema}.northstar_test_schema_guard \
         (singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton), token TEXT NOT NULL)"
    ))
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO {schema}.northstar_test_schema_guard(token) VALUES($1)"
    ))
    .bind(owner_token)
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}

async fn await_authorization_pause(entered: &Arc<tokio::sync::Notify>, operation: &str) {
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap_or_else(|_| panic!("MUC authorization pause was not reached: {operation}"));
}

fn local_process_authority<'a>(
    room_epoch: Uuid,
    user_id: Uuid,
    actor_scope: &'a str,
    full_jid: &'a str,
    nick: &'a str,
    role: &'a str,
    affiliation: &'a str,
) -> MucActorAuthority<'a> {
    MucActorAuthority {
        clustered: false,
        expected_room_epoch: room_epoch,
        principal: MucActorPrincipal::Local {
            user_id,
            local_domain: "local.test",
        },
        actor_scope,
        full_jid,
        nick,
        occupant_incarnation: Uuid::nil(),
        connection_uuid: Uuid::nil(),
        expected_role: role,
        expected_affiliation: affiliation,
        cluster_target: None,
    }
}

fn federated_process_authority<'a>(
    room_epoch: Uuid,
    actor_scope: &'a str,
    full_jid: &'a str,
    nick: &'a str,
    authenticated_domain: &'a str,
) -> MucActorAuthority<'a> {
    MucActorAuthority {
        clustered: false,
        expected_room_epoch: room_epoch,
        principal: MucActorPrincipal::Federated {
            bare_jid: actor_scope,
            authenticated_domain,
        },
        actor_scope,
        full_jid,
        nick,
        occupant_incarnation: Uuid::nil(),
        connection_uuid: Uuid::nil(),
        expected_role: "participant",
        expected_affiliation: "none",
        cluster_target: None,
    }
}

#[test]
fn room_passwords_are_argon2_hashed_and_verified() {
    let hash = hash_muc_password("cauldron burn").unwrap();
    assert!(hash.starts_with("$argon2"));
    assert!(!hash.contains("cauldron burn"));
    assert!(verify_muc_password(&hash, "cauldron burn"));
    assert!(!verify_muc_password(&hash, "wrong"));
}

#[test]
fn room_password_validation_rejects_empty_and_oversized_values() {
    assert!(hash_muc_password("").is_err());
    assert!(hash_muc_password(&"x".repeat(1025)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn locked_room_configuration_is_atomic_restart_safe_and_bounded() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("muc_lifecycle_test_{}", Uuid::new_v4().simple());
    create_harness_owned_schema(&admin, &schema).await;
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(Duration::from_secs(60))
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

    let alice_id = Uuid::new_v4();
    let bob_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES
         ($1,'lock-alice','test'),($2,'lock-bob','test')",
    )
    .bind(alice_id)
    .bind(bob_id)
    .execute(&pool)
    .await
    .unwrap();
    let alice = "lock-alice@local.test/Phone";
    let bob = "lock-bob@local.test/Tablet";
    let (room, created) = get_or_create_muc_room(&pool, "locked", alice_id, alice)
        .await
        .unwrap();
    assert!(created);
    assert!(room.is_locked());
    assert!(room.can_configure_locked_room(alice, chrono::Utc::now()));
    assert!(!room.can_configure_locked_room(bob, chrono::Utc::now()));
    assert!(public_muc_room_page(&pool, None, None, 100)
        .await
        .unwrap()
        .unwrap()
        .rooms
        .is_empty());

    // A racing second creator observes the locked row and cannot acquire
    // either creation ownership or a visibility window.
    let (same_room, second_created) = get_or_create_muc_room(&pool, "locked", bob_id, bob)
        .await
        .unwrap();
    assert!(!second_created);
    assert_eq!(same_room.id, room.id);
    assert_eq!(same_room.configuration_owner_jid.as_deref(), Some(alice));

    // Recreate the application pool to model a process restart.  The
    // durable lease and exact full-JID authorization survive it.
    pool.close().await;
    let restart_schema = schema.clone();
    let restarted = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {restart_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let after_restart = muc_room(&restarted, "locked").await.unwrap().unwrap();
    assert_eq!(
        after_restart.configuration_owner_jid.as_deref(),
        Some(alice)
    );
    let defaults = |persistent| MucConfigUpdate {
        title: Some("Locked room"),
        description: None,
        persistent,
        members_only: false,
        public: true,
        moderated: false,
        non_anonymous: true,
        max_occupants: 100,
        password_hash: None,
        allow_subject_change: false,
        allow_invites: true,
        allow_private_messages: true,
        logging_enabled: true,
        allow_registration: true,
    };
    assert_eq!(
        update_muc_config(&restarted, room.id, bob, defaults(false))
            .await
            .unwrap(),
        MucConfigurationOutcome::LockedByAnother
    );
    assert_eq!(
        update_muc_config(&restarted, room.id, alice, defaults(true))
            .await
            .unwrap(),
        MucConfigurationOutcome::Applied
    );
    let active = muc_room(&restarted, "locked").await.unwrap().unwrap();
    assert!(!active.is_locked());
    assert!(active.persistent);
    assert_eq!(
        public_muc_room_page(&restarted, None, None, 100)
            .await
            .unwrap()
            .unwrap()
            .rooms
            .len(),
        1
    );

    assert_eq!(
        set_muc_affiliations_batch(
            &restarted,
            room.id,
            &[
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                    affiliation: "member".to_owned(),
                },
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("lock-bob".to_owned()),
                    affiliation: "owner".to_owned(),
                },
                MucAffiliationChange {
                    target: MucAffiliationTarget::FederatedBareJid("admin@remote.test".to_owned(),),
                    affiliation: "admin".to_owned(),
                },
            ],
        )
        .await
        .unwrap(),
        MucAffiliationBatchOutcome::Applied
    );
    assert_eq!(
        super::muc_affiliation(&restarted, room.id, bob_id)
            .await
            .unwrap()
            .as_deref(),
        Some("owner")
    );
    assert_eq!(
        super::federated_muc_affiliation(&restarted, room.id, "admin@remote.test")
            .await
            .unwrap()
            .as_deref(),
        Some("admin")
    );

    // A multi-item request that would remove the final owner rolls back
    // every local and federated item rather than exposing a prefix.
    assert_eq!(
        set_muc_affiliations_batch(
            &restarted,
            room.id,
            &[
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("lock-bob".to_owned()),
                    affiliation: "member".to_owned(),
                },
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                    affiliation: "none".to_owned(),
                },
                MucAffiliationChange {
                    target: MucAffiliationTarget::FederatedBareJid("admin@remote.test".to_owned(),),
                    affiliation: "none".to_owned(),
                },
            ],
        )
        .await
        .unwrap(),
        MucAffiliationBatchOutcome::LastOwner
    );
    assert_eq!(
        super::muc_affiliation(&restarted, room.id, bob_id)
            .await
            .unwrap()
            .as_deref(),
        Some("owner")
    );
    assert_eq!(
        super::muc_affiliation(&restarted, room.id, alice_id)
            .await
            .unwrap()
            .as_deref(),
        Some("member")
    );

    // A missing or repeated target is rejected before any mutation.
    for (changes, outcome) in [
        (
            vec![
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                    affiliation: "admin".to_owned(),
                },
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("missing".to_owned()),
                    affiliation: "member".to_owned(),
                },
            ],
            MucAffiliationBatchOutcome::MissingTarget,
        ),
        (
            vec![
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                    affiliation: "admin".to_owned(),
                },
                MucAffiliationChange {
                    target: MucAffiliationTarget::LocalUsername("lock-alice".to_owned()),
                    affiliation: "member".to_owned(),
                },
            ],
            MucAffiliationBatchOutcome::DuplicateTarget,
        ),
    ] {
        assert_eq!(
            set_muc_affiliations_batch(&restarted, room.id, &changes)
                .await
                .unwrap(),
            outcome
        );
        assert_eq!(
            super::muc_affiliation(&restarted, room.id, alice_id)
                .await
                .unwrap()
                .as_deref(),
            Some("member")
        );
    }

    let (cancelled, _) = get_or_create_muc_room(&restarted, "cancelled", alice_id, alice)
        .await
        .unwrap();
    assert!(!cancel_locked_muc_room(&restarted, cancelled.id, bob)
        .await
        .unwrap());
    assert!(cancel_locked_muc_room(&restarted, cancelled.id, alice)
        .await
        .unwrap());
    assert!(muc_room(&restarted, "cancelled").await.unwrap().is_none());

    let (expired, _) = get_or_create_muc_room(&restarted, "expired", alice_id, alice)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE muc_rooms SET configuration_expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
    )
    .bind(expired.id)
    .execute(&restarted)
    .await
    .unwrap();
    assert!(delete_expired_locked_muc_room(&restarted, expired.id)
        .await
        .unwrap());
    assert!(muc_room(&restarted, "expired").await.unwrap().is_none());

    restarted.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn durable_invitation_admission_is_atomic_under_injected_failures() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("muc_invite_test_{}", uuid::Uuid::new_v4().simple());
    create_harness_owned_schema(&admin, &schema).await;
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(60))
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

    for statement in [
        "CREATE TABLE users(id UUID PRIMARY KEY, username TEXT NOT NULL UNIQUE, is_disabled BOOLEAN NOT NULL DEFAULT FALSE)",
        // Keep the fixture aligned with the complete retention/legal-hold
        // authority read performed by `admit_local_muc_invite`. PostgreSQL
        // resolves every relation in that statement even when this test
        // has no active policy or hold rows, so omitting one turns a valid
        // admission into a schema error before the transaction invariant
        // under test is reached.
        "CREATE TABLE user_retention_policies(user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, offline_message_days INTEGER CHECK (offline_message_days BETWEEN 1 AND 36500))",
        "CREATE TABLE legal_holds(id UUID PRIMARY KEY, released_at TIMESTAMPTZ)",
        "CREATE TABLE legal_hold_offline_messages(hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT, message_id UUID NOT NULL, PRIMARY KEY(hold_id,message_id))",
        "CREATE TABLE legal_hold_scopes(hold_id UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT, scope_type VARCHAR(40) NOT NULL CHECK (scope_type IN ('personal_archive_owner','muc_archive_room','offline_message_recipient','report_evidence_report')), subject_id UUID NOT NULL, PRIMARY KEY(hold_id,scope_type,subject_id))",
        "CREATE TABLE muc_affiliations(room_id UUID NOT NULL, user_id UUID NOT NULL, affiliation TEXT NOT NULL, reserved_nick VARCHAR(128), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(room_id,user_id))",
        "CREATE TABLE muc_external_affiliations(room_id UUID NOT NULL, jid TEXT NOT NULL, affiliation TEXT NOT NULL, reserved_nick VARCHAR(128), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(room_id,jid))",
        "CREATE TABLE offline_messages(id UUID PRIMARY KEY, recipient_id UUID NOT NULL, sender_jid TEXT NOT NULL, stanza TEXT NOT NULL, target_resource VARCHAR(1023), encrypted BOOLEAN NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), delivery_claim_id UUID, delivery_claim_expires_at TIMESTAMPTZ)",
        "CREATE TABLE sm_resume_stanzas(delivery_message_id UUID)",
        "CREATE TABLE bosh_delivery_fences(message_id UUID)",
        "CREATE TABLE s2s_outbox(id UUID PRIMARY KEY, target_domain TEXT NOT NULL, bounce_to TEXT, stanza TEXT NOT NULL, dedupe_hash BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL, next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), attempt_count INTEGER NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ, lock_token UUID, last_error TEXT, enqueue_sequence BIGINT GENERATED BY DEFAULT AS IDENTITY, UNIQUE(target_domain,dedupe_hash))",
    ] {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    let room_id = uuid::Uuid::new_v4();
    let recipient_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username) VALUES($1,'invitee')")
        .bind(recipient_id)
        .execute(&pool)
        .await
        .unwrap();
    let local_policy = OfflineStorePolicy {
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: false,
    };
    let s2s_policy = S2sOutboxPolicy {
        ttl_seconds: 300,
        max_rows: 100,
        max_bytes: 1_000_000,
        max_per_domain: 100,
    };

    sqlx::query(
        "CREATE FUNCTION fail_invite_offline() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced offline admission failure'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER fail_invite_offline BEFORE INSERT ON offline_messages FOR EACH ROW EXECUTE FUNCTION fail_invite_offline()")
        .execute(&pool)
        .await
        .unwrap();
    assert!(admit_local_muc_invite(
        &pool,
        Uuid::new_v4(),
        room_id,
        recipient_id,
        "invitee@local.test",
        "room@conference.local.test",
        "<message id='local-failure' to='invitee@local.test'/>",
        false,
        local_policy,
        None,
    )
    .await
    .is_err());
    let local_halves: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM muc_affiliations), (SELECT COUNT(*) FROM offline_messages)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(local_halves, (0, 0));
    sqlx::query("DROP TRIGGER fail_invite_offline ON offline_messages")
        .execute(&pool)
        .await
        .unwrap();

    let offline_id = Uuid::new_v4();
    let local_invitation = format!(
        "<message from='room@conference.local.test' to='invitee@local.test' type='normal'><stanza-id xmlns='urn:xmpp:sid:0' by='invitee@local.test' id='{offline_id}'/></message>"
    );
    let admitted_offline_id = match admit_local_muc_invite(
        &pool,
        offline_id,
        room_id,
        recipient_id,
        "invitee@local.test",
        "room@conference.local.test",
        &local_invitation,
        false,
        local_policy,
        None,
    )
    .await
    .unwrap()
    {
        DurableMucInviteOutcome::Stored {
            id,
            affiliation_changed,
        } => {
            assert!(
                affiliation_changed,
                "first invite must create the member affiliation"
            );
            id
        }
        outcome => panic!("unexpected local admission outcome: {outcome:?}"),
    };
    let local_halves: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM muc_affiliations WHERE affiliation='member'), (SELECT COUNT(*) FROM offline_messages)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(local_halves, (1, 1));
    assert_eq!(admitted_offline_id, offline_id);
    // Accepting a mediated invitation into a connection queue is not a
    // delivery acknowledgement. Simulate a disconnect before socket
    // write: the exact durable item is dropped, but its spool row remains
    // available for a later transport to complete.
    let local_delivery = crate::outbound::DurableDelivery {
        recipient_id,
        message_id: offline_id,
        claim_id: None,
    };
    let (local_tx, mut local_rx) = tokio::sync::mpsc::channel(1);
    crate::outbound::OutboundSender::new(local_tx)
        .try_send_durable(local_invitation, local_delivery)
        .unwrap();
    let queued = local_rx.recv().await.unwrap();
    assert_eq!(queued.c2s_delivery(), Some(local_delivery));
    drop(queued);
    drop(local_rx);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(offline_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    crate::db::replay::acknowledge_durable_delivery(&pool, local_delivery)
        .await
        .unwrap();
    let repeated_invite_id = Uuid::new_v4();
    let federated_invitation = format!(
        "<message from='room@conference.local.test' to='invitee@local.test' type='normal'><x xmlns='http://jabber.org/protocol/muc#user'><invite from='alice@remote.test/device'/></x><stanza-id xmlns='urn:xmpp:sid:0' by='invitee@local.test' id='{repeated_invite_id}'/></message>"
    );
    let admitted_repeated_invite_id = match admit_local_muc_invite(
        &pool,
        repeated_invite_id,
        room_id,
        recipient_id,
        "invitee@local.test",
        "room@conference.local.test",
        &federated_invitation,
        false,
        local_policy,
        None,
    )
    .await
    .unwrap()
    {
        DurableMucInviteOutcome::Stored {
            id,
            affiliation_changed,
        } => {
            assert!(
                !affiliation_changed,
                "repeated invite must not recreate membership"
            );
            id
        }
        outcome => panic!("unexpected repeated local admission outcome: {outcome:?}"),
    };
    assert_eq!(admitted_repeated_invite_id, repeated_invite_id);
    let federated_delivery = crate::outbound::DurableDelivery {
        recipient_id,
        message_id: repeated_invite_id,
        claim_id: None,
    };
    let (federated_tx, mut federated_rx) = tokio::sync::mpsc::channel(1);
    crate::outbound::OutboundSender::new(federated_tx)
        .try_send_durable(federated_invitation, federated_delivery)
        .unwrap();
    let queued = federated_rx.recv().await.unwrap();
    assert_eq!(queued.c2s_delivery(), Some(federated_delivery));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(repeated_invite_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    crate::db::replay::acknowledge_durable_delivery(&pool, federated_delivery)
        .await
        .unwrap();
    set_muc_affiliation(&pool, room_id, "invitee", "outcast")
        .await
        .unwrap();
    assert_eq!(
        admit_local_muc_invite(
            &pool,
            Uuid::new_v4(),
            room_id,
            recipient_id,
            "invitee@local.test",
            "room@conference.local.test",
            "<message id='blocked' to='invitee@local.test'/>",
            false,
            local_policy,
            None,
        )
        .await
        .unwrap(),
        DurableMucInviteOutcome::Outcast
    );

    sqlx::query(
        "CREATE FUNCTION fail_invite_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced outbox admission failure'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER fail_invite_outbox BEFORE INSERT ON s2s_outbox FOR EACH ROW EXECUTE FUNCTION fail_invite_outbox()")
        .execute(&pool)
        .await
        .unwrap();
    let injected_outbox_error = admit_federated_muc_invite(
        &pool,
        room_id,
        "guest@remote.test",
        "remote.test",
        "<message from='room@conference.local.test' to='guest@remote.test' type='normal' id='remote-failure'/>",
        Some("room@conference.local.test"),
        s2s_policy,
        None,
    )
    .await
    .expect_err("the injected outbox failure must abort the invitation");
    let injected_outbox_error = format!("{injected_outbox_error:#}");
    assert!(
        injected_outbox_error.contains("forced outbox admission failure"),
        "the fixture must reach the injected database failure instead of failing stanza validation: {injected_outbox_error}"
    );
    let remote_halves: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM muc_external_affiliations), (SELECT COUNT(*) FROM s2s_outbox)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remote_halves, (0, 0));
    sqlx::query("DROP TRIGGER fail_invite_outbox ON s2s_outbox")
        .execute(&pool)
        .await
        .unwrap();
    assert!(admit_federated_muc_invite(
        &pool,
        room_id,
        "guest@remote.test",
        "remote.test",
        "<message from='room@conference.local.test' to='guest@remote.test' type='normal' id='remote-success'/>",
        Some("room@conference.local.test"),
        s2s_policy,
        None,
    )
    .await
    .unwrap());
    let remote_halves: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM muc_external_affiliations WHERE affiliation='member'), (SELECT COUNT(*) FROM s2s_outbox)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remote_halves, (1, 1));
    set_federated_muc_affiliation(&pool, room_id, "banned@remote.test", "outcast")
        .await
        .unwrap();
    assert!(!admit_federated_muc_invite(
        &pool,
        room_id,
        "banned@remote.test",
        "remote.test",
        "<message from='room@conference.local.test' to='banned@remote.test' type='normal' id='remote-blocked'/>",
        Some("room@conference.local.test"),
        s2s_policy,
        None,
    )
    .await
    .unwrap());

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn history_identity_and_mutations_are_atomic_under_replay_and_failure() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("muc_history_test_{}", Uuid::new_v4().simple());
    create_harness_owned_schema(&admin, &schema).await;
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(60))
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

    let owner_id = Uuid::new_v4();
    let room_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret,subject)
         VALUES($1,'history',$2,$3,'old')",
    )
    .bind(room_id)
    .bind(owner_id)
    .bind(vec![7_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let room_epoch: Uuid = sqlx::query_scalar("SELECT room_epoch FROM muc_rooms WHERE id=$1")
        .bind(room_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let first_id = Uuid::new_v4();
    assert_eq!(
        admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: first_id,
                room_id,
                actor_scope: "alice@local.test",
                origin_id: Some("client-1"),
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                stanza: "<message id='first'/>",
                encrypted: false,
                archive: true,
                retention_days: 30,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "participant",
                    "none",
                ),
            },
        )
        .await
        .unwrap(),
        MucDiscussionAdmission::Stored(first_id)
    );
    assert_eq!(
        admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: Uuid::new_v4(),
                room_id,
                actor_scope: "alice@local.test",
                origin_id: Some("client-1"),
                sender_jid: "alice@local.test/Tablet",
                nick: "Renamed",
                stanza: "<message id='altered-retry'/>",
                encrypted: true,
                archive: true,
                retention_days: 30,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Tablet",
                    "Renamed",
                    "participant",
                    "none",
                ),
            },
        )
        .await
        .unwrap(),
        MucDiscussionAdmission::Replay(first_id)
    );
    let other_actor_id = Uuid::new_v4();
    assert_eq!(
        admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: other_actor_id,
                room_id,
                actor_scope: "bob@remote.test",
                origin_id: Some("client-1"),
                sender_jid: "bob@remote.test/Laptop",
                nick: "Bob",
                stanza: "<message id='same-id-other-actor'/>",
                encrypted: false,
                archive: true,
                retention_days: 30,
                authority: federated_process_authority(
                    room_epoch,
                    "bob@remote.test",
                    "bob@remote.test/Laptop",
                    "Bob",
                    "remote.test",
                ),
            },
        )
        .await
        .unwrap(),
        MucDiscussionAdmission::Stored(other_actor_id)
    );

    let no_store_id = Uuid::new_v4();
    assert_eq!(
        admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: no_store_id,
                room_id,
                actor_scope: "alice@local.test",
                origin_id: Some("no-store-origin"),
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                stanza: "<message><body>not retained</body></message>",
                encrypted: false,
                archive: false,
                retention_days: 30,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "participant",
                    "none",
                ),
            },
        )
        .await
        .unwrap(),
        MucDiscussionAdmission::Stored(no_store_id)
    );
    assert_eq!(
        admit_muc_discussion(
            &pool,
            MucDiscussion {
                id: Uuid::new_v4(),
                room_id,
                actor_scope: "alice@local.test",
                origin_id: Some("no-store-origin"),
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                stanza: "<message><body>retry must not be retained</body></message>",
                encrypted: false,
                archive: true,
                retention_days: 30,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "participant",
                    "none",
                ),
            },
        )
        .await
        .unwrap(),
        MucDiscussionAdmission::Replay(no_store_id)
    );
    let no_store_payloads: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM muc_messages WHERE room_id=$1 AND id=$2")
            .bind(room_id)
            .bind(no_store_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(no_store_payloads, 0);

    let collision_origin = "collision-probe";
    let collision_digest = muc_origin_digest("alice@local.test", collision_origin);
    sqlx::query(
        "INSERT INTO muc_origin_admissions
         (room_id,origin_digest,actor_scope,origin_id,stanza_id)
         VALUES($1,$2,'mallory@local.test','different-raw-value',$3)",
    )
    .bind(room_id)
    .bind(collision_digest)
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    assert!(admit_muc_discussion(
        &pool,
        MucDiscussion {
            id: Uuid::new_v4(),
            room_id,
            actor_scope: "alice@local.test",
            origin_id: Some(collision_origin),
            sender_jid: "alice@local.test/Phone",
            nick: "Alice",
            stanza: "<message/>",
            encrypted: false,
            archive: true,
            retention_days: 30,
            authority: local_process_authority(
                room_epoch,
                owner_id,
                "alice@local.test",
                "alice@local.test/Phone",
                "Alice",
                "participant",
                "none",
            ),
        },
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("digest collision"));

    let concurrent_origin = "concurrent-origin";
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let id = Uuid::new_v4();
            barrier.wait().await;
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id,
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: Some(concurrent_origin),
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    stanza: "<message id='concurrent'/>",
                    encrypted: false,
                    archive: true,
                    retention_days: 30,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "participant",
                        "none",
                    ),
                },
            )
            .await
            .unwrap()
        }));
    }
    barrier.wait().await;
    let outcomes = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, MucDiscussionAdmission::Stored(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, MucDiscussionAdmission::Replay(_)))
            .count(),
        1
    );

    sqlx::query(
        "CREATE FUNCTION reject_subject_history() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.message_kind='subject' THEN RAISE EXCEPTION 'forced subject failure'; END IF;
         RETURN NEW; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_subject_history BEFORE INSERT ON muc_messages
         FOR EACH ROW EXECUTE FUNCTION reject_subject_history()",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(set_local_muc_subject(
        &pool,
        MucSubjectMutation {
            stanza_id: Uuid::new_v4(),
            room_id,
            actor_scope: "alice@local.test",
            sender_jid: "alice@local.test/Phone",
            nick: "Alice",
            subject: "must roll back",
            stanza: "<message><subject>must roll back</subject></message>",
            encrypted: false,
        },
        true,
        local_process_authority(
            room_epoch,
            owner_id,
            "alice@local.test",
            "alice@local.test/Phone",
            "Alice",
            "moderator",
            "none",
        ),
    )
    .await
    .is_err());
    let subject: Option<String> = sqlx::query_scalar("SELECT subject FROM muc_rooms WHERE id=$1")
        .bind(room_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(subject.as_deref(), Some("old"));
    sqlx::query("DROP TRIGGER reject_subject_history ON muc_messages")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION reject_subject_history()")
        .execute(&pool)
        .await
        .unwrap();

    let subject_id = Uuid::new_v4();
    assert_eq!(
        set_local_muc_subject(
            &pool,
            MucSubjectMutation {
                stanza_id: subject_id,
                room_id,
                actor_scope: "alice@local.test",
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                subject: "committed",
                stanza: "<message><subject>committed</subject></message>",
                encrypted: false,
            },
            true,
            local_process_authority(
                room_epoch,
                owner_id,
                "alice@local.test",
                "alice@local.test/Phone",
                "Alice",
                "moderator",
                "none",
            ),
        )
        .await
        .unwrap(),
        MucSubjectOutcome::Applied
    );
    let subject_state: (Option<String>, Option<Uuid>, i64) = sqlx::query_as(
        "SELECT r.subject,r.subject_stanza_id,
                (SELECT COUNT(*) FROM muc_messages m
                 WHERE m.room_id=r.id AND m.id=$2 AND m.message_kind='subject')
         FROM muc_rooms r WHERE r.id=$1",
    )
    .bind(room_id)
    .bind(subject_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        subject_state,
        (Some("committed".to_owned()), Some(subject_id), 1)
    );
    let unarchived_subject_id = Uuid::new_v4();
    assert_eq!(
        set_local_muc_subject(
            &pool,
            MucSubjectMutation {
                stanza_id: unarchived_subject_id,
                room_id,
                actor_scope: "alice@local.test",
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                subject: "state only",
                stanza: "<message><subject>state only</subject></message>",
                encrypted: false,
            },
            false,
            local_process_authority(
                room_epoch,
                owner_id,
                "alice@local.test",
                "alice@local.test/Phone",
                "Alice",
                "moderator",
                "none",
            ),
        )
        .await
        .unwrap(),
        MucSubjectOutcome::Applied
    );
    let state_only: (Option<String>, i64) = sqlx::query_as(
        "SELECT subject,(SELECT COUNT(*) FROM muc_messages WHERE id=$2)
           FROM muc_rooms WHERE id=$1",
    )
    .bind(room_id)
    .bind(unarchived_subject_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state_only, (Some("state only".to_owned()), 0));
    assert!(muc_history_since(&pool, room_id, 0, None)
        .await
        .unwrap()
        .is_empty());
    assert!(muc_history_since(
        &pool,
        room_id,
        100,
        Some(chrono::Utc::now() + chrono::Duration::hours(1)),
    )
    .await
    .unwrap()
    .is_empty());
    assert!(muc_history_since(&pool, room_id, 100, None)
        .await
        .unwrap()
        .iter()
        .all(|message| !message.stanza.contains("<subject>committed</subject>")));

    update_muc_config(
        &pool,
        room_id,
        "alice@local.test/Phone",
        MucConfigUpdate {
            title: Some("Configured"),
            description: Some("A production room"),
            persistent: true,
            members_only: true,
            public: false,
            moderated: true,
            non_anonymous: true,
            max_occupants: 42,
            password_hash: None,
            allow_subject_change: true,
            allow_invites: false,
            allow_private_messages: false,
            logging_enabled: false,
            allow_registration: false,
        },
    )
    .await
    .unwrap();
    let configured = muc_room(&pool, "history").await.unwrap().unwrap();
    assert_eq!(configured.description.as_deref(), Some("A production room"));
    assert!(configured.allow_subject_change);
    assert!(!configured.allow_invites);
    assert!(!configured.allow_private_messages);
    assert!(!configured.logging_enabled);
    assert!(!configured.allow_registration);

    let bob_id = Uuid::new_v4();
    let carol_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES
         ($1,'bob','test'),($2,'carol','test')",
    )
    .bind(bob_id)
    .bind(carol_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO muc_affiliations(room_id,user_id,affiliation)
         VALUES($1,$2,'owner')",
    )
    .bind(room_id)
    .bind(owner_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        register_local_muc_member(&pool, room_id, owner_id, "OwnerNick")
            .await
            .unwrap(),
        MucRegistrationOutcome::Registered {
            affiliation_changed: false,
        }
    );
    let owner_registration: (String, Option<String>) = sqlx::query_as(
        "SELECT affiliation,reserved_nick FROM muc_affiliations
          WHERE room_id=$1 AND user_id=$2",
    )
    .bind(room_id)
    .bind(owner_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner_registration.0, "owner");
    assert_eq!(owner_registration.1.as_deref(), Some("OwnerNick"));
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "alice", "member")
            .await
            .unwrap(),
        MucAffiliationOutcome::LastOwner
    );
    assert_eq!(
        super::muc_affiliation(&pool, room_id, owner_id)
            .await
            .unwrap()
            .as_deref(),
        Some("owner")
    );
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "carol", "owner")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "alice", "member")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "alice", "owner")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "carol", "none")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );

    // Deterministic authorization races. The test hook pauses after the
    // request has begun but before the room/actor locks are acquired. A
    // revocation which commits during that pause must win the serial
    // order and leave no archive/admission projection behind.
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "carol", "owner")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );

    // A local username cannot be re-used under a foreign domain.  Both
    // the service boundary (unit-tested in services::muc) and this locked
    // repository fence reject the forged principal without a projection.
    let forged_domain_id = Uuid::new_v4();
    let forged_domain = admit_muc_discussion(
        &pool,
        MucDiscussion {
            id: forged_domain_id,
            room_id,
            actor_scope: "alice@evil.test",
            origin_id: None,
            sender_jid: "alice@evil.test/Phone",
            nick: "Alice",
            stanza: "<message id='forged-domain'/>",
            encrypted: false,
            archive: true,
            retention_days: 30,
            authority: local_process_authority(
                room_epoch,
                owner_id,
                "alice@evil.test",
                "alice@evil.test/Phone",
                "Alice",
                "moderator",
                "owner",
            ),
        },
    )
    .await
    .unwrap();
    assert_eq!(forged_domain, MucDiscussionAdmission::Unauthorized);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
            .bind(forged_domain_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    // Global lock-order regression: admission owns namespace 29 before it
    // asks for the room row.  Therefore a clustered room-row writer can
    // finish while admission is paused, and a legacy affiliation writer
    // merely queues behind the advisory lock; all three complete without
    // a room-row/advisory cycle once admission resumes.
    let lock_order_id = Uuid::new_v4();
    let (entered, resume) = install_muc_authorization_test_pause("discussion_after_advisory");
    let lock_order_admission = {
        let pool = pool.clone();
        tokio::spawn(async move {
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: lock_order_id,
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: None,
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    stanza: "<message id='lock-order'/>",
                    encrypted: false,
                    archive: false,
                    retention_days: 30,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "moderator",
                        "owner",
                    ),
                },
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "discussion_after_advisory").await;
    let cluster_room_writer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
                .bind(room_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        })
    };
    tokio::time::timeout(Duration::from_secs(5), cluster_room_writer)
        .await
        .expect("room-row writer must not wait behind the advisory-only admission phase")
        .unwrap();
    let legacy_affiliation_writer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            set_muc_affiliation(&pool, room_id, "alice", "owner")
                .await
                .unwrap()
        })
    };
    resume.notify_one();
    let (admission, affiliation) = tokio::time::timeout(
        Duration::from_secs(5),
        futures::future::join(lock_order_admission, legacy_affiliation_writer),
    )
    .await
    .expect("MUC room/advisory writers must not deadlock");
    assert_eq!(
        admission.unwrap(),
        MucDiscussionAdmission::Stored(lock_order_id)
    );
    assert_eq!(affiliation.unwrap(), MucAffiliationOutcome::Applied);

    let local_race_id = Uuid::new_v4();
    let (entered, resume) = install_muc_authorization_test_pause("discussion");
    let local_race = {
        let pool = pool.clone();
        tokio::spawn(async move {
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: local_race_id,
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: None,
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    stanza: "<message id='revoked-local'/>",
                    encrypted: false,
                    // Even volatile/no-store traffic must cross the same
                    // authorization transaction before live fan-out.
                    archive: false,
                    retention_days: 30,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "moderator",
                        "owner",
                    ),
                },
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "discussion local revocation").await;
    set_muc_affiliation(&pool, room_id, "alice", "outcast")
        .await
        .unwrap();
    resume.notify_one();
    assert_eq!(
        local_race.await.unwrap(),
        MucDiscussionAdmission::Unauthorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
            .bind(local_race_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    set_muc_affiliation(&pool, room_id, "alice", "owner")
        .await
        .unwrap();

    let federated_race_id = Uuid::new_v4();
    let (entered, resume) = install_muc_authorization_test_pause("discussion");
    let federated_race = {
        let pool = pool.clone();
        tokio::spawn(async move {
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: federated_race_id,
                    room_id,
                    actor_scope: "race@remote.test",
                    origin_id: None,
                    sender_jid: "race@remote.test/Phone",
                    nick: "Remote",
                    stanza: "<message id='revoked-federated'/>",
                    encrypted: false,
                    archive: true,
                    retention_days: 30,
                    authority: federated_process_authority(
                        room_epoch,
                        "race@remote.test",
                        "race@remote.test/Phone",
                        "Remote",
                        "remote.test",
                    ),
                },
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "discussion federated revocation").await;
    set_federated_muc_affiliation(&pool, room_id, "race@remote.test", "outcast")
        .await
        .unwrap();
    resume.notify_one();
    assert_eq!(
        federated_race.await.unwrap(),
        MucDiscussionAdmission::Unauthorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
            .bind(federated_race_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    set_federated_muc_affiliation(&pool, room_id, "race@remote.test", "none")
        .await
        .unwrap();

    // Exercise the repository's real authorization expression before the
    // race.  This is the intentional OMEMO recipient-discovery exception:
    // a member of a members-only, non-anonymous room may read the three
    // positive affiliation lists, but not the outcast list.
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "carol", "member")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );
    for requested in ["owner", "admin", "member"] {
        assert!(matches!(
            authorized_muc_admin_affiliation_list(
                &pool,
                room_id,
                room_epoch,
                carol_id,
                "carol@local.test",
                requested,
                "local.test",
            )
            .await
            .unwrap(),
            MucAdminSnapshot::Authorized(_)
        ));
    }
    assert_eq!(
        authorized_muc_admin_affiliation_list(
            &pool,
            room_id,
            room_epoch,
            carol_id,
            "carol@local.test",
            "outcast",
            "local.test",
        )
        .await
        .unwrap(),
        MucAdminSnapshot::Unauthorized
    );
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "carol", "owner")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );

    let (entered, resume) = install_muc_authorization_test_pause("admin_affiliation");
    let admin_snapshot = {
        let pool = pool.clone();
        tokio::spawn(async move {
            authorized_muc_admin_affiliation_list(
                &pool,
                room_id,
                room_epoch,
                carol_id,
                "carol@local.test",
                "owner",
                "local.test",
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "admin_affiliation").await;
    // In a members-only, non-anonymous room a member intentionally keeps
    // read access to owner/admin/member lists so an OMEMO client can build
    // the complete recipient set.  Use `none` here: this race is meant to
    // prove that a real authorization revocation committed before the
    // repository locks are acquired wins the serial order.
    assert_eq!(
        set_muc_affiliation(&pool, room_id, "carol", "none")
            .await
            .unwrap(),
        MucAffiliationOutcome::Applied
    );
    resume.notify_one();
    assert_eq!(
        admin_snapshot.await.unwrap(),
        MucAdminSnapshot::Unauthorized
    );
    set_muc_affiliation(&pool, room_id, "carol", "owner")
        .await
        .unwrap();

    let (entered, resume) = install_muc_authorization_test_pause("admin_role");
    let role_snapshot = {
        let pool = pool.clone();
        tokio::spawn(async move {
            authorized_muc_admin_role_list(
                &pool,
                room_id,
                room_epoch,
                owner_id,
                "alice@local.test",
                "local.test",
                "none",
                None,
                false,
                "participant",
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "admin_role").await;
    set_muc_affiliation(&pool, room_id, "alice", "member")
        .await
        .unwrap();
    resume.notify_one();
    assert_eq!(role_snapshot.await.unwrap(), MucAdminSnapshot::Unauthorized);
    set_muc_affiliation(&pool, room_id, "alice", "owner")
        .await
        .unwrap();

    let cluster_incarnation = Uuid::new_v4();
    let cluster_connection = Uuid::new_v4();
    let config_version: i64 =
        sqlx::query_scalar("SELECT config_version FROM muc_rooms WHERE id=$1")
            .bind(room_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO cluster_muc_occupancies(
             room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,
             identity_kind,local_user_id,bare_jid,full_jid,nick,authenticated_domain,
             owner_node_id,connection_uuid,connection_epoch,sm_session_id,state,role,
             affiliation,presence_payload,lease_until)
         VALUES($1,$2,$3,9001,$4,'local',$5,'alice@local.test',
                'alice@local.test/Cluster','ClusterAlice',NULL,'test-node',$6,1,NULL,
                'active','moderator','owner','',clock_timestamp()+INTERVAL '1 hour')",
    )
    .bind(room_id)
    .bind(room_epoch)
    .bind(cluster_incarnation)
    .bind(config_version)
    .bind(owner_id)
    .bind(cluster_connection)
    .execute(&pool)
    .await
    .unwrap();
    let cluster_target = crate::db::ClusterMucOccupancyTarget {
        room_id,
        room_epoch,
        occupant_incarnation: cluster_incarnation,
        occupancy_epoch: 9001,
        full_jid: "alice@local.test/Cluster".to_owned(),
        nick: "ClusterAlice".to_owned(),
        connection_uuid: cluster_connection,
        connection_epoch: 1,
    };
    let cluster_outbox_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM cluster_muc_event_outbox WHERE room_id=$1")
            .bind(room_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let cluster_race_id = Uuid::new_v4();
    let (entered, resume) = install_muc_authorization_test_pause("discussion");
    let cluster_race = {
        let pool = pool.clone();
        let cluster_target = cluster_target.clone();
        tokio::spawn(async move {
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: cluster_race_id,
                    room_id,
                    actor_scope: "alice@local.test",
                    origin_id: None,
                    sender_jid: "alice@local.test/Cluster",
                    nick: "ClusterAlice",
                    stanza: "<message id='revoked-cluster'/>",
                    encrypted: false,
                    archive: true,
                    retention_days: 30,
                    authority: MucActorAuthority {
                        clustered: true,
                        expected_room_epoch: room_epoch,
                        principal: MucActorPrincipal::Local {
                            user_id: owner_id,
                            local_domain: "local.test",
                        },
                        actor_scope: "alice@local.test",
                        full_jid: "alice@local.test/Cluster",
                        nick: "ClusterAlice",
                        occupant_incarnation: cluster_incarnation,
                        connection_uuid: cluster_connection,
                        expected_role: "moderator",
                        expected_affiliation: "owner",
                        cluster_target: Some(cluster_target),
                    },
                },
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "discussion clustered revocation").await;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',role='none',ended_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE room_id=$1 AND occupant_incarnation=$2",
    )
    .bind(room_id)
    .bind(cluster_incarnation)
    .execute(&pool)
    .await
    .unwrap();
    resume.notify_one();
    assert_eq!(
        cluster_race.await.unwrap(),
        MucDiscussionAdmission::Unauthorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
            .bind(cluster_race_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );

    let federated_cluster_incarnation = Uuid::new_v4();
    let federated_cluster_connection = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cluster_muc_occupancies(
             room_id,room_epoch,occupant_incarnation,occupancy_epoch,config_version,
             identity_kind,local_user_id,bare_jid,full_jid,nick,authenticated_domain,
             owner_node_id,connection_uuid,connection_epoch,sm_session_id,state,role,
             affiliation,presence_payload,lease_until)
         VALUES($1,$2,$3,9002,$4,'federated',NULL,'cluster@remote.test',
                'cluster@remote.test/Phone','ClusterRemote','remote.test','test-node',$5,1,NULL,
                'active','participant','none','',clock_timestamp()+INTERVAL '1 hour')",
    )
    .bind(room_id)
    .bind(room_epoch)
    .bind(federated_cluster_incarnation)
    .bind(config_version)
    .bind(federated_cluster_connection)
    .execute(&pool)
    .await
    .unwrap();
    let federated_cluster_target = crate::db::ClusterMucOccupancyTarget {
        room_id,
        room_epoch,
        occupant_incarnation: federated_cluster_incarnation,
        occupancy_epoch: 9002,
        full_jid: "cluster@remote.test/Phone".to_owned(),
        nick: "ClusterRemote".to_owned(),
        connection_uuid: federated_cluster_connection,
        connection_epoch: 1,
    };
    let federated_cluster_race_id = Uuid::new_v4();
    let (entered, resume) = install_muc_authorization_test_pause("discussion");
    let federated_cluster_race = {
        let pool = pool.clone();
        tokio::spawn(async move {
            admit_muc_discussion(
                &pool,
                MucDiscussion {
                    id: federated_cluster_race_id,
                    room_id,
                    actor_scope: "cluster@remote.test",
                    origin_id: None,
                    sender_jid: "cluster@remote.test/Phone",
                    nick: "ClusterRemote",
                    stanza: "<message id='revoked-federated-cluster'/>",
                    encrypted: false,
                    archive: true,
                    retention_days: 30,
                    authority: MucActorAuthority {
                        clustered: true,
                        expected_room_epoch: room_epoch,
                        principal: MucActorPrincipal::Federated {
                            bare_jid: "cluster@remote.test",
                            authenticated_domain: "remote.test",
                        },
                        actor_scope: "cluster@remote.test",
                        full_jid: "cluster@remote.test/Phone",
                        nick: "ClusterRemote",
                        occupant_incarnation: federated_cluster_incarnation,
                        connection_uuid: federated_cluster_connection,
                        expected_role: "participant",
                        expected_affiliation: "none",
                        cluster_target: Some(federated_cluster_target),
                    },
                },
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "discussion cluster handoff").await;
    sqlx::query(
        "UPDATE cluster_muc_occupancies
            SET state='revoked',role='none',ended_at=clock_timestamp(),updated_at=clock_timestamp()
          WHERE room_id=$1 AND occupant_incarnation=$2",
    )
    .bind(room_id)
    .bind(federated_cluster_incarnation)
    .execute(&pool)
    .await
    .unwrap();
    resume.notify_one();
    assert_eq!(
        federated_cluster_race.await.unwrap(),
        MucDiscussionAdmission::Unauthorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
            .bind(federated_cluster_race_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM cluster_muc_event_outbox WHERE room_id=$1",
        )
        .bind(room_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        cluster_outbox_before
    );
    set_muc_affiliation(&pool, room_id, "carol", "none")
        .await
        .unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let mut registrations = Vec::new();
    for user_id in [bob_id, carol_id] {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        registrations.push(tokio::spawn(async move {
            barrier.wait().await;
            register_local_muc_member(&pool, room_id, user_id, "SharedNick")
                .await
                .unwrap()
        }));
    }
    barrier.wait().await;
    let outcomes = futures::future::join_all(registrations)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                matches!(
                    **outcome,
                    MucRegistrationOutcome::Registered {
                        affiliation_changed: true
                    }
                )
            })
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == MucRegistrationOutcome::Conflict)
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM muc_affiliations
              WHERE room_id=$1 AND reserved_nick='SharedNick'",
        )
        .bind(room_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert!(!unregister_local_muc_member(&pool, room_id, owner_id)
        .await
        .unwrap());
    assert!(muc_reserved_nick(&pool, room_id, owner_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        super::muc_affiliation(&pool, room_id, owner_id)
            .await
            .unwrap()
            .as_deref(),
        Some("owner")
    );
    set_muc_affiliation(&pool, room_id, "bob", "outcast")
        .await
        .unwrap();
    assert!(muc_reserved_nick(&pool, room_id, bob_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        register_local_muc_member(&pool, room_id, bob_id, "BannedNick")
            .await
            .unwrap(),
        MucRegistrationOutcome::Outcast
    );

    let target_id = Uuid::new_v4();
    admit_muc_discussion(
        &pool,
        MucDiscussion {
            id: target_id,
            room_id,
            actor_scope: "alice@local.test",
            origin_id: None,
            sender_jid: "alice@local.test/Phone",
            nick: "Alice",
            stanza: "<message id='target'><body>secret</body></message>",
            encrypted: false,
            archive: true,
            retention_days: 30,
            authority: local_process_authority(
                room_epoch,
                owner_id,
                "alice@local.test",
                "alice@local.test/Phone",
                "Alice",
                "moderator",
                "owner",
            ),
        },
    )
    .await
    .unwrap();
    let revoked_moderation_id = Uuid::new_v4();
    let (entered, resume) = install_muc_authorization_test_pause("retraction");
    let revoked_moderation = {
        let pool = pool.clone();
        tokio::spawn(async move {
            retract_muc_message_and_archive_action(
                &pool,
                MucRetractionMutation {
                    action_id: revoked_moderation_id,
                    room_id,
                    target_id,
                    expected_stanza: "<message id='target'><body>secret</body></message>",
                    actor_scope: "alice@local.test",
                    sender_jid: "alice@local.test/Phone",
                    nick: "Alice",
                    tombstone: "<message id='target'><retracted/></message>",
                    action_stanza: "<message id='revoked-moderation'/>",
                    reason: Some("revoked"),
                    kind: MucRetractionKind::Moderator,
                    authority: local_process_authority(
                        room_epoch,
                        owner_id,
                        "alice@local.test",
                        "alice@local.test/Phone",
                        "Alice",
                        "moderator",
                        "owner",
                    ),
                },
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "retraction local revocation").await;
    set_muc_affiliation(&pool, room_id, "carol", "owner")
        .await
        .unwrap();
    set_muc_affiliation(&pool, room_id, "alice", "member")
        .await
        .unwrap();
    resume.notify_one();
    assert_eq!(
        revoked_moderation.await.unwrap(),
        MucRetractionOutcome::Unauthorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
            .bind(revoked_moderation_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let unchanged: (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT stanza,retracted_at FROM muc_messages WHERE id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        unchanged,
        (
            "<message id='target'><body>secret</body></message>".to_owned(),
            None
        )
    );

    // The same moderation fence applies to an authenticated federated
    // moderator. A committed remote-affiliation demotion wins before any
    // tombstone or moderation action can be projected.
    set_federated_muc_affiliation(&pool, room_id, "moderator@remote.test", "admin")
        .await
        .unwrap();
    let federated_moderation_id = Uuid::new_v4();
    let (entered, resume) = install_muc_authorization_test_pause("retraction");
    let federated_moderation = {
        let pool = pool.clone();
        tokio::spawn(async move {
            retract_muc_message_and_archive_action(
                &pool,
                MucRetractionMutation {
                    action_id: federated_moderation_id,
                    room_id,
                    target_id,
                    expected_stanza: "<message id='target'><body>secret</body></message>",
                    actor_scope: "moderator@remote.test",
                    sender_jid: "moderator@remote.test/Phone",
                    nick: "RemoteModerator",
                    tombstone: "<message id='target'><retracted/></message>",
                    action_stanza: "<message id='revoked-federated-moderation'/>",
                    reason: Some("revoked"),
                    kind: MucRetractionKind::Moderator,
                    authority: MucActorAuthority {
                        clustered: false,
                        expected_room_epoch: room_epoch,
                        principal: MucActorPrincipal::Federated {
                            bare_jid: "moderator@remote.test",
                            authenticated_domain: "remote.test",
                        },
                        actor_scope: "moderator@remote.test",
                        full_jid: "moderator@remote.test/Phone",
                        nick: "RemoteModerator",
                        occupant_incarnation: Uuid::nil(),
                        connection_uuid: Uuid::nil(),
                        expected_role: "moderator",
                        expected_affiliation: "admin",
                        cluster_target: None,
                    },
                },
            )
            .await
            .unwrap()
        })
    };
    await_authorization_pause(&entered, "retraction clustered revocation").await;
    set_federated_muc_affiliation(&pool, room_id, "moderator@remote.test", "member")
        .await
        .unwrap();
    resume.notify_one();
    assert_eq!(
        federated_moderation.await.unwrap(),
        MucRetractionOutcome::Unauthorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM muc_messages WHERE id=$1")
            .bind(federated_moderation_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    set_federated_muc_affiliation(&pool, room_id, "moderator@remote.test", "none")
        .await
        .unwrap();
    set_muc_affiliation(&pool, room_id, "alice", "owner")
        .await
        .unwrap();
    set_muc_affiliation(&pool, room_id, "carol", "none")
        .await
        .unwrap();
    sqlx::query(
        "CREATE FUNCTION reject_moderation_action() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.message_kind='moderation' THEN RAISE EXCEPTION 'forced action failure'; END IF;
         RETURN NEW; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_moderation_action BEFORE INSERT ON muc_messages
         FOR EACH ROW EXECUTE FUNCTION reject_moderation_action()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let failed_action = Uuid::new_v4();
    assert!(retract_muc_message_and_archive_action(
        &pool,
        MucRetractionMutation {
            action_id: failed_action,
            room_id,
            target_id,
            expected_stanza: "<message id='target'><body>secret</body></message>",
            actor_scope: "alice@local.test",
            sender_jid: "alice@local.test/Phone",
            nick: "Alice",
            tombstone: "<message id='target'><retracted/></message>",
            action_stanza: "<message id='moderate'><moderated/></message>",
            reason: Some("policy"),
            kind: MucRetractionKind::Moderator,
            authority: local_process_authority(
                room_epoch,
                owner_id,
                "alice@local.test",
                "alice@local.test/Phone",
                "Alice",
                "moderator",
                "owner",
            ),
        },
    )
    .await
    .is_err());
    let target_after_failure: (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT stanza,retracted_at FROM muc_messages WHERE id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        target_after_failure,
        (
            "<message id='target'><body>secret</body></message>".to_owned(),
            None
        )
    );
    sqlx::query("DROP TRIGGER reject_moderation_action ON muc_messages")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION reject_moderation_action()")
        .execute(&pool)
        .await
        .unwrap();

    let action_id = Uuid::new_v4();
    assert_eq!(
        retract_muc_message_and_archive_action(
            &pool,
            MucRetractionMutation {
                action_id,
                room_id,
                target_id,
                expected_stanza: "<message id='target'><body>secret</body></message>",
                actor_scope: "alice@local.test",
                sender_jid: "alice@local.test/Phone",
                nick: "Alice",
                tombstone: "<message id='target'><retracted/></message>",
                action_stanza: "<message id='moderate'><moderated/></message>",
                reason: Some("policy"),
                kind: MucRetractionKind::Author,
                authority: local_process_authority(
                    room_epoch,
                    owner_id,
                    "alice@local.test",
                    "alice@local.test/Phone",
                    "Alice",
                    "moderator",
                    "owner",
                ),
            },
        )
        .await
        .unwrap(),
        MucRetractionOutcome::Applied
    );
    let committed: (String, Option<Uuid>, i64) = sqlx::query_as(
        "SELECT stanza,retraction_action_id,
                (SELECT COUNT(*) FROM muc_messages a
                 WHERE a.room_id=m.room_id AND a.id=$2 AND a.message_kind='retraction')
         FROM muc_messages m WHERE m.id=$1",
    )
    .bind(target_id)
    .bind(action_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        committed,
        (
            "<message id='target'><retracted/></message>".to_owned(),
            Some(action_id),
            1
        )
    );

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
