use anyhow::Result;
use northstar_delivery_core::DurableDelivery;
use northstar_message_application::retractions::{
    ArchiveWrite, DeliveryProjection, OwnerProjection, RetractionCommand, RetractionOutcome,
    RetractionService,
};
use northstar_message_core::retraction::{personal_retraction_command, InvalidPersonalRetraction};
use northstar_message_core::{ActorGenerationFence, OfflineStorePolicy};
use northstar_message_postgres::personal_history::{
    PersonalArchiveWrite, PersonalC2sDeliveryAdmission, PersonalHistoryAdmission,
    PersonalHistoryIdentity,
};
use northstar_operations_postgres::data_lifecycle::{
    create_legal_hold_in_tx, CreateLegalHold, LegalHoldTarget,
};
use northstar_session_postgres::replay;
use northstar_workflows::personal_history::admit_personal_history_and_c2s_delivery;
use northstar_workflows::retraction_repository::PostgresRetractionRepository;
use roxmltree::Document;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::borrow::Cow;
use std::time::Duration;
use uuid::Uuid;

const SENDER: &str = "alice@local.test/Phone";
const RECIPIENT: &str = "bob@local.test";
const REMOTE: &str = "bob@remote.test/Phone";
const REMOTE_ACTION: &str = "<message xmlns='jabber:server' from='bob@remote.test/Phone' to='bob@local.test' id='reused'><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn schema() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await?;
        let schema = format!("retraction_lifecycle_{}", Uuid::new_v4().simple());
        eprintln!("isolated_schema={schema}");
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await?;
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await?;
        Ok(Self {
            admin,
            pool,
            schema,
        })
    }

    async fn migrated() -> Result<Self> {
        let fixture = Self::schema().await?;
        crate::support::migrate(&fixture.pool).await?;
        Ok(fixture)
    }

    async fn close(self) -> Result<()> {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Accounts {
    alice: Uuid,
    bob: Uuid,
}

async fn account(pool: &PgPool, username: &str, admin: bool) -> Result<Uuid> {
    Ok(sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test',$3) RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(username)
    .bind(admin)
    .fetch_one(pool)
    .await?)
}

async fn accounts(pool: &PgPool) -> Result<Accounts> {
    Ok(Accounts {
        alice: account(pool, "alice", false).await?,
        bob: account(pool, "bob", false).await?,
    })
}

fn service(pool: &PgPool) -> RetractionService<PostgresRetractionRepository> {
    RetractionService::new(
        PostgresRetractionRepository::new(pool.clone()),
        northstar_abuse_application::guard::test_personal_retraction_content_keyring(),
        "local.test",
    )
}

fn original_xml(target: &str) -> String {
    format!(
        "<message from='{SENDER}' to='{RECIPIENT}' id='{target}'><body>original</body></message>"
    )
}

async fn admit_original(
    pool: &PgPool,
    pair: Accounts,
    target: &str,
    archive: bool,
) -> Result<[Uuid; 2]> {
    admit_original_projections(pool, pair, target, if archive { 2 } else { 0 }, None).await
}

async fn admit_original_projections(
    pool: &PgPool,
    pair: Accounts,
    target: &str,
    archive_count: usize,
    identity: Option<&PersonalHistoryIdentity<'_>>,
) -> Result<[Uuid; 2]> {
    let ids = [Uuid::new_v4(), Uuid::new_v4()];
    let stanza = original_xml(target);
    let writes = [
        PersonalArchiveWrite {
            id: ids[0],
            owner_id: pair.alice,
            peer_jid: RECIPIENT,
            stanza: &stanza,
            encrypted: false,
            stanza_id: Some(target),
        },
        PersonalArchiveWrite {
            id: ids[1],
            owner_id: pair.bob,
            peer_jid: SENDER,
            stanza: &stanza,
            encrypted: false,
            stanza_id: Some(target),
        },
    ];
    let outcome = admit_personal_history_and_c2s_delivery(
        pool,
        identity,
        &writes[..archive_count],
        &PersonalC2sDeliveryAdmission {
            id: ids[1],
            recipient_id: pair.bob,
            recipient_bare_jid: RECIPIENT,
            local_actor_id: Some(pair.alice),
            sender_jid: SENDER,
            stanza: &stanza,
            target_full_jid: None,
            encrypted: false,
            policy: OfflineStorePolicy {
                max_messages: 32,
                max_bytes: 100_000,
                ttl_days: 30,
                mam_backed: archive_count == 2,
            },
        },
    )
    .await?;
    assert!(matches!(outcome, PersonalHistoryAdmission::Stored(_)));
    Ok(ids)
}

async fn local_retract(
    pool: &PgPool,
    pair: Accounts,
    target: &str,
    action: &str,
    archive: bool,
    max_messages: Option<i64>,
    actor_fence: Option<ActorGenerationFence>,
) -> Result<RetractionOutcome> {
    let stanza = format!(
        "<message from='{SENDER}' to='{RECIPIENT}' id='{action}'>\
         <retract xmlns='urn:xmpp:message-retract:1' id='{target}'/></message>"
    );
    let owners = [
        OwnerProjection {
            owner_id: pair.alice,
            peer_jid: RECIPIENT,
        },
        OwnerProjection {
            owner_id: pair.bob,
            peer_jid: SENDER,
        },
    ];
    let writes = owners.each_ref().map(|owner| ArchiveWrite {
        id: Uuid::new_v4(),
        owner_id: owner.owner_id,
        peer_jid: owner.peer_jid,
        stanza: &stanza,
        encrypted: false,
        stanza_id: Some(action),
    });
    let delivery = max_messages.map(|max_messages| DeliveryProjection {
        id: writes[1].id,
        recipient_id: pair.bob,
        local_actor_id: Some(pair.alice),
        sender_jid: SENDER,
        stanza: &stanza,
        encrypted: false,
        max_messages,
        max_bytes: 100_000,
        ttl_days: 30,
        mam_backed: archive,
    });
    service(pool)
        .apply_with_delivery(
            &owners,
            SENDER,
            &RetractionCommand {
                actor_fence,
                action_id: action,
                target_id: target,
                semantic_payload: &stanza,
            },
            if archive { &writes } else { &[] },
            delivery.as_ref(),
            None,
        )
        .await
}

async fn remote_retract(
    pool: &PgPool,
    recipient: Uuid,
    stanza: &str,
) -> Result<Result<RetractionOutcome, InvalidPersonalRetraction>> {
    let document = Document::parse(stanza)?;
    let command = match personal_retraction_command(document.root_element()) {
        Ok(Some(command)) => command,
        Ok(None) => anyhow::bail!("expected personal retraction"),
        Err(error) => return Ok(Err(error)),
    };
    let id = Uuid::new_v4();
    Ok(Ok(service(pool)
        .apply_with_delivery(
            &[OwnerProjection {
                owner_id: recipient,
                peer_jid: REMOTE,
            }],
            REMOTE,
            &RetractionCommand {
                actor_fence: None,
                action_id: &command.action_id,
                target_id: &command.target_id,
                semantic_payload: &command.semantic_payload,
            },
            &[ArchiveWrite {
                id,
                owner_id: recipient,
                peer_jid: REMOTE,
                stanza,
                encrypted: false,
                stanza_id: Some(&command.action_id),
            }],
            Some(&DeliveryProjection {
                id,
                recipient_id: recipient,
                local_actor_id: None,
                sender_jid: REMOTE,
                stanza,
                encrypted: false,
                max_messages: 32,
                max_bytes: 100_000,
                ttl_days: 30,
                mam_backed: true,
            }),
            None,
        )
        .await?))
}

async fn spool_payload(pool: &PgPool, id: Uuid) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT stanza FROM offline_messages WHERE id=$1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

async fn archive_payloads(pool: &PgPool, ids: &[Uuid]) -> Result<Vec<String>> {
    Ok(
        sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=ANY($1) ORDER BY id")
            .bind(ids)
            .fetch_all(pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn paired_admission_during_locked_scan_is_not_partially_retracted() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let pair = accounts(pool).await?;
    let (first_owner, peer) = if pair.alice < pair.bob {
        (pair.alice, RECIPIENT)
    } else {
        (pair.bob, SENDER)
    };
    let decoy = Uuid::new_v4();
    northstar_archive_postgres::archive_message(
        pool,
        decoy,
        first_owner,
        peer,
        &format!("<message from='{SENDER}' id='race'><received xmlns='urn:xmpp:receipts' id='earlier'/></message>"),
        false,
        Some("race"),
    )
    .await?;
    let mut barrier = pool.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await?;
    sqlx::query("SELECT id FROM message_archive WHERE id=$1 FOR UPDATE")
        .bind(decoy)
        .fetch_one(&mut *barrier)
        .await?;
    let retraction_pool = pool.clone();
    let task = tokio::spawn(async move {
        local_retract(
            &retraction_pool,
            pair,
            "race",
            "race-action",
            false,
            None,
            None,
        )
        .await
    });
    crate::support::blocked_backend(pool, blocker).await;
    let originals = admit_original(pool, pair, "race", true).await?;
    barrier.commit().await?;
    assert!(matches!(
        task.await??,
        RetractionOutcome::Applied { tombstones: 0, .. }
    ));
    assert_eq!(
        archive_payloads(pool, &originals).await?,
        vec![original_xml("race"); 2]
    );
    assert_eq!(
        spool_payload(pool, originals[1]).await?,
        Some(original_xml("race"))
    );
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn exact_unowned_spool_cancellation_commits_and_rolls_back_with_tombstones() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let pair = accounts(pool).await?;
    let original = admit_original(pool, pair, "same-client-id", true).await?;
    let unrelated = admit_original(pool, pair, "same-client-id", false).await?;
    assert_eq!(
        local_retract(pool, pair, "same-client-id", "cancel", true, Some(1), None).await?,
        RetractionOutcome::CapacityExceeded
    );
    assert_eq!(
        spool_payload(pool, original[1]).await?,
        Some(original_xml("same-client-id"))
    );
    assert_eq!(
        archive_payloads(pool, &original).await?,
        vec![original_xml("same-client-id"); 2]
    );
    assert!(matches!(
        local_retract(pool, pair, "same-client-id", "cancel", true, Some(2), None).await?,
        RetractionOutcome::Applied { tombstones: 2, .. }
    ));
    assert!(archive_payloads(pool, &original)
        .await?
        .iter()
        .all(|stanza| stanza.contains("<retracted")));
    assert_eq!(spool_payload(pool, original[1]).await?, None);
    assert_eq!(
        spool_payload(pool, unrelated[1]).await?,
        Some(original_xml("same-client-id"))
    );
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn sender_only_archive_cancels_spool_row_linked_by_origin_admission() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let pair = accounts(pool).await?;
    let stanza = original_xml("sender-only");
    let identity = PersonalHistoryIdentity {
        kind: "local-origin",
        actor_scope_raw: "alice@local.test",
        actor_scope: "alice@local.test",
        target_scope: RECIPIENT,
        identity_value: "sender-only-origin",
        payload_authenticators:
            northstar_abuse_application::guard::test_personal_message_content_keyring()
                .authenticators(stanza.as_bytes()),
        legacy_payload_digest: Sha256::digest(stanza.as_bytes()).into(),
    };
    let original =
        admit_original_projections(pool, pair, "sender-only", 1, Some(&identity)).await?;
    let unrelated = admit_original(pool, pair, "sender-only", false).await?;

    assert!(matches!(
        local_retract(
            pool,
            pair,
            "sender-only",
            "cancel-origin",
            false,
            None,
            None
        )
        .await?,
        RetractionOutcome::Applied { tombstones: 1, .. }
    ));
    assert_eq!(spool_payload(pool, original[1]).await?, None);
    assert_eq!(spool_payload(pool, unrelated[1]).await?, Some(stanza));
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn retraction_preserves_replay_socket_sm_and_bosh_ownership() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let pair = accounts(pool).await?;
    let claimed = admit_original(pool, pair, "claimed", true).await?[1];
    let replay::OfflineReplayLeaseAcquire::Acquired(lease) =
        replay::acquire_offline_replay_lease(pool, pair.bob, "Replay", Uuid::new_v4(), None, 120)
            .await?
    else {
        anyhow::bail!("failed to acquire fresh replay lease");
    };
    replay::claim_offline_replay_page(
        pool,
        &lease,
        30,
        RECIPIENT,
        "bob@local.test/Replay",
        None,
        false,
        120,
    )
    .await?;
    let socket = admit_original(pool, pair, "socket", true).await?[1];
    let socket_fence = replay::fence_durable_socket_write(
        pool,
        DurableDelivery {
            recipient_id: pair.bob,
            message_id: socket,
            claim_id: None,
        },
    )
    .await?;
    let sm = admit_original(pool, pair, "sm", true).await?[1];
    let sm_session = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sm_resume_sessions
         (id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
          resume_timeout_seconds,outbound_h,live_lease_until,expires_at)
         VALUES($1,decode(repeat('01',32),'hex'),$2,0,'bob@local.test/SM','SM',$1,
                300,1,now()+INTERVAL '5 minutes',now()+INTERVAL '5 minutes')",
    )
    .bind(sm_session)
    .bind(pair.bob)
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO sm_resume_stanzas(session_id,position,stanza,delivery_recipient_id,delivery_message_id)
         SELECT $1,0,stanza,recipient_id,id FROM offline_messages WHERE id=$2",
    )
    .bind(sm_session)
    .bind(sm)
    .execute(pool)
    .await?;
    let bosh = admit_original(pool, pair, "bosh", true).await?[1];
    replay::bind_bosh_delivery_response(
        pool,
        Uuid::new_v4(),
        1,
        &[DurableDelivery {
            recipient_id: pair.bob,
            message_id: bosh,
            claim_id: None,
        }],
        120,
    )
    .await?;
    let unowned = admit_original(pool, pair, "unowned", true).await?[1];
    let claim_tokens: Vec<Option<Uuid>> = sqlx::query_scalar(
        "SELECT delivery_claim_id FROM offline_messages WHERE id IN ($1,$2) ORDER BY id=$2",
    )
    .bind(claimed)
    .bind(socket)
    .fetch_all(pool)
    .await?;
    assert!(claim_tokens[0].is_some());
    assert_eq!(claim_tokens[1], socket_fence.claim_id);
    for (target, id) in [
        ("claimed", claimed),
        ("socket", socket),
        ("sm", sm),
        ("bosh", bosh),
    ] {
        let action = format!("retract-{target}");
        assert!(matches!(
            local_retract(pool, pair, target, &action, false, None, None).await?,
            RetractionOutcome::Applied { tombstones: 2, .. }
        ));
        assert_eq!(spool_payload(pool, id).await?, Some(original_xml(target)));
    }
    assert!(matches!(
        local_retract(pool, pair, "unowned", "cancel-unowned", false, None, None).await?,
        RetractionOutcome::Applied { tombstones: 2, .. }
    ));
    assert_eq!(spool_payload(pool, unowned).await?, None);
    let ownership: (bool, bool, i64) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1),
                EXISTS(SELECT 1 FROM bosh_delivery_fences WHERE message_id=$2),
                (SELECT count(*) FROM offline_messages WHERE delivery_claim_id=ANY($3))",
    )
    .bind(sm)
    .bind(bosh)
    .bind(claim_tokens.into_iter().flatten().collect::<Vec<_>>())
    .fetch_one(pool)
    .await?;
    assert_eq!(ownership, (true, true, 2));
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn retraction_leaves_held_archive_and_offline_evidence() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let pair = accounts(pool).await?;
    let admin = account(pool, "admin", true).await?;
    let held_archive = admit_original(pool, pair, "held-archive", true).await?[1];
    let held_spool = admit_original(pool, pair, "held-spool", true).await?[1];
    let unheld = admit_original(pool, pair, "unheld", true).await?[1];
    let mut tx = pool.begin().await?;
    create_legal_hold_in_tx(
        &mut tx,
        admin,
        &CreateLegalHold {
            id: Uuid::new_v4(),
            title: "Preserve originals",
            authority_reference: "fixture",
            reason: "Retraction evidence",
            targets: &[
                LegalHoldTarget::PersonalArchive(held_archive),
                LegalHoldTarget::OfflineMessage(held_spool),
            ],
            request_id: Uuid::new_v4(),
        },
    )
    .await?;
    tx.commit().await?;
    for target in ["held-archive", "held-spool", "unheld"] {
        assert!(matches!(
            local_retract(
                pool,
                pair,
                target,
                &format!("drop-{target}"),
                false,
                None,
                None
            )
            .await?,
            RetractionOutcome::Applied { tombstones: 2, .. }
        ));
    }
    assert_eq!(
        archive_payloads(pool, &[held_archive]).await?,
        vec![original_xml("held-archive")]
    );
    let display: String = sqlx::query_scalar(
        "SELECT display_stanza FROM personal_archive_display_changes WHERE archive_id=$1",
    )
    .bind(held_archive)
    .fetch_one(pool)
    .await?;
    assert!(display.contains("<retracted") && !display.contains("<body>"));
    assert_eq!(
        spool_payload(pool, held_archive).await?,
        Some(original_xml("held-archive"))
    );
    assert_eq!(
        spool_payload(pool, held_spool).await?,
        Some(original_xml("held-spool"))
    );
    assert_eq!(spool_payload(pool, unheld).await?, None);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn local_action_id_is_reusable_after_sender_recreation_but_remote_replay_survives(
) -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let old = accounts(pool).await?;
    admit_original(pool, old, "prior-original", true).await?;
    assert!(matches!(
        local_retract(pool, old, "prior-original", "reused", true, Some(32), None).await?,
        RetractionOutcome::Applied { tombstones: 2, .. }
    ));
    assert_eq!(
        local_retract(pool, old, "prior-original", "reused", true, Some(32), None).await?,
        RetractionOutcome::Replay
    );
    assert!(matches!(
        remote_retract(pool, old.bob, REMOTE_ACTION).await?,
        Ok(RetractionOutcome::Applied { tombstones: 0, .. })
    ));
    assert!(
        northstar_workflows::account_lifecycle::delete_user_with_roster(
            &northstar_workflows::roster::WorkflowRosterEffects,
            pool,
            old.alice,
            "local.test",
        )
        .await?
        .is_some()
    );
    let prior_intent: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM personal_retraction_intents WHERE sender_bare_jid='alice@local.test')",
    )
    .fetch_one(pool)
    .await?;
    assert!(!prior_intent);
    let replacement = Accounts {
        alice: account(pool, "alice", false).await?,
        bob: old.bob,
    };
    admit_original(pool, replacement, "new-original", true).await?;
    assert!(matches!(
        local_retract(
            pool,
            replacement,
            "new-original",
            "reused",
            true,
            Some(32),
            None
        )
        .await?,
        RetractionOutcome::Applied { tombstones: 2, .. }
    ));
    assert_eq!(
        local_retract(
            pool,
            replacement,
            "new-original",
            "reused",
            true,
            Some(32),
            None
        )
        .await?,
        RetractionOutcome::Replay
    );
    assert_eq!(
        remote_retract(pool, old.bob, REMOTE_ACTION).await?,
        Ok(RetractionOutcome::Replay)
    );
    let scopes: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT sender_bare_jid,sender_account_id FROM personal_retraction_intents ORDER BY sender_bare_jid",
    )
    .fetch_all(pool)
    .await?;
    assert_eq!(
        scopes,
        vec![
            ("alice@local.test".into(), Some(replacement.alice)),
            ("bob@remote.test".into(), None)
        ]
    );
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn migration_backfills_only_proven_local_sender_commitments() -> Result<()> {
    let fixture = Fixture::schema().await?;
    let pool = &fixture.pool;
    let predecessor = sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            northstar_postgres::MIGRATOR
                .iter()
                .filter(|migration| migration.version < 164)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    predecessor.run(pool).await?;
    let pair = accounts(pool).await?;
    for (action, sender, digest) in [
        ("local", "alice@local.test", 1_u8),
        ("remote", "bob@remote.test", 2),
        ("unproven", "alice@local.test", 3),
    ] {
        let intent = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO personal_retraction_intents
             (id,sender_bare_jid,action_id,action_digest,target_id,semantic_key_id,semantic_mac,
              owner_projection_key_id,owner_projection_mac,outbound_requested)
             VALUES($1,$2,$3,$4,'original','AAAAAAAAAAAAAAAA',$4,'AAAAAAAAAAAAAAAA',$4,FALSE)",
        )
        .bind(intent)
        .bind(sender)
        .bind(action)
        .bind(vec![digest; 32])
        .execute(pool)
        .await?;
        let projections = match action {
            "local" => vec![(pair.alice, RECIPIENT), (pair.bob, SENDER)],
            "remote" => vec![(pair.bob, REMOTE)],
            _ => vec![],
        };
        for (ordinal, (owner, peer)) in projections.into_iter().enumerate() {
            let id = Uuid::new_v4();
            northstar_archive_postgres::archive_message(
                pool, id, owner, peer,
                &format!("<message from='{sender}' to='{RECIPIENT}' id='{action}'><retract xmlns='urn:xmpp:message-retract:1' id='original'/></message>"),
                false, Some(action),
            )
            .await?;
            sqlx::query(
                "INSERT INTO personal_retraction_action_projections(intent_id,ordinal,owner_id,archive_id)
                 VALUES($1,$2,$3,$4)",
            )
            .bind(intent)
            .bind(i16::try_from(ordinal)?)
            .bind(owner)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }
    crate::support::migrate(pool).await?;
    let scopes: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT action_id,sender_account_id FROM personal_retraction_intents ORDER BY action_id",
    )
    .fetch_all(pool)
    .await?;
    assert_eq!(
        scopes,
        vec![
            ("local".into(), Some(pair.alice)),
            ("remote".into(), None),
            ("unproven".into(), None)
        ]
    );
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn stale_retraction_actor_cannot_write_or_replay_as_current_generation() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let pair = accounts(pool).await?;
    let original = admit_original(pool, pair, "fenced", true).await?;
    let current: i64 = sqlx::query_scalar(
        "UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1 RETURNING auth_generation",
    )
    .bind(pair.alice)
    .fetch_one(pool)
    .await?;
    let stale = Some(ActorGenerationFence {
        account_id: pair.alice,
        auth_generation: current - 1,
    });
    let fresh = Some(ActorGenerationFence {
        account_id: pair.alice,
        auth_generation: current,
    });
    assert_eq!(
        local_retract(pool, pair, "fenced", "actor-action", true, Some(32), stale).await?,
        RetractionOutcome::AccountUnavailable
    );
    assert_eq!(
        archive_payloads(pool, &original).await?,
        vec![original_xml("fenced"); 2]
    );
    assert_eq!(
        spool_payload(pool, original[1]).await?,
        Some(original_xml("fenced"))
    );
    assert!(matches!(
        local_retract(pool, pair, "fenced", "actor-action", true, Some(32), fresh).await?,
        RetractionOutcome::Applied { tombstones: 2, .. }
    ));
    assert_eq!(
        local_retract(pool, pair, "fenced", "actor-action", true, Some(32), stale).await?,
        RetractionOutcome::AccountUnavailable
    );
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn no_store_federated_retraction_has_no_durable_effects() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let recipient = account(pool, "bob", false).await?;
    let stanza =
        REMOTE_ACTION.replace("</message>", "<no-store xmlns='urn:xmpp:hints'/></message>");
    let outcome = remote_retract(pool, recipient, &stanza).await?;
    let effects: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM personal_retraction_intents),
                (SELECT count(*) FROM message_archive),
                (SELECT count(*) FROM offline_messages),
                (SELECT count(*) FROM direct_spool_wake_outbox),
                (SELECT count(*) FROM s2s_outbox)",
    )
    .fetch_one(pool)
    .await?;
    assert_eq!(effects, (0, 0, 0, 0, 0));
    assert_eq!(outcome, Err(InvalidPersonalRetraction::NoStore));
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn paired_tombstones_share_the_retraction_transaction_timestamp() -> Result<()> {
    let fixture = Fixture::migrated().await?;
    let pool = &fixture.pool;
    let pair = accounts(pool).await?;
    let originals = admit_original(pool, pair, "stamp", true).await?;
    sqlx::raw_sql(
        "CREATE TABLE retraction_test_clock(stamp TIMESTAMPTZ NOT NULL);
         CREATE FUNCTION capture_retraction_test_clock() RETURNS TRIGGER LANGUAGE plpgsql AS $$
         BEGIN
             INSERT INTO retraction_test_clock VALUES (now());
             RETURN NEW;
         END;
         $$;
         CREATE TRIGGER capture_retraction_test_clock AFTER INSERT ON personal_retraction_intents
         FOR EACH ROW EXECUTE FUNCTION capture_retraction_test_clock();",
    )
    .execute(pool)
    .await?;
    let mut barrier = pool.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await?;
    sqlx::query("SELECT id FROM message_archive WHERE id=$1 FOR UPDATE")
        .bind(originals[0])
        .fetch_one(&mut *barrier)
        .await?;
    let retraction_pool = pool.clone();
    let task = tokio::spawn(async move {
        local_retract(
            &retraction_pool,
            pair,
            "stamp",
            "stamp-action",
            false,
            None,
            None,
        )
        .await
    });
    let waiter = crate::support::blocked_backend(pool, blocker).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let passed: bool = sqlx::query_scalar(
                "SELECT clock_timestamp() > xact_start + INTERVAL '2 seconds' FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(waiter)
            .fetch_one(pool)
            .await?;
            if passed {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    barrier.commit().await?;
    assert!(matches!(
        task.await??,
        RetractionOutcome::Applied { tombstones: 2, .. }
    ));
    let expected: northstar_time::DateTime<northstar_time::Utc> =
        sqlx::query_scalar("SELECT stamp FROM retraction_test_clock")
            .fetch_one(pool)
            .await?;
    let expected = expected.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let tombstones = archive_payloads(pool, &originals).await?;
    assert_eq!(tombstones.len(), 2);
    for stanza in tombstones {
        let document = Document::parse(&stanza)?;
        let tombstone = document.root_element().first_element_child().unwrap();
        assert_eq!(tombstone.tag_name().name(), "retracted");
        assert_eq!(tombstone.attribute("stamp"), Some(expected.as_str()));
    }
    fixture.close().await
}
