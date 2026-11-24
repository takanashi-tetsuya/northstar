use northstar_operations_postgres::data_lifecycle::*;
use northstar_time::Duration;
use northstar_time::Utc;
use northstar_workflows::governance_repository::list_legal_holds_audited;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_hold_cleanup_delete_release_and_audit_invariants() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::support::migrate(&pool).await.unwrap();
    let admin = Uuid::new_v4();
    let user = Uuid::new_v4();
    for (id, prefix, is_admin) in [
        (admin, "governance-admin", true),
        (user, "governance-user", false),
    ] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
                 VALUES($1,$2,'test-only',$3)",
        )
        .bind(id)
        .bind(format!("{prefix}-{}", &id.simple().to_string()[..10]))
        .bind(is_admin)
        .execute(&pool)
        .await
        .unwrap();
    }
    let room = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,owner_id,persistent)
             VALUES($1,$2,$3,TRUE)",
    )
    .bind(room)
    .bind(format!("hold-{}", &room.simple().to_string()[..10]))
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let old = Utc::now() - Duration::days(60);
    let personal = Uuid::new_v4();
    let muc = Uuid::new_v4();
    let offline = Uuid::new_v4();
    let encrypted_stanza = "<message><encrypted xmlns='urn:xmpp:omemo:2'/></message>";
    sqlx::query(
        "INSERT INTO message_archive(
                 id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at)
             VALUES($1,$2,'peer@example.test','peer@example.test/device',$3,TRUE,$4)",
    )
    .bind(personal)
    .bind(user)
    .bind(encrypted_stanza)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO muc_messages(
                 id,room_id,sender_jid,nick,stanza,encrypted,created_at)
             VALUES($1,$2,'sender@example.test/device','sender',$3,TRUE,$4)",
    )
    .bind(muc)
    .bind(room)
    .bind(encrypted_stanza)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO offline_messages(
                 id,recipient_id,sender_jid,stanza,encrypted,created_at)
             VALUES($1,$2,'sender@example.test',$3,TRUE,$4)",
    )
    .bind(offline)
    .bind(user)
    .bind(encrypted_stanza)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    let report = Uuid::new_v4();
    let evidence = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO abuse_reports(
                 id,reporter_id,reported_jid,category,description,status,
                 resolved_at,created_at,updated_at)
             VALUES($1,$2,'reported@example.test','spam','fixture','closed',$3,$3,$3)",
    )
    .bind(report)
    .bind(user)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_report_evidence(
                 id,report_id,sender_jid,body_text,encrypted,position,created_at)
             VALUES($1,$2,'reported@example.test','unverified decrypted text',TRUE,0,$3)",
    )
    .bind(evidence)
    .bind(report)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();

    let hold = Uuid::new_v4();
    let targets = [
        LegalHoldTarget::PersonalArchive(personal),
        LegalHoldTarget::MucArchiveRoom(room),
        LegalHoldTarget::OfflineMessage(offline),
        LegalHoldTarget::ReportEvidence(evidence),
    ];
    let mut tx = pool.begin().await.unwrap();
    create_legal_hold_in_tx(
        &mut tx,
        admin,
        &CreateLegalHold {
            id: hold,
            title: "isolated fixture",
            authority_reference: "case-fixture-1",
            reason: "verify atomic retention exclusion",
            targets: &targets,
            request_id: Uuid::new_v4(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let admin_session = northstar_auth_postgres::users::create_api_session(&pool, admin, 1)
        .await
        .unwrap();
    let access_key_sha256 = "ab".repeat(32);
    let summaries = list_legal_holds_audited(
        &pool,
        admin,
        0,
        &admin_session,
        false,
        100,
        &access_key_sha256,
    )
    .await
    .unwrap();
    assert!(summaries.iter().any(|summary| summary.id == hold));
    assert!(matches!(
        list_legal_holds_audited(
            &pool,
            admin,
            0,
            &admin_session,
            false,
            101,
            &access_key_sha256,
        )
        .await,
        Err(LegalHoldError::Invalid)
    ));
    let mut logout = pool.begin().await.unwrap();
    assert!(
        northstar_auth_postgres::users::delete_api_session_audited_in_tx(
            &mut logout,
            &admin_session,
            Uuid::new_v4(),
        )
        .await
        .unwrap()
    );
    logout.commit().await.unwrap();
    assert!(matches!(
        list_legal_holds_audited(
            &pool,
            admin,
            0,
            &admin_session,
            false,
            100,
            &access_key_sha256,
        )
        .await,
        Err(LegalHoldError::Forbidden)
    ));

    for store in [
        northstar_workflows::retention::RetentionStore::PersonalMam,
        northstar_workflows::retention::RetentionStore::MucMam,
        northstar_workflows::retention::RetentionStore::OfflineMessages,
    ] {
        assert_eq!(
            northstar_workflows::retention::purge_resolved_retention_batch(
                &pool,
                store,
                Utc::now(),
                30,
                100
            )
            .await
            .unwrap(),
            0
        );
    }
    assert_eq!(
        northstar_operations_postgres::reports::purge_resolved_moderation_batch(&pool, 30, 100)
            .await
            .unwrap(),
        0
    );
    assert!(sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .is_err());
    assert!(sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room)
        .execute(&pool)
        .await
        .is_err());

    // A transport ACK may delete its queue row, but the trigger retains
    // only the encrypted, server-visible stanza in the same transaction.
    sqlx::query("DELETE FROM offline_messages WHERE id=$1")
        .bind(offline)
        .execute(&pool)
        .await
        .unwrap();
    let snapshot: (bool, String) = sqlx::query_as(
        "SELECT encrypted,stanza FROM legal_hold_offline_snapshots
              WHERE hold_id=$1 AND message_id=$2",
    )
    .bind(hold)
    .bind(offline)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(snapshot.0);
    assert!(snapshot.1.contains("urn:xmpp:omemo:2"));

    // Export initialization and release serialize on the same legal_holds
    // row.  The lease is inserted before that row lock is released, so a
    // release which was already waiting must observe the lease and fail
    // closed after the export transaction commits.
    let mut first_export_tx = pool.begin().await.unwrap();
    let first_export = export_legal_hold_page_in_tx(
        &mut first_export_tx,
        admin,
        hold,
        1,
        Uuid::new_v4(),
        None,
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    assert!(!first_export.complete);
    assert!(first_export.next.is_some());
    let release_pool = pool.clone();
    let blocked_release = tokio::spawn(async move {
        let mut tx = release_pool.begin().await.unwrap();
        let result = release_legal_hold_in_tx(
            &mut tx,
            admin,
            hold,
            "must wait for the frozen export",
            Uuid::new_v4(),
        )
        .await;
        tx.rollback().await.unwrap();
        result
    });
    tokio::task::yield_now().await;
    first_export_tx.commit().await.unwrap();
    assert!(matches!(
        blocked_release.await.unwrap(),
        Err(LegalHoldError::Conflict)
    ));

    let mut next = first_export.next;
    let mut previous_root = first_export.chain_root_sha256;
    while let Some(cursor) = next {
        let mut page_tx = pool.begin().await.unwrap();
        let page = export_legal_hold_page_in_tx(
            &mut page_tx,
            admin,
            hold,
            1,
            Uuid::new_v4(),
            Some(cursor),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
        assert_eq!(page.chain_start_sha256, previous_root);
        previous_root = page.chain_root_sha256.clone();
        next = page.next;
        page_tx.commit().await.unwrap();
    }

    // The inverse race is also fail closed: when release owns the row lock
    // first, an initial export waits, then observes a released hold.  It
    // may return only a complete single page and must not create a lease
    // or continuation that claims the released payload is frozen.
    let mut release = pool.begin().await.unwrap();
    release_legal_hold_in_tx(
        &mut release,
        admin,
        hold,
        "fixture authority ended",
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    let release_won_export_id = Uuid::new_v4();
    let released_export_pool = pool.clone();
    let released_export = tokio::spawn(async move {
        let mut tx = released_export_pool.begin().await.unwrap();
        let result = export_legal_hold_page_in_tx(
            &mut tx,
            admin,
            hold,
            MAX_GOVERNANCE_EXPORT_ROWS,
            release_won_export_id,
            None,
            Uuid::new_v4(),
        )
        .await;
        match result {
            Ok(page) => {
                tx.commit().await.unwrap();
                Ok(page)
            }
            Err(error) => {
                tx.rollback().await.unwrap();
                Err(error)
            }
        }
    });
    tokio::task::yield_now().await;
    release.commit().await.unwrap();
    let released_export = released_export.await.unwrap().unwrap();
    assert!(released_export.complete);
    assert!(released_export.next.is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM governance_export_leases WHERE id=$1")
            .bind(release_won_export_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        purge_released_hold_snapshots_batch(&pool, 30, 100)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        northstar_workflows::retention::purge_resolved_retention_batch(
            &pool,
            northstar_workflows::retention::RetentionStore::PersonalMam,
            Utc::now(),
            30,
            100,
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        northstar_workflows::retention::purge_resolved_retention_batch(
            &pool,
            northstar_workflows::retention::RetentionStore::MucMam,
            Utc::now(),
            30,
            100,
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        northstar_operations_postgres::reports::purge_resolved_moderation_batch(&pool, 30, 100)
            .await
            .unwrap(),
        1
    );

    let old_audit = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO audit_log(action,target,details,request_id,created_at)
             VALUES('fixture.old',$1,'{}'::JSONB,$2,$3)",
    )
    .bind(old_audit.to_string())
    .bind(old_audit)
    .bind(old)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        sqlx::query("UPDATE audit_log SET action='tampered' WHERE request_id=$1")
            .bind(old_audit)
            .execute(&pool)
            .await
            .is_err()
    );
    assert_eq!(purge_audit_log_batch(&pool, 30, 100).await.unwrap(), 1);

    sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(vec![user, admin])
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn legal_hold_retractions_succeed_without_replacing_evidence() {
    use northstar_archive_postgres::mix_source_retractions::{
        lock_sources_in_tx, record_locked_in_tx,
    };
    use northstar_archive_postgres::{
        mam_user_archive_page, MamArchiveQuery, MamRoomReadOutcome, MamRsmPage,
    };
    use northstar_message_application::retractions::{
        ArchiveWrite, OwnerProjection, RetractionCommand, RetractionOutcome, RetractionService,
    };
    use northstar_operations_application::api_queries::{ApiQueryRepository, ApiReadAuthority};
    use northstar_room_postgres::muc::{
        retract_muc_message_and_archive_action, MucActorAuthority, MucActorPrincipal,
        MucRetractionKind, MucRetractionMutation, MucRetractionOutcome,
    };
    use northstar_workflows::{
        api_queries::PostgresApiQueryRepository, mam_room::mam_room_archive_page_authorized,
        retraction_repository::PostgresRetractionRepository,
    };

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::support::migrate(&pool).await.unwrap();

    let [admin, sender, room, hold, personal, muc, personal_action, muc_action] =
        [(); 8].map(|()| Uuid::new_v4());
    let [mix_copy, mix_target, mix_action, overlapping_hold] = [(); 4].map(|()| Uuid::new_v4());
    let channel = format!("chan-{}@mix.remote.test", mix_target.simple());
    let mix_original = format!(
        "<message from='{channel}/publisher' type='groupchat' id='{mix_target}'><body>MIX evidence</body></message>"
    );
    let username = format!("held-sender-{}", &sender.simple().to_string()[..12]);
    let actor_scope = format!("{username}@local.test");
    let sender_jid = format!("{actor_scope}/Device");
    let peer = "peer@example.test/device";
    let localpart = format!("held-room-{}", &room.simple().to_string()[..12]);
    for (id, name, is_admin) in [
        (
            admin,
            format!("held-admin-{}", &admin.simple().to_string()[..12]),
            true,
        ),
        (sender, username.clone(), false),
    ] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',$3)",
        )
        .bind(id)
        .bind(name)
        .bind(is_admin)
        .execute(&pool)
        .await
        .unwrap();
    }
    let room_epoch: Uuid = sqlx::query_scalar(
        "INSERT INTO muc_rooms(id,localpart,owner_id,persistent)
         VALUES($1,$2,$3,TRUE) RETURNING room_epoch",
    )
    .bind(room)
    .bind(&localpart)
    .bind(sender)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO muc_affiliations(room_id,user_id,affiliation) VALUES($1,$2,'owner')")
        .bind(room)
        .bind(sender)
        .execute(&pool)
        .await
        .unwrap();

    let personal_original = format!(
        "<message from='{sender_jid}' to='{peer}' id='personal-original'><body>personal evidence</body></message>"
    );
    let muc_original =
        "<message type='groupchat' id='muc-original'><body>room evidence</body></message>";
    sqlx::query(
        "INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id,created_at)
         VALUES($1,$2,'peer@example.test',$3,$4,FALSE,'personal-original',NOW()-INTERVAL '1 day')",
    )
    .bind(personal)
    .bind(sender)
    .bind(peer)
    .bind(&personal_original)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,actor_scope,created_at)
         VALUES($1,$2,$3,'Sender',$4,FALSE,$5,NOW()-INTERVAL '1 day')",
    )
    .bind(muc)
    .bind(room)
    .bind(&sender_jid)
    .bind(muc_original)
    .bind(&actor_scope)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,
                                     source_by,source_stanza_id,source_payload_digest,created_at)
         VALUES($1,$2,$3,$3,$4,FALSE,$3,$5,decode(repeat('ab',32),'hex'),NOW()-INTERVAL '12 hours')",
    )
    .bind(mix_copy)
    .bind(sender)
    .bind(&channel)
    .bind(&mix_original)
    .bind(mix_target)
    .execute(&pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    create_legal_hold_in_tx(
        &mut tx,
        admin,
        &CreateLegalHold {
            id: hold,
            title: "retraction fixture",
            authority_reference: "case-retraction",
            reason: "preserve original archive payloads",
            targets: &[
                LegalHoldTarget::PersonalArchive(personal),
                LegalHoldTarget::PersonalArchive(mix_copy),
                LegalHoldTarget::MucArchiveRoom(room),
            ],
            request_id: Uuid::new_v4(),
        },
    )
    .await
    .unwrap();
    create_legal_hold_in_tx(
        &mut tx,
        admin,
        &CreateLegalHold {
            id: overlapping_hold,
            title: "overlapping exact and scoped hold",
            authority_reference: "case-overlap",
            reason: "verify one display change per archive row",
            targets: &[
                LegalHoldTarget::PersonalArchiveOwner(sender),
                LegalHoldTarget::MucArchive(muc),
            ],
            request_id: Uuid::new_v4(),
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let service = RetractionService::new(
        PostgresRetractionRepository::new(pool.clone()),
        northstar_abuse_application::guard::test_personal_retraction_content_keyring(),
        "local.test",
    );
    let personal_action_xml = format!(
        "<message from='{sender_jid}' to='{peer}' id='personal-action'><retract xmlns='urn:xmpp:message-retract:1' id='personal-original'/></message>"
    );
    let retract_personal = async || {
        service
            .apply(
                &[OwnerProjection {
                    owner_id: sender,
                    peer_jid: peer,
                }],
                &sender_jid,
                &RetractionCommand {
                    actor_fence: None,
                    target_id: "personal-original",
                    action_id: "personal-action",
                    semantic_payload: &personal_action_xml,
                },
                &[ArchiveWrite {
                    id: personal_action,
                    owner_id: sender,
                    peer_jid: peer,
                    stanza: &personal_action_xml,
                    encrypted: false,
                    stanza_id: Some("personal-action"),
                }],
                None,
            )
            .await
    };
    let muc_tombstone = format!(
        "<message type='groupchat' id='muc-original'><retracted xmlns='urn:xmpp:message-retract:1' id='{muc_action}' stamp='2026-01-01T00:00:00Z'><moderated xmlns='urn:xmpp:message-moderate:1' by='{localpart}@muc.local.test/Sender'/><reason>Off topic</reason></retracted></message>"
    );
    let muc_action_xml = format!(
        "<message type='groupchat' id='muc-action'><retract xmlns='urn:xmpp:message-retract:1' id='{muc}'><moderated xmlns='urn:xmpp:message-moderate:1' by='{localpart}@muc.local.test/Sender'/><reason>Off topic</reason></retract></message>"
    );
    let retract_muc = async || {
        retract_muc_message_and_archive_action(
            &pool,
            MucRetractionMutation {
                action_id: muc_action,
                room_id: room,
                target_id: muc,
                expected_stanza: muc_original,
                actor_scope: &actor_scope,
                sender_jid: &sender_jid,
                nick: "Sender",
                tombstone: &muc_tombstone,
                action_stanza: &muc_action_xml,
                reason: Some("Off topic"),
                kind: MucRetractionKind::Moderator,
                authority: MucActorAuthority {
                    clustered: false,
                    expected_room_epoch: room_epoch,
                    principal: MucActorPrincipal::Local {
                        user_id: sender,
                        local_domain: "local.test",
                    },
                    actor_scope: &actor_scope,
                    full_jid: &sender_jid,
                    nick: "Sender",
                    occupant_incarnation: Uuid::nil(),
                    connection_uuid: Uuid::nil(),
                    expected_role: "moderator",
                    expected_affiliation: "owner",
                    cluster_target: None,
                },
            },
        )
        .await
    };

    let api = PostgresApiQueryRepository::new(pool.clone());
    let token = northstar_auth_postgres::users::create_api_session(&pool, sender, 1)
        .await
        .unwrap();
    let query = MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page: MamRsmPage::First,
        max: 10,
    };
    let read_pages = async || {
        let personal_page = mam_user_archive_page(&pool, sender, &query)
            .await
            .unwrap()
            .unwrap();
        let history = api
            .history(
                ApiReadAuthority {
                    user_id: sender,
                    auth_generation: 0,
                    session_token: &token,
                },
                &query,
            )
            .await
            .unwrap()
            .expect("sender's bearer should authorize personal history")
            .value
            .unwrap();
        assert_eq!(history, personal_page);
        let MamRoomReadOutcome::Allowed {
            value: Some(muc_page),
            ..
        } = mam_room_archive_page_authorized(
            &pool,
            &localpart,
            &northstar_archive_core::MamLocalAuthority {
                id: sender,
                username: username.clone(),
                auth_generation: 0,
            },
            &northstar_archive_core::MamRoomReadAuthority {
                full_jid: sender_jid.clone(),
                occupancy: None,
            },
            &query,
        )
        .await
        .unwrap()
        else {
            panic!("room owner should have a MUC MAM page");
        };
        (personal_page, muc_page)
    };
    let export = async |hold| {
        let mut tx = pool.begin().await.unwrap();
        let page = export_legal_hold_page_in_tx(
            &mut tx,
            admin,
            hold,
            10,
            Uuid::new_v4(),
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert!(page.complete && page.next.is_none());
        page
    };

    let (original_personal, original_room) = read_pages().await;
    assert_eq!(
        archive_payloads(&original_personal),
        [
            (personal, personal_original.as_str()),
            (mix_copy, mix_original.as_str())
        ]
    );
    assert_eq!(archive_payloads(&original_room), [(muc, muc_original)]);
    assert_eq!(
        retract_personal().await.unwrap(),
        RetractionOutcome::Applied {
            tombstones: 1,
            live_claim_id: None
        }
    );
    assert_eq!(retract_muc().await.unwrap(), MucRetractionOutcome::Applied);
    let mut fact = pool.begin().await.unwrap();
    lock_sources_in_tx(&mut fact, &channel, &[mix_target, mix_action], true)
        .await
        .unwrap();
    assert!(
        record_locked_in_tx(&mut fact, &channel, mix_target, mix_action, "publisher",)
            .await
            .unwrap()
    );
    fact.commit().await.unwrap();

    let (held_personal, held_muc) = read_pages().await;
    assert_eq!(held_personal.total, 3);
    assert_eq!(held_muc.total, 2);
    assert_eq!(held_personal.first_index, original_personal.first_index);
    assert_eq!(held_muc.first_index, original_room.first_index);
    assert_eq!(
        held_personal.rows[0].created_at,
        original_personal.rows[0].created_at
    );
    assert_eq!(
        held_personal.rows[1].created_at,
        original_personal.rows[1].created_at
    );
    assert_eq!(
        held_muc.rows[0].created_at,
        original_room.rows[0].created_at
    );
    for (row, action) in held_personal.rows[..2]
        .iter()
        .zip(["personal-action".to_owned(), mix_action.to_string()])
    {
        let parsed = roxmltree::Document::parse(&row.stanza).unwrap();
        let children: Vec<_> = parsed
            .root_element()
            .children()
            .filter(roxmltree::Node::is_element)
            .collect();
        assert!(children.iter().all(|node| node.tag_name().name() != "body"));
        let retracted = children.last().unwrap();
        assert_eq!(retracted.tag_name().name(), "retracted");
        assert_eq!(
            retracted.tag_name().namespace(),
            Some("urn:xmpp:message-retract:1")
        );
        assert_eq!(retracted.attribute("id"), Some(action.as_str()));
        assert!(!row.encrypted);
    }
    assert_eq!(held_personal.rows[0].id, personal);
    assert_eq!(held_personal.rows[1].id, mix_copy);
    assert_eq!(held_personal.rows[2].id, personal_action);
    assert_eq!(held_personal.rows[2].stanza, personal_action_xml);
    assert_eq!(
        archive_payloads(&held_muc),
        [
            (muc, muc_tombstone.as_str()),
            (muc_action, muc_action_xml.as_str())
        ]
    );
    assert!(held_muc.rows[0].muc.as_ref().unwrap().retracted);

    for (table, id, original) in [
        ("message_archive", personal, personal_original.as_str()),
        ("message_archive", mix_copy, mix_original.as_str()),
        ("muc_messages", muc, muc_original),
    ] {
        let query = format!("SELECT stanza,encrypted FROM {table} WHERE id=$1");
        let raw: (String, bool) = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(raw, (original.to_owned(), false));
        for statement in [
            format!("UPDATE {table} SET stanza='<message/>' WHERE id=$1"),
            format!("DELETE FROM {table} WHERE id=$1"),
        ] {
            let error = sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                .bind(id)
                .execute(&pool)
                .await
                .unwrap_err();
            let db = error.as_database_error().unwrap();
            assert_eq!(db.code().as_deref(), Some("55000"));
            assert_eq!(
                db.message(),
                "data record is protected by an active legal hold"
            );
        }
    }

    let expected = [
        (
            "personal_archive",
            personal,
            Some(personal_original.as_str()),
        ),
        ("personal_archive", mix_copy, Some(mix_original.as_str())),
        ("muc_archive", muc, Some(muc_original)),
        ("muc_archive", muc_action, Some(muc_action_xml.as_str())),
    ];
    let held_export = export(hold).await;
    assert_eq!(held_export.format, "northstar-legal-hold-chain-v3");
    assert!(held_export.hold.released_at.is_none());
    assert_eq!(exported_payloads(&held_export), expected);
    let annotations = [
        (
            personal,
            "personal_retraction",
            actor_scope.as_str(),
            "personal-action".to_owned(),
            None,
        ),
        (
            mix_copy,
            "mix_retraction",
            channel.as_str(),
            mix_action.to_string(),
            None,
        ),
        (
            muc,
            "muc_moderation",
            actor_scope.as_str(),
            muc_action.to_string(),
            Some("Off topic"),
        ),
    ];
    let overlapping_export = export(overlapping_hold).await;
    for page in [&held_export, &overlapping_export] {
        assert_eq!(
            page.records
                .iter()
                .filter(|row| row.display_change.is_some())
                .count(),
            3
        );
        for (id, kind, actor, action, reason) in &annotations {
            let record = page
                .records
                .iter()
                .find(|row| row.record_id == *id)
                .unwrap();
            let change = record.display_change.as_ref().unwrap();
            assert_eq!(serde_json::to_value(change.kind).unwrap(), *kind);
            assert_eq!(change.actor.as_str(), *actor);
            assert_eq!(&change.action_id, action);
            assert_eq!(change.reason.as_deref(), *reason);
        }
    }

    for id in [hold, overlapping_hold] {
        let mut release = pool.begin().await.unwrap();
        release_legal_hold_in_tx(
            &mut release,
            admin,
            id,
            "fixture authority ended",
            Uuid::new_v4(),
        )
        .await
        .unwrap();
        release.commit().await.unwrap();
    }
    assert_eq!(retract_personal().await.unwrap(), RetractionOutcome::Replay);
    assert_eq!(retract_muc().await.unwrap(), MucRetractionOutcome::Conflict);
    assert_eq!(read_pages().await, (held_personal, held_muc));
    let released_export = export(hold).await;
    assert!(released_export.hold.released_at.is_some());
    assert!(released_export.lease_expires_at.is_none());
    assert_eq!(exported_payloads(&released_export), expected);
    assert_eq!(
        released_export
            .records
            .iter()
            .filter(|row| row.display_change.is_some())
            .count(),
        3
    );
    sqlx::query("DELETE FROM mix_source_retractions WHERE source_by=$1")
        .bind(&channel)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(vec![sender, admin])
        .execute(&pool)
        .await
        .unwrap();
}

fn archive_payloads(page: &northstar_archive_core::ArchivePage) -> Vec<(Uuid, &str)> {
    page.rows
        .iter()
        .map(|row| (row.id, row.stanza.as_str()))
        .collect()
}

fn exported_payloads(page: &LegalHoldExport) -> Vec<(&str, Uuid, Option<&str>)> {
    page.records
        .iter()
        .map(|record| {
            assert!(!record.encrypted);
            assert_eq!(record.payload_disposition, "server_plaintext");
            (
                record.resource_type.as_str(),
                record.record_id,
                record.server_visible_payload.as_deref(),
            )
        })
        .collect()
}
