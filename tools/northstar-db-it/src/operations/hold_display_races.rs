use futures::future::BoxFuture;
use northstar_archive_postgres::{
    mam_archive_page_for_in_transaction, ArchivePage, MamArchiveQuery, MamArchiveSource, MamRsmPage,
};
use northstar_message_application::retractions::{
    ArchiveWrite, DeliveryProjection, OwnerProjection, RetractionCommand, RetractionOutcome,
    RetractionService,
};
use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
use northstar_message_postgres::direct_cluster::{DirectCommitCluster, DirectCommitPermit};
use northstar_operations_postgres::data_lifecycle::*;
use northstar_room_postgres::muc::{
    muc_history_since, muc_message_by_id, retract_muc_message_and_archive_action,
    MucActorAuthority, MucActorPrincipal, MucRetractionKind, MucRetractionMutation,
    MucRetractionOutcome,
};
use northstar_security::cluster_keys::{ClusterKeyDeploymentIdentity, ClusterReadinessAuthority};
use northstar_session_postgres::cluster_keys::{
    claim_cluster_node_instance, fence_direct_message_authority_in_transaction,
    reconcile_cluster_key_deployment_before_instance_claim, release_cluster_node_instance,
};
use northstar_time::{Duration, Utc};
use northstar_workflows::retraction_repository::PostgresRetractionRepository;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const ROOM_ORIGINAL: &str =
    "<message type='groupchat' id='original'><body>held room bytes</body></message>";

#[derive(Clone)]
struct LiveRetractionCluster(ClusterReadinessAuthority);

struct LiveRetractionTurn;

impl DirectCommitPermit for LiveRetractionTurn {
    fn admitted_mode(&self) -> DirectPostCommitMode {
        DirectPostCommitMode::Live
    }

    fn finish(self: Box<Self>) -> DirectPostCommitMode {
        self.admitted_mode()
    }
}

impl DirectCommitCluster for LiveRetractionCluster {
    fn is_enabled(&self) -> bool {
        true
    }

    fn direct_mode(&self) -> DirectPostCommitMode {
        DirectPostCommitMode::Live
    }

    fn check_direct_eligibility(
        &self,
        _: DirectSpoolEligibility,
    ) -> anyhow::Result<Option<&ClusterReadinessAuthority>> {
        Ok(Some(&self.0))
    }

    fn begin_direct_commit_turn(
        &self,
        _: DirectSpoolEligibility,
    ) -> anyhow::Result<(
        Box<dyn DirectCommitPermit>,
        Option<&ClusterReadinessAuthority>,
    )> {
        Ok((Box::new(LiveRetractionTurn), Some(&self.0)))
    }

    fn fence_authority<'a>(
        &'a self,
        tx: &'a mut Transaction<'_, Postgres>,
        authority: &'a ClusterReadinessAuthority,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(fence_direct_message_authority_in_transaction(tx, authority))
    }
}

impl LiveRetractionCluster {
    async fn claim(pool: &PgPool) -> Self {
        let key = ClusterKeyDeploymentIdentity {
            xmpp_domain: format!("hold-{}.test", Uuid::new_v4().simple()),
            node_id: "held-retraction".into(),
            epoch: 1,
            current_key_id: "AAAAAAAAAAAAAAAA".into(),
            current_public_key_sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            previous_key_id: None,
            previous_public_key_sha256: None,
            staged_next_key_id: None,
            staged_next_public_key_sha256: None,
        };
        reconcile_cluster_key_deployment_before_instance_claim(pool, &key)
            .await
            .unwrap();
        let instance_uuid = Uuid::new_v4();
        let instance = claim_cluster_node_instance(
            pool,
            &key.xmpp_domain,
            &key.node_id,
            instance_uuid,
            &key.current_key_id,
            key.epoch,
            std::time::Duration::from_secs(90),
        )
        .await
        .unwrap();
        Self(ClusterReadinessAuthority {
            instance_node_id: key.node_id.clone(),
            signing_key_id: key.current_key_id.clone(),
            signing_key_epoch: key.epoch,
            key_identity: key,
            instance_uuid,
            instance_epoch: instance.instance_epoch,
        })
    }

    async fn release(&self, pool: &PgPool) {
        let authority = &self.0;
        assert!(release_cluster_node_instance(
            pool,
            &authority.key_identity.xmpp_domain,
            &authority.instance_node_id,
            authority.instance_uuid,
            authority.instance_epoch,
            &authority.signing_key_id,
            authority.signing_key_epoch,
        )
        .await
        .unwrap());
    }
}

#[derive(Clone, Copy, Debug)]
enum Archive {
    Personal,
    Room,
}

impl Archive {
    fn table(self) -> &'static str {
        match self {
            Self::Personal => "message_archive",
            Self::Room => "muc_messages",
        }
    }
}

#[derive(Clone)]
struct Fixture {
    pool: PgPool,
    admin: Uuid,
    user: Uuid,
    room: Uuid,
    room_epoch: Uuid,
    localpart: String,
    bare: String,
    full: String,
    personal: Uuid,
    muc: Uuid,
    action: Uuid,
    personal_original: String,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::support::migrate(&pool).await.unwrap();
        let [admin, user, room, personal, muc, action] = [(); 6].map(|()| Uuid::new_v4());
        let username = format!("held-user-{}", user.simple());
        for (id, name, is_admin) in [
            (admin, format!("held-admin-{}", admin.simple()), true),
            (user, username.clone(), false),
        ] {
            sqlx::query("INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',$3)")
                .bind(id).bind(name).bind(is_admin).execute(&pool).await.unwrap();
        }
        let bare = format!("{username}@local.test");
        let full = format!("{bare}/Device");
        let localpart = format!("held-room-{}", room.simple());
        let room_epoch = sqlx::query_scalar(
            "INSERT INTO muc_rooms(id,localpart,owner_id,persistent,occupant_id_secret)
             VALUES($1,$2,$3,TRUE,$4) RETURNING room_epoch",
        )
        .bind(room)
        .bind(&localpart)
        .bind(user)
        .bind(vec![9_u8; 32])
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO muc_affiliations(room_id,user_id,affiliation) VALUES($1,$2,'owner')",
        )
        .bind(room)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
        let personal_original = format!(
            "<message xmlns='jabber:client' from='{full}' to='{full}' id='original'><encrypted xmlns='urn:xmpp:omemo:2'/></message>"
        );
        sqlx::query(
            "INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id,created_at)
             VALUES($1,$2,$3,$4,$5,TRUE,'original',NOW()-INTERVAL '2 days')",
        )
        .bind(personal).bind(user).bind(&bare).bind(&full).bind(&personal_original)
        .execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,actor_scope,created_at)
             VALUES($1,$2,$3,'Sender',$4,FALSE,$5,NOW()-INTERVAL '2 days')",
        )
        .bind(muc).bind(room).bind(&full).bind(ROOM_ORIGINAL).bind(&bare)
        .execute(&pool).await.unwrap();
        Self {
            pool,
            admin,
            user,
            room,
            room_epoch,
            localpart,
            bare,
            full,
            personal,
            muc,
            action,
            personal_original,
        }
    }

    fn target(&self, archive: Archive, scope: bool) -> LegalHoldTarget {
        match (archive, scope) {
            (Archive::Personal, false) => LegalHoldTarget::PersonalArchive(self.personal),
            (Archive::Personal, true) => LegalHoldTarget::PersonalArchiveOwner(self.user),
            (Archive::Room, false) => LegalHoldTarget::MucArchive(self.muc),
            (Archive::Room, true) => LegalHoldTarget::MucArchiveRoom(self.room),
        }
    }

    async fn hold_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        targets: &[LegalHoldTarget],
    ) -> Uuid {
        let id = Uuid::new_v4();
        create_legal_hold_in_tx(
            tx,
            self.admin,
            &CreateLegalHold {
                id,
                title: "display fixture",
                authority_reference: "WP-690",
                reason: "preserve pre-display evidence",
                targets,
                request_id: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
        id
    }

    async fn hold(&self, targets: &[LegalHoldTarget]) -> Uuid {
        let mut tx = self.pool.begin().await.unwrap();
        let id = self.hold_in_tx(&mut tx, targets).await;
        tx.commit().await.unwrap();
        id
    }

    async fn release(&self, hold: Uuid) -> Result<(), LegalHoldError> {
        let mut tx = self.pool.begin().await.unwrap();
        release_legal_hold_in_tx(
            &mut tx,
            self.admin,
            hold,
            "fixture complete",
            Uuid::new_v4(),
        )
        .await?;
        tx.commit().await.unwrap();
        Ok(())
    }

    async fn export(
        &self,
        hold: Uuid,
        max: i64,
        continuation: Option<LegalHoldExportCursor>,
    ) -> LegalHoldExport {
        let mut tx = self.pool.begin().await.unwrap();
        let export = export_legal_hold_page_in_tx(
            &mut tx,
            self.admin,
            hold,
            max,
            Uuid::new_v4(),
            continuation,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        export
    }

    async fn personal_action(
        &self,
        id: Uuid,
        capacity: Option<i64>,
    ) -> anyhow::Result<RetractionOutcome> {
        self.personal_action_with_cluster(id, capacity, None).await
    }

    async fn personal_action_with_cluster(
        &self,
        id: Uuid,
        capacity: Option<i64>,
        cluster: Option<LiveRetractionCluster>,
    ) -> anyhow::Result<RetractionOutcome> {
        let repository = PostgresRetractionRepository::new(self.pool.clone());
        let repository = match cluster {
            Some(cluster) => repository.with_cluster_admission(cluster),
            None => repository,
        };
        let service = RetractionService::new(
            repository,
            northstar_abuse_application::guard::test_personal_retraction_content_keyring(),
            "local.test",
        );
        let client_id = id.to_string();
        let full = &self.full;
        let action = format!(
            "<message xmlns='jabber:client' from='{full}' to='{full}' id='{client_id}'><retract xmlns='urn:xmpp:message-retract:1' id='original'/></message>"
        );
        let delivery = capacity.map(|max_messages| DeliveryProjection {
            id,
            recipient_id: self.user,
            local_actor_id: Some(self.user),
            sender_jid: full,
            stanza: &action,
            encrypted: false,
            max_messages,
            max_bytes: 1_000_000,
            ttl_days: 30,
            mam_backed: true,
        });
        service
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: self.user,
                    peer_jid: full,
                }],
                full,
                &RetractionCommand {
                    target_id: "original",
                    action_id: &client_id,
                    semantic_payload: &action,
                },
                &[ArchiveWrite {
                    id,
                    owner_id: self.user,
                    peer_jid: full,
                    stanza: &action,
                    encrypted: false,
                    stanza_id: Some(&client_id),
                }],
                delivery.as_ref(),
                None,
            )
            .await
    }

    async fn room_action(&self, id: Uuid) -> anyhow::Result<MucRetractionOutcome> {
        self.room_action_for(id, self.muc).await
    }

    async fn room_action_for(
        &self,
        id: Uuid,
        target: Uuid,
    ) -> anyhow::Result<MucRetractionOutcome> {
        self.room_action_with_kind(id, target, MucRetractionKind::Moderator)
            .await
    }

    async fn room_action_with_kind(
        &self,
        id: Uuid,
        target: Uuid,
        kind: MucRetractionKind,
    ) -> anyhow::Result<MucRetractionOutcome> {
        let room = format!("{}@muc.local.test", self.localpart);
        let (content, reason) = match kind {
            MucRetractionKind::Moderator => (
                format!("<moderated xmlns='urn:xmpp:message-moderate:1' by='{room}/Sender'/><reason>Off topic</reason>"),
                Some("Off topic"),
            ),
            MucRetractionKind::Author => (String::new(), None),
        };
        let tombstone = format!(
            "<message id='original'><retracted xmlns='urn:xmpp:message-retract:1' id='{id}' stamp='2026-01-01T00:00:00Z'>{content}</retracted></message>"
        );
        let action = format!(
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='{target}'>{content}</retract></message>"
        );
        retract_muc_message_and_archive_action(
            &self.pool,
            MucRetractionMutation {
                action_id: id,
                room_id: self.room,
                target_id: target,
                expected_stanza: ROOM_ORIGINAL,
                actor_scope: &self.bare,
                sender_jid: &self.full,
                nick: "Sender",
                tombstone: &tombstone,
                action_stanza: &action,
                reason,
                kind,
                authority: MucActorAuthority {
                    clustered: false,
                    expected_room_epoch: self.room_epoch,
                    principal: MucActorPrincipal::Local {
                        user_id: self.user,
                        local_domain: "local.test",
                    },
                    actor_scope: &self.bare,
                    full_jid: &self.full,
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
    }

    async fn apply(&self, archive: Archive) {
        match archive {
            Archive::Personal => assert_eq!(
                self.personal_action(self.action, Some(10)).await.unwrap(),
                RetractionOutcome::Applied {
                    tombstones: 1,
                    live_claim_id: None
                },
            ),
            Archive::Room => assert_eq!(
                self.room_action(self.action).await.unwrap(),
                MucRetractionOutcome::Applied,
            ),
        }
    }

    async fn display_counts(&self) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM personal_archive_display_changes WHERE archive_id=$1),
                    (SELECT COUNT(*) FROM muc_archive_display_changes WHERE message_id=$2)",
        )
        .bind(self.personal)
        .bind(self.muc)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn personal_publication_counts(&self) -> (i64, i64, i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM message_archive WHERE id=$1),
                    (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id=$1::uuid::text),
                    (SELECT COUNT(*) FROM offline_messages WHERE id=$1),
                    (SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE '%' || $1::uuid::text || '%')",
        ).bind(self.action).fetch_one(&self.pool).await.unwrap()
    }

    async fn live_publication(&self) -> (Option<Uuid>, Option<Uuid>) {
        sqlx::query_as(
            "SELECT (SELECT delivery_claim_id FROM offline_messages WHERE id=$1),
                    (SELECT revision FROM direct_spool_wake_outbox WHERE recipient_id=$2)",
        )
        .bind(self.action)
        .bind(self.user)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn cleanup(self) {
        sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
            .bind(self.room)
            .execute(&self.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind([self.admin, self.user].as_slice())
            .execute(&self.pool)
            .await
            .unwrap();
        self.pool.close().await;
    }
}

async fn backend_pid(tx: &mut Transaction<'_, Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

// A fixture-only trigger waits on a test-held lock after the real target
// write and action INSERT, while both writes are still uncommitted.
async fn pause_action(f: &Fixture, archive: Archive) -> Transaction<'static, Postgres> {
    pause_insert(f, archive.table(), "id", f.action).await
}

async fn pause_insert(
    f: &Fixture,
    table: &str,
    column: &str,
    target: Uuid,
) -> Transaction<'static, Postgres> {
    let mut barrier = f.pool.begin().await.unwrap();
    let key: i64 = sqlx::query_scalar("SELECT hashtextextended($1::text,690)")
        .bind(f.action.to_string())
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *barrier)
        .await
        .unwrap();
    let trigger = format!(
        "CREATE FUNCTION wp690_pause_action() RETURNS trigger LANGUAGE plpgsql AS
         $$ BEGIN PERFORM pg_advisory_xact_lock({key}::bigint); RETURN NEW; END; $$;
         CREATE TRIGGER wp690_pause_action AFTER INSERT ON {table}
         FOR EACH ROW WHEN (NEW.{column}='{target}'::uuid) EXECUTE FUNCTION wp690_pause_action();",
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(trigger.as_str()))
        .execute(&f.pool)
        .await
        .unwrap();
    barrier
}

async fn remove_pause(f: &Fixture, table: &str) {
    let remove =
        format!("DROP TRIGGER wp690_pause_action ON {table}; DROP FUNCTION wp690_pause_action();",);
    sqlx::raw_sql(sqlx::AssertSqlSafe(remove.as_str()))
        .execute(&f.pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn hold_creation_and_retraction_serialize_in_both_orders() {
    use crate::support::blocked_backend;

    for archive in [Archive::Personal, Archive::Room] {
        for scope in [false, true] {
            for hold_first in [true, false] {
                let f = Fixture::new().await;
                let target = f.target(archive, scope);
                let operation = f.clone();
                let hold = if hold_first {
                    let mut tx = f.pool.begin().await.unwrap();
                    let hold = f.hold_in_tx(&mut tx, &[target]).await;
                    let pid = backend_pid(&mut tx).await;
                    let writer = tokio::spawn(async move { operation.apply(archive).await });
                    blocked_backend(&f.pool, pid).await;
                    tx.commit().await.unwrap();
                    writer.await.unwrap();
                    hold
                } else {
                    let mut barrier = pause_action(&f, archive).await;
                    let pid = backend_pid(&mut barrier).await;
                    let writer = tokio::spawn(async move { operation.apply(archive).await });
                    let writer_pid = blocked_backend(&f.pool, pid).await;
                    let creation = f.clone();
                    let hold = tokio::spawn(async move { creation.hold(&[target]).await });
                    blocked_backend(&f.pool, writer_pid).await;
                    barrier.commit().await.unwrap();
                    writer.await.unwrap();
                    let hold = hold.await.unwrap();
                    remove_pause(&f, archive.table()).await;
                    hold
                };
                let page = f.export(hold, 10, None).await;
                let (target_id, original, counts) = match archive {
                    Archive::Personal => {
                        assert_eq!(f.personal_publication_counts().await, (1, 1, 1, 0));
                        (
                            f.personal,
                            f.personal_original.as_str(),
                            (i64::from(u8::from(hold_first)), 0),
                        )
                    }
                    Archive::Room => (f.muc, ROOM_ORIGINAL, (0, i64::from(u8::from(hold_first)))),
                };
                let row = page
                    .records
                    .iter()
                    .find(|row| row.record_id == target_id)
                    .unwrap();
                assert_eq!(row.display_change.is_some(), hold_first);
                assert_eq!(
                    row.encrypted,
                    hold_first && matches!(archive, Archive::Personal)
                );
                if hold_first {
                    assert_eq!(row.server_visible_payload.as_deref(), Some(original));
                } else {
                    assert!(row
                        .server_visible_payload
                        .as_ref()
                        .unwrap()
                        .contains("<retracted"));
                }
                assert_eq!(f.display_counts().await, counts);
                f.release(hold).await.unwrap();
                f.cleanup().await;
            }
        }
    }

    let f = Fixture::new().await;
    let foreign_room = Fixture::new().await;
    assert_eq!(
        f.room_action_for(f.action, foreign_room.muc).await.unwrap(),
        MucRetractionOutcome::Conflict,
    );
    foreign_room.cleanup().await;
    let mut wrong_owner = f.pool.begin().await.unwrap();
    let outcome = northstar_archive_postgres::display_changes::begin_personal_display_writes(
        &mut wrong_owner,
    )
    .await
    .unwrap()
    .apply(
        northstar_archive_postgres::display_changes::PersonalArchiveDisplayChange {
            owner_id: f.admin,
            archive_id: f.personal,
            expected_stanza: &f.personal_original,
            display_stanza: "<message/>",
            actor_bare_jid: &f.bare,
            action_id: "wrong-owner",
        },
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        northstar_archive_postgres::display_changes::PersonalDisplayWriteOutcome::MissingOrChanged,
    );
    wrong_owner.rollback().await.unwrap();
    let hold = f.hold(&[f.target(Archive::Personal, false)]).await;
    let mut barrier = pause_action(&f, Archive::Personal).await;
    let pid = backend_pid(&mut barrier).await;
    let first = f.clone();
    let first = tokio::spawn(async move { first.apply(Archive::Personal).await });
    let first_pid = blocked_backend(&f.pool, pid).await;
    let second_id = Uuid::new_v4();
    let second = f.clone();
    let second = tokio::spawn(async move { second.personal_action(second_id, Some(10)).await });
    blocked_backend(&f.pool, first_pid).await;
    barrier.commit().await.unwrap();
    first.await.unwrap();
    assert_eq!(second.await.unwrap().unwrap(), RetractionOutcome::Conflict);
    assert_eq!(f.display_counts().await, (1, 0));
    assert_eq!(f.personal_publication_counts().await, (1, 1, 1, 0));
    let second_rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM message_archive WHERE id=$1)
              + (SELECT COUNT(*) FROM personal_retraction_intents WHERE action_id=$1::uuid::text)
              + (SELECT COUNT(*) FROM offline_messages WHERE id=$1)",
    )
    .bind(second_id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(second_rows, 0);
    remove_pause(&f, Archive::Personal.table()).await;
    f.release(hold).await.unwrap();
    let author_hold = f.hold(&[f.target(Archive::Room, false)]).await;
    assert_eq!(
        f.room_action_with_kind(f.action, f.muc, MucRetractionKind::Author)
            .await
            .unwrap(),
        MucRetractionOutcome::Applied,
    );
    let author_export = f.export(author_hold, 10, None).await;
    let author_target = &author_export.records[0];
    let change = author_target.display_change.as_ref().unwrap();
    assert_eq!(
        author_target.server_visible_payload.as_deref(),
        Some(ROOM_ORIGINAL)
    );
    assert_eq!(serde_json::to_value(change.kind).unwrap(), "muc_retraction");
    assert!(change.reason.is_none());
    f.release(author_hold).await.unwrap();
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn held_retraction_projection_and_delivery_roll_back_together() {
    let f = Fixture::new().await;
    let cluster = LiveRetractionCluster::claim(&f.pool).await;
    let hold = f
        .hold(&[
            f.target(Archive::Personal, false),
            f.target(Archive::Room, false),
        ])
        .await;
    let offline_seed = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,mam_backed)
         VALUES($1,$2,'seed@local.test','<message/>',FALSE,FALSE)",
    )
    .bind(offline_seed)
    .bind(f.user)
    .execute(&f.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,actor_scope)
         VALUES($1,$2,$3,'Sender','<message/>',FALSE,$4)",
    )
    .bind(f.action)
    .bind(f.room)
    .bind(&f.full)
    .bind(&f.bare)
    .execute(&f.pool)
    .await
    .unwrap();

    assert_eq!(
        f.personal_action_with_cluster(f.action, Some(1), Some(cluster.clone()))
            .await
            .unwrap(),
        RetractionOutcome::CapacityExceeded,
    );
    let error = f.room_action(f.action).await.unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|database| database.code())
            .as_deref(),
        Some("23505"),
    );
    assert_eq!(f.display_counts().await, (0, 0));
    assert_eq!(f.personal_publication_counts().await, (0, 0, 0, 0));
    assert_eq!(f.live_publication().await, (None, None));
    let page = f.export(hold, 10, None).await;
    assert_eq!(
        page.records[0].server_visible_payload.as_deref(),
        Some(f.personal_original.as_str())
    );
    assert_eq!(
        page.records[1].server_visible_payload.as_deref(),
        Some(ROOM_ORIGINAL)
    );
    assert_eq!(
        muc_message_by_id(&f.pool, f.room, f.muc)
            .await
            .unwrap()
            .unwrap()
            .stanza,
        ROOM_ORIGINAL
    );
    assert!(
        northstar_data_tools::pie::export_mam_for_test(&f.pool, f.user)
            .await
            .unwrap()
            .contains("urn:xmpp:omemo:2")
    );

    sqlx::query("DELETE FROM offline_messages WHERE id=$1")
        .bind(offline_seed)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM muc_messages WHERE id=$1")
        .bind(f.action)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut barrier = pause_insert(&f, "direct_spool_wake_outbox", "recipient_id", f.user).await;
    let pid = backend_pid(&mut barrier).await;
    let writer = f.clone();
    let writer_cluster = cluster.clone();
    let writer = tokio::spawn(async move {
        writer
            .personal_action_with_cluster(writer.action, Some(10), Some(writer_cluster))
            .await
    });
    crate::support::blocked_backend(&f.pool, pid).await;
    assert_eq!(f.display_counts().await, (0, 0));
    assert_eq!(f.personal_publication_counts().await, (0, 0, 0, 0));
    assert_eq!(f.live_publication().await, (None, None));
    barrier.commit().await.unwrap();
    assert_eq!(
        writer.await.unwrap().unwrap(),
        RetractionOutcome::Applied {
            tombstones: 1,
            live_claim_id: Some(f.action),
        }
    );
    remove_pause(&f, "direct_spool_wake_outbox").await;
    let live = f.live_publication().await;
    assert_eq!(live.0, Some(f.action));
    assert!(live.1.is_some());
    f.apply(Archive::Room).await;
    assert_eq!(f.display_counts().await, (1, 1));
    assert_eq!(f.personal_publication_counts().await, (1, 1, 1, 0));
    assert_eq!(
        f.room_action(f.action).await.unwrap(),
        MucRetractionOutcome::Conflict
    );
    assert_eq!(
        f.personal_action_with_cluster(f.action, Some(10), Some(cluster.clone()))
            .await
            .unwrap(),
        RetractionOutcome::Replay,
    );
    assert_eq!(f.personal_publication_counts().await, (1, 1, 1, 0));
    assert_eq!(f.live_publication().await, live);
    f.release(hold).await.unwrap();
    cluster.release(&f.pool).await;
    f.cleanup().await;
}

fn page_query() -> MamArchiveQuery {
    MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page: MamRsmPage::First,
        max: 10,
    }
}

async fn snapshot_pages(
    f: &Fixture,
    tx: &mut Transaction<'_, Postgres>,
) -> (ArchivePage, ArchivePage) {
    let query = page_query();
    let personal =
        mam_archive_page_for_in_transaction(tx, MamArchiveSource::User(f.user), None, &query)
            .await
            .unwrap()
            .unwrap();
    let room = mam_archive_page_for_in_transaction(tx, MamArchiveSource::Muc(f.room), None, &query)
        .await
        .unwrap()
        .unwrap();
    (personal, room)
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn display_readers_use_one_snapshot_and_never_refetch_held_bytes() {
    use northstar_archive_core::{
        FederatedMamStreamPage, FederatedMamStreamRow, MamRoomAccess, MamRoomReadAuthority,
    };
    use northstar_operations_postgres::reports::{
        create_report_in_tx, ReportCreateError, ReportEvidenceInput,
    };

    let f = Fixture::new().await;
    let hold = f
        .hold(&[
            f.target(Archive::Personal, false),
            f.target(Archive::Room, false),
        ])
        .await;
    let mut old = f.pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *old)
        .await
        .unwrap();
    let old_pages = snapshot_pages(&f, &mut old).await;
    assert_eq!(old_pages.0.rows[0].stanza, f.personal_original);
    assert_eq!(old_pages.1.rows[0].stanza, ROOM_ORIGINAL);

    let mut barrier = pause_action(&f, Archive::Personal).await;
    let pid = backend_pid(&mut barrier).await;
    let writer = f.clone();
    let writer = tokio::spawn(async move { writer.apply(Archive::Personal).await });
    let writer_pid = crate::support::blocked_backend(&f.pool, pid).await;
    let report = f.clone();
    let request = Uuid::new_v4();
    let report = tokio::spawn(async move {
        let mut tx = report.pool.begin().await.unwrap();
        let error = create_report_in_tx(
            &mut tx,
            report.user,
            &report.bare,
            "spam",
            "",
            &[ReportEvidenceInput {
                archive_id: report.personal,
                client_message_id: Some("original".into()),
                body_text: "client decrypted bytes".into(),
            }],
            Some(request),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ReportCreateError::InvalidEvidence(_)));
        // Commit even on InvalidEvidence to prove the rejection had no side effects.
        tx.commit().await.unwrap();
    });
    crate::support::blocked_backend(&f.pool, writer_pid).await;
    barrier.commit().await.unwrap();
    writer.await.unwrap();
    report.await.unwrap();
    f.apply(Archive::Room).await;
    assert_eq!(snapshot_pages(&f, &mut old).await, old_pages);
    old.commit().await.unwrap();
    remove_pause(&f, Archive::Personal.table()).await;

    let mut fresh = f.pool.begin().await.unwrap();
    let (personal, room) = snapshot_pages(&f, &mut fresh).await;
    fresh.commit().await.unwrap();
    assert!(personal.rows[0].stanza.contains("<retracted") && !personal.rows[0].encrypted);
    assert_eq!(personal.rows[0].created_at, old_pages.0.rows[0].created_at);
    assert_eq!(personal.first_index, old_pages.0.first_index);
    assert!(
        room.rows[0].stanza.contains("<retracted") && room.rows[0].muc.as_ref().unwrap().retracted
    );
    let join = muc_history_since(&f.pool, f.room, 10, None).await.unwrap();
    assert_eq!(join[0].stanza, room.rows[0].stanza);
    assert!(muc_message_by_id(&f.pool, f.room, f.muc)
        .await
        .unwrap()
        .is_none());
    let compatibility =
        northstar_workflows::api_pages::history_page(&f.pool, f.user, None, None, 10)
            .await
            .unwrap();
    let compatibility_target = compatibility
        .rows
        .iter()
        .find(|row| row.id == f.personal)
        .unwrap();
    assert_eq!(compatibility_target.stanza, personal.rows[0].stanza);
    assert!(!compatibility_target.encrypted);
    let pie = northstar_data_tools::pie::export_mam_for_test(&f.pool, f.user)
        .await
        .unwrap();
    assert!(!pie.contains("urn:xmpp:omemo:2") && pie.contains("retracted"));

    // Produce the same moderation against an unheld control using the
    // normal physical update and compare both stored displays.
    let control = Uuid::new_v4();
    let control_action = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,actor_scope)
         VALUES($1,$2,$3,'Sender',$4,FALSE,$5)",
    )
    .bind(control)
    .bind(f.room)
    .bind(&f.full)
    .bind(ROOM_ORIGINAL)
    .bind(&f.bare)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        f.room_action_for(control_action, control).await.unwrap(),
        MucRetractionOutcome::Applied,
    );
    let control_stanza: String = sqlx::query_scalar("SELECT stanza FROM muc_messages WHERE id=$1")
        .bind(control)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        room.rows[0].stanza,
        control_stanza.replace(&control_action.to_string(), &f.action.to_string()),
    );

    let actor = MamRoomReadAuthority {
        full_jid: "viewer@remote.test/device".into(),
        occupancy: None,
    };
    let northstar_archive_core::MamDbRoomReadOutcome::Allowed {
        access,
        value: Some(page),
    } = northstar_workflows::mam_room::mam_federated_room_archive_page_authorized(
        &f.pool,
        &f.localpart,
        &actor,
        &page_query(),
    )
    .await
    .unwrap()
    else {
        panic!("the fresh federated archive read must succeed");
    };
    let room_jid = format!("{}@muc.local.test", f.localpart);
    let held_row = &room.rows[0];
    let metadata = held_row.muc.as_ref().unwrap();
    let inner = northstar_room_core::stanza::project_muc_mam_message(
        &room_jid,
        access.occupant_id_secret(),
        access.reveal_real_jid(),
        northstar_room_core::stanza::MucMamStoredRow {
            id: held_row.id,
            stanza: &held_row.stanza,
            sender_jid: &held_row.peer_jid,
            nick: &metadata.nick,
            message_kind: &metadata.message_kind,
            encrypted: held_row.encrypted,
            retracted: metadata.retracted,
        },
    )
    .unwrap();
    let rows = page
        .rows
        .into_iter()
        .map(|row| FederatedMamStreamRow {
            id: row.id,
            peer_jid: row.peer_jid,
            stanza: row.stanza,
            created_at: row.created_at,
            encrypted: row.encrypted,
            muc: row.muc,
        })
        .collect();
    let access = MamRoomAccess::new(
        access.localpart().to_owned(),
        access.occupant_id_secret().to_vec(),
        access.reveal_real_jid(),
    );
    let stream_page =
        FederatedMamStreamPage::new(access, rows, page.total, page.first_index, page.complete);
    let wire = northstar_muc_xmpp::federated_muc::render_federated_mam_stream(
        &stream_page,
        &room_jid,
        &actor.full_jid,
        "query",
        None,
        false,
        Uuid::new_v4(),
    )
    .unwrap();
    assert!(wire[0].contains(inner.as_str()));
    assert!(wire[0].contains("<moderated") && wire[0].contains("Off topic"));
    assert!(!wire.iter().any(|stanza| stanza.contains("held room bytes")));
    let report_writes: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM abuse_reports WHERE reporter_id=$1),
                (SELECT COUNT(*) FROM abuse_report_evidence WHERE archive_id=$2),
                (SELECT COUNT(*) FROM audit_log WHERE request_id=$3)",
    )
    .bind(f.user)
    .bind(f.personal)
    .bind(request)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(report_writes, (0, 0, 0));
    f.release(hold).await.unwrap();
    f.cleanup().await;
}

fn hold_genesis(page: &LegalHoldExport, admin: Uuid, domain: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(page.export_id.as_bytes());
    hash.update(admin.as_bytes());
    hash.update(page.hold.id.as_bytes());
    hash.update(page.snapshot_at.timestamp_micros().to_be_bytes());
    hash.finalize().into()
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;

    let mut hex = String::with_capacity(64);
    for byte in bytes {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

fn verify_records(records: &[HeldRecordExport], mut root: [u8; 32], v3: bool) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    for row in records {
        if v3 {
            assert_eq!(row.previous_hash, hex_digest(&root));
        }
        let mut canonical = format!(
            concat!(
                "{{\"resource_type\":{},\"record_id\":{},\"subject_id\":{},\"encrypted\":{},",
                "\"record_created_at\":{},\"server_visible_payload\":{},\"payload_disposition\":{}"
            ),
            serde_json::to_string(&row.resource_type).unwrap(),
            serde_json::to_string(&row.record_id).unwrap(),
            serde_json::to_string(&row.subject_id).unwrap(),
            row.encrypted,
            serde_json::to_string(&row.record_created_at).unwrap(),
            serde_json::to_string(&row.server_visible_payload).unwrap(),
            serde_json::to_string(&row.payload_disposition).unwrap(),
        );
        if v3 {
            canonical.push_str(",\"display_change\":");
            canonical.push_str(&serde_json::to_string(&row.display_change).unwrap());
        }
        canonical.push('}');
        let mut hash = Sha256::new();
        hash.update(root);
        hash.update((canonical.len() as u64).to_be_bytes());
        hash.update(canonical);
        root = hash.finalize().into();
        if v3 {
            assert_eq!(row.entry_hash, hex_digest(&root));
        }
    }
    root
}

async fn seed_v2_lease_and_check_replay(f: &Fixture, mut first: LegalHoldExport) {
    use northstar_auth_core::api_session::ApiReadAuthority;
    use northstar_http::{cursor::CursorKeyring, governance_cursor::SignedGovernanceCursors};
    use northstar_operations_application::governance::{
        GovernanceCursorCodec, GovernanceService, HoldExportCommand,
    };
    use northstar_operations_core::api_mutations::{
        AdminMutationAdmission, ApiMutationOutcome, ApiPrincipalKind, IdempotencyRequest,
    };
    use northstar_operations_postgres::api_control::{api_request_fingerprint, ApiControlKeyring};
    use northstar_workflows::{
        admin_mutations::AdminMutationStore, governance_repository::PostgresGovernanceRepository,
    };
    use std::sync::Arc;

    first.export_id = Uuid::new_v4();
    first.format = "northstar-legal-hold-chain-v2";
    let genesis = hold_genesis(&first, f.admin, b"northstar/legal-hold-export/v2\0");
    let root = verify_records(&first.records, genesis, false);
    let cursor = first.next.as_mut().unwrap();
    cursor.export_id = first.export_id;
    cursor.chain_root = root;
    sqlx::query(
        "INSERT INTO governance_export_leases(id,export_kind,actor_id,hold_id,snapshot_at,expires_at)
         VALUES($1,'legal_hold',$2,$3,$4,$5)",
    ).bind(first.export_id).bind(f.admin).bind(first.hold.id).bind(first.snapshot_at)
    .bind(first.lease_expires_at).execute(&f.pool).await.unwrap();

    let secret = Uuid::new_v4().simple().to_string();
    let cursor_key = Arc::new(CursorKeyring::new(secret.as_bytes(), None).unwrap());
    let signed = SignedGovernanceCursors::new(Arc::clone(&cursor_key))
        .encode_hold(f.admin, &first)
        .unwrap()
        .unwrap();
    let session = northstar_auth_postgres::users::create_api_session(&f.pool, f.admin, 1)
        .await
        .unwrap();
    let keyring = Arc::new(ApiControlKeyring::new(secret.as_bytes(), None).unwrap());
    let cluster =
        northstar_cluster::ClusterManager::new(None, "governance.test", None, None, None, None)
            .await
            .unwrap();
    let mutations =
        AdminMutationStore::new(f.pool.clone(), Arc::clone(&keyring), cluster.admission());
    let service = GovernanceService::new(PostgresGovernanceRepository::new(
        f.pool.clone(),
        mutations,
        keyring,
        SignedGovernanceCursors::new(cursor_key),
    ));
    let key = Uuid::new_v4().to_string();
    let request_id = Uuid::new_v4();
    let body = serde_json::to_vec(&serde_json::json!({"cursor": &signed, "max_rows": 10})).unwrap();
    let command = || HoldExportCommand {
        admission: AdminMutationAdmission {
            authority: ApiReadAuthority {
                user_id: f.admin,
                auth_generation: 0,
                session_token: &session,
            },
            idempotency: IdempotencyRequest {
                request_id,
                actor_id: Some(f.admin),
                principal_scope: f.admin.as_bytes(),
                capacity_scope: f.admin.as_bytes(),
                target_scope: first.hold.id.as_bytes(),
                principal_kind: ApiPrincipalKind::Admin,
                method: "POST",
                route: "/api/admin/legal-holds/{id}/export",
                idempotency_key: &key,
                request_fingerprint: api_request_fingerprint("application/json", &body),
                ttl_seconds: 86_400,
                lease_seconds: 180,
            },
        },
        hold_id: first.hold.id,
        max_rows: 10,
        cursor: Some(&signed),
    };
    let ApiMutationOutcome::Committed(response) = service.export_hold(command()).await.unwrap()
    else {
        panic!("seeded V2 cursor should complete");
    };
    let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(json["format"], "northstar-legal-hold-chain-v2");
    assert_eq!(json["chain_start_sha256"], hex_digest(&root));
    assert_eq!(json["complete"], true);
    assert!(json["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row.get("display_change").is_none()));
    let ApiMutationOutcome::Replay(replay) = service.export_hold(command()).await.unwrap() else {
        panic!("completed V2 cursor must win through exact idempotent replay");
    };
    assert_eq!(replay.status, response.status);
    assert_eq!(replay.headers, response.headers);
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.request_id, request_id);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn hold_export_cutoff_freezes_annotations_across_pages() {
    use northstar_archive_postgres::mix_source_retractions::{
        lock_sources_in_tx, record_locked_in_tx,
    };
    use northstar_workflows::retention::{purge_retention_batch, RetentionStore};

    let f = Fixture::new().await;
    let [sentinel, mix_copy, target, action] = [(); 4].map(|()| Uuid::new_v4());
    sqlx::query(
        "INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at)
         VALUES($1,$2,$3,$4,'<message/>',FALSE,NOW()-INTERVAL '3 days')",
    ).bind(sentinel).bind(f.user).bind(&f.bare).bind(&f.full).execute(&f.pool).await.unwrap();
    let channel = format!("room-{target}@mix.remote.test");
    let mix_original = format!(
        "<message from='{channel}/publisher' type='groupchat' id='{target}'><body>original MIX</body></message>"
    );
    sqlx::query(
        "INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,source_by,
                                     source_stanza_id,source_payload_digest,created_at)
         VALUES($1,$2,$3,$3,$4,FALSE,$3,$5,decode(repeat('ab',32),'hex'),NOW()-INTERVAL '36 hours')",
    ).bind(mix_copy).bind(f.user).bind(&channel).bind(&mix_original).bind(target)
    .execute(&f.pool).await.unwrap();
    let hold = f
        .hold(&[
            LegalHoldTarget::PersonalArchive(sentinel),
            f.target(Archive::Personal, false),
            LegalHoldTarget::PersonalArchive(mix_copy),
            f.target(Archive::Room, false),
        ])
        .await;
    let first = f.export(hold, 1, None).await;
    assert_eq!(first.format, "northstar-legal-hold-chain-v3");
    assert_eq!(first.records[0].record_id, sentinel);
    let genesis = hold_genesis(&first, f.admin, b"northstar/legal-hold-export/v3\0");
    assert_eq!(first.chain_start_sha256, hex_digest(&genesis));
    let root = verify_records(&first.records, genesis, true);
    assert!(matches!(
        f.release(hold).await,
        Err(LegalHoldError::Conflict)
    ));

    f.apply(Archive::Personal).await;
    f.apply(Archive::Room).await;
    let mut fact = f.pool.begin().await.unwrap();
    lock_sources_in_tx(&mut fact, &channel, &[target, action], true)
        .await
        .unwrap();
    assert!(
        record_locked_in_tx(&mut fact, &channel, target, action, "publisher")
            .await
            .unwrap()
    );
    let fact_pid = backend_pid(&mut fact).await;
    let fresh = f.clone();
    let fresh = tokio::spawn(async move { fresh.export(hold, 10, None).await });
    crate::support::blocked_backend(&f.pool, fact_pid).await;
    // A reflected retraction still has to write its personal projection
    // after the fact. The export must be waiting before the archive fence.
    sqlx::query("LOCK TABLE message_archive IN ROW EXCLUSIVE MODE NOWAIT")
        .execute(&mut *fact)
        .await
        .unwrap();
    fact.commit().await.unwrap();
    let continuation = f.export(hold, 10, first.next.clone()).await;
    assert_eq!(continuation.chain_start_sha256, hex_digest(&root));
    assert_eq!(continuation.records.len(), 3);
    assert!(continuation
        .records
        .iter()
        .all(|row| row.display_change.is_none()));
    assert_eq!(
        continuation.records[1].server_visible_payload.as_deref(),
        Some(mix_original.as_str())
    );
    assert_eq!(
        continuation.chain_root_sha256,
        hex_digest(&verify_records(&continuation.records, root, true)),
    );

    let fresh = fresh.await.unwrap();
    assert_eq!(fresh.records.len(), 4);
    assert!(fresh.records[1..]
        .iter()
        .all(|row| row.display_change.is_some()));
    let mix = fresh
        .records
        .iter()
        .find(|row| row.record_id == mix_copy)
        .unwrap();
    let annotation = mix.display_change.as_ref().unwrap();
    assert_eq!(
        serde_json::to_value(annotation.kind).unwrap(),
        "mix_retraction"
    );
    assert_eq!(annotation.actor, channel);
    assert_eq!(annotation.action_id, action.to_string());
    let genesis = hold_genesis(&fresh, f.admin, b"northstar/legal-hold-export/v3\0");
    assert_eq!(
        fresh.chain_root_sha256,
        hex_digest(&verify_records(&fresh.records, genesis, true))
    );

    seed_v2_lease_and_check_replay(&f, first).await;
    let other = f
        .hold(&[
            f.target(Archive::Personal, false),
            f.target(Archive::Room, false),
        ])
        .await;
    f.release(hold).await.unwrap();
    let cutoff = Utc::now() - Duration::days(1);
    for store in [RetentionStore::PersonalMam, RetentionStore::MucMam] {
        purge_retention_batch(&f.pool, store, cutoff, 100)
            .await
            .unwrap();
    }
    assert_eq!(f.display_counts().await, (1, 1));
    f.release(other).await.unwrap();
    for store in [RetentionStore::PersonalMam, RetentionStore::MucMam] {
        purge_retention_batch(&f.pool, store, cutoff, 100)
            .await
            .unwrap();
    }
    assert_eq!(f.display_counts().await, (0, 0));
    let expired = f.export(hold, 10, None).await;
    assert_eq!(expired.records.len(), 4);
    assert!(expired
        .records
        .iter()
        .all(|row| row.payload_disposition == "released_record_expired"
            && row.server_visible_payload.is_none()
            && row.display_change.is_none()));
    let stale = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO governance_export_leases(id,export_kind,actor_id,hold_id,snapshot_at,expires_at)
         VALUES($1,'legal_hold',$2,$3,NOW()-INTERVAL '1 hour',NOW()-INTERVAL '50 minutes')",
    ).bind(stale).bind(f.admin).bind(hold).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO legal_hold_export_display_cutoffs VALUES($1,0)")
        .bind(stale)
        .execute(&f.pool)
        .await
        .unwrap();
    purge_governance_export_leases_batch(&f.pool, 30, 100)
        .await
        .unwrap();
    let orphan: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM legal_hold_export_display_cutoffs WHERE export_id=$1)",
    )
    .bind(stale)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(!orphan);
    sqlx::query("DELETE FROM mix_source_retractions WHERE source_by=$1")
        .bind(channel)
        .execute(&f.pool)
        .await
        .unwrap();
    f.cleanup().await;
}
