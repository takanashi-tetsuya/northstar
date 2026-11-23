//! PAM receive authority is coherent with block state and independent of transport.

use anyhow::Result;
use northstar_archive_postgres::mix_source_retractions::lock_sources_in_tx;
use northstar_room_application::mix_service::{
    MixDeliveryRepository, MixPamDeliveryRepository, MixReflectionKind, PamDeliveryQuery,
    ReflectedMixArchiveOutcome, SourceArchiveAdmission, VerifiedMixReflection, NODE_MESSAGES,
    NODE_PRESENCE,
};
use northstar_room_core::mix::{MixChannelAddress, MixPamState, MixRealJid};
use northstar_workflows::room_effects::PostgresMixRepository;
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use uuid::Uuid;

const CHANNEL: &str = "room@mix.remote.test";
const RECIPIENT: &str = "alice@local.test";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    schema: String,
    account_id: Uuid,
    recipient: MixRealJid,
    channel: MixChannelAddress,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_pam_ingress_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&owner)
            .await?;
        let options = url.parse::<sqlx::postgres::PgConnectOptions>()?.options([
            ("search_path", schema.as_str()),
            ("statement_timeout", "10000"),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options)
            .await?;
        crate::support::migrate(&pool).await?;
        let account_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash) VALUES ($1, 'alice', 'test-only')",
        )
        .bind(account_id)
        .execute(&pool)
        .await?;
        Ok(Self {
            owner,
            pool,
            schema,
            account_id,
            recipient: MixRealJid::parse(RECIPIENT)?,
            channel: MixChannelAddress::parse(CHANNEL)?,
        })
    }

    fn query(&self) -> PamDeliveryQuery<'_> {
        PamDeliveryQuery {
            recipient: &self.recipient,
            channel: &self.channel,
        }
    }

    async fn archive_count(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM message_archive WHERE owner_id=$1")
                .bind(self.account_id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn close(self) -> Result<()> {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.owner)
        .await?;
        self.owner.close().await;
        Ok(())
    }
}

pub(super) async fn join_with_subscription(
    pool: &PgPool,
    account_id: Uuid,
    channel: &MixChannelAddress,
    node: &str,
) -> Result<Uuid> {
    let membership = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO mix_pam_memberships (id, user_id, channel_jid, state, participant_id)
                 VALUES ($1, $2, $3, 'joined', 'recipient')",
    )
    .bind(membership)
    .bind(account_id)
    .bind(channel.as_str())
    .execute(&mut *tx)
    .await?;
    insert_subscription(&mut tx, membership, node).await?;
    tx.commit().await?;
    Ok(membership)
}

async fn insert_subscription(
    tx: &mut Transaction<'_, Postgres>,
    membership: Uuid,
    node: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO mix_pam_subscriptions (membership_id, node) VALUES ($1, $2)")
        .bind(membership)
        .bind(node)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn blocker_pid(tx: &mut Transaction<'_, Postgres>) -> Result<i32> {
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await?)
}

async fn block(pool: &PgPool, account_id: Uuid, blocked_jid: &str) -> Result<()> {
    sqlx::query("INSERT INTO blocked_jids (owner_id, blocked_jid) VALUES ($1,$2)")
        .bind(account_id)
        .bind(blocked_jid)
        .execute(pool)
        .await?;
    Ok(())
}

async fn archive(
    repo: &PostgresMixRepository,
    query: PamDeliveryQuery<'_>,
    source_id: Uuid,
    archive_id: Uuid,
) -> Result<ReflectedMixArchiveOutcome> {
    let stanza = format!("<message type='groupchat' from='{CHANNEL}/sender' to='{RECIPIENT}' id='{source_id}'><body>original</body><mix xmlns='urn:xmpp:mix:core:1'/><stanza-id xmlns='urn:xmpp:sid:0' by='{CHANNEL}' id='{source_id}'/></message>");
    repo.archive_verified_mix_reflection(VerifiedMixReflection {
        personal_archive_id: archive_id,
        channel: query.channel,
        authoritative_stanza_id: source_id,
        stanza: &stanza,
        encrypted: false,
        kind: MixReflectionKind::Original {
            recipient: query.recipient,
        },
    })
    .await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn leave_while_blocked_then_unblock_admits_no_reflection() -> Result<()> {
    let fixture = Fixture::new().await?;
    let membership = join_with_subscription(
        &fixture.pool,
        fixture.account_id,
        &fixture.channel,
        NODE_MESSAGES,
    )
    .await?;
    block(&fixture.pool, fixture.account_id, CHANNEL).await?;
    let repo = PostgresMixRepository::new(fixture.pool.clone());
    let before = repo.pam_delivery_view(fixture.query()).await?.unwrap();
    assert_eq!(before.state, Some(MixPamState::Joined));
    assert!(before.blocked);
    assert_eq!(before.receiving_account(NODE_MESSAGES), None);

    let mut barrier = fixture.pool.begin().await?;
    let source_id = Uuid::new_v4();
    lock_sources_in_tx(&mut barrier, CHANNEL, &[source_id], true).await?;
    let blocker = blocker_pid(&mut barrier).await?;
    let recipient = fixture.recipient.clone();
    let channel = fixture.channel.clone();
    let task = tokio::spawn(async move {
        archive(
            &repo,
            PamDeliveryQuery {
                recipient: &recipient,
                channel: &channel,
            },
            source_id,
            Uuid::new_v4(),
        )
        .await
    });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query("DELETE FROM mix_pam_memberships WHERE id=$1")
        .bind(membership)
        .execute(&mut *barrier)
        .await?;
    sqlx::query("DELETE FROM blocked_jids WHERE owner_id=$1 AND blocked_jid=$2")
        .bind(fixture.account_id)
        .bind(CHANNEL)
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    assert_eq!(task.await??, ReflectedMixArchiveOutcome::Denied);
    assert_eq!(fixture.archive_count().await?, 0);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pending_rejoin_replacing_subscriptions_is_read_in_one_snapshot() -> Result<()> {
    let fixture = Fixture::new().await?;
    let membership = join_with_subscription(
        &fixture.pool,
        fixture.account_id,
        &fixture.channel,
        NODE_PRESENCE,
    )
    .await?;
    let mut barrier = fixture.pool.begin().await?;
    sqlx::query("LOCK TABLE mix_pam_subscriptions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *barrier)
        .await?;
    let blocker = blocker_pid(&mut barrier).await?;
    let repo = PostgresMixRepository::new(fixture.pool.clone());
    let recipient = fixture.recipient.clone();
    let channel = fixture.channel.clone();
    let task = tokio::spawn(async move {
        repo.pam_delivery_view(PamDeliveryQuery {
            recipient: &recipient,
            channel: &channel,
        })
        .await
    });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query(
        "UPDATE mix_pam_memberships SET state='pending_join', participant_id=NULL WHERE id=$1",
    )
    .bind(membership)
    .execute(&mut *barrier)
    .await?;
    sqlx::query("DELETE FROM mix_pam_subscriptions WHERE membership_id=$1")
        .bind(membership)
        .execute(&mut *barrier)
        .await?;
    insert_subscription(&mut barrier, membership, NODE_MESSAGES).await?;
    barrier.commit().await?;
    let authority = task.await??.unwrap();
    assert_eq!(authority.receiving_account(NODE_MESSAGES), None);
    match authority.state {
        Some(MixPamState::Joined) => {
            assert_eq!(authority.subscriptions, vec![NODE_PRESENCE.to_owned()])
        }
        Some(MixPamState::PendingJoin) => {
            assert_eq!(authority.subscriptions, vec![NODE_MESSAGES.to_owned()])
        }
        state => panic!("unexpected PAM state: {state:?}"),
    }
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn denied_reflection_archives_nothing_and_fans_out_nothing() -> Result<()> {
    let fixture = Fixture::new().await?;
    join_with_subscription(
        &fixture.pool,
        fixture.account_id,
        &fixture.channel,
        NODE_MESSAGES,
    )
    .await?;
    let repo = PostgresMixRepository::new(fixture.pool.clone());
    let source_id = Uuid::new_v4();
    let archive_id = Uuid::new_v4();
    block(&fixture.pool, fixture.account_id, "mix.remote.test").await?;
    let denied = archive(&repo, fixture.query(), source_id, archive_id).await?;
    assert_eq!(denied, ReflectedMixArchiveOutcome::Denied);
    assert!(denied.stored_original_account().is_none());
    assert_eq!(fixture.archive_count().await?, 0);

    sqlx::query("DELETE FROM blocked_jids WHERE owner_id=$1")
        .bind(fixture.account_id)
        .execute(&fixture.pool)
        .await?;
    let stored = archive(&repo, fixture.query(), source_id, archive_id).await?;
    assert_eq!(stored.stored_original_account(), Some(fixture.account_id));
    let replay = archive(&repo, fixture.query(), source_id, Uuid::new_v4()).await?;
    assert_eq!(
        replay,
        ReflectedMixArchiveOutcome::AdmittedOriginal {
            account_id: fixture.account_id,
            archive: SourceArchiveAdmission::Replay(archive_id),
        }
    );
    assert!(replay.stored_original_account().is_none());
    assert_eq!(fixture.archive_count().await?, 1);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn reflected_presence_error_reaches_only_eligible_resources() -> Result<()> {
    let fixture = Fixture::new().await?;
    let repo = PostgresMixRepository::new(fixture.pool.clone());
    assert_eq!(
        repo.pam_delivery_view(fixture.query())
            .await?
            .unwrap()
            .receiving_account(NODE_PRESENCE),
        None
    );
    let membership = join_with_subscription(
        &fixture.pool,
        fixture.account_id,
        &fixture.channel,
        NODE_MESSAGES,
    )
    .await?;
    assert_eq!(
        repo.pam_delivery_view(fixture.query())
            .await?
            .unwrap()
            .receiving_account(NODE_PRESENCE),
        None
    );
    let mut tx = fixture.pool.begin().await?;
    insert_subscription(&mut tx, membership, NODE_PRESENCE).await?;
    tx.commit().await?;
    let eligible = repo.pam_delivery_view(fixture.query()).await?.unwrap();
    assert_eq!(eligible.account_id, fixture.account_id);
    assert_eq!(
        eligible.receiving_account(NODE_PRESENCE),
        Some(fixture.account_id)
    );

    block(&fixture.pool, fixture.account_id, CHANNEL).await?;
    assert_eq!(
        repo.pam_delivery_view(fixture.query())
            .await?
            .unwrap()
            .receiving_account(NODE_PRESENCE),
        None
    );
    sqlx::query("DELETE FROM blocked_jids WHERE owner_id=$1")
        .bind(fixture.account_id)
        .execute(&fixture.pool)
        .await?;
    sqlx::query("UPDATE users SET is_disabled=true WHERE id=$1")
        .bind(fixture.account_id)
        .execute(&fixture.pool)
        .await?;
    let disabled = repo.pam_delivery_view(fixture.query()).await?.unwrap();
    assert!(!disabled.enabled);
    assert_eq!(disabled.receiving_account(NODE_PRESENCE), None);
    assert_eq!(fixture.archive_count().await?, 0);
    fixture.close().await
}
