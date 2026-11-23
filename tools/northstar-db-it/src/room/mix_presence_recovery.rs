use anyhow::Result;
use northstar_room_application::mix_service::{
    MixPayloads, MixPresenceRecoveryRepository, MixRepository, PresenceOutcome,
    RecoveryPresenceSource, RecoveryProgress, RECOVERY_PRESENCE_PAGE_CAP,
};
use northstar_room_core::mix::MixChannelId;
use northstar_room_postgres::mix::{
    create_mix_channel, join_mix_channel, CreateChannelOutcome, JoinChannelOutcome, JoinMixRequest,
    NODE_PRESENCE,
};
use northstar_time::{DateTime, Utc};
use northstar_workflows::room_effects::{PostgresMixRepository, WorkflowRoomEffects};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const ACTOR: &str = "publisher@remote.test";
const SERVICE: &str = "mix.example.test";
const FULL: &str = "publisher@remote.test/online";
const STATUS: &str = "<status>working</status>";

type StoredPresence = (Uuid, String, String, DateTime<Utc>);

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_recovery_{}", Uuid::new_v4().simple());
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
        Ok(Self {
            owner,
            pool,
            schema,
        })
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

    fn repository(&self) -> PostgresMixRepository {
        PostgresMixRepository::new(self.pool.clone())
    }

    async fn channel(&self) -> Result<MixChannelId> {
        let (outcome, _) = create_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            SERVICE,
            Some("room"),
            ACTOR,
            100,
            &MixPayloads,
            None,
        )
        .await?;
        let CreateChannelOutcome::Created(channel) = outcome else {
            anyhow::bail!("fixture channel was not created");
        };
        let joined = join_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            channel,
            JoinMixRequest {
                actor_jid: ACTOR,
                nick: Some("Publisher"),
                nodes: &[NODE_PRESENCE.to_owned()],
                pam_user_id: None,
                invitation: None,
                preference: None,
                anonymous_profile: false,
            },
            &MixPayloads,
            None,
        )
        .await?;
        anyhow::ensure!(matches!(joined, JoinChannelOutcome::Joined { .. }));
        Ok(MixChannelId::new(channel))
    }

    async fn presence(
        &self,
        channel: &MixChannelId,
        source: &RecoveryPresenceSource,
    ) -> Result<Option<StoredPresence>> {
        Ok(sqlx::query_as(
            "SELECT id, item_id, payload, created_at FROM mix_events
              WHERE channel_id=$1 AND node=$2 AND source_full_jid=$3",
        )
        .bind(channel.as_uuid())
        .bind(NODE_PRESENCE)
        .bind(source.full().to_string())
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn unavailable_events(&self, channel: &MixChannelId) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT count(*) FROM mix_delivery_events WHERE channel_id=$1 AND stanza_template LIKE '%unavailable%'",
        )
        .bind(channel.as_uuid())
        .fetch_one(&self.pool)
        .await?)
    }
}

async fn publish(
    repository: &PostgresMixRepository,
    channel: &MixChannelId,
    source: &RecoveryPresenceSource,
    payload: &str,
) -> Result<()> {
    let outcome = repository
        .store_mix_presence(
            channel.as_uuid(),
            source.participant().as_str(),
            &source.full().to_string(),
            payload,
            false,
        )
        .await?;
    anyhow::ensure!(matches!(outcome, PresenceOutcome::Published));
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn startup_sweep_drains_more_than_one_page() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let repository = fixture.repository();
    for index in 0..=RECOVERY_PRESENCE_PAGE_CAP {
        let source = RecoveryPresenceSource::parse(&format!("{ACTOR}/resource-{index}"))?;
        publish(&repository, &channel, &source, STATUS).await?;
    }
    let prepared = repository.prepare_recovery().await?;
    assert_eq!(prepared.targets.len(), 1);
    assert_eq!(
        prepared.targets[0].channel.as_str(),
        "room@mix.example.test"
    );
    assert_eq!(prepared.targets[0].participant.as_str(), ACTOR);
    let first = repository
        .expire_recovery_presence_page(prepared.epoch, u32::MAX)
        .await?;
    assert_eq!(
        first,
        RecoveryProgress {
            expired: 128,
            has_remaining: true
        }
    );
    let second = repository
        .expire_recovery_presence_page(prepared.epoch, u32::MAX)
        .await?;
    assert_eq!(
        second,
        RecoveryProgress {
            expired: 1,
            has_remaining: false
        }
    );
    assert_eq!(fixture.unavailable_events(&channel).await?, 129);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn skipped_locked_rows_are_revisited() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let repository = fixture.repository();
    let source = RecoveryPresenceSource::parse(FULL)?;
    publish(&repository, &channel, &source, STATUS).await?;
    let epoch = repository.prepare_recovery().await?.epoch;
    let mut held = fixture.pool.begin().await?;
    let row_id = fixture.presence(&channel, &source).await?.unwrap().0;
    sqlx::query("SELECT id FROM mix_events WHERE id=$1 FOR UPDATE")
        .bind(row_id)
        .fetch_one(&mut *held)
        .await?;
    assert_eq!(
        repository.expire_recovery_presence_page(epoch, 1).await?,
        RecoveryProgress {
            expired: 0,
            has_remaining: true
        }
    );
    assert_eq!(fixture.unavailable_events(&channel).await?, 0);
    held.commit().await?;
    assert_eq!(
        repository.expire_recovery_presence_page(epoch, 1).await?,
        RecoveryProgress {
            expired: 1,
            has_remaining: false
        }
    );
    assert_eq!(fixture.unavailable_events(&channel).await?, 1);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn reensured_resource_before_cutoff_survives_the_sweep() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let repository = fixture.repository();
    let source = RecoveryPresenceSource::parse(FULL)?;
    let sibling = RecoveryPresenceSource::parse(&format!("{ACTOR}/idle"))?;
    let fallback = RecoveryPresenceSource::parse(&format!("{ACTOR}/fallback"))?;
    publish(&repository, &channel, &source, STATUS).await?;
    publish(&repository, &channel, &sibling, STATUS).await?;
    publish(&repository, &channel, &fallback, STATUS).await?;
    let epoch = repository.prepare_recovery().await?.epoch;
    let original = fixture.presence(&channel, &source).await?.unwrap();
    assert!(original.3 < epoch.cutoff);
    assert!(matches!(
        repository
            .refresh_recovery_presence(epoch, &channel, &source)
            .await?,
        PresenceOutcome::Unchanged
    ));
    assert!(matches!(
        repository
            .ensure_mix_presence(
                channel.as_uuid(),
                fallback.participant().as_str(),
                &fallback.full().to_string(),
                "",
            )
            .await?,
        PresenceOutcome::Unchanged
    ));
    assert_eq!(
        repository.expire_recovery_presence_page(epoch, 2).await?,
        RecoveryProgress {
            expired: 1,
            has_remaining: false
        }
    );
    let refreshed = fixture.presence(&channel, &source).await?.unwrap();
    assert_eq!(
        (refreshed.0, refreshed.1, refreshed.2),
        (original.0, original.1, original.2)
    );
    assert!(refreshed.3 >= epoch.cutoff);
    assert!(fixture.presence(&channel, &fallback).await?.unwrap().3 >= epoch.cutoff);
    assert!(fixture.presence(&channel, &sibling).await?.is_none());
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn fresh_concurrent_publish_survives_the_sweep() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let repository = fixture.repository();
    let source = RecoveryPresenceSource::parse(FULL)?;
    publish(&repository, &channel, &source, STATUS).await?;
    let row_id = fixture.presence(&channel, &source).await?.unwrap().0;
    let mut held = fixture.pool.begin().await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    sqlx::query("SELECT id FROM mix_events WHERE id=$1 FOR UPDATE")
        .bind(row_id)
        .fetch_one(&mut *held)
        .await?;
    let publisher = tokio::spawn({
        let repository = repository.clone();
        let channel = channel.clone();
        let source = source.clone();
        async move { publish(&repository, &channel, &source, "<status>fresh</status>").await }
    });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    let epoch = repository.prepare_recovery().await?.epoch;
    held.commit().await?;
    publisher.await??;
    assert_eq!(
        repository.expire_recovery_presence_page(epoch, 1).await?,
        RecoveryProgress {
            expired: 0,
            has_remaining: false
        }
    );
    let stored = fixture.presence(&channel, &source).await?.unwrap();
    assert_eq!(stored.2, "<status>fresh</status>");
    assert!(stored.3 >= epoch.cutoff);
    assert_eq!(fixture.unavailable_events(&channel).await?, 0);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn liveness_refresh_keeps_the_explicit_payload() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let repository = fixture.repository();
    let source = RecoveryPresenceSource::parse(FULL)?;
    let missing = RecoveryPresenceSource::parse(&format!("{ACTOR}/absent"))?;
    publish(&repository, &channel, &source, STATUS).await?;
    let before = fixture.presence(&channel, &source).await?.unwrap();
    let delivery_count = || {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mix_delivery_events")
            .fetch_one(&fixture.pool)
    };
    let pending_before = delivery_count().await?;
    let epoch = repository.prepare_recovery().await?.epoch;
    for source in [&source, &missing] {
        assert!(matches!(
            repository
                .refresh_probe_presence_liveness(&channel, source)
                .await?,
            PresenceOutcome::Unchanged
        ));
    }
    let after = fixture.presence(&channel, &source).await?.unwrap();
    assert_eq!(
        (after.0, after.1, after.2),
        (before.0, before.1, STATUS.to_owned())
    );
    assert!(after.3 >= epoch.cutoff && after.3 > before.3);
    assert!(fixture.presence(&channel, &missing).await?.is_none());
    assert_eq!(delivery_count().await?, pending_before);
    let progress = repository.expire_recovery_presence_page(epoch, 1).await?;
    assert_eq!(
        progress,
        RecoveryProgress {
            expired: 0,
            has_remaining: false
        }
    );
    assert_eq!(fixture.unavailable_events(&channel).await?, 0);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn cutoff_uses_the_database_clock_under_process_skew() -> Result<()> {
    let fixture = Fixture::new().await?;
    sqlx::query(
        "CREATE FUNCTION clock_timestamp() RETURNS timestamptz LANGUAGE sql VOLATILE
         AS $$ SELECT pg_catalog.clock_timestamp() + interval '2 days' $$",
    )
    .execute(&fixture.pool)
    .await?;
    let url = std::env::var("TEST_DATABASE_URL")?;
    let search_path = format!("{},pg_catalog", fixture.schema);
    let options = url.parse::<sqlx::postgres::PgConnectOptions>()?.options([
        ("search_path", search_path.as_str()),
        ("statement_timeout", "10000"),
    ]);
    let skewed_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await?;
    let repository = PostgresMixRepository::new(skewed_pool.clone());
    let before: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&skewed_pool)
        .await?;
    let prepared = repository.prepare_recovery().await?;
    let after: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&skewed_pool)
        .await?;
    assert!(before <= prepared.epoch.cutoff && prepared.epoch.cutoff <= after);
    assert!(prepared.epoch.cutoff > Utc::now() + northstar_time::Duration::days(1));
    assert!(prepared.targets.is_empty());
    skewed_pool.close().await;
    fixture.close().await
}
