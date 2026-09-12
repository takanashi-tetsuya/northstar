//! Force a producer commit after GC's snapshot and before its row lock.
use super::*;
use std::time::Duration;

async fn fixture_pool(url: &str, schema: &str, application: &str) -> Result<PgPool> {
    let options = url
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .application_name(application)
        .options([("search_path", schema), ("statement_timeout", "10000")]);
    Ok(sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await?)
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn sequence_gc_preserves_a_producer_committed_after_its_snapshot() -> Result<()> {
    let url = std::env::var("TEST_DATABASE_URL")?;
    let owner = PgPool::connect(&url).await?;
    let schema = format!("sequence_gc_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&owner)
        .await?;
    let writer = fixture_pool(&url, &schema, "northstar-sequence-gc-writer").await?;
    let collector = fixture_pool(&url, &schema, "northstar-sequence-gc-test").await?;
    let result: Result<()> = async {
        // The updatable view adds only an explicit scheduling barrier before
        // the authority row lock. Both versions of the production collector
        // operate unchanged; the writer updates the same underlying row.
        // This does not depend on sleeps winning a race or on superuser/RLS.
        sqlx::raw_sql(
            "CREATE TABLE authority_rows(recipient_jid text PRIMARY KEY,next_sequence bigint NOT NULL);
             CREATE TABLE mix_delivery_recipients(recipient_jid text NOT NULL);
             CREATE TABLE mix_delivery_dead_letters(recipient_jid text NOT NULL);
             CREATE FUNCTION gc_snapshot_gate() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
             BEGIN
                 IF current_setting('application_name')='northstar-sequence-gc-test' THEN
                     PERFORM pg_advisory_xact_lock(747162391);
                 END IF;
                 RETURN TRUE;
             END $$;
             CREATE VIEW mix_delivery_recipient_sequences AS
                 SELECT recipient_jid,next_sequence FROM authority_rows WHERE gc_snapshot_gate();",
        )
        .execute(&writer)
        .await?;

        for destination in ["mix_delivery_recipients", "mix_delivery_dead_letters"] {
            sqlx::query("INSERT INTO authority_rows VALUES('recipient@example.test',2)")
                .execute(&writer)
                .await?;
            let mut barrier = writer.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(747162391)")
                .execute(&mut *barrier)
                .await?;
            let gc_pool = collector.clone();
            let gc = tokio::spawn(async move { prune_empty_mix_delivery_sequences(&gc_pool, 1).await });
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let waiting: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                          WHERE application_name='northstar-sequence-gc-test'
                            AND datname=current_database() AND wait_event_type='Lock'
                            AND wait_event='advisory')",
                    )
                    .fetch_one(&writer)
                    .await?;
                    if waiting {
                        return Ok::<_, sqlx::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await??;
            let mut producer = writer.begin().await?;
            sqlx::query("UPDATE authority_rows SET next_sequence=3 WHERE recipient_jid='recipient@example.test'")
                .execute(&mut *producer)
                .await?;
            sqlx::query(&format!("INSERT INTO {destination} VALUES('recipient@example.test')"))
                .execute(&mut *producer)
                .await?;
            producer.commit().await?;
            barrier.commit().await?;
            tokio::time::timeout(Duration::from_secs(5), gc).await???;
            let sequence: Option<i64> = sqlx::query_scalar(
                "SELECT next_sequence FROM authority_rows WHERE recipient_jid='recipient@example.test'",
            )
            .fetch_optional(&writer)
            .await?;
            anyhow::ensure!(sequence == Some(3), "GC deleted a committed {destination} authority");
            // Retention still removes an authority once its last durable
            // dependency disappears; keeping every authority is not a fix.
            sqlx::query(&format!("DELETE FROM {destination}"))
                .execute(&writer)
                .await?;
            prune_empty_mix_delivery_sequences(&collector, 1).await?;
            let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM authority_rows")
                .fetch_one(&writer)
                .await?;
            anyhow::ensure!(remaining == 0, "empty sequence authority was not pruned");
        }

        sqlx::query("INSERT INTO authority_rows VALUES('a@example.test',2),('b@example.test',2),('c@example.test',2)")
            .execute(&writer)
            .await?;
        let mut producer = writer.begin().await?;
        sqlx::query("SELECT recipient_jid FROM authority_rows WHERE recipient_jid='a@example.test' FOR UPDATE")
            .fetch_one(&mut *producer)
            .await?;
        // A live producer is skipped, and the original one-row page bound
        // still applies to the other two empty authorities.
        tokio::time::timeout(Duration::from_secs(2), prune_empty_mix_delivery_sequences(&collector, 1)).await??;
        let survivors: Vec<String> = sqlx::query_scalar("SELECT recipient_jid FROM authority_rows ORDER BY recipient_jid")
            .fetch_all(&writer)
            .await?;
        anyhow::ensure!(survivors == ["a@example.test", "c@example.test"]);
        producer.rollback().await?;
        Ok(())
    }.await;
    collector.close().await;
    writer.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&owner)
        .await?;
    owner.close().await;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn event_gc_preserves_a_requeue_committed_after_its_snapshot() -> Result<()> {
    let url = std::env::var("TEST_DATABASE_URL")?;
    let owner = PgPool::connect(&url).await?;
    let schema = format!("event_gc_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&owner)
        .await?;
    let writer = fixture_pool(&url, &schema, "northstar-event-gc-writer").await?;
    let collector = fixture_pool(&url, &schema, "northstar-event-gc-test").await?;
    let result: Result<()> = async {
        sqlx::raw_sql(
            "CREATE TABLE event_rows(event_id uuid PRIMARY KEY,revision bigint NOT NULL DEFAULT 1);
             CREATE TABLE mix_delivery_recipients(event_id uuid REFERENCES event_rows ON DELETE CASCADE);
             CREATE TABLE mix_delivery_capacity_releases(release_kind integer,parent_event_id uuid);
             CREATE FUNCTION gc_snapshot_gate() RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
             BEGIN
                 IF current_setting('application_name')='northstar-event-gc-test' THEN
                     PERFORM pg_advisory_xact_lock(747162392);
                 END IF;
                 RETURN TRUE;
             END $$;
             CREATE VIEW mix_delivery_events AS
                 SELECT event_id FROM event_rows WHERE gc_snapshot_gate();",
        ).execute(&writer).await?;
        let event_id = Uuid::new_v4();
        sqlx::query("INSERT INTO event_rows(event_id) VALUES($1)").bind(event_id).execute(&writer).await?;
        sqlx::query("INSERT INTO mix_delivery_capacity_releases VALUES(1,$1)").bind(event_id).execute(&writer).await?;
        let mut barrier = writer.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(747162392)").execute(&mut *barrier).await?;
        let gc_pool = collector.clone();
        let gc = tokio::spawn(async move { prune_empty_mix_delivery_events(&gc_pool, 1).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                      WHERE application_name='northstar-event-gc-test'
                        AND datname=current_database() AND wait_event_type='Lock'
                        AND wait_event='advisory')",
                ).fetch_one(&writer).await?;
                if waiting { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        let mut producer = writer.begin().await?;
        sqlx::query("UPDATE event_rows SET revision=2 WHERE event_id=$1").bind(event_id).execute(&mut *producer).await?;
        sqlx::query("INSERT INTO mix_delivery_recipients VALUES($1)").bind(event_id).execute(&mut *producer).await?;
        producer.commit().await?;
        barrier.commit().await?;
        tokio::time::timeout(Duration::from_secs(5), gc).await???;
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM event_rows),(SELECT count(*) FROM mix_delivery_recipients)",
        ).fetch_one(&writer).await?;
        anyhow::ensure!(counts == (1,1), "GC cascaded a newly committed requeue: {counts:?}");
        sqlx::query("DELETE FROM mix_delivery_recipients").execute(&writer).await?;
        prune_empty_mix_delivery_events(&collector, 1).await?;
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM event_rows").fetch_one(&writer).await?;
        anyhow::ensure!(remaining == 0, "orphaned event was not pruned");
        Ok(())
    }.await;
    collector.close().await;
    writer.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&owner)
        .await?;
    owner.close().await;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn empty_delivery_claim_avoids_the_event_lock_and_recovers_after_insert() -> Result<()> {
    let url = std::env::var("TEST_DATABASE_URL")?;
    let owner = PgPool::connect(&url).await?;
    let schema = format!("empty_claim_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&owner)
        .await?;
    let pool = fixture_pool(&url, &schema, "northstar-empty-claim-test").await?;
    let result: Result<()> = async {
        crate::db::migrate(&pool).await?;
        let mut busy_event = pool.begin().await?;
        sqlx::query("LOCK TABLE mix_delivery_events IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *busy_event)
            .await?;
        let empty = tokio::time::timeout(
            Duration::from_secs(2),
            claim_mix_deliveries(&pool, 1, 65_536),
        )
        .await??;
        anyhow::ensure!(empty.is_empty());
        busy_event.rollback().await?;
        // Use the production admission helper from the neighboring ordering
        // regression so the later nonempty claim has real capacity, event,
        // sequence and recipient authority. The empty observation is not
        // cached and cannot hide a subsequent committed insertion.
        let recipient = format!("{}@example.test", Uuid::new_v4().simple());
        let (_, delivery_id) =
            delivery_route_wake_integration_tests::insert_delivery(&pool, &recipient, 1).await;
        let claimed = claim_mix_deliveries(&pool, 1, 65_536).await?;
        anyhow::ensure!(claimed.len() == 1 && claimed[0].delivery_id == delivery_id);
        anyhow::ensure!(
            acknowledge_mix_delivery(&pool, delivery_id, claimed[0].lease_token).await?
        );
        anyhow::ensure!(claim_mix_deliveries(&pool, 1, 65_536).await?.is_empty());
        Ok(())
    }
    .await;
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&owner)
        .await?;
    owner.close().await;
    result
}
