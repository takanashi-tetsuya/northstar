//! On-demand PubSub measurements. Run one scenario at a time on an isolated
//! database because pg_stat_statements_reset is shared across sessions.

use super::{integration_pool, named_single_connection_pool};
use anyhow::Result;
use northstar_pubsub_postgres::{
    set_subscription_limited_with_options_and_renderer, NoopMutationOutboxRenderer,
    PubSubMutationBusy, PubSubNode, PubSubSubscriptionOptions, SubscribeOutcome,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Barrier};
use tokio::task::JoinSet;

#[path = "lock_measure/auto_create.rs"]
mod auto_create;
#[path = "lock_measure/federation.rs"]
mod federation;
#[path = "lock_measure/graph.rs"]
mod graph;
#[path = "lock_measure/items.rs"]
mod items;
#[path = "lock_measure/replay.rs"]
mod replay;
#[path = "lock_measure/subscriptions.rs"]
mod subscriptions;

const DOMAIN: &str = "example.test";
const STORAGE_LIMIT: i64 = 1_000_000;
const LOCK_SAMPLE_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Default)]
struct OperationSamples {
    latencies: Vec<Duration>,
    outcomes: BTreeMap<String, usize>,
    failures: Vec<String>,
}

impl OperationSamples {
    async fn record<T: Debug>(
        &mut self,
        operation: impl Future<Output = Result<T>>,
        expected: impl FnOnce(&T) -> bool,
    ) {
        let started = Instant::now();
        let result = operation.await;
        self.latencies.push(started.elapsed());
        let label = match result {
            Ok(outcome) => {
                let debug = format!("{outcome:?}");
                let label = if debug == "()" {
                    "Ok"
                } else {
                    // Group Debug variants with arbitrary fields (e.g. SubIDs).
                    debug.split(['(', ' ', '{']).next().unwrap_or(&debug)
                }
                .to_owned();
                if !expected(&outcome) {
                    self.failures.push(debug);
                }
                label
            }
            Err(error) => {
                let busy = northstar_pubsub_application::is_pubsub_mutation_busy(&error)
                    || error.chain().any(|cause| {
                        cause.is::<PubSubMutationBusy>()
                            || cause.downcast_ref::<sqlx::Error>().is_some_and(
                                |error| match error {
                                    sqlx::Error::PoolTimedOut => true,
                                    sqlx::Error::Database(error) => {
                                        error.code().is_some_and(|code| {
                                            matches!(code.as_ref(), "55P03" | "57014")
                                        })
                                    }
                                    _ => false,
                                },
                            )
                    });
                self.failures.push(format!("{error:?}"));
                (if busy { "Busy" } else { "Error" }).to_owned()
            }
        };
        *self.outcomes.entry(label).or_default() += 1;
    }

    fn merge(&mut self, worker: Self) {
        self.latencies.extend(worker.latencies);
        self.failures.extend(worker.failures);
        for (label, count) in worker.outcomes {
            *self.outcomes.entry(label).or_default() += count;
        }
    }

    fn percentile_ms(&self, percentile: usize) -> f64 {
        let rank = (self.latencies.len() * percentile).div_ceil(100);
        self.latencies
            .get(rank.saturating_sub(1))
            .map_or(0.0, |latency| milliseconds(*latency))
    }
}

struct Measurement {
    operations: OperationSamples,
    wall_time: Duration,
    lock_wait: Value,
    statements: Value,
}

impl Measurement {
    fn report(mut self, scenario: &str, phase: &str, concurrency: usize) {
        self.operations.latencies.sort_unstable();
        let report = json!({
            "scenario": scenario,
            "phase": phase,
            "concurrency": concurrency,
            "ops": self.operations.latencies.len(),
            "wall_ms": milliseconds(self.wall_time),
            "p50_ms": self.operations.percentile_ms(50),
            "p95_ms": self.operations.percentile_ms(95),
            "max_ms": self.operations.percentile_ms(100),
            "outcomes": self.operations.outcomes,
            "lock_wait": self.lock_wait,
            "statements": self.statements,
        });
        println!("S46-MEASURE {report}");
        assert!(
            self.operations.failures.is_empty(),
            "{scenario}/{phase} produced unexpected outcomes: {:?}",
            self.operations.failures
        );
    }
}

struct Scenario {
    name: &'static str,
    pool: PgPool,
    monitor_pool: PgPool,
    sample_advisory_key: Option<i64>,
}

impl Scenario {
    async fn new(name: &'static str, max_concurrency: u32) -> Self {
        let (url, pool) = integration_pool(max_concurrency + 4).await;
        let monitor_pool = named_single_connection_pool(&url, "s46-measure-locks").await;
        let _ = sqlx::query("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
            .execute(&pool)
            .await;
        sqlx::query(
            "SELECT pg_catalog.set_config('search_path', pg_catalog.format('pg_catalog, %I', ns.nspname), FALSE)
               FROM pg_catalog.pg_extension ext
               JOIN pg_catalog.pg_namespace ns ON ns.oid=ext.extnamespace
              WHERE ext.extname='pg_stat_statements'",
        )
        .execute(&monitor_pool)
        .await
        .unwrap();

        // Open the worker connections outside the measurement window.
        let mut connections = Vec::new();
        for _ in 0..max_concurrency {
            connections.push(pool.acquire().await.unwrap());
        }
        drop(connections);
        Self {
            name,
            pool,
            monitor_pool,
            sample_advisory_key: None,
        }
    }

    async fn run<T, F, Fut, E>(
        &self,
        phase: &str,
        concurrency: usize,
        ops_per_worker: usize,
        operation: F,
        expected: E,
    ) where
        T: Debug + Send + 'static,
        F: Fn(usize, usize) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
        E: Fn(&T) -> bool + Clone + Send + Sync + 'static,
    {
        let stats_available = sqlx::query("SELECT pg_stat_statements_reset()")
            .execute(&self.monitor_pool)
            .await
            .is_ok();
        assert!(
            self.sample_advisory_key.is_none() || stats_available,
            "the S2S lock measurement needs pg_stat_statements and reset permission"
        );
        let (stop, stopped) = oneshot::channel();
        let monitor = tokio::spawn(sample_lock_waits(
            self.monitor_pool.clone(),
            stopped,
            self.sample_advisory_key,
        ));
        let barrier = Arc::new(Barrier::new(concurrency + 1));
        let mut workers = JoinSet::new();
        for worker in 0..concurrency {
            let barrier = Arc::clone(&barrier);
            let operation = operation.clone();
            let expected = expected.clone();
            workers.spawn(async move {
                let mut samples = OperationSamples::default();
                barrier.wait().await;
                for index in 0..ops_per_worker {
                    samples.record(operation(worker, index), &expected).await;
                }
                samples
            });
        }

        let started = Instant::now();
        barrier.wait().await;
        let mut operations = OperationSamples::default();
        while let Some(worker) = workers.join_next().await {
            match worker {
                Ok(worker) => operations.merge(worker),
                Err(error) => operations.failures.push(format!("{error:?}")),
            }
        }
        let wall_time = started.elapsed();
        let _ = stop.send(());
        let lock_wait = monitor.await.unwrap().unwrap();
        let statements = if stats_available {
            statement_statistics(&self.monitor_pool).await.unwrap()
        } else {
            json!({ "pg_stat_statements": "unavailable" })
        };
        Measurement {
            operations,
            wall_time,
            lock_wait,
            statements,
        }
        .report(self.name, phase, concurrency);
    }

    async fn close(self) {
        self.monitor_pool.close().await;
        self.pool.close().await;
    }
}

fn milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

async fn sample_lock_waits(
    pool: PgPool,
    mut stopped: oneshot::Receiver<()>,
    advisory_key: Option<i64>,
) -> Result<Value> {
    let mut ticks = tokio::time::interval(LOCK_SAMPLE_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut samples = 0;
    let mut max_waiters = 0;
    let mut waiter_sum = 0;
    let mut tuple_waiter_sum = 0;
    let mut advisory_waiter_sum = 0;
    let mut advisory_holder_sum = 0;
    loop {
        tokio::select! {
            biased;
            _ = &mut stopped => break,
            _ = ticks.tick() => {}
        }
        let (waiters, tuple_waiters): (i64, i64) = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE wait_event IN ('tuple','transactionid'))
             FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&pool)
        .await?;
        if let Some(key) = advisory_key {
            let (waiting, holding): (i64, i64) = sqlx::query_as(
                "SELECT count(*) FILTER (WHERE NOT granted), count(*) FILTER (WHERE granted)
                   FROM pg_locks
                  WHERE locktype='advisory' AND objsubid=1
                    AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
                    AND classid::bigint=(($1::bigint >> 32) & 4294967295)
                    AND objid::bigint=($1::bigint & 4294967295)",
            )
            .bind(key)
            .fetch_one(&pool)
            .await?;
            advisory_waiter_sum += waiting;
            advisory_holder_sum += holding;
        }
        samples += 1;
        max_waiters = max_waiters.max(waiters);
        waiter_sum += waiters;
        tuple_waiter_sum += tuple_waiters;
    }
    let interval_ms = milliseconds(LOCK_SAMPLE_INTERVAL);
    Ok(json!({
        "samples": samples,
        "max_waiters": max_waiters,
        "estimated_wait_ms": waiter_sum as f64 * interval_ms,
        "estimated_tuple_or_transaction_wait_ms": tuple_waiter_sum as f64 * interval_ms,
        "estimated_key_advisory_wait_ms": advisory_key.map(|_| advisory_waiter_sum as f64 * interval_ms),
        "estimated_key_advisory_hold_ms": advisory_key.map(|_| advisory_holder_sum as f64 * interval_ms),
    }))
}

async fn statement_statistics(pool: &PgPool) -> Result<Value> {
    let (calls, rows, shared_blocks, shared_block_bytes, total_exec_time_ms, top): (
        i64,
        i64,
        i64,
        i64,
        f64,
        Value,
    ) = sqlx::query_as(
        "WITH stats AS (
             SELECT queryid, userid, toplevel, query, calls, rows,
                    shared_blks_hit + shared_blks_read AS shared_blocks,
                    total_exec_time, mean_exec_time, max_exec_time
             FROM pg_stat_statements
             WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
               AND query NOT ILIKE '%pg_stat_statements%'
               AND query NOT ILIKE '%pg_stat_activity%'
               AND query NOT ILIKE '%pg_locks%'
         ), slowest AS (
             SELECT * FROM stats ORDER BY total_exec_time DESC, queryid, userid, toplevel LIMIT 10
         )
         SELECT COALESCE(sum(calls), 0)::bigint, COALESCE(sum(rows), 0)::bigint,
                COALESCE(sum(shared_blocks), 0)::bigint,
                (COALESCE(sum(shared_blocks), 0) * current_setting('block_size')::bigint)::bigint,
                COALESCE(sum(total_exec_time), 0),
                (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                    'calls', calls, 'rows', rows, 'total_exec_time_ms', total_exec_time,
                    'mean_exec_time_ms', mean_exec_time, 'max_exec_time_ms', max_exec_time,
                    'query', left(btrim(regexp_replace(query, '[[:space:]]+', ' ', 'g')), 160)
                 ) ORDER BY total_exec_time DESC, queryid, userid, toplevel), '[]'::jsonb)
                 FROM slowest)
         FROM stats",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "calls": calls,
        "rows": rows,
        "shared_blocks": shared_blocks,
        "shared_block_bytes": shared_block_bytes,
        "total_exec_time_ms": total_exec_time_ms,
        "top": top,
    }))
}

async fn subscribe(
    pool: &PgPool,
    node: &PubSubNode,
    requester: &str,
    subscriber: &str,
    subid: &str,
) -> Result<SubscribeOutcome> {
    let options = PubSubSubscriptionOptions::for_node_type(&node.node_type);
    set_subscription_limited_with_options_and_renderer(
        pool,
        DOMAIN,
        node.id,
        requester,
        subscriber,
        "subscribed",
        &node.node_type,
        &node.access_model,
        1_000,
        Some(&options),
        subid,
        &NoopMutationOutboxRenderer,
    )
    .await
}
