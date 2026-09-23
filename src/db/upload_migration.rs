//! Migrator-only journal for an offline local/S3 upload backend switch.
//!
//! Every copy has an attempt-qualified staging identity. A retry retires the
//! old attempt before issuing a new one, so an ambiguous write cannot be
//! mistaken for the new attempt's result.

use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

const OFFLINE_CONFIRMATION: &str = "ALL_NORTHSTAR_NODES_STOPPED_AND_NAMESPACE_VERIFIED";
const MAX_CLAIM_BATCH: i64 = 128;
const MANIFEST_DOMAIN: &[u8] = b"northstar-upload-migration-manifest-v1\0";

#[derive(Clone, Debug)]
pub(crate) struct BeginRun {
    pub run_id: Uuid,
    pub source_backend: String,
    pub target_backend: String,
    pub source_namespace_sha256: [u8; 32],
    pub target_namespace_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct MigrationRun {
    pub run_id: Uuid,
    pub source_backend: String,
    pub target_backend: String,
    pub source_namespace_sha256: [u8; 32],
    pub target_namespace_sha256: [u8; 32],
    pub source_generation: i64,
    pub source_slot_count: i64,
    pub state: String,
    pub manifest_sha256: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub(crate) struct MigrationItem {
    pub run_id: Uuid,
    pub object_id: Uuid,
    pub source_backend: String,
    pub source_key: String,
    pub source_version: Option<String>,
    pub source_fence: i64,
    pub source_size: i64,
    pub source_sha256: Option<[u8; 32]>,
    pub dest_attempt: Uuid,
    pub dest_key: String,
    pub claim_token: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedItem {
    pub item: MigrationItem,
    pub source_sha256: [u8; 32],
    pub dest_version: Option<String>,
    pub dest_size: i64,
    pub dest_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedManifestItem {
    pub object_id: Uuid,
    pub source_backend: String,
    pub source_key: String,
    pub source_version: Option<String>,
    pub source_fence: i64,
    pub source_size: i64,
    pub source_catalog_sha256: Option<[u8; 32]>,
    pub source_sha256: [u8; 32],
    pub dest_attempt: Uuid,
    pub dest_key: String,
    pub dest_version: Option<String>,
    pub dest_size: i64,
    pub dest_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct Cutover {
    pub run_id: Uuid,
    pub generation: i64,
    pub manifest_sha256: [u8; 32],
}

fn digest32(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored SHA-256 has the wrong length"))
}

fn maybe_digest32(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    bytes.map(digest32).transpose()
}

fn backend_pair(source: &str, target: &str) -> Result<()> {
    ensure!(
        matches!((source, target), ("local", "s3") | ("s3", "local")),
        "upload migration supports only local ↔ S3"
    );
    Ok(())
}

async fn run_by_id_tx(tx: &mut Transaction<'_, Postgres>, run_id: Uuid) -> Result<MigrationRun> {
    let row = sqlx::query("SELECT run_id,source_backend,target_backend,source_namespace_sha256,target_namespace_sha256,source_generation,source_slot_count,state,manifest_sha256 FROM upload_storage_migration_runs WHERE run_id=$1")
        .bind(run_id).fetch_one(&mut **tx).await?;
    Ok(MigrationRun {
        run_id: row.try_get("run_id")?,
        source_backend: row.try_get("source_backend")?,
        target_backend: row.try_get("target_backend")?,
        source_namespace_sha256: digest32(row.try_get("source_namespace_sha256")?)?,
        target_namespace_sha256: digest32(row.try_get("target_namespace_sha256")?)?,
        source_generation: row.try_get("source_generation")?,
        source_slot_count: row.try_get("source_slot_count")?,
        state: row.try_get("state")?,
        manifest_sha256: maybe_digest32(row.try_get("manifest_sha256")?)?,
    })
}

pub(crate) async fn find_active_run(pool: &PgPool) -> Result<Option<MigrationRun>> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT run_id FROM upload_storage_migration_runs WHERE state='copying'",
    )
    .fetch_optional(pool)
    .await?;
    let Some(id) = id else { return Ok(None) };
    let mut tx = pool.begin().await?;
    let run = run_by_id_tx(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Some(run))
}

/// Startup uses this owner-held probe instead of reading migration tables.
pub async fn upload_migration_active(pool: &PgPool) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_storage_migration_active()")
            .fetch_one(pool)
            .await?,
    )
}

pub(crate) async fn has_unverified_items(pool: &PgPool, run_id: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM upload_storage_migration_items WHERE run_id=$1 AND verified_at IS NULL)")
        .bind(run_id)
        .fetch_one(pool)
        .await?)
}

pub(crate) async fn get_run(pool: &PgPool, run_id: Uuid) -> Result<Option<MigrationRun>> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM upload_storage_migration_runs WHERE run_id=$1)",
    )
    .bind(run_id)
    .fetch_one(pool)
    .await?;
    if !exists {
        return Ok(None);
    }
    let mut tx = pool.begin().await?;
    let run = run_by_id_tx(&mut tx, run_id).await?;
    tx.commit().await?;
    Ok(Some(run))
}

pub(crate) async fn begin_offline_run(pool: &PgPool, input: BeginRun) -> Result<MigrationRun> {
    backend_pair(&input.source_backend, &input.target_backend)?;
    ensure!(
        input.source_namespace_sha256 != input.target_namespace_sha256,
        "source and target namespaces must differ"
    );
    let mut tx = pool.begin().await?;
    // A single fixed transaction lock serializes offline starts/cutovers with
    // other maintenance commands; the partial unique index is a second guard.
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(735559096281326101)")
        .execute(&mut *tx)
        .await?;
    let active: Option<Uuid> = sqlx::query_scalar(
        "SELECT run_id FROM upload_storage_migration_runs WHERE state='copying' FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(active_id) = active {
        let run = run_by_id_tx(&mut tx, active_id).await?;
        ensure!(
            run.source_backend == input.source_backend
                && run.target_backend == input.target_backend
                && run.source_namespace_sha256 == input.source_namespace_sha256
                && run.target_namespace_sha256 == input.target_namespace_sha256,
            "a different upload migration run is already active"
        );
        tx.commit().await?;
        return Ok(run);
    }
    sqlx::query("LOCK TABLE upload_slots,upload_storage_jobs,upload_cleanup_queue,upload_storage_authority IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    let authority = sqlx::query(
        "SELECT storage_backend,namespace_sha256,generation FROM upload_storage_authority WHERE singleton FOR UPDATE",
    ).fetch_one(&mut *tx).await?;
    let backend: String = authority.try_get("storage_backend")?;
    let namespace: Vec<u8> = authority.try_get("namespace_sha256")?;
    let generation: i64 = authority.try_get("generation")?;
    ensure!(
        backend == input.source_backend && namespace == input.source_namespace_sha256,
        "upload storage authority does not match the requested source"
    );
    let bad_slots: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM upload_slots WHERE storage_backend<>$1 OR storage_state NOT IN ('committed','legacy_committed') OR storage_object_key IS NULL OR storage_size IS DISTINCT FROM size OR storage_scrub_claim_token IS NOT NULL OR (storage_sha256 IS NOT NULL AND content_sha256 IS NOT NULL AND storage_sha256 IS DISTINCT FROM content_sha256) OR ($1='s3' AND (storage_state<>'committed' OR storage_object_version IS NULL OR storage_object_key IS DISTINCT FROM 'objects/'||id::text||'/'||storage_attempt::text)) OR ($1='local' AND (storage_object_version IS NOT NULL OR storage_object_key IS DISTINCT FROM id::text))",
    ).bind(&input.source_backend).fetch_one(&mut *tx).await?;
    ensure!(
        bad_slots == 0,
        "upload slots are not all quiescent committed source objects"
    );
    let pending: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM upload_storage_jobs)+(SELECT count(*) FROM upload_cleanup_queue)",
    ).fetch_one(&mut *tx).await?;
    ensure!(
        pending == 0,
        "upload storage or cleanup jobs must drain first"
    );
    let slot_count: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_slots")
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO upload_storage_migration_runs(run_id,source_backend,target_backend,source_namespace_sha256,target_namespace_sha256,source_generation,source_slot_count) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(input.run_id).bind(&input.source_backend).bind(&input.target_backend)
        .bind(input.source_namespace_sha256.as_slice()).bind(input.target_namespace_sha256.as_slice())
        .bind(generation).bind(slot_count).execute(&mut *tx).await?;
    let snapshotted=sqlx::query("INSERT INTO upload_storage_migration_items(run_id,object_id,source_backend,source_key,source_version,source_fence,source_size,source_catalog_sha256,source_sha256) SELECT $1,id,storage_backend,storage_object_key,storage_object_version,storage_fence,storage_size,storage_sha256,COALESCE(storage_sha256,content_sha256) FROM upload_slots ORDER BY id")
        .bind(input.run_id).execute(&mut *tx).await?;
    ensure!(
        snapshotted.rows_affected() == slot_count as u64,
        "upload slot snapshot changed during offline run creation"
    );
    let run = run_by_id_tx(&mut tx, input.run_id).await?;
    tx.commit().await?;
    Ok(run)
}

pub(crate) async fn claim_items(
    pool: &PgPool,
    run_id: Uuid,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<MigrationItem>> {
    ensure!(
        (1..=MAX_CLAIM_BATCH).contains(&limit),
        "claim batch must be 1..=128"
    );
    ensure!(
        (30..=3600).contains(&lease_seconds),
        "claim lease must be 30..=3600 seconds"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT 1 FROM upload_storage_migration_runs WHERE run_id=$1 FOR SHARE")
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
    let run = run_by_id_tx(&mut tx, run_id).await?;
    ensure!(run.state == "copying", "upload migration is not copyable");
    let rows = sqlx::query("SELECT object_id,source_backend,source_key,source_version,source_fence,source_size,source_sha256,current_attempt,claim_token,claim_expires_at FROM upload_storage_migration_items WHERE run_id=$1 AND verified_at IS NULL AND (claim_token IS NULL OR claim_expires_at<pg_catalog.clock_timestamp()) ORDER BY object_id FOR UPDATE SKIP LOCKED LIMIT $2")
        .bind(run_id).bind(limit).fetch_all(&mut *tx).await?;
    let mut claimed = Vec::with_capacity(rows.len());
    for row in rows {
        let object_id: Uuid = row.try_get("object_id")?;
        let old_attempt: Option<Uuid> = row.try_get("current_attempt")?;
        if let Some(old_attempt) = old_attempt {
            sqlx::query("UPDATE upload_storage_migration_attempts SET state='retired',retired_at=pg_catalog.clock_timestamp() WHERE run_id=$1 AND object_id=$2 AND attempt_id=$3 AND state='active'")
                .bind(run_id).bind(object_id).bind(old_attempt).execute(&mut *tx).await?;
        }
        let attempt = Uuid::new_v4();
        let token = Uuid::new_v4();
        let key = if run.target_backend == "s3" {
            format!("objects/{object_id}/{attempt}")
        } else {
            object_id.to_string()
        };
        sqlx::query("INSERT INTO upload_storage_migration_attempts(run_id,object_id,attempt_id,dest_key,state) VALUES($1,$2,$3,$4,'active')")
            .bind(run_id).bind(object_id).bind(attempt).bind(&key)
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE upload_storage_migration_items SET current_attempt=$3,claim_token=$4,claim_expires_at=pg_catalog.clock_timestamp()+($5::pg_catalog.int8 * INTERVAL '1 second') WHERE run_id=$1 AND object_id=$2 AND verified_at IS NULL")
            .bind(run_id).bind(object_id).bind(attempt).bind(token).bind(lease_seconds)
            .execute(&mut *tx).await?;
        claimed.push(MigrationItem {
            run_id,
            object_id,
            source_backend: row.try_get("source_backend")?,
            source_key: row.try_get("source_key")?,
            source_version: row.try_get("source_version")?,
            source_fence: row.try_get("source_fence")?,
            source_size: row.try_get("source_size")?,
            source_sha256: maybe_digest32(row.try_get("source_sha256")?)?,
            dest_attempt: attempt,
            dest_key: key,
            claim_token: token,
        });
    }
    tx.commit().await?;
    Ok(claimed)
}

pub(crate) async fn release_or_retry_claim(
    pool: &PgPool,
    run_id: Uuid,
    object_id: Uuid,
    claim_token: Uuid,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let attempt: Option<Uuid> = sqlx::query_scalar("SELECT current_attempt FROM upload_storage_migration_items WHERE run_id=$1 AND object_id=$2 AND claim_token=$3 AND verified_at IS NULL FOR UPDATE")
        .bind(run_id).bind(object_id).bind(claim_token).fetch_optional(&mut *tx).await?
        .flatten();
    let Some(attempt) = attempt else {
        return Ok(false);
    };
    sqlx::query("UPDATE upload_storage_migration_attempts SET state='retired',retired_at=pg_catalog.clock_timestamp() WHERE run_id=$1 AND object_id=$2 AND attempt_id=$3 AND state='active'")
        .bind(run_id).bind(object_id).bind(attempt).execute(&mut *tx).await?;
    sqlx::query("UPDATE upload_storage_migration_items SET current_attempt=NULL,claim_token=NULL,claim_expires_at=NULL WHERE run_id=$1 AND object_id=$2 AND claim_token=$3")
        .bind(run_id).bind(object_id).bind(claim_token).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(true)
}

pub(crate) async fn mark_verified(pool: &PgPool, verified: &VerifiedItem) -> Result<bool> {
    let item = &verified.item;
    ensure!(
        verified.dest_size == item.source_size && verified.dest_sha256 == verified.source_sha256,
        "destination bytes differ from the source"
    );
    if let Some(expected) = item.source_sha256 {
        ensure!(
            expected == verified.source_sha256,
            "source bytes differ from catalog SHA-256"
        );
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT 1 FROM upload_storage_migration_runs WHERE run_id=$1 FOR SHARE")
        .bind(item.run_id)
        .execute(&mut *tx)
        .await?;
    let run = run_by_id_tx(&mut tx, item.run_id).await?;
    ensure!(run.state == "copying", "upload migration is not copyable");
    ensure!(
        (run.target_backend == "s3" && verified.dest_version.is_some())
            || (run.target_backend == "local" && verified.dest_version.is_none()),
        "destination object version does not match its backend"
    );
    let result = sqlx::query("UPDATE upload_storage_migration_items SET source_sha256=$10,verified_at=pg_catalog.clock_timestamp(),dest_key=$11,dest_version=$12,dest_size=$13,dest_sha256=$14,claim_token=NULL,claim_expires_at=NULL WHERE run_id=$1 AND object_id=$2 AND source_backend=$3 AND source_key=$4 AND source_version IS NOT DISTINCT FROM $5 AND source_fence=$6 AND source_size=$7 AND source_sha256 IS NOT DISTINCT FROM $8 AND current_attempt=$9 AND claim_token=$15 AND claim_expires_at>=pg_catalog.clock_timestamp() AND verified_at IS NULL")
        .bind(item.run_id).bind(item.object_id).bind(&item.source_backend).bind(&item.source_key)
        .bind(&item.source_version).bind(item.source_fence).bind(item.source_size)
        .bind(item.source_sha256.map(|v| v.to_vec())).bind(item.dest_attempt)
        .bind(verified.source_sha256.as_slice()).bind(&item.dest_key)
        .bind(&verified.dest_version).bind(verified.dest_size)
        .bind(verified.dest_sha256.as_slice()).bind(item.claim_token)
        .execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Ok(false);
    }
    let attempt = sqlx::query("UPDATE upload_storage_migration_attempts SET state='verified',dest_version=$4 WHERE run_id=$1 AND object_id=$2 AND attempt_id=$3 AND state='active' AND dest_key=$5")
        .bind(item.run_id).bind(item.object_id).bind(item.dest_attempt)
        .bind(&verified.dest_version).bind(&item.dest_key).execute(&mut *tx).await?;
    ensure!(
        attempt.rows_affected() == 1,
        "migration attempt identity changed"
    );
    tx.commit().await?;
    Ok(true)
}

fn manifest_item(row: &sqlx::postgres::PgRow) -> Result<VerifiedManifestItem> {
    Ok(VerifiedManifestItem {
        object_id: row.try_get("object_id")?,
        source_backend: row.try_get("source_backend")?,
        source_key: row.try_get("source_key")?,
        source_version: row.try_get("source_version")?,
        source_fence: row.try_get("source_fence")?,
        source_size: row.try_get("source_size")?,
        source_catalog_sha256: maybe_digest32(row.try_get("source_catalog_sha256")?)?,
        source_sha256: digest32(row.try_get("source_sha256")?)?,
        dest_attempt: row.try_get("current_attempt")?,
        dest_key: row.try_get("dest_key")?,
        dest_version: row.try_get("dest_version")?,
        dest_size: row.try_get("dest_size")?,
        dest_sha256: digest32(row.try_get("dest_sha256")?)?,
    })
}

async fn list_verified_items_tx(
    tx: &mut Transaction<'_, Postgres>,
    run_id: Uuid,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<VerifiedManifestItem>> {
    let rows = sqlx::query("SELECT object_id,source_backend,source_key,source_version,source_fence,source_size,source_catalog_sha256,source_sha256,current_attempt,dest_key,dest_version,dest_size,dest_sha256 FROM upload_storage_migration_items WHERE run_id=$1 AND verified_at IS NOT NULL AND ($2::uuid IS NULL OR object_id>$2) ORDER BY object_id LIMIT $3")
        .bind(run_id).bind(after).bind(limit).fetch_all(&mut **tx).await?;
    rows.iter().map(manifest_item).collect()
}

pub(crate) async fn list_verified_items(
    pool: &PgPool,
    run_id: Uuid,
    after_object_id: Option<Uuid>,
    limit: i64,
) -> Result<Vec<VerifiedManifestItem>> {
    ensure!(
        (1..=1024).contains(&limit),
        "manifest page must be 1..=1024"
    );
    let mut tx = pool.begin().await?;
    let items = list_verified_items_tx(&mut tx, run_id, after_object_id, limit).await?;
    tx.commit().await?;
    Ok(items)
}

fn put_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
}

fn put_optional(hasher: &mut Sha256, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            hasher.update([1]);
            put_bytes(hasher, bytes);
        }
        None => hasher.update([0]),
    }
}

/// Canonical manifest v1 is domain-separated SHA-256 over length-prefixed
/// UTF-8 fields, UUID bytes, big-endian i64 values, and tagged optionals.
/// Rows must be supplied in ascending PostgreSQL UUID order, exactly once.
pub(crate) struct CanonicalManifestHasher {
    hasher: Sha256,
    last_id: Option<Uuid>,
    count: i64,
}

impl CanonicalManifestHasher {
    pub(crate) fn new(run: &MigrationRun) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_DOMAIN);
        hasher.update(run.run_id.as_bytes());
        put_bytes(&mut hasher, run.source_backend.as_bytes());
        put_bytes(&mut hasher, run.target_backend.as_bytes());
        hasher.update(run.source_namespace_sha256);
        hasher.update(run.target_namespace_sha256);
        hasher.update(run.source_generation.to_be_bytes());
        hasher.update(run.source_slot_count.to_be_bytes());
        Self {
            hasher,
            last_id: None,
            count: 0,
        }
    }

    pub(crate) fn update(&mut self, item: &VerifiedManifestItem) -> Result<()> {
        ensure!(
            self.last_id.is_none_or(|last| last < item.object_id),
            "manifest item order or identity is invalid"
        );
        self.last_id = Some(item.object_id);
        self.count += 1;
        self.hasher.update(item.object_id.as_bytes());
        put_bytes(&mut self.hasher, item.source_backend.as_bytes());
        put_bytes(&mut self.hasher, item.source_key.as_bytes());
        put_optional(
            &mut self.hasher,
            item.source_version.as_deref().map(str::as_bytes),
        );
        self.hasher.update(item.source_fence.to_be_bytes());
        self.hasher.update(item.source_size.to_be_bytes());
        put_optional(
            &mut self.hasher,
            item.source_catalog_sha256.as_ref().map(|v| v.as_slice()),
        );
        self.hasher.update(item.source_sha256);
        self.hasher.update(item.dest_attempt.as_bytes());
        put_bytes(&mut self.hasher, item.dest_key.as_bytes());
        put_optional(
            &mut self.hasher,
            item.dest_version.as_deref().map(str::as_bytes),
        );
        self.hasher.update(item.dest_size.to_be_bytes());
        self.hasher.update(item.dest_sha256);
        Ok(())
    }

    pub(crate) fn finish(self, expected_count: i64) -> Result<[u8; 32]> {
        ensure!(
            self.count == expected_count,
            "manifest does not cover every source slot"
        );
        Ok(self.hasher.finalize().into())
    }
}

pub(crate) async fn final_cutover(
    pool: &PgPool,
    run_id: Uuid,
    manifest_sha256: [u8; 32],
    operator_confirmation: &str,
) -> Result<Cutover> {
    ensure!(
        operator_confirmation == OFFLINE_CONFIRMATION,
        "offline storage cutover requires explicit all-nodes-stopped confirmation"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(735559096281326101)")
        .execute(&mut *tx)
        .await?;
    sqlx::query("LOCK TABLE upload_storage_migration_runs,upload_storage_migration_items,upload_storage_migration_attempts,upload_slots,upload_storage_jobs,upload_cleanup_queue,upload_storage_authority IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *tx).await?;
    let run = run_by_id_tx(&mut tx, run_id).await?;
    if run.state == "cutover" {
        ensure!(
            run.manifest_sha256 == Some(manifest_sha256),
            "completed cutover manifest differs from requested replay"
        );
        let authority = sqlx::query(
            "SELECT storage_backend,namespace_sha256,generation FROM upload_storage_authority WHERE singleton",
        ).fetch_one(&mut *tx).await?;
        let generation: i64 = authority.try_get("generation")?;
        ensure!(
            authority.try_get::<String, _>("storage_backend")? == run.target_backend
                && authority.try_get::<Vec<u8>, _>("namespace_sha256")?
                    == run.target_namespace_sha256
                && generation == run.source_generation + 1,
            "completed cutover is no longer the current storage authority"
        );
        tx.commit().await?;
        return Ok(Cutover {
            run_id,
            generation,
            manifest_sha256,
        });
    }
    ensure!(
        run.state == "copying",
        "upload migration is not ready for cutover"
    );
    let authority = sqlx::query("SELECT storage_backend,namespace_sha256,generation FROM upload_storage_authority WHERE singleton")
        .fetch_one(&mut *tx).await?;
    ensure!(
        authority.try_get::<String, _>("storage_backend")? == run.source_backend
            && authority.try_get::<Vec<u8>, _>("namespace_sha256")? == run.source_namespace_sha256
            && authority.try_get::<i64, _>("generation")? == run.source_generation,
        "upload storage authority changed during copy"
    );
    let pending: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM upload_storage_jobs)+(SELECT count(*) FROM upload_cleanup_queue)",
    ).fetch_one(&mut *tx).await?;
    ensure!(pending == 0, "upload jobs appeared during offline copy");
    let mismatches: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_slots s FULL JOIN (SELECT * FROM upload_storage_migration_items WHERE run_id=$1) i ON i.object_id=s.id WHERE s.id IS NULL OR i.object_id IS NULL OR i.verified_at IS NULL OR s.storage_backend IS DISTINCT FROM i.source_backend OR s.storage_state NOT IN ('committed','legacy_committed') OR s.storage_object_key IS DISTINCT FROM i.source_key OR s.storage_object_version IS DISTINCT FROM i.source_version OR s.storage_fence IS DISTINCT FROM i.source_fence OR s.storage_size IS DISTINCT FROM i.source_size OR s.storage_sha256 IS DISTINCT FROM i.source_catalog_sha256 OR (s.storage_sha256 IS NOT NULL AND s.content_sha256 IS NOT NULL AND s.storage_sha256 IS DISTINCT FROM s.content_sha256) OR s.storage_scrub_claim_token IS NOT NULL OR i.source_sha256 IS NULL OR i.dest_sha256 IS DISTINCT FROM i.source_sha256 OR i.dest_size IS DISTINCT FROM i.source_size OR (i.source_catalog_sha256 IS NOT NULL AND i.source_sha256 IS DISTINCT FROM i.source_catalog_sha256) OR (i.source_catalog_sha256 IS NULL AND s.content_sha256 IS NOT NULL AND i.source_sha256 IS DISTINCT FROM s.content_sha256) OR i.dest_key IS DISTINCT FROM CASE WHEN $2='s3' THEN 'objects/'||i.object_id::text||'/'||i.current_attempt::text ELSE i.object_id::text END OR ($2='s3' AND i.dest_version IS NULL) OR ($2='local' AND i.dest_version IS NOT NULL) OR NOT EXISTS (SELECT 1 FROM upload_storage_migration_attempts a WHERE a.run_id=i.run_id AND a.object_id=i.object_id AND a.attempt_id=i.current_attempt AND a.state='verified' AND a.dest_key=i.dest_key AND a.dest_version IS NOT DISTINCT FROM i.dest_version)")
        .bind(run_id).bind(&run.target_backend).fetch_one(&mut *tx).await?;
    ensure!(
        mismatches == 0,
        "upload slot or verified destination changed during copy"
    );
    let slot_count: i64 = sqlx::query_scalar("SELECT count(*) FROM upload_slots")
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        slot_count == run.source_slot_count,
        "upload slot count changed during copy"
    );
    let mut hasher = CanonicalManifestHasher::new(&run);
    let mut after = None;
    loop {
        let page = list_verified_items_tx(&mut tx, run_id, after, 512).await?;
        if page.is_empty() {
            break;
        }
        for item in &page {
            hasher.update(item)?;
        }
        after = page.last().map(|item| item.object_id);
    }
    ensure!(
        hasher.finish(run.source_slot_count)? == manifest_sha256,
        "manifest SHA-256 does not match the locked journal"
    );
    let updated = sqlx::query("UPDATE upload_slots s SET storage_backend=$2,storage_state='committed',storage_attempt=i.current_attempt,storage_stage_key=NULL,storage_stage_version=NULL,storage_object_key=i.dest_key,storage_object_version=i.dest_version,storage_sha256=i.dest_sha256,content_sha256=i.dest_sha256,completed_at=COALESCE(s.completed_at,s.created_at),storage_size=i.dest_size,storage_fence=s.storage_fence+1,storage_updated_at=pg_catalog.clock_timestamp(),storage_scrub_next_at=pg_catalog.clock_timestamp() FROM upload_storage_migration_items i WHERE i.run_id=$1 AND i.object_id=s.id AND i.verified_at IS NOT NULL")
        .bind(run_id).bind(&run.target_backend).execute(&mut *tx).await?;
    ensure!(
        updated.rows_affected() == run.source_slot_count as u64,
        "cutover did not update every upload slot"
    );
    sqlx::query(
        "ALTER TABLE upload_storage_authority DISABLE TRIGGER upload_storage_authority_immutable",
    )
    .execute(&mut *tx)
    .await?;
    let generation: i64 = sqlx::query_scalar("UPDATE upload_storage_authority SET storage_backend=$1,namespace_sha256=$2,generation=generation+1,updated_at=pg_catalog.clock_timestamp() WHERE singleton AND storage_backend=$3 AND namespace_sha256=$4 AND generation=$5 RETURNING generation")
        .bind(&run.target_backend).bind(run.target_namespace_sha256.as_slice())
        .bind(&run.source_backend).bind(run.source_namespace_sha256.as_slice())
        .bind(run.source_generation).fetch_one(&mut *tx).await?;
    sqlx::query(
        "ALTER TABLE upload_storage_authority ENABLE TRIGGER upload_storage_authority_immutable",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE upload_storage_migration_runs SET state='cutover',manifest_sha256=$2,updated_at=pg_catalog.clock_timestamp() WHERE run_id=$1 AND state='copying'")
        .bind(run_id).bind(manifest_sha256.as_slice()).execute(&mut *tx).await?;
    tx.commit()
        .await
        .context("offline upload cutover did not commit")?;
    Ok(Cutover {
        run_id,
        generation,
        manifest_sha256,
    })
}

pub(crate) async fn abort_run(pool: &PgPool, run_id: Uuid) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(735559096281326101)")
        .execute(&mut *tx)
        .await?;
    let state: String = sqlx::query_scalar(
        "SELECT state FROM upload_storage_migration_runs WHERE run_id=$1 FOR UPDATE",
    )
    .bind(run_id)
    .fetch_one(&mut *tx)
    .await?;
    if state == "cutover" {
        bail!("committed upload cutover cannot be aborted");
    }
    sqlx::query("UPDATE upload_storage_migration_attempts SET state='retired',retired_at=pg_catalog.clock_timestamp() WHERE run_id=$1 AND state='active'")
        .bind(run_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE upload_storage_migration_runs SET state='aborted',updated_at=pg_catalog.clock_timestamp() WHERE run_id=$1 AND state='copying'")
        .bind(run_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_manifest_rejects_duplicate_or_unsorted_items() {
        let run = MigrationRun {
            run_id: Uuid::new_v4(),
            source_backend: "local".into(),
            target_backend: "s3".into(),
            source_namespace_sha256: [1; 32],
            target_namespace_sha256: [2; 32],
            source_generation: 1,
            source_slot_count: 1,
            state: "copying".into(),
            manifest_sha256: None,
        };
        let id = Uuid::new_v4();
        let item = VerifiedManifestItem {
            object_id: id,
            source_backend: "local".into(),
            source_key: id.to_string(),
            source_version: None,
            source_fence: 0,
            source_size: 4,
            source_catalog_sha256: Some([3; 32]),
            source_sha256: [3; 32],
            dest_attempt: Uuid::new_v4(),
            dest_key: "objects/key".into(),
            dest_version: Some("version".into()),
            dest_size: 4,
            dest_sha256: [3; 32],
        };
        let mut hasher = CanonicalManifestHasher::new(&run);
        hasher.update(&item).unwrap();
        assert!(hasher.update(&item).is_err());
        assert_ne!(hasher.finish(1).unwrap(), [0; 32]);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_upload_migration_journal_fences_replay_and_cutover() {
        let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
        let expected_schema = std::env::var("TEST_DATABASE_SCHEMA")
            .expect("set TEST_DATABASE_SCHEMA to a random isolated schema");
        assert!(expected_schema
            .strip_prefix("northstar_upload_migrate_it_")
            .is_some_and(
                |suffix| suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
            ));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let actual_schema: String = sqlx::query_scalar("SELECT pg_catalog.current_schema()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(actual_schema, expected_schema);
        crate::db::migrate(&pool).await.unwrap();
        let mut ensure_tx = pool.begin().await.unwrap();
        sqlx::raw_sql(include_str!(
            "../../deploy/postgres-init/lib/ensure-northstar-restore-outcome-marker.sql"
        ))
        .execute(&mut *ensure_tx)
        .await
        .unwrap();
        ensure_tx.commit().await.unwrap();
        let mut tampered_marker = pool.begin().await.unwrap();
        sqlx::query(
            "ALTER TABLE northstar_restore_outcome_markers DROP CONSTRAINT northstar_restore_outcome_markers_outcome_check",
        )
        .execute(&mut *tampered_marker)
        .await
        .unwrap();
        assert!(sqlx::raw_sql(include_str!(
            "../../deploy/postgres-init/lib/ensure-northstar-restore-outcome-marker.sql"
        ))
        .execute(&mut *tampered_marker)
        .await
        .is_err());
        tampered_marker.rollback().await.unwrap();
        crate::db::upload::validate_upload_capacity_policy(&pool, 4096, 4096, 1 << 30)
            .await
            .unwrap();
        let local_namespace = [1_u8; 32];
        let s3_namespace = [2_u8; 32];
        sqlx::query("INSERT INTO upload_storage_authority(singleton,storage_backend,namespace_sha256) VALUES(TRUE,'local',$1)")
            .bind(local_namespace.as_slice()).execute(&pool).await.unwrap();
        let user = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',FALSE)",
        )
        .bind(user)
        .bind(format!("migrate-{}", user.simple()))
        .execute(&pool)
        .await
        .unwrap();
        let object = Uuid::new_v4();
        let digest = [3_u8; 32];
        sqlx::query("INSERT INTO upload_slots(id,user_id,filename,content_type,size,token_hash,expires_at,put_expires_at,uploaded,completed_at,content_sha256,storage_state,storage_backend,storage_object_key,storage_sha256,storage_size) VALUES($1,$2,'fixture.bin','application/octet-stream',4,$3,pg_catalog.clock_timestamp()+INTERVAL '2 hours',pg_catalog.clock_timestamp()+INTERVAL '1 hour',TRUE,pg_catalog.clock_timestamp(),$4,'committed','local',$5,$4,4)")
            .bind(object).bind(user).bind(b"migration-token".as_slice())
            .bind(digest.as_slice()).bind(object.to_string())
            .execute(&pool).await.unwrap();
        assert!(!upload_migration_active(&pool).await.unwrap());
        let inconsistent_digest = [4_u8; 32];
        sqlx::query("UPDATE upload_slots SET content_sha256=$2 WHERE id=$1")
            .bind(object)
            .bind(inconsistent_digest.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        assert!(begin_offline_run(
            &pool,
            BeginRun {
                run_id: Uuid::new_v4(),
                source_backend: "local".into(),
                target_backend: "s3".into(),
                source_namespace_sha256: local_namespace,
                target_namespace_sha256: s3_namespace,
            },
        )
        .await
        .is_err());
        sqlx::query("UPDATE upload_slots SET content_sha256=$2 WHERE id=$1")
            .bind(object)
            .bind(digest.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let first = begin_offline_run(
            &pool,
            BeginRun {
                run_id: Uuid::new_v4(),
                source_backend: "local".into(),
                target_backend: "s3".into(),
                source_namespace_sha256: local_namespace,
                target_namespace_sha256: s3_namespace,
            },
        )
        .await
        .unwrap();
        assert!(upload_migration_active(&pool).await.unwrap());
        assert!(has_unverified_items(&pool, first.run_id).await.unwrap());
        assert_eq!(first.source_slot_count, 1);
        assert_eq!(
            find_active_run(&pool).await.unwrap().unwrap().run_id,
            first.run_id
        );
        let claim = claim_items(&pool, first.run_id, 1, 60)
            .await
            .unwrap()
            .remove(0);
        assert!(
            release_or_retry_claim(&pool, first.run_id, object, claim.claim_token)
                .await
                .unwrap()
        );
        let replacement = claim_items(&pool, first.run_id, 1, 60)
            .await
            .unwrap()
            .remove(0);
        assert_ne!(claim.dest_attempt, replacement.dest_attempt);
        assert_ne!(claim.dest_key, replacement.dest_key);
        let old_state: String=sqlx::query_scalar("SELECT state FROM upload_storage_migration_attempts WHERE run_id=$1 AND object_id=$2 AND attempt_id=$3")
            .bind(first.run_id).bind(object).bind(claim.dest_attempt)
            .fetch_one(&pool).await.unwrap();
        assert_eq!(old_state, "retired");
        assert!(!mark_verified(
            &pool,
            &VerifiedItem {
                item: claim,
                source_sha256: digest,
                dest_version: Some("v1".into()),
                dest_size: 4,
                dest_sha256: digest,
            }
        )
        .await
        .unwrap());
        assert!(mark_verified(
            &pool,
            &VerifiedItem {
                item: replacement,
                source_sha256: digest,
                dest_version: Some("v2".into()),
                dest_size: 4,
                dest_sha256: digest,
            }
        )
        .await
        .unwrap());
        assert!(claim_items(&pool, first.run_id, 1, 60)
            .await
            .unwrap()
            .is_empty());
        assert!(!has_unverified_items(&pool, first.run_id).await.unwrap());
        let items = list_verified_items(&pool, first.run_id, None, 10)
            .await
            .unwrap();
        let mut hasher = CanonicalManifestHasher::new(&first);
        for item in &items {
            hasher.update(item).unwrap();
        }
        let manifest = hasher.finish(1).unwrap();
        assert!(
            final_cutover(&pool, first.run_id, [0; 32], OFFLINE_CONFIRMATION)
                .await
                .is_err()
        );
        let cutover = final_cutover(&pool, first.run_id, manifest, OFFLINE_CONFIRMATION)
            .await
            .unwrap();
        assert_eq!(cutover.generation, 2);
        assert_eq!(cutover.manifest_sha256, manifest);
        assert!(!upload_migration_active(&pool).await.unwrap());
        assert_eq!(
            final_cutover(&pool, first.run_id, manifest, OFFLINE_CONFIRMATION)
                .await
                .unwrap()
                .generation,
            2
        );
        assert!(find_active_run(&pool).await.unwrap().is_none());
        let second = begin_offline_run(
            &pool,
            BeginRun {
                run_id: Uuid::new_v4(),
                source_backend: "s3".into(),
                target_backend: "local".into(),
                source_namespace_sha256: s3_namespace,
                target_namespace_sha256: local_namespace,
            },
        )
        .await
        .unwrap();
        let second_claim = claim_items(&pool, second.run_id, 1, 60)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(second_claim.dest_key, object.to_string());
        assert!(mark_verified(
            &pool,
            &VerifiedItem {
                item: second_claim,
                source_sha256: digest,
                dest_version: None,
                dest_size: 4,
                dest_sha256: digest,
            }
        )
        .await
        .unwrap());
        let mut second_hasher = CanonicalManifestHasher::new(&second);
        for item in list_verified_items(&pool, second.run_id, None, 10)
            .await
            .unwrap()
        {
            second_hasher.update(&item).unwrap();
        }
        let second_manifest = second_hasher.finish(1).unwrap();
        sqlx::query("UPDATE upload_slots SET content_sha256=$2 WHERE id=$1")
            .bind(object)
            .bind(inconsistent_digest.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            final_cutover(&pool, second.run_id, second_manifest, OFFLINE_CONFIRMATION)
                .await
                .is_err()
        );
        sqlx::query("UPDATE upload_slots SET content_sha256=$2 WHERE id=$1")
            .bind(object)
            .bind(digest.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE upload_slots SET storage_fence=storage_fence+1 WHERE id=$1")
            .bind(object)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            final_cutover(&pool, second.run_id, second_manifest, OFFLINE_CONFIRMATION)
                .await
                .is_err()
        );
        sqlx::query("UPDATE upload_slots SET storage_fence=storage_fence-1 WHERE id=$1")
            .bind(object)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            final_cutover(&pool, second.run_id, second_manifest, OFFLINE_CONFIRMATION)
                .await
                .unwrap()
                .generation,
            3
        );
        let backend: String = sqlx::query_scalar(
            "SELECT storage_backend FROM upload_storage_authority WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(backend, "local");
        assert!(
            final_cutover(&pool, first.run_id, manifest, OFFLINE_CONFIRMATION)
                .await
                .is_err()
        );
        pool.close().await;
    }
}
