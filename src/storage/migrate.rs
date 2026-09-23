//! Offline, manifest-driven upload backend migration.
//!
//! Every target key is journaled before I/O. An uncertain attempt is never
//! reused: its lease must expire before the repository issues another key.

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use futures::{stream, StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use super::{
    s3_settings_from_env, upload_storage_namespace_id, LocalUploadStore, S3UploadStore, UploadStore,
};
use crate::db::upload_migration::{
    self, BeginRun, CanonicalManifestHasher, MigrationItem, VerifiedItem,
};

const OBJECT_IO_DEADLINE: Duration = Duration::from_secs(180);
const CLAIM_LEASE_SECONDS: i64 = 900;
const OFFLINE_CONFIRMATION: &str = "ALL_NORTHSTAR_NODES_STOPPED_AND_NAMESPACE_VERIFIED";

fn development_pause_enabled(name: &str) -> Result<bool> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value)
            if value == "true"
                && std::env::var("MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT").as_deref()
                    == Ok("true")
                && std::env::var("XMPP_DOMAIN").is_ok_and(|domain| {
                    domain == "localhost"
                        || domain.ends_with(".localhost")
                        || domain.ends_with(".test")
                }) =>
        {
            Ok(true)
        }
        _ => anyhow::bail!("{name} is restricted to explicit development fixtures"),
    }
}

fn digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug)]
struct Options {
    source: String,
    target: String,
    run_id: Option<Uuid>,
    all_nodes_stopped: bool,
    abort_run: Option<Uuid>,
    concurrency: usize,
}

fn parse_options(args: &[String]) -> Result<Options> {
    let mut source = None;
    let mut target = None;
    let mut run_id = None;
    let mut all_nodes_stopped = false;
    let mut abort_run = None;
    let mut concurrency = 2;
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--from" => {
                source = Some(
                    arguments
                        .next()
                        .context("--from needs local or s3")?
                        .clone(),
                )
            }
            "--to" => target = Some(arguments.next().context("--to needs local or s3")?.clone()),
            "--run-id" => {
                run_id = Some(Uuid::parse_str(
                    arguments.next().context("--run-id needs a UUID")?,
                )?)
            }
            "--all-nodes-stopped" => all_nodes_stopped = true,
            "--abort-run" => {
                abort_run = Some(Uuid::parse_str(
                    arguments.next().context("--abort-run needs a UUID")?,
                )?)
            }
            "--concurrency" => {
                concurrency = arguments
                    .next()
                    .context("--concurrency needs 1..=8")?
                    .parse()
                    .context("--concurrency must be a decimal integer")?;
            }
            _ => anyhow::bail!("unknown storage migration option: {argument}"),
        }
    }
    let source = source.context("--from local|s3 is required")?;
    let target = target.context("--to local|s3 is required")?;
    ensure!(
        matches!(
            (source.as_str(), target.as_str()),
            ("local", "s3") | ("s3", "local")
        ),
        "storage migration supports only local ↔ s3"
    );
    ensure!(
        all_nodes_stopped,
        "offline migration requires --all-nodes-stopped after stopping every server and worker"
    );
    ensure!(
        abort_run.is_none() || run_id.is_none(),
        "choose --run-id or --abort-run"
    );
    ensure!(
        (1..=8).contains(&concurrency),
        "--concurrency must be 1..=8"
    );
    Ok(Options {
        source,
        target,
        run_id,
        all_nodes_stopped,
        abort_run,
        concurrency,
    })
}

pub(crate) async fn run_cli(pool: &PgPool, args: &[String]) -> Result<()> {
    let options = parse_options(args)?;
    let pause_after_claim =
        development_pause_enabled("NORTHSTAR_STORAGE_MIGRATION_TEST_PAUSE_AFTER_CLAIM")?;
    let pause_before_cutover =
        development_pause_enabled("NORTHSTAR_STORAGE_MIGRATION_TEST_PAUSE_BEFORE_CUTOVER")?;
    if let Some(run_id) = options.abort_run {
        upload_migration::abort_run(pool, run_id).await?;
        println!(
            "upload migration {run_id} aborted; the journal and copied objects remain for review"
        );
        return Ok(());
    }
    let local_root = std::env::var_os("UPLOAD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/uploads"));
    let s3_settings = s3_settings_from_env()?;
    let source_namespace_sha256 =
        upload_storage_namespace_id(&options.source, &local_root, Some(&s3_settings))?;
    let target_namespace_sha256 =
        upload_storage_namespace_id(&options.target, &local_root, Some(&s3_settings))?;
    if let Some(requested_id) = options.run_id {
        if let Some(previous) = upload_migration::get_run(pool, requested_id).await? {
            ensure!(
                previous.source_backend == options.source
                    && previous.target_backend == options.target
                    && previous.source_namespace_sha256 == source_namespace_sha256
                    && previous.target_namespace_sha256 == target_namespace_sha256,
                "the requested migration run belongs to another storage namespace"
            );
            if previous.state == "cutover" {
                let manifest = previous
                    .manifest_sha256
                    .context("completed migration has no manifest digest")?;
                let cutover = upload_migration::final_cutover(
                    pool,
                    requested_id,
                    manifest,
                    OFFLINE_CONFIRMATION,
                )
                .await?;
                println!(
                    "upload migration {} already committed generation {} manifest {}",
                    cutover.run_id,
                    cutover.generation,
                    digest_hex(&cutover.manifest_sha256)
                );
                return Ok(());
            }
        }
    }
    let s3: Arc<dyn UploadStore> = Arc::new(S3UploadStore::new(s3_settings)?);
    let local: Arc<dyn UploadStore> = Arc::new(LocalUploadStore::new(local_root));
    let source_store = if options.source == "s3" {
        Arc::clone(&s3)
    } else {
        Arc::clone(&local)
    };
    let target_store = if options.target == "s3" { s3 } else { local };

    let existing = upload_migration::find_active_run(pool).await?;
    if let (Some(requested), Some(active)) = (options.run_id, &existing) {
        ensure!(
            requested == active.run_id,
            "a different migration run is already active"
        );
    }
    let run = upload_migration::begin_offline_run(
        pool,
        BeginRun {
            run_id: options
                .run_id
                .or_else(|| existing.as_ref().map(|run| run.run_id))
                .unwrap_or_else(Uuid::new_v4),
            source_backend: options.source,
            target_backend: options.target,
            source_namespace_sha256,
            target_namespace_sha256,
        },
    )
    .await?;
    eprintln!(
        "upload migration run {}: {} -> {}, {} objects",
        run.run_id, run.source_backend, run.target_backend, run.source_slot_count
    );
    let mut empty_rounds = 0_u16;
    loop {
        let items = upload_migration::claim_items(
            pool,
            run.run_id,
            options.concurrency as i64,
            CLAIM_LEASE_SECONDS,
        )
        .await?;
        if items.is_empty() {
            match verified_manifest(pool, &run).await? {
                Some(manifest) => {
                    if pause_before_cutover {
                        tokio::time::sleep(Duration::from_secs(20)).await;
                    }
                    revalidate_verified_destinations(
                        pool,
                        &run,
                        target_store.as_ref(),
                        options.concurrency,
                    )
                    .await?;
                    let cutover = upload_migration::final_cutover(pool, run.run_id, manifest,
                        if options.all_nodes_stopped { OFFLINE_CONFIRMATION } else { "" }).await?;
                    println!("upload migration {} committed generation {} manifest {}",
                        cutover.run_id, cutover.generation, digest_hex(&cutover.manifest_sha256));
                    return Ok(());
                }
                None if empty_rounds < 190 => {
                    empty_rounds += 1;
                    if empty_rounds == 1 || empty_rounds.is_multiple_of(12) {
                        eprintln!("waiting for an earlier upload migration claim to expire");
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                None => anyhow::bail!("migration has no claimable rows but is incomplete after waiting for claim expiry"),
            }
        }
        empty_rounds = 0;
        if pause_after_claim {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
        stream::iter(
            items
                .into_iter()
                .map(|item| copy_one(pool, source_store.as_ref(), target_store.as_ref(), item)),
        )
        .buffer_unordered(options.concurrency)
        .try_collect::<Vec<_>>()
        .await?;
    }
}

async fn verified_manifest(
    pool: &PgPool,
    run: &upload_migration::MigrationRun,
) -> Result<Option<[u8; 32]>> {
    if upload_migration::has_unverified_items(pool, run.run_id).await? {
        return Ok(None);
    }
    let mut hasher = CanonicalManifestHasher::new(run);
    let mut cursor = None;
    let mut count = 0_i64;
    loop {
        let page = upload_migration::list_verified_items(pool, run.run_id, cursor, 128).await?;
        if page.is_empty() {
            break;
        }
        for item in &page {
            hasher.update(item)?;
            count += 1;
        }
        cursor = page.last().map(|item| item.object_id);
    }
    if count != run.source_slot_count {
        return Ok(None);
    }
    Ok(Some(hasher.finish(run.source_slot_count)?))
}

async fn revalidate_verified_destinations(
    pool: &PgPool,
    run: &upload_migration::MigrationRun,
    target: &dyn UploadStore,
    concurrency: usize,
) -> Result<()> {
    ensure!(
        target.backend() == run.target_backend,
        "migration destination backend changed"
    );
    let mut cursor = None;
    let mut count = 0_i64;
    loop {
        let page = upload_migration::list_verified_items(pool, run.run_id, cursor, 128).await?;
        if page.is_empty() {
            break;
        }
        stream::iter(page.iter().map(|item| validate_destination(target, item)))
            .buffer_unordered(concurrency)
            .try_collect::<Vec<_>>()
            .await?;
        count += i64::try_from(page.len())?;
        cursor = page.last().map(|item| item.object_id);
    }
    ensure!(
        count == run.source_slot_count,
        "verified destination set changed before cutover"
    );
    Ok(())
}

async fn validate_destination(
    target: &dyn UploadStore,
    item: &upload_migration::VerifiedManifestItem,
) -> Result<()> {
    tokio::time::timeout(OBJECT_IO_DEADLINE, async {
        let mut object = target
            .get(&item.dest_key, item.dest_version.as_deref())
            .await?
            .context("verified migration destination is missing")?;
        let expected_size = u64::try_from(item.dest_size)?;
        ensure!(
            object.object_version == item.dest_version && object.size == expected_size,
            "migration destination version or size changed before cutover"
        );
        let mut digest = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let read = object.reader.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .context("destination size overflow")?;
            ensure!(
                size <= expected_size,
                "migration destination grew before cutover"
            );
            digest.update(&buffer[..read]);
        }
        ensure!(
            size == expected_size && digest.finalize().as_slice() == item.dest_sha256,
            "migration destination bytes changed before cutover"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("migration destination revalidation timed out")??;
    Ok(())
}

async fn copy_one(
    pool: &PgPool,
    source: &dyn UploadStore,
    target: &dyn UploadStore,
    item: MigrationItem,
) -> Result<()> {
    let size = u64::try_from(item.source_size).context("negative source object size")?;
    let source_read: Result<_> = async {
        let stored = tokio::time::timeout(
            OBJECT_IO_DEADLINE,
            source.get(&item.source_key, item.source_version.as_deref()),
        )
        .await
        .context("source object read timed out")??
        .context("source object is missing")?;
        ensure!(
            stored.size == size && stored.object_version == item.source_version,
            "source object version or size differs from the journal"
        );
        Ok(stored)
    }
    .await;
    let stored = match source_read {
        Ok(stored) => stored,
        Err(error) => {
            // No destination request has started, so this attempt can be
            // retired immediately without an ambiguous provider write.
            upload_migration::release_or_retry_claim(
                pool,
                item.run_id,
                item.object_id,
                item.claim_token,
            )
            .await?;
            return Err(error);
        }
    };
    let id = item.object_id.to_string();
    let attempt = item.dest_attempt.to_string();
    let mut staged = tokio::time::timeout(
        OBJECT_IO_DEADLINE,
        target.put(&id, &attempt, stored.reader, size),
    )
    .await
    .context("destination object upload timed out")??;
    ensure!(
        staged.object_key() == item.dest_key && staged.bytes_written() == size,
        "destination stage differs from the journal"
    );
    let source_sha256 = *staged
        .sha256()
        .context("destination upload did not receive exact source size")?;
    if let Some(expected) = item.source_sha256 {
        ensure!(
            source_sha256 == expected,
            "source bytes differ from committed SHA-256"
        );
    }
    let committed = tokio::time::timeout(
        OBJECT_IO_DEADLINE,
        target.commit(&id, &attempt, staged.stage_version(), size, &source_sha256),
    )
    .await
    .context("destination object verification timed out")??;
    ensure!(
        committed.backend == target.backend()
            && committed.object_key == item.dest_key
            && committed.size == size,
        "verified destination locator differs from the journal"
    );
    ensure!(
        target.backend() != "s3" || committed.object_version.is_some(),
        "S3 destination did not provide an immutable version identifier"
    );
    ensure!(
        target.backend() != "local" || committed.object_version.is_none(),
        "local destination unexpectedly returned an object version"
    );
    let verified = VerifiedItem {
        item,
        source_sha256,
        dest_version: committed.object_version,
        dest_size: i64::try_from(size)?,
        dest_sha256: source_sha256,
    };
    ensure!(
        upload_migration::mark_verified(pool, &verified).await?,
        "migration claim changed before object verification could be committed"
    );
    staged.durably_recorded();
    if target.backend() == "local" {
        if let Err(error) = target.abort(&id, &attempt, None).await {
            eprintln!("local migration stage for {id} remains for later cleanup: {error}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_cli_requires_offline_confirmation_and_opposite_backends() {
        let args = ["--from", "local", "--to", "s3"].map(str::to_owned);
        assert!(parse_options(&args).is_err());
        let args = ["--from", "s3", "--to", "s3", "--all-nodes-stopped"].map(str::to_owned);
        assert!(parse_options(&args).is_err());
        let args = ["--from", "local", "--to", "s3", "--all-nodes-stopped"].map(str::to_owned);
        assert!(parse_options(&args).is_ok());
    }
}
