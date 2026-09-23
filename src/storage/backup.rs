//! Exact-version S3 transfer for offline, authenticated backup and restore.

use super::{upload_storage_namespace_id, S3UploadStore, UploadStore};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

struct Entry {
    id: Uuid,
    key: String,
    version: String,
    size: u64,
    digest: [u8; 32],
}

fn digest_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_digest(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "digest is not canonical lowercase SHA-256"
    );
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(digest)
}

fn read_inventory(path: &Path) -> Result<Vec<Entry>> {
    anyhow::ensure!(
        path.is_file() && !path.is_symlink(),
        "inventory must be a regular file"
    );
    anyhow::ensure!(
        path.metadata()?.len() <= 512 * 1024 * 1024,
        "S3 inventory exceeds the bounded input size"
    );
    let raw = std::fs::read_to_string(path).context("could not read S3 inventory")?;
    let mut lines = raw.lines();
    anyhow::ensure!(
        lines.next() == Some("northstar-upload-inventory-v1"),
        "invalid S3 inventory header"
    );
    let mut entries = Vec::new();
    let mut previous = None;
    for line in lines {
        anyhow::ensure!(
            entries.len() < 1_000_000,
            "S3 inventory has too many objects"
        );
        let fields = line.split('\t').collect::<Vec<_>>();
        anyhow::ensure!(fields.len() == 5, "invalid S3 inventory row");
        let id = Uuid::parse_str(fields[0]).context("invalid inventory UUID")?;
        anyhow::ensure!(
            id.to_string() == fields[0] && previous.is_none_or(|last| last < id),
            "inventory UUIDs must be canonical, unique and sorted"
        );
        let attempt = fields[1]
            .strip_prefix(&format!("objects/{id}/"))
            .context("inventory key does not match its UUID")?;
        anyhow::ensure!(
            Uuid::parse_str(attempt)?.to_string() == attempt,
            "inventory attempt UUID is not canonical"
        );
        anyhow::ensure!(
            !fields[2].is_empty()
                && fields[2].len() <= 1024
                && !fields[2].chars().any(char::is_control),
            "invalid S3 version"
        );
        let size = fields[3].parse::<u64>().context("invalid S3 object size")?;
        anyhow::ensure!(
            size <= i64::MAX as u64,
            "S3 object size exceeds database range"
        );
        let digest = parse_digest(fields[4])?;
        entries.push(Entry {
            id,
            key: fields[1].to_owned(),
            version: fields[2].to_owned(),
            size,
            digest,
        });
        previous = Some(id);
    }
    Ok(entries)
}

fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn verify_namespace(expected: &str, settings: &super::S3UploadSettings) -> Result<()> {
    let _ = parse_digest(expected)?;
    let actual = upload_storage_namespace_id("s3", Path::new("."), Some(settings))?;
    anyhow::ensure!(
        digest_hex(&actual) == expected,
        "S3 namespace differs from signed backup inventory"
    );
    Ok(())
}

fn verify_object_dir(path: &Path) -> Result<()> {
    anyhow::ensure!(
        path.is_dir() && !path.is_symlink(),
        "S3 object staging directory must be real"
    );
    Ok(())
}

async fn export(store: &S3UploadStore, entries: &[Entry], directory: &Path) -> Result<()> {
    verify_object_dir(directory)?;
    for entry in entries {
        let path = directory.join(entry.id.to_string());
        anyhow::ensure!(
            !path.exists() && !path.is_symlink(),
            "S3 export target exists"
        );
        let mut source = store
            .get(&entry.key, Some(&entry.version))
            .await?
            .context("the exact S3 object version is missing")?;
        anyhow::ensure!(
            source.object_version.as_deref() == Some(entry.version.as_str())
                && source.size == entry.size,
            "S3 version or size differs from signed inventory"
        );
        let file = create_private(&path).context("could not create private S3 export object")?;
        let mut output = tokio::fs::File::from_std(file);
        let mut size = 0_u64;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = source.reader.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .context("S3 export size overflow")?;
            anyhow::ensure!(
                size <= entry.size,
                "S3 object grew during exact-version export"
            );
            digest.update(&buffer[..count]);
            output.write_all(&buffer[..count]).await?;
        }
        anyhow::ensure!(
            size == entry.size && digest.finalize().as_slice() == entry.digest,
            "S3 object bytes differ from inventory"
        );
        output.sync_all().await?;
    }
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

async fn verify(store: &S3UploadStore, entries: &[Entry]) -> Result<()> {
    for entry in entries {
        let attempt = entry
            .key
            .rsplit('/')
            .next()
            .context("S3 key has no attempt")?;
        let object = store
            .commit(
                &entry.id.to_string(),
                attempt,
                Some(&entry.version),
                entry.size,
                &entry.digest,
            )
            .await?;
        anyhow::ensure!(
            object.object_key == entry.key
                && object.object_version.as_deref() == Some(entry.version.as_str()),
            "S3 verification returned a different locator"
        );
    }
    Ok(())
}

fn read_attempts(path: &Path, entries: &[Entry]) -> Result<Vec<Uuid>> {
    anyhow::ensure!(
        path.is_file() && !path.is_symlink(),
        "restore attempt intent must be a regular file"
    );
    anyhow::ensure!(
        path.metadata()?.len() <= 128 * 1024 * 1024,
        "restore attempt intent exceeds the bounded input size"
    );
    let raw = std::fs::read_to_string(path)?;
    let mut lines = raw.lines();
    anyhow::ensure!(
        lines.next() == Some("northstar-s3-restore-attempts-v1"),
        "invalid restore attempt header"
    );
    let mut attempts = Vec::new();
    for entry in entries {
        let line = lines
            .next()
            .context("restore attempt intent is incomplete")?;
        let (id, attempt) = line
            .split_once('\t')
            .context("invalid restore attempt row")?;
        anyhow::ensure!(
            id == entry.id.to_string(),
            "restore attempt does not match inventory order"
        );
        let attempt = Uuid::parse_str(attempt)?;
        anyhow::ensure!(
            attempt.to_string() == line.split_once('\t').unwrap().1,
            "restore attempt is not canonical"
        );
        attempts.push(attempt);
    }
    anyhow::ensure!(
        lines.next().is_none(),
        "restore attempt intent has extra rows"
    );
    Ok(attempts)
}

async fn import(
    store: &S3UploadStore,
    entries: &[Entry],
    directory: &Path,
    attempts: &Path,
    result: &Path,
) -> Result<()> {
    verify_object_dir(directory)?;
    let attempts = read_attempts(attempts, entries)?;
    let mut output = create_private(result).context("restore result already exists")?;
    output.write_all(b"northstar-s3-restore-results-v1\n")?;
    output.sync_all()?;
    for (entry, attempt) in entries.iter().zip(attempts) {
        let path = directory.join(entry.id.to_string());
        anyhow::ensure!(
            path.is_file() && !path.is_symlink() && path.metadata()?.len() == entry.size,
            "restore object bytes are missing or changed"
        );
        let reader = tokio::fs::File::open(&path).await?;
        let new_key = format!("objects/{}/{}", entry.id, attempt);
        anyhow::ensure!(
            store.get(&new_key, None).await?.is_none(),
            "restore attempt key already exists; allocate a new intent instead of overwriting it"
        );
        let mut staged = store
            .put(
                &entry.id.to_string(),
                &attempt.to_string(),
                Box::new(reader),
                entry.size,
            )
            .await?;
        // The fsynced attempt intent owns cleanup from this point, even if
        // readback or the following database cutover fails.
        staged.durably_recorded();
        anyhow::ensure!(
            staged.sha256() == Some(&entry.digest),
            "restored S3 object digest differs from backup"
        );
        let version = staged
            .stage_version()
            .context("restore target bucket does not support exact versions")?
            .to_owned();
        let committed = store
            .commit(
                &entry.id.to_string(),
                &attempt.to_string(),
                Some(&version),
                entry.size,
                &entry.digest,
            )
            .await?;
        anyhow::ensure!(
            committed.object_version.as_deref() == Some(version.as_str()),
            "restored S3 version changed during readback"
        );
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            entry.id,
            committed.object_key,
            version,
            entry.size,
            digest_hex(&entry.digest)
        )?;
        output.sync_all()?;
    }
    Ok(())
}

pub(crate) async fn run_cli(args: &[String]) -> Result<()> {
    if args == ["namespace"] {
        let settings = super::s3_settings_from_env()?;
        println!(
            "{}",
            digest_hex(&upload_storage_namespace_id(
                "s3",
                Path::new("."),
                Some(&settings)
            )?)
        );
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("verify") && args.len() == 3 {
        let settings = super::s3_settings_from_env()?;
        verify_namespace(&args[2], &settings)?;
        let store = S3UploadStore::new(settings)?;
        return verify(&store, &read_inventory(Path::new(&args[1]))?).await;
    }
    anyhow::ensure!(args.len() >= 4, "usage: xmpp-server storage backup-object export|import INVENTORY OBJECT_DIR NAMESPACE_SHA256 [ATTEMPTS RESULTS]");
    let settings = super::s3_settings_from_env()?;
    verify_namespace(&args[3], &settings)?;
    let store = S3UploadStore::new(settings)?;
    let entries = read_inventory(Path::new(&args[1]))?;
    match args[0].as_str() {
        "export" if args.len() == 4 => export(&store, &entries, Path::new(&args[2])).await,
        "import" if args.len() == 6 => import(&store, &entries, Path::new(&args[2]), Path::new(&args[4]), Path::new(&args[5])).await,
        _ => anyhow::bail!("usage: xmpp-server storage backup-object export|import INVENTORY OBJECT_DIR NAMESPACE_SHA256 [ATTEMPTS RESULTS]"),
    }
}
