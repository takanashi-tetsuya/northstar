//! Protected secret file reading and secret file permission and metadata checks.

use anyhow::{Context, Result};
use std::{fs, io::Read};
use zeroize::Zeroize;

pub fn read_secret_file(path: &std::path::Path, variable: &str) -> Result<String> {
    read_protected_utf8_file(path, variable, 64 * 1024, true)
}

pub fn read_protected_utf8_file(
    path: &std::path::Path,
    variable: &str,
    max_bytes: u64,
    trim_line_ending: bool,
) -> Result<String> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect secret file configured by {variable}"))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > max_bytes
    {
        anyhow::bail!(
            "secret file configured by {variable} must be a non-symlink regular file of 1..={max_bytes} bytes"
        );
    }
    validate_secret_permissions(&before, variable)?;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot open secret file configured by {variable}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect opened secret file configured by {variable}"))?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > max_bytes {
        anyhow::bail!(
            "secret file configured by {variable} must be a non-symlink regular file of 1..={max_bytes} bytes"
        );
    }
    validate_secret_metadata(&before, &opened, variable)?;
    validate_secret_permissions(&opened, variable)?;

    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read secret file configured by {variable}"))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        anyhow::bail!("secret file configured by {variable} is empty or invalid");
    }

    let opened_after = file.metadata().with_context(|| {
        format!("cannot re-inspect opened secret file configured by {variable}")
    })?;
    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("cannot re-inspect secret file configured by {variable}"))?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || opened.len() != opened_after.len()
        || opened.modified().ok() != opened_after.modified().ok()
        || opened.len() != bytes.len() as u64
    {
        anyhow::bail!("secret file configured by {variable} changed while it was being read");
    }
    validate_secret_metadata(&opened, &opened_after, variable)?;
    validate_secret_metadata(&opened, &path_after, variable)?;
    validate_secret_permissions(&opened_after, variable)?;
    validate_secret_permissions(&path_after, variable)?;

    let mut value = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            anyhow::bail!("secret file configured by {variable} is not valid UTF-8");
        }
    };
    let value = if trim_line_ending {
        let trimmed = value.trim_end_matches(['\r', '\n']).to_owned();
        value.zeroize();
        trimmed
    } else {
        value
    };
    if value.is_empty() || value.contains('\0') {
        anyhow::bail!("secret file configured by {variable} is empty or invalid");
    }
    Ok(value)
}

#[cfg(unix)]
fn validate_secret_permissions(metadata: &fs::Metadata, variable: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o400 && mode != 0o600 {
        anyhow::bail!("secret file configured by {variable} must have permissions 0400 or 0600");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_permissions(_metadata: &fs::Metadata, _variable: &str) -> Result<()> {
    // Linux production preflight is authoritative. Windows ACLs do not have a
    // sound one-to-one mapping to Unix owner-only permission bits.
    Ok(())
}

#[cfg(unix)]
fn validate_secret_metadata(
    before: &fs::Metadata,
    after: &fs::Metadata,
    variable: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        anyhow::bail!("secret file configured by {variable} changed while it was being read");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_metadata(
    before: &fs::Metadata,
    after: &fs::Metadata,
    variable: &str,
) -> Result<()> {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        anyhow::bail!("secret file configured by {variable} changed while it was being read");
    }
    Ok(())
}
