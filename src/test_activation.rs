//! Test-only listener activation boundary.
//!
//! It is inert unless configuration explicitly enables it for a loopback,
//! reserved-domain deployment. Production startup never consumes inherited
//! handles or emits fixture control files.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::Path,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::config::Config;

#[derive(Serialize)]
struct ReadinessRecord<'a> {
    version: u8,
    instance_nonce: &'a str,
    pid: u32,
    listeners: &'a BTreeMap<String, SocketAddr>,
}

pub(crate) fn publish_if_enabled(
    config: &Config,
    listeners: &BTreeMap<String, SocketAddr>,
    pid: u32,
) -> Result<()> {
    if !config.test_listener_activation {
        return Ok(());
    }
    let destination = config
        .test_readiness_file
        .as_deref()
        .context("test activation was enabled without a readiness destination")?;
    let nonce = config
        .test_readiness_nonce
        .as_deref()
        .context("test activation was enabled without a readiness nonce")?;
    publish(destination, nonce, pid, listeners)?;
    tracing::info!(
        readiness_file = %destination.display(),
        listener_count = listeners.len(),
        "published nonce-bound test readiness record"
    );
    Ok(())
}

fn publish(
    destination: &Path,
    nonce: &str,
    pid: u32,
    listeners: &BTreeMap<String, SocketAddr>,
) -> Result<()> {
    if destination.exists() {
        bail!(
            "refusing to overwrite an existing test readiness record: {}",
            destination.display()
        );
    }
    let parent = destination
        .parent()
        .context("test readiness destination must have a parent directory")?;
    if !parent.is_dir() {
        bail!(
            "test readiness parent directory does not exist: {}",
            parent.display()
        );
    }
    let payload = serde_json::to_vec(&ReadinessRecord {
        version: 1,
        instance_nonce: nonce,
        pid,
        listeners,
    })
    .context("could not serialize test readiness record")?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("readiness.json");
    let temporary = destination.with_file_name(format!(".{name}.{pid}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| {
            format!(
                "could not create readiness staging file {}",
                temporary.display()
            )
        })?;
    let result = (|| -> Result<()> {
        file.write_all(&payload)
            .context("could not write readiness staging file")?;
        file.write_all(b"\n")
            .context("could not terminate readiness staging file")?;
        file.sync_all()
            .context("could not sync readiness staging file")?;
        fs::rename(&temporary, destination).with_context(|| {
            format!(
                "could not atomically publish test readiness record {}",
                destination.display()
            )
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::publish;
    use std::{collections::BTreeMap, fs, net::SocketAddr};

    #[test]
    fn readiness_publication_is_atomic_and_refuses_overwrite() {
        let directory = std::env::temp_dir().join("northstar-test-activation-unit");
        fs::create_dir_all(&directory).unwrap();
        let destination = directory.join("ready.json");
        let _ = fs::remove_file(&destination);
        let listeners = BTreeMap::from([(
            "http".to_owned(),
            "127.0.0.1:40123".parse::<SocketAddr>().unwrap(),
        )]);
        publish(&destination, "0123456789abcdef", 42, &listeners).unwrap();
        let body = fs::read_to_string(&destination).unwrap();
        assert!(body.contains("\"instance_nonce\":\"0123456789abcdef\""));
        assert!(publish(&destination, "0123456789abcdef", 42, &listeners).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
