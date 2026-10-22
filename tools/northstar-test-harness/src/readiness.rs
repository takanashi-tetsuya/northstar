//! Structured, nonce-bound readiness records for child-owned test listeners.
//!
//! A numeric port returned by a helper is not a reservation: another process
//! can bind it after the helper exits. Fixtures instead let the child bind
//! loopback `:0`, then publish actual addresses only after every listener is
//! ready. The parent verifies a one-time nonce and child PID before use.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const READINESS_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessRecord {
    pub version: u8,
    pub instance_nonce: String,
    pub pid: u32,
    /// Purpose-to-address mapping. A BTreeMap makes emitted evidence stable.
    pub listeners: BTreeMap<String, SocketAddr>,
}

impl ReadinessRecord {
    pub fn new(
        instance_nonce: impl Into<String>,
        pid: u32,
        listeners: BTreeMap<String, SocketAddr>,
    ) -> Result<Self> {
        let record = Self {
            version: READINESS_VERSION,
            instance_nonce: instance_nonce.into(),
            pid,
            listeners,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != READINESS_VERSION {
            bail!("unsupported readiness record version {}", self.version);
        }
        if !valid_nonce(&self.instance_nonce) {
            bail!("readiness nonce must be 16-128 lowercase hexadecimal characters");
        }
        if self.pid == 0 {
            bail!("readiness record PID must be non-zero");
        }
        if self.listeners.is_empty() {
            bail!("readiness record must contain at least one listener");
        }
        for (purpose, address) in &self.listeners {
            if !valid_purpose(purpose) {
                bail!("readiness listener purpose is not canonical: {purpose:?}");
            }
            if address.port() == 0 {
                bail!("readiness listener {purpose:?} has an unresolved port 0");
            }
        }
        Ok(())
    }

    /// Atomically publish the fully validated record. Callers must create the
    /// parent directory themselves so a typo cannot create a new tree.
    pub fn write_atomic(&self, destination: &Path) -> Result<()> {
        self.validate()?;
        let parent = destination
            .parent()
            .context("readiness destination must have a parent directory")?;
        if !parent.is_dir() {
            bail!(
                "readiness parent directory does not exist: {}",
                parent.display()
            );
        }
        let payload = serde_json::to_vec(self).context("could not serialize readiness record")?;
        let temporary = temporary_path(destination, self.pid);
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
        let write_result = (|| -> Result<()> {
            file.write_all(&payload)
                .context("could not write readiness staging file")?;
            file.write_all(b"\n")
                .context("could not terminate readiness staging file")?;
            file.sync_all()
                .context("could not sync readiness staging file")?;
            fs::rename(&temporary, destination).with_context(|| {
                format!(
                    "could not atomically publish readiness record {}",
                    destination.display()
                )
            })?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    pub fn read_verified(path: &Path, expected_nonce: &str, expected_pid: u32) -> Result<Self> {
        if !valid_nonce(expected_nonce) {
            bail!("expected readiness nonce is not canonical");
        }
        let bytes = fs::read(path)
            .with_context(|| format!("could not read readiness record {}", path.display()))?;
        let record: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("could not parse readiness record {}", path.display()))?;
        record.validate()?;
        if record.instance_nonce != expected_nonce {
            bail!("readiness nonce did not match the parent-issued nonce");
        }
        if record.pid != expected_pid {
            bail!(
                "readiness PID {} did not match the spawned child PID {expected_pid}",
                record.pid
            );
        }
        Ok(record)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReadinessTranscript {
    phases: Vec<String>,
}

impl ReadinessTranscript {
    pub fn phase(&mut self, name: impl AsRef<str>) {
        self.phases.push(name.as_ref().to_owned());
    }

    pub fn phases(&self) -> &[String] {
        &self.phases
    }

    pub fn wait_for_record(
        &mut self,
        path: &Path,
        expected_nonce: &str,
        expected_pid: u32,
        timeout: Duration,
    ) -> Result<ReadinessRecord> {
        self.phase("readiness-wait-started");
        let started = Instant::now();
        let mut latest_error = None;
        while started.elapsed() < timeout {
            match ReadinessRecord::read_verified(path, expected_nonce, expected_pid) {
                Ok(record) => {
                    self.phase("readiness-verified");
                    return Ok(record);
                }
                Err(error) if path.exists() => latest_error = Some(error.to_string()),
                Err(_) => {}
            }
            thread::sleep(Duration::from_millis(25));
        }
        self.phase("readiness-timed-out");
        let detail = latest_error.unwrap_or_else(|| "record was never published".to_owned());
        bail!(
            "timed out after {} ms waiting for nonce-bound readiness: {detail}",
            timeout.as_millis()
        );
    }
}

fn valid_nonce(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_purpose(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn temporary_path(destination: &Path, pid: u32) -> PathBuf {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("readiness.json");
    destination.with_file_name(format!(".{name}.{pid}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::{ReadinessRecord, ReadinessTranscript};
    use std::{collections::BTreeMap, fs, net::SocketAddr, time::Duration};

    fn record(nonce: &str, pid: u32) -> ReadinessRecord {
        ReadinessRecord::new(
            nonce,
            pid,
            BTreeMap::from([(
                "http".to_owned(),
                "127.0.0.1:40123".parse::<SocketAddr>().unwrap(),
            )]),
        )
        .unwrap()
    }

    #[test]
    fn atomic_record_is_nonce_and_pid_bound() {
        let nonce = "0123456789abcdef";
        let directory = std::env::temp_dir().join(format!("northstar-readiness-{nonce}"));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("ready.json");
        record(nonce, 42).write_atomic(&path).unwrap();
        assert_eq!(
            ReadinessRecord::read_verified(&path, nonce, 42).unwrap(),
            record(nonce, 42)
        );
        assert!(ReadinessRecord::read_verified(&path, nonce, 43).is_err());
        assert!(ReadinessRecord::read_verified(&path, "fedcba9876543210", 42).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn readiness_transcript_retains_timeout_phase() {
        let nonce = "0123456789abcdef";
        let path = std::env::temp_dir().join("northstar-missing-readiness.json");
        let _ = fs::remove_file(&path);
        let mut transcript = ReadinessTranscript::default();
        assert!(transcript
            .wait_for_record(&path, nonce, 42, Duration::from_millis(1))
            .is_err());
        assert_eq!(
            transcript.phases(),
            ["readiness-wait-started", "readiness-timed-out"]
        );
    }
}
