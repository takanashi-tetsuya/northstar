use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use anyhow::{Context, Result};

/// A managed subprocess with isolated temporary storage and monitored lifecycle.
pub struct ManagedProcess {
    name: String,
    child: Option<Child>,
    temp_dir: PathBuf,
    log_path: PathBuf,
}

impl ManagedProcess {
    pub fn spawn(name: impl Into<String>, mut command: Command) -> Result<Self> {
        let name = name.into();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("northstar-test-{name}-{nonce}"));
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("failed to create temporary working directory at {}", temp_dir.display()))?;

        let log_path = temp_dir.join(format!("{name}.log"));
        let log_file = std::fs::File::create(&log_path)
            .context("failed to create process log file")?;
        let log_file_err = log_file.try_clone()
            .context("failed to clone log file descriptor")?;

        command.stdout(Stdio::from(log_file));
        command.stderr(Stdio::from(log_file_err));
        command.current_dir(&temp_dir);

        let child = command.spawn()
            .with_context(|| format!("failed to spawn process {name}"))?;

        Ok(Self {
            name,
            child: Some(child),
            temp_dir,
            log_path,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    pub fn temp_path(&self) -> &Path {
        &self.temp_dir
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn read_log(&self) -> Result<String> {
        std::fs::read_to_string(&self.log_path)
            .with_context(|| format!("failed to read log at {}", self.log_path.display()))
    }

    /// Terminate process gracefully, killing if uncooperative after `timeout`.
    pub fn stop(&mut self, timeout: Duration) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_status)) => return Ok(()),
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        let _ = self.stop(Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}
