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
    diagnostics_retained: bool,
}

impl ManagedProcess {
    pub fn spawn(name: impl Into<String>, mut command: Command) -> Result<Self> {
        let name = name.into();
        let path_name = canonical_process_name(&name);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "northstar-test-{path_name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&temp_dir).with_context(|| {
            format!(
                "failed to create temporary working directory at {}",
                temp_dir.display()
            )
        })?;
        restrict_directory(&temp_dir)?;

        let log_path = temp_dir.join(format!("{path_name}.log"));
        let log_file =
            std::fs::File::create(&log_path).context("failed to create process log file")?;
        restrict_file(&log_path)?;
        let log_file_err = log_file
            .try_clone()
            .context("failed to clone log file descriptor")?;

        command.stdout(Stdio::from(log_file));
        command.stderr(Stdio::from(log_file_err));
        command.current_dir(&temp_dir);

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            // `setpgid` is async-signal-safe and runs in the child before it
            // executes the requested program. The dedicated group lets test
            // teardown terminate grandchildren as well as the direct child.
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&temp_dir);
                return Err(error).with_context(|| format!("failed to spawn process {name}"));
            }
        };

        Ok(Self {
            name,
            child: Some(child),
            temp_dir,
            log_path,
            diagnostics_retained: false,
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

    /// Preserve the isolated process transcript after a caller detects a
    /// failure outside of this type (for example, a protocol assertion).
    pub fn retain_diagnostics(&mut self, reason: &str) -> Result<()> {
        self.diagnostics_retained = true;
        let marker = self.temp_dir.join("RETAINED_DIAGNOSTICS.txt");
        let pid = self
            .id()
            .map_or_else(|| "exited".to_owned(), |pid| pid.to_string());
        std::fs::write(
            &marker,
            format!(
                "Northstar test-process diagnostics retained\nname={}\npid={}\nreason={}\nlog={}\n",
                self.name,
                pid,
                reason.replace(['\r', '\n'], " "),
                self.log_path.display(),
            ),
        )
        .with_context(|| format!("failed to write diagnostics marker at {}", marker.display()))?;
        restrict_file(&marker)?;
        Ok(())
    }

    pub fn diagnostics_retained(&self) -> bool {
        self.diagnostics_retained
    }

    /// Terminate process gracefully, first via SIGTERM/terminate, then SIGKILL.
    ///
    /// On Unix the process receives SIGTERM and we wait up to `timeout`.
    /// On timeout (or on unsupported platforms), we fall back to SIGKILL.
    pub fn stop(&mut self, timeout: Duration) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            let pid = child.id();
            if let Err(error) = self.request_stop(pid) {
                tracing::warn!(name = %self.name, pid, ?error, "failed to request graceful stop");
            }

            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_status)) => return Ok(()),
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            tracing::warn!(
                                name = %self.name,
                                pid,
                                timeout_secs = timeout.as_secs_f64(),
                                "graceful stop timed out; forcing kill"
                            );
                            let _ = self.force_stop(pid);
                            let _ = child.wait();
                            self.retain_diagnostics(
                                "graceful process-group termination timed out",
                            )?;
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

    #[cfg(unix)]
    fn request_stop(&self, pid: u32) -> Result<()> {
        let status = Command::new("kill")
            .args(["-TERM", "--", &format!("-{pid}")])
            .status()
            .context("failed to invoke `kill` to request process-group termination")?;
        if !status.success() {
            anyhow::bail!("`kill -TERM -- -{pid}` failed with status {status}");
        }
        Ok(())
    }

    #[cfg(unix)]
    fn force_stop(&self, pid: u32) -> Result<()> {
        let status = Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .status()
            .context("failed to invoke `kill` to force process-group termination")?;
        if !status.success() {
            anyhow::bail!("`kill -KILL -- -{pid}` failed with status {status}");
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn request_stop(&self, pid: u32) -> Result<()> {
        let mut command = Command::new("taskkill");
        command.args(["/PID", &pid.to_string(), "/T"]);
        let status = command
            .status()
            .context("failed to invoke `taskkill` to request termination")?;
        if !status.success() {
            anyhow::bail!("`taskkill /PID {pid} /T` failed with status {status}");
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn force_stop(&self, pid: u32) -> Result<()> {
        let mut command = Command::new("taskkill");
        command.args(["/PID", &pid.to_string(), "/T", "/F"]);
        let status = command
            .status()
            .context("failed to invoke `taskkill` to force termination")?;
        if !status.success() {
            anyhow::bail!("`taskkill /PID {pid} /T /F` failed with status {status}");
        }
        Ok(())
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        if let Err(error) = self.stop(Duration::from_millis(500)) {
            let _ = self.retain_diagnostics(&format!("drop-time termination failed: {error:#}"));
        }
        if !self.diagnostics_retained {
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }
}

fn canonical_process_name(name: &str) -> String {
    let canonical = name
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => character,
            _ => '_',
        })
        .collect::<String>();
    if canonical.is_empty() {
        "process".to_owned()
    } else {
        canonical
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to restrict test directory {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict test artifact {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::ManagedProcess;
    use std::{
        fs,
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn stop_reaps_the_entire_child_process_group_and_retains_transcript() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "sleep 60 & child=$!; printf '%s' \"$child\" > child.pid; wait \"$child\"",
        ]);
        let mut process = ManagedProcess::spawn("process-group-test", command).unwrap();
        let child_pid_path = process.temp_path().join("child.pid");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !child_pid_path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let child_pid = fs::read_to_string(&child_pid_path)
            .unwrap()
            .parse::<i32>()
            .unwrap();

        process.stop(Duration::from_secs(1)).unwrap();
        process
            .retain_diagnostics("assertion path requested transcript preservation")
            .unwrap();
        assert!(process.diagnostics_retained());
        assert!(process
            .temp_path()
            .join("RETAINED_DIAGNOSTICS.txt")
            .exists());

        let wait_deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::kill(child_pid, 0) == 0 } && Instant::now() < wait_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_ne!(
            unsafe { libc::kill(child_pid, 0) },
            0,
            "grandchild survived group teardown"
        );

        let path = process.temp_path().to_owned();
        drop(process);
        assert!(path.exists(), "failure diagnostics were deleted");
        fs::remove_dir_all(path).unwrap();
    }
}
