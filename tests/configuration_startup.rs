//! Exercise the configuration boundary through the shipped executable, without
//! database credentials or network services. Each child has an isolated cwd and
//! environment, so these tests never mutate the Cargo test process environment.

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct StartupFixture(PathBuf);

impl StartupFixture {
    fn malformed() -> Self {
        let path = std::env::temp_dir().join(format!(
            "northstar-configuration-startup-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&path).unwrap();
        fs::write(
            path.join(".env"),
            b"SERVER_NAME=private-value unquoted\nDATABASE_URL=private-database-url\n",
        )
        .unwrap();
        Self(path)
    }

    fn run(&self, arguments: &[&str], disable_dotenv: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rust-xmpp-server"));
        command
            .args(arguments)
            .env_clear()
            .env("XMPP_DOMAIN", "localhost")
            .current_dir(&self.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if disable_dotenv {
            command.env("NORTHSTAR_DISABLE_DOTENV", "true");
        }
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("configuration-only command did not exit: {arguments:?}");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for StartupFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn failure_diagnostic(output: Output) -> String {
    assert!(
        !output.status.success(),
        "configuration failure must exit nonzero"
    );
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!diagnostic.contains("private-value"), "{diagnostic}");
    assert!(!diagnostic.contains("private-database-url"), "{diagnostic}");
    diagnostic
}

#[test]
fn malformed_dotenv_fails_before_server_or_migrator_configuration() {
    let fixture = StartupFixture::malformed();
    for arguments in [
        &[][..],
        &["serve", "core"],
        &["serve", "standalone"],
        &["migrate"],
    ] {
        let diagnostic = failure_diagnostic(fixture.run(arguments, false));
        assert!(
            diagnostic.contains("could not parse .env configuration"),
            "{arguments:?}: {diagnostic}"
        );
        assert!(!diagnostic.contains("DATABASE_URL"), "{diagnostic}");
    }
}

#[test]
fn explicit_dotenv_disable_skips_even_a_malformed_file() {
    let diagnostic = failure_diagnostic(StartupFixture::malformed().run(&["migrate"], true));
    assert!(
        diagnostic.contains("set MIGRATOR_DATABASE_URL_FILE"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains(".env configuration"), "{diagnostic}");
}

#[test]
fn maintenance_never_loads_the_core_dotenv_file() {
    let diagnostic =
        failure_diagnostic(StartupFixture::malformed().run(&["serve", "maintenance"], false));
    assert!(
        diagnostic.contains("maintenance requires DATABASE_URL_FILE or DATABASE_URL"),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains(".env configuration"), "{diagnostic}");
}

#[test]
fn version_and_help_do_not_require_valid_dotenv() {
    let fixture = StartupFixture::malformed();
    for argument in ["--version", "--help"] {
        let output = fixture.run(&[argument], false);
        assert!(output.status.success(), "{argument}: {output:?}");
    }
}
