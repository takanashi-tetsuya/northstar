//! Optional development environment input, before any mode-specific config.
//!
//! Main decides which process modes may read dotenv. Keep parsing failures at
//! this boundary rather than letting a partly populated environment fail later
//! as an apparently missing database credential.

use anyhow::Result;
use std::{io::ErrorKind, path::PathBuf};

/// Preserve dotenvy's parent-directory search and existing-variable precedence.
/// A missing file is normal for deployments configured entirely by environment;
/// every other error must stop startup before the environment is consumed.
pub(crate) fn load_dotenv() -> Result<()> {
    check_dotenv_result(dotenvy::dotenv())
}

fn check_dotenv_result(result: dotenvy::Result<PathBuf>) -> Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(dotenvy::Error::Io(error)) if error.kind() == ErrorKind::NotFound => Ok(()),
        // Do not attach the dotenvy error as a source: both Display and Debug
        // include the offending line, which can contain passwords or tokens.
        Err(dotenvy::Error::LineParse(_, _)) => anyhow::bail!(
            "could not parse .env configuration: invalid syntax; quote values containing spaces and check assignments (setting values are redacted)"
        ),
        Err(dotenvy::Error::Io(error)) => anyhow::bail!(
            "could not read .env configuration: {}",
            error.kind()
        ),
        // EnvVar errors can also contain a non-Unicode secret value. The
        // dependency is non-exhaustive, so unknown errors are redacted too.
        Err(_) => anyhow::bail!(
            "could not load .env configuration (setting values are redacted)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{check_dotenv_result, load_dotenv};
    use std::{collections::HashMap, fs, io, path::PathBuf, process::Command};

    const DEVELOPMENT_ENV: &str = include_str!("../../.env.development.example");
    const PROBE_ENV: &str = "NORTHSTAR_DOTENV_TEST_PROBE";

    #[test]
    fn missing_dotenv_is_optional_but_read_failures_are_fatal() {
        assert!(check_dotenv_result(Ok(PathBuf::from(".env"))).is_ok());
        assert!(
            check_dotenv_result(Err(dotenvy::Error::Io(io::ErrorKind::NotFound.into()))).is_ok()
        );
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::InvalidData] {
            let error = check_dotenv_result(Err(dotenvy::Error::Io(io::Error::new(
                kind,
                "secret-bearing I/O detail",
            ))))
            .unwrap_err();
            let diagnostic = format!("{error:?}");
            assert!(diagnostic.contains("could not read .env configuration"));
            assert!(!diagnostic.contains("secret-bearing"));
            assert_eq!(error.chain().count(), 1);
        }
    }

    #[test]
    fn dotenv_syntax_errors_never_disclose_the_setting_or_value() {
        let parse_error = dotenvy::from_read_iter(
            b"BOOTSTRAP_ADMIN_PASSWORD=private-value unquoted\n".as_slice(),
        )
        .next()
        .unwrap()
        .unwrap_err();
        let error = check_dotenv_result(Err(parse_error)).unwrap_err();
        for diagnostic in [
            format!("{error}"),
            format!("{error:?}"),
            format!("{error:#}"),
        ] {
            assert!(diagnostic.contains("could not parse .env configuration"));
            assert!(!diagnostic.contains("BOOTSTRAP_ADMIN_PASSWORD"));
            assert!(!diagnostic.contains("private-value"));
        }
        assert_eq!(error.chain().count(), 1);
    }

    #[test]
    fn dotenv_environment_errors_do_not_expose_values() {
        let error = check_dotenv_result(Err(dotenvy::Error::EnvVar(
            std::env::VarError::NotUnicode("private-value".into()),
        )))
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("could not load .env configuration"));
        assert!(!format!("{error:?}").contains("private-value"));
        assert_eq!(error.chain().count(), 1);
    }

    #[test]
    fn development_example_parses_through_both_database_settings() {
        let values = dotenvy::from_read_iter(DEVELOPMENT_ENV.as_bytes())
            .collect::<dotenvy::Result<HashMap<_, _>>>()
            .expect("the distributed development example must be valid dotenv");
        assert_eq!(values["SERVER_NAME"], "Northstar Development");
        assert!(!values["DATABASE_URL"].is_empty());
        assert_eq!(values["DATABASE_URL"], values["MIGRATOR_DATABASE_URL"]);
        assert_eq!(values["RUST_LOG"], "info");
    }

    struct DotenvFixture(PathBuf);

    impl DotenvFixture {
        fn new(contents: &[u8]) -> Self {
            let path = std::env::temp_dir().join(format!(
                "northstar-dotenv-{}",
                uuid::Uuid::new_v4().simple()
            ));
            fs::create_dir(&path).unwrap();
            fs::write(path.join(".env"), contents).unwrap();
            Self(path)
        }

        fn probe(&self, case: &str, search_parent: bool) {
            let cwd = if search_parent {
                let child = self.0.join("child");
                fs::create_dir(&child).unwrap();
                child
            } else {
                self.0.clone()
            };
            // Environment mutation and current-directory changes must never
            // race the rest of the test suite in this process.
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "config::environment::tests::dotenv_subprocess_probe",
                    "--nocapture",
                ])
                .env_clear()
                .env(PROBE_ENV, case)
                .env("DOTENV_TEST_EXISTING", "from-process")
                .current_dir(cwd);
            // Windows uses this for OS facilities, even with an absolute exe.
            if let Some(system_root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", system_root);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "dotenv probe failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("DOTENV_PROBE_PASSED"));
        }
    }

    impl Drop for DotenvFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_dotenv_file_is_optional() {
        let fixture = DotenvFixture::new(b"");
        let path = fixture.0.join(".env");
        fs::remove_file(&path).unwrap();
        // Use an explicit path here so the missing-file regression cannot load
        // an unrelated .env in a parent of the system temporary directory.
        assert!(check_dotenv_result(dotenvy::from_path(&path).map(|()| path)).is_ok());
    }

    #[test]
    fn dotenv_loads_development_example_from_current_directory() {
        DotenvFixture::new(DEVELOPMENT_ENV.as_bytes()).probe("development", false);
    }

    #[test]
    fn dotenv_preserves_parent_search_process_precedence_and_first_declaration() {
        DotenvFixture::new(
            b"DOTENV_TEST_EXISTING=from-file\nDOTENV_TEST_NEW=first\nDOTENV_TEST_NEW=second\nDOTENV_TEST_EXPANDED=${DOTENV_TEST_EXISTING}\n",
        )
        .probe("precedence", true);
    }

    #[test]
    fn dotenv_rejects_malformed_input_before_consuming_configuration() {
        DotenvFixture::new(
            b"SERVER_NAME=Northstar Development\nDATABASE_URL=private-database-url\n",
        )
        .probe("malformed", false);
    }

    #[test]
    fn dotenv_rejects_unreadable_utf8_input() {
        DotenvFixture::new(b"SERVER_NAME=\xff\n").probe("invalid-utf8", false);
    }

    #[test]
    fn dotenv_subprocess_probe() {
        let Ok(case) = std::env::var(PROBE_ENV) else {
            return;
        };
        match case.as_str() {
            "development" => {
                load_dotenv().unwrap();
                assert_eq!(
                    std::env::var("SERVER_NAME").unwrap(),
                    "Northstar Development"
                );
                assert_eq!(
                    std::env::var("DATABASE_URL").unwrap(),
                    std::env::var("MIGRATOR_DATABASE_URL").unwrap()
                );
            }
            "precedence" => {
                load_dotenv().unwrap();
                assert_eq!(
                    std::env::var("DOTENV_TEST_EXISTING").unwrap(),
                    "from-process"
                );
                assert_eq!(std::env::var("DOTENV_TEST_NEW").unwrap(), "first");
                assert_eq!(
                    std::env::var("DOTENV_TEST_EXPANDED").unwrap(),
                    "from-process"
                );
            }
            "malformed" => {
                let error = load_dotenv().unwrap_err();
                assert!(error
                    .to_string()
                    .contains("could not parse .env configuration"));
                assert!(!format!("{error:?}").contains("Northstar Development"));
                assert!(std::env::var_os("DATABASE_URL").is_none());
            }
            "invalid-utf8" => {
                let error = load_dotenv().unwrap_err();
                assert!(error
                    .to_string()
                    .contains("could not read .env configuration"));
            }
            _ => panic!("unknown dotenv test probe"),
        }
        println!("DOTENV_PROBE_PASSED");
    }
}
