//! Shared PostgreSQL primitives for Northstar services.
//!
//! This crate deliberately does not run migrations.  A deployment's migrator
//! identity applies migrations before a service starts; runtime identities use
//! [`verify_migrations`] to attest that the expected ledger is present.

use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

/// Connection settings that every service should use instead of copying pool
/// construction and session hardening logic.
#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub url: String,
    pub application_name: String,
    pub ssl_mode: SslMode,
    pub min_connections: u32,
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
    pub statement_timeout: Duration,
    pub lock_timeout: Duration,
    pub idle_in_transaction_timeout: Duration,
}

impl PostgresConfig {
    pub fn new(url: impl Into<String>, application_name: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            application_name: application_name.into(),
            ssl_mode: SslMode::VerifyFull,
            min_connections: 0,
            max_connections: 16,
            acquire_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(600)),
            max_lifetime: Some(Duration::from_secs(1800)),
            statement_timeout: Duration::from_secs(30),
            lock_timeout: Duration::from_secs(5),
            idle_in_transaction_timeout: Duration::from_secs(60),
        }
    }

    pub fn validate(&self) -> Result<(), PostgresConfigError> {
        if self.url.trim().is_empty() {
            return Err(PostgresConfigError::MissingUrl);
        }
        if self.application_name.trim().is_empty() || self.application_name.len() > 63 {
            return Err(PostgresConfigError::InvalidApplicationName);
        }
        if self.min_connections > self.max_connections || self.max_connections == 0 {
            return Err(PostgresConfigError::InvalidPoolBounds);
        }
        for (name, duration) in [
            ("acquire_timeout", self.acquire_timeout),
            ("connect_timeout", self.connect_timeout),
            ("statement_timeout", self.statement_timeout),
            ("lock_timeout", self.lock_timeout),
            (
                "idle_in_transaction_timeout",
                self.idle_in_transaction_timeout,
            ),
        ] {
            if duration.is_zero() {
                return Err(PostgresConfigError::ZeroTimeout(name));
            }
        }
        if self.idle_timeout.is_some_and(|duration| duration.is_zero())
            || self.max_lifetime.is_some_and(|duration| duration.is_zero())
        {
            return Err(PostgresConfigError::ZeroPoolLifetime);
        }
        Ok(())
    }

    /// Build a pool with session-level safety settings.  No migration is run.
    pub async fn connect(&self) -> Result<PgPool, PostgresError> {
        self.validate()?;
        let mut options = PgConnectOptions::from_str(&self.url)
            .map_err(|source| PostgresError::InvalidUrl(source.to_string()))?;
        options = options
            .application_name(&self.application_name)
            .ssl_mode(self.ssl_mode.into());
        let statement_timeout = self.statement_timeout.as_millis();
        let lock_timeout = self.lock_timeout.as_millis();
        let idle_timeout = self.idle_in_transaction_timeout.as_millis();

        let connect = PgPoolOptions::new()
            .min_connections(self.min_connections)
            .max_connections(self.max_connections)
            .acquire_timeout(self.acquire_timeout)
            .idle_timeout(self.idle_timeout)
            .max_lifetime(self.max_lifetime)
            .after_connect(move |connection, _meta| {
                Box::pin(async move {
                    // SET LOCAL cannot be used in after_connect: these are
                    // connection defaults and every request may open a new tx.
                    sqlx::query(&format!(
                        "SET SESSION statement_timeout = '{}ms'",
                        statement_timeout
                    ))
                    .execute(&mut *connection)
                    .await?;
                    sqlx::query(&format!("SET SESSION lock_timeout = '{}ms'", lock_timeout))
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query(&format!(
                        "SET SESSION idle_in_transaction_session_timeout = '{}ms'",
                        idle_timeout
                    ))
                    .execute(&mut *connection)
                    .await?;
                    Ok(())
                })
            })
            .connect_with(options);
        let pool = tokio::time::timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| PostgresError::ConnectTimeout)??;
        Ok(pool)
    }
}

/// PostgreSQL TLS policy.  `VerifyFull` is the production default; weaker
/// modes must be selected explicitly by a development deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl From<SslMode> for PgSslMode {
    fn from(value: SslMode) -> Self {
        match value {
            SslMode::Disable => PgSslMode::Disable,
            SslMode::Prefer => PgSslMode::Prefer,
            SslMode::Require => PgSslMode::Require,
            SslMode::VerifyCa => PgSslMode::VerifyCa,
            SslMode::VerifyFull => PgSslMode::VerifyFull,
        }
    }
}

#[derive(Debug, Error)]
pub enum PostgresConfigError {
    #[error("DATABASE_URL is empty")]
    MissingUrl,
    #[error("application_name must be 1..=63 bytes")]
    InvalidApplicationName,
    #[error("pool bounds are invalid")]
    InvalidPoolBounds,
    #[error("{0} must be non-zero")]
    ZeroTimeout(&'static str),
    #[error("pool lifetime must be non-zero")]
    ZeroPoolLifetime,
}

#[derive(Debug, Error)]
pub enum PostgresError {
    #[error(transparent)]
    Config(#[from] PostgresConfigError),
    #[error("invalid PostgreSQL URL: {0}")]
    InvalidUrl(String),
    #[error("timed out while establishing the PostgreSQL pool")]
    ConnectTimeout,
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("migration ledger is not available")]
    MigrationTableMissing,
    #[error("migration {version} is not applied successfully")]
    MigrationNotApplied { version: i64 },
    #[error("migration ledger drift at version {version}")]
    MigrationDrift { version: i64 },
    #[error("database attestation failed: {0}")]
    Attestation(String),
}

/// Stable repository error categories.  SQLSTATE details remain available in
/// [`RepositoryError::sqlstate`] for structured logs without exposing query text.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RepositoryError {
    #[error("database unavailable")]
    Unavailable,
    #[error("database pool exhausted")]
    PoolExhausted,
    #[error("transaction serialization conflict")]
    SerializationConflict,
    #[error("transaction deadlock")]
    Deadlock,
    #[error("query timeout")]
    Timeout,
    #[error("unique constraint violation")]
    UniqueViolation,
    #[error("foreign key constraint violation")]
    ForeignKeyViolation,
    #[error("check constraint violation")]
    CheckViolation,
    #[error("permission denied")]
    PermissionDenied,
    #[error("database error ({sqlstate})")]
    Other { sqlstate: String },
}

impl RepositoryError {
    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            Self::Other { sqlstate } => Some(sqlstate),
            _ => None,
        }
    }
}

pub fn map_sqlx_error(error: &sqlx::Error) -> RepositoryError {
    match error {
        sqlx::Error::PoolTimedOut => RepositoryError::PoolExhausted,
        sqlx::Error::PoolClosed | sqlx::Error::Io(_) | sqlx::Error::Tls(_) => {
            RepositoryError::Unavailable
        }
        sqlx::Error::Database(db) => match db.code().as_deref() {
            Some("40001") => RepositoryError::SerializationConflict,
            Some("40P01") => RepositoryError::Deadlock,
            Some("57014") => RepositoryError::Timeout,
            Some("23505") => RepositoryError::UniqueViolation,
            Some("23503") => RepositoryError::ForeignKeyViolation,
            Some("23514") => RepositoryError::CheckViolation,
            Some("42501") => RepositoryError::PermissionDenied,
            Some(code) => RepositoryError::Other {
                sqlstate: code.to_string(),
            },
            None => RepositoryError::Unavailable,
        },
        _ => RepositoryError::Unavailable,
    }
}

/// Transaction options are explicit so callers choose their locking/isolation
/// semantics rather than having a helper silently change them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionOptions {
    pub isolation: IsolationLevel,
    pub read_only: bool,
    pub deferrable: bool,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        Self {
            isolation: IsolationLevel::ReadCommitted,
            read_only: false,
            deferrable: false,
        }
    }
}

pub async fn begin_transaction<'a>(
    pool: &'a PgPool,
    options: TransactionOptions,
) -> Result<Transaction<'a, Postgres>, PostgresError> {
    let mut tx = pool.begin().await?;
    let isolation = match options.isolation {
        IsolationLevel::ReadCommitted => "READ COMMITTED",
        IsolationLevel::RepeatableRead => "REPEATABLE READ",
        IsolationLevel::Serializable => "SERIALIZABLE",
    };
    let mode = if options.read_only {
        "READ ONLY"
    } else {
        "READ WRITE"
    };
    let deferrable = if options.deferrable {
        " DEFERRABLE"
    } else {
        ""
    };
    let statement = format!("SET TRANSACTION ISOLATION LEVEL {isolation} {mode}{deferrable}");
    sqlx::query(&statement).execute(&mut *tx).await?;
    Ok(tx)
}

/// Non-secret connection identity, suitable for an attestation log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionAttestation {
    pub current_user: String,
    pub session_user: String,
    pub database: String,
    pub schema: String,
    pub search_path: String,
}

#[derive(Debug, Clone, Default)]
pub struct AttestationPolicy {
    pub expected_role: Option<String>,
    pub expected_database: Option<String>,
    pub required_search_path: Option<String>,
}

pub async fn attest_connection(
    pool: &PgPool,
    policy: &AttestationPolicy,
) -> Result<ConnectionAttestation, PostgresError> {
    let row = sqlx::query(
        "SELECT current_user::text AS current_user,
                session_user::text AS session_user,
                current_database()::text AS database,
                current_schema()::text AS schema,
                current_setting('search_path')::text AS search_path",
    )
    .fetch_one(pool)
    .await?;
    let attestation = ConnectionAttestation {
        current_user: row.try_get("current_user")?,
        session_user: row.try_get("session_user")?,
        database: row.try_get("database")?,
        schema: row.try_get("schema")?,
        search_path: row.try_get("search_path")?,
    };
    if policy
        .expected_role
        .as_ref()
        .is_some_and(|role| role != &attestation.current_user)
    {
        return Err(PostgresError::Attestation("unexpected current_user".into()));
    }
    if policy
        .expected_database
        .as_ref()
        .is_some_and(|database| database != &attestation.database)
    {
        return Err(PostgresError::Attestation("unexpected database".into()));
    }
    if policy.required_search_path.as_ref().is_some_and(|path| {
        attestation
            .search_path
            .split(',')
            .map(str::trim)
            .all(|entry| entry != path)
    }) {
        return Err(PostgresError::Attestation(
            "required search_path missing".into(),
        ));
    }
    Ok(attestation)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedMigration {
    pub version: i64,
    pub description: String,
    pub checksum: Vec<u8>,
}

/// Verify SQLx's migration ledger without applying migrations.  The complete
/// expected ledger is supplied by the deployment build, preventing runtime
/// roles from silently accepting a drifted database.
pub async fn verify_migrations(
    pool: &PgPool,
    expected: &[ExpectedMigration],
) -> Result<(), PostgresError> {
    let rows = sqlx::query(
        "SELECT version, description, checksum, success
           FROM _sqlx_migrations
          ORDER BY version ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| match error {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("42P01") => {
            PostgresError::MigrationTableMissing
        }
        other => PostgresError::Sqlx(other),
    })?;
    if rows.len() != expected.len() {
        return Err(PostgresError::MigrationDrift { version: -1 });
    }
    for (row, wanted) in rows.iter().zip(expected) {
        let version: i64 = row.try_get("version")?;
        let description: String = row.try_get("description")?;
        let checksum: Vec<u8> = row.try_get("checksum")?;
        let success: bool = row.try_get("success")?;
        if version != wanted.version {
            return Err(PostgresError::MigrationDrift { version });
        }
        if !success {
            return Err(PostgresError::MigrationNotApplied { version });
        }
        if description != wanted.description || checksum != wanted.checksum {
            return Err(PostgresError::MigrationDrift { version });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_defaults_require_verified_tls() {
        let config = PostgresConfig::new("postgres://user:pass@db/northstar", "identity");
        assert_eq!(config.ssl_mode, SslMode::VerifyFull);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_pool_bounds_are_rejected() {
        let mut config = PostgresConfig::new("postgres://user:pass@db/northstar", "identity");
        config.max_connections = 0;
        assert!(matches!(
            config.validate(),
            Err(PostgresConfigError::InvalidPoolBounds)
        ));
    }

    #[test]
    fn sqlstate_mapping_is_typed() {
        let error = sqlx::Error::Database(Box::new(FakeDbError("40001")));
        assert_eq!(
            map_sqlx_error(&error),
            RepositoryError::SerializationConflict
        );
    }

    #[derive(Debug)]
    struct FakeDbError(&'static str);

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("test")
        }
    }
    impl std::error::Error for FakeDbError {}
    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            "test"
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(self.0.into())
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
    }
}
