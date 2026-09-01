use anyhow::{Context, Result};
use sqlx::PgPool;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppliedMigration {
    version: i64,
    success: bool,
    checksum: Vec<u8>,
}

fn validate_applied_migrations(
    expected: &[(i64, Vec<u8>)],
    applied: &[AppliedMigration],
) -> Result<()> {
    let expected = expected.iter().cloned().collect::<BTreeMap<_, _>>();
    let mut actual = BTreeMap::new();
    for migration in applied {
        anyhow::ensure!(
            actual.insert(migration.version, migration).is_none(),
            "database migration {} is recorded more than once",
            migration.version
        );
        anyhow::ensure!(
            migration.success,
            "database migration {} is recorded as failed",
            migration.version
        );
    }

    for (version, checksum) in &expected {
        let migration = actual
            .get(version)
            .with_context(|| format!("database migration {version} is pending"))?;
        anyhow::ensure!(
            migration.checksum == *checksum,
            "database migration {version} checksum does not match this binary"
        );
    }
    for version in actual.keys() {
        anyhow::ensure!(
            expected.contains_key(version),
            "database contains migration {version}, which is missing from this binary"
        );
    }
    Ok(())
}

fn required_identity_migrations(domain: &str) -> Vec<(String, i32)> {
    [
        "pubsub-pep-rfc7622-ulabel-v2",
        "authorization-keys-rfc7622-ulabel-v2",
        "push-keys-rfc7622-ulabel-v2",
        "mix-keys-rfc7622-ulabel-v2",
        "profile-pep-item-jids-rfc7622-ulabel-v2",
        "remaining-identity-metadata-rfc7622-ulabel-v2",
    ]
    .into_iter()
    .map(|migration| (migration.to_owned(), 2))
    .chain(std::iter::once((
        format!("session-authorization-rfc7622-ulabel-v2:{domain}"),
        2,
    )))
    .collect()
}

fn validate_identity_migrations(
    required: &[(String, i32)],
    applied: &[(String, i32)],
) -> Result<()> {
    let applied = applied.iter().cloned().collect::<BTreeMap<_, _>>();
    for (migration, version) in required {
        let applied_version = applied
            .get(migration)
            .with_context(|| format!("identity migration {migration} is pending"))?;
        anyhow::ensure!(
            applied_version == version,
            "identity migration {migration} canonicalizer version does not match this binary"
        );
    }
    Ok(())
}

/// Verify the SQLx migration ledger without creating or changing any database
/// object. Normal server startup uses this path with the non-owner runtime
/// role; only the explicit `migrate` command may run migrations.
pub async fn verify_schema(pool: &PgPool, domain: &str) -> Result<()> {
    let expected = super::MIGRATOR
        .iter()
        .map(|migration| (migration.version, migration.checksum.to_vec()))
        .collect::<Vec<_>>();
    let mut transaction = pool
        .begin()
        .await
        .context("could not begin read-only schema verification")?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .context("could not enforce read-only schema verification")?;
    // Production connections are pinned to `public` by
    // `pin_public_application_schema`. The explicit loopback-only development
    // escape hatch instead supplies a random isolated schema in its DSN. Keep
    // these verification reads on that already-pinned connection schema so a
    // test process cannot accidentally inspect a different shared schema.
    let rows: Vec<(i64, bool, Vec<u8>)> = sqlx::query_as(
        "SELECT version,success,checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut *transaction)
    .await
    .context(
        "could not read the SQLx migration ledger; run `xmpp-server migrate` with the migrator role",
    )?;
    let applied = rows
        .into_iter()
        .map(|(version, success, checksum)| AppliedMigration {
            version,
            success,
            checksum,
        })
        .collect::<Vec<_>>();
    validate_applied_migrations(&expected, &applied)?;

    // These canonicalizers intentionally run after SQLx's DDL migrations. A
    // migrator crash between those phases must not allow a runtime process to
    // start merely because the SQLx ledger is current.
    let identity_rows: Vec<(String, i32)> =
        sqlx::query_as("SELECT migration,canonicalizer_version FROM jid_identity_migrations")
            .fetch_all(&mut *transaction)
            .await
            .context("could not read the RFC 7622 identity-migration ledger")?;
    validate_identity_migrations(&required_identity_migrations(domain), &identity_rows)?;
    let session_authority_healthy: bool = sqlx::query_scalar(
        "SELECT northstar_session_capability_catalog_healthy(pg_catalog.current_schema())",
    )
    .fetch_one(&mut *transaction)
    .await
    .context("could not attest session capability ownership/ACLs")?;
    anyhow::ensure!(
        session_authority_healthy,
        "session capability ownership, search_path, or runtime ACL attestation failed; reconcile database grants before startup"
    );
    transaction
        .commit()
        .await
        .context("could not finish read-only schema verification")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(version: i64, checksum: &[u8]) -> AppliedMigration {
        AppliedMigration {
            version,
            success: true,
            checksum: checksum.to_vec(),
        }
    }

    #[test]
    fn exact_schema_is_accepted() {
        validate_applied_migrations(
            &[(1, vec![1]), (2, vec![2])],
            &[applied(1, &[1]), applied(2, &[2])],
        )
        .unwrap();
    }

    #[test]
    fn pending_failed_missing_and_checksum_drift_fail_closed() {
        let expected = [(1, vec![1]), (2, vec![2])];
        assert!(validate_applied_migrations(&expected, &[applied(1, &[1])]).is_err());
        assert!(validate_applied_migrations(
            &expected,
            &[
                applied(1, &[1]),
                AppliedMigration {
                    version: 2,
                    success: false,
                    checksum: vec![2],
                },
            ],
        )
        .is_err());
        assert!(
            validate_applied_migrations(&expected, &[applied(1, &[1]), applied(2, &[9])],).is_err()
        );
        assert!(validate_applied_migrations(
            &[(1, vec![1])],
            &[applied(1, &[1]), applied(2, &[2])],
        )
        .is_err());
    }

    #[test]
    fn duplicate_ledger_versions_fail_closed() {
        assert!(validate_applied_migrations(
            &[(1, vec![1])],
            &[applied(1, &[1]), applied(1, &[1])],
        )
        .is_err());
    }

    #[test]
    fn every_domain_scoped_identity_marker_is_required() {
        let required = required_identity_migrations("example.test");
        assert_eq!(required.len(), 7);
        assert!(required
            .iter()
            .any(|(name, version)| name.ends_with(":example.test") && *version == 2));
        validate_identity_migrations(&required, &required).unwrap();

        let mut incomplete = required.clone();
        incomplete.pop();
        assert!(validate_identity_migrations(&required, &incomplete).is_err());

        let mut stale = required.clone();
        stale[0].1 = 1;
        assert!(validate_identity_migrations(&required, &stale).is_err());
    }
}
