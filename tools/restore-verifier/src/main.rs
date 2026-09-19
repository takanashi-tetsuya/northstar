use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct RestoreCatalog {
    version: String,
    entries: Vec<RestoreEntry>,
}

#[derive(Debug, Deserialize)]
struct RestoreEntry {
    database: String,
    restore_order: u32,
    cluster_class: String,
    pitr: bool,
    base_backup: bool,
    wal_archiving: bool,
    encrypted: bool,
    retention_days: u32,
    #[serde(default)]
    dependencies: Vec<String>,
    #[serde(default)]
    deletion_ledger: bool,
    #[serde(default)]
    fence_check: String,
}

#[derive(Debug, Error)]
enum Error {
    #[error("usage: restore-verifier --catalog <catalog/restore-order.yaml>")]
    Usage,
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid restore catalog: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("restore catalog validation failed: {0}")]
    Validation(String),
}

fn validate(catalog: &RestoreCatalog) -> Result<(), Error> {
    if catalog.version.trim().is_empty() {
        return Err(Error::Validation("version is required".into()));
    }
    if catalog.entries.is_empty() {
        return Err(Error::Validation(
            "at least one database is required".into(),
        ));
    }
    let mut names = BTreeSet::new();
    let mut orders = BTreeMap::new();
    for entry in &catalog.entries {
        if !names.insert(entry.database.clone()) {
            return Err(Error::Validation(format!(
                "duplicate database {}",
                entry.database
            )));
        }
        if entry.restore_order == 0 {
            return Err(Error::Validation(format!(
                "{} has invalid restore_order",
                entry.database
            )));
        }
        if orders
            .insert(entry.restore_order, entry.database.clone())
            .is_some()
        {
            return Err(Error::Validation(format!(
                "restore_order {} is assigned more than once",
                entry.restore_order
            )));
        }
        if entry.cluster_class.trim().is_empty()
            || !entry.pitr
            || !entry.base_backup
            || !entry.wal_archiving
            || !entry.encrypted
            || entry.retention_days == 0
            || !entry.deletion_ledger
            || entry.fence_check.trim().is_empty()
        {
            return Err(Error::Validation(format!(
                "{} lacks PITR, encrypted backup, WAL, deletion-ledger, retention, or fence policy",
                entry.database
            )));
        }
    }
    let order_by_name: BTreeMap<_, _> = catalog
        .entries
        .iter()
        .map(|entry| (entry.database.as_str(), entry.restore_order))
        .collect();
    for entry in &catalog.entries {
        for dependency in &entry.dependencies {
            let Some(dependency_order) = order_by_name.get(dependency.as_str()) else {
                return Err(Error::Validation(format!(
                    "{} depends on unknown database {}",
                    entry.database, dependency
                )));
            };
            if dependency_order >= &entry.restore_order {
                return Err(Error::Validation(format!(
                    "{} restores before dependency {}",
                    entry.database, dependency
                )));
            }
        }
    }
    Ok(())
}

fn run() -> Result<(), Error> {
    let mut args = env::args().skip(1);
    let mut catalog_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--catalog" => catalog_path = args.next().map(PathBuf::from),
            _ => return Err(Error::Usage),
        }
    }
    let path = catalog_path.unwrap_or_else(|| PathBuf::from("catalog/restore-order.yaml"));
    let bytes = fs::read(&path).map_err(|source| Error::Read {
        path: path.clone(),
        source,
    })?;
    let catalog: RestoreCatalog = serde_yaml::from_slice(&bytes)?;
    validate(&catalog)?;
    println!(
        "restore catalog valid: {} logical database(s), {} ordered phases",
        catalog.entries.len(),
        catalog.entries.len()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("restore-verifier: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, order: u32) -> RestoreEntry {
        RestoreEntry {
            database: name.into(),
            restore_order: order,
            cluster_class: "primary-home".into(),
            pitr: true,
            base_backup: true,
            wal_archiving: true,
            encrypted: true,
            retention_days: 30,
            dependencies: Vec::new(),
            deletion_ledger: true,
            fence_check: "region_epoch".into(),
        }
    }

    #[test]
    fn dependency_order_and_required_controls_are_enforced() {
        let mut identity = entry("identity", 10);
        let mut session = entry("session", 20);
        session.dependencies.push("identity".into());
        assert!(validate(&RestoreCatalog {
            version: "2.0.0".into(),
            entries: vec![identity, session],
        })
        .is_ok());
        identity = entry("identity", 20);
        session = entry("session", 10);
        session.dependencies.push("identity".into());
        assert!(validate(&RestoreCatalog {
            version: "2.0.0".into(),
            entries: vec![identity, session],
        })
        .is_err());
    }
}
