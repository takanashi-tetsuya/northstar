use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct OwnershipCatalog {
    #[allow(dead_code)]
    version: String,
    ownership: BTreeMap<String, OwnershipEntry>,
}

#[derive(Debug, Deserialize)]
struct OwnershipEntry {
    database: String,
    #[serde(default)]
    logical_database: Option<String>,
    owner_role: String,
    migrator_role: String,
    runtime_role: String,
    ops_role: String,
    backup_role: String,
}

#[derive(Debug, Error)]
enum Error {
    #[error("usage: db-bootstrap --catalog <catalog/data-ownership.yaml> --output <roles.sql>")]
    Usage,
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid ownership catalog: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("unsafe PostgreSQL identifier '{0}' in ownership catalog")]
    UnsafeIdentifier(String),
}

fn quote_identifier(value: &str) -> Result<String, Error> {
    if value.is_empty()
        || value.len() > 63
        || !value.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && (byte.is_ascii_alphabetic() || byte == b'_') || index > 0)
                && (byte == b'_' || byte == b'-' || byte.is_ascii_alphanumeric())
        })
    {
        return Err(Error::UnsafeIdentifier(value.to_owned()));
    }
    Ok(format!("\"{}\"", value.replace('"', "\"\"")))
}

fn render(catalog: &OwnershipCatalog) -> Result<String, Error> {
    let mut output = String::from(
        "-- GENERATED FILE: db-bootstrap --catalog catalog/data-ownership.yaml\n-- Do not place passwords in this file. Provision LOGIN credentials through the deployment secret manager.\n-- Run from a control database (normally postgres) with a dedicated bootstrap identity.\n\n",
    );
    for (service, entry) in &catalog.ownership {
        let database = quote_identifier(&entry.database)?;
        let logical_database = entry.logical_database.as_deref().unwrap_or(&entry.database);
        let owner = quote_identifier(&entry.owner_role)?;
        let migrator = quote_identifier(&entry.migrator_role)?;
        let runtime = quote_identifier(&entry.runtime_role)?;
        let ops = quote_identifier(&entry.ops_role)?;
        let backup = quote_identifier(&entry.backup_role)?;
        let schema = quote_identifier(&format!("{}_private", service.replace('-', "_")))?;
        output.push_str(&format!(
            "-- service={service} logical_database={logical_database} database={}\n",
            database
        ));
        output.push_str(&format!(
            "DO $$ BEGIN\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {owner_literal}) THEN\n    CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\n  END IF;\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {migrator_literal}) THEN\n    CREATE ROLE {migrator} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;\n  END IF;\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {runtime_literal}) THEN\n    CREATE ROLE {runtime} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64;\n  END IF;\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {ops_literal}) THEN\n    CREATE ROLE {ops} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8;\n  END IF;\n  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {backup_literal}) THEN\n    CREATE ROLE {backup} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2;\n  END IF;\nEND $$;\n",
            owner_literal = quote_literal(&entry.owner_role),
            migrator_literal = quote_literal(&entry.migrator_role),
            runtime_literal = quote_literal(&entry.runtime_role),
            ops_literal = quote_literal(&entry.ops_role),
            backup_literal = quote_literal(&entry.backup_role),
        ));
        output.push_str(&format!(
            "SELECT pg_catalog.format('CREATE DATABASE %I OWNER %I', {database_literal}, {owner_literal})\n  WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = {database_literal}) \\gexec\n\\connect {database}\nREVOKE ALL ON DATABASE {database} FROM PUBLIC;\nGRANT CONNECT ON DATABASE {database} TO {migrator}, {runtime}, {ops}, {backup};\nCREATE SCHEMA IF NOT EXISTS {schema} AUTHORIZATION {owner};\nALTER ROLE {migrator} SET search_path = {schema}, pg_catalog;\nALTER ROLE {runtime} SET search_path = {schema}, pg_catalog;\nALTER ROLE {ops} SET search_path = {schema}, pg_catalog;\nALTER ROLE {backup} SET search_path = {schema}, pg_catalog;\nREVOKE ALL ON SCHEMA public FROM PUBLIC;\n\\connect postgres\n\n",
            database_literal = quote_literal(&entry.database),
            owner_literal = quote_literal(&entry.owner_role),
        ));
    }
    Ok(output)
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn run() -> Result<(), Error> {
    let mut args = env::args().skip(1);
    let mut catalog_path = None;
    let mut output_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--catalog" => catalog_path = args.next().map(PathBuf::from),
            "--output" => output_path = args.next().map(PathBuf::from),
            _ => return Err(Error::Usage),
        }
    }
    let catalog_path = catalog_path.ok_or(Error::Usage)?;
    let output_path = output_path.ok_or(Error::Usage)?;
    let bytes = fs::read(&catalog_path).map_err(|source| Error::Read {
        path: catalog_path.clone(),
        source,
    })?;
    let catalog: OwnershipCatalog = serde_yaml::from_slice(&bytes)?;
    let rendered = render(&catalog)?;
    if let Some(parent) = Path::new(&output_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| Error::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    fs::write(&output_path, rendered).map_err(|source| Error::Write {
        path: output_path.clone(),
        source,
    })?;
    println!("generated role bootstrap SQL at {}", output_path.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("db-bootstrap: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_strictly_bounded() {
        assert_eq!(
            quote_identifier("identity_runtime").unwrap(),
            "\"identity_runtime\""
        );
        assert!(quote_identifier("bad.name").is_err());
        assert!(quote_identifier("1bad").is_err());
    }

    #[test]
    fn generated_sql_has_no_password_literals() {
        let yaml = r#"
version: "2.0.0"
ownership:
  identity:
    database: northstar_identity
    owner_role: identity_owner
    migrator_role: identity_migrator
    runtime_role: identity_runtime
    ops_role: identity_ops
    backup_role: identity_backup
"#;
        let catalog: OwnershipCatalog = serde_yaml::from_str(yaml).unwrap();
        let sql = render(&catalog).unwrap();
        assert!(sql.contains("CREATE ROLE \"identity_runtime\" LOGIN"));
        assert!(!sql.contains("PASSWORD"));
    }
}
