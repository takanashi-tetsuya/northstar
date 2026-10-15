//! Read-only RFC 7622/PRECIS/IDNA audit for databases created by older releases.
//!
//! This module is deliberately independent from normal startup.  The operator
//! command connects with a single read-only session, never runs migrations and
//! reports every identity problem visible in one repeatable snapshot.  Values
//! are report-local pseudonyms unless the operator explicitly opts in to raw
//! identity output.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

mod identity_findings;
mod invariants;
mod schema;
mod semantic_findings;

use self::identity_findings::{collision_findings, hex, malformed_finding, noncanonical_finding};
use self::invariants::{
    message_archive_invariants, mix_channel_owner_invariants, mix_participant_invariants,
    muc_destroy_invariants, muc_origin_invariants, personal_admission_collisions,
};
use self::schema::{load_reference_graph, load_schema, load_schema_report, scan_specs};
use self::semantic_findings::{ownership_and_composite_findings, structural_findings};

const COMMAND: &str = "audit-identities";
const USAGE: &str = "usage: xmpp-server audit-identities --dry-run [--xmpp-domain DOMAIN] [--include-sensitive-values] [--compact]";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditOptions {
    pub(crate) domain: String,
    pub(crate) include_sensitive_values: bool,
    pub(crate) compact: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditOutcome {
    Clean,
    Dirty,
    Help,
}

#[derive(Clone, Copy, Debug)]
enum IdentityKind {
    Full,
    SessionFull,
    Bare,
    BareKey,
    UserBare,
    Domain,
    Localpart,
    Resource,
    AccessPattern,
}

impl IdentityKind {
    fn name(self) -> &'static str {
        match self {
            Self::Full => "rfc7622-full",
            Self::SessionFull => "rfc7622-session-full",
            Self::Bare => "rfc7622-bare",
            Self::BareKey => "rfc7622-bare-key",
            Self::UserBare => "rfc7622-user-bare",
            Self::Domain => "idna-domain-ulabel",
            Self::Localpart => "username-case-mapped",
            Self::Resource => "opaque-string",
            Self::AccessPattern => "rfc7622-bare-access-pattern",
        }
    }

    fn canonicalize(self, value: &str) -> Result<String> {
        match self {
            Self::Full => crate::jid::canonicalize(value),
            Self::SessionFull => crate::jid::canonical_session_key(value),
            Self::Bare => crate::jid::canonicalize_bare(value),
            Self::BareKey => crate::jid::canonical_bare_key(value),
            Self::UserBare => {
                let jid = crate::jid::CanonicalJid::parse_bare(value)?;
                anyhow::ensure!(jid.localpart().is_some(), "identity requires a localpart");
                Ok(jid.to_string())
            }
            Self::Domain => crate::jid::prepare_domainpart(value),
            Self::Localpart => crate::jid::prepare_localpart(value),
            Self::Resource => crate::jid::prepare_resourcepart(value),
            Self::AccessPattern => crate::jid::canonicalize_bare(value),
        }
    }
}

#[derive(Clone, Copy)]
enum ScanSource {
    Column {
        scope_sql: &'static str,
        predicate_sql: &'static str,
    },
    Query(&'static str),
}

#[derive(Clone, Copy)]
struct ScanSpec {
    table: &'static str,
    field: &'static str,
    required_columns: &'static [&'static str],
    source: ScanSource,
    kind: IdentityKind,
    collision_namespace: Option<&'static str>,
    reference_edges: &'static [&'static str],
    remediation: &'static str,
}

#[derive(Clone, Debug)]
struct ScannedIdentity {
    table: &'static str,
    field: &'static str,
    locator: String,
    scope: String,
    original: String,
    canonical: String,
    namespace: &'static str,
    reference_edges: &'static [&'static str],
}

#[derive(Serialize)]
struct AuditReport {
    format: &'static str,
    generated_at: DateTime<Utc>,
    status: &'static str,
    dry_run: bool,
    database_read_only: bool,
    configured_domain: SensitiveValue,
    privacy: PrivacyReport,
    schema: SchemaReport,
    coverage: CoverageReport,
    findings: Vec<Finding>,
    affected_tables: Vec<String>,
    reference_graph: Vec<ReferenceEdge>,
    repair_workflow: Vec<&'static str>,
}

#[derive(Serialize)]
struct PrivacyReport {
    mode: &'static str,
    fingerprint_scope: &'static str,
    notice: &'static str,
    forbidden_data_not_read: Vec<&'static str>,
    deliberate_limitations: Vec<&'static str>,
}

#[derive(Serialize)]
struct SchemaReport {
    current_schema: String,
    applied_sqlx_migrations: Option<i64>,
    latest_sqlx_migration: Option<i64>,
    identity_markers: Vec<MarkerReport>,
}

#[derive(Serialize)]
struct MarkerReport {
    marker_kind: String,
    domain_scope: Option<SensitiveValue>,
    canonicalizer_version: i32,
    transformed_rows: i64,
    completed_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct CoverageReport {
    configured_specs: usize,
    scanned_specs: usize,
    scanned_values: usize,
    skipped_specs: Vec<SkippedSpec>,
    structural_checks: Vec<&'static str>,
}

#[derive(Serialize)]
struct SkippedSpec {
    table: &'static str,
    field: &'static str,
    reason: String,
}

#[derive(Clone, Serialize)]
struct SensitiveValue {
    value: Option<String>,
    fingerprint: String,
    utf8_bytes: usize,
    unicode_scalars: usize,
}

#[derive(Serialize)]
struct Finding {
    code: &'static str,
    table: String,
    field: String,
    locator: String,
    canonicalizer: &'static str,
    scope: Option<SensitiveValue>,
    original: Option<SensitiveValue>,
    canonical: Option<SensitiveValue>,
    related_locations: Vec<String>,
    reference_edge_ids: Vec<String>,
    explanation: String,
    recommendation: String,
}

#[derive(Clone, Serialize)]
struct ReferenceEdge {
    id: String,
    kind: &'static str,
    source: String,
    target: String,
    relationship: String,
    row_data_inspected: bool,
}

struct Reporter {
    include_values: bool,
    salt: [u8; 32],
}

impl Reporter {
    fn new(include_values: bool) -> Self {
        let mut salt = [0_u8; 32];
        salt[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        salt[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        Self {
            include_values,
            salt,
        }
    }

    fn value(&self, value: &str) -> SensitiveValue {
        let mut digest = Sha256::new();
        digest.update(b"northstar:identity-audit:report-local:v1\0");
        digest.update(self.salt);
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
        SensitiveValue {
            value: self.include_values.then(|| value.to_owned()),
            fingerprint: format!("report-local-sha256:{}", hex(&digest.finalize())),
            utf8_bytes: value.len(),
            unicode_scalars: value.chars().count(),
        }
    }
}

#[derive(Default)]
struct SchemaMap {
    schema: String,
    tables: HashMap<String, HashSet<String>>,
}

impl SchemaMap {
    fn has(&self, table: &str, columns: &[&str]) -> bool {
        self.tables
            .get(table)
            .is_some_and(|available| columns.iter().all(|column| available.contains(*column)))
    }

    fn missing(&self, table: &str, columns: &[&str]) -> String {
        match self.tables.get(table) {
            None => "table is not present at this migration generation".to_owned(),
            Some(available) => {
                let missing = columns
                    .iter()
                    .filter(|column| !available.contains(**column))
                    .copied()
                    .collect::<Vec<_>>();
                format!(
                    "columns not present at this migration generation: {}",
                    missing.join(", ")
                )
            }
        }
    }
}

/// Handle the maintenance command before normal configuration, logging, TLS,
/// bootstrap writes or migrations are initialized.
pub(crate) async fn maybe_run(arguments: &[String]) -> Result<Option<AuditOutcome>> {
    if arguments.first().map(String::as_str) != Some(COMMAND) {
        return Ok(None);
    }
    if arguments
        .iter()
        .skip(1)
        .any(|argument| argument == "--help" || argument == "-h")
    {
        println!("{USAGE}");
        return Ok(Some(AuditOutcome::Help));
    }
    let options = parse_options(&arguments[1..])?;
    let database_url = database_url_from_env()?;
    let pool = read_only_pool(&database_url).await?;
    let result = audit_database(&pool, &options).await;
    pool.close().await;
    let report = result?;
    if options.compact {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }
    Ok(Some(if report.findings.is_empty() {
        AuditOutcome::Clean
    } else {
        AuditOutcome::Dirty
    }))
}

fn parse_options(arguments: &[String]) -> Result<AuditOptions> {
    let mut dry_run = false;
    let mut include_sensitive_values = false;
    let mut compact = false;
    let mut domain = std::env::var("XMPP_DOMAIN").unwrap_or_else(|_| "localhost".to_owned());
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--dry-run" => dry_run = true,
            "--include-sensitive-values" => include_sensitive_values = true,
            "--compact" => compact = true,
            "--xmpp-domain" => {
                index += 1;
                domain = arguments
                    .get(index)
                    .context("--xmpp-domain requires a value")?
                    .clone();
            }
            option => anyhow::bail!("unknown audit option {option:?}; {USAGE}"),
        }
        index += 1;
    }
    anyhow::ensure!(
        dry_run,
        "--dry-run is mandatory; this command never repairs or merges identities"
    );
    domain = crate::jid::prepare_domainpart(&domain)
        .context("audit XMPP domain is not a valid RFC 7622 domainpart")?;
    Ok(AuditOptions {
        domain,
        include_sensitive_values,
        compact,
    })
}

fn database_url_from_env() -> Result<Zeroizing<String>> {
    let direct = std::env::var("DATABASE_URL").ok();
    let file = std::env::var_os("DATABASE_URL_FILE").map(PathBuf::from);
    match (direct, file) {
        (Some(_), Some(_)) => anyhow::bail!("set only one of DATABASE_URL and DATABASE_URL_FILE"),
        (Some(value), None) => Ok(Zeroizing::new(value)),
        (None, Some(path)) => Ok(Zeroizing::new(crate::platform::config::read_secret_file(
            &path,
            "DATABASE_URL_FILE",
        )?)),
        (None, None) => {
            anyhow::bail!("DATABASE_URL or DATABASE_URL_FILE is required for identity audit")
        }
    }
}

async fn read_only_pool(database_url: &str) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_read_only=on")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET statement_timeout='5min'")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("SET lock_timeout='5s'")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
        .context("could not connect to PostgreSQL for read-only identity audit")
}

async fn audit_database(pool: &PgPool, options: &AuditOptions) -> Result<AuditReport> {
    let reporter = Reporter::new(options.include_sensitive_values);
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .context("could not establish the read-only identity audit snapshot")?;

    let schema = load_schema(&mut transaction).await?;
    let specs = scan_specs();
    let mut findings = Vec::new();
    let mut identities = Vec::new();
    let mut skipped_specs = Vec::new();
    let mut scanned_specs = 0;
    let mut scanned_values = 0;

    for spec in &specs {
        if !schema.has(spec.table, spec.required_columns) {
            skipped_specs.push(SkippedSpec {
                table: spec.table,
                field: spec.field,
                reason: schema.missing(spec.table, spec.required_columns),
            });
            continue;
        }
        scanned_specs += 1;
        let query = query_for(spec);
        let rows = sqlx::query(&query)
            .fetch_all(&mut *transaction)
            .await
            .with_context(|| {
                format!(
                    "read-only identity scan failed for {}.{}",
                    spec.table, spec.field
                )
            })?;
        scanned_values += rows.len();
        for row in rows {
            let locator: String = row.try_get("locator")?;
            let scope: String = row.try_get("scope")?;
            let original: String = row.try_get("value")?;
            match spec.kind.canonicalize(&original) {
                Ok(canonical) => {
                    if canonical != original {
                        findings.push(noncanonical_finding(
                            &reporter, spec, &locator, &scope, &original, &canonical,
                        ));
                    }
                    if let Some(namespace) = spec.collision_namespace {
                        identities.push(ScannedIdentity {
                            table: spec.table,
                            field: spec.field,
                            locator,
                            scope,
                            original,
                            canonical,
                            namespace,
                            reference_edges: spec.reference_edges,
                        });
                    }
                }
                Err(error) => findings.push(malformed_finding(
                    &reporter, spec, &locator, &scope, &original, &error,
                )),
            }
        }
    }

    findings.extend(collision_findings(&reporter, identities));
    findings.extend(structural_findings(&mut transaction, &schema).await?);
    findings.extend(
        ownership_and_composite_findings(&mut transaction, &schema, &reporter, &options.domain)
            .await?,
    );
    findings.sort_by(|left, right| {
        (&left.table, &left.field, &left.locator, left.code).cmp(&(
            &right.table,
            &right.field,
            &right.locator,
            right.code,
        ))
    });

    let affected_tables = findings
        .iter()
        .map(|finding| finding.table.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let schema_report = load_schema_report(&mut transaction, &schema, &reporter).await?;
    let reference_graph = load_reference_graph(&mut transaction, &schema, &specs).await?;
    let transaction_id: Option<i64> = sqlx::query_scalar("SELECT txid_current_if_assigned()")
        .fetch_one(&mut *transaction)
        .await?;
    anyhow::ensure!(
        transaction_id.is_none(),
        "read-only audit unexpectedly acquired a PostgreSQL transaction ID"
    );
    transaction.rollback().await?;

    Ok(AuditReport {
        format: "northstar-identity-audit/v1",
        generated_at: Utc::now(),
        status: if findings.is_empty() { "clean" } else { "operator_action_required" },
        dry_run: true,
        database_read_only: true,
        configured_domain: reporter.value(&options.domain),
        privacy: PrivacyReport {
            mode: if options.include_sensitive_values {
                "explicit-sensitive-identity-values"
            } else {
                "report-local-pseudonyms"
            },
            fingerprint_scope: "random salt is held only in memory; fingerprints correlate values within this report, not across reports",
            notice: "Pseudonymization is not anonymization. Protect reports as operational security material, especially when raw values are explicitly enabled.",
            forbidden_data_not_read: vec![
                "password hashes and SCRAM verifiers",
                "bearer tokens, API keys, HMAC keys and other secrets",
                "stanza/XML/message bodies and MAM content",
                "abuse evidence body_text and report descriptions",
                "PubSub, PEP and MIX payload bodies",
            ],
            deliberate_limitations: vec![
                "profile PEP ItemID values are audited, but the linked XML root id is not inspected because payload content is outside the privacy boundary",
                "API MUC destroy target metadata is audited, but immutable operation payload JSON is not inspected",
                "the tool proposes no automatic merge because canonical collisions can represent distinct principals",
                "ctid locators correlate rows only inside this snapshot and must never be used as durable repair keys",
            ],
        },
        schema: schema_report,
        coverage: CoverageReport {
            configured_specs: specs.len(),
            scanned_specs,
            scanned_values,
            skipped_specs,
            structural_checks: vec![
                "MIX contacts JSON is an array of strings",
                "SM joined_rooms JSON is an array of objects with string room_jid",
                "SM directed_presence JSON is an array of strings",
                "session/admin full JIDs belong to their account and SM resource matches full_jid",
                "MIX channel addresses and registered nick ownership remain unique after canonicalization",
            ],
        },
        findings,
        affected_tables,
        reference_graph,
        repair_workflow: vec![
            "Create and verify an encrypted, signed backup before changing identity data.",
            "Restore the backup into an isolated PostgreSQL copy and stop every Northstar process connected to that copy.",
            "Run this command in redacted mode first; use --include-sensitive-values only in a protected terminal or access-controlled file.",
            "Resolve each malformed value and collision manually. Confirm which principal and references survive; never merge solely because two strings canonicalize alike.",
            "Update every edge listed in reference_graph in one reviewed transaction on the isolated copy; payload-linked exceptions require a dedicated, content-aware repair procedure.",
            "Rerun the audit until status is clean, then run the normal migration on the copy and rerun the audit to prove idempotence.",
            "Schedule downtime, repeat the reviewed repair on production, and retain the before/after reports with restricted permissions.",
        ],
    })
}

fn query_for(spec: &ScanSpec) -> String {
    match spec.source {
        ScanSource::Column {
            scope_sql,
            predicate_sql,
        } => format!(
            "SELECT t.ctid::text AS locator, ({scope_sql})::text AS scope, t.{field}::text AS value \
             FROM {table} t WHERE t.{field} IS NOT NULL AND ({predicate_sql}) ORDER BY t.ctid",
            table = spec.table,
            field = spec.field,
        ),
        ScanSource::Query(query) => query.to_owned(),
    }
}

#[cfg(test)]
mod tests;
