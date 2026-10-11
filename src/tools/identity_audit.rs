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
        (None, Some(path)) => Ok(Zeroizing::new(crate::config::read_secret_file(
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

fn malformed_finding(
    reporter: &Reporter,
    spec: &ScanSpec,
    locator: &str,
    scope: &str,
    original: &str,
    error: &anyhow::Error,
) -> Finding {
    Finding {
        code: "malformed_identity",
        table: spec.table.to_owned(),
        field: spec.field.to_owned(),
        locator: format!("{}@{}", spec.table, locator),
        canonicalizer: spec.kind.name(),
        scope: (!scope.is_empty()).then(|| reporter.value(scope)),
        original: Some(reporter.value(original)),
        canonical: None,
        related_locations: Vec::new(),
        reference_edge_ids: spec
            .reference_edges
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        explanation: format!(
            "the value cannot be prepared by {}: {}",
            spec.kind.name(),
            safe_error(error)
        ),
        recommendation: spec.remediation.to_owned(),
    }
}

fn noncanonical_finding(
    reporter: &Reporter,
    spec: &ScanSpec,
    locator: &str,
    scope: &str,
    original: &str,
    canonical: &str,
) -> Finding {
    Finding {
        code: "noncanonical_identity",
        table: spec.table.to_owned(),
        field: spec.field.to_owned(),
        locator: format!("{}@{}", spec.table, locator),
        canonicalizer: spec.kind.name(),
        scope: (!scope.is_empty()).then(|| reporter.value(scope)),
        original: Some(reporter.value(original)),
        canonical: Some(reporter.value(canonical)),
        related_locations: Vec::new(),
        reference_edge_ids: spec
            .reference_edges
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        explanation: "stored identity differs from its exact RFC 7622/PRECIS/IDNA canonical form"
            .to_owned(),
        recommendation: spec.remediation.to_owned(),
    }
}

fn collision_findings(reporter: &Reporter, identities: Vec<ScannedIdentity>) -> Vec<Finding> {
    let mut groups: BTreeMap<(&str, &str, &str), Vec<&ScannedIdentity>> = BTreeMap::new();
    for identity in &identities {
        groups
            .entry((identity.namespace, &identity.scope, &identity.canonical))
            .or_default()
            .push(identity);
    }
    groups
        .into_values()
        .filter(|group| group.len() > 1)
        .map(|group| {
            let first = group[0];
            let idna = group.iter().any(|row| uses_alabel(&row.original))
                && group.iter().any(|row| !uses_alabel(&row.original));
            let edges = group
                .iter()
                .flat_map(|row| row.reference_edges.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(str::to_owned)
                .collect();
            Finding {
                code: if idna {
                    "idna_alabel_ulabel_collision"
                } else {
                    "precis_canonical_collision"
                },
                table: first.table.to_owned(),
                field: first.field.to_owned(),
                locator: format!("{}@{}", first.table, first.locator),
                canonicalizer: "canonical-key-collision",
                scope: (!first.scope.is_empty()).then(|| reporter.value(&first.scope)),
                original: Some(reporter.value(&first.original)),
                canonical: Some(reporter.value(&first.canonical)),
                related_locations: group
                    .iter()
                    .skip(1)
                    .map(|row| format!("{}@{}", row.table, row.locator))
                    .collect(),
                reference_edge_ids: edges,
                explanation: if idna {
                    "distinct A-label/U-label spellings resolve to one canonical identity in the same authorization scope".to_owned()
                } else {
                    "multiple stored identities resolve to one canonical key in the same authorization scope".to_owned()
                },
                recommendation: "Determine the intended principal using external account records, then repair or remove all dependent rows together. Do not automatically merge these principals.".to_owned(),
            }
        })
        .collect()
}

fn uses_alabel(value: &str) -> bool {
    let address = value.split('/').next().unwrap_or(value);
    let domain = address
        .rsplit_once('@')
        .map_or(address, |(_, domain)| domain);
    domain
        .split('.')
        .any(|label| label.to_ascii_lowercase().starts_with("xn--"))
}

fn safe_error(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .take(240)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

async fn load_schema(transaction: &mut Transaction<'_, Postgres>) -> Result<SchemaMap> {
    let schema = sqlx::query_scalar::<_, String>("SELECT current_schema()::text")
        .fetch_one(&mut **transaction)
        .await?;
    // pg_catalog is intentional: information_schema hides tables for which the
    // audit role lacks privileges and could turn a permission mistake into a
    // false "old schema / clean" result.  Catalog discovery sees the table;
    // the subsequent SELECT then fails closed if the role cannot read it.
    let rows = sqlx::query(
        "SELECT c.relname AS table_name,a.attname AS column_name
         FROM pg_class c
         JOIN pg_namespace n ON n.oid=c.relnamespace
         JOIN pg_attribute a ON a.attrelid=c.oid
         WHERE n.nspname=current_schema()
           AND c.relkind IN ('r','p')
           AND a.attnum > 0 AND NOT a.attisdropped
         ORDER BY c.relname,a.attnum",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut tables = HashMap::<String, HashSet<String>>::new();
    for row in rows {
        let table: String = row.try_get("table_name")?;
        let column: String = row.try_get("column_name")?;
        tables.entry(table).or_default().insert(column);
    }
    Ok(SchemaMap { schema, tables })
}

async fn load_schema_report(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<SchemaReport> {
    let (applied_sqlx_migrations, latest_sqlx_migration) =
        if schema.has("_sqlx_migrations", &["version", "success"]) {
            let row = sqlx::query(
                "SELECT COUNT(*) FILTER (WHERE success) AS applied,
                    MAX(version) FILTER (WHERE success) AS latest
             FROM _sqlx_migrations",
            )
            .fetch_one(&mut **transaction)
            .await?;
            (row.try_get("applied")?, row.try_get("latest")?)
        } else {
            (None, None)
        };
    let identity_markers = if schema.has(
        "jid_identity_migrations",
        &[
            "migration",
            "canonicalizer_version",
            "transformed_rows",
            "completed_at",
        ],
    ) {
        sqlx::query(
            "SELECT migration,canonicalizer_version,transformed_rows,completed_at
             FROM jid_identity_migrations ORDER BY migration",
        )
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let marker: String = row.try_get("migration")?;
            let (marker_kind, domain_scope) = marker_description(&marker, reporter);
            Ok(MarkerReport {
                marker_kind,
                domain_scope,
                canonicalizer_version: row.try_get("canonicalizer_version")?,
                transformed_rows: row.try_get("transformed_rows")?,
                completed_at: row.try_get("completed_at")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?
    } else {
        Vec::new()
    };
    Ok(SchemaReport {
        current_schema: schema.schema.clone(),
        applied_sqlx_migrations,
        latest_sqlx_migration,
        identity_markers,
    })
}

fn marker_description(marker: &str, reporter: &Reporter) -> (String, Option<SensitiveValue>) {
    const KNOWN: &[&str] = &[
        "pubsub-pep-rfc7622-ulabel-v2",
        "authorization-keys-rfc7622-ulabel-v2",
        "push-keys-rfc7622-ulabel-v2",
        "mix-keys-rfc7622-ulabel-v2",
        "profile-pep-item-jids-rfc7622-ulabel-v2",
        "remaining-identity-metadata-rfc7622-ulabel-v2",
    ];
    const SESSION: &str = "session-authorization-rfc7622-ulabel-v2:";
    if KNOWN.contains(&marker) {
        (marker.to_owned(), None)
    } else if let Some(domain) = marker.strip_prefix(SESSION) {
        (
            "session-authorization-rfc7622-ulabel-v2".to_owned(),
            Some(reporter.value(domain)),
        )
    } else {
        (
            "unrecognized-identity-migration-marker".to_owned(),
            Some(reporter.value(marker)),
        )
    }
}

async fn structural_findings(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
) -> Result<Vec<Finding>> {
    struct Check {
        table: &'static str,
        field: &'static str,
        required: &'static [&'static str],
        query: &'static str,
        explanation: &'static str,
    }
    const CHECKS: &[Check] = &[
        Check {
            table: "mix_channels",
            field: "contacts",
            required: &["contacts"],
            query: "SELECT ctid::text AS locator FROM mix_channels t
                    WHERE jsonb_typeof(t.contacts) IS DISTINCT FROM 'array'
                       OR EXISTS (
                         SELECT 1 FROM jsonb_array_elements(
                           CASE WHEN jsonb_typeof(t.contacts)='array' THEN t.contacts ELSE '[]'::jsonb END
                         ) value WHERE jsonb_typeof(value) IS DISTINCT FROM 'string'
                       ) ORDER BY ctid",
            explanation: "contacts must be a JSON array containing only string JIDs",
        },
        Check {
            table: "sm_resume_sessions",
            field: "joined_rooms",
            required: &["joined_rooms"],
            query: "SELECT ctid::text AS locator FROM sm_resume_sessions t
                    WHERE jsonb_typeof(t.joined_rooms) IS DISTINCT FROM 'array'
                       OR EXISTS (
                         SELECT 1 FROM jsonb_array_elements(
                           CASE WHEN jsonb_typeof(t.joined_rooms)='array' THEN t.joined_rooms ELSE '[]'::jsonb END
                         ) value
                         WHERE jsonb_typeof(value) IS DISTINCT FROM 'object'
                            OR jsonb_typeof(value->'room_jid') IS DISTINCT FROM 'string'
                       ) ORDER BY ctid",
            explanation: "joined_rooms must be a JSON array of objects with a string room_jid",
        },
        Check {
            table: "sm_resume_sessions",
            field: "directed_presence",
            required: &["directed_presence"],
            query: "SELECT ctid::text AS locator FROM sm_resume_sessions t
                    WHERE jsonb_typeof(t.directed_presence) IS DISTINCT FROM 'array'
                       OR EXISTS (
                         SELECT 1 FROM jsonb_array_elements(
                           CASE WHEN jsonb_typeof(t.directed_presence)='array' THEN t.directed_presence ELSE '[]'::jsonb END
                         ) value WHERE jsonb_typeof(value) IS DISTINCT FROM 'string'
                       ) ORDER BY ctid",
            explanation: "directed_presence must be a JSON array containing only string JIDs",
        },
    ];
    let mut findings = Vec::new();
    for check in CHECKS {
        if !schema.has(check.table, check.required) {
            continue;
        }
        for row in sqlx::query(check.query)
            .fetch_all(&mut **transaction)
            .await?
        {
            let locator: String = row.try_get("locator")?;
            findings.push(Finding {
                code: "invalid_identity_container",
                table: check.table.to_owned(),
                field: check.field.to_owned(),
                locator: format!("{}@{}", check.table, locator),
                canonicalizer: "container-shape",
                scope: None,
                original: None,
                canonical: None,
                related_locations: Vec::new(),
                reference_edge_ids: Vec::new(),
                explanation: check.explanation.to_owned(),
                recommendation: "Repair the container shape on an isolated copy before changing any nested identity values; never discard unknown membership state automatically.".to_owned(),
            });
        }
    }
    Ok(findings)
}

async fn ownership_and_composite_findings(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
    domain: &str,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    if schema.has("users", &["id", "username"])
        && schema.has(
            "sm_resume_sessions",
            &["id", "user_id", "full_jid", "resource"],
        )
    {
        let rows = sqlx::query(
            "SELECT s.ctid::text AS locator,u.username,s.full_jid,s.resource
             FROM sm_resume_sessions s JOIN users u ON u.id=s.user_id ORDER BY s.ctid",
        )
        .fetch_all(&mut **transaction)
        .await?;
        for row in rows {
            let locator: String = row.try_get("locator")?;
            let username: String = row.try_get("username")?;
            let full: String = row.try_get("full_jid")?;
            let resource: String = row.try_get("resource")?;
            let Ok(canonical_full) = crate::jid::canonical_session_key(&full) else {
                continue;
            };
            let Ok(parsed) = crate::jid::CanonicalJid::parse(&canonical_full) else {
                continue;
            };
            let expected_bare = crate::jid::canonicalize_bare(&format!("{username}@{domain}"));
            if expected_bare
                .as_deref()
                .is_ok_and(|expected| expected != parsed.bare())
            {
                findings.push(semantic_finding(
                    reporter,
                    SemanticFinding {
                        table: "sm_resume_sessions",
                        field: "full_jid",
                        locator: &locator,
                        original: &full,
                        code: "session_ownership_mismatch",
                        explanation: "the session full JID does not belong to the referenced users.username at the configured XMPP domain",
                        edges: &["sm-session-owner"],
                    },
                ));
            }
            if crate::jid::prepare_resourcepart(&resource).ok().as_deref() != parsed.resourcepart()
            {
                findings.push(semantic_finding(
                    reporter,
                    SemanticFinding {
                        table: "sm_resume_sessions",
                        field: "resource",
                        locator: &locator,
                        original: &resource,
                        code: "session_resource_mismatch",
                        explanation: "the prepared resource column does not equal the resourcepart of full_jid",
                        edges: &["sm-session-owner"],
                    },
                ));
            }
        }
    }
    if schema.has("users", &["id", "username"])
        && schema.has("admin_command_sessions", &["owner_id", "owner_full_jid"])
    {
        let rows = sqlx::query(
            "SELECT s.ctid::text AS locator,u.username,s.owner_full_jid
             FROM admin_command_sessions s JOIN users u ON u.id=s.owner_id ORDER BY s.ctid",
        )
        .fetch_all(&mut **transaction)
        .await?;
        for row in rows {
            let locator: String = row.try_get("locator")?;
            let username: String = row.try_get("username")?;
            let full: String = row.try_get("owner_full_jid")?;
            let expected = crate::jid::canonicalize_bare(&format!("{username}@{domain}"));
            let actual = crate::jid::canonical_bare_key(&full);
            if matches!((&expected, &actual), (Ok(expected), Ok(actual)) if expected != actual) {
                findings.push(semantic_finding(
                    reporter,
                    SemanticFinding {
                        table: "admin_command_sessions",
                        field: "owner_full_jid",
                        locator: &locator,
                        original: &full,
                        code: "session_ownership_mismatch",
                        explanation:
                            "the admin command full JID does not belong to the referenced account",
                        edges: &["admin-session-owner"],
                    },
                ));
            }
        }
    }
    findings.extend(mix_channel_collisions(transaction, schema, reporter).await?);
    findings.extend(mix_registered_nick_collisions(transaction, schema, reporter).await?);
    findings.extend(message_archive_invariants(transaction, schema, reporter).await?);
    findings.extend(personal_admission_collisions(transaction, schema, reporter).await?);
    findings.extend(muc_origin_invariants(transaction, schema, reporter).await?);
    findings.extend(mix_participant_invariants(transaction, schema, reporter).await?);
    findings.extend(mix_channel_owner_invariants(transaction, schema, reporter).await?);
    findings.extend(muc_destroy_invariants(transaction, schema, reporter, domain).await?);
    Ok(findings)
}

struct SemanticFinding<'a> {
    table: &'a str,
    field: &'a str,
    locator: &'a str,
    original: &'a str,
    code: &'static str,
    explanation: &'a str,
    edges: &'a [&'a str],
}

fn semantic_finding(reporter: &Reporter, input: SemanticFinding<'_>) -> Finding {
    Finding {
        code: input.code,
        table: input.table.to_owned(),
        field: input.field.to_owned(),
        locator: format!("{}@{}", input.table, input.locator),
        canonicalizer: "cross-column-identity-invariant",
        scope: None,
        original: Some(reporter.value(input.original)),
        canonical: None,
        related_locations: Vec::new(),
        reference_edge_ids: input
            .edges
            .iter()
            .map(|edge| (*edge).to_owned())
            .collect(),
        explanation: input.explanation.to_owned(),
        recommendation: "Verify the owning principal and repair every linked session row together on an isolated copy; stale bearer/session records should be revoked rather than reassigned by guesswork.".to_owned(),
    }
}

async fn mix_channel_collisions(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has("mix_channels", &["service_domain", "localpart"]) {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,service_domain,localpart FROM mix_channels ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut keys: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let service: String = row.try_get("service_domain")?;
        let local: String = row.try_get("localpart")?;
        if let (Ok(service), Ok(local)) = (
            crate::jid::prepare_domainpart(&service),
            crate::jid::prepare_localpart(&local),
        ) {
            keys.entry((service, local)).or_default().push((
                locator,
                format!(
                    "{}@{}",
                    row.try_get::<String, _>("localpart")?,
                    row.try_get::<String, _>("service_domain")?
                ),
            ));
        }
    }
    Ok(composite_collision_findings(
        reporter,
        "mix_channels",
        "service_domain+localpart",
        keys,
        "MIX channel addresses collide after localpart PRECIS and service-domain IDNA preparation",
        &["mix-channel-address"],
    ))
}

async fn mix_registered_nick_collisions(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has("mix_registered_nicks", &["service_domain", "jid", "nick"]) {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,service_domain,jid,nick FROM mix_registered_nicks ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut owner_keys: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    let mut nick_keys: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let original_service: String = row.try_get("service_domain")?;
        let original_jid: String = row.try_get("jid")?;
        let nick: String = row.try_get("nick")?;
        if let (Ok(service), Ok(jid)) = (
            crate::jid::prepare_domainpart(&original_service),
            IdentityKind::UserBare.canonicalize(&original_jid),
        ) {
            owner_keys
                .entry((service.clone(), jid))
                .or_default()
                .push((locator.clone(), original_jid));
            nick_keys
                .entry((service, nick.clone()))
                .or_default()
                .push((locator, nick));
        }
    }
    let mut findings = composite_collision_findings(
        reporter,
        "mix_registered_nicks",
        "service_domain+jid",
        owner_keys,
        "registered MIX ownership collides after service-domain/JID canonicalization",
        &["mix-registered-nick-owner"],
    );
    findings.extend(composite_collision_findings(
        reporter,
        "mix_registered_nicks",
        "service_domain+nick",
        nick_keys,
        "the same MIX nickname would have multiple owners after service-domain canonicalization",
        &["mix-registered-nick-owner"],
    ));
    Ok(findings)
}

fn composite_collision_findings(
    reporter: &Reporter,
    table: &str,
    field: &str,
    keys: BTreeMap<(String, String), Vec<(String, String)>>,
    explanation: &str,
    edges: &[&str],
) -> Vec<Finding> {
    keys.into_iter()
        .filter_map(|((left, right), rows)| {
            if rows.len() < 2 {
                return None;
            }
            let (locator, original) = &rows[0];
            Some(Finding {
                code: "precis_canonical_collision",
                table: table.to_owned(),
                field: field.to_owned(),
                locator: format!("{table}@{locator}"),
                canonicalizer: "composite-canonical-key",
                scope: Some(reporter.value(&left)),
                original: Some(reporter.value(original)),
                canonical: Some(reporter.value(&format!("{right}@{left}"))),
                related_locations: rows
                    .iter()
                    .skip(1)
                    .map(|(locator, _)| format!("{table}@{locator}"))
                    .collect(),
                reference_edge_ids: edges.iter().map(|edge| (*edge).to_owned()).collect(),
                explanation: explanation.to_owned(),
                recommendation: "Choose the authoritative principal/address manually and repair all referenced rows in one reviewed transaction; never select a winner automatically.".to_owned(),
            })
        })
        .collect()
}

struct InvariantFinding<'a> {
    table: &'a str,
    field: &'a str,
    locator: &'a str,
    original: Option<&'a str>,
    canonical: Option<&'a str>,
    code: &'static str,
    explanation: &'a str,
    edges: &'a [&'a str],
    related_locations: Vec<String>,
}

fn invariant_finding(reporter: &Reporter, input: InvariantFinding<'_>) -> Finding {
    Finding {
        code: input.code,
        table: input.table.to_owned(),
        field: input.field.to_owned(),
        locator: format!("{}@{}", input.table, input.locator),
        canonicalizer: "cross-row-identity-invariant",
        scope: None,
        original: input.original.map(|value| reporter.value(value)),
        canonical: input.canonical.map(|value| reporter.value(value)),
        related_locations: input.related_locations,
        reference_edge_ids: input
            .edges
            .iter()
            .map(|edge| (*edge).to_owned())
            .collect(),
        explanation: input.explanation.to_owned(),
        recommendation: "Resolve the authoritative identity and repair the complete referenced graph in one reviewed transaction on an isolated database copy; never merge automatically.".to_owned(),
    }
}

async fn message_archive_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "message_archive",
        &[
            "owner_id",
            "peer_jid",
            "peer_full_jid",
            "source_by",
            "source_stanza_id",
        ],
    ) {
        return Ok(Vec::new());
    }
    struct SourceRow {
        locator: String,
        original: String,
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,owner_id::text AS owner_id,peer_jid,peer_full_jid,
                source_by,source_stanza_id::text AS source_stanza_id
         FROM message_archive ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    let mut source_keys: BTreeMap<(String, String, String), Vec<SourceRow>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let owner: String = row.try_get("owner_id")?;
        let peer: String = row.try_get("peer_jid")?;
        let peer_full: String = row.try_get("peer_full_jid")?;
        if let (Ok(peer_key), Ok(full_key)) = (
            crate::jid::canonical_bare_key(&peer),
            crate::jid::canonical_bare_key(&peer_full),
        ) {
            if peer_key != full_key {
                findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "message_archive",
                        field: "peer_jid+peer_full_jid",
                        locator: &locator,
                        original: Some(&peer),
                        canonical: Some(&full_key),
                        code: "archive_peer_mismatch",
                        explanation: "peer_jid and the barepart of peer_full_jid identify different principals",
                        edges: &["account-principal"],
                        related_locations: Vec::new(),
                    },
                ));
            }
        }
        let source: Option<String> = row.try_get("source_by")?;
        let source_id: Option<String> = row.try_get("source_stanza_id")?;
        if let (Some(source), Some(source_id)) = (source, source_id) {
            if let Ok(canonical) = crate::jid::canonicalize_bare(&source) {
                source_keys
                    .entry((owner.clone(), canonical, source_id))
                    .or_default()
                    .push(SourceRow {
                        locator,
                        original: source,
                    });
            }
        }
    }
    for rows in source_keys.into_values().filter(|rows| rows.len() > 1) {
        findings.push(invariant_finding(
            reporter,
            InvariantFinding {
                table: "message_archive",
                field: "source_by+source_stanza_id",
                locator: &rows[0].locator,
                original: Some(&rows[0].original),
                canonical: None,
                code: "precis_canonical_collision",
                explanation:
                    "multiple archive rows would claim the same canonical stanza-id authority",
                edges: &["account-principal"],
                related_locations: rows
                    .iter()
                    .skip(1)
                    .map(|row| format!("message_archive@{}", row.locator))
                    .collect(),
            },
        ));
    }
    Ok(findings)
}

async fn personal_admission_collisions(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "personal_message_admissions",
        &[
            "identity_kind",
            "actor_scope",
            "target_scope",
            "identity_digest",
        ],
    ) {
        return Ok(Vec::new());
    }
    struct AdmissionRow {
        locator: String,
        actor: String,
        canonical_actor: String,
        canonical_target: String,
    }
    type AdmissionKey = (String, String, String, Vec<u8>);
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,identity_kind,actor_scope,target_scope,identity_digest
         FROM personal_message_admissions ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut keys: BTreeMap<AdmissionKey, Vec<AdmissionRow>> = BTreeMap::new();
    for row in rows {
        let actor: String = row.try_get("actor_scope")?;
        let target: String = row.try_get("target_scope")?;
        if let (Ok(canonical_actor), Ok(canonical_target)) = (
            crate::jid::canonicalize(&actor),
            crate::jid::canonicalize(&target),
        ) {
            let kind: String = row.try_get("identity_kind")?;
            let digest: Vec<u8> = row.try_get("identity_digest")?;
            keys.entry((
                kind,
                canonical_actor.clone(),
                canonical_target.clone(),
                digest,
            ))
            .or_default()
            .push(AdmissionRow {
                locator: row.try_get("locator")?,
                actor,
                canonical_actor,
                canonical_target,
            });
        }
    }
    Ok(keys
        .into_values()
        .filter(|rows| rows.len() > 1)
        .map(|rows| {
            invariant_finding(
                reporter,
                InvariantFinding {
                    table: "personal_message_admissions",
                    field: "identity_kind+actor_scope+target_scope+identity_digest",
                    locator: &rows[0].locator,
                    original: Some(&rows[0].actor),
                    canonical: Some(&format!(
                        "{} -> {}",
                        rows[0].canonical_actor, rows[0].canonical_target
                    )),
                    code: "precis_canonical_collision",
                    explanation:
                        "multiple admission rows become the same canonical idempotency identity",
                    edges: &["personal-admission-projections"],
                    related_locations: rows
                        .iter()
                        .skip(1)
                        .map(|row| format!("personal_message_admissions@{}", row.locator))
                        .collect(),
                },
            )
        })
        .collect())
}

fn muc_origin_digest(actor_scope: &str, origin_id: &str) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"northstar:muc-origin-id:v1\0");
    digest.update((actor_scope.len() as u32).to_be_bytes());
    digest.update(actor_scope.as_bytes());
    digest.update((origin_id.len() as u32).to_be_bytes());
    digest.update(origin_id.as_bytes());
    digest.finalize().to_vec()
}

async fn muc_origin_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "muc_origin_admissions",
        &[
            "room_id",
            "origin_digest",
            "actor_scope",
            "origin_id",
            "stanza_id",
        ],
    ) {
        return Ok(Vec::new());
    }
    struct Admission {
        locator: String,
        stanza: String,
        actor: String,
        origin: String,
        canonical_actor: String,
        canonical_digest: Vec<u8>,
    }
    let rows = sqlx::query(
        "SELECT ctid::text AS locator,room_id::text AS room_id,origin_digest,
                actor_scope,origin_id,stanza_id::text AS stanza_id
         FROM muc_origin_admissions ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    let mut keys: BTreeMap<(String, Vec<u8>), Vec<Admission>> = BTreeMap::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let actor: String = row.try_get("actor_scope")?;
        let origin: String = row.try_get("origin_id")?;
        let stored_digest: Vec<u8> = row.try_get("origin_digest")?;
        if let Ok(canonical_actor) = crate::jid::canonicalize_bare(&actor) {
            let canonical_digest = muc_origin_digest(&canonical_actor, &origin);
            if stored_digest != canonical_digest {
                findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "muc_origin_admissions",
                        field: "origin_digest",
                        locator: &locator,
                        original: Some(&actor),
                        canonical: Some(&canonical_actor),
                        code: "derived_identity_mismatch",
                        explanation: "origin_digest is not derived from the canonical actor_scope and origin_id",
                        edges: &["muc-origin-admission-message"],
                        related_locations: Vec::new(),
                    },
                ));
            }
            keys.entry((row.try_get("room_id")?, canonical_digest.clone()))
                .or_default()
                .push(Admission {
                    locator,
                    stanza: row.try_get("stanza_id")?,
                    actor,
                    origin,
                    canonical_actor,
                    canonical_digest,
                });
        }
    }
    for rows in keys.values().filter(|rows| rows.len() > 1) {
        findings.push(invariant_finding(
            reporter,
            InvariantFinding {
                table: "muc_origin_admissions",
                field: "room_id+origin_digest",
                locator: &rows[0].locator,
                original: Some(&rows[0].actor),
                canonical: Some(&rows[0].canonical_actor),
                code: "precis_canonical_collision",
                explanation: "multiple MUC admissions become the same canonical origin identity",
                edges: &["muc-origin-admission-message"],
                related_locations: rows
                    .iter()
                    .skip(1)
                    .map(|row| format!("muc_origin_admissions@{}", row.locator))
                    .collect(),
            },
        ));
    }

    if schema.has(
        "muc_messages",
        &["id", "room_id", "actor_scope", "origin_id", "origin_digest"],
    ) {
        let remaining_migration_complete = if schema.has(
            "jid_identity_migrations",
            &["migration", "canonicalizer_version"],
        ) {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                   SELECT 1 FROM jid_identity_migrations
                   WHERE migration='remaining-identity-metadata-rfc7622-ulabel-v2'
                     AND canonicalizer_version=2
                 )",
            )
            .fetch_one(&mut **transaction)
            .await?
        } else {
            false
        };
        let admissions = keys
            .into_iter()
            .flat_map(|((room, _), rows)| {
                rows.into_iter().map(move |row| {
                    (
                        room.clone(),
                        row.stanza,
                        row.canonical_actor,
                        row.origin,
                        row.canonical_digest,
                    )
                })
            })
            .collect::<HashSet<_>>();
        let messages = sqlx::query(
            "SELECT ctid::text AS locator,id::text AS id,room_id::text AS room_id,
                    actor_scope,origin_id,origin_digest
             FROM muc_messages ORDER BY ctid",
        )
        .fetch_all(&mut **transaction)
        .await?;
        for row in messages {
            let locator: String = row.try_get("locator")?;
            let actor: Option<String> = row.try_get("actor_scope")?;
            let origin: Option<String> = row.try_get("origin_id")?;
            let digest: Option<Vec<u8>> = row.try_get("origin_digest")?;
            match (actor, origin, digest) {
                (None, None, None) | (Some(_), None, None) => {}
                (Some(actor), Some(origin), Some(stored)) => {
                    if let Ok(canonical_actor) = crate::jid::canonicalize_bare(&actor) {
                        let expected = muc_origin_digest(&canonical_actor, &origin);
                        let key = (
                            row.try_get::<String, _>("room_id")?,
                            row.try_get::<String, _>("id")?,
                            canonical_actor.clone(),
                            origin.clone(),
                            expected.clone(),
                        );
                        if stored != expected
                            || (!remaining_migration_complete && !admissions.contains(&key))
                        {
                            findings.push(invariant_finding(
                                reporter,
                                InvariantFinding {
                                    table: "muc_messages",
                                    field: "actor_scope+origin_digest",
                                    locator: &locator,
                                    original: Some(&actor),
                                    canonical: Some(&canonical_actor),
                                    code: "origin_admission_mismatch",
                                    explanation: "message origin metadata has no exact canonical durable admission",
                                    edges: &["muc-origin-admission-message"],
                                    related_locations: Vec::new(),
                                },
                            ));
                        }
                    }
                }
                (actor, _, _) => findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "muc_messages",
                        field: "actor_scope+origin_id+origin_digest",
                        locator: &locator,
                        original: actor.as_deref(),
                        canonical: None,
                        code: "incomplete_origin_identity",
                        explanation: "message contains an incomplete origin identity tuple",
                        edges: &["muc-origin-admission-message"],
                        related_locations: Vec::new(),
                    },
                )),
            }
        }
    }
    Ok(findings)
}

async fn mix_participant_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "mix_participant_identities",
        &["channel_id", "participant_id", "jid"],
    ) || !schema.has("mix_participants", &["channel_id", "participant_id", "jid"])
    {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT p.ctid::text AS locator,p.jid AS participant_jid,i.jid AS identity_jid,
                (i.participant_id IS NOT NULL) AS parent_present
         FROM mix_participants p
         LEFT JOIN mix_participant_identities i
           ON i.channel_id=p.channel_id AND i.participant_id=p.participant_id
         ORDER BY p.ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let participant: String = row.try_get("participant_jid")?;
        let identity: Option<String> = row.try_get("identity_jid")?;
        let mismatch = match identity.as_deref() {
            Some(identity) => match (
                IdentityKind::UserBare.canonicalize(&participant),
                IdentityKind::UserBare.canonicalize(identity),
            ) {
                (Ok(left), Ok(right)) => left != right,
                _ => false,
            },
            None => true,
        };
        if mismatch {
            findings.push(invariant_finding(
                reporter,
                InvariantFinding {
                    table: "mix_participants",
                    field: "jid+participant_id",
                    locator: &locator,
                    original: Some(&participant),
                    canonical: identity.as_deref(),
                    code: "participant_identity_mismatch",
                    explanation: "active MIX participant does not have an exact stable participant identity parent after canonicalization",
                    edges: &["mix-participant-identity"],
                    related_locations: Vec::new(),
                },
            ));
        }
    }
    Ok(findings)
}

async fn mix_channel_owner_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
) -> Result<Vec<Finding>> {
    if !schema.has("mix_channels", &["id", "creator_jid"])
        || !schema.has("mix_channel_roles", &["channel_id", "jid", "role"])
    {
        return Ok(Vec::new());
    }
    let roles = sqlx::query(
        "SELECT channel_id::text AS channel_id,jid FROM mix_channel_roles
         WHERE role='owner' ORDER BY channel_id,jid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut canonical_roles = HashSet::new();
    for row in roles {
        let channel: String = row.try_get("channel_id")?;
        let jid: String = row.try_get("jid")?;
        if let Ok(jid) = IdentityKind::UserBare.canonicalize(&jid) {
            canonical_roles.insert((channel, jid));
        }
    }
    let channels = sqlx::query(
        "SELECT ctid::text AS locator,id::text AS channel_id,creator_jid
         FROM mix_channels ORDER BY ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    for row in channels {
        let locator: String = row.try_get("locator")?;
        let channel: String = row.try_get("channel_id")?;
        let creator: String = row.try_get("creator_jid")?;
        if let Ok(canonical) = IdentityKind::UserBare.canonicalize(&creator) {
            if !canonical_roles.contains(&(channel, canonical.clone())) {
                findings.push(invariant_finding(
                    reporter,
                    InvariantFinding {
                        table: "mix_channels",
                        field: "creator_jid",
                        locator: &locator,
                        original: Some(&creator),
                        canonical: Some(&canonical),
                        code: "mix_creator_owner_role_missing",
                        explanation: "the canonical channel creator has no canonical owner role",
                        edges: &["mix-channel-creator-role"],
                        related_locations: Vec::new(),
                    },
                ));
            }
        }
    }
    Ok(findings)
}

async fn muc_destroy_invariants(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    reporter: &Reporter,
    domain: &str,
) -> Result<Vec<Finding>> {
    if !schema.has(
        "api_muc_destroy_intents",
        &["room_jid", "localpart", "operation_id"],
    ) || !schema.has("api_operation_journal", &["id", "kind", "target"])
    {
        return Ok(Vec::new());
    }
    let conference = crate::jid::prepare_domainpart(&format!("conference.{domain}"))?;
    let rows = sqlx::query(
        "SELECT i.ctid::text AS locator,i.room_jid,i.localpart,o.kind,o.target
         FROM api_muc_destroy_intents i
         LEFT JOIN api_operation_journal o ON o.id=i.operation_id ORDER BY i.ctid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut findings = Vec::new();
    for row in rows {
        let locator: String = row.try_get("locator")?;
        let room: String = row.try_get("room_jid")?;
        let local: String = row.try_get("localpart")?;
        let kind: Option<String> = row.try_get("kind")?;
        let target: Option<String> = row.try_get("target")?;
        let valid = crate::jid::CanonicalJid::parse_bare(&room)
            .ok()
            .and_then(|jid| {
                let prepared_local = crate::jid::prepare_localpart(&local).ok()?;
                Some(
                    jid.localpart() == Some(prepared_local.as_str())
                        && jid.domainpart() == conference
                        && kind.as_deref() == Some("admin.muc_destroy")
                        && target.as_deref() == Some(jid.to_string().as_str()),
                )
            })
            .unwrap_or(false);
        if !valid {
            findings.push(invariant_finding(
                reporter,
                InvariantFinding {
                    table: "api_muc_destroy_intents",
                    field: "room_jid+localpart+operation_id",
                    locator: &locator,
                    original: Some(&room),
                    canonical: None,
                    code: "muc_destroy_identity_mismatch",
                    explanation: "destroy tombstone address, configured conference service and immutable operation kind/target disagree",
                    edges: &["muc-destroy-operation"],
                    related_locations: Vec::new(),
                },
            ));
        }
    }
    Ok(findings)
}

fn scan_specs() -> Vec<ScanSpec> {
    use IdentityKind as K;
    use ScanSource::{Column, Query};
    const NONE: &[&str] = &[];
    const USER: &[&str] = &["account-principal"];
    const PUBSUB_NODE: &[&str] = &["pubsub-node-owner"];
    const PEP_NODE: &[&str] = &["pep-node-owner"];
    const PUSH: &[&str] = &["push-attempt-subscription"];
    const MIX_CHANNEL: &[&str] = &["mix-channel-address"];
    const MIX_PARTICIPANT: &[&str] = &["mix-participant-identity"];
    const SM: &[&str] = &["sm-session-owner", "sm-resume-stanzas"];
    const ADMIN: &[&str] = &["admin-session-owner"];
    const MUC_INTENT: &[&str] = &["muc-destroy-operation"];
    const PROFILE: &[&str] = &["profile-pep-item-payload-root"];

    vec![
        ScanSpec { table: "users", field: "username", required_columns: &["username"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Localpart, collision_namespace: Some("account-username"), reference_edges: USER, remediation: "Resolve the account principal and every users(id) reference together; never merge two accounts automatically." },
        ScanSpec { table: "roster_items", field: "contact_jid", required_columns: &["owner_id", "contact_jid"], source: Column { scope_sql: "t.owner_id::text", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: Some("roster-contact"), reference_edges: USER, remediation: "Repair the owner-scoped roster key and its change-log history together." },
        ScanSpec { table: "roster_change_log", field: "contact_jid", required_columns: &["owner_id", "version", "contact_jid"], source: Column { scope_sql: "t.owner_id::text || ':' || t.version::text", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: USER, remediation: "Rewrite the historical contact identity only after its live roster principal is resolved." },
        ScanSpec { table: "blocked_jids", field: "blocked_jid", required_columns: &["owner_id", "blocked_jid"], source: Column { scope_sql: "t.owner_id::text", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: Some("blocked-jid"), reference_edges: USER, remediation: "Preserve the owner's deny policy and deduplicate only after confirming equivalent principals/resources." },
        ScanSpec { table: "federated_presence_pending", field: "from_jid", required_columns: &["recipient_id", "from_jid"], source: Column { scope_sql: "t.recipient_id::text", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: Some("pending-presence"), reference_edges: USER, remediation: "Resolve the sender principal before deduplicating pending subscription state." },
        ScanSpec { table: "mam_preference_jids", field: "jid", required_columns: &["user_id", "jid"], source: Column { scope_sql: "t.user_id::text", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: Some("mam-preference"), reference_edges: USER, remediation: "Review conflicting always/never archive policies before consolidating their keys." },
        ScanSpec { table: "muc_external_affiliations", field: "jid", required_columns: &["room_id", "jid"], source: Column { scope_sql: "t.room_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("muc-external-affiliation"), reference_edges: &["muc-room-affiliation"], remediation: "Resolve room affiliation authority manually; conflicting affiliations must not be combined by precedence guesswork." },
        ScanSpec { table: "federation_runtime_rules", field: "domain", required_columns: &["kind", "domain"], source: Column { scope_sql: "t.kind", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: Some("federation-runtime-rule"), reference_edges: NONE, remediation: "Review allow/deny policy for the canonical domain and keep one explicit rule." },

        ScanSpec { table: "pubsub_nodes", field: "creator_jid", required_columns: &["creator_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: PUBSUB_NODE, remediation: "Repair creator attribution together with node affiliations; a resourcepart is discarded only after review." },
        ScanSpec { table: "pubsub_nodes", field: "children_association_whitelist", required_columns: &["children_association_whitelist"], source: Query("SELECT t.ctid::text || '/array/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity AS value FROM pubsub_nodes t CROSS JOIN LATERAL unnest(t.children_association_whitelist) WITH ORDINALITY AS value(identity,ordinality) ORDER BY t.ctid,value.ordinality"), kind: K::BareKey, collision_namespace: Some("pubsub-child-whitelist"), reference_edges: PUBSUB_NODE, remediation: "Remove only the explicitly reviewed duplicate whitelist member and preserve collection policy." },
        ScanSpec { table: "pubsub_items", field: "publisher_jid", required_columns: &["publisher_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: PUBSUB_NODE, remediation: "Repair publisher attribution without changing the item XML payload." },
        ScanSpec { table: "pubsub_affiliations", field: "jid", required_columns: &["node_id", "jid"], source: Column { scope_sql: "t.node_id::text", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: Some("pubsub-affiliation"), reference_edges: PUBSUB_NODE, remediation: "Resolve conflicting node affiliations explicitly before changing the key." },
        ScanSpec { table: "pubsub_subscriptions", field: "jid", required_columns: &["node_id", "jid"], source: Column { scope_sql: "t.node_id::text", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: Some("pubsub-subscription"), reference_edges: PUBSUB_NODE, remediation: "Resolve subscription ownership and subid state before deduplicating." },
        ScanSpec { table: "pubsub_digest_queue", field: "subscriber_jid", required_columns: &["subscriber_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: &["pubsub-digest-subscription"], remediation: "Repair the queue recipient consistently with its subscription; do not inspect or rewrite event XML in this audit." },
        ScanSpec { table: "pep_nodes", field: "access_whitelist", required_columns: &["access_whitelist"], source: Query("SELECT t.ctid::text || '/array/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity AS value FROM pep_nodes t CROSS JOIN LATERAL unnest(t.access_whitelist) WITH ORDINALITY AS value(identity,ordinality) ORDER BY t.ctid,value.ordinality"), kind: K::BareKey, collision_namespace: Some("pep-access-whitelist"), reference_edges: PEP_NODE, remediation: "Review and deduplicate the owner/node access policy explicitly." },
        ScanSpec { table: "pep_subscriptions", field: "subscriber_jid", required_columns: &["owner_id", "node", "subscriber_jid"], source: Column { scope_sql: "t.owner_id::text || ':' || t.node", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: Some("pep-subscription"), reference_edges: PEP_NODE, remediation: "Resolve full-JID subscriber/subid ownership without collapsing case-sensitive resourceparts." },

        ScanSpec { table: "push_subscriptions", field: "service_jid", required_columns: &["user_id", "service_jid", "node"], source: Column { scope_sql: "t.user_id::text || ':' || COALESCE(t.node,'')", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: Some("push-subscription"), reference_edges: PUSH, remediation: "Rewrite the parent subscription and all delivery attempts atomically after resolving any duplicate service." },
        ScanSpec { table: "push_delivery_attempts", field: "service_jid", required_columns: &["user_id", "service_jid", "node"], source: Column { scope_sql: "t.user_id::text || ':' || COALESCE(t.node,'')", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: PUSH, remediation: "Keep the attempt key identical to its parent push subscription." },

        ScanSpec { table: "mix_channels", field: "service_domain", required_columns: &["service_domain"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair service_domain together with localpart and every channel reference." },
        ScanSpec { table: "mix_channels", field: "localpart", required_columns: &["localpart"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Localpart, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair localpart together with service_domain and every channel reference." },
        ScanSpec { table: "mix_channels", field: "creator_jid", required_columns: &["creator_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: None, reference_edges: &["mix-channel-creator-role"], remediation: "Ensure the canonical creator still has the channel owner role." },
        ScanSpec { table: "mix_channels", field: "contacts", required_columns: &["contacts"], source: Query("SELECT t.ctid::text || '/json/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity #>> '{}' AS value FROM mix_channels t CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t.contacts)='array' THEN t.contacts ELSE '[]'::jsonb END) WITH ORDINALITY AS value(identity,ordinality) WHERE jsonb_typeof(value.identity)='string' ORDER BY t.ctid,value.ordinality"), kind: K::UserBare, collision_namespace: Some("mix-channel-contact"), reference_edges: MIX_CHANNEL, remediation: "Remove only reviewed duplicate contacts and preserve contact ordering intentionally." },
        ScanSpec { table: "mix_participant_identities", field: "jid", required_columns: &["channel_id", "jid"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-participant-identity"), reference_edges: MIX_PARTICIPANT, remediation: "Resolve the stable participant ID and active participant row as one graph." },
        ScanSpec { table: "mix_participants", field: "jid", required_columns: &["channel_id", "jid"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-active-participant"), reference_edges: MIX_PARTICIPANT, remediation: "Keep the active participant's JID and stable identity parent consistent." },
        ScanSpec { table: "mix_channel_roles", field: "jid", required_columns: &["channel_id", "jid"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-channel-role"), reference_edges: &["mix-channel-creator-role"], remediation: "Resolve owner/administrator authorization explicitly before consolidating keys." },
        ScanSpec { table: "mix_allowed", field: "jid_pattern", required_columns: &["channel_id", "jid_pattern"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::AccessPattern, collision_namespace: Some("mix-access-policy"), reference_edges: MIX_CHANNEL, remediation: "Choose one allow/ban outcome explicitly; a canonical identity cannot remain in both lists." },
        ScanSpec { table: "mix_banned", field: "jid_pattern", required_columns: &["channel_id", "jid_pattern"], source: Column { scope_sql: "t.channel_id::text", predicate_sql: "TRUE" }, kind: K::AccessPattern, collision_namespace: Some("mix-access-policy"), reference_edges: MIX_CHANNEL, remediation: "Choose one allow/ban outcome explicitly; a canonical identity cannot remain in both lists." },
        ScanSpec { table: "mix_allowed", field: "added_by", required_columns: &["added_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair historical policy attribution only after confirming the actor principal." },
        ScanSpec { table: "mix_banned", field: "added_by", required_columns: &["added_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair historical policy attribution only after confirming the actor principal." },
        ScanSpec { table: "mix_pam_memberships", field: "channel_jid", required_columns: &["user_id", "channel_jid"], source: Column { scope_sql: "t.user_id::text", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-pam-membership"), reference_edges: USER, remediation: "Resolve the account's channel membership and pending request state before deduplicating." },
        ScanSpec { table: "mix_pam_memberships", field: "requester_full_jid", required_columns: &["requester_full_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::SessionFull, collision_namespace: None, reference_edges: USER, remediation: "Revoke an unowned or malformed pending requester session instead of reassigning it." },
        ScanSpec { table: "mix_registered_nicks", field: "service_domain", required_columns: &["service_domain"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: None, reference_edges: &["mix-registered-nick-owner"], remediation: "Repair the service scope together with JID and nickname uniqueness." },
        ScanSpec { table: "mix_registered_nicks", field: "jid", required_columns: &["service_domain", "jid"], source: Column { scope_sql: "t.service_domain", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("mix-registered-jid"), reference_edges: &["mix-registered-nick-owner"], remediation: "Resolve the registered nickname owner explicitly." },
        ScanSpec { table: "mix_invitations", field: "inviter_jid", required_columns: &["inviter_jid", "consumed_at", "expires_at"], source: Column { scope_sql: "''", predicate_sql: "t.consumed_at IS NULL AND t.expires_at > clock_timestamp()" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair or revoke the active invitation; never expose or regenerate its token." },
        ScanSpec { table: "mix_invitations", field: "invitee_jid", required_columns: &["invitee_jid", "consumed_at", "expires_at"], source: Column { scope_sql: "''", predicate_sql: "t.consumed_at IS NULL AND t.expires_at > clock_timestamp()" }, kind: K::UserBare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair or revoke the active invitation; never expose or regenerate its token." },

        ScanSpec { table: "pep_items", field: "item_id", required_columns: &["owner_id", "node", "item_id"], source: Column { scope_sql: "t.owner_id::text || ':' || t.node", predicate_sql: "t.node IN ('urn:xmpp:bookmarks:1','urn:xmpp:contacts')" }, kind: K::UserBare, collision_namespace: Some("profile-pep-item"), reference_edges: PROFILE, remediation: "Use the dedicated profile ItemID repair on an isolated copy so the key and XML root id change atomically; this audit intentionally does not read payload XML." },
        ScanSpec { table: "sm_resume_sessions", field: "full_jid", required_columns: &["user_id", "full_jid"], source: Column { scope_sql: "t.user_id::text", predicate_sql: "TRUE" }, kind: K::SessionFull, collision_namespace: Some("sm-session-full-jid"), reference_edges: SM, remediation: "Resolve ownership and revoke stale colliding sessions rather than merging bearer state." },
        ScanSpec { table: "sm_resume_sessions", field: "resource", required_columns: &["resource"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Resource, collision_namespace: None, reference_edges: SM, remediation: "Keep the resource exactly equal to the full_jid resourcepart; resourceparts are case-sensitive." },
        ScanSpec { table: "sm_resume_sessions", field: "joined_rooms", required_columns: &["joined_rooms"], source: Query("SELECT t.ctid::text || '/joined/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.membership->>'room_jid' AS value FROM sm_resume_sessions t CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t.joined_rooms)='array' THEN t.joined_rooms ELSE '[]'::jsonb END) WITH ORDINALITY AS value(membership,ordinality) WHERE jsonb_typeof(value.membership)='object' AND jsonb_typeof(value.membership->'room_jid')='string' ORDER BY t.ctid,value.ordinality"), kind: K::UserBare, collision_namespace: Some("sm-joined-room"), reference_edges: SM, remediation: "Resolve duplicate room membership state within the suspended session before rewriting JSON." },
        ScanSpec { table: "sm_resume_sessions", field: "directed_presence", required_columns: &["directed_presence"], source: Query("SELECT t.ctid::text || '/directed/' || value.ordinality::text AS locator,t.ctid::text AS scope,value.identity #>> '{}' AS value FROM sm_resume_sessions t CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(t.directed_presence)='array' THEN t.directed_presence ELSE '[]'::jsonb END) WITH ORDINALITY AS value(identity,ordinality) WHERE jsonb_typeof(value.identity)='string' ORDER BY t.ctid,value.ordinality"), kind: K::Full, collision_namespace: Some("sm-directed-presence"), reference_edges: SM, remediation: "Resolve duplicate directed-presence targets within the suspended session before rewriting JSON." },
        ScanSpec { table: "admin_command_sessions", field: "owner_full_jid", required_columns: &["owner_id", "owner_full_jid"], source: Column { scope_sql: "t.owner_id::text", predicate_sql: "TRUE" }, kind: K::SessionFull, collision_namespace: None, reference_edges: ADMIN, remediation: "Revoke a malformed/unowned command session; never transfer privileged session state automatically." },
        ScanSpec { table: "api_muc_destroy_intents", field: "room_jid", required_columns: &["room_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::UserBare, collision_namespace: Some("muc-destroy-room"), reference_edges: MUC_INTENT, remediation: "Repair the tombstone and immutable operation target together using a reviewed control-plane procedure." },
        ScanSpec { table: "api_muc_destroy_intents", field: "localpart", required_columns: &["localpart"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Localpart, collision_namespace: Some("muc-destroy-localpart"), reference_edges: MUC_INTENT, remediation: "Keep localpart equal to room_jid localpart and the configured conference service." },

        ScanSpec { table: "offline_messages", field: "sender_jid", required_columns: &["sender_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: USER, remediation: "Repair only sender identity metadata; this audit never reads or rewrites the stanza." },
        ScanSpec { table: "message_archive", field: "peer_jid", required_columns: &["peer_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: USER, remediation: "Repair archive identity metadata without reading or rewriting archived stanza content." },
        ScanSpec { table: "message_archive", field: "peer_full_jid", required_columns: &["peer_full_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: USER, remediation: "Keep peer_full_jid's bare key consistent with peer_jid while preserving an opaque resourcepart." },
        ScanSpec { table: "message_archive", field: "source_by", required_columns: &["source_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: USER, remediation: "Resolve the stanza-id authority before changing archive metadata; never inspect content in this tool." },
        ScanSpec { table: "personal_message_admissions", field: "actor_scope", required_columns: &["actor_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["personal-admission-projections"], remediation: "Repair actor/target scopes and every durable projection as one admission identity; never inspect content commitments." },
        ScanSpec { table: "personal_message_admissions", field: "target_scope", required_columns: &["target_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["personal-admission-projections"], remediation: "Repair actor/target scopes and every durable projection as one admission identity; never inspect content commitments." },
        ScanSpec { table: "muc_origin_admissions", field: "actor_scope", required_columns: &["actor_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["muc-origin-admission-message"], remediation: "Recompute the admission digest using the reviewed origin-id procedure; never guess which colliding event survives." },
        ScanSpec { table: "muc_rooms", field: "subject_set_by", required_columns: &["subject_set_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["muc-room-affiliation"], remediation: "Repair subject attribution independently of subject text." },
        ScanSpec { table: "muc_rooms", field: "configuration_owner_jid", required_columns: &["configuration_owner_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["muc-room-affiliation"], remediation: "Verify configuration authority against current room ownership before changing it." },
        ScanSpec { table: "muc_messages", field: "sender_jid", required_columns: &["sender_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["muc-origin-admission-message"], remediation: "Repair sender metadata without reading or rewriting the archived stanza." },
        ScanSpec { table: "muc_messages", field: "actor_scope", required_columns: &["actor_scope"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["muc-origin-admission-message"], remediation: "Keep actor scope and origin admission digest consistent." },
        ScanSpec { table: "abuse_reports", field: "reported_jid", required_columns: &["reported_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::BareKey, collision_namespace: None, reference_edges: &["abuse-report-evidence"], remediation: "Repair only the reported principal metadata; descriptions and evidence content are deliberately outside this audit." },
        ScanSpec { table: "abuse_report_evidence", field: "sender_jid", required_columns: &["sender_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: &["abuse-report-evidence"], remediation: "Repair only sender metadata; body_text is deliberately not read." },
        ScanSpec { table: "s2s_outbox", field: "target_domain", required_columns: &["target_domain", "dedupe_hash"], source: Column { scope_sql: "encode(t.dedupe_hash,'hex')", predicate_sql: "TRUE" }, kind: K::Domain, collision_namespace: Some("s2s-target-dedupe"), reference_edges: NONE, remediation: "Resolve canonical target/dedupe collisions before rewriting; stanza content is deliberately not read." },
        ScanSpec { table: "s2s_outbox", field: "bounce_to", required_columns: &["bounce_to"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Full, collision_namespace: None, reference_edges: NONE, remediation: "Repair the bounce identity without reading or rewriting the queued stanza." },
        ScanSpec { table: "privacy_list_items", field: "match_value", required_columns: &["match_type", "match_value"], source: Column { scope_sql: "''", predicate_sql: "t.match_type='jid'" }, kind: K::Full, collision_namespace: None, reference_edges: USER, remediation: "Review privacy-list first-match semantics before changing a JID match value." },
        ScanSpec { table: "mix_events", field: "publisher_jid", required_columns: &["publisher_jid"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Repair publisher metadata only; event payload is deliberately not read." },
        ScanSpec { table: "mix_events", field: "source_full_jid", required_columns: &["node", "source_full_jid"], source: Column { scope_sql: "''", predicate_sql: "t.node='urn:xmpp:mix:nodes:presence'" }, kind: K::SessionFull, collision_namespace: None, reference_edges: MIX_CHANNEL, remediation: "Preserve the case-sensitive resourcepart in historical presence attribution." },
        ScanSpec { table: "mix_events", field: "item_id", required_columns: &["channel_id", "node", "item_id"], source: Column { scope_sql: "t.channel_id::text || ':' || t.node", predicate_sql: "t.node IN ('urn:xmpp:mix:nodes:allowed','urn:xmpp:mix:nodes:banned')" }, kind: K::AccessPattern, collision_namespace: Some("mix-event-policy-item"), reference_edges: MIX_CHANNEL, remediation: "Repair the event key only with a payload-aware procedure; payload is deliberately not read by this audit." },
        ScanSpec { table: "mix_events", field: "item_id", required_columns: &["channel_id", "node", "item_id"], source: Column { scope_sql: "t.channel_id::text || ':' || t.node", predicate_sql: "t.node='urn:xmpp:mix:nodes:presence'" }, kind: K::SessionFull, collision_namespace: Some("mix-event-presence-item"), reference_edges: MIX_CHANNEL, remediation: "Repair the event key only with a payload-aware procedure; resourceparts remain case-sensitive." },
        ScanSpec { table: "mix_muc_mirrors", field: "created_by", required_columns: &["created_by"], source: Column { scope_sql: "''", predicate_sql: "TRUE" }, kind: K::Bare, collision_namespace: None, reference_edges: &["mix-muc-mirror"], remediation: "Verify the mirror creator against MUC/MIX ownership before changing attribution." },
    ]
}

async fn load_reference_graph(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &SchemaMap,
    specs: &[ScanSpec],
) -> Result<Vec<ReferenceEdge>> {
    let audited = specs.iter().map(|spec| spec.table).collect::<HashSet<_>>();
    let mut edges = Vec::new();
    let rows = sqlx::query(
        "SELECT c.conname,
                c.conrelid::regclass::text AS source_table,
                c.confrelid::regclass::text AS target_table,
                pg_get_constraintdef(c.oid,false) AS definition
         FROM pg_constraint c
         JOIN pg_namespace n ON n.oid=c.connamespace
         WHERE c.contype='f' AND n.nspname=current_schema()
         ORDER BY source_table,c.conname",
    )
    .fetch_all(&mut **transaction)
    .await?;
    for row in rows {
        let source: String = row.try_get("source_table")?;
        let target: String = row.try_get("target_table")?;
        let source_name = source
            .rsplit('.')
            .next()
            .unwrap_or(&source)
            .trim_matches('"');
        let target_name = target
            .rsplit('.')
            .next()
            .unwrap_or(&target)
            .trim_matches('"');
        if !audited.contains(source_name) && !audited.contains(target_name) {
            continue;
        }
        let name: String = row.try_get("conname")?;
        edges.push(ReferenceEdge {
            id: format!("fk:{source_name}:{name}"),
            kind: "database-foreign-key",
            source,
            target,
            relationship: row.try_get("definition")?,
            row_data_inspected: false,
        });
    }

    struct StaticEdge {
        id: &'static str,
        source_table: &'static str,
        target_table: &'static str,
        source: &'static str,
        target: &'static str,
        relationship: &'static str,
    }
    const STATIC: &[StaticEdge] = &[
        StaticEdge { id: "account-principal", source_table: "users", target_table: "roster_items", source: "users.username + configured XMPP domain", target: "account-owned identity-bearing rows", relationship: "users.id foreign keys and reconstructed bare JID define the account principal" },
        StaticEdge { id: "pubsub-node-owner", source_table: "pubsub_nodes", target_table: "pubsub_affiliations", source: "pubsub_nodes.creator_jid", target: "pubsub_affiliations/subscriptions/items", relationship: "creator, authorization keys, subscriptions and item attribution share one node identity graph" },
        StaticEdge { id: "pubsub-digest-subscription", source_table: "pubsub_digest_queue", target_table: "pubsub_subscriptions", source: "pubsub_digest_queue.subscription_node_id + subscriber_jid", target: "pubsub_subscriptions.node_id + jid", relationship: "semantic queue recipient must remain the canonical subscription recipient; queue XML is not inspected" },
        StaticEdge { id: "pep-node-owner", source_table: "pep_nodes", target_table: "pep_subscriptions", source: "pep_nodes(owner_id,node)", target: "pep_subscriptions and access_whitelist", relationship: "PEP access and subscriber identities are owner/node scoped" },
        StaticEdge { id: "push-attempt-subscription", source_table: "push_delivery_attempts", target_table: "push_subscriptions", source: "push_delivery_attempts(user_id,service_jid,node)", target: "push_subscriptions(user_id,service_jid,node)", relationship: "delivery attempt is a composite foreign-key child of the push subscription" },
        StaticEdge { id: "mix-channel-address", source_table: "mix_channels", target_table: "mix_participants", source: "mix_channels(service_domain,localpart)", target: "all channel_id children and address-derived protocol state", relationship: "MIX channel address is a composite canonical key; every channel_id child follows it" },
        StaticEdge { id: "mix-channel-creator-role", source_table: "mix_channels", target_table: "mix_channel_roles", source: "mix_channels.creator_jid", target: "mix_channel_roles jid where role=owner", relationship: "the canonical channel creator must retain an owner role" },
        StaticEdge { id: "mix-participant-identity", source_table: "mix_participants", target_table: "mix_participant_identities", source: "mix_participants(channel_id,jid,participant_id)", target: "mix_participant_identities(channel_id,jid,participant_id)", relationship: "active participant must match the stable participant identity in both JID and participant ID" },
        StaticEdge { id: "mix-registered-nick-owner", source_table: "mix_registered_nicks", target_table: "mix_channels", source: "mix_registered_nicks(service_domain,jid,nick)", target: "MIX service scope", relationship: "both canonical owner JID and nickname are unique within canonical service_domain" },
        StaticEdge { id: "sm-session-owner", source_table: "sm_resume_sessions", target_table: "users", source: "sm_resume_sessions(user_id,full_jid,resource)", target: "users(id,username) + configured XMPP domain", relationship: "full JID barepart belongs to the referenced account and resource equals its opaque resourcepart" },
        StaticEdge { id: "sm-resume-stanzas", source_table: "sm_resume_stanzas", target_table: "sm_resume_sessions", source: "sm_resume_stanzas.session_id", target: "sm_resume_sessions.id", relationship: "queued stanzas follow a session, but stanza bytes are never inspected by this audit" },
        StaticEdge { id: "admin-session-owner", source_table: "admin_command_sessions", target_table: "users", source: "admin_command_sessions(owner_id,owner_full_jid)", target: "users(id,username) + configured XMPP domain", relationship: "privileged command session full JID must belong to its owner account" },
        StaticEdge { id: "muc-destroy-operation", source_table: "api_muc_destroy_intents", target_table: "api_operation_journal", source: "api_muc_destroy_intents(operation_id,room_jid,localpart)", target: "api_operation_journal(id,kind,target)", relationship: "destroy tombstone address and immutable operation target agree; operation payload is deliberately not inspected" },
        StaticEdge { id: "profile-pep-item-payload-root", source_table: "pep_items", target_table: "pep_items", source: "profile pep_items.item_id", target: "root id attribute in the same row payload", relationship: "key and XML root id must change atomically in a dedicated content-aware repair; payload is deliberately not inspected" },
        StaticEdge { id: "personal-admission-projections", source_table: "personal_message_admissions", target_table: "message_archive", source: "personal_message_admissions identity tuple", target: "archive/offline/S2S/durable delivery projection IDs", relationship: "admission identity and all recoverable projections form one idempotency graph" },
        StaticEdge { id: "muc-origin-admission-message", source_table: "muc_origin_admissions", target_table: "muc_messages", source: "canonical actor_scope + origin_id digest", target: "muc_messages origin_digest/actor_scope", relationship: "canonical actor changes require digest recomputation and atomic admission/message repair" },
        StaticEdge { id: "muc-room-affiliation", source_table: "muc_rooms", target_table: "muc_external_affiliations", source: "MUC room identity and attribution", target: "local/external affiliation authorization", relationship: "room attribution must remain consistent with owner/admin/member authority" },
        StaticEdge { id: "abuse-report-evidence", source_table: "abuse_reports", target_table: "abuse_report_evidence", source: "abuse_reports.reported_jid", target: "abuse_report_evidence.sender_jid", relationship: "identity metadata is linked by report_id; descriptions and evidence body are never inspected" },
        StaticEdge { id: "mix-muc-mirror", source_table: "mix_muc_mirrors", target_table: "mix_channels", source: "mix_muc_mirrors(created_by,mix_channel_id,muc_room_id)", target: "MIX channel and MUC room ownership", relationship: "mirror creator attribution crosses the MIX/MUC identity graph" },
    ];
    for edge in STATIC {
        if schema.tables.contains_key(edge.source_table)
            || schema.tables.contains_key(edge.target_table)
        {
            edges.push(ReferenceEdge {
                id: edge.id.to_owned(),
                kind: "semantic-identity-edge",
                source: edge.source.to_owned(),
                target: edge.target.to_owned(),
                relationship: edge.relationship.to_owned(),
                row_data_inspected: false,
            });
        }
    }
    edges.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(edges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_requires_an_explicit_dry_run_and_rejects_unknown_flags() {
        let error = parse_options(&[]).unwrap_err().to_string();
        assert!(error.contains("--dry-run"));
        let error = parse_options(&["--dry-run".into(), "--repair".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown audit option"));
        let options = parse_options(&[
            "--dry-run".into(),
            "--xmpp-domain".into(),
            "XN--BCHER-KVA.example.".into(),
        ])
        .unwrap();
        assert_eq!(options.domain, "bücher.example");
    }

    #[test]
    fn default_json_never_contains_the_identity_value() {
        let reporter = Reporter {
            include_values: false,
            salt: [7; 32],
        };
        let secret_identity = "Alice@XN--BCHER-KVA.example/Phone";
        let encoded = serde_json::to_string(&reporter.value(secret_identity)).unwrap();
        assert!(!encoded.contains(secret_identity));
        assert!(!encoded.contains("Alice"));
        assert!(encoded.contains("report-local-sha256"));
        let second = reporter.value(secret_identity);
        assert_eq!(
            second.fingerprint,
            reporter.value(secret_identity).fingerprint
        );
    }

    #[test]
    fn raw_values_require_the_explicit_sensitive_mode() {
        let reporter = Reporter {
            include_values: true,
            salt: [9; 32],
        };
        assert_eq!(
            reporter.value("alice@example.test").value.as_deref(),
            Some("alice@example.test")
        );
    }

    #[test]
    fn detects_precis_and_alabel_ulabel_collision_classes() {
        let reporter = Reporter {
            include_values: false,
            salt: [1; 32],
        };
        let rows = vec![
            ScannedIdentity {
                table: "roster_items",
                field: "contact_jid",
                locator: "(0,1)".into(),
                scope: "owner".into(),
                original: "ALICE@xn--bcher-kva.example".into(),
                canonical: "alice@bücher.example".into(),
                namespace: "roster",
                reference_edges: &[],
            },
            ScannedIdentity {
                table: "roster_items",
                field: "contact_jid",
                locator: "(0,2)".into(),
                scope: "owner".into(),
                original: "alice@bücher.example".into(),
                canonical: "alice@bücher.example".into(),
                namespace: "roster",
                reference_edges: &[],
            },
        ];
        let findings = collision_findings(&reporter, rows);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "idna_alabel_ulabel_collision");

        let rows = vec![
            ScannedIdentity {
                table: "users",
                field: "username",
                locator: "(0,1)".into(),
                scope: String::new(),
                original: "A\u{30a}LICE".into(),
                canonical: "ålice".into(),
                namespace: "users",
                reference_edges: &[],
            },
            ScannedIdentity {
                table: "users",
                field: "username",
                locator: "(0,2)".into(),
                scope: String::new(),
                original: "ålice".into(),
                canonical: "ålice".into(),
                namespace: "users",
                reference_edges: &[],
            },
        ];
        assert_eq!(
            collision_findings(&reporter, rows)[0].code,
            "precis_canonical_collision"
        );
    }

    #[test]
    fn scan_inventory_is_unique_and_never_selects_content_or_secret_columns() {
        let specs = scan_specs();
        let mut identities = BTreeSet::new();
        for spec in &specs {
            assert!(identities.insert((
                spec.table,
                spec.field,
                spec.kind.name(),
                match spec.source {
                    ScanSource::Column { predicate_sql, .. } => predicate_sql,
                    ScanSource::Query(query) => query,
                }
            )));
            let query = query_for(spec).to_ascii_lowercase();
            for forbidden in [
                "password_hash",
                "scram_",
                "token_hash",
                "body_text",
                "description",
                "resolution",
                "event_xml",
                "xml_payload",
                "payload_value",
                "select payload",
                "select stanza",
                ".stanza",
                ".payload",
            ] {
                assert!(
                    !query.contains(forbidden),
                    "{}.{}, forbidden token {forbidden}: {query}",
                    spec.table,
                    spec.field
                );
            }
        }
        assert!(specs.len() >= 55, "identity coverage unexpectedly shrank");
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL schema"]
    async fn postgres_audit_reports_all_rows_and_leaves_the_database_unchanged() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL schema");
        let setup = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate::Migrator::new(std::path::Path::new("migrations"))
            .await
            .unwrap()
            .run(&setup)
            .await
            .unwrap();
        let first_domain = format!("xn--bcher-kva.audit-{}.example", Uuid::new_v4().simple());
        let canonical = crate::jid::prepare_domainpart(&first_domain).unwrap();
        sqlx::query("INSERT INTO federation_runtime_rules(kind,domain) VALUES('blacklist',$1),('blacklist',$2)")
            .bind(&first_domain)
            .bind(&canonical)
            .execute(&setup)
            .await
            .unwrap();
        let before: Vec<String> = sqlx::query_scalar("SELECT domain FROM federation_runtime_rules WHERE domain=$1 OR domain=$2 ORDER BY domain")
            .bind(&first_domain)
            .bind(&canonical)
            .fetch_all(&setup)
            .await
            .unwrap();
        setup.close().await;

        let audit_pool = read_only_pool(&url).await.unwrap();
        let report = audit_database(
            &audit_pool,
            &AuditOptions {
                domain: "localhost".into(),
                include_sensitive_values: false,
                compact: true,
            },
        )
        .await
        .unwrap();
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "idna_alabel_ulabel_collision"));
        audit_pool.close().await;

        let verify = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let after: Vec<String> = sqlx::query_scalar("SELECT domain FROM federation_runtime_rules WHERE domain=$1 OR domain=$2 ORDER BY domain")
            .bind(&first_domain)
            .bind(&canonical)
            .fetch_all(&verify)
            .await
            .unwrap();
        assert_eq!(before, after);
        sqlx::query("DELETE FROM federation_runtime_rules WHERE domain=$1 OR domain=$2")
            .bind(&first_domain)
            .bind(&canonical)
            .execute(&verify)
            .await
            .unwrap();
        verify.close().await;

        let clean_pool = read_only_pool(&url).await.unwrap();
        for _ in 0..2 {
            let clean = audit_database(
                &clean_pool,
                &AuditOptions {
                    domain: "localhost".into(),
                    include_sensitive_values: false,
                    compact: true,
                },
            )
            .await
            .unwrap();
            assert!(clean.findings.is_empty(), "clean audit was not idempotent");
        }
        clean_pool.close().await;
    }
}
