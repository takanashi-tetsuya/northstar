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
    let canonical = northstar_xmpp_types::jid::prepare_domainpart(&first_domain).unwrap();
    sqlx::query(
        "INSERT INTO federation_runtime_rules(kind,domain) VALUES('blacklist',$1),('blacklist',$2)",
    )
    .bind(&first_domain)
    .bind(&canonical)
    .execute(&setup)
    .await
    .unwrap();
    let before: Vec<String> = sqlx::query_scalar(
        "SELECT domain FROM federation_runtime_rules WHERE domain=$1 OR domain=$2 ORDER BY domain",
    )
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
    let after: Vec<String> = sqlx::query_scalar(
        "SELECT domain FROM federation_runtime_rules WHERE domain=$1 OR domain=$2 ORDER BY domain",
    )
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
