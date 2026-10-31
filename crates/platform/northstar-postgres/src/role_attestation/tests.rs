use super::*;

fn runtime_relation_manifest_with_rows(rows: &str) -> String {
    format!(
        "INSERT INTO pg_temp.northstar_runtime_relation_manifest(\n\
         relation_name,can_select,can_insert,can_update,can_delete,origin\n\
         )\n\
         VALUES\n{rows};"
    )
}

#[test]
fn embedded_capability_manifest_is_complete_and_partitioned() {
    let (signatures, workloads) = security_definer_capability_manifest().unwrap();
    assert_eq!(signatures.len(), workloads.len());
    assert!(workloads.iter().any(|workload| workload == "runtime"));
    assert!(workloads.iter().any(|workload| workload == "command"));
    assert!(workloads.iter().any(|workload| workload == "storage"));
    assert_eq!(
        workloads
            .iter()
            .filter(|workload| workload.as_str() == "storage")
            .count(),
        37
    );
    assert!(workloads.iter().any(|workload| workload == "private"));
    let retention = signatures
        .iter()
        .position(|signature| signature == "northstar_session_recovery_retention(uuid,timestamptz)")
        .expect("SM retention capability is absent");
    assert_eq!(workloads[retention], "runtime");
    assert!(signatures
        .iter()
        .all(|signature| signature.contains('(') && signature.ends_with(')')));
    for signature in [
        "northstar_sm_state_version()",
        "northstar_sm_state_notify()",
    ] {
        let index = signatures
            .iter()
            .position(|candidate| candidate == signature)
            .expect("SM event-authority capability is absent");
        assert_eq!(workloads[index], "private");
    }
}

#[test]
fn capability_manifest_parser_rejects_sql_bearing_signatures() {
    let malformed = "INSERT INTO pg_temp.northstar_capability_manifest VALUES\n\
        ('safe();drop_table()','runtime','0114');";
    assert!(parse_security_definer_capability_manifest(malformed).is_err());
}

#[test]
fn embedded_runtime_relation_manifest_is_complete_and_exact() {
    let manifest = parse_runtime_relation_manifest(CAPABILITY_MANIFEST_SQL).unwrap();
    assert!(manifest.relation_names.len() > 100);
    assert_eq!(manifest.relation_names.len(), manifest.can_select.len());
    assert_eq!(manifest.relation_names.len(), manifest.can_insert.len());
    assert_eq!(manifest.relation_names.len(), manifest.can_update.len());
    assert_eq!(manifest.relation_names.len(), manifest.can_delete.len());
    assert_eq!(manifest.relation_names.len(), manifest.origins.len());

    for (relation_name, expected, origin) in [
        ("_sqlx_migrations", [true, false, false, false], "sqlx"),
        ("sm_resume_sessions", [false, false, false, false], "0028"),
        ("mix_pam_operations", [true, false, true, false], "0123"),
        (
            "mix_delivery_capacity_releases",
            [true, false, false, false],
            "0126",
        ),
        (
            "mix_pam_operation_capacity",
            [true, false, false, false],
            "0128",
        ),
    ] {
        let index = manifest
            .relation_names
            .iter()
            .position(|candidate| candidate == relation_name)
            .unwrap_or_else(|| panic!("runtime relation {relation_name} is absent"));
        assert_eq!(
            [
                manifest.can_select[index],
                manifest.can_insert[index],
                manifest.can_update[index],
                manifest.can_delete[index],
            ],
            expected
        );
        assert_eq!(manifest.origins[index], origin);
    }
}

#[test]
fn runtime_relation_manifest_parser_preserves_rows_and_origins() {
    let source = runtime_relation_manifest_with_rows(
        "  ('_sqlx_migrations',TRUE,FALSE,FALSE,FALSE,'sqlx'),\n\
         ('mutable_table',TRUE,TRUE,TRUE,TRUE,'0128')",
    );
    let manifest = parse_runtime_relation_manifest(&source).unwrap();
    assert_eq!(
        manifest,
        RuntimeRelationManifest {
            relation_names: vec!["_sqlx_migrations".into(), "mutable_table".into()],
            can_select: vec![true, true],
            can_insert: vec![false, true],
            can_update: vec![false, true],
            can_delete: vec![false, true],
            origins: vec!["sqlx".into(), "0128".into()],
        }
    );
}

#[test]
fn runtime_relation_manifest_parser_rejects_unsafe_or_ambiguous_rows() {
    for rows in [
        "  ('duplicate',TRUE,FALSE,FALSE,FALSE,'0001'),\n\
         ('duplicate',TRUE,FALSE,FALSE,FALSE,'0002')",
        "  ('UnsafeName',TRUE,FALSE,FALSE,FALSE,'0001')",
        "  ('unsafe;drop',TRUE,FALSE,FALSE,FALSE,'0001')",
        "  ('bad_origin',TRUE,FALSE,FALSE,FALSE,'0000')",
        "  ('bad_origin',TRUE,FALSE,FALSE,FALSE,'latest')",
        "  ('bad_boolean',true,FALSE,FALSE,FALSE,'0001')",
        "  ('trailing_sql',TRUE,FALSE,FALSE,FALSE,'0001') SELECT 1",
    ] {
        let source = runtime_relation_manifest_with_rows(rows);
        assert!(
            parse_runtime_relation_manifest(&source).is_err(),
            "malformed relation manifest row was accepted: {rows}"
        );
    }
}

#[test]
fn embedded_migration_ledger_is_complete_and_preserves_intentional_gaps() {
    let manifest = parse_migration_ledger_manifest(MIGRATION_LEDGER_MANIFEST_SQL).unwrap();
    assert_eq!(manifest.versions.len(), manifest.descriptions.len());
    assert_eq!(manifest.versions.len(), manifest.checksum_hex.len());
    assert!(manifest.versions.contains(&113));
    assert!(manifest.versions.contains(&114));
    assert!(manifest.versions.contains(&115));
    // The ledger has one intentional historical gap (0021).  Keep this
    // assertion exact so adding a migration requires reviewing both the
    // embedded capability manifest and its attestation expectation.
    assert_eq!(manifest.versions.last(), Some(&158));
    assert_eq!(manifest.versions.len(), 157);
    assert!(!manifest.versions.contains(&21));
    assert!(manifest
        .checksum_hex
        .iter()
        .all(|checksum| checksum.len() == 96));
}

#[test]
fn embedded_migration_ledger_matches_every_compiled_sqlx_migration() {
    let expected = super::super::MIGRATOR
        .iter()
        .map(|migration| {
            (
                migration.version,
                migration.description.to_string(),
                migration
                    .checksum
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
        })
        .collect::<Vec<_>>();
    let manifest = parse_migration_ledger_manifest(MIGRATION_LEDGER_MANIFEST_SQL).unwrap();
    validate_migration_ledger_source(&expected, &manifest).unwrap();
}

#[test]
fn migration_ledger_source_comparison_rejects_missing_extra_and_changed_entries() {
    let expected = vec![
        (1, "one".to_owned(), "a".repeat(96)),
        (2, "two".to_owned(), "b".repeat(96)),
    ];
    let complete = MigrationLedgerManifest {
        versions: vec![1, 2],
        descriptions: vec!["one".to_owned(), "two".to_owned()],
        checksum_hex: vec!["a".repeat(96), "b".repeat(96)],
    };
    validate_migration_ledger_source(&expected, &complete).unwrap();

    for manifest in [
        MigrationLedgerManifest {
            versions: vec![1],
            descriptions: vec!["one".to_owned()],
            checksum_hex: vec!["a".repeat(96)],
        },
        MigrationLedgerManifest {
            versions: vec![1, 2, 3],
            descriptions: vec!["one".to_owned(), "two".to_owned(), "three".to_owned()],
            checksum_hex: vec!["a".repeat(96), "b".repeat(96), "c".repeat(96)],
        },
        MigrationLedgerManifest {
            versions: vec![1, 2],
            descriptions: vec!["one".to_owned(), "changed".to_owned()],
            checksum_hex: vec!["a".repeat(96), "c".repeat(96)],
        },
    ] {
        assert!(validate_migration_ledger_source(&expected, &manifest).is_err());
    }
}

#[test]
fn migration_ledger_parser_rejects_duplicate_or_malformed_rows() {
    let duplicate = "INSERT INTO pg_temp.northstar_migration_ledger_manifest VALUES\n\
        (1,'one',pg_catalog.decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','hex')),\n\
        (1,'again',pg_catalog.decode('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','hex'));";
    assert!(parse_migration_ledger_manifest(duplicate).is_err());
    let short_checksum = "(1,'one',pg_catalog.decode('aa','hex'));";
    assert!(parse_migration_ledger_manifest(short_checksum).is_err());
}

#[test]
fn migration_ledger_attestation_aligns_independently_typed_arrays_by_ordinality() {
    assert!(MIGRATION_LEDGER_ATTESTATION_SQL.contains("version_rows"));
    assert!(MIGRATION_LEDGER_ATTESTATION_SQL.contains("description_rows"));
    assert!(MIGRATION_LEDGER_ATTESTATION_SQL.contains("checksum_rows"));
    assert!(MIGRATION_LEDGER_ATTESTATION_SQL.contains("JOIN description_rows USING(ordinality)"));
    assert!(MIGRATION_LEDGER_ATTESTATION_SQL.contains("JOIN checksum_rows USING(ordinality)"));
    assert!(!MIGRATION_LEDGER_ATTESTATION_SQL.contains("int8[],\n                 $2"));
}
