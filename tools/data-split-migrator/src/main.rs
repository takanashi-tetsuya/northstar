//! CLI entry point for Northstar Monolith-to-Microservices Data Split Migrator.
//!
//! Defined per northstar_microservices_deep_audit_2026-09-03.md (Sections 17, 19.1).

use data_split_migrator::DataSplitMigrator;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Northstar Monolith-to-Microservices Data Split Migrator ===");
    let catalog_path = Path::new("catalog/data-ownership.yaml");
    if !catalog_path.exists() {
        eprintln!(
            "Catalog file not found at: {}",
            catalog_path.to_string_lossy()
        );
        std::process::exit(1);
    }

    let content = fs::read_to_string(catalog_path)?;
    let mut migrator = DataSplitMigrator::new();

    let mut current_db = String::new();
    let mut table_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() || trimmed.starts_with("version:") {
            continue;
        }

        if line.trim_start().starts_with("database:") {
            current_db = trimmed
                .trim_start_matches("database:")
                .trim()
                .trim_matches('"')
                .to_string();
        } else if trimmed.starts_with("- ") && !current_db.is_empty() {
            let table = trimmed.trim_start_matches("- ").trim();
            if !table.is_empty() {
                migrator.register_assignment(table, &current_db)?;
                table_count += 1;
            }
        }
    }

    println!(
        "Loaded {} tables across target microservice databases from catalog.",
        table_count
    );

    if !migrator.validate_ownership() {
        eprintln!("ERROR: Table ownership validation failed: duplicate table assignments found!");
        std::process::exit(1);
    }
    println!("Ownership Validation: OK (Exclusive database ownership verified).");

    // Perform dry-run migration simulation with baseline estimates
    let mut sample_counts = HashMap::new();
    sample_counts.insert("users".to_string(), 100_000);
    sample_counts.insert("active_sessions".to_string(), 10_000);
    sample_counts.insert("roster_items".to_string(), 500_000);
    sample_counts.insert("archive_messages".to_string(), 10_000_000);
    sample_counts.insert("muc_rooms".to_string(), 1_000);
    sample_counts.insert("pubsub_nodes".to_string(), 5_000);
    sample_counts.insert("uploads".to_string(), 50_000);

    let report = migrator.simulate_migration(&sample_counts);
    println!("\n--- Dry Run Migration Report ---");
    println!("Total Rows Simulated: {}", report.total_rows);
    println!("Verification Passed: {}", report.verification_passed);
    for t in &report.tables_migrated {
        println!(
            "  - Table: {:<25} Rows: {:<10} Target DB: {}",
            t.table_name, t.source_rows, t.target_database
        );
    }

    println!("\nMigration preparation complete. Ready for production cutover window.");
    Ok(())
}
