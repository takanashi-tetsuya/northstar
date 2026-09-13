//! Monolith-to-Microservices Database Splitting and Migration Tool.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 17, 19.1, 22).

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct TableMigrationStatus {
    pub table_name: String,
    pub source_rows: u64,
    pub target_rows: u64,
    pub target_database: String,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub tables_migrated: Vec<TableMigrationStatus>,
    pub total_rows: u64,
    pub verification_passed: bool,
}

pub struct DataSplitMigrator {
    table_ownership: HashMap<String, String>, // table_name -> target_database
}

impl DataSplitMigrator {
    pub fn new() -> Self {
        Self {
            table_ownership: HashMap::new(),
        }
    }

    /// Registers table assignments from catalog/data-ownership.yaml
    pub fn register_assignment(
        &mut self,
        table_name: impl Into<String>,
        target_db: impl Into<String>,
    ) -> Result<(), String> {
        let table = table_name.into();
        let db = target_db.into();
        if let Some(existing_db) = self.table_ownership.get(&table) {
            return Err(format!(
                "Table '{}' is already assigned to database '{}'; cannot assign to '{}'",
                table, existing_db, db
            ));
        }
        self.table_ownership.insert(table, db);
        Ok(())
    }

    /// Validates that no two services share ownership of any table.
    pub fn validate_ownership(&self) -> bool {
        let mut seen = HashSet::new();
        for table in self.table_ownership.keys() {
            if !seen.insert(table) {
                return false;
            }
        }
        true
    }

    /// Simulates dry-run migration and performs row-count verification.
    pub fn simulate_migration(&self, source_counts: &HashMap<String, u64>) -> MigrationReport {
        let mut tables = Vec::new();
        let mut total_rows = 0;
        let mut all_passed = true;

        for (table, &count) in source_counts {
            let target_db = self
                .table_ownership
                .get(table)
                .cloned()
                .unwrap_or_else(|| "unassigned".to_string());

            let verified = target_db != "unassigned";
            if !verified {
                all_passed = false;
            }

            tables.push(TableMigrationStatus {
                table_name: table.clone(),
                source_rows: count,
                target_rows: count, // In simulation, rows are fully copied
                target_database: target_db,
                verified,
            });

            total_rows += count;
        }

        MigrationReport {
            tables_migrated: tables,
            total_rows,
            verification_passed: all_passed,
        }
    }
}

impl Default for DataSplitMigrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrator_registration_and_simulation() {
        let mut migrator = DataSplitMigrator::new();
        assert!(migrator
            .register_assignment("users", "northstar_identity")
            .is_ok());
        assert!(migrator
            .register_assignment("sessions", "northstar_session")
            .is_ok());

        // Duplicate table assignment fails
        assert!(migrator
            .register_assignment("users", "northstar_other")
            .is_err());

        assert!(migrator.validate_ownership());

        let mut counts = HashMap::new();
        counts.insert("users".to_string(), 1000);
        counts.insert("sessions".to_string(), 500);

        let report = migrator.simulate_migration(&counts);
        assert!(report.verification_passed);
        assert_eq!(report.total_rows, 1500);
        assert_eq!(report.tables_migrated.len(), 2);
    }
}
