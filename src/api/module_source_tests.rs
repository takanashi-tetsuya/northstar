//! Guard for the parent's MODULE_SOURCE list.

use super::MODULE_SOURCE;

#[test]
fn module_source_lists_every_role_split_child() {
    let catalog: serde_json::Value =
        serde_json::from_str(include_str!("../../catalog/source-role-splits.json"))
            .expect("catalog/source-role-splits.json is valid JSON");
    let declared: std::collections::BTreeSet<&str> = catalog["files"]["src/api/mod.rs"]
        .as_array()
        .expect("src/api/mod.rs is listed in catalog/source-role-splits.json")
        .iter()
        .filter_map(|name| name.as_str())
        .collect();
    let listed: std::collections::BTreeSet<&str> =
        MODULE_SOURCE[1..].iter().map(|(name, _)| *name).collect();
    assert_eq!(declared, listed);
}
