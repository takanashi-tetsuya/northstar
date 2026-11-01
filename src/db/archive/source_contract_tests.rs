//! Source contracts of the archive module.

use super::*;

#[test]
fn module_source_lists_every_child_module() {
    let (_, parent) = MODULE_SOURCE[0];
    let declared: std::collections::BTreeSet<&str> = parent
        .lines()
        .filter_map(|line| line.strip_prefix("mod ")?.strip_suffix(';'))
        .filter(|name| !name.ends_with("_tests"))
        .collect();
    let listed: std::collections::BTreeSet<&str> =
        MODULE_SOURCE[1..].iter().map(|(name, _)| *name).collect();
    assert_eq!(declared, listed);
}
