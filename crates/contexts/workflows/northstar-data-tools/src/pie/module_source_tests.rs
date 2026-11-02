//! Guard for the parent's MODULE_SOURCE list.

use super::MODULE_SOURCE;

#[test]
fn module_source_lists_every_child_module() {
    let (_, parent) = MODULE_SOURCE[0];
    let declared: std::collections::BTreeSet<&str> = parent
        .lines()
        .zip(std::iter::once("").chain(parent.lines()))
        .filter(|(_, previous)| *previous != "#[cfg(test)]" && !previous.starts_with("#[path = "))
        .filter_map(|(line, _)| line.strip_prefix("mod ")?.strip_suffix(';'))
        .collect();
    let listed: std::collections::BTreeSet<&str> =
        MODULE_SOURCE[1..].iter().map(|(name, _)| *name).collect();
    assert_eq!(declared, listed);
}
