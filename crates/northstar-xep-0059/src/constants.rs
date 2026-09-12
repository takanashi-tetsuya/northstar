//! XEP-0059 Result Set Management constants, namespaces, and descriptor.

use northstar_xep_core::{ExtensionDescriptor, XepId};

/// Stable numeric identity of XEP-0059.
pub const XEP_ID: XepId = XepId::new(59);

/// The canonical XML namespace for XEP-0059 Result Set Management.
pub const NAMESPACE: &str = "http://jabber.org/protocol/rsm";

/// Legacy alias for the RSM namespace.
pub const NS_RSM: &str = NAMESPACE;

/// Default maximum page size when unspecified.
pub const DEFAULT_MAX_PAGE_SIZE: usize = 1_000;

/// Default maximum cursor byte length (1 KiB).
pub const DEFAULT_MAX_CURSOR_BYTES: usize = 1_024;

/// Default maximum allowed offset index (1,000,000).
pub const DEFAULT_MAX_INDEX: u64 = 1_000_000;

/// Static extension descriptor for XEP-0059 Result Set Management.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Result Set Management",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_matches_xep_0059_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Result Set Management");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert!(DESCRIPTOR.routes.is_empty());
    }
}
