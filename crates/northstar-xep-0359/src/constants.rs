//! XEP-0359 namespaces, bounds and extension metadata.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

pub const XEP_ID: XepId = XepId::new(359);
pub const NAMESPACE: &str = "urn:xmpp:sid:0";
pub const MAX_ID_BYTES: usize = 1_024;
pub const MAX_ID_ELEMENTS: usize = 256;

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Unique and Stable Stanza IDs",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "origin-id",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "stanza-id",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "referenced-stanza",
        },
    ],
};
