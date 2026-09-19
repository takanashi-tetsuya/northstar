//! XEP-0191 metadata and safety bounds.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

pub const XEP_ID: XepId = XepId::new(191);
pub const NAMESPACE: &str = "urn:xmpp:blocking";
pub const MAX_ITEMS: usize = 1_024;

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Blocking Command",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: NAMESPACE,
            local_name: "blocklist",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: NAMESPACE,
            local_name: "block",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: NAMESPACE,
            local_name: "unblock",
        },
    ],
};
