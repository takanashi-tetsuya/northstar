//! Protocol constants, namespaces, bounds, and extension descriptor for XEP-0313.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

/// Stable numeric identifier for XEP-0313.
pub const XEP_ID: XepId = XepId::new(313);

/// XEP-0313 MAM version 2 namespace.
pub const XMLNS_MAM: &str = "urn:xmpp:mam:2";

/// Canonical XEP-0059 Result Set Management namespace.
pub use northstar_xep_0059::NAMESPACE as XMLNS_RSM;

/// XEP-0004 Data Forms namespace.
pub const XMLNS_DATA: &str = "jabber:x:data";

/// XEP-0297 Stanza Forwarding namespace.
pub const XMLNS_FORWARD: &str = "urn:xmpp:forward:0";

/// XEP-0203 Delayed Delivery namespace.
pub const XMLNS_DELAY: &str = "urn:xmpp:delay";

/// XEP-0359 Unique and Stable Stanza IDs namespace.
pub const XMLNS_SID: &str = "urn:xmpp:sid:0";

/// XEP-0122 Data Forms Validation namespace.
pub const XMLNS_XDATA_VALIDATE: &str = "http://jabber.org/protocol/xdata-validate";

/// RFC 6120 / RFC 6121 Client namespace.
pub const XMLNS_CLIENT: &str = "jabber:client";

/// Discovery feature for standard MAM support.
pub const DISCO_FEATURE_MAM: &str = "urn:xmpp:mam:2";

/// Discovery feature for extended MAM query filtering support.
pub const DISCO_FEATURE_MAM_EXTENDED: &str = "urn:xmpp:mam:2#extended";

/// Maximum default number of results returned in a single MAM page.
pub const MAX_MAM_RESULTS: u32 = 100;

/// Maximum number of IDs permitted in the `ids` multi-item filter field.
pub const MAX_MAM_IDS: usize = 100;

/// Maximum zero-based item index allowed in an RSM query request.
pub const MAX_MAM_RSM_INDEX: u64 = 1_000_000;

/// Maximum total number of JIDs allowed across `always` and `never` preference lists.
pub const MAX_PREFS_JIDS: usize = 500;

/// Maximum byte length for a client-supplied query ID attribute.
pub const MAX_QUERY_ID_BYTES: usize = 1_024;

/// Maximum byte length for an archive message identifier.
pub const MAX_ARCHIVE_ID_BYTES: usize = 1_024;

/// Static ExtensionDescriptor for XEP-0313 Message Archive Management.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Message Archive Management",
    default_enabled: true,
    dependencies: &[XepId::new(30), XepId::new(59)],
    conflicts: &[],
    disco_features: &[DISCO_FEATURE_MAM, DISCO_FEATURE_MAM_EXTENDED],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: XMLNS_MAM,
            local_name: "query",
        },
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: XMLNS_MAM,
            local_name: "query",
        },
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: XMLNS_MAM,
            local_name: "metadata",
        },
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: XMLNS_MAM,
            local_name: "prefs",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: XMLNS_MAM,
            local_name: "prefs",
        },
    ],
};
