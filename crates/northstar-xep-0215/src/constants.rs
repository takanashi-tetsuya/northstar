//! XEP-0215 metadata and bounded parser limits.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

pub const XEP_ID: XepId = XepId::new(215);
pub const NAMESPACE: &str = "urn:xmpp:extdisco:2";
pub const DATA_FORMS_NAMESPACE: &str = "jabber:x:data";
pub const MAX_CREDENTIAL_REQUESTS: usize = 16;
pub const MAX_RESULT_SERVICES: usize = 256;
pub const MAX_SERVICE_TYPE_BYTES: usize = 64;
pub const MAX_LABEL_BYTES: usize = 512;
pub const MAX_CREDENTIAL_BYTES: usize = 4_096;
pub const MAX_EXTENDED_FIELDS: usize = 64;
pub const MAX_FIELD_VALUES: usize = 64;
pub const MAX_FIELD_VALUE_BYTES: usize = 4_096;

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "External Service Discovery",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: NAMESPACE,
            local_name: "services",
        },
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: NAMESPACE,
            local_name: "credentials",
        },
    ],
};
