//! Protocol namespaces, attribute names, limits, and structural bounds for XEP-0115.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

/// Stable numeric identity for XEP-0115.
pub const XEP_ID: XepId = XepId::new(115);

/// XML namespace for XEP-0115 Entity Capabilities.
pub const CAPS_NS: &str = "http://jabber.org/protocol/caps";

/// XML namespace for XEP-0030 Service Discovery Info.
pub const DISCO_INFO_NS: &str = "http://jabber.org/protocol/disco#info";

/// XML namespace for XEP-0004 Data Forms.
pub const DATA_NS: &str = "jabber:x:data";

/// W3C XML namespace for `xml:lang`.
pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// Maximum allowed payload size for a disco#info query response (64 KiB).
pub const MAX_DISCO_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum number of top-level children in a disco#info query element.
pub const MAX_DISCO_CHILDREN: usize = 512;

/// Maximum length of a node URI string (2048 bytes).
pub const MAX_NODE_LEN: usize = 2048;

/// Maximum length of a ver/version string (256 bytes).
pub const MAX_VER_LEN: usize = 256;

/// Maximum length of a hash algorithm identifier string (64 bytes).
pub const MAX_HASH_LEN: usize = 64;

/// Maximum length of an ext attribute string (1024 bytes).
pub const MAX_EXT_LEN: usize = 1024;

/// Maximum length of an identity category string (128 bytes).
pub const MAX_CATEGORY_LEN: usize = 128;

/// Maximum length of an identity type string (128 bytes).
pub const MAX_TYPE_LEN: usize = 128;

/// Maximum length of an identity language tag string (35 bytes per RFC 5646).
pub const MAX_LANG_LEN: usize = 35;

/// Maximum length of an identity human-readable name (256 bytes).
pub const MAX_NAME_LEN: usize = 256;

/// Maximum length of a feature var string (2048 bytes).
pub const MAX_FEATURE_LEN: usize = 2048;

/// Maximum length of a FORM_TYPE URI string (2048 bytes).
pub const MAX_FORM_TYPE_LEN: usize = 2048;

/// Maximum length of a form field var string (256 bytes).
pub const MAX_FIELD_VAR_LEN: usize = 256;

/// Maximum length of a form field value string (4096 bytes).
pub const MAX_FIELD_VALUE_LEN: usize = 4096;

/// Maximum number of identities in one disco#info payload.
pub const MAX_IDENTITIES: usize = 128;

/// Maximum number of features in one disco#info payload.
pub const MAX_FEATURES: usize = 512;

/// Maximum number of extended forms in one disco#info payload.
pub const MAX_FORMS: usize = 64;

/// Maximum number of fields in one extended data form.
pub const MAX_FORM_FIELDS: usize = 256;

/// Maximum number of values in one form field.
pub const MAX_FIELD_VALUES: usize = 256;

/// Static extension descriptor for XEP-0115 Entity Capabilities.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Entity Capabilities",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[CAPS_NS],
    routes: &[StanzaRoute {
        stanza: StanzaKind::Presence,
        namespace: CAPS_NS,
        local_name: "c",
    }],
};
