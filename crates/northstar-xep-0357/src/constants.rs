//! Protocol constants, namespaces, bounds, and extension descriptor for XEP-0357 Push Notifications.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

/// Stable numeric identifier for XEP-0357.
pub const XEP_ID: XepId = XepId::new(357);

/// XEP-0357 Push Notifications namespace.
pub const XMLNS_PUSH: &str = "urn:xmpp:push:0";

/// XEP-0357 Push Notifications summary form namespace.
pub const XMLNS_SUMMARY: &str = "urn:xmpp:push:summary";

/// XEP-0060 Publish-Subscribe namespace.
pub const XMLNS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";

/// XEP-0060 Publish-Subscribe publish-options namespace.
pub const XMLNS_PUBLISH_OPTIONS: &str = "http://jabber.org/protocol/pubsub#publish-options";

/// XEP-0004 Data Forms namespace.
pub const XMLNS_DATA: &str = "jabber:x:data";

/// RFC 6120 / RFC 6121 Client namespace.
pub const XMLNS_CLIENT: &str = "jabber:client";

/// RFC 6120 Stanza Error namespace.
pub const XMLNS_STANZAS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";

/// Discovery feature for standard XEP-0357 Push Notifications support.
pub const DISCO_FEATURE_PUSH: &str = "urn:xmpp:push:0";

/// Maximum byte length for a push subscription node identifier.
pub const MAX_NODE_BYTES: usize = 1_024;

/// Maximum byte length for a raw publish-options XML payload.
pub const MAX_OPTIONS_XML_BYTES: usize = 16 * 1_024; // 16 KB

/// Maximum number of fields permitted in a publish-options data form.
pub const MAX_FORM_FIELDS: usize = 64;

/// Maximum byte length for a data form field variable name (`var`).
pub const MAX_FIELD_VAR_BYTES: usize = 256;

/// Maximum number of `<value>` elements permitted within a single data form field.
pub const MAX_FIELD_VALUES: usize = 16;

/// Maximum byte length for a single data form field value text.
pub const MAX_VALUE_BYTES: usize = 4_096;

/// Default maximum number of push subscriptions allowed per account.
pub const MAX_SUBSCRIPTIONS_PER_USER: usize = 16;

/// Maximum enable attempts allowed per minute under default rate limiting policy.
pub const MAX_ENABLE_ATTEMPTS_PER_MINUTE: u32 = 30;

/// Default duration in seconds to coalesce push notifications for a recipient.
pub const NOTIFICATION_COALESCE_SECONDS: u64 = 15;

/// Default expiration duration in seconds for in-flight push delivery correlation.
pub const DELIVERY_CORRELATION_SECONDS: u64 = 300;

/// Static ExtensionDescriptor for XEP-0357 Push Notifications.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Push Notifications",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[DISCO_FEATURE_PUSH],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: XMLNS_PUSH,
            local_name: "enable",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: XMLNS_PUSH,
            local_name: "disable",
        },
    ],
};
