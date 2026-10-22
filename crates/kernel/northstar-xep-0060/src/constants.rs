//! Protocol constants, namespaces, form types, and structural limits for XEP-0060.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};

/// Stable XEP numeric identifier.
pub const XEP_ID: XepId = XepId::new(60);

// XML Namespaces
pub const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
pub const NS_PUBSUB_OWNER: &str = "http://jabber.org/protocol/pubsub#owner";
pub const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
pub const NS_PUBSUB_ERRORS: &str = "http://jabber.org/protocol/pubsub#errors";
pub const NS_DATA: &str = "jabber:x:data";
pub const NS_RSM: &str = "http://jabber.org/protocol/rsm";
pub const NS_SHIM: &str = "http://jabber.org/protocol/shim";
pub const NS_DELAY: &str = "urn:xmpp:delay";
pub const NS_DISCO_INFO: &str = "http://jabber.org/protocol/disco#info";
pub const NS_DISCO_ITEMS: &str = "http://jabber.org/protocol/disco#items";
pub const NS_ATOM: &str = "http://www.w3.org/2005/Atom";
pub const NS_STANZAS: &str = "urn:ietf:params:xml:ns:xmpp-stanzas";

// Form Type Identifiers (jabber:x:data)
pub const NODE_CONFIG_FORM: &str = "http://jabber.org/protocol/pubsub#node_config";
pub const PUBLISH_OPTIONS_FORM: &str = "http://jabber.org/protocol/pubsub#publish-options";
pub const SUBSCRIBE_AUTH_FORM: &str = "http://jabber.org/protocol/pubsub#subscribe_authorization";
pub const SUBSCRIBE_OPTIONS_FORM: &str = "http://jabber.org/protocol/pubsub#subscribe_options";
pub const NODE_METADATA_FORM: &str = "http://jabber.org/protocol/pubsub#meta-data";

// Structural & Protocol Bounds
pub const MAX_NODE_ID_BYTES: usize = 1_024;
pub const MAX_ITEM_ID_BYTES: usize = 1_024;
pub const MAX_PUBLISH_ITEMS: usize = 100;
pub const MAX_ITEM_XML_BYTES: usize = 1_048_576; // 1 MiB
pub const MAX_PUBLISH_XML_BYTES: usize = 4 * 1_048_576; // 4 MiB
pub const MAX_TITLE_BYTES: usize = 512;
pub const MAX_DESCRIPTION_BYTES: usize = 4_096;
pub const MAX_PAYLOAD_TYPE_BYTES: usize = 512;
pub const MAX_SUBSCRIPTION_LEASE_DAYS: i64 = 365;
pub const MAX_DIGEST_FREQUENCY_MS: u32 = 86_400_000;
pub const MIN_DIGEST_FREQUENCY_MS: u32 = 1_000;
pub const MAX_RSM_PAGE_SIZE: usize = 1_000;
pub const MAX_RSM_INDEX: usize = 1_000_000;
pub const MAX_SUBSCRIPTIONS_PER_REQUEST: usize = 100;
pub const MAX_AFFILIATIONS_PER_REQUEST: usize = 100;
pub const MAX_COLLECTION_ASSOCIATION_WHITELIST: usize = 100;
pub const MAX_COLLECTIONS_PER_CONFIG: usize = 1_000;
pub const MAX_CHILDREN_PER_CONFIG: usize = 1_000;
pub const MAX_CHILDREN_NODES: usize = 1_000;
pub const MAX_REDIRECT_URI_BYTES: usize = 2_048;
pub const MAX_JID_BYTES: usize = 3_071;
pub const MAX_ATOM_BODY_BYTES: usize = 1_024;

/// Feature tokens advertised in Service Discovery for XEP-0060 and related PubSub specs.
pub const SERVICE_FEATURES: &[&str] = &[
    "access-authorize",
    "access-open",
    "access-whitelist",
    "auto-create",
    "collections",
    "config-node",
    "create-and-configure",
    "create-nodes",
    "delete-items",
    "delete-nodes",
    "instant-nodes",
    "item-ids",
    "last-published",
    "leased-subscription",
    "manage-subscriptions",
    "member-affiliation",
    "meta-data",
    "modify-affiliations",
    "multi-collections",
    "multi-items",
    "outcast-affiliation",
    "persistent-items",
    "publish",
    "publish-only-affiliation",
    "publish-options",
    "publisher-affiliation",
    "purge-nodes",
    "retract-items",
    "retrieve-affiliations",
    "retrieve-default",
    "retrieve-default-sub",
    "retrieve-items",
    "retrieve-subscriptions",
    "rsm",
    "subscribe",
    "subscription-notifications",
    "subscription-options",
];

/// Capability-free extension descriptor for XEP-0060.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Publish-Subscribe",
    default_enabled: true,
    dependencies: &[XepId::new(30), XepId::new(59)],
    conflicts: &[],
    disco_features: &[
        NS_PUBSUB,
        "http://jabber.org/protocol/pubsub#access-authorize",
        "http://jabber.org/protocol/pubsub#access-open",
        "http://jabber.org/protocol/pubsub#access-whitelist",
        "http://jabber.org/protocol/pubsub#auto-create",
        "http://jabber.org/protocol/pubsub#collections",
        "http://jabber.org/protocol/pubsub#config-node",
        "http://jabber.org/protocol/pubsub#create-and-configure",
        "http://jabber.org/protocol/pubsub#create-nodes",
        "http://jabber.org/protocol/pubsub#delete-items",
        "http://jabber.org/protocol/pubsub#delete-nodes",
        "http://jabber.org/protocol/pubsub#instant-nodes",
        "http://jabber.org/protocol/pubsub#item-ids",
        "http://jabber.org/protocol/pubsub#last-published",
        "http://jabber.org/protocol/pubsub#leased-subscription",
        "http://jabber.org/protocol/pubsub#manage-subscriptions",
        "http://jabber.org/protocol/pubsub#member-affiliation",
        "http://jabber.org/protocol/pubsub#meta-data",
        "http://jabber.org/protocol/pubsub#modify-affiliations",
        "http://jabber.org/protocol/pubsub#multi-collections",
        "http://jabber.org/protocol/pubsub#multi-items",
        "http://jabber.org/protocol/pubsub#outcast-affiliation",
        "http://jabber.org/protocol/pubsub#persistent-items",
        "http://jabber.org/protocol/pubsub#publish",
        "http://jabber.org/protocol/pubsub#publish-only-affiliation",
        "http://jabber.org/protocol/pubsub#publish-options",
        "http://jabber.org/protocol/pubsub#publisher-affiliation",
        "http://jabber.org/protocol/pubsub#purge-nodes",
        "http://jabber.org/protocol/pubsub#retract-items",
        "http://jabber.org/protocol/pubsub#retrieve-affiliations",
        "http://jabber.org/protocol/pubsub#retrieve-default",
        "http://jabber.org/protocol/pubsub#retrieve-default-sub",
        "http://jabber.org/protocol/pubsub#retrieve-items",
        "http://jabber.org/protocol/pubsub#retrieve-subscriptions",
        "http://jabber.org/protocol/pubsub#rsm",
        "http://jabber.org/protocol/pubsub#subscribe",
        "http://jabber.org/protocol/pubsub#subscription-notifications",
        "http://jabber.org/protocol/pubsub#subscription-options",
    ],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: NS_PUBSUB,
            local_name: "pubsub",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: NS_PUBSUB,
            local_name: "pubsub",
        },
        StanzaRoute {
            stanza: StanzaKind::IqGet,
            namespace: NS_PUBSUB_OWNER,
            local_name: "pubsub",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: NS_PUBSUB_OWNER,
            local_name: "pubsub",
        },
    ],
};
