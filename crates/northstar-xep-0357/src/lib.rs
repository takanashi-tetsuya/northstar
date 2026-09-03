#![forbid(unsafe_code)]

//! Pure, capability-free XEP-0357 Push Notifications wire parsing, disclosure policy, and XML builders.
//!
//! This crate contains transport-neutral domain models and pure validation logic for XEP-0357
//! Push Notifications. It deliberately has no dependencies on PostgreSQL (`sqlx`, `PgPool`),
//! Redis, async runtimes (`tokio`), networking/sockets, filesystem, environment access,
//! logging, clocks, randomness, or server state (`AppState`).

pub mod builder;
pub mod constants;
pub mod error;
pub mod policy;
pub mod subscription;
pub mod summary;
pub mod wire;
pub mod xml;

pub use builder::{
    build_disable, build_enable, build_iq_error, build_iq_result, build_notification_iq,
    build_xdata_value_field,
};
pub use constants::{
    DELIVERY_CORRELATION_SECONDS, DESCRIPTOR, DISCO_FEATURE_PUSH, MAX_ENABLE_ATTEMPTS_PER_MINUTE,
    MAX_FIELD_VALUES, MAX_FIELD_VAR_BYTES, MAX_FORM_FIELDS, MAX_NODE_BYTES, MAX_OPTIONS_XML_BYTES,
    MAX_SUBSCRIPTIONS_PER_USER, MAX_VALUE_BYTES, NOTIFICATION_COALESCE_SECONDS, XEP_ID,
    XMLNS_CLIENT, XMLNS_DATA, XMLNS_PUBLISH_OPTIONS, XMLNS_PUBSUB, XMLNS_PUSH, XMLNS_STANZAS,
    XMLNS_SUMMARY,
};
pub use error::PushError;
pub use policy::{
    apply_disclosure_policy, evaluate_eligibility, BodyDisclosure, DeliveryAttemptReason,
    DeliveryResponseKind, DeliveryResponseOutcome, DisclosurePolicy, EligibilityDecision,
    EligibilityInput, EligibilityReason, IneligibilityReason, MessageEncryption, MessageImportance,
    NotificationEvent, PushCoalesceKey, RecipientSessionState, SenderDisclosure,
};
pub use subscription::{
    PublishOptionField, PublishOptions, PushDisableRequest, PushEnableRequest, PushNode,
    PushSubscriptionKey,
};
pub use summary::PushSummary;
pub use wire::{
    iq_targets_own_account, parse_disable, parse_enable, parse_notification_iq_payload,
};
pub use xml::{attr_escape, escape_xml_attr, escape_xml_text, xml_escape, XmlElement};
