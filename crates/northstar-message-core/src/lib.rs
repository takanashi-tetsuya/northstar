//! Capability-free application types for personal-message admission.
//!
//! The crate deliberately owns no database, clock, network or provider
//! capability. Protocol adapters construct one validated command and the
//! server application service commits it through the matching repository
//! transaction.

use uuid::Uuid;

/// One enabled personal-history projection of an accepted stanza.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveProjection<'a> {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub peer_jid: &'a str,
    pub stanza: &'a str,
    pub encrypted: bool,
    pub stanza_id: Option<&'a str>,
}

/// The authenticated authority which owns a stable message identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityAuthority {
    LocalOrigin,
    AuthenticatedRemoteStanza,
}

impl IdentityAuthority {
    /// Stable persistence discriminator. This value is part of the replay
    /// namespace and must not be derived from untrusted stanza text.
    pub const fn persistence_kind(self) -> &'static str {
        match self {
            Self::LocalOrigin => "local-origin",
            Self::AuthenticatedRemoteStanza => "remote-stanza",
        }
    }
}

/// A trusted, bounded replay identity extracted by a protocol adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageIdentity<'a> {
    pub authority: IdentityAuthority,
    pub actor_scope_raw: &'a str,
    pub actor_scope: &'a str,
    pub target_scope: &'a str,
    pub value: &'a str,
    pub payload: &'a str,
}

/// Runtime limits captured with a federation outbox admission.
pub use northstar_federation_core::S2sOutboxPolicy as FederationOutboxLimits;

/// Recoverable local C2S projection committed before volatile fan-out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDelivery<'a> {
    pub delivery_id: Uuid,
    pub recipient_id: Uuid,
    pub recipient_bare_jid: &'a str,
    pub sender_jid: &'a str,
    pub stanza: &'a str,
    pub encrypted: bool,
    pub mam_backed: bool,
}

/// Durable federation projection committed before the outbox worker wakes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationDelivery<'a> {
    pub local_actor_id: Uuid,
    pub target_domain: &'a str,
    pub stanza: &'a str,
    pub bounce_to: Option<&'a str>,
    pub limits: FederationOutboxLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonalMessageDestination<'a> {
    Local(LocalDelivery<'a>),
    Federation(FederationDelivery<'a>),
}

/// One validated personal-message admission command.
///
/// `local_actor_id` is absent only for an authenticated federation ingress.
/// A federation egress carries its actor directly in `FederationDelivery`, so
/// the repository cannot accidentally enqueue an anonymous local outbox row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedPersonalMessage<'a> {
    pub local_actor_id: Option<Uuid>,
    pub identity: Option<MessageIdentity<'a>>,
    pub archives: &'a [ArchiveProjection<'a>],
    pub destination: PersonalMessageDestination<'a>,
}

impl ValidatedPersonalMessage<'_> {
    pub const fn writes_history(&self) -> bool {
        !self.archives.is_empty()
    }
}

/// Authoritative transaction result. Post-commit socket, Carbon, Push and
/// provider effects are plans, never represented as already completed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessagePostCommit {
    RouteLocalDelivery {
        delivery_id: Uuid,
        recipient_id: Uuid,
    },
    WakeFederationOutbox,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageCommit {
    Stored {
        archive_written: bool,
        post_commit: MessagePostCommit,
    },
    Replay,
    AccountUnavailable,
}

/// RFC 6121 routing behavior for a message addressed to a bare local JID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BareMessageRoute {
    Primary,
    All,
    Reject,
    Ignore,
}

pub fn bare_message_route(kind: &str) -> BareMessageRoute {
    match kind {
        "headline" => BareMessageRoute::All,
        "groupchat" => BareMessageRoute::Reject,
        "error" => BareMessageRoute::Ignore,
        _ => BareMessageRoute::Primary,
    }
}

pub fn missing_user_message_should_error(kind: &str) -> bool {
    !matches!(kind, "headline" | "error")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FullNoMatchRoute {
    FallbackChat,
    Reject,
    Ignore,
}

pub fn full_no_match_route(kind: &str) -> FullNoMatchRoute {
    match kind {
        "chat" => FullNoMatchRoute::FallbackChat,
        "error" => FullNoMatchRoute::Ignore,
        _ => FullNoMatchRoute::Reject,
    }
}

/// Once a durable delivery projection commits, route disappearance is a
/// recovery condition rather than a truthful stanza rejection.
pub fn durable_full_no_match_recovers(kind: &str, durable_committed: bool) -> bool {
    durable_committed && full_no_match_route(kind) == FullNoMatchRoute::Reject
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UndeliveredDisposition {
    Drop,
    RejectCancel,
    RejectWait,
    StoreOffline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectDeliveryMode {
    Durable,
    Volatile,
    VolatileExplicitNoStore,
}

pub const fn classify_direct_delivery(
    explicit_no_store: bool,
    persistence_allowed: bool,
) -> DirectDeliveryMode {
    if explicit_no_store {
        DirectDeliveryMode::VolatileExplicitNoStore
    } else if persistence_allowed {
        DirectDeliveryMode::Durable
    } else {
        DirectDeliveryMode::Volatile
    }
}

pub const fn durable_direct_delivery_allowed(
    mode: DirectDeliveryMode,
    content_storage_allowed: bool,
) -> bool {
    matches!(mode, DirectDeliveryMode::Durable) && content_storage_allowed
}

pub fn undelivered_disposition(
    message_type: &str,
    persistence_allowed: bool,
    content_storage_allowed: bool,
) -> UndeliveredDisposition {
    if message_type == "headline" || !persistence_allowed {
        return UndeliveredDisposition::Drop;
    }
    if !matches!(message_type, "normal" | "chat") {
        return UndeliveredDisposition::RejectCancel;
    }
    if !content_storage_allowed {
        return UndeliveredDisposition::RejectWait;
    }
    UndeliveredDisposition::StoreOffline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_authority_has_a_closed_persistence_namespace() {
        assert_eq!(
            IdentityAuthority::LocalOrigin.persistence_kind(),
            "local-origin"
        );
        assert_eq!(
            IdentityAuthority::AuthenticatedRemoteStanza.persistence_kind(),
            "remote-stanza"
        );
    }

    #[test]
    fn history_projection_is_explicit_and_not_inferred_from_delivery() {
        let local = LocalDelivery {
            delivery_id: Uuid::nil(),
            recipient_id: Uuid::nil(),
            recipient_bare_jid: "alice@example.test",
            sender_jid: "bob@example.test/device",
            stanza: "<message/>",
            encrypted: false,
            mam_backed: false,
        };
        let command = ValidatedPersonalMessage {
            local_actor_id: Some(Uuid::nil()),
            identity: None,
            archives: &[],
            destination: PersonalMessageDestination::Local(local),
        };
        assert!(!command.writes_history());
    }

    #[test]
    fn federation_destination_requires_a_concrete_local_actor() {
        let destination = PersonalMessageDestination::Federation(FederationDelivery {
            local_actor_id: Uuid::nil(),
            target_domain: "remote.test",
            stanza: "<message/>",
            bounce_to: None,
            limits: FederationOutboxLimits {
                ttl_seconds: 60,
                max_rows: 10,
                max_bytes: 1024,
                max_per_domain: 2,
            },
        });
        assert!(matches!(
            destination,
            PersonalMessageDestination::Federation(_)
        ));
    }

    #[test]
    fn route_policy_keeps_error_and_headline_non_durable() {
        assert_eq!(bare_message_route("error"), BareMessageRoute::Ignore);
        assert_eq!(bare_message_route("headline"), BareMessageRoute::All);
        assert!(!missing_user_message_should_error("error"));
        assert_eq!(
            undelivered_disposition("headline", true, true),
            UndeliveredDisposition::Drop
        );
    }

    #[test]
    fn explicit_no_store_cannot_be_upgraded_to_durable_delivery() {
        let mode = classify_direct_delivery(true, true);
        assert_eq!(mode, DirectDeliveryMode::VolatileExplicitNoStore);
        assert!(!durable_direct_delivery_allowed(mode, true));
    }

    #[test]
    fn durable_full_target_rejection_becomes_recovery_after_commit() {
        assert!(!durable_full_no_match_recovers("normal", false));
        assert!(durable_full_no_match_recovers("normal", true));
        assert!(!durable_full_no_match_recovers("chat", true));
    }
}
