//! Immutable notification identities and recipient ordering.
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const PUBSUB_OUTBOX_MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
pub const PUBSUB_OUTBOX_DEFAULT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubOutboxSource {
    PubSub,
    Pep,
}

impl PubSubOutboxSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PubSub => "pubsub",
            Self::Pep => "pep",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubOutboxDeliveryKind {
    PubSubChildren,
    PubSubDigest,
    PubSubDirect,
    PepStanza,
}

impl PubSubOutboxDeliveryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PubSubChildren => "pubsub-children",
            Self::PubSubDigest => "pubsub-digest",
            Self::PubSubDirect => "pubsub-direct",
            Self::PepStanza => "pep-stanza",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pubsub-children" => Ok(Self::PubSubChildren),
            "pubsub-digest" => Ok(Self::PubSubDigest),
            "pubsub-direct" => Ok(Self::PubSubDirect),
            "pep-stanza" => Ok(Self::PepStanza),
            other => anyhow::bail!("unknown PubSub outbox delivery kind {other}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepOutboxEventKind {
    Publish,
    LastItem,
    Retract,
    Purge,
    Delete,
    Configuration,
    SubscriptionState,
    AffiliationState,
}

impl PepOutboxEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::LastItem => "last-item",
            Self::Retract => "retract",
            Self::Purge => "purge",
            Self::Delete => "delete",
            Self::Configuration => "configuration",
            Self::SubscriptionState => "subscription-state",
            Self::AffiliationState => "affiliation-state",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "publish" => Ok(Self::Publish),
            "last-item" => Ok(Self::LastItem),
            "retract" => Ok(Self::Retract),
            "purge" => Ok(Self::Purge),
            "delete" => Ok(Self::Delete),
            "configuration" => Ok(Self::Configuration),
            "subscription-state" => Ok(Self::SubscriptionState),
            "affiliation-state" => Ok(Self::AffiliationState),
            other => anyhow::bail!("unknown PEP outbox event kind {other}"),
        }
    }

    pub fn requires_causal_authorization(self) -> bool {
        matches!(
            self,
            Self::Retract
                | Self::Purge
                | Self::Delete
                | Self::Configuration
                | Self::SubscriptionState
                | Self::AffiliationState
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepOutboxAuthorizationMode {
    /// The recipient was authorized by the same transaction as the mutation.
    /// Delivery still rechecks live account, block and privacy policy.
    CausalAudience,
    /// In addition to live communication policy, delivery must re-evaluate the
    /// current PEP node ACL/subscription. Used for security-sensitive material.
    LiveNodeAccess,
}

impl PepOutboxAuthorizationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CausalAudience => "causal-audience",
            Self::LiveNodeAccess => "live-node-access",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "causal-audience" => Ok(Self::CausalAudience),
            "live-node-access" => Ok(Self::LiveNodeAccess),
            other => anyhow::bail!("unknown PEP outbox authorization mode {other}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepOutboxSubject {
    pub sender_account_id: Uuid,
    pub sender_bare_jid: String,
    /// The originating local C2S policy context. `None` means that only the
    /// sender account's durable default privacy list is applicable.
    pub sender_connection_id: Option<Uuid>,
    /// Required for recipients in the local deployment and absent for remote
    /// recipients. The FK prevents delivery after local account deletion.
    pub recipient_account_id: Option<Uuid>,
    /// Immutable deployment-scope classification. Keeping this explicit lets
    /// the database reject a supposedly local row without an account FK (and
    /// a remote row carrying one) instead of relying only on worker parsing.
    pub recipient_is_local: bool,
    pub event_kind: PepOutboxEventKind,
    pub authorization_mode: PepOutboxAuthorizationMode,
}

/// One immutable recipient in the audience captured for a committed event.
#[derive(Clone, Debug)]
pub struct PubSubOutboxInsert {
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub ordering_key: String,
    pub source: PubSubOutboxSource,
    pub source_node: String,
    pub delivery_kind: PubSubOutboxDeliveryKind,
    pub recipient_jid: String,
    pub target_domain: String,
    pub payload_xml: String,
    pub payload_digest: [u8; 32],
    pub show_values: Option<Vec<String>>,
    pub subscription_node_id: Option<Uuid>,
    pub digest_frequency_ms: Option<i32>,
    pub security_sensitive: bool,
    pub coalesce_key: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub pep_subject: Option<PepOutboxSubject>,
    pub legacy_unverifiable: bool,
}

impl PubSubOutboxInsert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: Uuid,
        ordering_key: impl Into<String>,
        source: PubSubOutboxSource,
        delivery_kind: PubSubOutboxDeliveryKind,
        recipient_jid: impl Into<String>,
        payload_xml: impl Into<String>,
        show_values: Option<Vec<String>>,
        digest: Option<(Uuid, i32)>,
        node: &str,
        coalesce_key: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        anyhow::ensure!(
            source != PubSubOutboxSource::Pep
                && delivery_kind != PubSubOutboxDeliveryKind::PepStanza,
            "PEP stanza deliveries require new_pep_stanza with structured identity"
        );
        Self::new_inner(
            event_id,
            ordering_key,
            source,
            delivery_kind,
            recipient_jid,
            payload_xml,
            show_values,
            digest,
            node,
            coalesce_key,
            now,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_pep_stanza(
        event_id: Uuid,
        sender_account_id: Uuid,
        sender_bare_jid: &str,
        sender_connection_id: Option<Uuid>,
        recipient_jid: impl Into<String>,
        recipient_account_id: Option<Uuid>,
        event_kind: PepOutboxEventKind,
        authorization_mode: PepOutboxAuthorizationMode,
        payload_xml: impl Into<String>,
        node: &str,
        local_domain: &str,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        anyhow::ensure!(
            !sender_account_id.is_nil(),
            "PEP sender account identity may not be nil"
        );
        anyhow::ensure!(
            sender_connection_id.is_none_or(|connection_id| !connection_id.is_nil()),
            "PEP sender connection identity may not be nil"
        );
        let sender_bare_jid = northstar_xmpp_types::canonicalize_bare(sender_bare_jid)?;
        let sender = northstar_xmpp_types::CanonicalJid::parse_bare(&sender_bare_jid)?;
        anyhow::ensure!(
            sender.localpart().is_some() && sender.domainpart() == local_domain,
            "PEP sender must be a local account bare JID"
        );
        let recipient_jid = northstar_xmpp_types::canonicalize(&recipient_jid.into())?;
        let recipient = northstar_xmpp_types::CanonicalJid::parse(&recipient_jid)?;
        let recipient_is_local = recipient.domainpart() == local_domain;
        if recipient_is_local {
            anyhow::ensure!(
                recipient.localpart().is_some() && recipient_account_id.is_some(),
                "local PEP recipient requires an account identity"
            );
        } else {
            anyhow::ensure!(
                recipient_account_id.is_none(),
                "remote PEP recipient may not carry a local account identity"
            );
        }
        anyhow::ensure!(
            recipient_account_id.is_none_or(|recipient_id| !recipient_id.is_nil()),
            "PEP recipient account identity may not be nil"
        );
        anyhow::ensure!(
            !event_kind.requires_causal_authorization()
                || authorization_mode == PepOutboxAuthorizationMode::CausalAudience,
            "state-removal PEP events must retain their causal audience"
        );
        let authorization_mode = if security_sensitive_pep_node(node)
            && matches!(
                event_kind,
                PepOutboxEventKind::Publish | PepOutboxEventKind::LastItem
            ) {
            PepOutboxAuthorizationMode::LiveNodeAccess
        } else {
            authorization_mode
        };
        let ordering_key = format!("pep:{sender_account_id}:{node}");
        Self::new_inner(
            event_id,
            ordering_key,
            PubSubOutboxSource::Pep,
            PubSubOutboxDeliveryKind::PepStanza,
            recipient_jid,
            payload_xml,
            None,
            None,
            node,
            None,
            now,
            Some(PepOutboxSubject {
                sender_account_id,
                sender_bare_jid,
                sender_connection_id,
                recipient_account_id,
                recipient_is_local,
                event_kind,
                authorization_mode,
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        event_id: Uuid,
        ordering_key: impl Into<String>,
        source: PubSubOutboxSource,
        delivery_kind: PubSubOutboxDeliveryKind,
        recipient_jid: impl Into<String>,
        payload_xml: impl Into<String>,
        show_values: Option<Vec<String>>,
        digest: Option<(Uuid, i32)>,
        node: &str,
        coalesce_key: Option<String>,
        now: DateTime<Utc>,
        pep_subject: Option<PepOutboxSubject>,
    ) -> Result<Self> {
        let ordering_scope = ordering_key.into();
        anyhow::ensure!(
            !ordering_scope.is_empty() && ordering_scope.len() <= 1_990,
            "invalid PubSub outbox ordering scope"
        );
        let recipient_jid = northstar_xmpp_types::canonicalize(&recipient_jid.into())?;
        // XMPP ordering is observed per recipient, not globally across every
        // subscriber of a node.  Hash the canonical recipient into the stream
        // key so one offline subscriber cannot head-of-line block all other
        // recipients while still preserving strict order for that subscriber.
        let recipient_scope = URL_SAFE_NO_PAD.encode(Sha256::digest(recipient_jid.as_bytes()));
        let ordering_key = format!("{ordering_scope}|jid:{recipient_scope}");
        let target_domain = northstar_xmpp_types::CanonicalJid::parse(&recipient_jid)?
            .domainpart()
            .to_owned();
        let payload_xml = payload_xml.into();
        anyhow::ensure!(
            !payload_xml.is_empty() && payload_xml.len() <= PUBSUB_OUTBOX_MAX_PAYLOAD_BYTES,
            "PubSub notification payload exceeds outbox limit"
        );
        let security_sensitive = security_sensitive_pep_node(node);
        anyhow::ensure!(
            !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control),
            "invalid PubSub outbox source node"
        );
        anyhow::ensure!(
            coalesce_key.is_none() || !security_sensitive,
            "security-sensitive PEP/PubSub nodes may not be coalesced"
        );
        if let Some(values) = show_values.as_ref() {
            anyhow::ensure!(
                !values.is_empty() && values.len() <= 8,
                "invalid PubSub show-value snapshot"
            );
        }
        anyhow::ensure!(
            matches!(delivery_kind, PubSubOutboxDeliveryKind::PubSubDigest) == digest.is_some(),
            "PubSub digest delivery metadata does not match its kind"
        );
        let (subscription_node_id, digest_frequency_ms) = digest
            .map(|(node_id, frequency)| (Some(node_id), Some(frequency.clamp(1_000, 86_400_000))))
            .unwrap_or((None, None));
        Ok(Self {
            delivery_id: Uuid::new_v4(),
            event_id,
            ordering_key,
            source,
            source_node: node.to_owned(),
            delivery_kind,
            recipient_jid,
            target_domain,
            payload_digest: Sha256::digest(payload_xml.as_bytes()).into(),
            payload_xml,
            show_values,
            subscription_node_id,
            digest_frequency_ms,
            security_sensitive,
            coalesce_key,
            expires_at: now + chrono::Duration::seconds(PUBSUB_OUTBOX_DEFAULT_TTL_SECONDS),
            pep_subject,
            legacy_unverifiable: false,
        })
    }
}

pub fn security_sensitive_pep_node(node: &str) -> bool {
    let lower = node.to_ascii_lowercase();
    lower.contains("omemo")
        || lower.contains("axolotl")
        || lower.contains("device-list")
        || lower.contains("devices")
        || lower.contains("bundle")
        || lower.contains("prekeys")
        || lower.contains("signed-pre-key")
}

#[derive(Clone, Debug)]
pub struct ClaimedPubSubOutboxDelivery {
    pub delivery_id: Uuid,
    pub event_id: Uuid,
    pub ordering_key: String,
    pub event_sequence: i64,
    pub source: PubSubOutboxSource,
    pub source_node: String,
    pub delivery_kind: PubSubOutboxDeliveryKind,
    pub recipient_jid: String,
    pub target_domain: String,
    pub payload_xml: String,
    pub payload_digest: [u8; 32],
    pub show_values: Option<Vec<String>>,
    pub subscription_node_id: Option<Uuid>,
    pub digest_frequency_ms: Option<i32>,
    pub attempt_count: i32,
    pub lease_token: Uuid,
    pub expires_at: DateTime<Utc>,
    pub security_sensitive: bool,
    pub pep_subject: Option<PepOutboxSubject>,
    pub legacy_unverifiable: bool,
}
impl ClaimedPubSubOutboxDelivery {
    pub fn payload_binding_valid(&self) -> bool {
        <[u8; 32]>::from(Sha256::digest(self.payload_xml.as_bytes())) == self.payload_digest
    }
}
