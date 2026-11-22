//! Personal Eventing Protocol account, node, and mutation types.

use crate::{CanonicalJid, PubSubOutboxInsert};
use anyhow::Result;
use northstar_time::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct PubSubAccount {
    pub id: Uuid,
    pub username: String,
    pub auth_generation: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepNodeConfig {
    pub access_model: String,
    pub max_items: i32,
    pub persist_items: bool,
    pub send_last_published_item: String,
    pub deliver_notifications: bool,
    pub roster_groups_allowed: Vec<String>,
    pub access_whitelist: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct PepQuotas {
    pub max_nodes: i64,
    pub max_storage_bytes: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepCreateOutcome {
    Created,
    Conflict,
    QuotaExceeded,
    StaleAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepPublishOutcome {
    Published,
    Unauthorized,
    PreconditionFailed,
    MaxItemsExceeded,
    QuotaExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepSubscription {
    pub jid: String,
    pub subid: String,
}

#[derive(Clone, Debug)]
pub struct PepPresenceSubscription {
    pub owner_id: Uuid,
    pub owner_username: String,
    pub node: String,
}

#[derive(Clone, Debug)]
pub struct PepItem {
    pub item_id: String,
    pub payload: String,
    pub updated_at: DateTime<Utc>,
}

/// Authenticated principal and addressed PEP subscription identity.
pub struct PepSubscriptionActor<'a> {
    pub jid: &'a str,
    pub local_account: Option<&'a PubSubAccount>,
}

pub struct PepSubscribeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub actor: PepSubscriptionActor<'a>,
    pub node: &'a str,
    pub subscriber_jid: &'a str,
    pub max_subscriptions: i64,
    pub requested_subid: &'a str,
}

pub struct PepUnsubscribeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub actor: PepSubscriptionActor<'a>,
    pub node: &'a str,
    pub subscriber_jid: &'a str,
    pub subid: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct PepSubscribeSnapshot {
    pub owner_id: Uuid,
    pub owner_bare_jid: String,
    pub node: String,
    pub subscriber_jid: String,
    pub subscriber_account_id: Option<Uuid>,
    pub local_domain: String,
    pub last_item: Option<PepItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PepSubscribeOutcome {
    Subscribed(PepSubscription),
    NotFound,
    Forbidden,
    NotAuthorized(String),
    LimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PepUnsubscribeOutcome {
    /// `None` is an idempotent retry after the exact subscription disappeared.
    Unsubscribed(Option<String>),
    NotFound,
    Forbidden,
    InvalidSubid,
}

pub struct PepProfileWrite<'a> {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub requested: &'a PepNodeConfig,
    pub enforce_preconditions: bool,
    pub items: &'a [(&'a str, &'a str)],
    pub max_nodes: i64,
    pub max_storage_bytes: i64,
}

/// Generic PEP publication intent. Durable authorization is intentionally not
/// part of this command: the service derives it from the locked node, roster,
/// block policy and explicit subscriptions in the write transaction.
pub struct PepPublishWrite<'a> {
    pub user_id: Uuid,
    pub username: &'a str,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub requested: &'a PepNodeConfig,
    pub enforce_preconditions: bool,
    pub items: &'a [(&'a str, &'a str)],
    pub quotas: PepQuotas,
}

/// Exact durable PEP audience captured while every policy input is locked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepAudienceSnapshot {
    pub owner_bare_jid: String,
    pub roster_jids: Vec<String>,
    pub explicit_jids: Vec<String>,
}

impl PepAudienceSnapshot {
    pub fn authorizes_routed_jid(&self, recipient: &str) -> bool {
        let Ok(recipient) = CanonicalJid::parse(recipient) else {
            return false;
        };
        let full = recipient.to_string();
        let bare = recipient.bare();
        bare == self.owner_bare_jid
            || self.roster_jids.iter().any(|jid| jid == &bare)
            || self.explicit_jids.iter().any(|jid| {
                CanonicalJid::parse(jid).is_ok_and(|explicit| {
                    if explicit.resourcepart().is_some() {
                        explicit.to_string() == full
                    } else {
                        explicit.bare() == bare
                    }
                })
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PepDirectStateTransition {
    Subscription {
        recipient_jid: String,
        subid: String,
        state: String,
    },
    Affiliation {
        recipient_jid: String,
        affiliation: String,
    },
}

impl PepDirectStateTransition {
    pub fn recipient_jid(&self) -> &str {
        match self {
            Self::Subscription { recipient_jid, .. } | Self::Affiliation { recipient_jid, .. } => {
                recipient_jid
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PepDirectStateSnapshot {
    pub owner_bare_jid: String,
    pub node: String,
    pub transitions: Vec<PepDirectStateTransition>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepOwnerMutationOutcome {
    Applied(u64),
    NotFound,
    Forbidden,
    Stale,
    NotSubscribed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PepBookmarkMutationOutcome {
    Stored,
    ConcurrentChange,
    ResourceConstraint,
    Forbidden,
}

pub struct PepRetractWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub item_ids: &'a [String],
    pub notify: bool,
}

pub struct PepDeleteNodeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
}

pub struct PepPurgeNodeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
}

pub struct PepConfigureNodeWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub expected: &'a PepNodeConfig,
    pub config: &'a PepNodeConfig,
}

pub struct PepSetAffiliationsWrite<'a> {
    pub owner: &'a PubSubAccount,
    pub connection_id: Uuid,
    pub node: &'a str,
    pub expected: &'a PepNodeConfig,
    pub changes: &'a [(String, String)],
}

pub const PEP_MAX_ITEMS: i32 = 100;
pub fn default_pep_node_config(node: &str) -> PepNodeConfig {
    let (access_model, max_items, send_last) = match node {
        "urn:xmpp:omemo:2:devices" | "eu.siacs.conversations.axolotl.devicelist" => {
            ("open", 1, "on_sub_and_presence")
        }
        "urn:xmpp:omemo:2:bundles" => ("open", PEP_MAX_ITEMS, "on_sub_and_presence"),
        node if node.starts_with("eu.siacs.conversations.axolotl.bundles") => {
            ("open", PEP_MAX_ITEMS, "on_sub_and_presence")
        }
        "urn:xmpp:avatar:data" => ("open", PEP_MAX_ITEMS, "never"),
        "urn:xmpp:avatar:metadata" | "urn:xmpp:vcard4" => ("open", 1, "on_sub_and_presence"),
        "urn:xmpp:contacts" | "urn:xmpp:bookmarks:1" | "storage:bookmarks" => {
            ("whitelist", PEP_MAX_ITEMS, "never")
        }
        _ => ("presence", 100, "on_sub_and_presence"),
    };
    PepNodeConfig {
        access_model: access_model.to_owned(),
        max_items,
        persist_items: true,
        send_last_published_item: send_last.to_owned(),
        deliver_notifications: true,
        roster_groups_allowed: Vec::new(),
        access_whitelist: Vec::new(),
    }
}

pub fn canonical_profile_item_id(node: &str, item_id: &str) -> Result<String> {
    if !["urn:xmpp:bookmarks:1", "urn:xmpp:contacts"].contains(&node) {
        return Ok(item_id.to_owned());
    }
    let canonical = northstar_xmpp_types::CanonicalJid::parse_bare(item_id).map_err(|error| {
        error.context(format!(
            "profile PEP node {node:?} requires a valid bare-JID ItemID; rejected {item_id:?}"
        ))
    })?;
    anyhow::ensure!(
        canonical.localpart().is_some(),
        "profile PEP node {node:?} requires an account bare-JID ItemID; rejected domain-only {item_id:?}"
    );
    Ok(canonical.to_string())
}

/// Pure renderer invoked while the authoritative subscription transaction is
/// open. It receives only values read under the policy locks and cannot add a
/// recipient other than the newly subscribed JID.
pub trait PepSubscribeOutboxFactory: Send + Sync {
    fn build(&self, snapshot: &PepSubscribeSnapshot) -> Result<Vec<PubSubOutboxInsert>>;
}

impl<F> PepSubscribeOutboxFactory for F
where
    F: Fn(&PepSubscribeSnapshot) -> Result<Vec<PubSubOutboxInsert>> + Send + Sync,
{
    fn build(&self, snapshot: &PepSubscribeSnapshot) -> Result<Vec<PubSubOutboxInsert>> {
        self(snapshot)
    }
}

/// Synchronous payload factory used under the publication transaction. It may
/// consult in-memory caps/resources, but cannot perform I/O or introduce a
/// principal absent from `PepAudienceSnapshot`.
pub trait PepOutboxFactory: Send + Sync {
    fn build(&self, audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>>;

    /// A publication may supply its item changes from the locked write
    /// transaction. Renderers that do not need the diff keep their existing
    /// audience-only behavior.
    fn build_published(
        &self,
        audience: &PepAudienceSnapshot,
        _changed_items: &[(&str, &str)],
    ) -> Result<Vec<(String, String)>> {
        self.build(audience)
    }

    /// A replacement may also retract items. Both slices are read while the
    /// replacement transaction holds its item locks.
    fn build_replaced(
        &self,
        _audience: &PepAudienceSnapshot,
        _current_items: &[(&str, &str)],
        _previous_items: &[(&str, &str)],
    ) -> Result<Vec<(String, String)>> {
        anyhow::bail!("PEP replacement requires a locked item diff renderer")
    }
}

pub trait PepDirectOutboxFactory: Send + Sync {
    fn build(&self, snapshot: &PepDirectStateSnapshot) -> Result<Vec<(String, String)>>;
}

impl<F> PepDirectOutboxFactory for F
where
    F: Fn(&PepDirectStateSnapshot) -> Result<Vec<(String, String)>> + Send + Sync,
{
    fn build(&self, snapshot: &PepDirectStateSnapshot) -> Result<Vec<(String, String)>> {
        self(snapshot)
    }
}

impl<F> PepOutboxFactory for F
where
    F: Fn(&PepAudienceSnapshot) -> Result<Vec<(String, String)>> + Send + Sync,
{
    fn build(&self, audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
        self(audience)
    }
}
