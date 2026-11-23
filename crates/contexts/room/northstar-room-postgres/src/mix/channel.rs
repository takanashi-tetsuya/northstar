//! MIX channel records: operation outcomes, row mapping, creation, lookup, discovery and destruction.

use super::*;

mod create;
mod destroy;
mod discovery;

pub use self::create::{create_mix_channel, create_mix_channel_at};
pub use self::destroy::destroy_mix_channel;
pub use self::discovery::{discoverable_mix_channel_page, mix_channel_discoverable_to};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateChannelOutcome {
    Created(Uuid),
    Conflict,
    QuotaExceeded,
}

#[derive(Clone, Debug)]
pub enum JoinChannelOutcome {
    Joined {
        participant: MixParticipant,
        preference: MixParticipantPreference,
        subscriptions: Vec<String>,
        newly_joined: bool,
        roster_change: Option<Box<northstar_roster_core::RosterChange>>,
    },
    Banned,
    NotAllowed,
    Full,
    MissingNick,
    NickConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreEventOutcome {
    Stored(Uuid),
    Existing(MixIntentEvidence),
    NotParticipant,
    Conflict,
    IdentityPolicyChanged,
    TooLarge,
}

#[derive(Clone, Debug)]
pub struct StoreMixMessageAdmission {
    pub outcome: StoreEventOutcome,
    /// Audience captured while the channel lock and archive transaction were
    /// still held. Join/leave/subscription changes use the same lock, so a
    /// committed message has one linearizable recipient set.
    pub recipients: Vec<MixParticipant>,
}

/// Exact event and audience committed by one state mutation.  Protocol code
/// must publish this snapshot and must not reconstruct security-sensitive
/// configuration from a later read.
#[derive(Clone, Debug)]
pub struct MixMutationAdmission {
    pub channel: MixChannel,
    pub node: String,
    pub item_id: String,
    pub payload: String,
    pub recipients: Vec<MixParticipant>,
}

#[derive(Clone, Debug)]
pub struct LeaveMixOutcome {
    pub participant: MixParticipant,
    pub presence_items: Vec<MixPresenceItem>,
    pub roster_change: Option<northstar_roster_core::RosterChange>,
}

#[derive(Clone, Debug)]
pub struct MixPresenceItem {
    pub item_id: String,
    pub payload: String,
    pub source_full_jid: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PresenceOutcome {
    Published,
    Retracted,
    Unchanged,
    NotSharing,
    NotParticipant,
    /// Only a probe liveness refresh returns this: the channel or the resource's
    /// presence row was absent, and nothing was written.
    NoKnownPresence,
}

#[derive(Clone, Debug)]
pub struct UpdateSubscriptionsOutcome {
    pub subscriptions: Vec<String>,
    pub participant: MixParticipant,
    pub removed_presence: Vec<MixPresenceItem>,
}

#[derive(Clone, Debug)]
pub struct MixParticipantPreferenceUpdateOutcome {
    pub participant: MixParticipant,
    pub roster_changes: Vec<(Uuid, northstar_roster_core::RosterChange)>,
}

#[derive(Clone, Debug, Default)]
pub struct AccessChangeOutcome {
    pub removed_participants: Vec<Uuid>,
    pub removed_local_users: Vec<Uuid>,
    /// Current presence items removed as a consequence of a ban.  The
    /// protocol layer uses these to publish the mandatory unavailable
    /// transition instead of leaving subscribers with a ghost resource.
    pub removed_presence: Vec<(MixParticipant, Vec<MixPresenceItem>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixAccessList {
    Allowed,
    Banned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MixAccessEntryOperation<'a> {
    Publish { reason: Option<&'a str> },
    Retract,
}

/// One authorized mutation of a MIX allow/ban list.
///
/// Keeping the target list and operation explicit prevents callers from
/// constructing ambiguous combinations of `banned`, `present` and `reason`
/// booleans while the repository retains the existing single transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixAccessEntryUpdate<'a> {
    pub channel_id: Uuid,
    pub actor: &'a str,
    pub pattern: &'a str,
    pub list: MixAccessList,
    pub operation: MixAccessEntryOperation<'a>,
}

/// XEP-0403 identifies each current presence item by the encoded participant
/// JID plus the publishing resource, never by the participant's real full
/// JID.  Keeping this constructor beside persistence makes that privacy
/// invariant hard to bypass accidentally.
pub fn mix_presence_item_id(
    channel: &MixChannel,
    participant_id: Uuid,
    public_resource: &str,
) -> Result<String> {
    let resource = northstar_xmpp_types::jid::prepare_resourcepart(public_resource)?;
    let encoded = format!(
        "{}#{}@{}/{}",
        participant_id, channel.localpart, channel.service_domain, resource
    );
    let canonical = northstar_xmpp_types::jid::CanonicalJid::parse(&encoded)?;
    anyhow::ensure!(
        canonical.to_string() == encoded,
        "encoded MIX presence item is not canonical"
    );
    Ok(encoded)
}

pub fn canonical_user_bare(jid: &str) -> Result<String> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse(jid)?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "MIX participants require a user bare JID"
    );
    Ok(jid.bare())
}

pub async fn pam_account_matches_actor_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    actor_jid: &str,
) -> Result<bool> {
    let actor_username = northstar_xmpp_types::jid::CanonicalJid::parse_bare(actor_jid)?
        .localpart()
        .context("MIX-PAM actor requires a localpart")?
        .to_owned();
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND username=$2 AND NOT is_disabled)",
    )
    .bind(user_id)
    .bind(actor_username)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

pub fn canonical_service_domain(domain: &str) -> Result<String> {
    northstar_xmpp_types::jid::prepare_domainpart(domain)
}

pub fn canonical_channel_localpart(localpart: &str) -> Result<String> {
    let value = northstar_xmpp_types::jid::prepare_localpart(localpart)?;
    anyhow::ensure!(value.len() <= 1023, "MIX channel localpart is too large");
    Ok(value)
}

pub fn channel_from_row(row: &sqlx::postgres::PgRow) -> MixChannel {
    let contacts = row
        .get::<serde_json::Value, _>("contacts")
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    MixChannel {
        id: row.get("id"),
        revision: row.get("revision"),
        service_domain: row.get("service_domain"),
        localpart: row.get("localpart"),
        creator_jid: row.get("creator_jid"),
        name: row.get("name"),
        description: row.get("description"),
        contacts,
        access_model: row.get("access_model"),
        jid_visibility: row.get("jid_visibility"),
        nick_required: row.get("nick_required"),
        max_participants: row.get("max_participants"),
        max_events: row.get("max_events"),
        allow_private_messages: row.get("allow_private_messages"),
        allow_participant_invites: row.get("allow_participant_invites"),
        allow_user_message_retraction: row.get("allow_user_message_retraction"),
        administrator_retraction_rights: row.get("administrator_retraction_rights"),
        enforce_registered_nick: row.get("enforce_registered_nick"),
    }
}

pub fn participant_from_row(row: &sqlx::postgres::PgRow) -> MixParticipant {
    MixParticipant {
        participant_id: row.get("participant_id"),
        jid: row.get("jid"),
        nick: row.get("nick"),
    }
}

pub async fn mix_channel<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    service_domain: &str,
    localpart: &str,
) -> Result<Option<MixChannel>> {
    let service_domain = canonical_service_domain(service_domain)?;
    let localpart = canonical_channel_localpart(localpart)?;
    let row =
        sqlx::query("SELECT * FROM mix_channels WHERE service_domain = $1 AND localpart = $2")
            .bind(service_domain)
            .bind(localpart)
            .fetch_optional(executor)
            .await?;
    Ok(row.as_ref().map(channel_from_row))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn mix_channel_by_id(pool: &PgPool, channel_id: Uuid) -> Result<Option<MixChannel>> {
    let row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(channel_from_row))
}

#[derive(Clone, Debug)]
pub struct MixDiscoPage {
    pub channels: Vec<MixChannel>,
    pub total: i64,
    pub first_index: i64,
}

pub async fn mix_role(pool: &PgPool, channel_id: Uuid, jid: &str) -> Result<Option<String>> {
    let jid = canonical_user_bare(jid)?;
    sqlx::query_scalar("SELECT role FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2")
        .bind(channel_id)
        .bind(jid)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
}

pub struct JoinMixRequest<'a> {
    pub actor_jid: &'a str,
    pub nick: Option<&'a str>,
    pub nodes: &'a [String],
    /// Set only for a local MIX-PAM operation. The membership is committed in
    /// the same transaction as the local channel participant.
    pub pam_user_id: Option<Uuid>,
    /// A XEP-0407 invitation is consumed atomically with an allow-list join.
    pub invitation: Option<&'a MixInvitationProof>,
    /// XEP-0404 preferences supplied with the join. Missing preferences use
    /// the specification defaults and are committed with membership.
    pub preference: Option<&'a MixParticipantPreference>,
    /// Whether the XEP-0404 anonymous-profile namespace was used for this
    /// join result. This affects only the exact protocol acknowledgement.
    pub anonymous_profile: bool,
}

#[derive(Clone, Debug)]
pub struct MixInvitationProof {
    pub inviter_jid: String,
    pub invitee_jid: String,
    pub channel_jid: String,
    pub token: String,
}
