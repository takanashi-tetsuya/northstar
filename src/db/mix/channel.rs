//! MIX channel records: operation outcomes, row mapping, creation, lookup, discovery and destruction.

use super::*;

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
        roster_change: Option<Box<super::super::RosterChange>>,
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
    pub roster_change: Option<super::super::RosterChange>,
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
    pub roster_changes: Vec<(Uuid, super::super::RosterChange)>,
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
pub(crate) fn mix_presence_item_id(
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

pub(super) fn canonical_user_bare(jid: &str) -> Result<String> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse(jid)?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "MIX participants require a user bare JID"
    );
    Ok(jid.bare())
}

pub(super) async fn pam_account_matches_actor_tx(
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

pub(super) fn canonical_service_domain(domain: &str) -> Result<String> {
    northstar_xmpp_types::jid::prepare_domainpart(domain)
}

pub(super) fn canonical_channel_localpart(localpart: &str) -> Result<String> {
    let value = northstar_xmpp_types::jid::prepare_localpart(localpart)?;
    anyhow::ensure!(value.len() <= 1023, "MIX channel localpart is too large");
    Ok(value)
}

pub(super) fn channel_from_row(row: &sqlx::postgres::PgRow) -> MixChannel {
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

pub(super) fn participant_from_row(row: &sqlx::postgres::PgRow) -> MixParticipant {
    MixParticipant {
        participant_id: row.get("participant_id"),
        jid: row.get("jid"),
        nick: row.get("nick"),
    }
}

pub async fn create_mix_channel(
    pool: &PgPool,
    service_domain: &str,
    requested_localpart: Option<&str>,
    creator_jid: &str,
    max_channels_per_owner: i64,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<(CreateChannelOutcome, String)> {
    let service_domain = canonical_service_domain(service_domain)?;
    let creator_jid = canonical_user_bare(creator_jid)?;
    let discoverable = requested_localpart.is_some();
    let localpart = match requested_localpart {
        Some(value) => canonical_channel_localpart(value)?,
        None => Uuid::new_v4().simple().to_string(),
    };
    let mut transaction = pool.begin().await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&creator_jid)
        .execute(&mut *transaction)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mix_channels WHERE creator_jid = $1")
        .bind(&creator_jid)
        .fetch_one(&mut *transaction)
        .await?;
    if count >= max_channels_per_owner.max(1) {
        transaction.rollback().await?;
        return Ok((CreateChannelOutcome::QuotaExceeded, localpart));
    }
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        "INSERT INTO mix_channels (id, service_domain, localpart, creator_jid, discoverable) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (service_domain, localpart) DO NOTHING",
    )
    .bind(id)
    .bind(&service_domain)
    .bind(&localpart)
    .bind(&creator_jid)
    .bind(discoverable)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if inserted == 0 {
        transaction.rollback().await?;
        return Ok((CreateChannelOutcome::Conflict, localpart));
    }
    sqlx::query("INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'owner')")
        .bind(id)
        .bind(&creator_jid)
        .execute(&mut *transaction)
        .await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
    let channel = channel_from_row(&channel_row);
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_INFO,
        &mix_timestamp_item_id(),
        None,
        &payloads.info_payload(&channel),
    )
    .await?;
    let _ = store_mix_event_tx(
        &mut transaction,
        &channel,
        NODE_CONFIG,
        &mix_timestamp_item_id(),
        None,
        &payloads.config_payload(
            &channel,
            &creator_jid,
            &BTreeSet::from([creator_jid.clone()]),
            &BTreeSet::new(),
        ),
    )
    .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Create {
            channel: localpart.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok((CreateChannelOutcome::Created(id), localpart))
}

pub async fn mix_channel(
    pool: &PgPool,
    service_domain: &str,
    localpart: &str,
) -> Result<Option<MixChannel>> {
    let service_domain = canonical_service_domain(service_domain)?;
    let localpart = canonical_channel_localpart(localpart)?;
    let row =
        sqlx::query("SELECT * FROM mix_channels WHERE service_domain = $1 AND localpart = $2")
            .bind(service_domain)
            .bind(localpart)
            .fetch_optional(pool)
            .await?;
    Ok(row.as_ref().map(channel_from_row))
}

#[cfg(test)]
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

/// Page channels visible and joinable by `requester` in one stable snapshot.
/// `before == Some(None)` is XEP-0059's empty-before request for the final page.
pub async fn discoverable_mix_channel_page(
    pool: &PgPool,
    service_domain: &str,
    requester: &str,
    after: Option<&str>,
    before: Option<Option<&str>>,
    max: i64,
) -> Result<Option<MixDiscoPage>> {
    anyhow::ensure!(
        after.is_none() || before.is_none(),
        "ambiguous MIX RSM page"
    );
    let service_domain = canonical_service_domain(service_domain)?;
    let requester = canonical_user_bare(requester)?;
    let requester_domain = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&requester)?
        .domainpart()
        .to_owned();
    let after = after.map(canonical_channel_localpart).transpose()?;
    let before = before
        .map(|value| value.map(canonical_channel_localpart).transpose())
        .transpose()?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let visible = "c.service_domain = $1 AND c.discoverable AND NOT EXISTS (SELECT 1 FROM mix_banned b WHERE b.channel_id = c.id AND b.jid_pattern IN ($2, $3)) AND (c.access_model = 'open' OR EXISTS (SELECT 1 FROM mix_allowed a WHERE a.channel_id = c.id AND a.jid_pattern IN ($2, $3)) OR EXISTS (SELECT 1 FROM mix_channel_roles r WHERE r.channel_id = c.id AND r.jid = $2))";
    if let Some(cursor) = after
        .as_deref()
        .or(before.as_ref().and_then(|v| v.as_deref()))
    {
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM mix_channels c WHERE {visible} AND c.localpart = $4)"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(cursor)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            transaction.rollback().await?;
            return Ok(None);
        }
    }
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM mix_channels c WHERE {visible}"
    ))
    .bind(&service_domain)
    .bind(&requester)
    .bind(&requester_domain)
    .fetch_one(&mut *transaction)
    .await?;
    let max = max.clamp(0, 100);
    let rows = if let Some(after) = after.as_deref() {
        sqlx::query(&format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} AND c.localpart > $4 ORDER BY c.localpart ASC LIMIT $5"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(after)
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else if let Some(before) = before.as_ref() {
        sqlx::query(&format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} AND ($4::text IS NULL OR c.localpart < $4) ORDER BY c.localpart DESC LIMIT $5"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(before.as_deref())
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    } else {
        sqlx::query(&format!(
            "SELECT c.* FROM mix_channels c WHERE {visible} ORDER BY c.localpart ASC LIMIT $4"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(max + 1)
        .fetch_all(&mut *transaction)
        .await?
    };
    let mut channels = rows.iter().map(channel_from_row).collect::<Vec<_>>();
    if channels.len() > max as usize {
        channels.truncate(max as usize);
    }
    if before.is_some() {
        channels.reverse();
    }
    let first_index = if let Some(first) = channels.first() {
        sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM mix_channels c WHERE {visible} AND c.localpart < $4"
        ))
        .bind(&service_domain)
        .bind(&requester)
        .bind(&requester_domain)
        .bind(&first.localpart)
        .fetch_one(&mut *transaction)
        .await?
    } else {
        0
    };
    transaction.commit().await?;
    Ok(Some(MixDiscoPage {
        channels,
        total,
        first_index,
    }))
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

/// Apply the same joinability/privacy boundary to channel disco#info and
/// disco#items. Ad-hoc channels are visible only to participants and channel
/// administrators; named channels are visible only when the requester is not
/// banned and satisfies the channel access model.
pub async fn mix_channel_discoverable_to(
    pool: &PgPool,
    channel: &MixChannel,
    actor: &str,
) -> Result<bool> {
    let actor = northstar_xmpp_types::jid::CanonicalJid::parse(actor)?;
    anyhow::ensure!(
        actor.resourcepart().is_none(),
        "MIX disco requester must be a bare JID or authenticated domain"
    );
    let actor_domain = actor.domainpart().to_owned();
    let actor = actor.to_string();
    let row = sqlx::query(
        "SELECT c.discoverable, c.access_model,
            EXISTS(SELECT 1 FROM mix_participants WHERE channel_id = $1 AND jid = $2) AS participant,
            EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2) AS privileged,
            EXISTS(SELECT 1 FROM mix_banned WHERE channel_id = $1 AND jid_pattern IN ($2, $3)) AS banned,
            EXISTS(SELECT 1 FROM mix_allowed WHERE channel_id = $1 AND jid_pattern IN ($2, $3)) AS allowed
         FROM mix_channels c WHERE c.id = $1",
    )
    .bind(channel.id)
    .bind(&actor)
    .bind(actor_domain)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let participant: bool = row.get("participant");
    let privileged: bool = row.get("privileged");
    if row.get::<bool, _>("banned") && !privileged {
        return Ok(false);
    }
    if !row.get::<bool, _>("discoverable") {
        return Ok(participant || privileged);
    }
    Ok(row.get::<String, _>("access_model") == "open"
        || participant
        || privileged
        || row.get::<bool, _>("allowed"))
}

pub async fn destroy_mix_channel(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    payloads: &dyn MixEventPayloadRenderer,
    federated: Option<&FederatedMixMutation>,
) -> Result<bool> {
    let actor = canonical_user_bare(actor)?;
    let (mut transaction, delivery_fence) = begin_mix_delivery_admission(pool).await?;
    guard_federated_mix_mutation_tx(&mut transaction, federated).await?;
    let channel_row = sqlx::query("SELECT * FROM mix_channels WHERE id=$1 FOR UPDATE")
        .bind(channel_id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(channel_row) = channel_row else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let channel = channel_from_row(&channel_row);
    let channel_jid = channel.jid();
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mix_channel_roles WHERE channel_id = $1 AND jid = $2 AND role = 'owner')",
    )
    .bind(channel_id)
    .bind(&actor)
    .fetch_one(&mut *transaction)
    .await?;
    if !authorized {
        transaction.rollback().await?;
        return Ok(false);
    }
    let participants = sqlx::query(
        "SELECT channel_id,participant_id,jid,nick,role,joined_at
           FROM mix_participants WHERE channel_id=$1 ORDER BY participant_id",
    )
    .bind(channel_id)
    .fetch_all(&mut *transaction)
    .await?
    .iter()
    .map(participant_from_row)
    .collect::<Vec<_>>();
    // Keep one terminal channel-state event after the authority row is gone.
    // Every current participant is an explicit recipient, independently of
    // its optional node subscriptions, and the normalized outbox stores the
    // channel address rather than depending on the deleted row.
    let info_item_id: String = sqlx::query_scalar(
        "SELECT item_id FROM mix_events
          WHERE channel_id=$1 AND node=$2
          ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(channel_id)
    .bind(NODE_INFO)
    .fetch_optional(&mut *transaction)
    .await?
    .unwrap_or_else(|| channel_jid.clone());
    enqueue_mix_node_event_tx(
        &mut transaction,
        &delivery_fence,
        MixNodeProjection {
            channel: &channel,
            node: NODE_INFO,
            item_id: &info_item_id,
            payload: None,
            retract: true,
            event_id: Uuid::new_v4(),
            extra_recipients: participants,
        },
        payloads,
    )
    .await?;
    let local_users: Vec<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM mix_pam_memberships WHERE channel_jid = $1")
            .bind(&channel_jid)
            .fetch_all(&mut *transaction)
            .await?;
    for user_id in local_users {
        delete_mix_roster_tx(&mut transaction, user_id, &channel_jid).await?;
    }
    sqlx::query("DELETE FROM mix_pam_memberships WHERE channel_jid = $1")
        .bind(&channel_jid)
        .execute(&mut *transaction)
        .await?;
    sqlx::query("DELETE FROM mix_channels WHERE id = $1")
        .bind(channel_id)
        .execute(&mut *transaction)
        .await?;
    finalize_federated_mix_mutation_tx(
        &mut transaction,
        federated,
        FederatedMixSuccess::Destroy {
            channel: channel.localpart.clone(),
        },
        payloads,
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
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
