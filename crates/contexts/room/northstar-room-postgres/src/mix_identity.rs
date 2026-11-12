//! Exact RFC 7622 migration for the coupled live MIX identity graph.

use anyhow::{Context, Result};
use serde_json::Value;
#[cfg(any(test, feature = "test-support"))]
use sqlx::PgPool;
use sqlx::{Postgres, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const MIGRATION: &str = "mix-keys-rfc7622-ulabel-v2";
const CANONICALIZER_VERSION: i32 = 2;
pub const PRESENCE_NODE: &str = "urn:xmpp:mix:nodes:presence";

#[derive(Debug)]
struct ChannelRow {
    id: Uuid,
    domain: String,
    canonical_domain: String,
    localpart: String,
    canonical_localpart: String,
    creator: String,
    canonical_creator: String,
    contacts: Value,
    canonical_contacts: Value,
}

#[derive(Clone, Debug)]
struct ScopedJid {
    scope: String,
    row_key: String,
    original: String,
    canonical: String,
}

#[derive(Debug)]
struct ParticipantIdentityRow {
    channel_id: Uuid,
    participant_id: Uuid,
    original: String,
    canonical: String,
}

#[derive(Debug)]
struct ParticipantRow {
    channel_id: Uuid,
    participant_id: Uuid,
    original: String,
    canonical: String,
}

#[derive(Debug)]
struct PamRow {
    id: Uuid,
    user_id: Uuid,
    channel_jid: String,
    canonical_channel_jid: String,
    requester_full_jid: Option<String>,
    canonical_requester_full_jid: Option<String>,
}

#[derive(Debug)]
struct RegisteredNickRow {
    domain: String,
    canonical_domain: String,
    jid: String,
    canonical_jid: String,
    nick: String,
}

#[derive(Debug)]
struct InvitationRow {
    id: Uuid,
    inviter: String,
    canonical_inviter: String,
    invitee: String,
    canonical_invitee: String,
}

fn invalid(table: &str, row: &str, value: &str, error: anyhow::Error) -> anyhow::Error {
    error.context(format!(
        "MIX JID migration rejected invalid identity in {table} row {row}: {value:?}; correct or remove this live row and restart"
    ))
}

fn canonical_user_bare(table: &str, row: &str, value: &str) -> Result<String> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(value)
        .map_err(|error| invalid(table, row, value, error))?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "MIX JID migration requires a user bare JID in {table} row {row}: {value:?}"
    );
    Ok(jid.to_string())
}

fn canonical_bare(table: &str, row: &str, value: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonicalize_bare(value)
        .map_err(|error| invalid(table, row, value, error))
}

fn canonical_full(table: &str, row: &str, value: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonical_session_key(value)
        .map_err(|error| invalid(table, row, value, error))
}

fn ensure_no_collisions(table: &str, rows: &[ScopedJid]) -> Result<()> {
    let mut owners = BTreeMap::<(&str, &str), (&str, &str)>::new();
    for row in rows {
        let key = (row.scope.as_str(), row.canonical.as_str());
        if let Some((previous_row, previous_value)) =
            owners.insert(key, (row.row_key.as_str(), row.original.as_str()))
        {
            anyhow::bail!(
                "MIX JID migration found a canonical collision in {table}: rows {previous_row} ({previous_value:?}) and {} ({:?}) in scope {:?} both map to {:?}; resolve it explicitly and restart",
                row.row_key,
                row.original,
                row.scope,
                row.canonical
            );
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn canonicalize_mix_identity_storage(pool: &PgPool) -> Result<()> {
    let mut transaction = pool.begin().await?;
    canonicalize_mix_identity_storage_in_transaction(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn canonicalize_mix_identity_storage_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7622))")
        .bind(MIGRATION)
        .execute(&mut **transaction)
        .await?;
    let complete: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1 AND canonicalizer_version=$2)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .fetch_one(&mut **transaction)
    .await?;
    if complete {
        return Ok(());
    }

    sqlx::query("SET LOCAL lock_timeout='30s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "LOCK TABLE mix_channels, mix_participant_identities, mix_participants,
         mix_channel_roles, mix_allowed, mix_banned, mix_pam_memberships,
         mix_registered_nicks, mix_invitations, mix_events IN ACCESS EXCLUSIVE MODE",
    )
    .execute(&mut **transaction)
    .await
    .context(
        "timed out after 30 seconds waiting to lock the MIX identity graph; stop other Northstar nodes using this database, then restart the migration",
    )?;

    let channels = load_channels(transaction).await?;
    let identities = load_participant_identities(transaction).await?;
    let participants = load_participants(transaction).await?;
    validate_participant_graph(&identities, &participants)?;
    let roles = load_scoped_user_jids(
        transaction,
        "mix_channel_roles.jid",
        "SELECT channel_id::text AS scope,jid AS value,jid AS row_key FROM mix_channel_roles ORDER BY channel_id,jid",
    )
    .await?;
    ensure_no_collisions("mix_channel_roles(channel_id,jid)", &roles)?;
    validate_creators_have_owner_roles(&channels, &roles, transaction).await?;
    let allowed = load_access_patterns(transaction, "mix_allowed").await?;
    let banned = load_access_patterns(transaction, "mix_banned").await?;
    ensure_no_collisions("mix_allowed(channel_id,jid_pattern)", &allowed)?;
    ensure_no_collisions("mix_banned(channel_id,jid_pattern)", &banned)?;
    ensure_access_lists_disjoint(&allowed, &banned)?;
    let pam = load_pam(transaction).await?;
    ensure_pam_unique(&pam)?;
    let registered = load_registered_nicks(transaction).await?;
    ensure_registered_unique(&registered)?;
    let invitations = load_active_invitations(transaction).await?;
    let sources = load_presence_sources(transaction).await?;
    ensure_no_collisions("mix_events(channel_id,presence,source_full_jid)", &sources)?;

    let mut transformed = 0_i64;
    transformed += update_channels(transaction, &channels).await?;

    // The original FK is non-deferrable.  Locks prevent concurrent writes;
    // dropping and recreating it inside this transaction permits both sides
    // of each key to move atomically, and rollback restores the old constraint.
    sqlx::query(
        "ALTER TABLE mix_participants DROP CONSTRAINT mix_participants_channel_id_jid_fkey",
    )
    .execute(&mut **transaction)
    .await?;
    transformed += update_participant_identities(transaction, &identities).await?;
    transformed += update_participants(transaction, &participants).await?;
    sqlx::query(
        "ALTER TABLE mix_participants ADD CONSTRAINT mix_participants_channel_id_jid_fkey
         FOREIGN KEY(channel_id,jid) REFERENCES mix_participant_identities(channel_id,jid) NOT VALID",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "ALTER TABLE mix_participants VALIDATE CONSTRAINT mix_participants_channel_id_jid_fkey",
    )
    .execute(&mut **transaction)
    .await?;

    transformed += update_scoped_column(transaction, "mix_channel_roles", "jid", &roles).await?;
    transformed +=
        update_scoped_column(transaction, "mix_allowed", "jid_pattern", &allowed).await?;
    transformed += update_scoped_column(transaction, "mix_banned", "jid_pattern", &banned).await?;
    transformed += update_pam(transaction, &pam).await?;
    transformed += update_registered(transaction, &registered).await?;
    transformed += update_invitations(transaction, &invitations).await?;
    transformed += update_presence_sources(transaction, &sources).await?;

    sqlx::query(
        "INSERT INTO jid_identity_migrations(migration,canonicalizer_version,transformed_rows) VALUES($1,$2,$3)",
    )
    .bind(MIGRATION)
    .bind(CANONICALIZER_VERSION)
    .bind(transformed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn load_channels(transaction: &mut Transaction<'_, Postgres>) -> Result<Vec<ChannelRow>> {
    let rows = sqlx::query(
        "SELECT id,service_domain,localpart,creator_jid,contacts FROM mix_channels ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    let mut channel_keys = BTreeMap::<(String, String), Uuid>::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let domain: String = row.get("service_domain");
        let localpart: String = row.get("localpart");
        let creator: String = row.get("creator_jid");
        let contacts: Value = row.get("contacts");
        let canonical_domain =
            northstar_xmpp_types::jid::prepare_domainpart(&domain).map_err(|error| {
                invalid(
                    "mix_channels.service_domain",
                    &id.to_string(),
                    &domain,
                    error,
                )
            })?;
        let canonical_localpart = northstar_xmpp_types::jid::prepare_localpart(&localpart)
            .map_err(|error| {
                invalid("mix_channels.localpart", &id.to_string(), &localpart, error)
            })?;
        if let Some(previous) =
            channel_keys.insert((canonical_domain.clone(), canonical_localpart.clone()), id)
        {
            anyhow::bail!(
                "MIX JID migration found channel address collision: channels {previous} and {id} both map to {canonical_localpart:?}@{canonical_domain:?}"
            );
        }
        let canonical_creator =
            canonical_user_bare("mix_channels.creator_jid", &id.to_string(), &creator)?;
        let array = contacts.as_array().context(format!(
            "MIX JID migration requires an array in mix_channels.contacts row {id}"
        ))?;
        let mut canonical_values = Vec::with_capacity(array.len());
        let mut unique = BTreeSet::new();
        for (index, value) in array.iter().enumerate() {
            let contact = value.as_str().context(format!(
                "MIX JID migration requires a string contact in channel {id} index {index}"
            ))?;
            let canonical =
                canonical_user_bare("mix_channels.contacts", &format!("{id}/{index}"), contact)?;
            anyhow::ensure!(
                unique.insert(canonical.clone()),
                "MIX JID migration found canonical contact collision in channel {id}: {contact:?} maps to duplicate {canonical:?}"
            );
            canonical_values.push(Value::String(canonical));
        }
        result.push(ChannelRow {
            id,
            domain,
            canonical_domain,
            localpart,
            canonical_localpart,
            creator,
            canonical_creator,
            contacts,
            canonical_contacts: Value::Array(canonical_values),
        });
    }
    Ok(result)
}

async fn load_participant_identities(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ParticipantIdentityRow>> {
    let rows = sqlx::query(
        "SELECT channel_id,jid,participant_id FROM mix_participant_identities ORDER BY channel_id,jid",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    let mut keys = BTreeMap::<(Uuid, String), String>::new();
    for row in rows {
        let channel_id: Uuid = row.get("channel_id");
        let participant_id: Uuid = row.get("participant_id");
        let original: String = row.get("jid");
        let canonical = canonical_user_bare(
            "mix_participant_identities.jid",
            &format!("{channel_id}/{participant_id}"),
            &original,
        )?;
        if let Some(previous) = keys.insert((channel_id, canonical.clone()), original.clone()) {
            anyhow::bail!(
                "MIX JID migration found participant identity collision in channel {channel_id}: {previous:?} and {original:?} both map to {canonical:?}"
            );
        }
        result.push(ParticipantIdentityRow {
            channel_id,
            participant_id,
            original,
            canonical,
        });
    }
    Ok(result)
}

async fn load_participants(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ParticipantRow>> {
    let rows = sqlx::query(
        "SELECT channel_id,participant_id,jid FROM mix_participants ORDER BY channel_id,participant_id",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    let mut keys = BTreeMap::<(Uuid, String), Uuid>::new();
    for row in rows {
        let channel_id: Uuid = row.get("channel_id");
        let participant_id: Uuid = row.get("participant_id");
        let original: String = row.get("jid");
        let canonical = canonical_user_bare(
            "mix_participants.jid",
            &format!("{channel_id}/{participant_id}"),
            &original,
        )?;
        if let Some(previous) = keys.insert((channel_id, canonical.clone()), participant_id) {
            anyhow::bail!(
                "MIX JID migration found participant collision in channel {channel_id}: participants {previous} and {participant_id} both map to {canonical:?}"
            );
        }
        result.push(ParticipantRow {
            channel_id,
            participant_id,
            original,
            canonical,
        });
    }
    Ok(result)
}

fn validate_participant_graph(
    identities: &[ParticipantIdentityRow],
    participants: &[ParticipantRow],
) -> Result<()> {
    let parents = identities
        .iter()
        .map(|row| {
            (
                (row.channel_id, row.original.as_str()),
                (row.participant_id, row.canonical.as_str()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for row in participants {
        let (participant_id, canonical) = parents
            .get(&(row.channel_id, row.original.as_str()))
            .context("MIX participant identity parent is missing")?;
        anyhow::ensure!(
            *participant_id == row.participant_id && *canonical == row.canonical,
            "MIX participant {} in channel {} does not match its stable identity parent",
            row.participant_id,
            row.channel_id
        );
    }
    Ok(())
}

async fn load_scoped_user_jids(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    query: &'static str,
) -> Result<Vec<ScopedJid>> {
    sqlx::query(query)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let scope: String = row.get("scope");
            let row_key: String = row.get("row_key");
            let original: String = row.get("value");
            let canonical = canonical_user_bare(table, &format!("{scope}/{row_key}"), &original)?;
            Ok(ScopedJid {
                scope,
                row_key,
                original,
                canonical,
            })
        })
        .collect()
}

async fn validate_creators_have_owner_roles(
    channels: &[ChannelRow],
    roles: &[ScopedJid],
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    let owner_rows = sqlx::query(
        "SELECT channel_id::text AS scope,jid FROM mix_channel_roles WHERE role='owner'",
    )
    .fetch_all(&mut **transaction)
    .await?;
    let mut canonical_owners = BTreeSet::new();
    for row in owner_rows {
        let scope: String = row.get("scope");
        let jid: String = row.get("jid");
        let canonical =
            canonical_user_bare("mix_channel_roles.jid", &format!("{scope}/{jid}"), &jid)?;
        canonical_owners.insert((scope, canonical));
    }
    for channel in channels {
        anyhow::ensure!(
            canonical_owners.contains(&(channel.id.to_string(), channel.canonical_creator.clone())),
            "MIX channel {} creator {:?} lacks its owner role; repair the authorization graph and restart",
            channel.id,
            channel.creator
        );
    }
    anyhow::ensure!(
        roles.iter().all(|role| !role.canonical.is_empty()),
        "MIX role canonicalization produced an empty key"
    );
    Ok(())
}

async fn load_access_patterns(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
) -> Result<Vec<ScopedJid>> {
    let query = format!(
        "SELECT channel_id::text AS scope,jid_pattern AS value,jid_pattern AS row_key FROM {table} ORDER BY channel_id,jid_pattern"
    );
    sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|row| {
            let scope: String = row.get("scope");
            let row_key: String = row.get("row_key");
            let original: String = row.get("value");
            let canonical = canonical_bare(table, &format!("{scope}/{row_key}"), &original)?;
            Ok(ScopedJid {
                scope,
                row_key,
                original,
                canonical,
            })
        })
        .collect()
}

fn ensure_access_lists_disjoint(allowed: &[ScopedJid], banned: &[ScopedJid]) -> Result<()> {
    let allowed = allowed
        .iter()
        .map(|row| (row.scope.as_str(), row.canonical.as_str()))
        .collect::<BTreeSet<_>>();
    for row in banned {
        anyhow::ensure!(
            !allowed.contains(&(row.scope.as_str(), row.canonical.as_str())),
            "MIX JID migration found cross-list collision in channel {}: {:?} is both allowed and banned after canonicalization; choose one policy and restart",
            row.scope,
            row.canonical
        );
    }
    Ok(())
}

async fn load_pam(transaction: &mut Transaction<'_, Postgres>) -> Result<Vec<PamRow>> {
    sqlx::query(
        "SELECT id,user_id,channel_jid,requester_full_jid FROM mix_pam_memberships ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let id: Uuid = row.get("id");
        let user_id: Uuid = row.get("user_id");
        let channel_jid: String = row.get("channel_jid");
        let requester_full_jid: Option<String> = row.get("requester_full_jid");
        let canonical_channel_jid = canonical_user_bare(
            "mix_pam_memberships.channel_jid",
            &id.to_string(),
            &channel_jid,
        )?;
        let canonical_requester_full_jid = requester_full_jid
            .as_deref()
            .map(|value| {
                canonical_full(
                    "mix_pam_memberships.requester_full_jid",
                    &id.to_string(),
                    value,
                )
            })
            .transpose()?;
        Ok(PamRow {
            id,
            user_id,
            channel_jid,
            canonical_channel_jid,
            requester_full_jid,
            canonical_requester_full_jid,
        })
    })
    .collect()
}

fn ensure_pam_unique(rows: &[PamRow]) -> Result<()> {
    let mut keys = BTreeMap::<(Uuid, &str), Uuid>::new();
    for row in rows {
        if let Some(previous) = keys.insert((row.user_id, &row.canonical_channel_jid), row.id) {
            anyhow::bail!(
                "MIX JID migration found PAM membership collision for user {} channel {:?}: memberships {previous} and {}",
                row.user_id,
                row.canonical_channel_jid,
                row.id
            );
        }
    }
    Ok(())
}

async fn load_registered_nicks(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<RegisteredNickRow>> {
    sqlx::query(
        "SELECT service_domain,jid,nick FROM mix_registered_nicks ORDER BY service_domain,jid",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let domain: String = row.get("service_domain");
        let jid: String = row.get("jid");
        let nick: String = row.get("nick");
        let key = format!("{domain}/{jid}");
        let canonical_domain =
            northstar_xmpp_types::jid::prepare_domainpart(&domain).map_err(|error| {
                invalid("mix_registered_nicks.service_domain", &key, &domain, error)
            })?;
        let canonical_jid = canonical_user_bare("mix_registered_nicks.jid", &key, &jid)?;
        Ok(RegisteredNickRow {
            domain,
            canonical_domain,
            jid,
            canonical_jid,
            nick,
        })
    })
    .collect()
}

fn ensure_registered_unique(rows: &[RegisteredNickRow]) -> Result<()> {
    let mut identities = BTreeMap::<(&str, &str), (&str, &str)>::new();
    let mut nicks = BTreeMap::<(&str, &str), (&str, &str)>::new();
    for row in rows {
        if let Some(previous) = identities.insert(
            (&row.canonical_domain, &row.canonical_jid),
            (&row.domain, &row.jid),
        ) {
            anyhow::bail!(
                "MIX JID migration found registered identity collision: {:?} and ({:?},{:?}) map to ({:?},{:?})",
                previous,
                row.domain,
                row.jid,
                row.canonical_domain,
                row.canonical_jid
            );
        }
        if let Some(previous) =
            nicks.insert((&row.canonical_domain, &row.nick), (&row.domain, &row.jid))
        {
            anyhow::bail!(
                "MIX JID migration found registered nick collision after service-domain canonicalization: {:?} and ({:?},{:?}) both own nick {:?}",
                previous,
                row.domain,
                row.jid,
                row.nick
            );
        }
    }
    Ok(())
}

async fn load_active_invitations(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<InvitationRow>> {
    sqlx::query(
        "SELECT id,inviter_jid,invitee_jid FROM mix_invitations
         WHERE consumed_at IS NULL AND expires_at > clock_timestamp() ORDER BY id",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let id: Uuid = row.get("id");
        let inviter: String = row.get("inviter_jid");
        let invitee: String = row.get("invitee_jid");
        let canonical_inviter =
            canonical_user_bare("mix_invitations.inviter_jid", &id.to_string(), &inviter)?;
        let canonical_invitee =
            canonical_user_bare("mix_invitations.invitee_jid", &id.to_string(), &invitee)?;
        Ok(InvitationRow {
            id,
            inviter,
            canonical_inviter,
            invitee,
            canonical_invitee,
        })
    })
    .collect()
}

async fn load_presence_sources(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ScopedJid>> {
    sqlx::query(
        "SELECT id::text AS row_key,channel_id::text AS scope,source_full_jid AS value
         FROM mix_events WHERE node=$1 AND source_full_jid IS NOT NULL ORDER BY channel_id,id",
    )
    .bind(PRESENCE_NODE)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let scope: String = row.get("scope");
        let row_key: String = row.get("row_key");
        let original: String = row.get("value");
        let canonical = canonical_full("mix_events.source_full_jid", &row_key, &original)?;
        Ok(ScopedJid {
            scope,
            row_key,
            original,
            canonical,
        })
    })
    .collect()
}

async fn update_channels(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[ChannelRow],
) -> Result<i64> {
    let mut changed = 0;
    for row in rows {
        if row.domain != row.canonical_domain
            || row.localpart != row.canonical_localpart
            || row.creator != row.canonical_creator
            || row.contacts != row.canonical_contacts
        {
            changed += sqlx::query(
                "UPDATE mix_channels SET service_domain=$2,localpart=$3,creator_jid=$4,contacts=$5 WHERE id=$1",
            )
            .bind(row.id)
            .bind(&row.canonical_domain)
            .bind(&row.canonical_localpart)
            .bind(&row.canonical_creator)
            .bind(&row.canonical_contacts)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn update_participant_identities(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[ParticipantIdentityRow],
) -> Result<i64> {
    let mut changed = 0;
    for row in rows.iter().filter(|row| row.original != row.canonical) {
        changed += sqlx::query(
            "UPDATE mix_participant_identities SET jid=$3 WHERE channel_id=$1 AND participant_id=$2 AND jid=$4",
        )
        .bind(row.channel_id)
        .bind(row.participant_id)
        .bind(&row.canonical)
        .bind(&row.original)
        .execute(&mut **transaction)
        .await?
        .rows_affected() as i64;
    }
    Ok(changed)
}

async fn update_participants(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[ParticipantRow],
) -> Result<i64> {
    let mut changed = 0;
    for row in rows.iter().filter(|row| row.original != row.canonical) {
        changed += sqlx::query(
            "UPDATE mix_participants SET jid=$3 WHERE channel_id=$1 AND participant_id=$2 AND jid=$4",
        )
        .bind(row.channel_id)
        .bind(row.participant_id)
        .bind(&row.canonical)
        .bind(&row.original)
        .execute(&mut **transaction)
        .await?
        .rows_affected() as i64;
    }
    Ok(changed)
}

async fn update_scoped_column(
    transaction: &mut Transaction<'_, Postgres>,
    table: &str,
    column: &str,
    rows: &[ScopedJid],
) -> Result<i64> {
    let statement =
        format!("UPDATE {table} SET {column}=$3 WHERE channel_id=$1::uuid AND {column}=$2");
    let mut changed = 0;
    for row in rows.iter().filter(|row| row.original != row.canonical) {
        changed += sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
            .bind(&row.scope)
            .bind(&row.original)
            .bind(&row.canonical)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
    }
    Ok(changed)
}

async fn update_pam(transaction: &mut Transaction<'_, Postgres>, rows: &[PamRow]) -> Result<i64> {
    let mut changed = 0;
    for row in rows {
        if row.channel_jid != row.canonical_channel_jid
            || row.requester_full_jid != row.canonical_requester_full_jid
        {
            changed += sqlx::query(
                "UPDATE mix_pam_memberships SET channel_jid=$2,requester_full_jid=$3 WHERE id=$1",
            )
            .bind(row.id)
            .bind(&row.canonical_channel_jid)
            .bind(&row.canonical_requester_full_jid)
            .execute(&mut **transaction)
            .await?
            .rows_affected() as i64;
        }
    }
    Ok(changed)
}

async fn update_registered(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[RegisteredNickRow],
) -> Result<i64> {
    let mut changed = 0;
    for row in rows
        .iter()
        .filter(|row| row.domain != row.canonical_domain || row.jid != row.canonical_jid)
    {
        changed += sqlx::query(
            "UPDATE mix_registered_nicks SET service_domain=$3,jid=$4 WHERE service_domain=$1 AND jid=$2",
        )
        .bind(&row.domain)
        .bind(&row.jid)
        .bind(&row.canonical_domain)
        .bind(&row.canonical_jid)
        .execute(&mut **transaction)
        .await?
        .rows_affected() as i64;
    }
    Ok(changed)
}

async fn update_invitations(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[InvitationRow],
) -> Result<i64> {
    let mut changed = 0;
    for row in rows
        .iter()
        .filter(|row| row.inviter != row.canonical_inviter || row.invitee != row.canonical_invitee)
    {
        changed +=
            sqlx::query("UPDATE mix_invitations SET inviter_jid=$2,invitee_jid=$3 WHERE id=$1")
                .bind(row.id)
                .bind(&row.canonical_inviter)
                .bind(&row.canonical_invitee)
                .execute(&mut **transaction)
                .await?
                .rows_affected() as i64;
    }
    Ok(changed)
}

async fn update_presence_sources(
    transaction: &mut Transaction<'_, Postgres>,
    rows: &[ScopedJid],
) -> Result<i64> {
    let mut changed = 0;
    for row in rows.iter().filter(|row| row.original != row.canonical) {
        changed +=
            sqlx::query("UPDATE mix_events SET source_full_jid=$2 WHERE id=$1::uuid AND node=$3")
                .bind(&row.row_key)
                .bind(&row.canonical)
                .bind(PRESENCE_NODE)
                .execute(&mut **transaction)
                .await?
                .rows_affected() as i64;
    }
    Ok(changed)
}
