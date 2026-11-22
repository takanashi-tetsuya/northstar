//! Exactly-once archiving of reflected MIX messages into personal archives.

use anyhow::Result;
use northstar_archive_postgres::mix_source_retractions::{
    action_binding_in_tx, lock_sources_in_tx, primary_retraction_in_tx, record_locked_in_tx,
    MixSourceRetraction,
};
use northstar_archive_postgres::personal_display::render_mix_source_tombstone;
use northstar_room_application::mix_service::{
    valid_stable_participant_id, MixReflectionKind, ReflectedMixArchiveOutcome,
    VerifiedMixReflection,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub use northstar_room_application::mix_service::SourceArchiveAdmission;

/// Store a reflected MIX message in a personal archive exactly once per
/// channel authority and authoritative stanza-id.  A retry with the same key
/// is accepted only when all persisted content is identical; a conflicting
/// payload is rejected instead of being silently misclassified as a replay.
#[allow(clippy::too_many_arguments)]
pub async fn archive_mix_message_once(
    pool: &PgPool,
    personal_archive_id: Uuid,
    owner_id: Uuid,
    channel_jid: &str,
    authoritative_stanza_id: Uuid,
    stanza: &str,
    encrypted: bool,
    client_stanza_id: Option<&str>,
) -> Result<SourceArchiveAdmission> {
    archive_mix_message_once_inner(
        pool,
        personal_archive_id,
        owner_id,
        channel_jid,
        authoritative_stanza_id,
        stanza,
        encrypted,
        client_stanza_id,
        None,
    )
    .await
}

pub async fn archive_mix_message_once_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::mix_outbox::ArchiveRequest,
) -> Result<SourceArchiveAdmission> {
    let command = request.command();
    archive_mix_message_once_inner(
        pool,
        command.personal_archive_id,
        command.owner_id,
        &command.channel_jid,
        command.authoritative_stanza_id,
        &command.stanza,
        command.encrypted,
        command.client_stanza_id.as_deref(),
        Some(request),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn archive_mix_message_once_inner(
    pool: &PgPool,
    personal_archive_id: Uuid,
    owner_id: Uuid,
    channel_jid: &str,
    authoritative_stanza_id: Uuid,
    stanza: &str,
    encrypted: bool,
    client_stanza_id: Option<&str>,
    observation: Option<&northstar_delivery_core::mix_outbox::ArchiveRequest>,
) -> Result<SourceArchiveAdmission> {
    let prepared = prepare_source_archive(SourceArchiveInput {
        personal_archive_id,
        owner_id,
        channel_jid,
        authoritative_stanza_id,
        stanza,
        encrypted,
        client_stanza_id,
    })?;
    let mut transaction = begin_source_archive(pool).await?;
    lock_sources_in_tx(
        &mut transaction,
        channel_jid,
        &[authoritative_stanza_id],
        false,
    )
    .await?;
    let primary =
        primary_retraction_in_tx(&mut transaction, channel_jid, authoritative_stanza_id).await?;
    let outcome =
        archive_mix_message_once_in_tx(&mut transaction, &prepared, primary.as_ref()).await?;
    commit_mix_archive(transaction, observation, outcome).await?;
    Ok(outcome)
}

pub(super) async fn archive_verified_mix_reflection(
    pool: &PgPool,
    request: VerifiedMixReflection<'_>,
) -> Result<ReflectedMixArchiveOutcome> {
    let action = request.authoritative_stanza_id;
    let client_stanza_id = action.to_string();
    let channel = request.channel_jid;
    if let MixReflectionKind::Retraction {
        target_id,
        source_participant,
    } = request.kind
    {
        anyhow::ensure!(
            target_id != action
                && valid_stable_participant_id(source_participant)
                && !request.encrypted,
            "invalid verified MIX retraction identity or encryption"
        );
    }
    let prepared = prepare_source_archive(SourceArchiveInput {
        personal_archive_id: request.personal_archive_id,
        owner_id: request.owner_id,
        channel_jid: channel,
        authoritative_stanza_id: action,
        stanza: request.stanza,
        encrypted: request.encrypted,
        client_stanza_id: Some(&client_stanza_id),
    })?;
    let mut transaction = begin_source_archive(pool).await?;
    let bound = match request.kind {
        MixReflectionKind::Original => {
            lock_sources_in_tx(&mut transaction, channel, &[action], false).await?;
            action_binding_in_tx(&mut transaction, channel, action)
                .await?
                .is_none()
        }
        MixReflectionKind::Retraction {
            target_id,
            source_participant,
        } => {
            lock_sources_in_tx(&mut transaction, channel, &[target_id, action], true).await?;
            record_locked_in_tx(
                &mut transaction,
                channel,
                target_id,
                action,
                source_participant,
            )
            .await?
        }
    };
    if !bound {
        transaction.rollback().await?;
        return Ok(ReflectedMixArchiveOutcome::Conflict);
    }
    let primary = primary_retraction_in_tx(&mut transaction, channel, action).await?;
    match archive_mix_message_once_in_tx(&mut transaction, &prepared, primary.as_ref()).await {
        Ok(outcome) => {
            transaction.commit().await?;
            Ok(ReflectedMixArchiveOutcome::Archived(outcome))
        }
        Err(MixArchiveError::Conflict) => {
            transaction.rollback().await?;
            Ok(ReflectedMixArchiveOutcome::Conflict)
        }
        Err(error) => Err(error.into()),
    }
}

async fn begin_source_archive(pool: &PgPool) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

struct SourceArchiveInput<'a> {
    personal_archive_id: Uuid,
    owner_id: Uuid,
    channel_jid: &'a str,
    authoritative_stanza_id: Uuid,
    stanza: &'a str,
    encrypted: bool,
    client_stanza_id: Option<&'a str>,
}

struct PreparedSourceArchive<'a> {
    input: SourceArchiveInput<'a>,
    payload_digest: Vec<u8>,
}

fn prepare_source_archive(input: SourceArchiveInput<'_>) -> Result<PreparedSourceArchive<'_>> {
    let SourceArchiveInput {
        channel_jid,
        authoritative_stanza_id,
        stanza,
        encrypted,
        client_stanza_id,
        ..
    } = input;
    anyhow::ensure!(
        !stanza.is_empty() && stanza.len() <= 1_048_576,
        "MIX archive stanza must contain 1 to 1048576 bytes"
    );
    if let Some(client_stanza_id) = client_stanza_id {
        anyhow::ensure!(
            !client_stanza_id.is_empty() && client_stanza_id.len() <= 128,
            "client stanza id must contain 1 to 128 bytes"
        );
    }
    let channel = northstar_xmpp_types::jid::CanonicalJid::parse_bare(channel_jid)?;
    anyhow::ensure!(
        channel.localpart().is_some(),
        "MIX channel authority must be a bare channel JID"
    );
    let channel = channel.to_string();
    anyhow::ensure!(
        channel == channel_jid,
        "MIX channel authority must already be canonical"
    );
    let mut digest = Sha256::new();
    digest.update(b"northstar:personal-mix-archive:v1\0");
    digest.update((channel.len() as u32).to_be_bytes());
    digest.update(channel.as_bytes());
    digest.update(authoritative_stanza_id.as_bytes());
    digest.update([u8::from(encrypted)]);
    digest.update((stanza.len() as u32).to_be_bytes());
    digest.update(stanza.as_bytes());
    Ok(PreparedSourceArchive {
        input,
        payload_digest: digest.finalize().to_vec(),
    })
}

#[derive(Debug, thiserror::Error)]
enum MixArchiveError {
    #[error("conflicting MIX source stanza identity")]
    Conflict,
    #[error("MIX source identity conflict row disappeared during admission")]
    MissingConflict,
    #[error(transparent)]
    Storage(#[from] sqlx::Error),
}

async fn archive_mix_message_once_in_tx(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: &PreparedSourceArchive<'_>,
    primary: Option<&MixSourceRetraction>,
) -> std::result::Result<SourceArchiveAdmission, MixArchiveError> {
    let SourceArchiveInput {
        personal_archive_id,
        owner_id,
        channel_jid: channel,
        authoritative_stanza_id,
        stanza,
        encrypted,
        client_stanza_id,
    } = prepared.input;
    let tombstone = primary
        .map(|fact| render_mix_source_tombstone(stanza, channel, authoritative_stanza_id, fact));
    let inserted = sqlx::query(
        "INSERT INTO message_archive
         (id, owner_id, peer_jid, peer_full_jid, stanza, encrypted, stanza_id,
          source_by, source_stanza_id, source_payload_digest)
         VALUES ($1, $2, $3, $3, $4, $5, $6, $3, $7, $8)
         ON CONFLICT (owner_id, source_by, source_stanza_id)
         WHERE source_stanza_id IS NOT NULL
         DO NOTHING",
    )
    .bind(personal_archive_id)
    .bind(owner_id)
    .bind(channel)
    .bind(tombstone.as_deref().unwrap_or(stanza))
    .bind(primary.is_none() && encrypted)
    .bind(client_stanza_id)
    .bind(authoritative_stanza_id)
    .bind(&prepared.payload_digest)
    .execute(&mut **transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        return Ok(SourceArchiveAdmission::Stored(personal_archive_id));
    }

    let row = sqlx::query(
        "SELECT id, peer_jid, peer_full_jid, stanza, encrypted, stanza_id,
                source_by, source_stanza_id, source_payload_digest
         FROM message_archive
         WHERE owner_id=$1 AND source_by=$2 AND source_stanza_id=$3
         FOR SHARE",
    )
    .bind(owner_id)
    .bind(channel)
    .bind(authoritative_stanza_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        return Err(MixArchiveError::MissingConflict);
    };
    let exact_replay = row.get::<String, _>("peer_jid") == channel
        && row.get::<String, _>("peer_full_jid") == channel
        && (primary.is_some()
            || (row.get::<String, _>("stanza") == stanza
                && row.get::<bool, _>("encrypted") == encrypted))
        && row.get::<Option<String>, _>("stanza_id").as_deref() == client_stanza_id
        && row.get::<Option<String>, _>("source_by").as_deref() == Some(channel)
        && row.get::<Option<Uuid>, _>("source_stanza_id") == Some(authoritative_stanza_id)
        && row
            .get::<Option<Vec<u8>>, _>("source_payload_digest")
            .as_deref()
            == Some(prepared.payload_digest.as_slice());
    if !exact_replay {
        return Err(MixArchiveError::Conflict);
    }
    Ok(SourceArchiveAdmission::Replay(row.get("id")))
}

async fn commit_mix_archive(
    transaction: Transaction<'_, Postgres>,
    observation: Option<&northstar_delivery_core::mix_outbox::ArchiveRequest>,
    outcome: SourceArchiveAdmission,
) -> Result<()> {
    if let Some(request) = observation {
        let result = match outcome {
            SourceArchiveAdmission::Stored(id) => {
                northstar_delivery_core::mix_outbox::ArchiveResult::Stored(id)
            }
            SourceArchiveAdmission::Replay(id) => {
                northstar_delivery_core::mix_outbox::ArchiveResult::Replay(id)
            }
        };
        northstar_delivery_core::mix_outbox::archive_commit_observed(
            transaction.commit(),
            request,
            result,
        )
        .await
        .map_err(northstar_room_application::mix_service::outbox::commit_error)
    } else {
        transaction.commit().await.map_err(Into::into)
    }
}
