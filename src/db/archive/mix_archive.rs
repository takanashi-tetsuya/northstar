//! Exactly-once archiving of reflected MIX messages into personal archives.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceArchiveAdmission {
    Stored(Uuid),
    Replay(Uuid),
}

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
pub(super) async fn archive_mix_message_once_inner(
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
    let payload_digest = digest.finalize().to_vec();

    let mut transaction = pool.begin().await?;
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
    .bind(&channel)
    .bind(stanza)
    .bind(encrypted)
    .bind(client_stanza_id)
    .bind(authoritative_stanza_id)
    .bind(&payload_digest)
    .execute(&mut *transaction)
    .await?
    .rows_affected()
        == 1;
    if inserted {
        commit_mix_archive(
            transaction,
            observation,
            SourceArchiveAdmission::Stored(personal_archive_id),
        )
        .await?;
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
    .bind(&channel)
    .bind(authoritative_stanza_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("MIX source identity conflict row disappeared during admission");
    };
    let exact_replay = row.get::<String, _>("peer_jid") == channel
        && row.get::<String, _>("peer_full_jid") == channel
        && row.get::<String, _>("stanza") == stanza
        && row.get::<bool, _>("encrypted") == encrypted
        && row.get::<Option<String>, _>("stanza_id").as_deref() == client_stanza_id
        && row.get::<Option<String>, _>("source_by").as_deref() == Some(channel.as_str())
        && row.get::<Option<Uuid>, _>("source_stanza_id") == Some(authoritative_stanza_id)
        && row
            .get::<Option<Vec<u8>>, _>("source_payload_digest")
            .as_deref()
            == Some(payload_digest.as_slice());
    anyhow::ensure!(exact_replay, "conflicting MIX source stanza identity");
    let existing_id: Uuid = row.get("id");
    commit_mix_archive(
        transaction,
        observation,
        SourceArchiveAdmission::Replay(existing_id),
    )
    .await?;
    Ok(SourceArchiveAdmission::Replay(existing_id))
}

pub(super) async fn commit_mix_archive(
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
        .map_err(crate::services::mix::outbox::commit_error)
    } else {
        transaction.commit().await.map_err(Into::into)
    }
}
