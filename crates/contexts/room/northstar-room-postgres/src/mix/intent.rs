//! MIX business-intent idempotency and federated MIX IQ replay admission.

use super::*;
use northstar_room_application::mix_service::{
    FederatedMixIqAlreadyFinalized, FederatedMixIqConflict, FederatedMixOutcome,
};

mod federated_result;
pub use self::federated_result::finalize_mix_iq;
use self::federated_result::{
    insert_federated_result, lock_federated_result_key, read_federated_result,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MixIntentEvidence {
    pub authoritative_id: Uuid,
    pub semantic_key_id: String,
    pub semantic_mac: Vec<u8>,
    pub target_id: Option<Uuid>,
}

pub fn foreground_existing(raw: &MixIntentEvidence) -> northstar_room_core::mix::Existing {
    northstar_room_core::mix::Existing {
        authoritative_id: raw.authoritative_id,
        semantic_key_id: raw.semantic_key_id.clone(),
        semantic_mac: raw.semantic_mac.clone(),
        target_id: raw.target_id,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MixBusinessIdentity<'a> {
    pub client_id: &'a str,
    pub semantic_key_id: &'a str,
    pub semantic_mac: &'a [u8; 32],
}

/// Read an unexpired replay commitment before consulting mutable channel
/// policy. An exact retry must keep returning the original authoritative
/// outcome even if the actor subsequently leaves, permissions change, or the
/// retracted event ages out. A miss is not inserted here: first execution is
/// still admitted only after all current authorization checks succeed.
pub async fn existing_mix_business_intent_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    actor: &str,
    operation: &str,
    client_id: &str,
) -> Result<Option<MixIntentEvidence>> {
    anyhow::ensure!(
        !client_id.is_empty() && client_id.len() <= 1_024,
        "invalid MIX client replay id"
    );
    let row = sqlx::query(
        "SELECT authoritative_id,semantic_key_id,semantic_mac,target_id
           FROM mix_business_intents
          WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3 AND operation=$4
            AND expires_at>clock_timestamp()
          FOR SHARE",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(client_id)
    .bind(operation)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(row.map(|row| MixIntentEvidence {
        authoritative_id: row.get("authoritative_id"),
        semantic_key_id: row.get("semantic_key_id"),
        semantic_mac: row.get("semantic_mac"),
        target_id: row.get("target_id"),
    }))
}

pub async fn lookup_mix_business_intent(
    pool: &PgPool,
    channel_id: Uuid,
    actor: &str,
    operation: &str,
    client_id: &str,
) -> Result<Option<MixIntentEvidence>> {
    let actor = canonical_user_bare(actor)?;
    anyhow::ensure!(
        matches!(operation, "message" | "retraction"),
        "invalid MIX replay operation"
    );
    anyhow::ensure!(
        !client_id.is_empty() && client_id.len() <= 1_024,
        "invalid MIX client replay id"
    );
    let row = sqlx::query(
        "SELECT authoritative_id,semantic_key_id,semantic_mac,target_id
           FROM mix_business_intents
          WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3 AND operation=$4
            AND expires_at>clock_timestamp()",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(client_id)
    .bind(operation)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| MixIntentEvidence {
        authoritative_id: row.get("authoritative_id"),
        semantic_key_id: row.get("semantic_key_id"),
        semantic_mac: row.get("semantic_mac"),
        target_id: row.get("target_id"),
    }))
}

pub async fn admit_mix_business_intent_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: Uuid,
    actor: &str,
    operation: &str,
    identity: MixBusinessIdentity<'_>,
    authoritative_id: Uuid,
    target_id: Option<Uuid>,
) -> Result<Option<MixIntentEvidence>> {
    anyhow::ensure!(
        !identity.client_id.is_empty() && identity.client_id.len() <= 1_024,
        "invalid MIX client replay id"
    );
    anyhow::ensure!(
        identity.semantic_key_id.len() == 16
            && identity
                .semantic_key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')),
        "invalid MIX semantic key id"
    );
    sqlx::query(
        "DELETE FROM mix_business_intents
          WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3
            AND operation=$4 AND expires_at<=clock_timestamp()",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(identity.client_id)
    .bind(operation)
    .execute(&mut **transaction)
    .await?;
    let inserted = sqlx::query(
        "INSERT INTO mix_business_intents(channel_id,actor_jid,client_id,operation,semantic_key_id,semantic_mac,authoritative_id,target_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(channel_id,actor_jid,client_id,operation) DO NOTHING",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(identity.client_id)
    .bind(operation)
    .bind(identity.semantic_key_id)
    .bind(identity.semantic_mac.as_slice())
    .bind(authoritative_id)
    .bind(target_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT authoritative_id,semantic_key_id,semantic_mac,target_id FROM mix_business_intents WHERE channel_id=$1 AND actor_jid=$2 AND client_id=$3 AND operation=$4 FOR SHARE",
    )
    .bind(channel_id)
    .bind(actor)
    .bind(identity.client_id)
    .bind(operation)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(Some(MixIntentEvidence {
        authoritative_id: row.get("authoritative_id"),
        semantic_key_id: row.get("semantic_key_id"),
        semantic_mac: row.get("semantic_mac"),
        target_id: row.get("target_id"),
    }))
}

/// Remove a bounded page of replay intents whose commitment is no longer
/// authoritative.  `SKIP LOCKED` keeps cleanup independent from live
/// admissions, while deleting by the complete primary key prevents a row
/// renewed by another transaction from being removed accidentally.
pub async fn prune_expired_mix_business_intents(pool: &PgPool, limit: i64) -> Result<u64> {
    let removed = sqlx::query(
        "WITH expired AS (
             SELECT channel_id,actor_jid,client_id,operation
               FROM mix_business_intents
              WHERE expires_at<=clock_timestamp()
              ORDER BY expires_at,channel_id,actor_jid,client_id,operation
              LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM mix_business_intents intent
          USING expired
          WHERE intent.channel_id=expired.channel_id
            AND intent.actor_jid=expired.actor_jid
            AND intent.client_id=expired.client_id
            AND intent.operation=expired.operation",
    )
    .bind(limit.clamp(1, 2_048))
    .execute(pool)
    .await?
    .rows_affected();
    Ok(removed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederatedMixIqReplay {
    Miss,
    Replay(String),
    Conflict,
}

pub fn validate_federated_mix_mutation(context: &FederatedMixMutation) -> Result<()> {
    anyhow::ensure!(
        northstar_xmpp_types::jid::prepare_domainpart(&context.authenticated_domain)?
            == context.authenticated_domain,
        "non-canonical federated MIX authenticated domain"
    );
    anyhow::ensure!(
        northstar_xmpp_types::jid::CanonicalJid::parse(&context.actor_jid)?.to_string()
            == context.actor_jid,
        "non-canonical federated MIX actor JID"
    );
    anyhow::ensure!(
        !context.request_id.is_empty() && context.request_id.len() <= 1_024,
        "invalid federated MIX IQ id"
    );
    anyhow::ensure!(
        !context.addressed.is_empty()
            && context.addressed.len() <= 3_071
            && !context.reply_to.is_empty()
            && context.reply_to.len() <= 3_071,
        "invalid federated MIX IQ addresses"
    );
    Ok(())
}

/// Serialize equal authenticated mutation keys before touching authority.
/// If a concurrent/exact replay already finalized while this transaction was
/// waiting, stop before any state change and return the durable response to
/// the protocol. A changed digest returns the typed conflict instead. The
/// advisory key is only a serialization fence, never a
/// security identity or durable commitment.
pub async fn guard_federated_mix_mutation_tx(
    transaction: &mut Transaction<'_, Postgres>,
    context: Option<&FederatedMixMutation>,
) -> Result<()> {
    let Some(context) = context else {
        return Ok(());
    };
    validate_federated_mix_mutation(context)?;
    match lock_federated_result_key(
        transaction,
        &context.authenticated_domain,
        &context.actor_jid,
        &context.request_id,
        &context.request_digest,
    )
    .await?
    {
        FederatedMixIqReplay::Miss => Ok(()),
        FederatedMixIqReplay::Replay(response) => {
            Err(FederatedMixIqAlreadyFinalized::new(response).into())
        }
        FederatedMixIqReplay::Conflict => Err(FederatedMixIqConflict.into()),
    }
}

/// Persist the exact successful IQ result and its durable S2S delivery in the
/// same transaction as the authoritative state change. Once this succeeds,
/// a process kill can at worst delay delivery; an exact retry returns the
/// journaled bytes and never executes the business mutation again.
pub async fn finalize_federated_mix_mutation_tx(
    effects: &impl crate::effects::RoomEffects,
    transaction: &mut Transaction<'_, Postgres>,
    context: Option<&FederatedMixMutation>,
    success: FederatedMixSuccess,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<()> {
    finalize_mix_iq(
        effects,
        transaction,
        context,
        FederatedMixOutcome::Success(success),
        payloads,
    )
    .await
}

pub async fn federated_mix_iq_replay(
    pool: &PgPool,
    authenticated_domain: &str,
    actor_jid: &str,
    request_id: &str,
    request_digest: &[u8; 32],
) -> Result<FederatedMixIqReplay> {
    let authenticated_domain = northstar_xmpp_types::jid::prepare_domainpart(authenticated_domain)?;
    let actor_jid = northstar_xmpp_types::jid::CanonicalJid::parse(actor_jid)?.to_string();
    anyhow::ensure!(
        !request_id.is_empty() && request_id.len() <= 1_024,
        "invalid federated MIX IQ id"
    );
    read_federated_result(
        pool,
        &authenticated_domain,
        &actor_jid,
        request_id,
        request_digest,
        false,
    )
    .await
}

/// Persist the exact authenticated mutation result and admit its S2S reply in
/// one transaction. A retry with changed bytes cannot reuse the IQ id; an
/// exact retry re-enqueues the original result rather than recomputing it.
#[allow(clippy::too_many_arguments)]
pub async fn admit_federated_mix_iq_result(
    effects: &impl crate::effects::RoomEffects,
    pool: &PgPool,
    authenticated_domain: &str,
    actor_jid: &str,
    request_id: &str,
    request_digest: &[u8; 32],
    response: &str,
    policy: northstar_federation_core::S2sOutboxPolicy,
) -> Result<FederatedMixIqReplay> {
    let authenticated_domain = northstar_xmpp_types::jid::prepare_domainpart(authenticated_domain)?;
    let actor_jid = northstar_xmpp_types::jid::CanonicalJid::parse(actor_jid)?.to_string();
    anyhow::ensure!(
        !request_id.is_empty() && request_id.len() <= 1_024,
        "invalid federated MIX IQ id"
    );
    anyhow::ensure!(
        !response.is_empty() && response.len() <= 2_097_152,
        "invalid federated MIX IQ result"
    );
    let mut transaction = pool.begin().await?;
    let exact_response = match lock_federated_result_key(
        &mut transaction,
        &authenticated_domain,
        &actor_jid,
        request_id,
        request_digest,
    )
    .await?
    {
        FederatedMixIqReplay::Miss => {
            insert_federated_result(
                &mut transaction,
                &authenticated_domain,
                &actor_jid,
                request_id,
                request_digest,
                response,
            )
            .await?;
            response.to_owned()
        }
        FederatedMixIqReplay::Replay(response) => response,
        FederatedMixIqReplay::Conflict => {
            transaction.rollback().await?;
            return Ok(FederatedMixIqReplay::Conflict);
        }
    };
    effects
        .enqueue_federated_stanza(
            &mut transaction,
            &authenticated_domain,
            &exact_response,
            None,
            policy,
        )
        .await?;
    transaction.commit().await?;
    Ok(FederatedMixIqReplay::Replay(exact_response))
}

pub async fn prune_expired_federated_mix_iq_results(pool: &PgPool, limit: i64) -> Result<u64> {
    let removed = sqlx::query(
        "WITH expired AS (
             SELECT authenticated_domain,actor_jid,request_id
               FROM mix_federated_iq_results
              WHERE expires_at<=clock_timestamp()
              ORDER BY expires_at,authenticated_domain,actor_jid,request_id
              LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM mix_federated_iq_results result
          USING expired
          WHERE result.authenticated_domain=expired.authenticated_domain
            AND result.actor_jid=expired.actor_jid
            AND result.request_id=expired.request_id",
    )
    .bind(limit.clamp(1, 2_048))
    .execute(pool)
    .await?
    .rows_affected();
    Ok(removed)
}
