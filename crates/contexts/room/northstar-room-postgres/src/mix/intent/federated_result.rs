use super::*;

pub(super) async fn lock_federated_result_key(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated_domain: &str,
    actor_jid: &str,
    request_id: &str,
    request_digest: &[u8; 32],
) -> Result<FederatedMixIqReplay> {
    sqlx::query(
        "SELECT pg_advisory_xact_lock(
             hashtextextended($1 || E'\\n' || $2 || E'\\n' || $3, 0)
         )",
    )
    .bind(authenticated_domain)
    .bind(actor_jid)
    .bind(request_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "DELETE FROM mix_federated_iq_results
          WHERE authenticated_domain=$1 AND actor_jid=$2 AND request_id=$3
            AND expires_at<=clock_timestamp()",
    )
    .bind(authenticated_domain)
    .bind(actor_jid)
    .bind(request_id)
    .execute(&mut **transaction)
    .await?;
    read_federated_result(
        &mut **transaction,
        authenticated_domain,
        actor_jid,
        request_id,
        request_digest,
        true,
    )
    .await
}

/// Journal while holding the admission fence acquired by `guard_federated_mix_mutation_tx`.
pub async fn finalize_mix_iq(
    effects: &impl crate::effects::RoomEffects,
    transaction: &mut Transaction<'_, Postgres>,
    context: Option<&FederatedMixMutation>,
    outcome: FederatedMixOutcome,
    payloads: &dyn MixEventPayloadRenderer,
) -> Result<()> {
    let Some(context) = context else {
        return Ok(());
    };
    let response = outcome.render(context, payloads)?;
    insert_federated_result(
        transaction,
        &context.authenticated_domain,
        &context.actor_jid,
        &context.request_id,
        &context.request_digest,
        &response,
    )
    .await?;
    effects
        .enqueue_federated_stanza(
            transaction,
            &context.authenticated_domain,
            &response,
            None,
            context.policy,
        )
        .await?;
    Ok(())
}

pub(super) async fn insert_federated_result(
    transaction: &mut Transaction<'_, Postgres>,
    authenticated_domain: &str,
    actor_jid: &str,
    request_id: &str,
    request_digest: &[u8; 32],
    response: &str,
) -> Result<()> {
    anyhow::ensure!(
        !response.is_empty() && response.len() <= 2_097_152,
        "invalid federated MIX IQ result"
    );
    let inserted = sqlx::query(
        "INSERT INTO mix_federated_iq_results(
             authenticated_domain,actor_jid,request_id,request_digest,response
         ) VALUES($1,$2,$3,$4,$5)
         ON CONFLICT(authenticated_domain,actor_jid,request_id) DO NOTHING",
    )
    .bind(authenticated_domain)
    .bind(actor_jid)
    .bind(request_id)
    .bind(request_digest.as_slice())
    .bind(response)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        inserted == 1,
        "federated MIX result fence changed inside one transaction"
    );
    Ok(())
}

pub(super) async fn read_federated_result<'executor>(
    executor: impl sqlx::PgExecutor<'executor>,
    authenticated_domain: &str,
    actor_jid: &str,
    request_id: &str,
    request_digest: &[u8; 32],
    include_expired: bool,
) -> Result<FederatedMixIqReplay> {
    let row = sqlx::query(
        "SELECT request_digest,response FROM mix_federated_iq_results
          WHERE authenticated_domain=$1 AND actor_jid=$2 AND request_id=$3
            AND ($4 OR expires_at>clock_timestamp())",
    )
    .bind(authenticated_domain)
    .bind(actor_jid)
    .bind(request_id)
    .bind(include_expired)
    .fetch_optional(executor)
    .await?;
    let Some(row) = row else {
        return Ok(FederatedMixIqReplay::Miss);
    };
    if row.get::<Vec<u8>, _>("request_digest").as_slice() == request_digest {
        Ok(FederatedMixIqReplay::Replay(row.get("response")))
    } else {
        Ok(FederatedMixIqReplay::Conflict)
    }
}
