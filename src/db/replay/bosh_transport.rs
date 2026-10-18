//! Bind, renew, acknowledge and release durable C2S and MIX ownership for BOSH responses.

use super::*;

pub(super) async fn bind_bosh_transport_response_inner(
    pool: &PgPool,
    session_id: Uuid,
    response_rid: u64,
    sources: &[crate::xmpp::outbound::TransportOwnershipSource],
    ttl_seconds: u64,
    observation: Option<&northstar_delivery_core::bosh_ownership::response::BindRequest>,
) -> Result<crate::xmpp::outbound::BoshResponseOwnership> {
    let response_rid = i64::try_from(response_rid).context("BOSH RID exceeds bigint")?;
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, BOSH_FENCE_MAX_AGE_SECONDS as u64))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut c2s = BTreeMap::new();
    let mut mix = BTreeMap::new();
    for source in sources {
        match source {
            crate::xmpp::outbound::TransportOwnershipSource::C2s(delivery) => {
                anyhow::ensure!(
                    c2s.insert(delivery.message_id, *delivery).is_none(),
                    "duplicate C2S durable delivery in one BOSH response"
                );
            }
            crate::xmpp::outbound::TransportOwnershipSource::Mix(delivery) => {
                anyhow::ensure!(
                    mix.insert(delivery.delivery_id, *delivery).is_none(),
                    "duplicate MIX durable delivery in one BOSH response"
                );
            }
        }
    }
    anyhow::ensure!(
        c2s.len().saturating_add(mix.len()) <= 512,
        "BOSH response fence limit exceeded"
    );

    let mut transaction = pool.begin().await?;
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT (
             SELECT COUNT(*) FROM bosh_delivery_fences
              WHERE session_id=$1
                AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'
         ) + (
             SELECT COUNT(*) FROM mix_bosh_delivery_fences
              WHERE session_id=$1
                AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'
         )",
    )
    .bind(session_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        existing_count.saturating_add(i64::try_from(c2s.len() + mix.len()).unwrap_or(i64::MAX))
            <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_rids = sqlx::query_scalar::<_, i64>(
        "SELECT response_rid FROM bosh_delivery_fences
          WHERE session_id=$1
         UNION
         SELECT response_rid FROM mix_bosh_delivery_fences
          WHERE session_id=$1 AND response_rid IS NOT NULL",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        response_rids.len() < 2 || response_rids.contains(&response_rid),
        "BOSH unacknowledged response limit exceeded"
    );

    for delivery in c2s.values() {
        let offline = sqlx::query(
            "SELECT delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(offline) = offline else {
            return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                message_id: delivery.message_id,
            }
            .into());
        };
        let sm_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
             )",
        )
        .bind(delivery.message_id)
        .fetch_one(&mut *transaction)
        .await?;
        if sm_owned {
            return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                message_id: delivery.message_id,
            }
            .into());
        }
        let existing = sqlx::query(
            "SELECT session_id,response_rid,expires_at>clock_timestamp() AS active
               FROM bosh_delivery_fences WHERE message_id=$1 FOR UPDATE",
        )
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let owner: Uuid = existing.try_get("session_id")?;
            let rid: i64 = existing.try_get("response_rid")?;
            if owner == session_id && rid == response_rid {
                if offline
                    .try_get::<Option<Uuid>, _>("delivery_claim_id")?
                    .is_some()
                {
                    return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                        message_id: delivery.message_id,
                    }
                    .into());
                }
                let renewed = sqlx::query(
                    "UPDATE bosh_delivery_fences
                        SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                             first_owned_at+INTERVAL '5 minutes')
                      WHERE message_id=$1
                        AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
                )
                .bind(delivery.message_id)
                .bind(ttl_seconds)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                anyhow::ensure!(
                    renewed == 1,
                    "BOSH response exceeded maximum acknowledgement age"
                );
                continue;
            }
            if existing.try_get::<bool, _>("active")? {
                return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                    message_id: delivery.message_id,
                }
                .into());
            }
            sqlx::query("DELETE FROM bosh_delivery_fences WHERE message_id=$1")
                .bind(delivery.message_id)
                .execute(&mut *transaction)
                .await?;
        }
        if offline.try_get::<Option<Uuid>, _>("delivery_claim_id")? != delivery.claim_id {
            return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                message_id: delivery.message_id,
            }
            .into());
        }
        sqlx::query(
            "UPDATE offline_messages
                SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
              WHERE recipient_id=$1 AND id=$2",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO bosh_delivery_fences(
                message_id,recipient_id,session_id,response_rid,expires_at,first_owned_at
             ) VALUES($1,$2,$3,$4,
                LEAST(clock_timestamp()+($5*INTERVAL '1 second'),clock_timestamp()+INTERVAL '5 minutes'),
                clock_timestamp())",
        )
        .bind(delivery.message_id)
        .bind(delivery.recipient_id)
        .bind(session_id)
        .bind(response_rid)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
    }

    for source in mix.values() {
        // The recipient row is the first lock in every MIX transfer path;
        // lock it before the BOSH fence to preserve that global order.
        let recipient = sqlx::query(
            "SELECT lease_token FROM mix_delivery_recipients
              WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(source.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(recipient) = recipient else {
            anyhow::bail!("MIX delivery disappeared before BOSH response binding");
        };
        anyhow::ensure!(
            recipient.try_get::<Option<Uuid>, _>("lease_token")? == Some(source.lease_token),
            "MIX delivery lease changed before BOSH response binding"
        );
        let fence = sqlx::query(
            "SELECT session_id,response_rid,lease_token,
                    expires_at>clock_timestamp() AS active
               FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(source.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(fence) = fence else {
            anyhow::bail!("MIX BOSH response has no pending ownership fence");
        };
        anyhow::ensure!(
            fence.try_get::<Uuid, _>("session_id")? == session_id
                && fence.try_get::<Uuid, _>("lease_token")? == source.lease_token,
            "MIX BOSH response fence is owned by another transport"
        );
        anyhow::ensure!(
            fence.try_get::<bool, _>("active")?,
            "MIX BOSH response fence expired before response binding"
        );
        let stored_rid: Option<i64> = fence.try_get("response_rid")?;
        anyhow::ensure!(
            stored_rid.is_none() || stored_rid == Some(response_rid),
            "MIX BOSH source was bound to a different response"
        );
        let bound = sqlx::query(
            "UPDATE mix_bosh_delivery_fences
                SET response_rid=$3,
                    bound_at=COALESCE(bound_at,clock_timestamp()),
                    expires_at=LEAST(clock_timestamp()+($4*INTERVAL '1 second'),
                                     first_owned_at+INTERVAL '5 minutes')
              WHERE delivery_id=$1 AND lease_token=$2",
        )
        .bind(source.delivery_id)
        .bind(source.lease_token)
        .bind(response_rid)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(bound == 1, "MIX BOSH response fence lost ownership");
    }
    let ownership = crate::xmpp::outbound::BoshResponseOwnership {
        c2s_message_ids: c2s.into_keys().collect(),
        mix_delivery_ids: mix.into_keys().collect(),
    };
    if let Some(request) = observation {
        // Both value copies are prepared before COMMIT. The callback stores
        // the transaction-derived receipt before returning this membership.
        let receipt = ownership.clone();
        northstar_delivery_core::bosh_ownership::response::bind_commit_observed(
            transaction.commit(),
            request,
            receipt,
        )
        .await?;
    } else {
        transaction.commit().await?;
    }
    Ok(ownership)
}

/// Renew both C2S and MIX BOSH ownership records as one coherent actor
/// snapshot. Cached-response replay passes its immutable source identities so
/// a mismatched or partially lost response fails closed before bytes repeat.
pub async fn renew_bosh_transport_fences(
    pool: &PgPool,
    request: &northstar_delivery_core::bosh_ownership::response::RenewRequest,
) -> Result<()> {
    request.validate_for_io()?;
    let session_id = request.session_id();
    let expected_response = request.expected();
    let ttl_seconds = request.ttl_seconds();
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, BOSH_FENCE_MAX_AGE_SECONDS as u64))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let c2s = sqlx::query(
        "SELECT message_id,response_rid,
                expires_at>clock_timestamp() AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes' AS active
           FROM bosh_delivery_fences
          WHERE session_id=$1 ORDER BY message_id FOR UPDATE",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    let mix = sqlx::query(
        "SELECT delivery_id,response_rid,
                expires_at>clock_timestamp() AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes' AS active
           FROM mix_bosh_delivery_fences
          WHERE session_id=$1 ORDER BY delivery_id FOR UPDATE",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in c2s.iter().chain(mix.iter()) {
        anyhow::ensure!(
            fence.try_get::<bool, _>("active")?,
            "BOSH durable transport lease expired before renewal"
        );
    }
    anyhow::ensure!(
        c2s.len().saturating_add(mix.len()) <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_count = c2s
        .iter()
        .filter_map(|fence| fence.try_get::<i64, _>("response_rid").ok())
        .chain(mix.iter().filter_map(|fence| {
            fence
                .try_get::<Option<i64>, _>("response_rid")
                .ok()
                .flatten()
        }))
        .collect::<BTreeSet<_>>()
        .len();
    anyhow::ensure!(
        response_count <= 2,
        "BOSH unacknowledged response limit exceeded"
    );
    if let Some((response_rid, expected)) = expected_response {
        let response_rid = i64::try_from(response_rid).context("BOSH RID exceeds bigint")?;
        let actual_c2s = c2s
            .iter()
            .filter_map(|fence| {
                (fence.try_get::<i64, _>("response_rid").ok() == Some(response_rid))
                    .then(|| fence.try_get::<Uuid, _>("message_id").ok())
                    .flatten()
            })
            .collect::<BTreeSet<_>>();
        let actual_mix = mix
            .iter()
            .filter_map(|fence| {
                (fence
                    .try_get::<Option<i64>, _>("response_rid")
                    .ok()
                    .flatten()
                    == Some(response_rid))
                .then(|| fence.try_get::<Uuid, _>("delivery_id").ok())
                .flatten()
            })
            .collect::<BTreeSet<_>>();
        let expected_c2s = expected
            .c2s_message_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected_mix = expected
            .mix_delivery_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            actual_c2s == expected_c2s && actual_mix == expected_mix,
            "cached BOSH response no longer owns its exact durable transport sources"
        );
    }
    let renewed_c2s = sqlx::query(
        "UPDATE bosh_delivery_fences
            SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                 first_owned_at+INTERVAL '5 minutes')
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    let renewed_mix = sqlx::query(
        "UPDATE mix_bosh_delivery_fences
            SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                 first_owned_at+INTERVAL '5 minutes')
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        renewed_c2s as usize == c2s.len() && renewed_mix as usize == mix.len(),
        "BOSH acknowledgement-age fence was lost during renewal"
    );
    northstar_delivery_core::bosh_ownership::response::renew_commit_observed(
        transaction.commit(),
        request,
    )
    .await?;
    Ok(())
}

/// Atomically consume all C2S and MIX sources covered by a valid BOSH client
/// acknowledgement. MIX deletion validates the rotated BOSH lease token, so
/// an acknowledgement can never remove a newly reclaimed recipient row.
pub async fn acknowledge_bosh_transport_responses(
    pool: &PgPool,
    request: &northstar_delivery_core::bosh_ownership::response::AckRequest,
) -> Result<usize> {
    request.validate_for_io()?;
    let session_id = request.session_id();
    let acknowledged_rid = request.rid();
    let acknowledged_rid =
        i64::try_from(acknowledged_rid).context("BOSH acknowledgement exceeds bigint")?;
    let mut transaction = pool.begin().await?;
    let mut deleted_sources = Vec::new();
    let c2s = sqlx::query(
        "SELECT recipient_id,message_id FROM bosh_delivery_fences
          WHERE session_id=$1 AND response_rid<=$2
          ORDER BY message_id",
    )
    .bind(session_id)
    .bind(acknowledged_rid)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in &c2s {
        let recipient_id: Uuid = fence.try_get("recipient_id")?;
        let message_id: Uuid = fence.try_get("message_id")?;
        let offline = sqlx::query_scalar::<_, bool>(
            "SELECT TRUE FROM offline_messages WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(recipient_id)
        .bind(message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(offline.is_some(), "BOSH-owned durable delivery disappeared");
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT expires_at>clock_timestamp()
               FROM bosh_delivery_fences
              WHERE message_id=$1 AND session_id=$2 AND response_rid<=$3 FOR UPDATE",
        )
        .bind(message_id)
        .bind(session_id)
        .bind(acknowledged_rid)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            active == Some(true),
            "BOSH durable delivery lease was lost before acknowledgement"
        );
        let deleted = sqlx::query("DELETE FROM offline_messages WHERE recipient_id=$1 AND id=$2")
            .bind(recipient_id)
            .bind(message_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        anyhow::ensure!(deleted == 1, "BOSH-owned durable delivery disappeared");
        deleted_sources.push(
            northstar_delivery_core::bosh_ownership::response::DeletedSource::C2s {
                recipient_id,
                message_id,
            },
        );
    }
    let mix = sqlx::query(
        "SELECT delivery_id,lease_token FROM mix_bosh_delivery_fences
          WHERE session_id=$1 AND response_rid<=$2
          ORDER BY delivery_id",
    )
    .bind(session_id)
    .bind(acknowledged_rid)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in &mix {
        let delivery_id: Uuid = fence.try_get("delivery_id")?;
        let lease_token: Uuid = fence.try_get("lease_token")?;
        let recipient = sqlx::query_scalar::<_, Uuid>(
            "SELECT lease_token FROM mix_delivery_recipients WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            recipient == Some(lease_token),
            "MIX BOSH-owned delivery lease changed before acknowledgement"
        );
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT expires_at>clock_timestamp()
               FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND lease_token=$2 AND session_id=$3
                AND response_rid<=$4 FOR UPDATE",
        )
        .bind(delivery_id)
        .bind(lease_token)
        .bind(session_id)
        .bind(acknowledged_rid)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            active == Some(true),
            "MIX BOSH delivery lease was lost before acknowledgement"
        );
        let deleted = sqlx::query(
            "DELETE FROM mix_delivery_recipients WHERE delivery_id=$1 AND lease_token=$2",
        )
        .bind(delivery_id)
        .bind(lease_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(deleted == 1, "MIX BOSH-owned delivery disappeared");
        deleted_sources.push(
            northstar_delivery_core::bosh_ownership::response::DeletedSource::Mix(
                crate::xmpp::outbound::MixDelivery {
                    delivery_id,
                    lease_token,
                },
            ),
        );
    }
    let acknowledged = deleted_sources.len();
    northstar_delivery_core::bosh_ownership::response::ack_commit_observed(
        transaction.commit(),
        request,
        deleted_sources,
    )
    .await?;
    Ok(acknowledged)
}

/// Release an actor's unacknowledged BOSH transport sources without consuming
/// them. C2S rows become eligible through their deleted fences; MIX rows keep
/// their event/sequence but lose only the exact rotated BOSH lease.
pub async fn release_bosh_transport_fences(pool: &PgPool, session_id: Uuid) -> Result<()> {
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM bosh_delivery_fences WHERE session_id=$1")
        .bind(session_id)
        .execute(&mut *transaction)
        .await?;
    let mix = sqlx::query(
        "SELECT delivery_id,lease_token FROM mix_bosh_delivery_fences
          WHERE session_id=$1 ORDER BY delivery_id",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    for fence in &mix {
        let delivery_id: Uuid = fence.try_get("delivery_id")?;
        let lease_token: Uuid = fence.try_get("lease_token")?;
        let recipient = sqlx::query_scalar::<_, Uuid>(
            "SELECT lease_token FROM mix_delivery_recipients WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let owned = sqlx::query_scalar::<_, Uuid>(
            "SELECT lease_token FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND session_id=$2 FOR UPDATE",
        )
        .bind(delivery_id)
        .bind(session_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if recipient == Some(lease_token) && owned == Some(lease_token) {
            let released = sqlx::query(
                "UPDATE mix_delivery_recipients
                    SET lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()
                  WHERE delivery_id=$1 AND lease_token=$2",
            )
            .bind(delivery_id)
            .bind(lease_token)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            anyhow::ensure!(
                released == 1,
                "MIX BOSH lease release lost its recipient row"
            );
        }
        sqlx::query(
            "DELETE FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND session_id=$2 AND lease_token=$3",
        )
        .bind(delivery_id)
        .bind(session_id)
        .bind(lease_token)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}
