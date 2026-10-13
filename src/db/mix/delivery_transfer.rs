//! MIX delivery ownership transfer to the cluster, socket writes and BOSH.

use super::*;

/// Consume an optional remote-node fence while holding the recipient row.
///
/// A direct socket, XEP-0198 or BOSH transfer receives the rotated fence
/// token through a signed cluster command. The token is sufficient proof of
/// that exact hand-off, but the fence must be removed before the next local
/// transport owner is recorded. Calling this for a normal local source is a
/// no-op; a different active token is always an ownership violation.
pub(crate) async fn consume_mix_cluster_delivery_fence_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    source: crate::xmpp::outbound::MixDelivery,
) -> Result<()> {
    let fence = sqlx::query(
        "SELECT lease_token,expires_at>clock_timestamp() AS active
           FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(fence) = fence else {
        return Ok(());
    };
    let fence_token: Uuid = fence.try_get("lease_token")?;
    anyhow::ensure!(
        fence_token == source.lease_token,
        "MIX cluster hand-off fence is owned by a different source lease"
    );
    let removed = sqlx::query(
        "DELETE FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        removed == 1,
        "MIX cluster hand-off fence changed during local transport transfer"
    );
    Ok(())
}

/// Move an exact claimed source to one authenticated remote node before that
/// node is allowed to enqueue it locally. The source worker's original token
/// becomes invalid in the same transaction, so a lost Redis acknowledgement
/// can only leave a recoverable remote fence rather than two active writers.
pub async fn transfer_mix_delivery_to_cluster(
    pool: &PgPool,
    source: crate::xmpp::outbound::MixDelivery,
    node_id: &str,
    request_id: Uuid,
    ttl_seconds: u64,
) -> Result<crate::xmpp::outbound::MixDelivery> {
    anyhow::ensure!(
        !node_id.is_empty() && node_id.len() <= 128 && !node_id.chars().any(char::is_control),
        "MIX cluster hand-off node identifier is invalid"
    );
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, 300))
        .context("MIX cluster hand-off TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_until>clock_timestamp() AS active
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        anyhow::bail!("MIX lease changed before cluster hand-off");
    };
    anyhow::ensure!(
        recipient.try_get::<bool, _>("active")?,
        "MIX lease expired before cluster hand-off"
    );
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM sm_resume_stanzas stanza
               JOIN sm_resume_sessions session ON session.id=stanza.session_id
              WHERE stanza.mix_delivery_id=$1
                AND session.expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "MIX delivery is already owned by an active XEP-0198 sequence"
    );
    let bosh_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !bosh_owned,
        "MIX delivery is already owned by an active BOSH response"
    );
    let existing = sqlx::query(
        "SELECT expires_at>clock_timestamp() AS active
           FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(existing) = existing {
        anyhow::ensure!(
            !existing.try_get::<bool, _>("active")?,
            "MIX delivery is already owned by an active remote node"
        );
        sqlx::query("DELETE FROM mix_cluster_delivery_fences WHERE delivery_id=$1")
            .bind(source.delivery_id)
            .execute(&mut *transaction)
            .await?;
    }
    let transferred = crate::xmpp::outbound::MixDelivery {
        delivery_id: source.delivery_id,
        lease_token: Uuid::new_v4(),
    };
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=$3,
                lease_until=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(transferred.lease_token)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(updated == 1, "MIX lease changed during cluster hand-off");
    let inserted = sqlx::query(
        "INSERT INTO mix_cluster_delivery_fences(
            delivery_id,lease_token,node_id,request_id,expires_at
         ) VALUES($1,$2,$3,$4,clock_timestamp()+make_interval(secs=>$5))",
    )
    .bind(transferred.delivery_id)
    .bind(transferred.lease_token)
    .bind(node_id)
    .bind(request_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        inserted == 1,
        "MIX cluster hand-off did not create its fence"
    );
    transaction.commit().await?;
    Ok(transferred)
}

/// Release an exact remote-node hand-off which failed before it became a
/// socket, SM, or BOSH owner. A mismatched token is intentionally harmless:
/// it proves that a later local transport already took responsibility.
pub async fn release_mix_cluster_delivery(
    pool: &PgPool,
    source: crate::xmpp::outbound::MixDelivery,
    node_id: &str,
    request_id: Uuid,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_token FROM mix_delivery_recipients
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        transaction.commit().await?;
        return Ok(false);
    };
    if recipient.try_get::<Option<Uuid>, _>("lease_token")? != Some(source.lease_token) {
        transaction.commit().await?;
        return Ok(false);
    }
    let fence = sqlx::query(
        "SELECT lease_token FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 AND node_id=$2 AND request_id=$3 FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(node_id)
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(fence) = fence else {
        transaction.commit().await?;
        return Ok(false);
    };
    if fence.try_get::<Uuid, _>("lease_token")? != source.lease_token {
        transaction.commit().await?;
        return Ok(false);
    }
    let released = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp(),
                last_error='remote cluster transport did not establish ownership'
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(released == 1, "MIX cluster hand-off lost its recipient row");
    let deleted = sqlx::query(
        "DELETE FROM mix_cluster_delivery_fences
          WHERE delivery_id=$1 AND lease_token=$2 AND node_id=$3 AND request_id=$4",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(node_id)
    .bind(request_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        deleted == 1,
        "MIX cluster hand-off fence changed during release"
    );
    transaction.commit().await?;
    Ok(true)
}

/// Transfer a claimed MIX recipient source to one direct TCP/WebSocket writer
/// before it receives the stanza bytes. The returned rotated token belongs
/// only to that writer. A claiming worker which still holds `source` can no
/// longer retry or acknowledge it, so a queued stale item cannot overtake the
/// recovery path after its caller is cancelled.
pub async fn fence_mix_socket_write(
    pool: &PgPool,
    source: crate::xmpp::outbound::MixDelivery,
) -> Result<crate::xmpp::outbound::MixDelivery> {
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_until>clock_timestamp() AS active
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        anyhow::bail!("MIX lease changed before direct socket fencing");
    };
    anyhow::ensure!(
        recipient.try_get::<bool, _>("active")?,
        "MIX lease expired before direct socket fencing"
    );
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM sm_resume_stanzas stanza
               JOIN sm_resume_sessions session ON session.id=stanza.session_id
              WHERE stanza.mix_delivery_id=$1
                AND session.expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "MIX delivery is already owned by an active XEP-0198 sequence"
    );
    let bosh_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM mix_bosh_delivery_fences
              WHERE delivery_id=$1 AND expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !bosh_owned,
        "MIX delivery is already owned by an active BOSH response"
    );
    consume_mix_cluster_delivery_fence_tx(&mut transaction, source).await?;
    let fenced = crate::xmpp::outbound::MixDelivery {
        delivery_id: source.delivery_id,
        lease_token: Uuid::new_v4(),
    };
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=$3,
                lease_until=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(fenced.lease_token)
    .bind(MIX_SOCKET_WRITE_FENCE_SECONDS)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "MIX lease changed while direct socket fencing was committed"
    );
    transaction.commit().await?;
    Ok(fenced)
}

/// Transfer one exact claimed MIX recipient lease to a BOSH actor before the
/// actor is allowed to retain the stanza in its response FIFO. The original
/// worker token is rotated in the same transaction so a delayed worker cannot
/// retry, dead-letter, or acknowledge a source already owned by BOSH.
pub async fn transfer_mix_delivery_to_bosh(
    pool: &PgPool,
    request: &northstar_delivery_core::bosh_ownership::TransferRequest,
) -> Result<crate::xmpp::outbound::MixDelivery> {
    request.validate_for_io()?;
    let source = request.source();
    let session_id = request.session_id();
    let ttl_seconds = request.ttl_seconds();
    let ttl_seconds =
        i64::try_from(ttl_seconds.clamp(1, 300)).context("MIX BOSH hand-off TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let recipient = sqlx::query(
        "SELECT lease_until>clock_timestamp() AS active
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(recipient) = recipient else {
        anyhow::bail!("MIX lease changed before BOSH ownership transfer");
    };
    anyhow::ensure!(
        recipient.try_get::<bool, _>("active")?,
        "MIX lease expired before BOSH ownership transfer"
    );
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM sm_resume_stanzas stanza
               JOIN sm_resume_sessions session ON session.id=stanza.session_id
              WHERE stanza.mix_delivery_id=$1
                AND session.expires_at>clock_timestamp()
         )",
    )
    .bind(source.delivery_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "MIX delivery is already owned by an active XEP-0198 sequence"
    );
    consume_mix_cluster_delivery_fence_tx(&mut transaction, source).await?;
    let existing = sqlx::query(
        "SELECT session_id,expires_at>clock_timestamp() AS active
           FROM mix_bosh_delivery_fences
          WHERE delivery_id=$1
          FOR UPDATE",
    )
    .bind(source.delivery_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(existing) = existing {
        anyhow::ensure!(
            !existing.try_get::<bool, _>("active")?,
            "MIX delivery is already owned by an active BOSH response"
        );
        sqlx::query("DELETE FROM mix_bosh_delivery_fences WHERE delivery_id=$1")
            .bind(source.delivery_id)
            .execute(&mut *transaction)
            .await?;
    }
    let transferred = crate::xmpp::outbound::MixDelivery {
        delivery_id: source.delivery_id,
        lease_token: Uuid::new_v4(),
    };
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=$3,
                lease_until=clock_timestamp()+make_interval(secs=>$4)
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(transferred.lease_token)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "MIX lease changed while BOSH ownership was being transferred"
    );
    let inserted = sqlx::query(
        "INSERT INTO mix_bosh_delivery_fences(
            delivery_id,lease_token,session_id,expires_at
         ) VALUES(
            $1,$2,$3,
            clock_timestamp()+make_interval(secs=>$4)
         )",
    )
    .bind(transferred.delivery_id)
    .bind(transferred.lease_token)
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        inserted == 1,
        "MIX BOSH ownership transfer did not create its fence"
    );
    // A lost response after entering COMMIT leaves the whole transfer
    // unresolved. The exact positive receipt precedes this returned source.
    northstar_delivery_core::bosh_ownership::transfer_commit_observed(
        transaction.commit(),
        request,
        transferred,
    )
    .await?;
    Ok(transferred)
}
