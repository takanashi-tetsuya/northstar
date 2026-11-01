//! Personal history admission: archive writes, history identity fences and C2S/S2S delivery admission.

use anyhow::Result;
use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
use northstar_message_postgres::direct_cluster::DirectCommitCluster;
use northstar_message_postgres::direct_spool_wake::record_direct_spool_wake_in_transaction;
use northstar_message_postgres::personal_history::*;
use northstar_postgres::cluster_lock::lock_direct_spool_instance_claims_in_transaction;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

/// Atomically write every personal MAM projection of one message.  When a
/// trusted XEP-0359 identity is supplied, concurrent retries are admitted
/// exactly once. Raw identity/authority values are compared exactly and
/// content is verified through purpose-separated current/previous HMAC
/// commitments. Migration-only SHA-256 evidence is upgraded on exact replay;
/// the admission record never receives or persists an extra plaintext copy.
pub async fn admit_personal_history(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
) -> Result<PersonalHistoryAdmission> {
    admit_personal_history_inner(pool, identity, writes, None, None, None)
        .await
        .map(|result| result.0)
}

/// Atomically commit all enabled MAM projections and the transient C2S
/// delivery row. An authoritative origin/stanza ID therefore cannot become a
/// history-only tombstone after a crash, and an exact retry never fans out a
/// second live copy.
pub async fn admit_personal_history_and_c2s_delivery(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    delivery: &PersonalC2sDeliveryAdmission<'_>,
) -> Result<PersonalHistoryAdmission> {
    admit_personal_history_inner(pool, identity, writes, None, Some(delivery), None)
        .await
        .map(|result| result.0)
}

/// Atomically admit one federated personal message and its optional sender
/// MAM projection. The S2S outbox remains the recoverable projection when
/// archive policy suppresses plaintext MAM. An outbox quota/DB failure leaves
/// no identity/history ghost; an exact replay never enqueues a second stanza.
pub async fn admit_outbound_personal_history(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: &PersonalS2sOutboxAdmission<'_>,
) -> Result<PersonalHistoryAdmission> {
    admit_personal_history_inner(pool, identity, writes, Some(outbox), None, None)
        .await
        .map(|result| result.0)
}

pub async fn admit_personal_history_with_direct_fence(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: Option<&PersonalS2sOutboxAdmission<'_>>,
    delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
    cluster: &dyn DirectCommitCluster,
    eligibility: DirectSpoolEligibility,
) -> Result<(PersonalHistoryAdmission, DirectPostCommitMode, Option<Uuid>)> {
    admit_personal_history_inner(
        pool,
        identity,
        writes,
        outbox,
        delivery,
        Some(DirectCommitContext {
            cluster: Some((cluster, eligibility)),
            observer: None,
        }),
    )
    .await
}

pub struct DirectCommitContext<'a> {
    pub cluster: Option<(&'a dyn DirectCommitCluster, DirectSpoolEligibility)>,
    pub observer:
        Option<&'a dyn northstar_message_application::direct_commit::DirectCommitObserver>,
}

pub async fn admit_personal_history_observed_direct(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    delivery: &PersonalC2sDeliveryAdmission<'_>,
    cluster: Option<&dyn DirectCommitCluster>,
    eligibility: DirectSpoolEligibility,
    observer: &dyn northstar_message_application::direct_commit::DirectCommitObserver,
) -> Result<(PersonalHistoryAdmission, DirectPostCommitMode, Option<Uuid>)> {
    admit_personal_history_inner(
        pool,
        identity,
        writes,
        None,
        Some(delivery),
        Some(DirectCommitContext {
            cluster: cluster.map(|cluster| (cluster, eligibility)),
            observer: Some(observer),
        }),
    )
    .await
}

pub fn direct_transaction_outcome(
    outcome: &PersonalHistoryAdmission,
    delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
    live_claim_id: Option<Uuid>,
) -> Result<northstar_message_application::direct_commit::TransactionOutcome> {
    use northstar_message_application::direct_commit::TransactionOutcome;
    Ok(match outcome {
        PersonalHistoryAdmission::Stored(ids) => {
            let delivery = delivery
                .ok_or_else(|| anyhow::anyhow!("observed local transaction lacked delivery"))?;
            TransactionOutcome::Stored {
                recipient_id: delivery.recipient_id,
                delivery_id: delivery.id,
                archive_ids: ids.clone(),
                live_claim_id,
            }
        }
        PersonalHistoryAdmission::Replay(ids) => TransactionOutcome::Replay {
            archive_ids: ids.clone(),
        },
        PersonalHistoryAdmission::AccountUnavailable => TransactionOutcome::AccountUnavailable,
    })
}

pub async fn admit_personal_history_inner(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: Option<&PersonalS2sOutboxAdmission<'_>>,
    c2s_delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
    context: Option<DirectCommitContext<'_>>,
) -> Result<(PersonalHistoryAdmission, DirectPostCommitMode, Option<Uuid>)> {
    let (cluster, observer) =
        context.map_or((None, None), |context| (context.cluster, context.observer));
    let mut transaction = pool.begin().await?;
    if let Some((cluster, eligibility)) = cluster {
        lock_direct_spool_instance_claims_in_transaction(&mut transaction).await?;
        if let Some(authority) = cluster.check_direct_eligibility(eligibility)? {
            cluster.fence_authority(&mut transaction, authority).await?;
        }
    }
    let outcome = admit_personal_history_in_transaction(
        &mut transaction,
        identity,
        writes,
        outbox,
        c2s_delivery,
    )
    .await?;
    // The short health gate admits this final turn before the exact PostgreSQL
    // authority recheck, and holds a counted permit through acknowledged
    // COMMIT. A concurrent health transition freezes new work immediately,
    // then publishes its state after this turn finishes. Routing is outside
    // the permit.
    let mut live_claim_id = None;
    let mode = if let Some((cluster, eligibility)) = cluster {
        let (turn, authority) = cluster.begin_direct_commit_turn(eligibility)?;
        if let Some(authority) = authority {
            cluster.fence_authority(&mut transaction, authority).await?;
            if let (PersonalHistoryAdmission::Stored(_), Some(delivery)) = (&outcome, c2s_delivery)
            {
                // A committed wake can start replay before the postcommit
                // primary route reaches its socket. Reserve this exact row in
                // the same transaction as its wake when this turn can still
                // return Live. The message UUID is the initial claim token;
                // the socket fence rotates it before bytes are exposed.
                if turn.admitted_mode() == DirectPostCommitMode::Live {
                    reserve_cluster_live_delivery_in_transaction(
                        &mut transaction,
                        delivery.recipient_id,
                        delivery.id,
                    )
                    .await?;
                    live_claim_id = Some(delivery.id);
                }
                record_direct_spool_wake_in_transaction(
                    &mut transaction,
                    &authority.key_identity.xmpp_domain,
                    delivery.recipient_id,
                )
                .await?;
            }
        }
        if let Some(observer) = observer {
            let fact = direct_transaction_outcome(&outcome, c2s_delivery, live_claim_id)?;
            northstar_message_application::messaging::direct_workflow::commit_observed(
                transaction.commit(),
                observer,
                fact,
                turn.admitted_mode(),
            )
            .await?;
        } else {
            transaction.commit().await?;
        }
        let admitted_mode = turn.finish();
        if admitted_mode == DirectPostCommitMode::Live
            && cluster.direct_mode() != DirectPostCommitMode::Live
        {
            DirectPostCommitMode::SpoolOnly
        } else {
            admitted_mode
        }
    } else {
        if let Some(observer) = observer {
            let fact = direct_transaction_outcome(&outcome, c2s_delivery, None)?;
            northstar_message_application::messaging::direct_workflow::commit_observed(
                transaction.commit(),
                observer,
                fact,
                DirectPostCommitMode::Live,
            )
            .await?;
        } else {
            transaction.commit().await?;
        }
        DirectPostCommitMode::Live
    };
    Ok((outcome, mode, live_claim_id))
}

/// Repository half of a larger application-owned admission transaction.
///
/// The caller owns commit/rollback. In particular, a replay does not commit
/// the transaction here: a service may still need to roll back projections
/// made by another repository before returning its typed replay result.
pub async fn admit_personal_history_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: Option<&PersonalS2sOutboxAdmission<'_>>,
    c2s_delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
) -> Result<PersonalHistoryAdmission> {
    anyhow::ensure!(
        (!writes.is_empty() || outbox.is_some() || c2s_delivery.is_some()) && writes.len() <= 2,
        "personal history admission must contain an owner projection or durable delivery"
    );
    let mut required_accounts = writes
        .iter()
        .map(|write| write.owner_id)
        .collect::<Vec<_>>();
    if let Some(outbox) = outbox {
        required_accounts.push(outbox.local_actor_id);
    }
    if let Some(delivery) = c2s_delivery {
        required_accounts.push(delivery.recipient_id);
        required_accounts.extend(delivery.local_actor_id);
    }
    if !northstar_auth_postgres::users::lock_enabled_users_in_transaction(
        transaction,
        &required_accounts,
    )
    .await?
    {
        return Ok(PersonalHistoryAdmission::AccountUnavailable);
    }
    anyhow::ensure!(
        identity.is_none() || !writes.is_empty() || outbox.is_some() || c2s_delivery.is_some(),
        "personal history identity requires a recoverable archive, S2S, or C2S projection"
    );
    let mut normalized = Vec::with_capacity(writes.len());
    let mut owner_ids = HashSet::new();
    let mut archive_ids = HashSet::new();
    for write in writes {
        anyhow::ensure!(
            owner_ids.insert(write.owner_id),
            "personal history admission contains duplicate owners"
        );
        anyhow::ensure!(
            archive_ids.insert(write.id),
            "personal history admission contains duplicate archive ids"
        );
        anyhow::ensure!(
            !write.stanza.is_empty() && write.stanza.len() <= 1_048_576,
            "personal archive stanza must contain 1 byte to 1 MiB"
        );
        if let Some(stanza_id) = write.stanza_id {
            anyhow::ensure!(
                !stanza_id.is_empty()
                    && stanza_id.len() <= 128
                    && !stanza_id.chars().any(char::is_control),
                "client stanza id must contain 1 to 128 non-control bytes"
            );
        }
        let peer_full_jid = northstar_xmpp_types::jid::canonicalize(write.peer_jid)?;
        let peer_bare_jid = northstar_xmpp_types::jid::canonical_bare_key(&peer_full_jid)?;
        normalized.push((write, peer_bare_jid, peer_full_jid));
    }

    let identity_values = if let Some(identity) = identity {
        anyhow::ensure!(
            matches!(identity.kind, "local-origin" | "remote-stanza"),
            "unsupported personal history identity kind"
        );
        anyhow::ensure!(
            !identity.actor_scope_raw.is_empty() && identity.actor_scope_raw.len() <= 3071,
            "raw actor scope must contain 1 to 3071 bytes"
        );
        let actor_scope = northstar_xmpp_types::jid::canonicalize(identity.actor_scope)?;
        anyhow::ensure!(
            actor_scope == identity.actor_scope,
            "personal history actor scope must already be canonical"
        );
        let target_scope = northstar_xmpp_types::jid::canonicalize(identity.target_scope)?;
        anyhow::ensure!(
            target_scope == identity.target_scope,
            "personal history target scope must already be canonical"
        );
        anyhow::ensure!(
            !identity.identity_value.is_empty()
                && identity.identity_value.len() <= 1024
                && !identity.identity_value.chars().any(char::is_control),
            "personal history identity must contain 1 to 1024 non-control bytes"
        );
        let mut identity_hasher = Sha256::new();
        identity_hasher.update(b"northstar:personal-history-identity:v1\0");
        identity_hasher.update(identity.identity_value.as_bytes());
        let identity_digest = identity_hasher.finalize().to_vec();
        Some((actor_scope, target_scope, identity_digest))
    } else {
        None
    };

    let normalized_delivery = if let Some(delivery) = c2s_delivery {
        anyhow::ensure!(
            !delivery.stanza.is_empty() && delivery.stanza.len() <= 1_048_576,
            "C2S delivery stanza must contain 1 byte to 1 MiB"
        );
        let sender_jid = northstar_xmpp_types::jid::canonicalize(delivery.sender_jid)?;
        anyhow::ensure!(
            delivery.policy.max_messages > 0
                && delivery.policy.max_bytes > 0
                && delivery.policy.ttl_days >= 0,
            "C2S delivery policy is invalid"
        );
        Some((delivery, sender_jid))
    } else {
        None
    };

    // Allocate the S2S projection identity before inserting the admission.
    // Its foreign key is deferred because the outbox row is inserted later in
    // this same transaction, after replay admission has succeeded.
    let s2s_outbox_id = outbox.map(|_| Uuid::new_v4());
    if let (Some(identity), Some((actor_scope, target_scope, identity_digest))) =
        (identity, identity_values.as_ref())
    {
        let replayed = claim_personal_admission_in_transaction(
            transaction,
            identity,
            actor_scope,
            target_scope,
            identity_digest,
            PersonalAdmissionProjections {
                sender_archive_id: writes.first().map(|write| write.id),
                recipient_archive_id: writes.get(1).map(|write| write.id),
                offline_message_id: c2s_delivery.map(|delivery| delivery.id),
                s2s_outbox_id,
            },
        )
        .await?;
        if let Some(existing) = replayed {
            return Ok(PersonalHistoryAdmission::Replay(existing));
        }
    }

    for (write, peer_bare_jid, peer_full_jid) in normalized {
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(write.id)
        .bind(write.owner_id)
        .bind(peer_bare_jid)
        .bind(peer_full_jid)
        .bind(write.stanza)
        .bind(write.encrypted)
        .bind(write.stanza_id)
        .execute(&mut **transaction)
        .await?;
    }
    if let Some(outbox) = outbox {
        northstar_federation_postgres::enqueue_s2s_outbox_with_id_in_transaction(
            transaction,
            s2s_outbox_id.expect("an outbound admission always allocates an outbox id"),
            outbox.target_domain,
            outbox.stanza,
            outbox.bounce_to,
            outbox.policy,
        )
        .await?;
    }
    if let Some((delivery, sender_jid)) = normalized_delivery {
        insert_c2s_delivery_in_transaction(transaction, delivery, &sender_jid).await?;
    }
    Ok(PersonalHistoryAdmission::Stored(
        writes.iter().map(|write| write.id).collect(),
    ))
}
