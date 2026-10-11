//! Personal history admission: archive writes, history identity fences and C2S/S2S delivery admission.

use super::*;

#[derive(Clone, Debug)]
pub struct PersonalArchiveWrite<'a> {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub peer_jid: &'a str,
    pub stanza: &'a str,
    pub encrypted: bool,
    pub stanza_id: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct PersonalHistoryIdentity<'a> {
    pub kind: &'a str,
    /// Exact authority spelling observed at the protocol boundary.  The
    /// canonical companion below is used for uniqueness; retaining both lets
    /// a digest collision or non-canonical replay fail closed.
    pub actor_scope_raw: &'a str,
    pub actor_scope: &'a str,
    pub target_scope: &'a str,
    pub identity_value: &'a str,
    /// Purpose-separated current/previous HMAC commitments computed by the
    /// application service. The identity record never receives an additional
    /// copy of the stanza bytes carried by its authorized projections.
    pub payload_authenticators: ContentIdentityAuthenticators,
    /// Compatibility-only SHA-256 used to verify and upgrade rows written
    /// before migration 0104. New rows never persist this value.
    pub legacy_payload_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersonalHistoryAdmission {
    Stored(Vec<Uuid>),
    Replay(Vec<Uuid>),
    AccountUnavailable,
}

pub struct PersonalS2sOutboxAdmission<'a> {
    /// Local account whose authority causes this durable federation write.
    pub local_actor_id: Uuid,
    pub target_domain: &'a str,
    pub stanza: &'a str,
    pub bounce_to: Option<&'a str>,
    pub policy: super::super::S2sOutboxPolicy,
}

/// One transient, database-backed C2S copy. It is intentionally separate
/// from MAM: the row exists only until a transport confirms the stanza, but
/// it closes the process-crash window before an online socket write.
pub struct PersonalC2sDeliveryAdmission<'a> {
    pub id: Uuid,
    pub recipient_id: Uuid,
    /// Canonical bare JID owned by `recipient_id` at the application boundary.
    pub recipient_bare_jid: &'a str,
    /// Present for local C2S senders; absent for authenticated remote domains.
    pub local_actor_id: Option<Uuid>,
    pub sender_jid: &'a str,
    pub stanza: &'a str,
    /// Canonical resource affinity derived from an explicit full-JID `to`
    /// only for a `normal` message. Account-scoped/bare/chat delivery is NULL.
    pub target_full_jid: Option<&'a str>,
    pub encrypted: bool,
    pub policy: OfflineStorePolicy,
}

#[derive(Debug, thiserror::Error)]
#[error("durable C2S delivery reached the recipient queue capacity")]
pub(crate) struct C2sDeliveryCapacityExceeded;

#[derive(Debug, thiserror::Error)]
#[error("conflicting personal history identity")]
pub(crate) struct PersonalHistoryIdentityConflict;

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

pub(crate) async fn admit_personal_history_with_direct_fence(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: Option<&PersonalS2sOutboxAdmission<'_>>,
    delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
    cluster: &crate::cluster::ClusterAdmission,
    eligibility: crate::cluster::DirectSpoolEligibility,
) -> Result<(
    PersonalHistoryAdmission,
    crate::cluster::DirectPostCommitMode,
    Option<Uuid>,
)> {
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

pub(super) struct DirectCommitContext<'a> {
    pub(super) cluster: Option<(
        &'a crate::cluster::ClusterAdmission,
        crate::cluster::DirectSpoolEligibility,
    )>,
    pub(super) observer:
        Option<&'a dyn northstar_message_application::direct_commit::DirectCommitObserver>,
}

pub(crate) async fn admit_personal_history_observed_direct(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    delivery: &PersonalC2sDeliveryAdmission<'_>,
    cluster: Option<&crate::cluster::ClusterAdmission>,
    eligibility: crate::cluster::DirectSpoolEligibility,
    observer: &dyn northstar_message_application::direct_commit::DirectCommitObserver,
) -> Result<(
    PersonalHistoryAdmission,
    crate::cluster::DirectPostCommitMode,
    Option<Uuid>,
)> {
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

pub(super) fn direct_transaction_outcome(
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

pub(super) async fn admit_personal_history_inner(
    pool: &PgPool,
    identity: Option<&PersonalHistoryIdentity<'_>>,
    writes: &[PersonalArchiveWrite<'_>],
    outbox: Option<&PersonalS2sOutboxAdmission<'_>>,
    c2s_delivery: Option<&PersonalC2sDeliveryAdmission<'_>>,
    context: Option<DirectCommitContext<'_>>,
) -> Result<(
    PersonalHistoryAdmission,
    crate::cluster::DirectPostCommitMode,
    Option<Uuid>,
)> {
    let (cluster, observer) =
        context.map_or((None, None), |context| (context.cluster, context.observer));
    let mut transaction = pool.begin().await?;
    if let Some((cluster, eligibility)) = cluster {
        super::super::cluster_keys::lock_direct_spool_instance_claims_in_transaction(
            &mut transaction,
        )
        .await?;
        if let Some(authority) = cluster.check_direct_eligibility(eligibility)? {
            super::super::fence_direct_message_authority_in_transaction(
                &mut transaction,
                authority,
            )
            .await?;
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
            super::super::fence_direct_message_authority_in_transaction(
                &mut transaction,
                authority,
            )
            .await?;
            if let (PersonalHistoryAdmission::Stored(_), Some(delivery)) = (&outcome, c2s_delivery)
            {
                // A committed wake can start replay before the postcommit
                // primary route reaches its socket. Reserve this exact row in
                // the same transaction as its wake when this turn can still
                // return Live. The message UUID is the initial claim token;
                // the socket fence rotates it before bytes are exposed.
                if turn.admitted_mode() == crate::cluster::DirectPostCommitMode::Live {
                    reserve_cluster_live_delivery_in_transaction(
                        &mut transaction,
                        delivery.recipient_id,
                        delivery.id,
                    )
                    .await?;
                    live_claim_id = Some(delivery.id);
                }
                super::super::direct_spool_wake_repository::record_direct_spool_wake_in_transaction(
                    &mut transaction,
                    &authority.key_identity.xmpp_domain,
                    delivery.recipient_id,
                )
                .await?;
            }
        }
        if let Some(observer) = observer {
            let fact = direct_transaction_outcome(&outcome, c2s_delivery, live_claim_id)?;
            crate::services::messaging::direct_workflow::commit_observed(
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
        if admitted_mode == crate::cluster::DirectPostCommitMode::Live
            && cluster.direct_mode() != crate::cluster::DirectPostCommitMode::Live
        {
            crate::cluster::DirectPostCommitMode::SpoolOnly
        } else {
            admitted_mode
        }
    } else {
        if let Some(observer) = observer {
            let fact = direct_transaction_outcome(&outcome, c2s_delivery, None)?;
            crate::services::messaging::direct_workflow::commit_observed(
                transaction.commit(),
                observer,
                fact,
                crate::cluster::DirectPostCommitMode::Live,
            )
            .await?;
        } else {
            transaction.commit().await?;
        }
        crate::cluster::DirectPostCommitMode::Live
    };
    Ok((outcome, mode, live_claim_id))
}

/// Reserve the newly inserted durable row for its postcommit primary route.
/// The initial token is deliberately the row UUID, allowing every transport
/// to receive the same exact claim without a second result-shape projection.
pub(crate) async fn reserve_cluster_live_delivery_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    recipient_id: Uuid,
    message_id: Uuid,
) -> Result<()> {
    let updated = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=$2,
                delivery_claim_expires_at=clock_timestamp()+INTERVAL '60 seconds'
          WHERE recipient_id=$1 AND id=$2 AND delivery_claim_id IS NULL",
    )
    .bind(recipient_id)
    .bind(message_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "new direct delivery lost its live reservation before commit"
    );
    Ok(())
}

/// Release only the initial claim if no transport has taken it, and refresh
/// the persistent wake in the same transaction. A socket fence rotates the
/// token; SM and BOSH transfers clear it while creating their own owner.
pub(crate) async fn release_cluster_live_delivery_reservation_and_rearm(
    pool: &PgPool,
    domain: &str,
    recipient_id: Uuid,
    message_id: Uuid,
    claim_id: Uuid,
) -> Result<bool> {
    anyhow::ensure!(
        claim_id == message_id,
        "direct live reservation token is not the durable message ID"
    );
    let mut transaction = pool.begin().await?;
    super::super::cluster_keys::lock_direct_spool_instance_claims_in_transaction(&mut transaction)
        .await?;
    let released = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
          WHERE recipient_id=$1 AND id=$2 AND delivery_claim_id=$3",
    )
    .bind(recipient_id)
    .bind(message_id)
    .bind(claim_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if released == 1 {
        super::super::direct_spool_wake_repository::record_direct_spool_wake_in_transaction(
            &mut transaction,
            domain,
            recipient_id,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(released == 1)
}

/// Repository half of a larger application-owned admission transaction.
///
/// The caller owns commit/rollback. In particular, a replay does not commit
/// the transaction here: a service may still need to roll back projections
/// made by another repository before returning its typed replay result.
pub(crate) async fn admit_personal_history_in_transaction(
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
    if !super::super::lock_enabled_users_in_transaction(transaction, &required_accounts).await? {
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
        let peer_full_jid = crate::jid::canonicalize(write.peer_jid)?;
        let peer_bare_jid = crate::jid::canonical_bare_key(&peer_full_jid)?;
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
        let actor_scope = crate::jid::canonicalize(identity.actor_scope)?;
        anyhow::ensure!(
            actor_scope == identity.actor_scope,
            "personal history actor scope must already be canonical"
        );
        let target_scope = crate::jid::canonicalize(identity.target_scope)?;
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
        let sender_jid = crate::jid::canonicalize(delivery.sender_jid)?;
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
        let admission_id = Uuid::new_v4();
        let sender_archive_id = writes.first().map(|write| write.id);
        let recipient_archive_id = writes.get(1).map(|write| write.id);
        let offline_message_id = c2s_delivery.map(|delivery| delivery.id);
        let primary_authenticator = identity.payload_authenticators.primary();
        let inserted = sqlx::query(
            "INSERT INTO personal_message_admissions
             (id,identity_kind,actor_scope_raw,actor_scope,target_scope,
              identity_value,identity_digest,payload_key_id,payload_mac,
              sender_archive_id,recipient_archive_id,offline_message_id,s2s_outbox_id)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (
                identity_kind,
                (pg_catalog.md5(
                    'northstar:personal-admission-actor-scope:v1:'::pg_catalog.text
                    || actor_scope::pg_catalog.text
                )),
                (pg_catalog.md5(
                    'northstar:personal-admission-target-scope:v1:'::pg_catalog.text
                    || target_scope::pg_catalog.text
                )),
                identity_digest
             )
             DO NOTHING",
        )
        .bind(admission_id)
        .bind(identity.kind)
        .bind(identity.actor_scope_raw)
        .bind(actor_scope)
        .bind(target_scope)
        .bind(identity.identity_value)
        .bind(identity_digest)
        .bind(primary_authenticator.key_id())
        .bind(primary_authenticator.mac().as_slice())
        .bind(sender_archive_id)
        .bind(recipient_archive_id)
        .bind(offline_message_id)
        .bind(s2s_outbox_id)
        .execute(&mut **transaction)
        .await?
        .rows_affected()
            == 1;
        if !inserted {
            let row = sqlx::query(
                "SELECT id,actor_scope_raw,actor_scope,target_scope,identity_value,
                        payload_key_id,payload_mac,payload_digest,
                        sender_archive_id,recipient_archive_id
                   FROM personal_message_admissions
                  WHERE identity_kind=$1
                    AND pg_catalog.md5(
                          'northstar:personal-admission-actor-scope:v1:'::pg_catalog.text
                          || actor_scope::pg_catalog.text
                        ) = pg_catalog.md5(
                          'northstar:personal-admission-actor-scope:v1:'::pg_catalog.text
                          || $2::pg_catalog.text
                        )
                    AND pg_catalog.md5(
                          'northstar:personal-admission-target-scope:v1:'::pg_catalog.text
                          || target_scope::pg_catalog.text
                        ) = pg_catalog.md5(
                          'northstar:personal-admission-target-scope:v1:'::pg_catalog.text
                          || $3::pg_catalog.text
                        )
                    AND identity_digest=$4
                  FOR UPDATE",
            )
            .bind(identity.kind)
            .bind(actor_scope)
            .bind(target_scope)
            .bind(identity_digest)
            .fetch_optional(&mut **transaction)
            .await?;
            let Some(row) = row else {
                anyhow::bail!(
                    "personal history identity conflict row disappeared during admission"
                );
            };
            let stored_key_id = row.get::<Option<String>, _>("payload_key_id");
            let stored_mac = row.get::<Option<Vec<u8>>, _>("payload_mac");
            let legacy_digest = row.get::<Option<Vec<u8>>, _>("payload_digest");
            let keyed_exact = match (stored_key_id.as_deref(), stored_mac.as_deref()) {
                (Some(key_id), Some(mac)) if legacy_digest.is_none() => {
                    identity.payload_authenticators.verifies(key_id, mac)
                }
                _ => false,
            };
            let legacy_exact = match (
                stored_key_id.as_deref(),
                stored_mac.as_deref(),
                legacy_digest.as_deref(),
            ) {
                (None, None, Some(digest)) if digest.len() == 32 => {
                    bool::from(digest.ct_eq(identity.legacy_payload_digest.as_slice()))
                }
                _ => false,
            };
            // The unique B-tree uses bounded scope fingerprints so a valid
            // maximum-size JID cannot exceed PostgreSQL's index tuple limit.
            // Fingerprints only locate a conflict candidate: all identity
            // scopes and the originally observed authority spelling remain
            // exact comparisons. A hash collision is therefore a typed
            // conflict, never a cross-principal replay.
            let exact_replay = row.get::<String, _>("actor_scope").as_str() == actor_scope.as_str()
                && row.get::<String, _>("target_scope").as_str() == target_scope.as_str()
                && row.get::<String, _>("actor_scope_raw") == identity.actor_scope_raw
                && row.get::<String, _>("identity_value") == identity.identity_value
                && (keyed_exact || legacy_exact);
            if !exact_replay {
                return Err(PersonalHistoryIdentityConflict.into());
            }
            if legacy_exact {
                let upgraded = sqlx::query(
                    "UPDATE personal_message_admissions
                        SET payload_key_id=$2,payload_mac=$3,payload_digest=NULL
                      WHERE id=$1 AND payload_key_id IS NULL AND payload_mac IS NULL
                        AND payload_digest IS NOT NULL",
                )
                .bind(row.get::<Uuid, _>("id"))
                .bind(primary_authenticator.key_id())
                .bind(primary_authenticator.mac().as_slice())
                .execute(&mut **transaction)
                .await?;
                anyhow::ensure!(
                    upgraded.rows_affected() == 1,
                    "legacy personal history evidence changed while locked"
                );
            }
            let existing = [
                row.get::<Option<Uuid>, _>("sender_archive_id"),
                row.get::<Option<Uuid>, _>("recipient_archive_id"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
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
        super::super::enqueue_s2s_outbox_with_id_in_transaction(
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

pub(crate) async fn insert_c2s_delivery_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    delivery: &PersonalC2sDeliveryAdmission<'_>,
    sender_jid: &str,
) -> Result<()> {
    let (target_resource, stanza_target_bare_jid) = normalized_c2s_target_resource(delivery)?;
    let recipient_bare_jid = crate::jid::canonicalize_bare(delivery.recipient_bare_jid)?;
    anyhow::ensure!(
        recipient_bare_jid == delivery.recipient_bare_jid,
        "C2S delivery recipient bare JID must already be canonical"
    );
    if let Some(stanza_target_bare_jid) = stanza_target_bare_jid.as_deref() {
        anyhow::ensure!(
            stanza_target_bare_jid == recipient_bare_jid.as_str(),
            "C2S delivery target domain does not match recipient authority"
        );
    }
    let recipient = crate::jid::CanonicalJid::parse_bare(&recipient_bare_jid)?;
    let recipient_matches: bool =
        sqlx::query_scalar("SELECT northstar_lock_enabled_user_name($1,$2)")
            .bind(delivery.recipient_id)
            .bind(recipient.localpart().unwrap_or_default())
            .fetch_one(&mut **transaction)
            .await?;
    anyhow::ensure!(
        recipient_matches,
        "C2S delivery recipient account is unavailable or authority does not match"
    );
    // Serialize account capacity admission exactly like normal offline
    // storage. The row is a transient outbox even when the user is online.
    sqlx::query("SELECT pg_advisory_xact_lock_shared(5645368709120102)")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 3))")
        .bind(delivery.recipient_id.to_string())
        .execute(&mut **transaction)
        .await?;
    {
        sqlx::query(
            "WITH expired AS MATERIALIZED (
                 SELECT message.id FROM offline_messages message
                  WHERE message.recipient_id=$1
                    AND COALESCE(
                        (SELECT retention.offline_message_days
                           FROM user_retention_policies retention
                          WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                    ) IS NOT NULL
                    AND message.created_at < clock_timestamp()-(
                        COALESCE(
                            (SELECT retention.offline_message_days
                               FROM user_retention_policies retention
                              WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                        )::BIGINT*INTERVAL '1 day')
                    AND (message.delivery_claim_id IS NULL
                         OR message.delivery_claim_expires_at<=clock_timestamp())
                    AND NOT EXISTS (
                        SELECT 1 FROM sm_resume_stanzas sm
                         WHERE sm.delivery_message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM bosh_delivery_fences bosh
                         WHERE bosh.message_id=message.id
                    )
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                      WHERE link.hold_id=hold.id AND link.message_id=message.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='offline_message_recipient'
                                          AND scope_link.subject_id=message.recipient_id)
                         )
                    )
                  FOR UPDATE OF message SKIP LOCKED
             )
             DELETE FROM offline_messages message USING expired
              WHERE message.id=expired.id",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.policy.ttl_days)
        .execute(&mut **transaction)
        .await?;
    }
    let (current_messages, current_bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT,COALESCE(SUM(octet_length(stanza)),0)::BIGINT
           FROM offline_messages WHERE recipient_id=$1",
    )
    .bind(delivery.recipient_id)
    .fetch_one(&mut **transaction)
    .await?;
    let stanza_bytes = i64::try_from(delivery.stanza.len()).unwrap_or(i64::MAX);
    if current_messages >= delivery.policy.max_messages
        || current_bytes
            .checked_add(stanza_bytes)
            .is_none_or(|bytes| bytes > delivery.policy.max_bytes)
    {
        return Err(C2sDeliveryCapacityExceeded.into());
    }
    sqlx::query(
        "INSERT INTO offline_messages
         (id,recipient_id,sender_jid,stanza,target_resource,encrypted,mam_backed)
         VALUES($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(delivery.id)
    .bind(delivery.recipient_id)
    .bind(sender_jid)
    .bind(delivery.stanza)
    .bind(target_resource)
    .bind(delivery.encrypted)
    .bind(delivery.policy.mam_backed)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// Re-derive resource affinity from the persisted stanza at the repository
/// boundary. This prevents an internal caller from binding a bare/chat row to
/// one resource, omitting affinity from an explicit full-JID normal message,
/// or changing the target independently of the authenticated XML payload.
pub(super) fn normalized_c2s_target_resource(
    delivery: &PersonalC2sDeliveryAdmission<'_>,
) -> Result<(Option<String>, Option<String>)> {
    let document = roxmltree::Document::parse(delivery.stanza)?;
    let root = document.root_element();
    anyhow::ensure!(
        root.tag_name().name() == "message",
        "C2S delivery projection must contain one message stanza"
    );
    let target = root
        .attribute("to")
        .map(crate::jid::CanonicalJid::parse)
        .transpose()?;
    let target_bare_jid = target.as_ref().map(|target| target.bare().to_string());
    let expected = target
        .as_ref()
        .filter(|target| {
            root.attribute("type").unwrap_or("normal") == "normal"
                && target.resourcepart().is_some()
        })
        .map(ToString::to_string);
    let supplied = delivery
        .target_full_jid
        .map(crate::jid::canonical_session_key)
        .transpose()?;
    anyhow::ensure!(
        supplied == expected,
        "C2S delivery target resource affinity does not match stanza routing semantics"
    );
    if let Some(raw) = delivery.target_full_jid {
        anyhow::ensure!(
            supplied.as_deref() == Some(raw),
            "C2S delivery target resource affinity must already be canonical"
        );
    }
    let target_resource = expected
        .as_deref()
        .map(crate::jid::CanonicalJid::parse)
        .transpose()?
        .and_then(|target| target.resourcepart().map(str::to_owned));
    Ok((target_resource, target_bare_jid))
}
