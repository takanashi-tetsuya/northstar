//! Atomic retraction intents, archive tombstones and delivery projections.
use crate::{db, services::retractions::*};
use anyhow::Result;
use roxmltree::Document;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresRetractionRepository {
    pool: PgPool,
}
impl PostgresRetractionRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl RetractionRepository for PostgresRetractionRepository {
    async fn apply_prepared(&self, prepared: PreparedRetraction<'_>) -> Result<RetractionOutcome> {
        let PreparedRetraction {
            command,
            command_encrypted,
            canonical_sender,
            configured_domain,
            canonical_semantics,
            normalized_owners,
            normalized_writes,
            normalized_delivery,
            normalized_outbound,
            action_digest,
            semantic_sha256,
            semantic_sha512,
            semantic_length,
            semantic_authenticators,
            owner_projection_sha256,
            owner_projection_sha512,
            owner_projection_length,
            owner_authenticators,
            delivery_authenticators,
        } = prepared;
        let mut transaction = self.pool.begin().await?;
        let mut required_accounts = normalized_owners
            .iter()
            .map(|owner| owner.owner_id)
            .collect::<Vec<_>>();
        if let Some(delivery) = normalized_delivery.as_ref() {
            required_accounts.push(delivery.projection.recipient_id);
            required_accounts.extend(delivery.projection.local_actor_id);
        }
        if !db::lock_enabled_users_in_transaction(&mut transaction, &required_accounts).await? {
            transaction.rollback().await?;
            return Ok(RetractionOutcome::AccountUnavailable);
        }
        let account_rows = sqlx::query(
            "SELECT id,username FROM users
              WHERE id=ANY($1) AND NOT is_disabled
              ORDER BY id FOR SHARE",
        )
        .bind(&required_accounts)
        .fetch_all(&mut *transaction)
        .await?;
        let mut account_bares = HashMap::with_capacity(account_rows.len());
        for row in account_rows {
            let id: Uuid = row.get("id");
            let username: String = row.get("username");
            let bare = crate::jid::canonical_bare_key(&format!("{username}@{configured_domain}"))?;
            account_bares.insert(id, bare);
        }
        validate_owner_authority(
            &normalized_owners,
            &account_bares,
            &canonical_sender,
            &configured_domain,
            normalized_delivery.as_ref(),
            normalized_outbound.as_ref(),
        )?;
        let lock_key = retraction_lock_key(&canonical_sender, command.action_id);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *transaction)
            .await?;

        let intent_id = Uuid::new_v4();
        let primary_semantic = semantic_authenticators.primary();
        let primary_delivery = delivery_authenticators
            .as_ref()
            .map(|authenticators| authenticators.primary());
        let primary_owner = owner_authenticators.primary();
        let inserted_intent = sqlx::query(
            "INSERT INTO personal_retraction_intents
             (id,sender_bare_jid,action_id,action_digest,target_id,
              semantic_key_id,semantic_mac,
              owner_projection_key_id,owner_projection_mac,
              outbound_requested,c2s_delivery_requested,
              c2s_projection_key_id,c2s_projection_mac)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (sender_bare_jid,action_digest) DO NOTHING",
        )
        .bind(intent_id)
        .bind(&canonical_sender)
        .bind(command.action_id)
        .bind(action_digest.as_slice())
        .bind(command.target_id)
        .bind(primary_semantic.key_id())
        .bind(primary_semantic.mac().as_slice())
        .bind(primary_owner.key_id())
        .bind(primary_owner.mac().as_slice())
        .bind(normalized_outbound.is_some())
        .bind(normalized_delivery.is_some())
        .bind(primary_delivery.map(|authenticator| authenticator.key_id()))
        .bind(primary_delivery.map(|authenticator| authenticator.mac().as_slice()))
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if !inserted_intent {
            let row = sqlx::query(
                "SELECT id,action_id,target_id,semantic_key_id,semantic_mac,
                        semantic_sha256,semantic_sha512,semantic_length,
                        owner_projection_key_id,owner_projection_mac,
                        owner_projection_sha256,owner_projection_sha512,owner_projection_length,
                        outbound_requested,c2s_delivery_requested,
                        c2s_projection_key_id,c2s_projection_mac
                   FROM personal_retraction_intents
                  WHERE sender_bare_jid=$1 AND action_digest=$2
                  FOR UPDATE",
            )
            .bind(&canonical_sender)
            .bind(action_digest.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(row) = row else {
                anyhow::bail!("retraction intent disappeared during exact replay comparison");
            };
            let stored_key_id = row.get::<Option<String>, _>("semantic_key_id");
            let stored_mac = row.get::<Option<Vec<u8>>, _>("semantic_mac");
            let legacy_sha256 = row.get::<Option<Vec<u8>>, _>("semantic_sha256");
            let legacy_sha512 = row.get::<Option<Vec<u8>>, _>("semantic_sha512");
            let legacy_length = row.get::<Option<i64>, _>("semantic_length");
            let stored_delivery_key_id = row.get::<Option<String>, _>("c2s_projection_key_id");
            let stored_delivery_mac = row.get::<Option<Vec<u8>>, _>("c2s_projection_mac");
            let stored_owner_key_id = row.get::<Option<String>, _>("owner_projection_key_id");
            let stored_owner_mac = row.get::<Option<Vec<u8>>, _>("owner_projection_mac");
            let legacy_owner_sha256 = row.get::<Option<Vec<u8>>, _>("owner_projection_sha256");
            let legacy_owner_sha512 = row.get::<Option<Vec<u8>>, _>("owner_projection_sha512");
            let legacy_owner_length = row.get::<Option<i64>, _>("owner_projection_length");
            let keyed_semantic_exact = match (stored_key_id.as_deref(), stored_mac.as_deref()) {
                (Some(key_id), Some(mac))
                    if legacy_sha256.is_none()
                        && legacy_sha512.is_none()
                        && legacy_length.is_none() =>
                {
                    semantic_authenticators.verifies(key_id, mac)
                }
                _ => false,
            };
            let legacy_semantic_exact = match (
                stored_key_id.as_deref(),
                stored_mac.as_deref(),
                legacy_sha256.as_deref(),
                legacy_sha512.as_deref(),
                legacy_length,
            ) {
                (None, None, Some(sha256), Some(sha512), Some(length))
                    if sha256.len() == 32 && sha512.len() == 64 =>
                {
                    length == semantic_length
                        && bool::from(
                            sha256.ct_eq(semantic_sha256.as_slice())
                                & sha512.ct_eq(semantic_sha512.as_slice()),
                        )
                }
                _ => false,
            };
            let delivery_exact = match (
                delivery_authenticators.as_ref(),
                stored_delivery_key_id.as_deref(),
                stored_delivery_mac.as_deref(),
            ) {
                (None, None, None) => true,
                (Some(authenticators), Some(key_id), Some(mac)) => {
                    authenticators.verifies(key_id, mac)
                }
                _ => false,
            };
            let keyed_owner_exact = match (
                stored_owner_key_id.as_deref(),
                stored_owner_mac.as_deref(),
                legacy_owner_sha256.as_deref(),
                legacy_owner_sha512.as_deref(),
                legacy_owner_length,
            ) {
                (Some(key_id), Some(mac), None, None, None) => {
                    owner_authenticators.verifies(key_id, mac)
                }
                _ => false,
            };
            let legacy_owner_exact = match (
                stored_owner_key_id.as_deref(),
                stored_owner_mac.as_deref(),
                legacy_owner_sha256.as_deref(),
                legacy_owner_sha512.as_deref(),
                legacy_owner_length,
            ) {
                (None, None, Some(sha256), Some(sha512), Some(length))
                    if sha256.len() == 32 && sha512.len() == 64 =>
                {
                    length == owner_projection_length
                        && bool::from(
                            sha256.ct_eq(owner_projection_sha256.as_slice())
                                & sha512.ct_eq(owner_projection_sha512.as_slice()),
                        )
                }
                _ => false,
            };
            let exact = row.get::<String, _>("action_id") == command.action_id
                && row.get::<String, _>("target_id") == command.target_id
                && (keyed_semantic_exact || legacy_semantic_exact)
                && (keyed_owner_exact || legacy_owner_exact)
                && row.get::<bool, _>("outbound_requested") == normalized_outbound.is_some()
                && row.get::<bool, _>("c2s_delivery_requested") == normalized_delivery.is_some()
                && delivery_exact;
            if !exact {
                transaction.rollback().await?;
                return Ok(RetractionOutcome::Conflict);
            }
            let persisted_intent_id: Uuid = row.get("id");
            let projections = sqlx::query(
                "SELECT owner_id,archive_id
                   FROM personal_retraction_action_projections
                  WHERE intent_id=$1
                  ORDER BY ordinal
                  FOR UPDATE",
            )
            .bind(persisted_intent_id)
            .fetch_all(&mut *transaction)
            .await?;
            for projection in projections {
                let owner_id: Uuid = projection.get("owner_id");
                let Some(peer_bare_jid) = normalized_owners.iter().find_map(|owner| {
                    (owner.owner_id == owner_id).then_some(owner.peer_bare_jid.as_str())
                }) else {
                    transaction.rollback().await?;
                    return Ok(RetractionOutcome::Conflict);
                };
                let Some(archive_id) = projection.get::<Option<Uuid>, _>("archive_id") else {
                    // The projection row is the immutable replay plan. MAM
                    // retention may legitimately delete its archive row and
                    // clear this SET NULL foreign key; the keyed intent still
                    // proves exact operation equivalence.
                    continue;
                };
                let existing = sqlx::query(
                    "SELECT stanza,encrypted FROM message_archive
                      WHERE id=$1 AND owner_id=$2 AND peer_jid=$3 AND stanza_id=$4
                      FOR UPDATE",
                )
                .bind(archive_id)
                .bind(owner_id)
                .bind(peer_bare_jid)
                .bind(command.action_id)
                .fetch_optional(&mut *transaction)
                .await?;
                let Some(existing) = existing else {
                    transaction.rollback().await?;
                    return Ok(RetractionOutcome::Conflict);
                };
                let existing_stanza = existing.get::<String, _>("stanza");
                let existing_encrypted = existing.get::<bool, _>("encrypted");
                let existing_encryption_shape = Document::parse(&existing_stanza)
                    .ok()
                    .map(|document| crate::xmpp::xml_util::is_encrypted(document.root_element()));
                if existing_encrypted != command_encrypted
                    || existing_encryption_shape != Some(existing_encrypted)
                {
                    transaction.rollback().await?;
                    return Ok(RetractionOutcome::Conflict);
                }
                let existing_semantics = canonical_retraction_semantics(
                    &existing_stanza,
                    &canonical_sender,
                    command.action_id,
                    command.target_id,
                );
                let expected_semantics = if command_encrypted {
                    let sanitized = crate::xmpp::xml_util::encrypted_retraction_archive_stanza(
                        command.semantic_payload,
                        command.target_id,
                    );
                    canonical_retraction_semantics(
                        &sanitized,
                        &canonical_sender,
                        command.action_id,
                        command.target_id,
                    )?
                } else {
                    canonical_semantics.clone()
                };
                if existing_semantics
                    .ok()
                    .is_none_or(|semantics| semantics != expected_semantics)
                {
                    transaction.rollback().await?;
                    return Ok(RetractionOutcome::Conflict);
                }
            }
            if legacy_semantic_exact {
                let upgraded = sqlx::query(
                    "UPDATE personal_retraction_intents
                        SET semantic_key_id=$2,semantic_mac=$3,
                            semantic_sha256=NULL,semantic_sha512=NULL,semantic_length=NULL
                      WHERE id=$1 AND semantic_key_id IS NULL AND semantic_mac IS NULL
                        AND semantic_sha256 IS NOT NULL AND semantic_sha512 IS NOT NULL
                        AND semantic_length IS NOT NULL",
                )
                .bind(persisted_intent_id)
                .bind(primary_semantic.key_id())
                .bind(primary_semantic.mac().as_slice())
                .execute(&mut *transaction)
                .await?;
                anyhow::ensure!(
                    upgraded.rows_affected() == 1,
                    "legacy retraction commitment changed while locked"
                );
            }
            if legacy_owner_exact {
                let upgraded = sqlx::query(
                    "UPDATE personal_retraction_intents
                        SET owner_projection_key_id=$2,owner_projection_mac=$3,
                            owner_projection_sha256=NULL,owner_projection_sha512=NULL,
                            owner_projection_length=NULL
                      WHERE id=$1
                        AND owner_projection_key_id IS NULL
                        AND owner_projection_mac IS NULL
                        AND owner_projection_sha256 IS NOT NULL
                        AND owner_projection_sha512 IS NOT NULL
                        AND owner_projection_length IS NOT NULL",
                )
                .bind(persisted_intent_id)
                .bind(primary_owner.key_id())
                .bind(primary_owner.mac().as_slice())
                .execute(&mut *transaction)
                .await?;
                anyhow::ensure!(
                    upgraded.rows_affected() == 1,
                    "legacy retraction owner commitment changed while locked"
                );
            }
            if legacy_semantic_exact || legacy_owner_exact {
                transaction.commit().await?;
            } else {
                transaction.rollback().await?;
            }
            return Ok(RetractionOutcome::Replay);
        }

        // A newly recorded intent must not adopt legacy or manually inserted
        // action rows whose full operation identity was never committed with
        // it. The immutable projection plan below is the only replay snapshot.
        for write in &normalized_writes {
            let existing: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM message_archive
                     WHERE owner_id=$1
                       AND pg_catalog.md5(peer_jid)=pg_catalog.md5($2::TEXT)
                       AND pg_catalog.md5(stanza_id)=pg_catalog.md5($3::TEXT)
                       AND peer_jid=$2 AND stanza_id=$3
                     LIMIT 1
                 )",
            )
            .bind(write.write.owner_id)
            .bind(&write.peer_bare_jid)
            .bind(command.action_id)
            .fetch_one(&mut *transaction)
            .await?;
            if existing {
                transaction.rollback().await?;
                return Ok(RetractionOutcome::Conflict);
            }
        }
        for (ordinal, write) in normalized_writes.iter().enumerate() {
            sqlx::query(
                "INSERT INTO personal_retraction_action_projections
                 (intent_id,ordinal,owner_id,archive_id)
                 VALUES($1,$2,$3,$4)",
            )
            .bind(intent_id)
            .bind(i16::try_from(ordinal)?)
            .bind(write.write.owner_id)
            .bind(write.write.id)
            .execute(&mut *transaction)
            .await?;
        }

        let mut tombstones = Vec::new();
        let mut saw_same_tombstone = false;
        let mut saw_foreign_original = false;
        for owner in &normalized_owners {
            let rows = sqlx::query(
                "SELECT id,stanza FROM message_archive
                  WHERE owner_id=$1
                    AND pg_catalog.md5(peer_jid)=pg_catalog.md5($2::TEXT)
                    AND pg_catalog.md5(stanza_id)=pg_catalog.md5($3::TEXT)
                    AND peer_jid=$2 AND stanza_id=$3
                  ORDER BY created_at DESC,id DESC LIMIT 3 FOR UPDATE",
            )
            .bind(owner.owner_id)
            .bind(&owner.peer_bare_jid)
            .bind(command.target_id)
            .fetch_all(&mut *transaction)
            .await?;
            if rows.len() == 3 {
                // Three exact owner/peer/stanza-id matches exhaust this
                // deliberately bounded ambiguity probe. Fail closed instead
                // of allowing newer decoy rows to hide an older retractable
                // message beyond the query limit.
                transaction.rollback().await?;
                return Ok(RetractionOutcome::Conflict);
            }
            let mut owned = Vec::new();
            for row in rows {
                let archive_id: Uuid = row.get("id");
                let stanza: String = row.get("stanza");
                match classify_target(&stanza, &canonical_sender, command.action_id)? {
                    TargetClassification::OwnedOriginal(tombstone) => {
                        owned.push((owner.owner_id, archive_id, tombstone));
                    }
                    TargetClassification::SameTombstone => saw_same_tombstone = true,
                    TargetClassification::ConflictingTombstone => {
                        transaction.rollback().await?;
                        return Ok(RetractionOutcome::Conflict);
                    }
                    TargetClassification::ForeignOriginal => saw_foreign_original = true,
                    TargetClassification::Irrelevant => {}
                }
            }
            if owned.len() > 1 {
                transaction.rollback().await?;
                return Ok(RetractionOutcome::Conflict);
            }
            tombstones.extend(owned);
        }
        if saw_foreign_original {
            transaction.rollback().await?;
            return Ok(RetractionOutcome::Forbidden);
        }
        if tombstones.is_empty() && saw_same_tombstone {
            if normalized_writes.is_empty()
                && normalized_delivery.is_none()
                && normalized_outbound.is_none()
            {
                transaction.commit().await?;
                return Ok(RetractionOutcome::Replay);
            }
            transaction.rollback().await?;
            return Ok(RetractionOutcome::Conflict);
        }

        for (owner_id, archive_id, tombstone) in &tombstones {
            let updated = sqlx::query(
                "UPDATE message_archive SET stanza=$3,encrypted=FALSE
                  WHERE owner_id=$1 AND id=$2",
            )
            .bind(owner_id)
            .bind(archive_id)
            .bind(tombstone)
            .execute(&mut *transaction)
            .await?;
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "locked retraction target disappeared before tombstoning"
            );
        }
        for write in &normalized_writes {
            sqlx::query(
                "INSERT INTO message_archive
                 (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
                 VALUES($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(write.write.id)
            .bind(write.write.owner_id)
            .bind(&write.peer_bare_jid)
            .bind(&write.peer_full_jid)
            .bind(write.write.stanza)
            .bind(write.write.encrypted)
            .bind(write.write.stanza_id)
            .execute(&mut *transaction)
            .await?;
        }
        if let Some(delivery) = normalized_delivery.as_ref() {
            let projection = delivery.projection;
            let bound = sqlx::query(
                "UPDATE personal_retraction_intents
                    SET c2s_delivery_id=$2
                  WHERE id=$1",
            )
            .bind(intent_id)
            .bind(projection.id)
            .execute(&mut *transaction)
            .await?;
            anyhow::ensure!(
                bound.rows_affected() == 1,
                "retraction intent disappeared before C2S delivery binding"
            );
            let db_delivery = db::PersonalC2sDeliveryAdmission {
                id: projection.id,
                recipient_id: projection.recipient_id,
                recipient_bare_jid: &delivery.recipient_bare_jid,
                local_actor_id: projection.local_actor_id,
                sender_jid: &delivery.sender_full_jid,
                stanza: projection.stanza,
                target_full_jid: delivery.target_full_jid.as_deref(),
                encrypted: projection.encrypted,
                policy: db::OfflineStorePolicy {
                    max_messages: projection.max_messages,
                    max_bytes: projection.max_bytes,
                    ttl_days: projection.ttl_days,
                    mam_backed: projection.mam_backed,
                },
            };
            if let Err(error) = db::archive::insert_c2s_delivery_in_transaction(
                &mut transaction,
                &db_delivery,
                &delivery.sender_full_jid,
            )
            .await
            {
                if error
                    .downcast_ref::<db::archive::C2sDeliveryCapacityExceeded>()
                    .is_some()
                {
                    transaction.rollback().await?;
                    return Ok(RetractionOutcome::CapacityExceeded);
                }
                return Err(error);
            }
        }
        if let Some(outbound) = normalized_outbound.as_ref() {
            let projection = outbound.projection;
            let outbox_id = Uuid::new_v4();
            let bound = sqlx::query(
                "UPDATE personal_retraction_intents
                    SET s2s_outbox_id=$2
                  WHERE id=$1",
            )
            .bind(intent_id)
            .bind(outbox_id)
            .execute(&mut *transaction)
            .await?;
            anyhow::ensure!(
                bound.rows_affected() == 1,
                "retraction intent disappeared before outbox binding"
            );
            db::s2s::enqueue_s2s_outbox_with_id_in_transaction(
                &mut transaction,
                outbox_id,
                &outbound.target_domain,
                projection.stanza,
                projection.bounce_to,
                projection.policy.into(),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(RetractionOutcome::Applied {
            tombstones: tombstones.len(),
        })
    }
}
