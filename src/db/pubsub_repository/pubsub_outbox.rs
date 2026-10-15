//! PostgreSQL implementation of the PubSub outbox repository port.

use super::*;

impl PubSubOutboxRepository for PostgresPubSubRepository {
    async fn cleanup_idle_pubsub_event_streams(&self, limit: i64) -> Result<u64> {
        let outcome: Result<_> =
            async { db::cleanup_idle_pubsub_event_streams(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }

    async fn cleanup_pubsub_dead_letters(&self, limit: i64) -> Result<u64> {
        let outcome: Result<_> =
            async { db::cleanup_pubsub_dead_letters(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }

    async fn outbox_get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::get_subscription(&self.pool, node_id, jid)
                .await?
                .map(Into::into))
        }
        .await;
        outcome.map_err(map_database_busy)
    }

    async fn local_account_blocks_pubsub(&self, username: &str, service: &str) -> Result<bool> {
        let outcome: Result<_> = async {
            let Some(user) = db::find_enabled_user(&self.pool, username).await? else {
                return Ok(false);
            };
            db::is_blocked(&self.pool, user.id, service).await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn presence_delivery_denied(
        &self,
        recipient_id: Uuid,
        active_privacy_list: Option<&str>,
        connection_id: Uuid,
        service: &str,
    ) -> Result<bool> {
        let outcome: Result<_> = async {
            if db::is_blocked(&self.pool, recipient_id, service).await? {
                return Ok(true);
            }
            if active_privacy_list.is_some() {
                db::refresh_active_privacy_session(&self.pool, recipient_id, connection_id).await?;
            }
            db::privacy_denies(
                &self.pool,
                recipient_id,
                active_privacy_list,
                service,
                db::PrivacyStanzaKind::Message,
            )
            .await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn authorize_pep_outbox_delivery(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
    ) -> Result<PepOutboxAuthorizationOutcome> {
        let outcome: Result<_> = async {
            let drop_unverifiable = || {
                db::record_unverifiable_pep_drop();
                PepOutboxAuthorizationOutcome::Drop(PepOutboxDropReason::UnverifiableIdentity)
            };
            if item.delivery_kind != PubSubOutboxDeliveryKind::PepStanza
                || item.source != PubSubOutboxSource::Pep
                || item.legacy_unverifiable
            {
                return Ok(drop_unverifiable());
            }
            let Some(subject) = item.pep_subject.as_ref() else {
                return Ok(drop_unverifiable());
            };
            if subject.sender_account_id.is_nil()
                || subject
                    .sender_connection_id
                    .is_some_and(|connection_id| connection_id.is_nil())
                || subject
                    .recipient_account_id
                    .is_some_and(|recipient_id| recipient_id.is_nil())
                || (subject.event_kind.requires_causal_authorization()
                    && subject.authorization_mode != PepOutboxAuthorizationMode::CausalAudience)
                || item.security_sensitive != db::security_sensitive_pep_node(&item.source_node)
                || (item.security_sensitive
                    && matches!(
                        subject.event_kind,
                        PepOutboxEventKind::Publish | PepOutboxEventKind::LastItem
                    )
                    && subject.authorization_mode != PepOutboxAuthorizationMode::LiveNodeAccess)
            {
                return Ok(drop_unverifiable());
            }

            let Ok(sender) = crate::jid::CanonicalJid::parse_bare(&subject.sender_bare_jid) else {
                return Ok(drop_unverifiable());
            };
            let Ok(recipient) = crate::jid::CanonicalJid::parse(&item.recipient_jid) else {
                return Ok(drop_unverifiable());
            };
            if sender.to_string() != subject.sender_bare_jid
                || sender.domainpart() != self.domain
                || sender.localpart().is_none()
                || recipient.to_string() != item.recipient_jid
                || recipient.domainpart() != item.target_domain
            {
                return Ok(drop_unverifiable());
            }
            let recipient_is_local = recipient.domainpart() == self.domain;
            if recipient_is_local != subject.recipient_is_local
                || subject.recipient_is_local != subject.recipient_account_id.is_some()
                || recipient_is_local && recipient.localpart().is_none()
            {
                return Ok(drop_unverifiable());
            }

            let mut transaction = self.begin_mutation().await?;
            let mut account_ids = vec![subject.sender_account_id];
            if let Some(recipient_id) = subject.recipient_account_id {
                account_ids.push(recipient_id);
            }
            account_ids.sort_unstable();
            account_ids.dedup();
            let rows = sqlx::query(
                "SELECT id,username,is_disabled FROM users
              WHERE id=ANY($1)
              ORDER BY id
              FOR SHARE",
            )
            .bind(&account_ids)
            .fetch_all(&mut *transaction)
            .await?;
            let accounts = rows
                .into_iter()
                .map(|row| {
                    Ok::<_, sqlx::Error>((
                        row.try_get::<Uuid, _>("id")?,
                        (
                            row.try_get::<String, _>("username")?,
                            row.try_get::<bool, _>("is_disabled")?,
                        ),
                    ))
                })
                .collect::<std::result::Result<HashMap<_, _>, _>>()?;
            let sender_matches =
                accounts
                    .get(&subject.sender_account_id)
                    .is_some_and(|(username, disabled)| {
                        !*disabled
                            && crate::jid::CanonicalJid::parse_bare(&format!(
                                "{username}@{}",
                                self.domain
                            ))
                            .is_ok_and(|jid| jid.to_string() == subject.sender_bare_jid)
                    });
            if !sender_matches {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::SenderUnavailable,
                ));
            }
            if let Some(recipient_id) = subject.recipient_account_id {
                let recipient_matches =
                    accounts
                        .get(&recipient_id)
                        .is_some_and(|(username, disabled)| {
                            !*disabled
                                && recipient.localpart() == Some(username.as_str())
                                && recipient.domainpart() == self.domain
                        });
                if !recipient_matches {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::RecipientUnavailable,
                    ));
                }
            }

            // A publication holds the per-node audience lock while it derives
            // the causal delivery set, and subsequently takes the block-policy
            // locks for that same set.  A live authorization must take those
            // shared authorities in exactly that order.  Taking block policy
            // first here creates an advisory-lock cycle with a simultaneous
            // security-sensitive publication: publish owns audience and waits for
            // block policy while delivery owns block policy and waits for
            // audience.  Causal-audience events do not consult a live node policy
            // and therefore intentionally do not take the audience lock.
            let lock_plan = pep_outbox_authorization_lock_plan(subject.authorization_mode);
            if lock_plan == PepOutboxAuthorizationLockPlan::AudienceThenBlockPolicy {
                lock_pep_audience(
                    &mut transaction,
                    subject.sender_account_id,
                    &item.source_node,
                )
                .await?;
            }
            for owner_id in &account_ids {
                lock_pep_block_policy(&mut transaction, *owner_id).await?;
            }
            let block_rows = sqlx::query(
                "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid
              FOR SHARE",
            )
            .bind(&account_ids)
            .fetch_all(&mut *transaction)
            .await?;
            let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
            for row in block_rows {
                blocks
                    .entry(row.try_get("owner_id")?)
                    .or_default()
                    .push(row.try_get("blocked_jid")?);
            }
            let same_account = subject.recipient_account_id == Some(subject.sender_account_id);
            let sender_blocks_recipient = !same_account
                && blocks
                    .get(&subject.sender_account_id)
                    .is_some_and(|patterns| {
                        patterns.iter().any(|pattern| {
                            db::roster::blocked_jid_matches(pattern, &item.recipient_jid)
                        })
                    });
            let recipient_blocks_sender = !same_account
                && subject.recipient_account_id.is_some_and(|recipient_id| {
                    blocks.get(&recipient_id).is_some_and(|patterns| {
                        patterns.iter().any(|pattern| {
                            db::roster::blocked_jid_matches(pattern, &subject.sender_bare_jid)
                        })
                    })
                });
            if sender_blocks_recipient || recipient_blocks_sender {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::Blocked,
                ));
            }

            if !same_account
                && db::privacy::privacy_denies_in_transaction(
                    &mut transaction,
                    subject.sender_account_id,
                    subject.sender_connection_id,
                    &item.recipient_jid,
                    db::PrivacyStanzaKind::Message,
                )
                .await?
            {
                transaction.rollback().await?;
                return Ok(PepOutboxAuthorizationOutcome::Drop(
                    PepOutboxDropReason::PrivacyDenied,
                ));
            }
            if !same_account {
                if let Some(recipient_id) = subject.recipient_account_id {
                    if db::privacy::privacy_denies_in_transaction(
                        &mut transaction,
                        recipient_id,
                        None,
                        &subject.sender_bare_jid,
                        db::PrivacyStanzaKind::Message,
                    )
                    .await?
                    {
                        transaction.rollback().await?;
                        return Ok(PepOutboxAuthorizationOutcome::Drop(
                            PepOutboxDropReason::PrivacyDenied,
                        ));
                    }
                }
            }

            if lock_plan == PepOutboxAuthorizationLockPlan::AudienceThenBlockPolicy {
                let policy = sqlx::query(
                "SELECT access_model,deliver_notifications,roster_groups_allowed,access_whitelist
                   FROM pep_nodes
                  WHERE owner_id=$1 AND node=$2
                  FOR SHARE",
            )
            .bind(subject.sender_account_id)
            .bind(&item.source_node)
            .fetch_optional(&mut *transaction)
            .await?;
                let Some(policy) = policy else {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::NodeAccessRevoked,
                    ));
                };
                if !policy.try_get::<bool, _>("deliver_notifications")? {
                    transaction.rollback().await?;
                    return Ok(PepOutboxAuthorizationOutcome::Drop(
                        PepOutboxDropReason::NodeAccessRevoked,
                    ));
                }
                let recipient_bare = recipient.bare();
                if recipient_bare != subject.sender_bare_jid {
                    let roster = sqlx::query(
                        "SELECT subscription,groups FROM roster_items
                      WHERE owner_id=$1 AND contact_jid=$2
                      FOR SHARE",
                    )
                    .bind(subject.sender_account_id)
                    .bind(&recipient_bare)
                    .fetch_optional(&mut *transaction)
                    .await?;
                    let automatic = roster
                        .as_ref()
                        .map(|row| row.try_get::<String, _>("subscription"))
                        .transpose()?
                        .is_some_and(|subscription| {
                            matches!(subscription.as_str(), "from" | "both")
                        });
                    let access_model: String = policy.try_get("access_model")?;
                    let access_allowed = match access_model.as_str() {
                        // The causal audience was already captured while the
                        // publication transaction held the node locks. `open`
                        // therefore remains open at delivery time; the live check
                        // detects a later restrictive policy without inventing a
                        // subscription requirement XEP-0060 does not impose.
                        "open" => true,
                        "whitelist" => policy
                            .try_get::<Vec<String>, _>("access_whitelist")?
                            .iter()
                            .any(|jid| {
                                crate::jid::canonical_bare_key(jid)
                                    .is_ok_and(|jid| jid == recipient_bare)
                            }),
                        "presence" => automatic,
                        "roster" => match roster.as_ref() {
                            Some(row) => {
                                let groups = serde_json::from_value::<Vec<String>>(
                                    row.try_get::<serde_json::Value, _>("groups")?,
                                )
                                .context("stored PEP roster groups are not a string array")?;
                                let allowed: Vec<String> =
                                    policy.try_get("roster_groups_allowed")?;
                                automatic && groups.iter().any(|group| allowed.contains(group))
                            }
                            None => false,
                        },
                        _ => false,
                    };
                    if !access_allowed {
                        transaction.rollback().await?;
                        return Ok(PepOutboxAuthorizationOutcome::Drop(
                            PepOutboxDropReason::NodeAccessRevoked,
                        ));
                    }
                }
            }
            transaction.commit().await?;
            Ok(PepOutboxAuthorizationOutcome::Deliver)
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn claim_pubsub_outbox(&self, limit: i64) -> Result<Vec<ClaimedPubSubOutboxDelivery>> {
        let outcome: Result<_> = async { db::claim_pubsub_outbox(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn acknowledge_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let outcome: Result<_> =
            async { db::acknowledge_pubsub_outbox(&self.pool, delivery_id, lease_token).await }
                .await;
        outcome.map_err(map_database_busy)
    }
    async fn renew_pubsub_outbox_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<bool> {
        let outcome: Result<_> =
            async { db::renew_pubsub_outbox_lease(&self.pool, delivery_id, lease_token).await }
                .await;
        outcome.map_err(map_database_busy)
    }
    async fn retry_pubsub_outbox(
        &self,
        item: &ClaimedPubSubOutboxDelivery,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let outcome: Result<_> =
            async { db::retry_pubsub_outbox(&self.pool, item, error).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn dead_letter_pubsub_outbox(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        reason: &str,
        error: &str,
    ) -> Result<PubSubOutboxFailureDisposition> {
        let outcome: Result<_> = async {
            db::dead_letter_pubsub_outbox(&self.pool, delivery_id, lease_token, reason, error).await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn expire_pubsub_outbox(&self, limit: i64) -> Result<u64> {
        let outcome: Result<_> = async { db::expire_pubsub_outbox(&self.pool, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn pubsub_outbox_snapshot(&self) -> Result<PubSubOutboxSnapshot> {
        let outcome: Result<_> = async { db::pubsub_outbox_snapshot(&self.pool).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn enqueue_pubsub_digest_snapshot(
        &self,
        source_delivery_id: Uuid,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
        show_values: &[String],
    ) -> Result<()> {
        let outcome: Result<_> = async {
            // This is a projection of an already-committed outbox row, not a
            // client mutation. It must not occupy the foreground PubSub mutation
            // admission while delivery workers recover under a small pool.

            db::enqueue_pubsub_digest_snapshot(
                &self.pool,
                source_delivery_id,
                node_id,
                subscriber_jid,
                event_xml,
                frequency_ms,
                show_values,
            )
            .await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn enqueue_pubsub_digest(
        &self,
        node_id: Uuid,
        subscriber_jid: &str,
        event_xml: &str,
        frequency_ms: i32,
    ) -> Result<bool> {
        let outcome: Result<_> = async {
            db::enqueue_pubsub_digest(&self.pool, node_id, subscriber_jid, event_xml, frequency_ms)
                .await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn claim_due_pubsub_digests(&self, limit: i64) -> Result<Vec<DuePubSubDigest>> {
        let outcome: Result<_> = async {
            Ok(db::claim_due_pubsub_digests(&self.pool, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn release_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let outcome: Result<_> = async { db::release_pubsub_digests(&self.pool, ids).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn acknowledge_pubsub_digests(&self, ids: &[Uuid]) -> Result<()> {
        let outcome: Result<_> =
            async { db::acknowledge_pubsub_digests(&self.pool, ids).await }.await;
        outcome.map_err(map_database_busy)
    }
}
