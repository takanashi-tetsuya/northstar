//! PostgreSQL implementations of the PEP node, item, subscription and affiliation repository ports.

use super::*;

impl PepNodeQueryRepository for PostgresPubSubRepository {
    async fn roster_item(
        &self,
        owner_id: Uuid,
        jid: &str,
    ) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
        let outcome: Result<_> = async { db::roster_item(&self.pool, owner_id, jid).await }.await;
        outcome.map_err(map_database_busy)
    }

    async fn pep_node(&self, owner_id: Uuid, node: &str) -> Result<Option<PepNodeConfig>> {
        let outcome: Result<_> = async {
            Ok(db::pep_node(&self.pool, owner_id, node)
                .await?
                .map(Into::into))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_nodes(&self, owner_id: Uuid) -> Result<Vec<String>> {
        let outcome: Result<_> = async { db::pep_nodes(&self.pool, owner_id).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn find_enabled_user(&self, username: &str) -> Result<Option<PubSubAccount>> {
        let outcome: Result<_> = async {
            Ok(db::find_enabled_user(&self.pool, username)
                .await?
                .map(|user| PubSubAccount {
                    id: user.id,
                    username: user.username,
                    auth_generation: user.auth_generation,
                }))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn roster(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
        let outcome: Result<_> = async { db::roster(&self.pool, owner_id).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        let outcome: Result<_> =
            async { db::is_blocked(&self.pool, owner_id, candidate).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn roster_group_allowed(
        &self,
        owner_id: Uuid,
        jid: &str,
        groups: &[String],
    ) -> Result<bool> {
        let outcome: Result<_> =
            async { db::roster_group_allowed(&self.pool, owner_id, jid, groups).await }.await;
        outcome.map_err(map_database_busy)
    }
}
impl PepNodeMutationRepository for PostgresPubSubRepository {
    async fn create_pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
        config: &PepNodeConfig,
        max_nodes: i64,
    ) -> Result<PepCreateOutcome> {
        let outcome: Result<_> = async {
            let config = db::PepNodeConfig::from(config);
            Ok(
                db::create_pep_node(&self.pool, owner_id, node, &config, max_nodes)
                    .await?
                    .into(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn update_pep_node_config(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        config: &PepNodeConfig,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            let Some(current) =
                Self::locked_pep_node_config(&mut transaction, owner.id, node).await?
            else {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            };
            if &current != expected {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::Stale);
            }
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Configuration,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                    None,
                )
                .await?;
            Self::store_pep_node_config(&mut transaction, owner.id, node, config).await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn purge_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Purge,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                    None,
                )
                .await?;
            sqlx::query("DELETE FROM pep_items WHERE owner_id=$1 AND node=$2")
                .bind(owner.id)
                .bind(node)
                .execute(&mut *transaction)
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn delete_pep_node(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Delete,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                    None,
                )
                .await?;
            sqlx::query("DELETE FROM pep_nodes WHERE owner_id=$1 AND node=$2")
                .bind(owner.id)
                .bind(node)
                .execute(&mut *transaction)
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepItemQueryRepository for PostgresPubSubRepository {
    async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        let outcome: Result<_> =
            async { db::pep_items(&self.pool, owner_id, node, item_id, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_items_by_ids(
        &self,
        owner_id: Uuid,
        node: &str,
        item_ids: &[&str],
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        let outcome: Result<_> =
            async { db::pep_items_by_ids(&self.pool, owner_id, node, item_ids, limit).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_items_with_timestamp(
        &self,
        owner_id: Uuid,
        node: &str,
        limit: i64,
    ) -> Result<Vec<PepItem>> {
        let outcome: Result<_> = async {
            Ok(
                db::pep_items_with_timestamp(&self.pool, owner_id, node, limit)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepItemMutationRepository for PostgresPubSubRepository {
    async fn retract_pep_items(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        item_ids: &[&str],
        notify: bool,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let matched: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pep_items
              WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)",
            )
            .bind(owner.id)
            .bind(node)
            .bind(item_ids)
            .fetch_one(&mut *transaction)
            .await?;
            if matched != i64::try_from(item_ids.len())? {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let outbox = if notify {
                self.exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    node,
                    PepOutboxEventKind::Retract,
                    PepOutboxAuthorizationMode::CausalAudience,
                    factory,
                    None,
                )
                .await?
            } else {
                Vec::new()
            };
            let removed = sqlx::query(
                "DELETE FROM pep_items WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)",
            )
            .bind(owner.id)
            .bind(node)
            .bind(item_ids)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(removed))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn commit_legacy_bookmarks(
        &self,
        command: PepCommitLegacyBookmarksCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepCommitLegacyBookmarksResult> {
        const LEGACY_BOOKMARKS: &str = "storage:bookmarks";
        let PepCommitLegacyBookmarksCommand {
            owner,
            connection_id: sender_connection_id,
            private_xml,
            items,
            expected_previous_items,
            max_private_bytes,
            quotas,
        } = command;
        let outcome: Result<_> = async {
            let Some((mut transaction, _)) = self
                .begin_authorized_pep_owner_mutation(owner, BOOKMARKS2)
                .await?
            else {
                return Ok(PepBookmarkMutationOutcome::Forbidden);
            };
            db::private::lock_private_xml_owner(&mut transaction, owner.id).await?;
            let previous_items = sqlx::query(
                "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2
              ORDER BY item_id
              FOR UPDATE",
            )
            .bind(owner.id)
            .bind(BOOKMARKS2)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| Ok::<_, sqlx::Error>((row.try_get("item_id")?, row.try_get("payload")?)))
            .collect::<std::result::Result<Vec<(String, String)>, _>>()?;
            if previous_items != expected_previous_items {
                transaction.rollback().await?;
                return Ok(PepBookmarkMutationOutcome::ConcurrentChange);
            }
            let borrowed = items
                .iter()
                .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
                .collect::<Vec<_>>();
            let config = db::default_pep_node_config(BOOKMARKS2);
            let pep_outcome = db::pep::replace_pep_items_in_transaction(
                &mut transaction,
                owner.id,
                BOOKMARKS2,
                &config,
                &borrowed,
                quotas.into(),
            )
            .await?;
            if pep_outcome != db::PepPublishOutcome::Published {
                transaction.rollback().await?;
                return Ok(PepBookmarkMutationOutcome::ResourceConstraint);
            }
            let private_outcome = db::private::set_private_xml_batch_in_transaction(
                &mut transaction,
                owner.id,
                &[db::PrivateXmlEntry {
                    element_name: "storage",
                    element_ns: LEGACY_BOOKMARKS,
                    xml_data: private_xml,
                }],
                max_private_bytes,
            )
            .await?;
            if private_outcome != db::PrivateXmlWriteOutcome::Stored {
                transaction.rollback().await?;
                return Ok(PepBookmarkMutationOutcome::ResourceConstraint);
            }
            let replacement_factory = PepBookmarkReplacementOutbox {
                factory,
                current: items
                    .iter()
                    .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
                    .collect(),
                previous: previous_items
                    .iter()
                    .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
                    .collect(),
            };
            let outbox = self
                .exact_pep_outbox(
                    &mut transaction,
                    owner.id,
                    &owner.username,
                    Some(sender_connection_id),
                    BOOKMARKS2,
                    PepOutboxEventKind::Publish,
                    PepOutboxAuthorizationMode::CausalAudience,
                    &replacement_factory,
                    None,
                )
                .await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepBookmarkMutationOutcome::Stored)
        }
        .await;
        outcome.map(Into::into).map_err(map_database_busy)
    }
    async fn publish_pep_items(
        &self,
        command: PepPublishItemsCommand<'_>,
        factory: &dyn PepOutboxFactory,
    ) -> Result<PepPublishItemsResult> {
        let outcome: Result<_> = async {
            let write = command.write;

            let mut transaction = self.begin_mutation().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 2))")
                .bind(write.user_id.to_string())
                .execute(&mut *transaction)
                .await?;
            let owner_username = sqlx::query_scalar::<_, String>(
                "SELECT username FROM users
              WHERE id=$1 AND username=$2 AND auth_generation=$3 AND NOT is_disabled
              FOR SHARE",
            )
            .bind(write.user_id)
            .bind(write.username)
            .bind(write.auth_generation)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(owner_username) = owner_username else {
                transaction.rollback().await?;
                return Ok(PepPublishItemsResult {
                    outcome: PepPublishItemsOutcome::Unauthorized,
                    content_changed: false,
                });
            };
            lock_pep_audience(&mut transaction, write.user_id, write.node).await?;

            let item_ids = write
                .items
                .iter()
                .map(|(item_id, _)| *item_id)
                .collect::<Vec<_>>();
            let previous = sqlx::query(
                "SELECT item_id,payload FROM pep_items
              WHERE owner_id=$1 AND node=$2 AND item_id=ANY($3)
              FOR UPDATE",
            )
            .bind(write.user_id)
            .bind(write.node)
            .bind(&item_ids)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| {
                Ok::<_, sqlx::Error>((
                    row.try_get::<String, _>("item_id")?,
                    row.try_get::<String, _>("payload")?,
                ))
            })
            .collect::<std::result::Result<HashMap<_, _>, _>>()?;
            let changed = previous.len() != write.items.len()
                || write.items.iter().any(|(item_id, payload)| {
                    previous.get(*item_id).map(String::as_str) != Some(*payload)
                });
            let changed_items = if write.node == BOOKMARKS2 {
                write
                    .items
                    .iter()
                    .copied()
                    .filter(|(item_id, payload)| {
                        previous.get(*item_id).map(String::as_str) != Some(*payload)
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let requested = db::PepNodeConfig::from(write.requested);
            let outcome = db::pep::publish_pep_items_in_transaction(
                &mut transaction,
                write.user_id,
                write.node,
                &requested,
                write.enforce_preconditions,
                write.items,
                write.quotas.into(),
            )
            .await?;
            if outcome != db::PepPublishOutcome::Published {
                transaction.rollback().await?;
                return Ok(PepPublishItemsResult {
                    outcome: PepPublishItemsOutcome::from(PepPublishOutcome::from(outcome)),
                    content_changed: false,
                });
            }
            if changed || !command.require_content_change {
                let outbox = self
                    .exact_pep_outbox(
                        &mut transaction,
                        write.user_id,
                        &owner_username,
                        Some(write.connection_id),
                        write.node,
                        PepOutboxEventKind::Publish,
                        PepOutboxAuthorizationMode::CausalAudience,
                        factory,
                        (write.node == BOOKMARKS2).then_some(changed_items.as_slice()),
                    )
                    .await?;
                db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            }
            transaction.commit().await?;
            Ok(PepPublishItemsResult {
                outcome: PepPublishItemsOutcome::Published,
                content_changed: changed,
            })
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepSubscriptionQueryRepository for PostgresPubSubRepository {
    async fn pep_subscribers(&self, owner_id: Uuid, node: &str) -> Result<Vec<PepSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::pep_subscribers(&self.pool, owner_id, node)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_subscriptions_for_available_resource(
        &self,
        subscriber_jid: &str,
    ) -> Result<Vec<PepPresenceSubscription>> {
        let outcome: Result<_> = async {
            Ok(
                db::pep_subscriptions_for_available_resource(&self.pool, subscriber_jid)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn pep_owner_usernames_for_presence_subscriber(
        &self,
        subscriber_bare: &str,
    ) -> Result<Vec<String>> {
        let outcome: Result<_> = async {
            db::pep_owner_usernames_for_presence_subscriber(&self.pool, subscriber_bare).await
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepSubscriptionMutationRepository for PostgresPubSubRepository {
    async fn subscribe_pep_node(
        &self,
        command: PepSubscribeCommand<'_>,
        factory: &dyn PepSubscribeOutboxFactory,
    ) -> Result<PepSubscribeResult> {
        let outcome: Result<_> = async {
        let write = command.write;

        let mut transaction = self.begin_mutation().await?;
        let Some(principal) = self
            .lock_pep_subscription_principal(
                &mut transaction,
                write.owner,
                &write.actor,
                write.subscriber_jid,
            )
            .await?
        else {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::Forbidden));
        };

        // Per-bare-JID quota first, then per-node serialization. All callers
        // use this order, so concurrent subscriptions cannot deadlock by
        // choosing different nodes for the same subscriber.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4))")
            .bind(&principal.subscriber_bare)
            .execute(&mut *transaction)
            .await?;
        lock_pep_audience(&mut transaction, write.owner.id, write.node).await?;

        let policy = sqlx::query(
            "SELECT access_model,send_last_published_item,deliver_notifications,
                    roster_groups_allowed,access_whitelist
               FROM pep_nodes
              WHERE owner_id=$1 AND node=$2
              FOR SHARE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(policy) = policy else {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::NotFound));
        };

        let mut block_owners = vec![write.owner.id];
        if let Some(subscriber_id) = principal.local_subscriber_id {
            block_owners.push(subscriber_id);
        }
        block_owners.sort_unstable();
        block_owners.dedup();
        for block_owner in &block_owners {
            lock_pep_block_policy(&mut transaction, *block_owner).await?;
        }
        let block_rows = sqlx::query(
            "SELECT owner_id,blocked_jid FROM blocked_jids
              WHERE owner_id=ANY($1)
              ORDER BY owner_id,blocked_jid
              FOR SHARE",
        )
        .bind(&block_owners)
        .fetch_all(&mut *transaction)
        .await?;
        let mut blocks: HashMap<Uuid, Vec<String>> = HashMap::new();
        for row in block_rows {
            blocks
                .entry(row.try_get("owner_id")?)
                .or_default()
                .push(row.try_get("blocked_jid")?);
        }

        let owner_blocks_subscriber = blocks.get(&write.owner.id).is_some_and(|patterns| {
            patterns
                .iter()
                .any(|pattern| db::roster::blocked_jid_matches(pattern, &principal.subscriber_jid))
        });
        let subscriber_blocks_owner = principal.local_subscriber_id.is_some_and(|subscriber_id| {
            blocks.get(&subscriber_id).is_some_and(|patterns| {
                patterns
                    .iter()
                    .any(|pattern| db::roster::blocked_jid_matches(pattern, &principal.owner_bare))
            })
        });

        let roster = sqlx::query("SELECT subscription,groups FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR SHARE")
            .bind(write.owner.id)
            .bind(&principal.subscriber_bare)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<PepRosterAudienceEntry, anyhow::Error>(PepRosterAudienceEntry {
                    subscription: row.try_get("subscription")?,
                    groups: serde_json::from_value(row.try_get("groups")?)
                        .context("stored PEP roster groups are not a string array")?,
                })
            })
            .transpose()?;
        let access_model: String = policy.try_get("access_model")?;
        let authorized = if principal.subscriber_bare == principal.owner_bare {
            true
        } else if owner_blocks_subscriber || subscriber_blocks_owner {
            false
        } else {
            match access_model.as_str() {
                "open" => true,
                "whitelist" => {
                    let whitelist: Vec<String> = policy.try_get("access_whitelist")?;
                    whitelist.iter().any(|jid| {
                        crate::jid::canonical_bare_key(jid)
                            .is_ok_and(|jid| jid == principal.subscriber_bare)
                    })
                }
                "presence" => roster
                    .as_ref()
                    .is_some_and(|entry| matches!(entry.subscription.as_str(), "from" | "both")),
                "roster" => {
                    let allowed: Vec<String> = policy.try_get("roster_groups_allowed")?;
                    roster.as_ref().is_some_and(|entry| {
                        entry.groups.iter().any(|group| allowed.contains(group))
                    })
                }
                _ => false,
            }
        };
        if !authorized {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(
                PepSubscribeOutcome::NotAuthorized(access_model),
            ));
        }

        let existing = sqlx::query_scalar::<_, String>(
            "SELECT subid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
              FOR UPDATE",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(subid) = existing {
            transaction.commit().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::Subscribed(
                PepSubscription {
                    jid: principal.subscriber_jid,
                    subid,
                },
            )));
        }

        let subscriber_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pep_subscriptions
              WHERE split_part(subscriber_jid, '/', 1)=$1",
        )
        .bind(&principal.subscriber_bare)
        .fetch_one(&mut *transaction)
        .await?;
        let node_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pep_subscriptions WHERE owner_id=$1 AND node=$2",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .fetch_one(&mut *transaction)
        .await?;
        if write.max_subscriptions <= 0
            || subscriber_count >= write.max_subscriptions
            || node_count >= db::PEP_MAX_SUBSCRIBERS_PER_NODE
        {
            transaction.rollback().await?;
            return Ok(PepSubscribeResult::from(PepSubscribeOutcome::LimitExceeded));
        }

        let last_item = if policy.try_get::<bool, _>("deliver_notifications")?
            && policy.try_get::<String, _>("send_last_published_item")? != "never"
        {
            sqlx::query(
                "SELECT item_id,payload,updated_at FROM pep_items
                  WHERE owner_id=$1 AND node=$2
                  ORDER BY updated_at DESC,item_id DESC LIMIT 1
                  FOR SHARE",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| {
                Ok::<PepItem, sqlx::Error>(PepItem {
                    item_id: row.try_get("item_id")?,
                    payload: row.try_get("payload")?,
                    updated_at: row.try_get("updated_at")?,
                })
            })
            .transpose()?
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid)
             VALUES($1,$2,$3,$4)",
        )
        .bind(write.owner.id)
        .bind(write.node)
        .bind(&principal.subscriber_jid)
        .bind(write.requested_subid)
        .execute(&mut *transaction)
        .await?;
        let snapshot = PepSubscribeSnapshot {
            owner_id: write.owner.id,
            owner_bare_jid: principal.owner_bare,
            node: write.node.to_owned(),
            subscriber_jid: principal.subscriber_jid.clone(),
            subscriber_account_id: principal.local_subscriber_id,
            local_domain: self.domain.clone(),
            last_item,
        };
        let outbox = db_outbox(&factory.build(&snapshot)?);
        anyhow::ensure!(
            outbox.iter().all(|entry| {
                entry.source == db::PubSubOutboxSource::Pep
                    && entry.delivery_kind == db::PubSubOutboxDeliveryKind::PepStanza
                    && entry.source_node == write.node
                    && entry.recipient_jid == principal.subscriber_jid
            }),
            "PEP subscription renderer escaped the transaction-owned recipient"
        );
        db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
        transaction.commit().await?;
        Ok(PepSubscribeResult::from(PepSubscribeOutcome::Subscribed(
            PepSubscription {
                jid: principal.subscriber_jid,
                subid: write.requested_subid.to_owned(),
            },
        )))
    }.await;
        outcome.map_err(map_database_busy)
    }
    async fn unsubscribe_pep_node(
        &self,
        command: PepUnsubscribeCommand<'_>,
    ) -> Result<PepUnsubscribeResult> {
        let outcome: Result<_> = async {
            let write = command.write;

            let mut transaction = self.begin_mutation().await?;
            let Some(principal) = self
                .lock_pep_subscription_principal(
                    &mut transaction,
                    write.owner,
                    &write.actor,
                    write.subscriber_jid,
                )
                .await?
            else {
                transaction.rollback().await?;
                return Ok(PepUnsubscribeResult::from(PepUnsubscribeOutcome::Forbidden));
            };
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 4))")
                .bind(&principal.subscriber_bare)
                .execute(&mut *transaction)
                .await?;
            lock_pep_audience(&mut transaction, write.owner.id, write.node).await?;
            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT TRUE FROM pep_nodes WHERE owner_id=$1 AND node=$2 FOR SHARE",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .fetch_optional(&mut *transaction)
            .await?;
            if exists.is_none() {
                transaction.rollback().await?;
                return Ok(PepUnsubscribeResult::from(PepUnsubscribeOutcome::NotFound));
            }
            let existing = sqlx::query_scalar::<_, String>(
                "SELECT subid FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
              FOR UPDATE",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .bind(&principal.subscriber_jid)
            .fetch_optional(&mut *transaction)
            .await?;
            let Some(existing) = existing else {
                transaction.commit().await?;
                return Ok(PepUnsubscribeResult::from(
                    PepUnsubscribeOutcome::Unsubscribed(None),
                ));
            };
            if write.subid.is_some_and(|subid| subid != existing.as_str()) {
                transaction.rollback().await?;
                return Ok(PepUnsubscribeResult::from(
                    PepUnsubscribeOutcome::InvalidSubid,
                ));
            }
            sqlx::query(
                "DELETE FROM pep_subscriptions
              WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND subid=$4",
            )
            .bind(write.owner.id)
            .bind(write.node)
            .bind(&principal.subscriber_jid)
            .bind(&existing)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(PepUnsubscribeResult::from(
                PepUnsubscribeOutcome::Unsubscribed(Some(existing)),
            ))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn unsubscribe_pep_nodes_batch(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        changes: &[(String, Option<String>)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, owner_bare_jid)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            if Self::locked_pep_node_config(&mut transaction, owner.id, node)
                .await?
                .is_none()
            {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            }
            let mut canonical = Vec::with_capacity(changes.len());
            let mut unique = HashSet::new();
            for (jid, requested_subid) in changes {
                let jid = crate::jid::canonicalize(jid)?;
                if !unique.insert((jid.clone(), requested_subid.clone())) {
                    transaction.rollback().await?;
                    return Ok(PepOwnerMutationOutcome::NotSubscribed);
                }
                let stored = sqlx::query_scalar::<_, String>(
                    "SELECT subid FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3
                  FOR UPDATE",
                )
                .bind(owner.id)
                .bind(node)
                .bind(&jid)
                .fetch_optional(&mut *transaction)
                .await?;
                let Some(stored) = stored.filter(|stored| {
                    requested_subid
                        .as_ref()
                        .is_none_or(|requested| requested == stored)
                }) else {
                    transaction.rollback().await?;
                    return Ok(PepOwnerMutationOutcome::NotSubscribed);
                };
                canonical.push((jid, stored));
            }
            if canonical.is_empty() {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotSubscribed);
            }
            let snapshot = PepDirectStateSnapshot {
                owner_bare_jid,
                node: node.to_owned(),
                transitions: canonical
                    .iter()
                    .map(
                        |(recipient_jid, subid)| PepDirectStateTransition::Subscription {
                            recipient_jid: recipient_jid.clone(),
                            subid: subid.clone(),
                            state: "none".to_owned(),
                        },
                    )
                    .collect(),
            };
            let outbox = self
                .direct_pep_outbox(
                    &mut transaction,
                    owner.id,
                    Some(sender_connection_id),
                    PepOutboxEventKind::SubscriptionState,
                    &snapshot,
                    factory,
                )
                .await?;
            for (jid, subid) in &canonical {
                sqlx::query(
                    "DELETE FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3 AND subid=$4",
                )
                .bind(owner.id)
                .bind(node)
                .bind(jid)
                .bind(subid)
                .execute(&mut *transaction)
                .await?;
            }
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(u64::try_from(
                canonical.len(),
            )?))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PepAffiliationRepository for PostgresPubSubRepository {
    async fn update_pep_affiliations(
        &self,
        owner: &PubSubAccount,
        sender_connection_id: Uuid,
        node: &str,
        expected: &PepNodeConfig,
        changes: &[(String, String)],
        factory: &dyn PepDirectOutboxFactory,
    ) -> Result<PepOwnerMutationOutcome> {
        let outcome: Result<_> = async {
            let Some((mut transaction, owner_bare_jid)) = self
                .begin_authorized_pep_owner_mutation(owner, node)
                .await?
            else {
                return Ok(PepOwnerMutationOutcome::Forbidden);
            };
            let Some(mut current) =
                Self::locked_pep_node_config(&mut transaction, owner.id, node).await?
            else {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::NotFound);
            };
            if &current != expected {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::Stale);
            }
            let mut whitelist = current
                .access_whitelist
                .iter()
                .cloned()
                .collect::<HashSet<_>>();
            let mut transitions = Vec::with_capacity(changes.len());
            let mut seen = HashSet::new();
            for (jid, affiliation) in changes {
                let jid = crate::jid::canonicalize_bare(jid)?;
                if jid == owner_bare_jid
                    || !matches!(affiliation.as_str(), "member" | "none")
                    || !seen.insert(jid.clone())
                {
                    transaction.rollback().await?;
                    return Ok(PepOwnerMutationOutcome::Forbidden);
                }
                if affiliation == "member" {
                    whitelist.insert(jid.clone());
                } else {
                    whitelist.remove(&jid);
                }
                transitions.push(PepDirectStateTransition::Affiliation {
                    recipient_jid: jid,
                    affiliation: affiliation.clone(),
                });
            }
            if transitions.is_empty() || whitelist.len() > 10_000 {
                transaction.rollback().await?;
                return Ok(PepOwnerMutationOutcome::Forbidden);
            }
            current.access_whitelist = whitelist.into_iter().collect();
            current.access_whitelist.sort_unstable();
            let snapshot = PepDirectStateSnapshot {
                owner_bare_jid,
                node: node.to_owned(),
                transitions,
            };
            let outbox = self
                .direct_pep_outbox(
                    &mut transaction,
                    owner.id,
                    Some(sender_connection_id),
                    PepOutboxEventKind::AffiliationState,
                    &snapshot,
                    factory,
                )
                .await?;
            Self::store_pep_node_config(&mut transaction, owner.id, node, &current).await?;
            db::enqueue_pubsub_outbox_in_transaction(&mut transaction, &outbox).await?;
            transaction.commit().await?;
            Ok(PepOwnerMutationOutcome::Applied(0))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
