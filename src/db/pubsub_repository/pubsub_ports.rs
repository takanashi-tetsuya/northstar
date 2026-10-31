//! PostgreSQL implementations of the PubSub node, item, subscription and affiliation repository ports.

use super::*;

impl PubSubNodeMutationRepository for PostgresPubSubRepository {
    async fn delete_node_as_owner_with_redirect_and_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
        redirect: Option<&str>,
    ) -> Result<OwnerMutationOutcome> {
        let outcome: Result<_> = async {
            Ok(db::delete_node_as_owner_with_redirect_and_outbox(
                &self.pool,
                node_id,
                requester,
                redirect,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }

    async fn update_node_config_and_graph_with_outbox(
        &self,
        node: &PubSubNode,
        requester: &str,
        expected: &PubSubNodeConfig,
        config: &PubSubNodeConfig,
    ) -> Result<PubSubConfigOutcome> {
        let outcome: Result<_> = async {
            Ok(db::update_node_config_and_graph_with_outbox(
                &self.pool,
                node,
                requester,
                expected,
                config,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }

    async fn create_node(
        &self,
        node: &str,
        creator_jid: &str,
        config: &PubSubNodeConfig,
        max_nodes_per_owner: i64,
    ) -> Result<CreateNodeOutcome> {
        let outcome: Result<_> = async {
            Ok(db::create_node_with_renderer(
                &self.pool,
                node,
                creator_jid,
                config,
                max_nodes_per_owner,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn associate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let outcome: Result<_> = async {
            Ok(db::associate_collection_child_with_renderer(
                &self.pool,
                collection,
                child,
                requester,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn dissociate_collection_child(
        &self,
        collection: &PubSubNode,
        child: &PubSubNode,
        requester: &str,
    ) -> Result<CollectionUpdateOutcome> {
        let outcome: Result<_> = async {
            Ok(db::dissociate_collection_child_with_renderer(
                &self.pool,
                collection,
                child,
                requester,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubNodeQueryRepository for PostgresPubSubRepository {
    async fn owner_read(
        &self,
        node: &str,
        requester: &str,
        kind: PubSubOwnerReadKind,
    ) -> Result<PubSubOwnerRead> {
        northstar_pubsub_postgres::owner_read(&self.pool, node, requester, kind)
            .await
            .map_err(map_database_busy)
    }

    async fn get_node(&self, node: &str) -> Result<Option<PubSubNode>> {
        db::get_node(&self.pool, node)
            .await
            .map_err(map_database_busy)
    }
    async fn node_redirect(&self, node: &str) -> Result<Option<String>> {
        let outcome: Result<_> = async { db::node_redirect(&self.pool, node).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn collection_parents(&self, child_id: Uuid) -> Result<Vec<PubSubNode>> {
        db::collection_parents(&self.pool, child_id)
            .await
            .map_err(map_database_busy)
    }
    async fn collection_children(&self, collection_id: Uuid) -> Result<Vec<PubSubNode>> {
        db::collection_children(&self.pool, collection_id)
            .await
            .map_err(map_database_busy)
    }
    async fn is_owner(&self, node_id: Uuid, requester: &str) -> Result<bool> {
        let outcome: Result<_> = async {
            Ok(db::get_node_affiliation(&self.pool, node_id, requester)
                .await?
                .as_deref()
                == Some("owner"))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn node_metadata(&self, node_id: Uuid) -> Result<PubSubNodeMetadata> {
        db::node_metadata(&self.pool, node_id)
            .await
            .map_err(map_database_busy)
    }
}
impl PubSubRootDiscoveryQueryRepository for PostgresPubSubRepository {
    async fn root_disco_page(
        &self,
        requester: &str,
        cursor: Option<&str>,
        backwards: bool,
        limit: i64,
    ) -> Result<PubSubRootDiscoPage> {
        db::root_disco_page(&self.pool, requester, cursor, backwards, limit)
            .await
            .map_err(map_database_busy)
    }
}
impl PubSubItemQueryRepository for PostgresPubSubRepository {
    async fn leaf_disco_snapshot(
        &self,
        node: &str,
        requester: &str,
    ) -> Result<Option<PubSubLeafDiscoSnapshot>> {
        let snapshot = db::leaf_disco_snapshot(&self.pool, node, requester)
            .await
            .map_err(map_database_busy)?;
        Ok(snapshot.map(|snapshot| PubSubLeafDiscoSnapshot {
            node_type: snapshot.node_type,
            access_model: snapshot.access_model,
            affiliation: snapshot.affiliation,
            subscribed: snapshot.subscribed,
            item_ids: snapshot.item_ids,
        }))
    }
    async fn collection_disco_snapshot(
        &self,
        node: &str,
        requester: &str,
    ) -> Result<Option<PubSubCollectionDiscoSnapshot>> {
        let snapshot = db::collection_disco_snapshot(&self.pool, node, requester)
            .await
            .map_err(map_database_busy)?;
        Ok(snapshot.map(|snapshot| PubSubCollectionDiscoSnapshot {
            node_type: snapshot.node_type,
            access_model: snapshot.access_model,
            affiliation: snapshot.affiliation,
            subscribed: snapshot.subscribed,
            children: snapshot
                .children
                .into_iter()
                .map(|child| PubSubCollectionDiscoChild {
                    node: child.node,
                    title: child.title,
                })
                .collect(),
        }))
    }
    async fn get_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        limit: i64,
    ) -> Result<Vec<PubSubItem>> {
        let outcome: Result<_> = async {
            Ok(db::get_items(&self.pool, node_id, item_ids, limit)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn collection_visible_items(
        &self,
        collection_id: Uuid,
        requester: &str,
        global_item_limit: i64,
        xml_byte_limit: i64,
    ) -> Result<Vec<CollectionVisibleItem>> {
        let outcome: Result<_> = async {
            Ok(db::collection_visible_items(
                &self.pool,
                collection_id,
                requester,
                global_item_limit,
                xml_byte_limit,
            )
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn can_publish(&self, node: &PubSubNode, requester: &str) -> Result<bool> {
        let outcome: Result<_> = async {
            let (affiliation, subscribed) =
                db::node_authorization_facts(&self.pool, node.id, requester).await?;
            let affiliation = affiliation
                .as_deref()
                .map(str::parse::<northstar_xep_0060::Affiliation>)
                .transpose()
                .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
            let publish_model = node
                .publish_model
                .parse::<northstar_xep_0060::PublishModel>()
                .map_err(|error| anyhow::anyhow!("invalid stored PubSub publish model: {error}"))?;
            let access_model = node
                .access_model
                .parse::<northstar_xep_0060::AccessModel>()
                .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
            Ok(northstar_xep_0060::can_publish_pure(
                publish_model,
                access_model,
                affiliation,
                subscribed,
            ))
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubItemMutationRepository for PostgresPubSubRepository {
    async fn purge_node_as_owner_with_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
    ) -> Result<OwnerMutationOutcome> {
        let outcome: Result<_> = async {
            Ok(
                db::purge_node_as_owner_with_outbox(&self.pool, node_id, requester, &self.renderer)
                    .await?
                    .into(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn publish_items(
        &self,
        node: &PubSubNode,
        publisher_jid: &str,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> Result<PublishItemsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::publish_items_with_renderer(
                &self.pool,
                node,
                publisher_jid,
                items,
                false,
                max_storage_bytes_per_owner,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn retract_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        publisher_jid: &str,
        force_notification: bool,
    ) -> Result<RetractItemsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::retract_items_with_renderer(
                &self.pool,
                node_id,
                item_ids,
                publisher_jid,
                force_notification,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubSubscriptionQueryRepository for PostgresPubSubRepository {
    async fn is_subscribed(&self, node_id: Uuid, jid: &str) -> Result<bool> {
        let outcome: Result<_> = async { db::is_subscribed(&self.pool, node_id, jid).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn subscriptions_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(db::subscriptions_for_jid(&self.pool, jid, node)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn subscriptions_addressing_jid_page(
        &self,
        jid: &str,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> Result<Vec<PubSubSubscription>> {
        let outcome: Result<_> = async {
            Ok(
                db::subscriptions_addressing_jid_page(&self.pool, jid, after, limit)
                    .await?
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            )
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn get_subscription(
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
}
impl PubSubSubscriptionMutationRepository for PostgresPubSubRepository {
    fn local_domain(&self) -> &str {
        &self.domain
    }

    async fn update_subscription_options_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: Option<&str>,
        options: &PubSubSubscriptionOptions,
    ) -> Result<SubscriptionOptionsOutcome> {
        let outcome: Result<_> = async {
            let options = db::PubSubSubscriptionOptions::from(options);
            Ok(db::update_subscription_options_checked(
                &self.pool,
                &self.domain,
                node_id,
                requester,
                subscriber_jid,
                expected_subid,
                &options,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    #[allow(clippy::too_many_arguments)]
    async fn set_subscription_limited_with_options(
        &self,
        node_id: Uuid,
        requester: &str,
        jid: &str,
        state: &str,
        expected_node_type: &str,
        expected_access_model: &str,
        max_subscriptions: i64,
        options: Option<&PubSubSubscriptionOptions>,
        requested_subid: &str,
    ) -> Result<SubscribeOutcome> {
        let outcome: Result<_> = async {
            let options = options.map(db::PubSubSubscriptionOptions::from);
            Ok(db::set_subscription_limited_with_options_and_renderer(
                &self.pool,
                &self.domain,
                node_id,
                requester,
                jid,
                state,
                expected_node_type,
                expected_access_model,
                max_subscriptions,
                options.as_ref(),
                requested_subid,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn unsubscribe_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
    ) -> Result<UnsubscribeOutcome> {
        let outcome: Result<_> = async {
            Ok(db::unsubscribe_checked_with_renderer(
                &self.pool,
                node_id,
                requester,
                subscriber_jid,
                expected_subid,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn set_subscriptions(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String, Option<String>)],
    ) -> Result<SetSubscriptionsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::set_subscriptions_with_renderer(
                &self.pool,
                node_id,
                requester,
                changes,
                None,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
    async fn resolve_pending_subscription(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
        allow: bool,
    ) -> Result<SubscriptionAuthorizationOutcome> {
        let outcome: Result<_> = async {
            Ok(db::resolve_pending_subscription_with_renderer(
                &self.pool,
                node_id,
                requester,
                subscriber_jid,
                expected_subid,
                allow,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubAffiliationQueryRepository for PostgresPubSubRepository {
    async fn retrieval_authorization_facts(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<(Option<String>, bool)> {
        db::node_authorization_facts(&self.pool, node_id, jid)
            .await
            .map_err(map_database_busy)
    }

    async fn get_node_affiliation(&self, node_id: Uuid, jid: &str) -> Result<Option<String>> {
        let outcome: Result<_> =
            async { db::get_node_affiliation(&self.pool, node_id, jid).await }.await;
        outcome.map_err(map_database_busy)
    }
    async fn affiliations_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubAffiliation>> {
        let outcome: Result<_> = async {
            Ok(db::affiliations_for_jid(&self.pool, jid, node)
                .await?
                .into_iter()
                .map(Into::into)
                .collect())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
impl PubSubAffiliationMutationRepository for PostgresPubSubRepository {
    async fn set_affiliations(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String)],
    ) -> Result<SetAffiliationsOutcome> {
        let outcome: Result<_> = async {
            Ok(db::set_affiliations_with_renderer(
                &self.pool,
                node_id,
                requester,
                changes,
                None,
                None,
                &self.renderer,
            )
            .await?
            .into())
        }
        .await;
        outcome.map_err(map_database_busy)
    }
}
