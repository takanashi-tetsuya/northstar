//! Repository-facing PEP and PubSub queries, authorization snapshots, and admitted aggregate mutation adapters.

use super::*;

impl<R: PepNodeQueryRepository> PubSubService<R> {
    pub(crate) async fn pep_node(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        self.repository.pep_node(owner_id, node).await
    }
}

impl<R: PepItemQueryRepository> PubSubService<R> {
    pub(crate) async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        self.repository
            .pep_items(owner_id, node, item_id, limit)
            .await
    }
    pub(crate) async fn pep_items_by_ids(
        &self,
        owner_id: Uuid,
        node: &str,
        item_ids: &[&str],
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        self.repository
            .pep_items_by_ids(owner_id, node, item_ids, limit)
            .await
    }
    pub(crate) async fn pep_items_with_timestamp(
        &self,
        owner_id: Uuid,
        node: &str,
        limit: i64,
    ) -> Result<Vec<PepItem>> {
        self.repository
            .pep_items_with_timestamp(owner_id, node, limit)
            .await
    }
}

impl<R: PepNodeQueryRepository> PubSubService<R> {
    pub(crate) async fn pep_nodes(&self, owner_id: Uuid) -> Result<Vec<String>> {
        self.repository.pep_nodes(owner_id).await
    }
}

impl<R: PepSubscriptionQueryRepository> PubSubService<R> {
    pub(crate) async fn pep_subscribers(
        &self,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Vec<PepSubscription>> {
        self.repository.pep_subscribers(owner_id, node).await
    }
    pub(crate) async fn pep_subscriptions_for_available_resource(
        &self,
        subscriber_jid: &str,
    ) -> Result<Vec<PepPresenceSubscription>> {
        self.repository
            .pep_subscriptions_for_available_resource(subscriber_jid)
            .await
    }
    pub(crate) async fn pep_owner_usernames_for_presence_subscriber(
        &self,
        subscriber_bare: &str,
    ) -> Result<Vec<String>> {
        self.repository
            .pep_owner_usernames_for_presence_subscriber(subscriber_bare)
            .await
    }
}

impl<R: PepNodeQueryRepository> PubSubService<R> {
    pub(crate) async fn find_enabled_user(&self, username: &str) -> Result<Option<PubSubAccount>> {
        self.repository.find_enabled_user(username).await
    }
    pub(crate) async fn roster(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<(String, Option<String>, String, Option<String>)>> {
        self.repository.roster(owner_id).await
    }
    pub(crate) async fn roster_item(
        &self,
        owner_id: Uuid,
        jid: &str,
    ) -> Result<Option<(String, Option<String>, String, Option<String>)>> {
        self.repository.roster_item(owner_id, jid).await
    }
    pub(crate) async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        self.repository.is_blocked(owner_id, candidate).await
    }
    pub(crate) async fn roster_group_allowed(
        &self,
        owner_id: Uuid,
        jid: &str,
        groups: &[String],
    ) -> Result<bool> {
        self.repository
            .roster_group_allowed(owner_id, jid, groups)
            .await
    }
}

impl<
        R: PubSubNodeMutationRepository
            + PubSubItemMutationRepository
            + PubSubSubscriptionMutationRepository
            + PubSubAffiliationMutationRepository,
    > PubSubService<R>
{
    pub(crate) async fn create_node(
        &self,
        node: &str,
        creator_jid: &str,
        config: &PubSubNodeConfig,
        max_nodes_per_owner: i64,
    ) -> Result<CreateNodeOutcome> {
        let _permit = self.admit_mutation(&[creator_jid, node], true).await?;
        self.repository
            .create_node(node, creator_jid, config, max_nodes_per_owner)
            .await
    }
    pub(crate) async fn publish_items(
        &self,
        node: &PubSubNode,
        publisher_jid: &str,
        items: &[(String, String)],
        max_storage_bytes_per_owner: i64,
    ) -> Result<PublishItemsOutcome> {
        let node_key = node.id.to_string();
        let _permit = self
            .admit_mutation(&[publisher_jid, &node_key], true)
            .await?;
        self.repository
            .publish_items(node, publisher_jid, items, max_storage_bytes_per_owner)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn set_subscription_limited_with_options(
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
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, jid, &node_key], false)
            .await?;
        self.repository
            .set_subscription_limited_with_options(
                node_id,
                requester,
                jid,
                state,
                expected_node_type,
                expected_access_model,
                max_subscriptions,
                options,
                requested_subid,
            )
            .await
    }
    pub(crate) async fn unsubscribe_checked(
        &self,
        node_id: Uuid,
        requester: &str,
        subscriber_jid: &str,
        expected_subid: &str,
    ) -> Result<UnsubscribeOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[requester, subscriber_jid, &node_key], false)
            .await?;
        self.repository
            .unsubscribe_checked(node_id, requester, subscriber_jid, expected_subid)
            .await
    }
    pub(crate) async fn retract_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        publisher_jid: &str,
        force_notification: bool,
    ) -> Result<RetractItemsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self
            .admit_mutation(&[publisher_jid, &node_key], true)
            .await?;
        self.repository
            .retract_items(node_id, item_ids, publisher_jid, force_notification)
            .await
    }
    pub(crate) async fn update_node_config_and_graph_with_outbox(
        &self,
        node: &PubSubNode,
        requester: &str,
        expected: &PubSubNodeConfig,
        config: &PubSubNodeConfig,
    ) -> Result<PubSubConfigOutcome> {
        let node_key = node.id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        self.repository
            .update_node_config_and_graph_with_outbox(node, requester, expected, config)
            .await
    }
    pub(crate) async fn set_subscriptions(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String, Option<String>)],
    ) -> Result<SetSubscriptionsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], false).await?;
        self.repository
            .set_subscriptions(node_id, requester, changes)
            .await
    }
    pub(crate) async fn set_affiliations(
        &self,
        node_id: Uuid,
        requester: &str,
        changes: &[(String, String)],
    ) -> Result<SetAffiliationsOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], false).await?;
        self.repository
            .set_affiliations(node_id, requester, changes)
            .await
    }
    pub(crate) async fn purge_node_as_owner_with_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
    ) -> Result<OwnerMutationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        self.repository
            .purge_node_as_owner_with_outbox(node_id, requester)
            .await
    }
    pub(crate) async fn delete_node_as_owner_with_redirect_and_outbox(
        &self,
        node_id: Uuid,
        requester: &str,
        redirect: Option<&str>,
    ) -> Result<OwnerMutationOutcome> {
        let node_key = node_id.to_string();
        let _permit = self.admit_mutation(&[requester, &node_key], true).await?;
        self.repository
            .delete_node_as_owner_with_redirect_and_outbox(node_id, requester, redirect)
            .await
    }
}

impl<R: PubSubNodeQueryRepository> PubSubService<R> {
    pub(crate) async fn owner_read(
        &self,
        node: &str,
        requester: &str,
        kind: PubSubOwnerReadKind,
    ) -> Result<PubSubOwnerRead> {
        self.repository.owner_read(node, requester, kind).await
    }

    pub(crate) async fn get_node(&self, node: &str) -> Result<Option<PubSubNode>> {
        self.repository.get_node(node).await
    }

    pub(crate) async fn node_redirect(&self, node: &str) -> Result<Option<String>> {
        self.repository.node_redirect(node).await
    }

    pub(crate) async fn collection_parents(&self, child_id: Uuid) -> Result<Vec<PubSubNode>> {
        self.repository.collection_parents(child_id).await
    }

    pub(crate) async fn collection_children(&self, collection_id: Uuid) -> Result<Vec<PubSubNode>> {
        self.repository.collection_children(collection_id).await
    }

    pub(crate) async fn is_owner(&self, node_id: Uuid, requester: &str) -> Result<bool> {
        self.repository.is_owner(node_id, requester).await
    }

    pub(crate) async fn node_metadata(&self, node_id: Uuid) -> Result<PubSubNodeMetadata> {
        self.repository.node_metadata(node_id).await
    }
}

impl<R: PubSubRootDiscoveryQueryRepository> PubSubService<R> {
    pub(crate) async fn discover_roots(
        &self,
        query: PubSubRootDiscoQuery<'_>,
    ) -> Result<Option<PubSubRootDiscoResult>> {
        northstar_pubsub_application::discover_roots(&self.repository, query).await
    }
}

impl<R: PubSubAffiliationQueryRepository> PubSubService<R> {
    pub(crate) async fn get_node_affiliation(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<String>> {
        self.repository.get_node_affiliation(node_id, jid).await
    }

    pub(crate) async fn affiliations_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubAffiliation>> {
        self.repository.affiliations_for_jid(jid, node).await
    }
}

impl<R: PubSubAffiliationQueryRepository> PubSubService<R> {
    pub(crate) async fn can_retrieve_node(&self, node: &PubSubNode, jid: &str) -> Result<bool> {
        // Affiliation and subscription share one statement snapshot. The
        // caller loaded node configuration separately for its response.
        let (affiliation, subscribed) = self
            .repository
            .retrieval_authorization_facts(node.id, jid)
            .await?;
        let affiliation = affiliation
            .as_deref()
            .map(str::parse::<northstar_xep_0060::Affiliation>)
            .transpose()
            .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
        let access_model = node
            .access_model
            .parse::<northstar_xep_0060::AccessModel>()
            .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
        Ok(northstar_xep_0060::can_retrieve_pure(
            access_model,
            affiliation,
            subscribed,
        ))
    }
}

impl<R: PubSubSubscriptionQueryRepository> PubSubService<R> {
    pub(crate) async fn subscriptions_for_jid(
        &self,
        jid: &str,
        node: Option<&str>,
    ) -> Result<Vec<PubSubSubscription>> {
        self.repository.subscriptions_for_jid(jid, node).await
    }

    pub(crate) async fn subscriptions_addressing_jid_page(
        &self,
        jid: &str,
        after: Option<(&str, &str)>,
        limit: i64,
    ) -> Result<Vec<PubSubSubscription>> {
        self.repository
            .subscriptions_addressing_jid_page(jid, after, limit)
            .await
    }

    pub(crate) async fn get_subscription(
        &self,
        node_id: Uuid,
        jid: &str,
    ) -> Result<Option<PubSubSubscription>> {
        self.repository.get_subscription(node_id, jid).await
    }
}

impl<R: PubSubItemQueryRepository> PubSubService<R> {
    pub(crate) async fn leaf_disco_items(
        &self,
        node: &str,
        requester: &str,
    ) -> Result<LeafDiscoItems> {
        let Some(snapshot) = self.repository.leaf_disco_snapshot(node, requester).await? else {
            return Ok(LeafDiscoItems::NotFound);
        };
        if snapshot.node_type != "leaf" {
            return Ok(LeafDiscoItems::NotLeaf);
        }
        if !can_retrieve_disco_snapshot(
            &snapshot.access_model,
            snapshot.affiliation.as_deref(),
            snapshot.subscribed,
        )? {
            return Ok(LeafDiscoItems::Forbidden);
        }
        Ok(LeafDiscoItems::Items(snapshot.item_ids))
    }

    pub(crate) async fn collection_disco_items(
        &self,
        node: &str,
        requester: &str,
    ) -> Result<CollectionDiscoItems> {
        let Some(snapshot) = self
            .repository
            .collection_disco_snapshot(node, requester)
            .await?
        else {
            return Ok(CollectionDiscoItems::NotFound);
        };
        if snapshot.node_type != "collection" {
            return Ok(CollectionDiscoItems::NotCollection);
        }
        if !can_retrieve_disco_snapshot(
            &snapshot.access_model,
            snapshot.affiliation.as_deref(),
            snapshot.subscribed,
        )? {
            return Ok(CollectionDiscoItems::Forbidden);
        }
        Ok(CollectionDiscoItems::Items(snapshot.children))
    }

    pub(crate) async fn get_items(
        &self,
        node_id: Uuid,
        item_ids: &[String],
        limit: i64,
    ) -> Result<Vec<PubSubItem>> {
        self.repository.get_items(node_id, item_ids, limit).await
    }

    pub(crate) async fn collection_visible_items(
        &self,
        collection_id: Uuid,
        requester: &str,
        global_item_limit: i64,
        xml_byte_limit: i64,
    ) -> Result<Vec<CollectionVisibleItem>> {
        self.repository
            .collection_visible_items(collection_id, requester, global_item_limit, xml_byte_limit)
            .await
    }

    pub(crate) async fn can_publish(&self, node: &PubSubNode, requester: &str) -> Result<bool> {
        self.repository.can_publish(node, requester).await
    }
}

pub(super) fn can_retrieve_disco_snapshot(
    access_model: &str,
    affiliation: Option<&str>,
    subscribed: bool,
) -> Result<bool> {
    let access_model = access_model
        .parse::<northstar_xep_0060::AccessModel>()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub access model: {error}"))?;
    let affiliation = affiliation
        .map(str::parse::<northstar_xep_0060::Affiliation>)
        .transpose()
        .map_err(|error| anyhow::anyhow!("invalid stored PubSub affiliation: {error}"))?;
    Ok(northstar_xep_0060::can_retrieve_pure(
        access_model,
        affiliation,
        subscribed,
    ))
}
