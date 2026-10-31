//! Handle entity namespace read and mutation operations.

use super::*;

pub(super) async fn handle_entity_get<H: PubSubHost>(
    host: &H,
    requester: &str,
    operations: Vec<Node<'_, '_>>,
) -> Result<PubSubReply> {
    let rsm = operations.iter().find(|node| {
        node.tag_name().name() == "set" && node.tag_name().namespace() == Some(NS_RSM)
    });
    let primary = operations
        .iter()
        .filter(|node| node.tag_name().namespace() == Some(NS_PUBSUB))
        .copied()
        .collect::<Vec<_>>();
    if primary.len() != 1 {
        return Ok(PubSubReply::Error("bad-request"));
    }
    let operation = primary[0];
    if rsm.is_some() && operation.tag_name().name() != "items" {
        return Ok(PubSubReply::Error("bad-request"));
    }
    let requester_full = normalized_jid(requester)?;
    let requester = normalized_bare(&requester_full)?;
    match operation.tag_name().name() {
        "default" => {
            if !has_only_attributes(operation, &["node"]) || !has_no_element_content(operation) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node = match operation.attribute("node") {
                Some(name) => {
                    let Some(name) = valid_node_id(Some(name)) else {
                        return Ok(PubSubReply::Error("bad-request"));
                    };
                    match host.pubsub_application_service().get_node(name).await? {
                        Some(node) => Some(node),
                        None => return missing_node_reply(host, name).await,
                    }
                }
                None => None,
            };
            let options = PubSubSubscriptionOptions::for_node_type(
                node.as_ref().map_or("leaf", |node| node.node_type.as_str()),
            );
            let form = subscription_options_form(
                &options,
                "result",
                node.as_ref().is_some_and(supports_include_body),
                node.as_ref().map_or("leaf", |node| node.node_type.as_str()),
            );
            let mut default = XmlElement::new("default")
                .optional_attr("node", node.as_ref().map(|node| node.node.as_str()));
            default.push_validated_fragment(&form)?;
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB)
                    .child(default)
                    .finish(),
            ))
        }
        "options" => {
            if !has_only_attributes(operation, &["node", "jid", "subid"])
                || !has_no_element_content(operation)
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node_name = match required_node_id(operation.attribute("node")) {
                Ok(node) => node,
                Err(reply) => return Ok(reply),
            };
            let Some(requested_jid) = operation
                .attribute("jid")
                .and_then(|jid| normalized_jid(jid).ok())
            else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "jid-required",
                )));
            };
            if normalized_bare(&requested_jid)? != requester {
                return Ok(PubSubReply::Error("forbidden"));
            }
            let Some(node) = host
                .pubsub_application_service()
                .get_node(node_name)
                .await?
            else {
                return missing_node_reply(host, node_name).await;
            };
            let Some(subscription) = host
                .pubsub_application_service()
                .get_subscription(node.id, &requested_jid)
                .await?
            else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "unexpected-request",
                    "not-subscribed",
                )));
            };
            if subscription.is_expired_at(chrono::Utc::now()) {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "unexpected-request",
                    "not-subscribed",
                )));
            }
            if operation
                .attribute("subid")
                .is_some_and(|subid| subid != subscription.subid)
            {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "not-acceptable",
                    "invalid-subid",
                )));
            }
            let options = subscription_options(&subscription);
            let form = subscription_options_form(
                &options,
                "form",
                supports_include_body(&node),
                &node.node_type,
            );
            let mut options = XmlElement::new("options")
                .attr("node", node_name)
                .attr("jid", &requested_jid)
                .attr("subid", &subscription.subid);
            options.push_validated_fragment(&form)?;
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB)
                    .child(options)
                    .finish(),
            ))
        }
        "items" => {
            if !has_only_attributes(operation, &["node", "max_items", "subid"]) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let rsm = match rsm {
                Some(set) => match parse_pubsub_rsm(*set) {
                    Ok(rsm) => Some(rsm),
                    Err(reply) => return Ok(reply),
                },
                None => None,
            };
            let node_name = match required_node_id(operation.attribute("node")) {
                Ok(node) => node,
                Err(reply) => return Ok(reply),
            };
            if node_name == "serverinfo" {
                if rsm.is_some() || operation.attribute("subid").is_some() {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                if let Some(value) = operation.attribute("max_items") {
                    if value
                        .parse::<u32>()
                        .ok()
                        .filter(|value| *value > 0)
                        .is_none()
                    {
                        return Ok(PubSubReply::Error("bad-request"));
                    }
                }
                for item in operation.children().filter(|child| child.is_element()) {
                    if item.tag_name().name() != "item"
                        || item.tag_name().namespace() != Some(NS_PUBSUB)
                    {
                        return Ok(PubSubReply::Error("bad-request"));
                    }
                    if item.attribute("id") != Some("current") {
                        return Ok(PubSubReply::Error("item-not-found"));
                    }
                }
                let serverinfo = XmlElement::namespaced("serverinfo", "urn:xmpp:serverinfo:0")
                    .child(XmlElement::new("domain").attr("name", host.pubsub_local_domain()));
                return Ok(PubSubReply::Result(
                    XmlElement::namespaced("pubsub", NS_PUBSUB)
                        .child(
                            XmlElement::new("items").attr("node", "serverinfo").child(
                                XmlElement::new("item")
                                    .attr("id", "current")
                                    .child(serverinfo),
                            ),
                        )
                        .finish(),
                ));
            }
            let Some(node) = host
                .pubsub_application_service()
                .get_node(node_name)
                .await?
            else {
                return missing_node_reply(host, node_name).await;
            };
            let affiliation = host
                .pubsub_application_service()
                .get_node_affiliation(node.id, &requester)
                .await?;
            let subscriptions = host
                .pubsub_application_service()
                .subscriptions_for_jid(&requester_full, Some(node_name))
                .await?;
            let now = chrono::Utc::now();
            let subscriptions = subscriptions
                .into_iter()
                .filter(|subscription| subscription.is_active_at(now))
                .collect::<Vec<_>>();
            if let Err(reply) = item_retrieval_access(
                &node.access_model,
                affiliation.as_deref(),
                &subscriptions,
                operation.attribute("subid"),
            ) {
                return Ok(reply);
            }
            if node.node_type == "collection" {
                if rsm.is_some() {
                    return Ok(PubSubReply::ExtendedError(PubSubError::unsupported("rsm")));
                }
                if operation.children().any(|child| child.is_element()) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let limit = match operation.attribute("max_items") {
                    Some(value) => value
                        .parse::<i64>()
                        .ok()
                        .filter(|value| *value > 0)
                        .map(|value| value.min(100))
                        .ok_or_else(|| anyhow::anyhow!("invalid collection max_items")),
                    None => Ok(100),
                };
                let limit = match limit {
                    Ok(limit) => limit,
                    Err(_) => return Ok(PubSubReply::Error("bad-request")),
                };
                let visible_items = host
                    .pubsub_application_service()
                    .collection_visible_items(
                        node.id,
                        &requester,
                        limit,
                        MAX_PUBLISH_XML_BYTES as i64,
                    )
                    .await?;
                let mut pubsub = XmlElement::namespaced("pubsub", NS_PUBSUB);
                let mut remaining = limit as usize;
                let mut response_bytes = 0usize;
                let mut current_items: Option<(String, XmlElement)> = None;
                for item in visible_items {
                    if remaining == 0 || response_bytes >= MAX_PUBLISH_XML_BYTES {
                        break;
                    }
                    if response_bytes.saturating_add(item.xml_payload.len()) > MAX_PUBLISH_XML_BYTES
                    {
                        break;
                    }
                    if current_items
                        .as_ref()
                        .is_some_and(|(current_node, _)| current_node != &item.node)
                    {
                        if let Some((_, completed)) = current_items.take() {
                            pubsub.push_child(completed);
                        }
                    }
                    let (_, items) = current_items.get_or_insert_with(|| {
                        (
                            item.node.clone(),
                            XmlElement::new("items").attr("node", &item.node),
                        )
                    });
                    response_bytes += item.xml_payload.len();
                    remaining -= 1;
                    items.push_validated_fragment(&item.xml_payload)?;
                }
                if let Some((_, completed)) = current_items {
                    pubsub.push_child(completed);
                }
                return Ok(PubSubReply::Result(pubsub.finish()));
            }
            if !node.persist_items {
                return Ok(PubSubReply::ExtendedError(PubSubError::unsupported(
                    "persistent-items",
                )));
            }
            if rsm.is_some() && operation.attribute("max_items").is_some() {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let limit = match operation.attribute("max_items") {
                Some(value) => match value.parse::<i64>() {
                    Ok(value) if value > 0 => value.min(node.max_items as i64),
                    _ => return Ok(PubSubReply::Error("bad-request")),
                },
                None => node.max_items as i64,
            };
            let mut requested_ids = Vec::new();
            let mut unique_requested_ids = BTreeSet::new();
            for item in operation.children().filter(|node| node.is_element()) {
                if item.tag_name().name() != "item"
                    || item.tag_name().namespace() != Some(NS_PUBSUB)
                    || item.attributes().any(|attribute| {
                        attribute.namespace().is_some() || attribute.name() != "id"
                    })
                    || item.children().any(|child| {
                        child.is_element()
                            || child.text().is_some_and(|text| !text.trim().is_empty())
                    })
                {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let Some(item_id) = item.attribute("id").filter(|value| valid_item_id(value))
                else {
                    return Ok(PubSubReply::Error("bad-request"));
                };
                if !unique_requested_ids.insert(item_id) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                requested_ids.push(item_id.to_owned());
            }
            if rsm.is_some() && !requested_ids.is_empty() {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let all_stored = host
                .pubsub_application_service()
                .get_items(
                    node.id,
                    &requested_ids,
                    if rsm.is_some() {
                        node.max_items as i64
                    } else {
                        limit
                    },
                )
                .await?;
            let (stored, rsm_xml) = if let Some(rsm) = rsm {
                match pubsub_rsm_page(all_stored, &rsm, limit as usize) {
                    Ok(page) => page,
                    Err(reply) => return Ok(reply),
                }
            } else {
                (all_stored, String::new())
            };
            if !requested_ids.is_empty() && stored.len() != requested_ids.len() {
                return Ok(PubSubReply::Error("item-not-found"));
            }
            let mut items = XmlElement::new("items").attr("node", node_name);
            for item in stored {
                items.push_validated_fragment(&item.xml_payload)?;
            }
            let mut pubsub = XmlElement::namespaced("pubsub", NS_PUBSUB).child(items);
            pubsub.push_validated_fragment(&rsm_xml)?;
            Ok(PubSubReply::Result(pubsub.finish()))
        }
        "subscriptions" => {
            if !has_only_attributes(operation, &["node"]) || !has_no_element_content(operation) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node_name = operation.attribute("node");
            if let Some(name) = node_name {
                if valid_node_id(Some(name)).is_none() {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                if host
                    .pubsub_application_service()
                    .get_node(name)
                    .await?
                    .is_none()
                {
                    return missing_node_reply(host, name).await;
                }
            }
            let subscriptions = host
                .pubsub_application_service()
                .subscriptions_for_jid(&requester_full, node_name)
                .await?;
            let mut entries = XmlElement::new("subscriptions").optional_attr("node", node_name);
            for subscription in &subscriptions {
                entries.push_child(subscription_element(
                    &subscription.node,
                    &subscription.jid,
                    &subscription.state,
                    Some(&subscription.subid),
                    subscription.expire,
                ));
            }
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB)
                    .child(entries)
                    .finish(),
            ))
        }
        "affiliations" => {
            if !has_only_attributes(operation, &["node"]) || !has_no_element_content(operation) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node_name = operation.attribute("node");
            if let Some(name) = node_name {
                if valid_node_id(Some(name)).is_none() {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                if host
                    .pubsub_application_service()
                    .get_node(name)
                    .await?
                    .is_none()
                {
                    return missing_node_reply(host, name).await;
                }
            }
            let affiliations = host
                .pubsub_application_service()
                .affiliations_for_jid(&requester, node_name)
                .await?;
            let mut entries = XmlElement::new("affiliations");
            for affiliation in &affiliations {
                entries.push_child(
                    XmlElement::new("affiliation")
                        .attr("node", &affiliation.node)
                        .attr("affiliation", &affiliation.affiliation),
                );
            }
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB)
                    .child(entries)
                    .finish(),
            ))
        }
        _ => Ok(PubSubReply::Error("feature-not-implemented")),
    }
}

pub(super) async fn handle_entity_set<H: PubSubHost>(
    host: &H,
    requester: &str,
    operations: Vec<Node<'_, '_>>,
) -> Result<PubSubReply> {
    let requester_full = normalized_jid(requester)?;
    let requester = normalized_bare(&requester_full)?;
    let primary = operations[0];
    match primary.tag_name().name() {
        "options" => {
            if operations.len() != 1 {
                return Ok(PubSubReply::Error("bad-request"));
            }
            if !has_only_attributes(primary, &["node", "jid", "subid"])
                || single_element_child(primary).is_none()
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node_name = match required_node_id(primary.attribute("node")) {
                Ok(node) => node,
                Err(reply) => return Ok(reply),
            };
            let Some(requested_jid) = primary
                .attribute("jid")
                .and_then(|jid| normalized_jid(jid).ok())
            else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "jid-required",
                )));
            };
            if normalized_bare(&requested_jid)? != requester {
                return Ok(PubSubReply::Error("forbidden"));
            }
            let (node, subscription) = match host
                .pubsub_application_service()
                .subscription_options_read(node_name, &requested_jid, primary.attribute("subid"))
                .await?
            {
                PubSubSubscriptionOptionsRead::MissingNode => {
                    return missing_node_reply(host, node_name).await;
                }
                PubSubSubscriptionOptionsRead::NotSubscribed => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "unexpected-request",
                        "not-subscribed",
                    )));
                }
                PubSubSubscriptionOptionsRead::InvalidSubid => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-acceptable",
                        "invalid-subid",
                    )));
                }
                PubSubSubscriptionOptionsRead::Ready { node, subscription } => (node, subscription),
            };
            let form = single_element_child(primary)
                .expect("subscription options structure was validated above");
            if form.attribute("type") == Some("cancel") {
                return Ok(if valid_cancel_form_structure(form) {
                    PubSubReply::Result(String::new())
                } else {
                    PubSubReply::Error("bad-request")
                });
            }
            let options = match parse_subscription_options(
                form,
                subscription_options(&subscription),
                &node.node_type,
                supports_include_body(&node),
            ) {
                Ok(options) => options,
                Err(error) => return Ok(error),
            };
            match host
                .pubsub_application_service()
                .execute_pubsub_update_subscription_options(
                    PubSubUpdateSubscriptionOptionsCommand {
                        node_id: node.id,
                        requester: &requester,
                        subscriber_jid: &requested_jid,
                        expected_subid: &subscription.subid,
                        options: &options,
                    },
                )
                .await?
                .outcome
            {
                SubscriptionOptionsOutcome::Updated => {}
                SubscriptionOptionsOutcome::NotFound => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "unexpected-request",
                        "not-subscribed",
                    )));
                }
                SubscriptionOptionsOutcome::InvalidSubid => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-acceptable",
                        "invalid-subid",
                    )));
                }
                SubscriptionOptionsOutcome::InvalidOptions => {
                    return Ok(invalid_subscription_options());
                }
                SubscriptionOptionsOutcome::Forbidden => {
                    return Ok(PubSubReply::Error("forbidden"));
                }
            }
            Ok(PubSubReply::Result(String::new()))
        }
        "create" => {
            if operations.len() > 2
                || operations
                    .get(1)
                    .is_some_and(|node| node.tag_name().name() != "configure")
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            if !has_only_attributes(primary, &["node"]) || !has_no_element_content(primary) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let generated;
            let node_name = if let Some(value) = primary.attribute("node") {
                let Some(value) = valid_node_id(Some(value)) else {
                    return Ok(PubSubReply::Error("bad-request"));
                };
                value
            } else {
                generated = uuid::Uuid::new_v4().to_string();
                generated.as_str()
            };
            let mut config = PubSubNodeConfig::default();
            if node_name == "serverinfo" {
                return Ok(PubSubReply::Error("conflict"));
            }
            if let Some(configure) = operations.get(1) {
                if !has_only_attributes(*configure, &[]) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                config = match parse_node_config(*configure, config) {
                    Ok(config) => config,
                    Err(condition) => return Ok(node_config_parse_error(condition)),
                };
            }
            let cmd = PubSubCreateNodeCommand::from(PubSubCreateNodeWrite {
                creator_jid: &requester,
                node: node_name,
                config: &config,
                max_nodes_per_owner: host.pubsub_node_owner_limits().max_nodes,
            });
            match host
                .pubsub_application_service()
                .execute_pubsub_create_node(cmd)
                .await?
                .outcome
            {
                CreateNodeOutcome::Created => {}
                CreateNodeOutcome::Conflict => {
                    return Ok(PubSubReply::Error("conflict"));
                }
                CreateNodeOutcome::QuotaExceeded => {
                    return Ok(PubSubReply::Error("resource-constraint"));
                }
                CreateNodeOutcome::InvalidOptions | CreateNodeOutcome::Cycle => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-allowed",
                        "invalid-options",
                    )));
                }
                CreateNodeOutcome::Forbidden => {
                    return Ok(PubSubReply::Error("forbidden"));
                }
                CreateNodeOutcome::CollectionLimitExceeded => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-allowed",
                        "max-nodes-exceeded",
                    )));
                }
            }
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB)
                    .child(XmlElement::new("create").attr("node", node_name))
                    .finish(),
            ))
        }
        "publish" => {
            if operations.len() > 2
                || operations
                    .get(1)
                    .is_some_and(|node| node.tag_name().name() != "publish-options")
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            if !has_only_attributes(primary, &["node"])
                || operations
                    .get(1)
                    .is_some_and(|options| !has_only_attributes(*options, &[]))
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node_name = match required_node_id(primary.attribute("node")) {
                Ok(node) => node,
                Err(reply) => return Ok(reply),
            };
            if node_name == "serverinfo" {
                return Ok(PubSubReply::Error("forbidden"));
            }
            let publish_options = if let Some(options) = operations.get(1) {
                let parsed = match parse_publish_options(*options, PubSubNodeConfig::default()) {
                    Ok(config) => config,
                    Err(condition) => return Ok(node_config_parse_error(condition)),
                };
                Some(parsed)
            } else {
                None
            };
            let item_nodes: Vec<_> = primary
                .children()
                .filter(|node| node.is_element())
                .collect();
            if !publish_batch_size_allowed(item_nodes.len()) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let mut items = Vec::with_capacity(item_nodes.len());
            let mut seen_item_ids = BTreeSet::new();
            let mut total_bytes = 0usize;
            for item_node in item_nodes {
                let payload_count = item_node
                    .children()
                    .filter(|node| node.is_element())
                    .count();
                if item_node.tag_name().name() != "item"
                    || item_node.tag_name().namespace() != Some(NS_PUBSUB)
                    || !has_only_attributes(item_node, &["id"])
                {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                if payload_count > 1 {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "bad-request",
                        "invalid-payload",
                    )));
                }
                let item_id = item_node
                    .attribute("id")
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                if !valid_item_id(&item_id) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                if !seen_item_ids.insert(item_id.clone()) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let item_xml = serialize_pubsub_item(item_node, &item_id)?;
                total_bytes = total_bytes.saturating_add(item_xml.len());
                if item_xml.len() > MAX_ITEM_XML_BYTES || total_bytes > MAX_PUBLISH_XML_BYTES {
                    return Ok(PubSubReply::Error("policy-violation"));
                }
                items.push((item_id, item_xml));
            }
            let limits = host.pubsub_node_owner_limits();
            let cmd = PubSubPublishCommand::from(PubSubPublishWrite {
                publisher_jid: &requester,
                node: node_name,
                items: &items,
                publish_options: publish_options.as_ref(),
                max_storage_bytes_per_owner: limits.max_storage_bytes,
                max_nodes_per_owner: limits.max_nodes,
            });
            let result = host
                .pubsub_application_service()
                .execute_pubsub_publish(cmd)
                .await?;
            let item_ids = match result.outcome {
                PubSubPublishOutcome::Published { item_ids } => item_ids,
                PubSubPublishOutcome::Conflict => return Ok(PubSubReply::Error("conflict")),
                PubSubPublishOutcome::QuotaExceeded => {
                    return Ok(PubSubReply::Error("resource-constraint"));
                }
                PubSubPublishOutcome::Forbidden => return Ok(PubSubReply::Error("forbidden")),
                PubSubPublishOutcome::MissingNode => {
                    return Ok(PubSubReply::Error("item-not-found"))
                }
                PubSubPublishOutcome::PreconditionNotMet => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "conflict",
                        "precondition-not-met",
                    )));
                }
                PubSubPublishOutcome::NotLeafNode => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::unsupported(
                        "publish",
                    )));
                }
                PubSubPublishOutcome::MaxItemsExceeded => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-allowed",
                        "max-items-exceeded",
                    )));
                }
                PubSubPublishOutcome::ItemRequired => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "bad-request",
                        "item-required",
                    )));
                }
                PubSubPublishOutcome::ItemForbidden => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "bad-request",
                        "item-forbidden",
                    )));
                }
                PubSubPublishOutcome::PayloadRequired => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "bad-request",
                        "payload-required",
                    )));
                }
                PubSubPublishOutcome::PayloadTooBig => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-acceptable",
                        "payload-too-big",
                    )));
                }
                PubSubPublishOutcome::InvalidPayload => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "bad-request",
                        "invalid-payload",
                    )));
                }
            };
            let mut published = XmlElement::new("publish").attr("node", node_name);
            for item_id in &item_ids {
                published.push_child(XmlElement::new("item").attr("id", item_id));
            }
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB)
                    .child(published)
                    .finish(),
            ))
        }
        "subscribe" => {
            if operations.len() > 2
                || operations
                    .get(1)
                    .is_some_and(|operation| operation.tag_name().name() != "options")
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            if !has_only_attributes(primary, &["node", "jid"])
                || !has_no_element_content(primary)
                || operations.get(1).is_some_and(|options| {
                    !has_only_attributes(*options, &[]) || single_element_child(*options).is_none()
                })
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node_name = match required_node_id(primary.attribute("node")) {
                Ok(node) => node,
                Err(reply) => return Ok(reply),
            };
            let Some(node) = host
                .pubsub_application_service()
                .get_node(node_name)
                .await?
            else {
                return missing_node_reply(host, node_name).await;
            };
            let Some(requested_jid) = primary.attribute("jid") else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "jid-required",
                )));
            };
            let Ok(requested_jid) = normalized_jid(requested_jid) else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "invalid-jid",
                )));
            };
            if normalized_bare(&requested_jid)? != requester {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "invalid-jid",
                )));
            }
            let subscription_options = if let Some(options) = operations.get(1) {
                let form = single_element_child(*options)
                    .expect("subscribe-and-configure structure was validated above");
                let parsed = match parse_subscription_options(
                    form,
                    PubSubSubscriptionOptions::for_node_type(&node.node_type),
                    &node.node_type,
                    supports_include_body(&node),
                ) {
                    Ok(options) => options,
                    Err(error) => return Ok(error),
                };
                if !northstar_xep_0060::subscription_show_values_allowed(
                    northstar_xmpp_types::jid::CanonicalJid::parse_bare(&requester)?.domainpart(),
                    host.pubsub_local_domain(),
                    &parsed.show_values,
                ) {
                    return Ok(invalid_subscription_options());
                }
                Some(parsed)
            } else {
                None
            };
            let cmd = PubSubSubscribeCommand::from(PubSubSubscribeWrite {
                requester: &requester,
                subscriber_jid: &requested_jid,
                node: node_name,
                options: subscription_options.as_ref(),
                max_subscriptions: 1_000,
            });
            let result = host
                .pubsub_application_service()
                .execute_pubsub_subscribe(cmd)
                .await?;
            match result.outcome {
                PubSubSubscribeOutcome::Subscribed(subscription) => {
                    Ok(PubSubReply::Result(subscription_payload(
                        node_name,
                        &requested_jid,
                        &subscription.state,
                        Some(&subscription.subid),
                        subscription.expire.as_ref(),
                    )))
                }
                PubSubSubscribeOutcome::ExistingActive(existing) => {
                    Ok(PubSubReply::Result(subscription_payload(
                        node_name,
                        &requested_jid,
                        "subscribed",
                        Some(&existing.subid),
                        existing.expire.as_ref(),
                    )))
                }
                PubSubSubscribeOutcome::PendingSubscription => Ok(PubSubReply::ExtendedError(
                    PubSubError::new("not-authorized", "pending-subscription"),
                )),
                PubSubSubscribeOutcome::LimitExceeded => Ok(PubSubReply::ExtendedError(
                    PubSubError::new("policy-violation", "too-many-subscriptions"),
                )),
                PubSubSubscribeOutcome::NotFound => missing_node_reply(host, node_name).await,
                PubSubSubscribeOutcome::Forbidden => Ok(PubSubReply::Error("forbidden")),
                PubSubSubscribeOutcome::ClosedNode => Ok(PubSubReply::ExtendedError(
                    PubSubError::new("not-allowed", "closed-node"),
                )),
                PubSubSubscribeOutcome::PreconditionFailed => Ok(PubSubReply::Error("conflict")),
                PubSubSubscribeOutcome::InvalidOptions => Ok(invalid_subscription_options()),
            }
        }
        "unsubscribe" => {
            if operations.len() != 1 {
                return Ok(PubSubReply::Error("bad-request"));
            }
            if !has_only_attributes(primary, &["node", "jid", "subid"])
                || !has_no_element_content(primary)
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let node_name = match required_node_id(primary.attribute("node")) {
                Ok(node) => node,
                Err(reply) => return Ok(reply),
            };
            let Some(requested_jid) = primary.attribute("jid") else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "jid-required",
                )));
            };
            let Ok(requested_jid) = normalized_jid(requested_jid) else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "invalid-jid",
                )));
            };
            if normalized_bare(&requested_jid)? != requester {
                return Ok(PubSubReply::Error("forbidden"));
            }
            let supplied_subid = primary.attribute("subid");
            let cmd = PubSubUnsubscribeCommand::from(PubSubUnsubscribeWrite {
                requester: &requester,
                subscriber_jid: &requested_jid,
                node: node_name,
                subid: supplied_subid,
            });
            let result = host
                .pubsub_application_service()
                .execute_pubsub_unsubscribe(cmd)
                .await?;
            match result.outcome {
                PubSubUnsubscribeOutcome::Unsubscribed { subid } => Ok(PubSubReply::Result(
                    subscription_payload(node_name, &requested_jid, "none", subid.as_deref(), None),
                )),
                PubSubUnsubscribeOutcome::NotFound => missing_node_reply(host, node_name).await,
                PubSubUnsubscribeOutcome::NotSubscribed => Ok(PubSubReply::ExtendedError(
                    PubSubError::new("unexpected-request", "not-subscribed"),
                )),
                PubSubUnsubscribeOutcome::InvalidSubid => Ok(PubSubReply::ExtendedError(
                    PubSubError::new("not-acceptable", "invalid-subid"),
                )),
                PubSubUnsubscribeOutcome::Forbidden => Ok(PubSubReply::Error("forbidden")),
            }
        }
        "retract" => {
            if operations.len() != 1 {
                return Ok(PubSubReply::Error("bad-request"));
            }
            if !has_only_attributes(primary, &["node", "notify"]) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let force_notification = match primary.attribute("notify") {
                Some(value) => match parse_bool(Some(value)) {
                    Some(value) => value,
                    None => return Ok(PubSubReply::Error("bad-request")),
                },
                None => false,
            };
            let node_name = match required_node_id(primary.attribute("node")) {
                Ok(node) => node,
                Err(reply) => return Ok(reply),
            };
            let mut ids = BTreeSet::new();
            for item in primary.children().filter(|node| node.is_element()) {
                if item.tag_name().name() != "item"
                    || item.tag_name().namespace() != Some(NS_PUBSUB)
                    || item.attributes().any(|attribute| {
                        attribute.namespace().is_some() || attribute.name() != "id"
                    })
                    || item.children().any(|child| {
                        child.is_element()
                            || child.text().is_some_and(|text| !text.trim().is_empty())
                    })
                {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let Some(item_id) = item.attribute("id").filter(|value| valid_item_id(value))
                else {
                    return Ok(PubSubReply::Error("bad-request"));
                };
                if !ids.insert(item_id.to_owned()) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
            }
            if ids.is_empty() {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "bad-request",
                    "item-required",
                )));
            }
            let ids = ids.into_iter().collect::<Vec<_>>();
            let cmd = PubSubRetractCommand::from(PubSubRetractWrite {
                requester: &requester,
                node: node_name,
                item_ids: &ids,
                force_notification,
            });
            let result = host
                .pubsub_application_service()
                .execute_pubsub_retract(cmd)
                .await?;
            match result.outcome {
                PubSubRetractOutcome::Retracted => {}
                PubSubRetractOutcome::NotFound => return missing_node_reply(host, node_name).await,
                PubSubRetractOutcome::ItemNotFound => {
                    return Ok(PubSubReply::Error("item-not-found"));
                }
                PubSubRetractOutcome::Forbidden => return Ok(PubSubReply::Error("forbidden")),
                PubSubRetractOutcome::NotLeafNode => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::unsupported(
                        "delete-items",
                    )));
                }
                PubSubRetractOutcome::NotPersistent => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::unsupported(
                        "persistent-items",
                    )));
                }
            }
            Ok(PubSubReply::Result(String::new()))
        }
        _ => Ok(PubSubReply::Error("feature-not-implemented")),
    }
}
