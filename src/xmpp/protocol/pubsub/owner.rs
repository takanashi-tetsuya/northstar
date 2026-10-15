//! Handle owner namespace operations and collection association replies.

use super::*;

pub(super) async fn handle_owner_get(
    state: &AppState,
    requester: &str,
    operations: Vec<Node<'_, '_>>,
) -> Result<PubSubReply> {
    if operations.len() != 1 {
        return Ok(PubSubReply::Error("bad-request"));
    }
    let requester = normalized_bare(requester)?;
    let operation = operations[0];
    if operation.tag_name().name() == "default" {
        let node_type = match requested_default_node_type(operation) {
            Ok(node_type) => node_type,
            Err(reply) => return Ok(reply),
        };
        let defaults = if node_type == "collection" {
            PubSubNodeConfig {
                node_type: "collection".to_owned(),
                persist_items: false,
                deliver_payloads: false,
                ..PubSubNodeConfig::default()
            }
        } else {
            PubSubNodeConfig::default()
        };
        let form = node_config_form(&defaults, "form");
        let mut default = XmlElement::new("default");
        default.push_validated_fragment(&form)?;
        return Ok(PubSubReply::Result(
            XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
                .child(default)
                .finish(),
        ));
    }
    let node_name = match required_node_id(operation.attribute("node")) {
        Ok(node) => node,
        Err(reply) => return Ok(reply),
    };
    let name = operation.tag_name().name();
    let valid_body = has_only_attributes(operation, &["node"]) && has_no_element_content(operation);
    let kind = if valid_body {
        match name {
            "configure" => PubSubOwnerReadKind::Configure,
            "subscriptions" => PubSubOwnerReadKind::Subscriptions,
            "affiliations" => PubSubOwnerReadKind::Affiliations,
            _ => PubSubOwnerReadKind::CheckOnly,
        }
    } else {
        PubSubOwnerReadKind::CheckOnly
    };
    let snapshot = match state
        .pubsub_service()
        .owner_read(node_name, &requester, kind)
        .await?
    {
        PubSubOwnerRead::Missing => return missing_node_reply(state, node_name).await,
        PubSubOwnerRead::Forbidden => return Ok(PubSubReply::Error("forbidden")),
        snapshot => snapshot,
    };
    if !valid_body && matches!(name, "configure" | "subscriptions" | "affiliations") {
        return Ok(PubSubReply::Error("bad-request"));
    }
    match snapshot {
        PubSubOwnerRead::Configure(config) => {
            let form = node_config_form(&config, "form");
            let mut configure = XmlElement::new("configure").attr("node", node_name);
            configure.push_validated_fragment(&form)?;
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
                    .child(configure)
                    .finish(),
            ))
        }
        PubSubOwnerRead::Subscriptions(subscriptions) => {
            let mut entries = XmlElement::new("subscriptions").attr("node", node_name);
            for subscription in &subscriptions {
                entries.push_child(
                    XmlElement::new("subscription")
                        .attr("jid", &subscription.jid)
                        .attr("subscription", &subscription.state)
                        .attr("subid", &subscription.subid)
                        .optional_attr(
                            "expiry",
                            subscription.expire.map(|expiry| expiry.to_rfc3339()),
                        ),
                );
            }
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
                    .child(entries)
                    .finish(),
            ))
        }
        PubSubOwnerRead::Affiliations(affiliations) => {
            let mut entries = XmlElement::new("affiliations").attr("node", node_name);
            for affiliation in &affiliations {
                entries.push_child(
                    XmlElement::new("affiliation")
                        .attr("jid", &affiliation.jid)
                        .attr("affiliation", &affiliation.affiliation),
                );
            }
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
                    .child(entries)
                    .finish(),
            ))
        }
        PubSubOwnerRead::Authorized => Ok(PubSubReply::Error("feature-not-implemented")),
        PubSubOwnerRead::Missing | PubSubOwnerRead::Forbidden => Err(anyhow::anyhow!(
            "PubSub owner read returned an inconsistent result"
        )),
    }
}

pub(super) fn requested_default_node_type(
    operation: Node<'_, '_>,
) -> Result<&'static str, PubSubReply> {
    if !has_only_attributes(operation, &[]) || !has_only_whitespace_text(operation) {
        return Err(PubSubReply::Error("bad-request"));
    }
    let mut children = operation.children().filter(|child| child.is_element());
    let Some(form) = children.next() else {
        return Ok("leaf");
    };
    if children.next().is_some() || !valid_submit_form_structure(form) || has_duplicate_fields(form)
    {
        return Err(PubSubReply::Error("bad-request"));
    }
    let fields = data_form_fields(form);
    if fields
        .keys()
        .any(|field| !matches!(field.as_str(), "FORM_TYPE" | "pubsub#node_type"))
        || fields.values().any(|values| values.len() != 1)
        || first_field(&fields, "FORM_TYPE") != Some(NODE_CONFIG_FORM)
    {
        return Err(PubSubReply::Error("bad-request"));
    }
    match first_field(&fields, "pubsub#node_type") {
        Some("collection") => Ok("collection"),
        Some("leaf") | None => Ok("leaf"),
        Some(_) => Err(PubSubReply::Error("bad-request")),
    }
}

pub(super) async fn handle_owner_set(
    state: &AppState,
    requester: &str,
    operations: Vec<Node<'_, '_>>,
) -> Result<PubSubReply> {
    if operations.len() != 1 {
        return Ok(PubSubReply::Error("bad-request"));
    }
    let requester = normalized_bare(requester)?;
    let operation = operations[0];
    let node_name = match required_node_id(operation.attribute("node")) {
        Ok(node) => node,
        Err(reply) => return Ok(reply),
    };
    let Some(node) = state.pubsub_service().get_node(node_name).await? else {
        return missing_node_reply(state, node_name).await;
    };
    if operation.tag_name().name() == "collection" {
        if !has_only_attributes(operation, &["node"]) {
            return Ok(PubSubReply::Error("bad-request"));
        }
        let children = operation
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if children.len() != 1
            || children[0].tag_name().namespace() != Some(NS_PUBSUB_OWNER)
            || !matches!(children[0].tag_name().name(), "associate" | "dissociate")
        {
            return Ok(PubSubReply::Error("bad-request"));
        }
        let action = children[0];
        if !has_only_attributes(action, &["node"]) {
            return Ok(PubSubReply::Error("bad-request"));
        }
        let child_name = match required_node_id(action.attribute("node")) {
            Ok(node) => node,
            Err(reply) => return Ok(reply),
        };
        let operation = if action.tag_name().name() == "associate" {
            PubSubCollectionEdgeOperation::Associate
        } else {
            PubSubCollectionEdgeOperation::Dissociate
        };
        let result = state
            .pubsub_service()
            .execute_pubsub_collection_edge(PubSubCollectionEdgeCommand {
                requester: &requester,
                collection: &node,
                child: child_name,
                operation,
            })
            .await?;
        return Ok(collection_edge_reply(result));
    }
    if !is_owner(state, node.id, &requester).await? {
        return Ok(PubSubReply::Error("forbidden"));
    }
    match operation.tag_name().name() {
        "configure" => {
            if !has_only_attributes(operation, &["node"]) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let Some(form) = single_element_child(operation) else {
                return Ok(PubSubReply::Error("bad-request"));
            };
            if form.attribute("type") == Some("cancel") {
                return Ok(if valid_cancel_form_structure(form) {
                    PubSubReply::Result(String::new())
                } else {
                    PubSubReply::Error("bad-request")
                });
            }
            let mut current = node.config();
            current.collections = state
                .pubsub_service()
                .collection_parents(node.id)
                .await?
                .into_iter()
                .map(|node| node.node)
                .collect();
            current.children = state
                .pubsub_service()
                .collection_children(node.id)
                .await?
                .into_iter()
                .map(|node| node.node)
                .collect();
            let expected = current.clone();
            let config = match parse_node_config(operation, current) {
                Ok(config) => config,
                Err(condition) => return Ok(node_config_parse_error(condition)),
            };
            let cmd = PubSubConfigureNodeCommand::from(PubSubConfigureNodeWrite {
                requester: &requester,
                node: node_name,
                expected: &expected,
                config: &config,
            });
            match state
                .pubsub_service()
                .execute_pubsub_configure_node(cmd)
                .await?
                .outcome
            {
                PubSubConfigOutcome::Updated => {}
                PubSubConfigOutcome::Conflict => {
                    return Ok(PubSubReply::Error("conflict"));
                }
                PubSubConfigOutcome::NotFound => {
                    return Ok(PubSubReply::Error("item-not-found"));
                }
                PubSubConfigOutcome::Forbidden => {
                    return Ok(PubSubReply::Error("forbidden"));
                }
                PubSubConfigOutcome::LimitExceeded => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-allowed",
                        "max-nodes-exceeded",
                    )));
                }
                PubSubConfigOutcome::Cycle | PubSubConfigOutcome::InvalidOptions => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::new(
                        "not-allowed",
                        "invalid-options",
                    )));
                }
            }
        }
        "subscriptions" => {
            if !has_only_attributes(operation, &["node"]) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let mut changes = Vec::new();
            let mut seen_jids = BTreeSet::new();
            let mut entry_count = 0usize;
            for entry in operation.children().filter(|node| node.is_element()) {
                entry_count += 1;
                if entry.tag_name().name() != "subscription"
                    || entry.tag_name().namespace() != Some(NS_PUBSUB_OWNER)
                    || !has_only_attributes(entry, &["jid", "subscription", "subid"])
                    || entry.children().any(|child| child.is_element())
                {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let Some(jid) = entry
                    .attribute("jid")
                    .and_then(|jid| normalized_jid(jid).ok())
                else {
                    return Ok(PubSubReply::Error("bad-request"));
                };
                if !seen_jids.insert(jid.clone()) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let Some(value) = entry.attribute("subscription") else {
                    // XEP-0060 section 8.8.2 explicitly says an omitted
                    // subscription attribute MUST leave the value unchanged.
                    continue;
                };
                if !matches!(value, "subscribed" | "pending" | "unconfigured" | "none") {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                changes.push((
                    jid,
                    value.to_owned(),
                    entry.attribute("subid").map(ToOwned::to_owned),
                ));
            }
            if entry_count == 0 || entry_count > 100 {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let transitions = if changes.is_empty() {
                Vec::new()
            } else {
                let cmd = PubSubSetSubscriptionsCommand::from(PubSubSetSubscriptionsWrite {
                    requester: &requester,
                    node: node_name,
                    changes: &changes,
                });
                match state
                    .pubsub_service()
                    .execute_pubsub_set_subscriptions(cmd)
                    .await?
                    .outcome
                {
                    SetSubscriptionsOutcome::Updated(transitions) => transitions,
                    SetSubscriptionsOutcome::LimitExceeded => {
                        return Ok(PubSubReply::ExtendedError(PubSubError::new(
                            "policy-violation",
                            "too-many-subscriptions",
                        )));
                    }
                    SetSubscriptionsOutcome::InvalidSubid => {
                        return Ok(PubSubReply::ExtendedError(PubSubError::new(
                            "not-acceptable",
                            "invalid-subid",
                        )));
                    }
                    SetSubscriptionsOutcome::NotFound => {
                        return Ok(PubSubReply::Error("item-not-found"));
                    }
                    SetSubscriptionsOutcome::Forbidden => {
                        return Ok(PubSubReply::Error("forbidden"));
                    }
                }
            };
            let _ = transitions;
        }
        "affiliations" => {
            if !has_only_attributes(operation, &["node"]) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let mut changes = Vec::new();
            let mut seen_jids = BTreeSet::new();
            let mut entry_count = 0usize;
            for entry in operation.children().filter(|node| node.is_element()) {
                entry_count += 1;
                if entry.tag_name().name() != "affiliation"
                    || entry.tag_name().namespace() != Some(NS_PUBSUB_OWNER)
                    || !has_only_attributes(entry, &["jid", "affiliation"])
                    || entry.children().any(|child| child.is_element())
                {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let Some(jid) = entry.attribute("jid").filter(|jid| valid_bare_jid(jid)) else {
                    return Ok(PubSubReply::Error("bad-request"));
                };
                let jid = normalized_bare(jid)?;
                if !seen_jids.insert(jid.clone()) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                let Some(value) = entry.attribute("affiliation") else {
                    // A missing affiliation is explicitly a no-op delta.
                    continue;
                };
                if !matches!(
                    value,
                    "owner" | "publisher" | "publish-only" | "member" | "outcast" | "none"
                ) {
                    return Ok(PubSubReply::Error("bad-request"));
                }
                changes.push((jid, value.to_owned()));
            }
            if entry_count == 0 || entry_count > 100 {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let (revoked_subscriptions, approved_subscriptions) = if changes.is_empty() {
                (Vec::new(), Vec::new())
            } else {
                let cmd = PubSubSetAffiliationsCommand::from(PubSubSetAffiliationsWrite {
                    requester: &requester,
                    node: node_name,
                    changes: &changes,
                });
                match state
                    .pubsub_service()
                    .execute_pubsub_set_affiliations(cmd)
                    .await?
                    .outcome
                {
                    SetAffiliationsOutcome::LastOwner => {
                        return Ok(PubSubReply::Error("not-acceptable"));
                    }
                    SetAffiliationsOutcome::NotFound => {
                        return Ok(PubSubReply::Error("item-not-found"));
                    }
                    SetAffiliationsOutcome::Forbidden => {
                        return Ok(PubSubReply::Error("forbidden"));
                    }
                    SetAffiliationsOutcome::Updated {
                        revoked_subscriptions,
                        approved_subscriptions,
                    } => (revoked_subscriptions, approved_subscriptions),
                }
            };
            let _ = (revoked_subscriptions, approved_subscriptions);
        }
        "purge" => {
            if !has_only_attributes(operation, &["node"]) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            if node.node_type != "leaf" || !node.persist_items {
                return Ok(PubSubReply::ExtendedError(PubSubError::unsupported(
                    "persistent-items",
                )));
            }
            let cmd = PubSubPurgeNodeCommand::from(PubSubPurgeNodeWrite {
                requester: &requester,
                node: node_name,
            });
            match state
                .pubsub_service()
                .execute_pubsub_purge_node(cmd)
                .await?
                .outcome
            {
                OwnerMutationOutcome::Applied => {}
                OwnerMutationOutcome::NotFound => {
                    return Ok(PubSubReply::Error("item-not-found"));
                }
                OwnerMutationOutcome::Forbidden => {
                    return Ok(PubSubReply::Error("forbidden"));
                }
                OwnerMutationOutcome::Invalid => {
                    return Ok(PubSubReply::ExtendedError(PubSubError::unsupported(
                        "persistent-items",
                    )));
                }
            }
        }
        "delete" => {
            if !has_only_attributes(operation, &["node"]) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let redirect_nodes = operation
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            if redirect_nodes.len() > 1
                || redirect_nodes.first().is_some_and(|redirect| {
                    redirect.tag_name().name() != "redirect"
                        || redirect.tag_name().namespace() != Some(NS_PUBSUB_OWNER)
                })
            {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let redirect = match redirect_nodes.first() {
                Some(redirect) => {
                    if !has_only_attributes(*redirect, &["uri"])
                        || redirect.children().any(|child| child.is_element())
                    {
                        return Ok(PubSubReply::Error("bad-request"));
                    }
                    let Some(uri) = redirect
                        .attribute("uri")
                        .filter(|uri| valid_redirect_uri(uri))
                    else {
                        return Ok(PubSubReply::Error("bad-request"));
                    };
                    Some(uri)
                }
                None => None,
            };
            let cmd = PubSubDeleteNodeCommand::from(PubSubDeleteNodeWrite {
                requester: &requester,
                node: node_name,
                redirect,
            });
            match state
                .pubsub_service()
                .execute_pubsub_delete_node(cmd)
                .await?
                .outcome
            {
                OwnerMutationOutcome::Applied => {}
                OwnerMutationOutcome::NotFound => {
                    return Ok(PubSubReply::Error("item-not-found"));
                }
                OwnerMutationOutcome::Forbidden => {
                    return Ok(PubSubReply::Error("forbidden"));
                }
                OwnerMutationOutcome::Invalid => {
                    return Ok(PubSubReply::Error("bad-request"));
                }
            }
        }
        _ => return Ok(PubSubReply::Error("feature-not-implemented")),
    }
    Ok(PubSubReply::Result(String::new()))
}

pub(super) fn collection_edge_reply(result: PubSubCollectionEdgeResult) -> PubSubReply {
    match result {
        PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::Updated) => {
            PubSubReply::Result(String::new())
        }
        PubSubCollectionEdgeResult::MissingChild
        | PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::NotFound) => {
            PubSubReply::Error("item-not-found")
        }
        // XEP-0248 section 7.6.3.1 uses bad-request for a missing edge.
        PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::NotAssociated) => {
            PubSubReply::Error("bad-request")
        }
        PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::NotCollection)
        | PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::DepthExceeded)
        | PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::Cycle) => {
            PubSubReply::ExtendedError(PubSubError::new("not-allowed", "invalid-options"))
        }
        PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::Forbidden) => {
            PubSubReply::Error("forbidden")
        }
        PubSubCollectionEdgeResult::Mutation(CollectionUpdateOutcome::LimitExceeded) => {
            PubSubReply::ExtendedError(PubSubError::new("not-allowed", "max-nodes-exceeded"))
        }
    }
}
