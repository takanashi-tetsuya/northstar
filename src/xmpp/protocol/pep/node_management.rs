//! Create PEP nodes and handle owner operations and node configuration forms.

use super::*;

pub(super) fn pep_data_field(
    variable: &str,
    field_type: Option<&str>,
    values: impl IntoIterator<Item = impl ToString>,
) -> XmlElement {
    let mut field = XmlElement::new("field")
        .attr("var", variable)
        .optional_attr("type", field_type);
    for value in values {
        field.push_child(XmlElement::new("value").text(value.to_string()));
    }
    field
}

impl ProtocolSession {
    pub(super) async fn pep_create(
        &self,
        id: &str,
        user: &crate::services::authentication::AuthenticatedAccount,
        create: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(node) = create
            .attribute("node")
            .filter(|node| valid_node_name(node))
        else {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("nodeid-required"),
            )));
        };
        match self
            .state
            .pubsub_service()
            .execute_pep_create_node(PepCreateNodeCommand::new(
                user.id,
                node,
                self.state.pep_account_quotas().max_nodes,
            ))
            .await?
            .outcome
        {
            PepCreateOutcome::Created => {
                let payload = XmlElement::namespaced("pubsub", NS_PUBSUB)
                    .child(XmlElement::new("create").attr("node", node))
                    .finish();
                Ok(Action::Send(iq_result(id, &payload)))
            }
            PepCreateOutcome::Conflict => Ok(Action::Send(iq_error(id, "conflict"))),
            PepCreateOutcome::QuotaExceeded => Ok(Action::Send(pep_error(
                id,
                None,
                "wait",
                "resource-constraint",
                Some("max-nodes-exceeded"),
            ))),
        }
    }

    pub(crate) async fn pep_owner_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if !pep_owner_target_allowed(self, iq, user) {
            return Ok(Action::Send(iq_error(id, "forbidden")));
        }
        let operations = pubsub
            .children()
            .filter(Node::is_element)
            .collect::<Vec<_>>();
        if operations.len() != 1 {
            return Ok(Action::Send(iq_error(id, "feature-not-implemented")));
        }
        let operation = operations[0];
        let Some(node) = operation
            .attribute("node")
            .filter(|node| valid_node_name(node))
        else {
            return Ok(Action::Send(pep_error(
                id,
                iq.attribute("to"),
                "modify",
                "bad-request",
                Some("nodeid-required"),
            )));
        };
        let Some(config) = self.state.pubsub_service().pep_node(user.id, node).await? else {
            return Ok(Action::Send(iq_error_from_optional(
                id,
                iq.attribute("to"),
                "item-not-found",
            )));
        };
        let owner_jid = canonical_account_jid(&user.username, self.state.local_domain())?;
        let inner = match operation.tag_name().name() {
            "configure" => {
                let mut configure = XmlElement::new("configure").attr("node", node);
                configure.push_validated_fragment(&pep_config_form(&config, "form"))?;
                configure
            }
            "subscriptions" => {
                let subscriptions = self
                    .state
                    .pubsub_service()
                    .pep_subscribers(user.id, node)
                    .await?;
                let mut entries = XmlElement::new("subscriptions").attr("node", node);
                for subscription in subscriptions {
                    entries.push_child(
                        XmlElement::new("subscription")
                            .attr("jid", subscription.jid)
                            .attr("subscription", "subscribed")
                            .attr("subid", subscription.subid),
                    );
                }
                entries
            }
            "affiliations" => {
                let mut entries = XmlElement::new("affiliations").attr("node", node).child(
                    XmlElement::new("affiliation")
                        .attr("jid", &owner_jid)
                        .attr("affiliation", "owner"),
                );
                for member in &config.access_whitelist {
                    entries.push_child(
                        XmlElement::new("affiliation")
                            .attr("jid", member)
                            .attr("affiliation", "member"),
                    );
                }
                entries
            }
            _ => return Ok(Action::Send(iq_error(id, "feature-not-implemented"))),
        };
        let payload = XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub#owner")
            .child(inner)
            .finish();
        Ok(Action::Send(iq_result_from_optional(
            id,
            iq.attribute("to"),
            &payload,
        )))
    }

    pub(crate) async fn pep_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if !pep_owner_target_allowed(self, iq, user) {
            return Ok(Action::Send(iq_error(id, "forbidden")));
        }
        let operations = pubsub
            .children()
            .filter(Node::is_element)
            .collect::<Vec<_>>();
        if operations.len() != 1 {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let operation = operations[0];
        let Some(node) = operation
            .attribute("node")
            .filter(|node| valid_node_name(node))
        else {
            return Ok(Action::Send(pep_error(
                id,
                iq.attribute("to"),
                "modify",
                "bad-request",
                Some("nodeid-required"),
            )));
        };
        let Some(current) = self.state.pubsub_service().pep_node(user.id, node).await? else {
            return Ok(Action::Send(iq_error_from_optional(
                id,
                iq.attribute("to"),
                "item-not-found",
            )));
        };
        let owner = PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        };
        match operation.tag_name().name() {
            "configure" => {
                if operation
                    .children()
                    .find(Node::is_element)
                    .is_some_and(|form| form.attribute("type") == Some("cancel"))
                {
                    return Ok(Action::Send(iq_result_from_optional(
                        id,
                        iq.attribute("to"),
                        "",
                    )));
                }
                let config = match parse_owner_config(operation, current.clone(), node) {
                    Ok(config) => config,
                    Err(()) => {
                        return Ok(Action::Send(pep_error(
                            id,
                            iq.attribute("to"),
                            "modify",
                            "not-acceptable",
                            Some("invalid-options"),
                        )));
                    }
                };
                let mut event = XmlElement::new("configuration").attr("node", node);
                event.push_validated_fragment(&pep_config_form(&config, "result"))?;
                let event = event.finish();
                let audience_state = std::sync::Arc::clone(&self.state);
                let publisher_full_jid = self.full_jid.clone();
                let cmd = PepConfigureNodeCommand::from(PepConfigureNodeWrite {
                    owner: &owner,
                    connection_id: self.connection_id,
                    node,
                    expected: &current,
                    config: &config,
                });
                let factory = move |audience: &PepAudienceSnapshot| {
                    ProtocolSession::prepare_pep_audience_messages(
                        audience_state.as_ref(),
                        publisher_full_jid.as_deref(),
                        node,
                        &event,
                        audience,
                    )
                };
                let outcome = self
                    .state
                    .pubsub_service()
                    .execute_pep_configure_node(cmd, &factory)
                    .await?
                    .outcome;
                if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                    return Ok(Action::Send(error));
                }
            }
            "purge" => {
                let event = XmlElement::new("purge").attr("node", node).finish();
                let audience_state = std::sync::Arc::clone(&self.state);
                let publisher_full_jid = self.full_jid.clone();
                let cmd = PepPurgeNodeCommand::from(PepPurgeNodeWrite {
                    owner: &owner,
                    connection_id: self.connection_id,
                    node,
                });
                let factory = move |audience: &PepAudienceSnapshot| {
                    ProtocolSession::prepare_pep_audience_messages(
                        audience_state.as_ref(),
                        publisher_full_jid.as_deref(),
                        node,
                        &event,
                        audience,
                    )
                };
                let outcome = self
                    .state
                    .pubsub_service()
                    .execute_pep_purge_node(cmd, &factory)
                    .await?
                    .outcome;
                if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                    return Ok(Action::Send(error));
                }
            }
            "delete" => {
                let event = XmlElement::new("delete").attr("node", node).finish();
                let audience_state = std::sync::Arc::clone(&self.state);
                let publisher_full_jid = self.full_jid.clone();
                let cmd = PepDeleteNodeCommand::from(PepDeleteNodeWrite {
                    owner: &owner,
                    connection_id: self.connection_id,
                    node,
                });
                let factory = move |audience: &PepAudienceSnapshot| {
                    ProtocolSession::prepare_pep_audience_messages(
                        audience_state.as_ref(),
                        publisher_full_jid.as_deref(),
                        node,
                        &event,
                        audience,
                    )
                };
                let outcome = self
                    .state
                    .pubsub_service()
                    .execute_pep_delete_node(cmd, &factory)
                    .await?
                    .outcome;
                if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                    return Ok(Action::Send(error));
                }
            }
            "affiliations" => {
                let owner_jid = canonical_account_jid(&user.username, self.state.local_domain())?;
                let changes = operation
                    .children()
                    .filter(Node::is_element)
                    .map(|affiliation| {
                        if affiliation.tag_name().name() != "affiliation"
                            || affiliation.tag_name().namespace()
                                != Some("http://jabber.org/protocol/pubsub#owner")
                            || affiliation.attributes().len() != 2
                        {
                            return None;
                        }
                        let jid = affiliation.attribute("jid").and_then(|jid| {
                            northstar_xmpp_types::jid::canonical_bare_key(jid).ok()
                        })?;
                        let value = affiliation.attribute("affiliation")?;
                        matches!(value, "member" | "none").then(|| (jid, value.to_owned()))
                    })
                    .collect::<Option<Vec<_>>>();
                let Some(changes) = changes.filter(|changes| {
                    !changes.is_empty()
                        && changes.len() <= 1_000
                        && changes.iter().all(|(jid, _)| jid != &owner_jid)
                }) else {
                    return Ok(Action::Send(pep_error(
                        id,
                        iq.attribute("to"),
                        "modify",
                        "bad-request",
                        Some("invalid-jid"),
                    )));
                };
                let cmd = PepSetAffiliationsCommand::from(PepSetAffiliationsWrite {
                    owner: &owner,
                    connection_id: self.connection_id,
                    node,
                    expected: &current,
                    changes: &changes,
                });
                let outcome = self
                    .state
                    .pubsub_service()
                    .execute_pep_set_affiliations(cmd, &render_pep_direct_state_messages)
                    .await?
                    .outcome;
                if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                    return Ok(Action::Send(error));
                }
            }
            "subscriptions" => {
                let changes = operation
                    .children()
                    .filter(Node::is_element)
                    .map(|subscription| {
                        if subscription.tag_name().name() != "subscription"
                            || subscription.tag_name().namespace()
                                != Some("http://jabber.org/protocol/pubsub#owner")
                            || subscription.attribute("subscription") != Some("none")
                        {
                            return None;
                        }
                        let jid = subscription
                            .attribute("jid")
                            .and_then(|jid| northstar_xmpp_types::jid::canonicalize(jid).ok())?;
                        Some((jid, subscription.attribute("subid").map(ToOwned::to_owned)))
                    })
                    .collect::<Option<Vec<_>>>();
                let Some(changes) = changes.filter(|changes| {
                    !changes.is_empty()
                        && changes.len() <= 1_000
                        && changes
                            .iter()
                            .collect::<std::collections::BTreeSet<_>>()
                            .len()
                            == changes.len()
                }) else {
                    return Ok(Action::Send(iq_error(id, "bad-request")));
                };
                let outcome = self
                    .state
                    .pubsub_service()
                    .execute_pep_unsubscribe_batch(
                        PepUnsubscribeBatchCommand {
                            owner: &owner,
                            connection_id: self.connection_id,
                            node,
                            changes: &changes,
                        },
                        &render_pep_direct_state_messages,
                    )
                    .await?
                    .outcome;
                match outcome {
                    PepOwnerMutationOutcome::Applied(_) => {}
                    PepOwnerMutationOutcome::NotSubscribed => {
                        return Ok(Action::Send(pep_error(
                            id,
                            iq.attribute("to"),
                            "cancel",
                            "unexpected-request",
                            Some("not-subscribed"),
                        )));
                    }
                    other => {
                        if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), other)
                        {
                            return Ok(Action::Send(error));
                        }
                    }
                }
            }
            _ => return Ok(Action::Send(iq_error(id, "feature-not-implemented"))),
        }
        Ok(Action::Send(iq_result_from_optional(
            id,
            iq.attribute("to"),
            "",
        )))
    }
}

pub(super) fn pep_owner_mutation_error(
    id: &str,
    from: Option<&str>,
    outcome: PepOwnerMutationOutcome,
) -> Option<String> {
    match outcome {
        PepOwnerMutationOutcome::Applied(_) => None,
        PepOwnerMutationOutcome::NotFound => {
            Some(iq_error_from_optional(id, from, "item-not-found"))
        }
        PepOwnerMutationOutcome::Forbidden => Some(iq_error_from_optional(id, from, "forbidden")),
        PepOwnerMutationOutcome::Stale => Some(iq_error_from_optional(id, from, "conflict")),
        PepOwnerMutationOutcome::NotSubscribed => Some(pep_error(
            id,
            from,
            "cancel",
            "unexpected-request",
            Some("not-subscribed"),
        )),
    }
}

pub(super) fn pep_owner_target_allowed(
    session: &ProtocolSession,
    iq: Node<'_, '_>,
    user: &crate::services::authentication::AuthenticatedAccount,
) -> bool {
    iq.attribute("to").is_none_or(|to| {
        canonical_account_jid(&user.username, session.state.local_domain()).is_ok_and(|owner| {
            northstar_xmpp_types::jid::canonicalize_bare(to).is_ok_and(|target| target == owner)
        })
    })
}

pub(super) fn valid_node_name(node: &str) -> bool {
    !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
}

pub(super) fn parse_owner_config(
    container: Node<'_, '_>,
    mut config: PepNodeConfig,
    node: &str,
) -> std::result::Result<PepNodeConfig, ()> {
    let form = container
        .children()
        .find(|child| {
            child.is_element()
                && child.tag_name().name() == "x"
                && child.tag_name().namespace() == Some(NS_XDATA)
        })
        .ok_or(())?;
    if form.attribute("type") != Some("submit")
        || xdata_field(form, "FORM_TYPE") != Some("http://jabber.org/protocol/pubsub#node_config")
    {
        return Err(());
    }
    let mut seen = HashSet::new();
    for field in form.children().filter(|child| {
        child.is_element()
            && child.tag_name().name() == "field"
            && child.tag_name().namespace() == Some(NS_XDATA)
    }) {
        let variable = field.attribute("var").ok_or(())?;
        if !seen.insert(variable) {
            return Err(());
        }
        match variable {
            "FORM_TYPE" => {}
            "pubsub#access_model" => {
                let value = child_text(field, "value").ok_or(())?;
                if !matches!(value, "open" | "presence" | "roster" | "whitelist") {
                    return Err(());
                }
                config.access_model = value.to_owned();
            }
            "pubsub#max_items" => {
                let value = child_text(field, "value").ok_or(())?;
                config.max_items = if value == "max" {
                    crate::services::pubsub::PEP_MAX_ITEMS
                } else {
                    value.parse().map_err(|_| ())?
                };
                if !(1..=crate::services::pubsub::PEP_MAX_ITEMS).contains(&config.max_items) {
                    return Err(());
                }
            }
            "pubsub#persist_items" => {
                config.persist_items = parse_form_bool(child_text(field, "value").ok_or(())?)?
            }
            "pubsub#send_last_published_item" => {
                let value = child_text(field, "value").ok_or(())?;
                if !matches!(value, "never" | "on_sub" | "on_sub_and_presence") {
                    return Err(());
                }
                config.send_last_published_item = value.to_owned();
            }
            "pubsub#deliver_notifications" => {
                config.deliver_notifications =
                    parse_form_bool(child_text(field, "value").ok_or(())?)?
            }
            "pubsub#roster_groups_allowed" => {
                let values = field
                    .children()
                    .filter(|child| {
                        child.is_element()
                            && child.tag_name().name() == "value"
                            && child.tag_name().namespace() == Some(NS_XDATA)
                    })
                    .map(|child| child.text().unwrap_or_default().to_owned())
                    .collect::<Vec<_>>();
                if values.is_empty()
                    || values.len() > 100
                    || values
                        .iter()
                        .any(|value| value.is_empty() || value.len() > 128)
                {
                    return Err(());
                }
                config.roster_groups_allowed = values;
            }
            _ => return Err(()),
        }
    }
    if matches!(node, OMEMO_DEVICES | OMEMO_BUNDLES)
        && (config.access_model != "open"
            || !config.persist_items
            || node == OMEMO_DEVICES && config.max_items != 1
            || node == OMEMO_BUNDLES && config.max_items != crate::services::pubsub::PEP_MAX_ITEMS)
    {
        return Err(());
    }
    if matches!(node, AVATAR_DATA | AVATAR_METADATA | VCARD4)
        && (config.access_model != "open"
            || !config.persist_items
            || matches!(node, AVATAR_METADATA | VCARD4) && config.max_items != 1)
    {
        return Err(());
    }
    if matches!(node, BOOKMARKS2 | CONTACTS | "storage:bookmarks")
        && config.access_model != "whitelist"
    {
        return Err(());
    }
    Ok(config)
}

pub(super) fn pep_config_form(config: &PepNodeConfig, kind: &str) -> String {
    XmlElement::namespaced("x", NS_XDATA)
        .attr("type", kind)
        .child(pep_data_field(
            "FORM_TYPE",
            Some("hidden"),
            ["http://jabber.org/protocol/pubsub#node_config"],
        ))
        .child(pep_data_field(
            "pubsub#access_model",
            None,
            [&config.access_model],
        ))
        .child(pep_data_field(
            "pubsub#max_items",
            None,
            [config.max_items.to_string()],
        ))
        .child(pep_data_field(
            "pubsub#persist_items",
            None,
            [config.persist_items.to_string()],
        ))
        .child(pep_data_field(
            "pubsub#send_last_published_item",
            None,
            [&config.send_last_published_item],
        ))
        .child(pep_data_field(
            "pubsub#deliver_notifications",
            None,
            [config.deliver_notifications.to_string()],
        ))
        .child(pep_data_field(
            "pubsub#roster_groups_allowed",
            Some("list-multi"),
            config.roster_groups_allowed.iter(),
        ))
        .finish()
}

pub(super) fn parse_form_bool(value: &str) -> std::result::Result<bool, ()> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(()),
    }
}
