//! Create PEP nodes and handle owner operations and node configuration forms.

use super::forms::{decode_pep_config_form, is_pep_config_form};
use super::*;
use northstar_pubsub_core::{apply_pep_config_patch, pep_owner_config_policy, PepConfigPatch};

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

pub(super) async fn pep_create<S: PepSession>(
    session: &S,
    id: &str,
    user: &PubSubAccount,
    from: Option<&str>,
    create: Node<'_, '_>,
) -> Result<String> {
    let Some(node) = create
        .attribute("node")
        .filter(|node| valid_node_name(node))
    else {
        return Ok(pep_error(
            id,
            None,
            "modify",
            "bad-request",
            Some("nodeid-required"),
        ));
    };
    let outcome = session
        .pep_pubsub_service()
        .execute_pep_create_node(PepCreateNodeCommand::new(
            user,
            node,
            session.pep_quotas().max_nodes,
        ))
        .await?
        .outcome;
    Ok(pep_create_reply(id, from, node, outcome))
}

fn pep_create_reply(id: &str, from: Option<&str>, node: &str, outcome: PepCreateOutcome) -> String {
    match outcome {
        PepCreateOutcome::Created => {
            let payload = XmlElement::namespaced("pubsub", NS_PUBSUB)
                .child(XmlElement::new("create").attr("node", node))
                .finish();
            iq_result(id, &payload)
        }
        PepCreateOutcome::Conflict => iq_error(id, "conflict"),
        PepCreateOutcome::QuotaExceeded => pep_error(
            id,
            None,
            "wait",
            "resource-constraint",
            Some("max-nodes-exceeded"),
        ),
        PepCreateOutcome::StaleAuthority => pep_owner_forbidden(id, from),
    }
}

pub async fn pep_owner_get<S: PepSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    pubsub: Node<'_, '_>,
) -> Result<String> {
    let Some(user) = session.pep_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    if !pep_owner_target_allowed(session, iq, &user) {
        return Ok(iq_error(id, "forbidden"));
    }
    let operations = pubsub
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if operations.len() != 1 {
        return Ok(iq_error(id, "feature-not-implemented"));
    }
    let operation = operations[0];
    let Some(node) = operation
        .attribute("node")
        .filter(|node| valid_node_name(node))
    else {
        return Ok(pep_error(
            id,
            iq.attribute("to"),
            "modify",
            "bad-request",
            Some("nodeid-required"),
        ));
    };
    let from = iq.attribute("to");
    let operation_name = operation.tag_name().name();
    let inner = if operation_name == "subscriptions" {
        let PepOwnerSubscriptionsRead::Subscribers(subscriptions) = session
            .pep_pubsub_service()
            .pep_owner_subscriptions(&PepOwnerQuery { owner: &user, node })
            .await?
        else {
            return Ok(iq_error_from_optional(id, from, "item-not-found"));
        };
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
    } else {
        let Some(config) = session.pep_pubsub_service().pep_node(user.id, node).await? else {
            return Ok(iq_error_from_optional(id, from, "item-not-found"));
        };
        let owner_jid = canonical_account_jid(&user.username, session.pep_local_domain())?;
        match operation_name {
            "configure" => {
                let mut configure = XmlElement::new("configure").attr("node", node);
                configure.push_validated_fragment(&pep_config_form(&config, "form"))?;
                configure
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
            _ => return Ok(iq_error(id, "feature-not-implemented")),
        }
    };
    let payload = XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub#owner")
        .child(inner)
        .finish();
    Ok(iq_result_from_optional(id, from, &payload))
}

pub async fn pep_owner_set<S: PepSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    pubsub: Node<'_, '_>,
) -> Result<String> {
    let Some(user) = session.pep_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    if !pep_owner_target_allowed(session, iq, &user) {
        return Ok(iq_error(id, "forbidden"));
    }
    let operations = pubsub
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if operations.len() != 1 {
        return Ok(iq_error(id, "bad-request"));
    }
    let operation = operations[0];
    let Some(node) = operation
        .attribute("node")
        .filter(|node| valid_node_name(node))
    else {
        return Ok(pep_error(
            id,
            iq.attribute("to"),
            "modify",
            "bad-request",
            Some("nodeid-required"),
        ));
    };
    let Some(current) = session.pep_pubsub_service().pep_node(user.id, node).await? else {
        return Ok(iq_error_from_optional(
            id,
            iq.attribute("to"),
            "item-not-found",
        ));
    };
    let owner = user.clone();
    match operation.tag_name().name() {
        "configure" => {
            if operation
                .children()
                .find(Node::is_element)
                .is_some_and(|form| form.attribute("type") == Some("cancel"))
            {
                return Ok(iq_result_from_optional(id, iq.attribute("to"), ""));
            }
            let proposed = parse_owner_config(operation).and_then(|patch| {
                let config = apply_pep_config_patch(&current, &patch).map_err(|_| ())?;
                pep_owner_config_policy(node, &config).map_err(|_| ())?;
                Ok(config)
            });
            let config = match proposed {
                Ok(config) => config,
                Err(()) => {
                    return Ok(pep_error(
                        id,
                        iq.attribute("to"),
                        "modify",
                        "not-acceptable",
                        Some("invalid-options"),
                    ));
                }
            };
            let mut event = XmlElement::new("configuration").attr("node", node);
            event.push_validated_fragment(&pep_config_form(&config, "result"))?;
            let event = event.finish();
            let publisher_full_jid = session.pep_full_jid().map(str::to_owned);
            let cmd = PepConfigureNodeCommand::from(PepConfigureNodeWrite {
                owner: &owner,
                connection_id: session.pep_connection_id(),
                node,
                expected: &current,
                config: &config,
            });
            let factory = move |audience: &PepAudienceSnapshot| {
                pep_audience_messages(
                    session.pep_audience_routing(),
                    publisher_full_jid.as_deref(),
                    node,
                    &event,
                    audience,
                )
            };
            let outcome = session
                .pep_pubsub_service()
                .execute_pep_configure_node(cmd, &factory)
                .await?
                .outcome;
            if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                return Ok(error);
            }
        }
        "purge" => {
            let event = XmlElement::new("purge").attr("node", node).finish();
            let publisher_full_jid = session.pep_full_jid().map(str::to_owned);
            let cmd = PepPurgeNodeCommand::from(PepPurgeNodeWrite {
                owner: &owner,
                connection_id: session.pep_connection_id(),
                node,
            });
            let factory = move |audience: &PepAudienceSnapshot| {
                pep_audience_messages(
                    session.pep_audience_routing(),
                    publisher_full_jid.as_deref(),
                    node,
                    &event,
                    audience,
                )
            };
            let outcome = session
                .pep_pubsub_service()
                .execute_pep_purge_node(cmd, &factory)
                .await?
                .outcome;
            if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                return Ok(error);
            }
        }
        "delete" => {
            let event = XmlElement::new("delete").attr("node", node).finish();
            let publisher_full_jid = session.pep_full_jid().map(str::to_owned);
            let cmd = PepDeleteNodeCommand::from(PepDeleteNodeWrite {
                owner: &owner,
                connection_id: session.pep_connection_id(),
                node,
            });
            let factory = move |audience: &PepAudienceSnapshot| {
                pep_audience_messages(
                    session.pep_audience_routing(),
                    publisher_full_jid.as_deref(),
                    node,
                    &event,
                    audience,
                )
            };
            let outcome = session
                .pep_pubsub_service()
                .execute_pep_delete_node(cmd, &factory)
                .await?
                .outcome;
            if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                return Ok(error);
            }
        }
        "affiliations" => {
            let owner_jid = canonical_account_jid(&user.username, session.pep_local_domain())?;
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
                    let jid = affiliation
                        .attribute("jid")
                        .and_then(|jid| northstar_xmpp_types::jid::canonical_bare_key(jid).ok())?;
                    let value = affiliation.attribute("affiliation")?;
                    matches!(value, "member" | "none").then(|| (jid, value.to_owned()))
                })
                .collect::<Option<Vec<_>>>();
            let Some(changes) = changes.filter(|changes| {
                !changes.is_empty()
                    && changes.len() <= 1_000
                    && changes.iter().all(|(jid, _)| jid != &owner_jid)
            }) else {
                return Ok(pep_error(
                    id,
                    iq.attribute("to"),
                    "modify",
                    "bad-request",
                    Some("invalid-jid"),
                ));
            };
            let cmd = PepSetAffiliationsCommand::from(PepSetAffiliationsWrite {
                owner: &owner,
                connection_id: session.pep_connection_id(),
                node,
                expected: &current,
                changes: &changes,
            });
            let outcome = session
                .pep_pubsub_service()
                .execute_pep_set_affiliations(cmd, &render_pep_direct_state_messages)
                .await?
                .outcome;
            if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                return Ok(error);
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
                return Ok(iq_error(id, "bad-request"));
            };
            let outcome = session
                .pep_pubsub_service()
                .execute_pep_unsubscribe_batch(
                    PepUnsubscribeBatchCommand {
                        owner: &owner,
                        connection_id: session.pep_connection_id(),
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
                    return Ok(pep_error(
                        id,
                        iq.attribute("to"),
                        "cancel",
                        "unexpected-request",
                        Some("not-subscribed"),
                    ));
                }
                other => {
                    if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), other) {
                        return Ok(error);
                    }
                }
            }
        }
        _ => return Ok(iq_error(id, "feature-not-implemented")),
    }
    Ok(iq_result_from_optional(id, iq.attribute("to"), ""))
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
        PepOwnerMutationOutcome::Forbidden => Some(pep_owner_forbidden(id, from)),
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

fn pep_owner_forbidden(id: &str, from: Option<&str>) -> String {
    iq_error_from_optional(id, from, "forbidden")
}

pub(super) fn pep_owner_target_allowed<S: PepSession>(
    session: &S,
    iq: Node<'_, '_>,
    user: &PubSubAccount,
) -> bool {
    iq.attribute("to").is_none_or(|to| {
        canonical_account_jid(&user.username, session.pep_local_domain()).is_ok_and(|owner| {
            northstar_xmpp_types::jid::canonicalize_bare(to).is_ok_and(|target| target == owner)
        })
    })
}

pub(super) fn valid_node_name(node: &str) -> bool {
    !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
}

fn parse_owner_config(container: Node<'_, '_>) -> std::result::Result<PepConfigPatch, ()> {
    let form = container
        .children()
        .find(|child| is_pep_config_form(*child))
        .ok_or(())?;
    decode_pep_config_form(form, "http://jabber.org/protocol/pubsub#node_config")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_pep_create_uses_the_owner_mutation_forbidden_reply() {
        for from in [None, Some("owner@example.test")] {
            assert_eq!(
                pep_create_reply("create", from, "news", PepCreateOutcome::StaleAuthority),
                pep_owner_mutation_error("create", from, PepOwnerMutationOutcome::Forbidden)
                    .unwrap(),
            );
        }
    }
}
