//! Handle PEP publication and retraction with publication options, event factories, and item normalization.

use super::*;

pub(super) struct PepPublishedEventFactory<'a> {
    pub(super) state: std::sync::Arc<crate::state::AppState>,
    pub(super) publisher_full_jid: Option<String>,
    pub(super) node: &'a str,
    pub(super) event: Option<&'a str>,
}

impl PepPublishedEventFactory<'_> {
    pub(super) fn render(
        &self,
        audience: &PepAudienceSnapshot,
        event: &str,
    ) -> Result<Vec<(String, String)>> {
        ProtocolSession::prepare_pep_audience_messages(
            self.state.as_ref(),
            self.publisher_full_jid.as_deref(),
            self.node,
            event,
            audience,
        )
    }
}

impl PepOutboxFactory for PepPublishedEventFactory<'_> {
    fn build(&self, audience: &PepAudienceSnapshot) -> Result<Vec<(String, String)>> {
        anyhow::ensure!(
            self.node != BOOKMARKS2,
            "Bookmarks2 publication requires a transaction-owned item diff"
        );
        self.event
            .map_or_else(|| Ok(Vec::new()), |event| self.render(audience, event))
    }

    fn build_published(
        &self,
        audience: &PepAudienceSnapshot,
        changed_items: &[(&str, &str)],
    ) -> Result<Vec<(String, String)>> {
        if self.node != BOOKMARKS2 {
            return self.build(audience);
        }
        let Some(event) = bookmarks2_items_event(changed_items)? else {
            return Ok(Vec::new());
        };
        self.render(audience, &event)
    }
}

pub(crate) fn bookmarks2_items_event(changed_items: &[(&str, &str)]) -> Result<Option<String>> {
    if changed_items.is_empty() {
        return Ok(None);
    }
    let payload = changed_items
        .iter()
        .map(|(_, item)| *item)
        .collect::<String>();
    let mut event = XmlElement::new("items").attr("node", BOOKMARKS2);
    event.push_validated_fragment(&strip_pubsub_item_root_namespaces(&payload)?)?;
    Ok(Some(event.finish()))
}

pub(super) fn profile_publish_error(id: &str, status: ProfilePublishStatus) -> Option<String> {
    match status {
        ProfilePublishStatus::Published => None,
        ProfilePublishStatus::Unauthorized => Some(iq_error(id, "not-authorized")),
        ProfilePublishStatus::PreconditionFailed => Some(pep_error(
            id,
            None,
            "cancel",
            "conflict",
            Some("precondition-not-met"),
        )),
        ProfilePublishStatus::MaxItemsExceeded => Some(pep_error(
            id,
            None,
            "modify",
            "not-allowed",
            Some("max-items-exceeded"),
        )),
        ProfilePublishStatus::QuotaExceeded => {
            Some(pep_error(id, None, "wait", "resource-constraint", None))
        }
        ProfilePublishStatus::InvalidAvatar => Some(pep_error(
            id,
            None,
            "cancel",
            "item-not-found",
            Some("invalid-payload"),
        )),
    }
}

impl ProtocolSession {
    pub(crate) async fn pep_publish(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let operations = pubsub
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if operations.iter().any(|node| {
            node.tag_name().namespace() != Some(NS_PUBSUB)
                || !matches!(
                    node.tag_name().name(),
                    "publish"
                        | "publish-options"
                        | "retract"
                        | "create"
                        | "subscribe"
                        | "unsubscribe"
                )
        }) {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let primary = operations
            .iter()
            .filter(|node| node.tag_name().name() != "publish-options")
            .copied()
            .collect::<Vec<_>>();
        if primary.len() != 1 {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let primary = primary[0];
        let publish_options_count = operations
            .iter()
            .filter(|node| node.tag_name().name() == "publish-options")
            .count();
        if publish_options_count > 1
            || (primary.tag_name().name() != "publish" && publish_options_count != 0)
        {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        if matches!(primary.tag_name().name(), "publish" | "retract" | "create")
            && iq.attribute("to").is_some_and(|to| {
                !canonical_account_jid(&user.username, self.state.local_domain()).is_ok_and(
                    |owner| {
                        northstar_xmpp_types::jid::canonicalize_bare(to)
                            .is_ok_and(|target| target == owner)
                    },
                )
            })
        {
            return Ok(Action::Send(iq_error(id, "forbidden")));
        }
        if primary.tag_name().name() == "create" {
            return self.pep_create(id, user, primary).await;
        }
        if primary.tag_name().name() == "subscribe" {
            return self.pep_subscribe(id, iq, user, primary).await;
        }
        if primary.tag_name().name() == "unsubscribe" {
            return self.pep_unsubscribe(id, iq, user, primary).await;
        }
        if primary.tag_name().name() == "retract" {
            let retract = primary;
            return self.pep_retract(id, user, retract).await;
        }
        let publish = primary;
        if publish.tag_name().name() != "publish" {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let Some(node) = publish.attribute("node") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if node.is_empty() || node.len() > 512 {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }
        let items: Vec<_> = publish
            .children()
            .filter(|child| {
                child.is_element()
                    && child.tag_name().namespace() == Some(NS_PUBSUB)
                    && child.tag_name().name() == "item"
            })
            .collect();
        if publish.children().filter(Node::is_element).count() != items.len() {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        if items.is_empty() {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("item-required"),
            )));
        }
        if items.len() > northstar_pubsub_core::PEP_MAX_ITEMS as usize {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "not-allowed",
                Some("max-items-exceeded"),
            )));
        }

        let options = match publish_options(pubsub, node) {
            Ok(options) => options,
            Err(()) => {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "bad-request",
                    Some("precondition-not-met"),
                )));
            }
        };
        let stored_config = self.state.pubsub_service().pep_node(user.id, node).await?;
        if options.explicit
            && stored_config
                .as_ref()
                .is_some_and(|config| config != &options.config)
        {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "cancel",
                "conflict",
                Some("precondition-not-met"),
            )));
        }
        let effective_config = stored_config
            .clone()
            .unwrap_or_else(|| options.config.clone());
        let mut normalized = Vec::with_capacity(items.len());
        let mut assigned_ids = Vec::new();
        let mut unique_ids = HashSet::new();
        for item in items {
            let generated = item.attribute("id").is_none();
            let wire_item_id = item
                .attribute("id")
                .map(str::to_owned)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let item_id =
                match northstar_pubsub_core::canonical_profile_item_id(node, &wire_item_id) {
                    Ok(item_id) => item_id,
                    Err(_) => {
                        return Ok(Action::Send(pep_error(
                            id,
                            None,
                            "modify",
                            "bad-request",
                            Some("invalid-payload"),
                        )));
                    }
                };
            if item_id.is_empty()
                || item_id.len() > 1024
                || !unique_ids.insert(item_id.clone())
                || !valid_pep_payload(node, &item_id, item)
            {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "bad-request",
                    Some("invalid-payload"),
                )));
            }
            let range = item.range();
            let item_xml =
                normalized_pep_item(&raw[range], &item_id, generated || wire_item_id != item_id);
            if item_xml.len() > 512 * 1024 {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "not-acceptable",
                    Some("payload-too-big"),
                )));
            }
            normalized.push((item_id.clone(), item_xml));
            if generated {
                assigned_ids.push(item_id);
            }
        }
        if normalized.len() > effective_config.max_items as usize {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "not-allowed",
                Some("max-items-exceeded"),
            )));
        }
        let borrowed = normalized
            .iter()
            .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
            .collect::<Vec<_>>();
        // XEP-0292 notifications deliberately omit the vCard4 payload.  The
        // item itself remains stored in PEP and is retrieved with an IQ.
        let payload = if node == BOOKMARKS2 {
            String::new()
        } else {
            published_event_items(node, &normalized)?
        };
        let profile_node = matches!(node, AVATAR_DATA | AVATAR_METADATA | VCARD4);
        let mut profile_event = None;
        let generic_event = if payload.is_empty() || profile_node {
            if profile_node && !payload.is_empty() {
                profile_event = Some(profile_item_event(node, &payload)?);
            }
            None
        } else {
            let mut event = XmlElement::new("items").attr("node", node);
            event.push_validated_fragment(&strip_pubsub_item_root_namespaces(&payload)?)?;
            Some(event.finish())
        };
        let quotas = self.state.pep_account_quotas();
        let mut avatar_presence = AvatarPresenceUpdate::Unchanged;
        let (outcome, _content_changed) = if node == AVATAR_METADATA {
            let event = profile_event
                .as_deref()
                .expect("non-empty avatar metadata has a prepared event");
            let audience_state = std::sync::Arc::clone(&self.state);
            let publisher_full_jid = self.full_jid.clone();
            let result = self
                .state
                .pubsub_service()
                .publish_avatar_metadata(
                    self.state.profile_service(),
                    PepProfileWrite {
                        user_id: user.id,
                        auth_generation: user.auth_generation,
                        connection_id: self.connection_id,
                        node,
                        requested: &options.config,
                        enforce_preconditions: options.explicit,
                        items: &borrowed,
                        max_nodes: quotas.max_nodes,
                        max_storage_bytes: quotas.max_storage_bytes,
                    },
                    &move |audience: &ProfileAudienceSnapshot| {
                        ProtocolSession::prepare_profile_audience_messages(
                            audience_state.as_ref(),
                            publisher_full_jid.as_deref(),
                            AVATAR_METADATA,
                            event,
                            audience,
                        )
                    },
                )
                .await?;
            if let Some(error) = profile_publish_error(id, result.status) {
                return Ok(Action::Send(error));
            }
            avatar_presence = result.avatar_presence;
            (None, result.content_changed)
        } else if matches!(node, AVATAR_DATA | VCARD4) {
            let event = profile_event
                .as_deref()
                .expect("non-empty profile publication has a prepared event");
            let audience_state = std::sync::Arc::clone(&self.state);
            let publisher_full_jid = self.full_jid.clone();
            let result: ProfilePublishResult = self
                .state
                .pubsub_service()
                .publish_profile_items(
                    self.state.profile_service(),
                    PepProfileWrite {
                        user_id: user.id,
                        auth_generation: user.auth_generation,
                        connection_id: self.connection_id,
                        node,
                        requested: &options.config,
                        enforce_preconditions: options.explicit,
                        items: &borrowed,
                        max_nodes: quotas.max_nodes,
                        max_storage_bytes: quotas.max_storage_bytes,
                    },
                    &move |audience: &ProfileAudienceSnapshot| {
                        ProtocolSession::prepare_profile_audience_messages(
                            audience_state.as_ref(),
                            publisher_full_jid.as_deref(),
                            node,
                            event,
                            audience,
                        )
                    },
                    node == VCARD4,
                )
                .await?;
            if let Some(error) = profile_publish_error(id, result.status) {
                return Ok(Action::Send(error));
            }
            (None, result.content_changed)
        } else {
            let factory = PepPublishedEventFactory {
                state: std::sync::Arc::clone(&self.state),
                publisher_full_jid: self.full_jid.clone(),
                node,
                event: generic_event.as_deref(),
            };
            let result = self
                .state
                .pubsub_service()
                .publish_pep_items(
                    PepPublishItemsCommand::new(
                        PepPublishWrite {
                            user_id: user.id,
                            username: &user.username,
                            auth_generation: user.auth_generation,
                            connection_id: self.connection_id,
                            node,
                            requested: &options.config,
                            enforce_preconditions: options.explicit,
                            items: &borrowed,
                            quotas,
                        },
                        node == BOOKMARKS2,
                    ),
                    &factory,
                )
                .await?;
            let outcome = result.outcome;
            let content_changed = result.content_changed;
            (Some(outcome.into()), content_changed)
        };
        match outcome {
            None | Some(PepPublishOutcome::Published) => {}
            Some(PepPublishOutcome::Unauthorized) => {
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            }
            Some(PepPublishOutcome::PreconditionFailed) => {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "cancel",
                    "conflict",
                    Some("precondition-not-met"),
                )));
            }
            Some(PepPublishOutcome::MaxItemsExceeded) => {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "not-allowed",
                    Some("max-items-exceeded"),
                )));
            }
            Some(PepPublishOutcome::QuotaExceeded) => {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "wait",
                    "resource-constraint",
                    None,
                )));
            }
        }
        if let AvatarPresenceUpdate::Changed(hash) = avatar_presence {
            self.refresh_local_avatar_presence(
                &canonical_account_jid(&user.username, self.state.local_domain())?,
                hash.as_deref(),
            );
        }
        self.state
            .pep_telemetry()
            .published(normalized.len() as u64);

        if assigned_ids.is_empty() {
            Ok(Action::Send(iq_result(id, "")))
        } else {
            let mut publish = XmlElement::new("publish").attr("node", node);
            for item_id in &assigned_ids {
                publish.push_child(XmlElement::new("item").attr("id", item_id));
            }
            let payload = XmlElement::namespaced("pubsub", NS_PUBSUB)
                .child(publish)
                .finish();
            Ok(Action::Send(iq_result(id, &payload)))
        }
    }

    pub(super) async fn pep_retract(
        &self,
        id: &str,
        user: &crate::services::authentication::AuthenticatedAccount,
        retract: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(node) = retract.attribute("node") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if node.is_empty() || node.len() > 512 {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }
        let item_ids = retract
            .children()
            .filter(|child| {
                child.is_element()
                    && child.tag_name().namespace() == Some(NS_PUBSUB)
                    && child.tag_name().name() == "item"
            })
            .map(|item| item.attribute("id"))
            .collect::<Option<Vec<_>>>();
        if retract.children().filter(Node::is_element).count()
            != item_ids.as_ref().map_or(0, Vec::len)
        {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let Some(item_ids) = item_ids.filter(|ids| {
            !ids.is_empty()
                && ids.len() <= northstar_pubsub_core::PEP_MAX_ITEMS as usize
                && ids
                    .iter()
                    .all(|item_id| !item_id.is_empty() && item_id.len() <= 1024)
        }) else {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("item-required"),
            )));
        };
        let mut canonical_ids = Vec::with_capacity(item_ids.len());
        let mut unique_ids = HashSet::new();
        for item_id in item_ids {
            let Ok(item_id) = northstar_pubsub_core::canonical_profile_item_id(node, item_id)
            else {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "bad-request",
                    Some("invalid-payload"),
                )));
            };
            if !unique_ids.insert(item_id.clone()) {
                return Ok(Action::Send(iq_error(id, "bad-request")));
            }
            canonical_ids.push(item_id);
        }
        let item_ids = canonical_ids.iter().map(String::as_str).collect::<Vec<_>>();
        let notify = retract.attribute("notify") != Some("false")
            && retract.attribute("notify") != Some("0");
        let mut event = XmlElement::new("items").attr("node", node);
        for item_id in &item_ids {
            event.push_child(XmlElement::new("retract").attr("id", item_id));
        }
        let event = event.finish();
        let audience_state = std::sync::Arc::clone(&self.state);
        let publisher_full_jid = self.full_jid.clone();
        let owner = PubSubAccount {
            id: user.id,
            username: user.username.clone(),
            auth_generation: user.auth_generation,
        };
        let cmd = PepRetractCommand::from(PepRetractWrite {
            owner: &owner,
            connection_id: self.connection_id,
            node,
            item_ids: &canonical_ids,
            notify,
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
            .execute_pep_retract(cmd, &factory)
            .await?
            .outcome;
        let retracted = match outcome {
            PepOwnerMutationOutcome::Applied(retracted) => retracted,
            PepOwnerMutationOutcome::NotFound => {
                return Ok(Action::Send(iq_error(id, "item-not-found")));
            }
            PepOwnerMutationOutcome::Forbidden => {
                return Ok(Action::Send(iq_error(id, "forbidden")));
            }
            PepOwnerMutationOutcome::Stale | PepOwnerMutationOutcome::NotSubscribed => {
                return Ok(Action::Send(iq_error(id, "conflict")));
            }
        };
        self.state.pep_telemetry().retracted(retracted);
        Ok(Action::Send(iq_result(id, "")))
    }
}

pub(super) struct PublishOptions {
    pub(super) config: PepNodeConfig,
    pub(super) explicit: bool,
}

pub(super) fn publish_options(
    pubsub: Node<'_, '_>,
    node: &str,
) -> std::result::Result<PublishOptions, ()> {
    let mut config = northstar_pubsub_core::default_pep_node_config(node);
    let Some(options) = pubsub.children().find(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(NS_PUBSUB)
            && child.tag_name().name() == "publish-options"
    }) else {
        return Ok(PublishOptions {
            config,
            explicit: false,
        });
    };
    let form = options
        .children()
        .find(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some(NS_XDATA)
                && child.tag_name().name() == "x"
                && child.attribute("type") == Some("submit")
        })
        .ok_or(())?;
    if xdata_field(form, "FORM_TYPE") != Some("http://jabber.org/protocol/pubsub#publish-options") {
        return Err(());
    }
    let mut seen_fields = HashSet::new();
    for field in form.children().filter(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(NS_XDATA)
            && child.tag_name().name() == "field"
    }) {
        let variable = field.attribute("var").ok_or(())?;
        if !seen_fields.insert(variable) {
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
                    northstar_pubsub_core::PEP_MAX_ITEMS
                } else {
                    value.parse().map_err(|_| ())?
                };
                if !(1..=northstar_pubsub_core::PEP_MAX_ITEMS).contains(&config.max_items) {
                    return Err(());
                }
            }
            "pubsub#persist_items" => {
                config.persist_items = parse_form_bool(child_text(field, "value").ok_or(())?)?;
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
                    parse_form_bool(child_text(field, "value").ok_or(())?)?;
            }
            "pubsub#roster_groups_allowed" => {
                let values = field
                    .children()
                    .filter(|node| {
                        node.is_element()
                            && node.tag_name().name() == "value"
                            && node.tag_name().namespace() == Some(NS_XDATA)
                    })
                    .map(|node| node.text().unwrap_or_default().to_owned())
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
            || node == OMEMO_BUNDLES && config.max_items != northstar_pubsub_core::PEP_MAX_ITEMS)
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
        && (config.access_model != "whitelist"
            || !config.persist_items
            || config.send_last_published_item != "never")
    {
        return Err(());
    }
    Ok(PublishOptions {
        config,
        explicit: true,
    })
}

pub(super) fn normalized_pep_item(item_xml: &str, item_id: &str, rewrite_id: bool) -> String {
    if !rewrite_id {
        return item_xml.to_owned();
    }
    set_root_attribute(item_xml, "id", item_id)
}
