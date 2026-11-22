//! Handle PEP publication and retraction with publication options, event factories, and item normalization.

use super::forms::{decode_pep_config_form, is_pep_config_form};
use super::*;
use northstar_pubsub_core::{
    pep_publish_config_decision, requested_pep_publish_config, PepConfigPatch,
    PepPublishConfigRejection, PepRequestedConfig, PubSubTimeSources,
};

pub(super) struct PepPublishedEventFactory<'a, S> {
    pub(super) session: &'a S,
    pub(super) publisher_full_jid: Option<String>,
    pub(super) node: &'a str,
    pub(super) event: Option<&'a str>,
}

impl<S: PepSession> PepPublishedEventFactory<'_, S> {
    pub(super) fn render(
        &self,
        audience: &PepAudienceSnapshot,
        event: &str,
    ) -> Result<Vec<(String, String)>> {
        pep_audience_messages(
            self.session.pep_audience_routing(),
            self.publisher_full_jid.as_deref(),
            self.node,
            event,
            audience,
        )
    }
}

impl<S: PepSession> PepOutboxFactory for PepPublishedEventFactory<'_, S> {
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

/// Renders the `<items/>` event of changed items on the Bookmarks2 node.
pub fn bookmarks2_items_event(changed_items: &[(&str, &str)]) -> Result<Option<String>> {
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
        ProfilePublishStatus::PreconditionFailed => Some(publish_config_error(
            id,
            PepPublishConfigRejection::PreconditionNotMet,
        )),
        ProfilePublishStatus::MaxItemsExceeded => Some(publish_config_error(
            id,
            PepPublishConfigRejection::MaxItemsExceeded,
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

pub async fn pep_publish<S: PepSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    pubsub: Node<'_, '_>,
    raw: &str,
) -> Result<String> {
    let Some(user) = session.pep_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    let operations = pubsub
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if operations.iter().any(|node| {
        node.tag_name().namespace() != Some(NS_PUBSUB)
            || !matches!(
                node.tag_name().name(),
                "publish" | "publish-options" | "retract" | "create" | "subscribe" | "unsubscribe"
            )
    }) {
        return Ok(iq_error(id, "bad-request"));
    }
    let primary = operations
        .iter()
        .filter(|node| node.tag_name().name() != "publish-options")
        .copied()
        .collect::<Vec<_>>();
    if primary.len() != 1 {
        return Ok(iq_error(id, "bad-request"));
    }
    let primary = primary[0];
    let publish_options_count = operations
        .iter()
        .filter(|node| node.tag_name().name() == "publish-options")
        .count();
    if publish_options_count > 1
        || (primary.tag_name().name() != "publish" && publish_options_count != 0)
    {
        return Ok(iq_error(id, "bad-request"));
    }
    if matches!(primary.tag_name().name(), "publish" | "retract" | "create")
        && iq.attribute("to").is_some_and(|to| {
            !canonical_account_jid(&user.username, session.pep_local_domain()).is_ok_and(|owner| {
                northstar_xmpp_types::jid::canonicalize_bare(to).is_ok_and(|target| target == owner)
            })
        })
    {
        return Ok(iq_error(id, "forbidden"));
    }
    if primary.tag_name().name() == "create" {
        return pep_create(session, id, &user, iq.attribute("to"), primary).await;
    }
    if primary.tag_name().name() == "subscribe" {
        return pep_subscribe(session, id, iq, &user, primary).await;
    }
    if primary.tag_name().name() == "unsubscribe" {
        return pep_unsubscribe(session, id, iq, &user, primary).await;
    }
    if primary.tag_name().name() == "retract" {
        let retract = primary;
        return pep_retract(session, id, &user, retract).await;
    }
    let publish = primary;
    if publish.tag_name().name() != "publish" {
        return Ok(iq_error(id, "bad-request"));
    }
    let Some(node) = publish.attribute("node") else {
        return Ok(iq_error(id, "bad-request"));
    };
    if node.is_empty() || node.len() > 512 {
        return Ok(iq_error(id, "not-acceptable"));
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
        return Ok(iq_error(id, "bad-request"));
    }
    if items.is_empty() {
        return Ok(pep_error(
            id,
            None,
            "modify",
            "bad-request",
            Some("item-required"),
        ));
    }
    if items.len() > northstar_pubsub_core::PEP_MAX_ITEMS as usize {
        return Ok(pep_error(
            id,
            None,
            "modify",
            "not-allowed",
            Some("max-items-exceeded"),
        ));
    }

    let options = match publish_options(pubsub, node) {
        Ok(options) => options,
        Err(()) => {
            return Ok(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("precondition-not-met"),
            ));
        }
    };
    let service = session.pep_pubsub_service();
    let stored_config = service.pep_node(user.id, node).await?;
    let PreparedPepItems {
        normalized,
        assigned_ids,
    } = match prepare_pep_items(
        id,
        node,
        raw,
        items,
        &options,
        stored_config.as_ref(),
        service.time_sources(),
    ) {
        Ok(items) => items,
        Err(error) => return Ok(error),
    };
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
    let quotas = session.pep_quotas();
    let mut avatar_presence = AvatarPresenceUpdate::Unchanged;
    let (outcome, _content_changed) = if node == AVATAR_METADATA {
        let event = profile_event
            .as_deref()
            .expect("non-empty avatar metadata has a prepared event");
        let publisher_full_jid = session.pep_full_jid().map(str::to_owned);
        let result = session
            .pep_pubsub_service()
            .publish_avatar_metadata(
                session.pep_profile_service(),
                PepProfileWrite {
                    user_id: user.id,
                    auth_generation: user.auth_generation,
                    connection_id: session.pep_connection_id(),
                    node,
                    requested: &options.config,
                    enforce_preconditions: options.explicit,
                    items: &borrowed,
                    max_nodes: quotas.max_nodes,
                    max_storage_bytes: quotas.max_storage_bytes,
                },
                &move |audience: &ProfileAudienceSnapshot| {
                    profile_audience_messages(
                        session.pep_audience_routing(),
                        publisher_full_jid.as_deref(),
                        AVATAR_METADATA,
                        event,
                        audience,
                    )
                },
            )
            .await?;
        if let Some(error) = profile_publish_error(id, result.status) {
            return Ok(error);
        }
        avatar_presence = result.avatar_presence;
        (None, result.content_changed)
    } else if matches!(node, AVATAR_DATA | VCARD4) {
        let event = profile_event
            .as_deref()
            .expect("non-empty profile publication has a prepared event");
        let publisher_full_jid = session.pep_full_jid().map(str::to_owned);
        let result: ProfilePublishResult = session
            .pep_pubsub_service()
            .publish_profile_items(
                session.pep_profile_service(),
                PepProfileWrite {
                    user_id: user.id,
                    auth_generation: user.auth_generation,
                    connection_id: session.pep_connection_id(),
                    node,
                    requested: &options.config,
                    enforce_preconditions: options.explicit,
                    items: &borrowed,
                    max_nodes: quotas.max_nodes,
                    max_storage_bytes: quotas.max_storage_bytes,
                },
                &move |audience: &ProfileAudienceSnapshot| {
                    profile_audience_messages(
                        session.pep_audience_routing(),
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
            return Ok(error);
        }
        (None, result.content_changed)
    } else {
        let factory = PepPublishedEventFactory {
            session,
            publisher_full_jid: session.pep_full_jid().map(str::to_owned),
            node,
            event: generic_event.as_deref(),
        };
        let result = session
            .pep_pubsub_service()
            .publish_pep_items(
                PepPublishItemsCommand::new(
                    PepPublishWrite {
                        user_id: user.id,
                        username: &user.username,
                        auth_generation: user.auth_generation,
                        connection_id: session.pep_connection_id(),
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
            return Ok(iq_error(id, "not-authorized"));
        }
        Some(PepPublishOutcome::PreconditionFailed) => {
            return Ok(publish_config_error(
                id,
                PepPublishConfigRejection::PreconditionNotMet,
            ));
        }
        Some(PepPublishOutcome::MaxItemsExceeded) => {
            return Ok(publish_config_error(
                id,
                PepPublishConfigRejection::MaxItemsExceeded,
            ));
        }
        Some(PepPublishOutcome::QuotaExceeded) => {
            return Ok(pep_error(id, None, "wait", "resource-constraint", None));
        }
    }
    if let AvatarPresenceUpdate::Changed(hash) = avatar_presence {
        session.pep_refresh_avatar_presence(
            &canonical_account_jid(&user.username, session.pep_local_domain())?,
            hash.as_deref(),
        );
    }
    session.pep_record_published(normalized.len() as u64);

    if assigned_ids.is_empty() {
        Ok(iq_result(id, ""))
    } else {
        let mut publish = XmlElement::new("publish").attr("node", node);
        for item_id in &assigned_ids {
            publish.push_child(XmlElement::new("item").attr("id", item_id));
        }
        let payload = XmlElement::namespaced("pubsub", NS_PUBSUB)
            .child(publish)
            .finish();
        Ok(iq_result(id, &payload))
    }
}

pub(super) async fn pep_retract<S: PepSession>(
    session: &S,
    id: &str,
    user: &PubSubAccount,
    retract: Node<'_, '_>,
) -> Result<String> {
    let Some(node) = retract.attribute("node") else {
        return Ok(iq_error(id, "bad-request"));
    };
    if node.is_empty() || node.len() > 512 {
        return Ok(iq_error(id, "not-acceptable"));
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
    if retract.children().filter(Node::is_element).count() != item_ids.as_ref().map_or(0, Vec::len)
    {
        return Ok(iq_error(id, "bad-request"));
    }
    let Some(item_ids) = item_ids.filter(|ids| {
        !ids.is_empty()
            && ids.len() <= northstar_pubsub_core::PEP_MAX_ITEMS as usize
            && ids
                .iter()
                .all(|item_id| !item_id.is_empty() && item_id.len() <= 1024)
    }) else {
        return Ok(pep_error(
            id,
            None,
            "modify",
            "bad-request",
            Some("item-required"),
        ));
    };
    let mut canonical_ids = Vec::with_capacity(item_ids.len());
    let mut unique_ids = HashSet::new();
    for item_id in item_ids {
        let Ok(item_id) = northstar_pubsub_core::canonical_profile_item_id(node, item_id) else {
            return Ok(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("invalid-payload"),
            ));
        };
        if !unique_ids.insert(item_id.clone()) {
            return Ok(iq_error(id, "bad-request"));
        }
        canonical_ids.push(item_id);
    }
    let item_ids = canonical_ids.iter().map(String::as_str).collect::<Vec<_>>();
    let notify =
        retract.attribute("notify") != Some("false") && retract.attribute("notify") != Some("0");
    let mut event = XmlElement::new("items").attr("node", node);
    for item_id in &item_ids {
        event.push_child(XmlElement::new("retract").attr("id", item_id));
    }
    let event = event.finish();
    let publisher_full_jid = session.pep_full_jid().map(str::to_owned);
    let owner = user.clone();
    let cmd = PepRetractCommand::from(PepRetractWrite {
        owner: &owner,
        connection_id: session.pep_connection_id(),
        node,
        item_ids: &canonical_ids,
        notify,
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
        .execute_pep_retract(cmd, &factory)
        .await?
        .outcome;
    let retracted = match outcome {
        PepOwnerMutationOutcome::Applied(retracted) => retracted,
        PepOwnerMutationOutcome::NotFound => {
            return Ok(iq_error(id, "item-not-found"));
        }
        PepOwnerMutationOutcome::Forbidden => {
            return Ok(iq_error(id, "forbidden"));
        }
        PepOwnerMutationOutcome::Stale | PepOwnerMutationOutcome::NotSubscribed => {
            return Ok(iq_error(id, "conflict"));
        }
    };
    session.pep_record_retracted(retracted);
    Ok(iq_result(id, ""))
}

fn decode_publish_options(pubsub: Node<'_, '_>) -> std::result::Result<Option<PepConfigPatch>, ()> {
    let Some(options) = pubsub.children().find(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(NS_PUBSUB)
            && child.tag_name().name() == "publish-options"
    }) else {
        return Ok(None);
    };
    let form = options
        .children()
        .find(|child| is_pep_config_form(*child) && child.attribute("type") == Some("submit"))
        .ok_or(())?;
    decode_pep_config_form(form, "http://jabber.org/protocol/pubsub#publish-options").map(Some)
}

pub(super) fn publish_options(
    pubsub: Node<'_, '_>,
    node: &str,
) -> std::result::Result<PepRequestedConfig, ()> {
    let patch = decode_publish_options(pubsub)?;
    requested_pep_publish_config(node, patch.as_ref()).map_err(|_| ())
}

struct PreparedPepItems {
    normalized: Vec<(String, String)>,
    assigned_ids: Vec<String>,
}

fn prepare_pep_items(
    id: &str,
    node: &str,
    raw: &str,
    items: Vec<Node<'_, '_>>,
    options: &PepRequestedConfig,
    stored_config: Option<&PepNodeConfig>,
    time_sources: &PubSubTimeSources,
) -> std::result::Result<PreparedPepItems, String> {
    // Reject explicit mismatches before decoding payloads without acquiring the owner lock.
    // The decision against the locked configuration is authoritative and uses the same function.
    if let Some(rejection) =
        pep_publish_config_decision(&options.config, options.explicit, stored_config, 0)
    {
        return Err(publish_config_error(id, rejection));
    }
    let mut normalized = Vec::with_capacity(items.len());
    let mut assigned_ids = Vec::new();
    let mut unique_ids = HashSet::new();
    for item in items {
        let generated = item.attribute("id").is_none();
        let wire_item_id = item
            .attribute("id")
            .map(str::to_owned)
            .unwrap_or_else(|| time_sources.new_uuid().to_string());
        let item_id = match northstar_pubsub_core::canonical_profile_item_id(node, &wire_item_id) {
            Ok(item_id) => item_id,
            Err(_) => {
                return Err(pep_error(
                    id,
                    None,
                    "modify",
                    "bad-request",
                    Some("invalid-payload"),
                ));
            }
        };
        if item_id.is_empty()
            || item_id.len() > 1024
            || !unique_ids.insert(item_id.clone())
            || !valid_pep_payload(node, &item_id, item)
        {
            return Err(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("invalid-payload"),
            ));
        }
        let range = item.range();
        let item_xml =
            normalized_pep_item(&raw[range], &item_id, generated || wire_item_id != item_id);
        if item_xml.len() > 512 * 1024 {
            return Err(pep_error(
                id,
                None,
                "modify",
                "not-acceptable",
                Some("payload-too-big"),
            ));
        }
        normalized.push((item_id.clone(), item_xml));
        if generated {
            assigned_ids.push(item_id);
        }
    }
    if let Some(rejection) = pep_publish_config_decision(
        &options.config,
        options.explicit,
        stored_config,
        normalized.len(),
    ) {
        return Err(publish_config_error(id, rejection));
    }
    Ok(PreparedPepItems {
        normalized,
        assigned_ids,
    })
}

fn publish_config_error(id: &str, rejection: PepPublishConfigRejection) -> String {
    match rejection {
        PepPublishConfigRejection::PreconditionNotMet => {
            pep_error(id, None, "cancel", "conflict", Some("precondition-not-met"))
        }
        PepPublishConfigRejection::MaxItemsExceeded => pep_error(
            id,
            None,
            "modify",
            "not-allowed",
            Some("max-items-exceeded"),
        ),
    }
}

pub(super) fn normalized_pep_item(item_xml: &str, item_id: &str, rewrite_id: bool) -> String {
    if !rewrite_id {
        return item_xml.to_owned();
    }
    set_root_attribute(item_xml, "id", item_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn explicit_config_mismatch_wins_over_an_invalid_payload() {
        let raw = "<pubsub xmlns='http://jabber.org/protocol/pubsub'>
            <publish node='example'><item id='broken'/></publish>
            <publish-options><x xmlns='jabber:x:data' type='submit'>
                <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>
                <field var='pubsub#access_model'><value>open</value></field>
            </x></publish-options>
        </pubsub>";
        let document = Document::parse(raw).unwrap();
        let pubsub = document.root_element();
        let item = pubsub
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "item")
            .unwrap();
        let options = publish_options(pubsub, "example").unwrap();
        let stored = northstar_pubsub_core::default_pep_node_config("example");
        for (actual, error_type, condition, detail) in [
            (&stored, "cancel", "conflict", "precondition-not-met"),
            (&options.config, "modify", "bad-request", "invalid-payload"),
        ] {
            let Err(reply) = prepare_pep_items(
                "test",
                "example",
                raw,
                vec![item],
                &options,
                Some(actual),
                &PubSubTimeSources::default(),
            ) else {
                panic!("expected the publish to be rejected");
            };
            let reply = Document::parse(&reply).unwrap();
            let iq = reply.root_element();
            assert_eq!(iq.attribute("type"), Some("error"));
            let error = iq.first_element_child().unwrap();
            assert_eq!(error.attribute("type"), Some(error_type));
            let children = error
                .children()
                .filter(Node::is_element)
                .collect::<Vec<_>>();
            assert_eq!(children.len(), 2);
            assert_eq!(children[0].tag_name().name(), condition);
            assert_eq!(
                children[0].tag_name().namespace(),
                Some("urn:ietf:params:xml:ns:xmpp-stanzas")
            );
            assert_eq!(children[1].tag_name().name(), detail);
            assert_eq!(
                children[1].tag_name().namespace(),
                Some("http://jabber.org/protocol/pubsub#errors")
            );
        }
    }
}
