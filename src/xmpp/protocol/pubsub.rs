use super::{Action, ProtocolSession};
use crate::mam_pubsub_parsing::{self, PubSubNamespace, PubSubRsmRequest};
use crate::services::privacy::PrivacyStanzaKind;
use crate::services::pubsub::{
    ClaimedPubSubOutboxDelivery, CollectionUpdateOutcome, CreateNodeOutcome, OwnerMutationOutcome,
    PepOutboxAuthorizationOutcome, PubSubConfigOutcome, PubSubConfigureNodeCommand,
    PubSubConfigureNodeWrite, PubSubCreateNodeCommand, PubSubCreateNodeWrite,
    PubSubDeleteNodeCommand, PubSubDeleteNodeWrite, PubSubItem, PubSubNode, PubSubNodeConfig,
    PubSubOutboxDeliveryKind, PubSubPublishCommand, PubSubPublishOutcome, PubSubPublishWrite,
    PubSubPurgeNodeCommand, PubSubPurgeNodeWrite, PubSubRetractCommand, PubSubRetractOutcome,
    PubSubRetractWrite, PubSubSetAffiliationsCommand, PubSubSetAffiliationsWrite,
    PubSubSetSubscriptionsCommand, PubSubSetSubscriptionsWrite, PubSubSubscribeCommand,
    PubSubSubscribeOutcome, PubSubSubscribeWrite, PubSubSubscription, PubSubSubscriptionOptions,
    PubSubUnsubscribeCommand, PubSubUnsubscribeOutcome, PubSubUnsubscribeWrite,
    SetAffiliationsOutcome, SetSubscriptionsOutcome, SubscriptionOptionsOutcome,
};
use crate::state::AppState;
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
use roxmltree::Node;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Debug)]
struct DiscoItem {
    node: String,
    title: Option<String>,
    published_item: bool,
}

const NS_PUBSUB: &str = northstar_xep_0060::NS_PUBSUB;
const NS_PUBSUB_OWNER: &str = northstar_xep_0060::NS_PUBSUB_OWNER;
const NS_PUBSUB_EVENT: &str = northstar_xep_0060::NS_PUBSUB_EVENT;
const NS_PUBSUB_ERRORS: &str = northstar_xep_0060::NS_PUBSUB_ERRORS;
const NS_DATA: &str = northstar_xep_0060::NS_DATA;
const NS_RSM: &str = northstar_xep_0060::NS_RSM;
const NODE_CONFIG_FORM: &str = northstar_xep_0060::NODE_CONFIG_FORM;
const PUBLISH_OPTIONS_FORM: &str = northstar_xep_0060::PUBLISH_OPTIONS_FORM;
const SERVICE_FEATURES: &[&str] = northstar_xep_0060::SERVICE_FEATURES;
const SUBSCRIBE_AUTH_FORM: &str = northstar_xep_0060::SUBSCRIBE_AUTH_FORM;
const SUBSCRIBE_OPTIONS_FORM: &str = northstar_xep_0060::SUBSCRIBE_OPTIONS_FORM;
const MAX_PUBLISH_ITEMS: usize = northstar_xep_0060::MAX_PUBLISH_ITEMS;
const MAX_ITEM_XML_BYTES: usize = northstar_xep_0060::MAX_ITEM_XML_BYTES;
const MAX_PUBLISH_XML_BYTES: usize = northstar_xep_0060::MAX_PUBLISH_XML_BYTES;
const MAX_TITLE_BYTES: usize = northstar_xep_0060::MAX_TITLE_BYTES;
const MAX_DESCRIPTION_BYTES: usize = northstar_xep_0060::MAX_DESCRIPTION_BYTES;
const MAX_SUBSCRIPTION_LEASE_DAYS: i64 = northstar_xep_0060::MAX_SUBSCRIPTION_LEASE_DAYS;

#[derive(Debug)]
pub(crate) enum PubSubReply {
    Result(String),
    Error(&'static str),
    ExtendedError(PubSubError),
}

pub(crate) type PubSubError = northstar_xep_0060::PubSubError;

pub(crate) fn error_payload(error: &PubSubReply) -> Option<(&'static str, String)> {
    match error {
        PubSubReply::Result(_) => None,
        PubSubReply::Error(condition) => Some((stanza_error_type(condition), String::new())),
        PubSubReply::ExtendedError(error) => {
            let extra = error
                .pubsub_condition
                .map(|specific| {
                    dynamic_protocol_element(specific, NS_PUBSUB_ERRORS)
                        .optional_attr("feature", error.feature)
                        .finish()
                })
                .unwrap_or_default();
            Some((stanza_error_type(error.condition), extra))
        }
    }
}

pub(crate) fn error_condition(error: &PubSubReply) -> Option<&'static str> {
    match error {
        PubSubReply::Result(_) => None,
        PubSubReply::Error(condition) => Some(condition),
        PubSubReply::ExtendedError(error) => Some(error.condition),
    }
}

fn node_config_parse_error(condition: &'static str) -> PubSubReply {
    if condition == "unsupported-access-model" {
        PubSubReply::ExtendedError(PubSubError::new(
            "not-acceptable",
            "unsupported-access-model",
        ))
    } else {
        PubSubReply::Error(condition)
    }
}

fn invalid_subscription_options() -> PubSubReply {
    PubSubReply::ExtendedError(PubSubError::new("bad-request", "invalid-options"))
}

fn stanza_error_type(condition: &str) -> &'static str {
    northstar_xep_0060::stanza_error_type_for_condition(condition).as_str()
}

fn pubsub_iq_error(id: &str, from: &str, reply: &PubSubReply) -> String {
    let condition = error_condition(reply).unwrap_or("undefined-condition");
    let (kind, _) = error_payload(reply).unwrap_or(("cancel", String::new()));
    let mut stanza_error = XmlElement::new("error")
        .attr("type", kind)
        .child(stanza_condition_element(reply, condition));
    if let PubSubReply::ExtendedError(error) = reply {
        if let Some(specific) = error.pubsub_condition {
            stanza_error.push_child(
                dynamic_protocol_element(specific, NS_PUBSUB_ERRORS)
                    .optional_attr("feature", error.feature),
            );
        }
    }
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("id", id)
        .child(stanza_error)
        .finish()
}

pub(crate) fn pubsub_s2s_iq_error(id: &str, from: &str, to: &str, reply: &PubSubReply) -> String {
    let condition = error_condition(reply).unwrap_or("undefined-condition");
    let (kind, _) = error_payload(reply).unwrap_or(("cancel", String::new()));
    let mut stanza_error = XmlElement::new("error")
        .attr("type", kind)
        .child(stanza_condition_element(reply, condition));
    if let PubSubReply::ExtendedError(error) = reply {
        if let Some(specific) = error.pubsub_condition {
            stanza_error.push_child(
                dynamic_protocol_element(specific, NS_PUBSUB_ERRORS)
                    .optional_attr("feature", error.feature),
            );
        }
    }
    XmlElement::namespaced("iq", "jabber:server")
        .attr("type", "error")
        .attr("id", id)
        .attr("from", from)
        .attr("to", to)
        .child(stanza_error)
        .finish()
}

fn dynamic_protocol_element(name: &str, namespace: &'static str) -> XmlElement {
    // Error/collection element names come from finite protocol enums. If a
    // future caller violates that invariant, fail closed with a legal stanza
    // condition instead of emitting an unchecked QName.
    match XmlElement::dynamic(name) {
        Ok(element) => element.attr("xmlns", namespace),
        Err(_) => {
            XmlElement::namespaced("undefined-condition", "urn:ietf:params:xml:ns:xmpp-stanzas")
        }
    }
}

fn stanza_condition_element(reply: &PubSubReply, condition: &str) -> XmlElement {
    let mut element = dynamic_protocol_element(condition, "urn:ietf:params:xml:ns:xmpp-stanzas");
    if let PubSubReply::ExtendedError(PubSubError {
        redirect: Some(uri),
        ..
    }) = reply
    {
        element = element.text(uri.to_owned());
    }
    element
}

pub(crate) fn service_disco_payload(state: &AppState) -> String {
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
        .child(
            XmlElement::new("identity")
                .attr("category", "pubsub")
                .attr("type", "service")
                .attr(
                    "name",
                    format!("{} PubSub Service", state.config.server_name),
                ),
        )
        .child(XmlElement::new("feature").attr("var", NS_PUBSUB));
    for feature in SERVICE_FEATURES {
        query.push_child(XmlElement::new("feature").attr(
            "var",
            format!("http://jabber.org/protocol/pubsub#{feature}"),
        ));
    }
    query.finish()
}

pub(crate) async fn federated_disco_info(
    state: &AppState,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<PubSubReply> {
    let Some(node_name) = requested_node else {
        return Ok(PubSubReply::Result(service_disco_payload(state)));
    };
    if node_name == "serverinfo" {
        return Ok(PubSubReply::Result(
            XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
                .attr("node", "serverinfo")
                .child(
                    XmlElement::new("identity")
                        .attr("category", "pubsub")
                        .attr("type", "leaf"),
                )
                .child(XmlElement::new("feature").attr("var", NS_PUBSUB))
                .child(
                    XmlElement::new("feature")
                        .attr("var", "http://jabber.org/protocol/pubsub#retrieve-items"),
                )
                .child(XmlElement::new("feature").attr("var", "urn:xmpp:serverinfo:0"))
                .finish(),
        ));
    }
    let Some(node) = state.pubsub_service().get_node(node_name).await? else {
        return missing_node_reply(state, node_name).await;
    };
    if !can_retrieve(state, &node, &normalized_bare(requester)?).await? {
        return Ok(PubSubReply::Error("forbidden"));
    }
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
        .attr("node", node_name)
        .child(
            XmlElement::new("identity")
                .attr("category", "pubsub")
                .attr("type", &node.node_type),
        )
        .child(XmlElement::new("feature").attr("var", NS_PUBSUB));
    if node.persist_items && node.node_type == "leaf" {
        query.push_child(
            XmlElement::new("feature")
                .attr("var", "http://jabber.org/protocol/pubsub#persistent-items"),
        );
    }
    query.push_child(
        XmlElement::new("feature").attr("var", "http://jabber.org/protocol/pubsub#retrieve-items"),
    );
    query.push_validated_fragment(&node_metadata_form(state, &node).await?)?;
    Ok(PubSubReply::Result(query.finish()))
}

pub(crate) async fn federated_disco_items(
    state: &AppState,
    requester: &str,
    request: Node<'_, '_>,
) -> Result<PubSubReply> {
    if request
        .attributes()
        .any(|attribute| attribute.name() != "node")
        || request
            .attribute("node")
            .is_some_and(|node| valid_node_id(Some(node)).is_none())
        || request
            .children()
            .filter(|child| child.is_text())
            .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Ok(PubSubReply::Error("bad-request"));
    }
    let mut rsm = None;
    for child in request.children().filter(Node::is_element) {
        if rsm.is_some() {
            return Ok(PubSubReply::Error("bad-request"));
        }
        rsm = match parse_pubsub_rsm(child) {
            Ok(parsed) => Some(parsed),
            Err(error) => return Ok(error),
        };
    }
    let requested_node = request.attribute("node");
    let service = pubsub_domain(state);
    let requester_full = normalized_jid(requester)?;
    let requester = normalized_bare(&requester_full)?;
    if requested_node.is_none() {
        return root_disco_items(state, &service, &requester, rsm.as_ref()).await;
    }
    let mut visible = Vec::new();
    if let Some(node_name) = requested_node {
        if node_name == "serverinfo" {
            // The synthetic serverinfo node has one current PubSub item, but
            // its data is retrieved via XEP-0060 rather than disco#items.
        } else {
            let Some(node) = state.pubsub_service().get_node(node_name).await? else {
                return missing_node_reply(state, node_name).await;
            };
            if !can_retrieve(state, &node, &requester).await? {
                return Ok(PubSubReply::Error("forbidden"));
            }
            if node.node_type == "collection" {
                for child in state.pubsub_service().collection_children(node.id).await? {
                    // XEP-0248 defines collection visibility using the
                    // collection's access model, not each child's model.
                    visible.push(DiscoItem {
                        node: child.node,
                        title: child.title,
                        published_item: false,
                    });
                }
            } else {
                for item_id in state.pubsub_service().item_ids_for_disco(node.id).await? {
                    visible.push(DiscoItem {
                        node: item_id,
                        title: None,
                        published_item: true,
                    });
                }
            }
        }
    }
    let (visible, rsm_xml) = if let Some(rsm) = &rsm {
        match disco_rsm_page(visible, rsm, 100) {
            Ok(page) => page,
            Err(error) => return Ok(error),
        }
    } else {
        (visible, String::new())
    };
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items")
        .optional_attr("node", requested_node);
    for item in visible {
        query.push_child(disco_item_element(&service, &item));
    }
    query.push_validated_fragment(&rsm_xml)?;
    Ok(PubSubReply::Result(query.finish()))
}

async fn root_disco_items(
    state: &AppState,
    service: &str,
    requester: &str,
    rsm: Option<&PubSubRsmRequest>,
) -> Result<PubSubReply> {
    let total = usize::try_from(
        state
            .pubsub_service()
            .visible_root_disco_count(requester)
            .await?,
    )
    .map_err(|_| anyhow::anyhow!("visible PubSub root count exceeded platform bounds"))?;
    let max = rsm
        .and_then(|request| request.max)
        .unwrap_or(100)
        .min(1_000);
    let cursor = rsm.and_then(|request| {
        request
            .after
            .as_deref()
            .or_else(|| request.before.as_ref().and_then(|value| value.as_deref()))
    });
    if let Some(cursor) = cursor {
        if !state
            .pubsub_service()
            .visible_root_disco_cursor_exists(requester, cursor)
            .await?
        {
            return Ok(PubSubReply::Error("item-not-found"));
        }
    }
    let backwards = rsm.is_some_and(|request| request.before.is_some());
    let mut visible = if max == 0 {
        Vec::new()
    } else {
        state
            .pubsub_service()
            .visible_root_disco_page(requester, cursor, backwards, max as i64)
            .await?
            .into_iter()
            .map(|node| DiscoItem {
                node: node.node,
                title: node.title,
                published_item: false,
            })
            .collect::<Vec<_>>()
    };
    if backwards {
        visible.reverse();
    }
    let first_index = match visible.first() {
        Some(first) => usize::try_from(
            state
                .pubsub_service()
                .visible_root_disco_index(requester, &first.node)
                .await?,
        )
        .map_err(|_| anyhow::anyhow!("visible PubSub root index exceeded platform bounds"))?,
        None => 0,
    };
    // A service-side default limit is always finite. If an old client omitted
    // RSM and the result was truncated, include the notation recommended by
    // XEP-0059/XEP-0060 so it can discover and continue the full set.
    let rsm_xml = if rsm.is_some() || visible.len() < total {
        rsm_set_element(
            visible
                .first()
                .map(|item| (first_index, item.node.as_str())),
            visible.last().map(|item| item.node.as_str()),
            total,
        )
        .finish()
    } else {
        String::new()
    };
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
    for item in &visible {
        query.push_child(disco_item_element(service, item));
    }
    query.push_validated_fragment(&rsm_xml)?;
    Ok(PubSubReply::Result(query.finish()))
}

#[cfg(test)]
fn disco_item_xml(service: &str, item: &DiscoItem) -> String {
    disco_item_element(service, item).finish()
}

fn disco_item_element(service: &str, item: &DiscoItem) -> XmlElement {
    if item.published_item {
        // XEP-0060 section 5.5: published ItemIDs are exposed in the disco
        // item's `name`; a leaf item MUST NOT carry a `node` attribute.
        return XmlElement::new("item")
            .attr("jid", service)
            .attr("name", &item.node);
    }
    XmlElement::new("item")
        .attr("jid", service)
        .attr("node", &item.node)
        .optional_attr("name", item.title.as_deref())
}

fn rsm_set_element(first: Option<(usize, &str)>, last: Option<&str>, total: usize) -> XmlElement {
    let mut set = XmlElement::namespaced("set", NS_RSM);
    if let Some((index, value)) = first {
        set.push_child(
            XmlElement::new("first")
                .attr("index", index)
                .text(value.to_owned()),
        );
    }
    if let Some(value) = last {
        set.push_child(XmlElement::new("last").text(value.to_owned()));
    }
    set.push_child(XmlElement::new("count").text(total.to_string()));
    set
}

fn data_field_element(
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
    pub(crate) fn pubsub_domain(&self) -> String {
        pubsub_domain(&self.state)
    }

    pub(crate) async fn pubsub_iq_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "get", child).await
    }

    pub(crate) async fn pubsub_iq_set(
        &self,
        id: &str,
        child: Node<'_, '_>,
        _to: &str,
    ) -> Result<Action> {
        self.pubsub_request(id, "set", child).await
    }

    pub(crate) async fn pubsub_owner_get(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "get", child).await
    }

    pub(crate) async fn pubsub_owner_set(&self, id: &str, child: Node<'_, '_>) -> Result<Action> {
        self.pubsub_request(id, "set", child).await
    }

    async fn pubsub_request(&self, id: &str, kind: &str, child: Node<'_, '_>) -> Result<Action> {
        let service = self.pubsub_domain();
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error_from(id, &service, "not-authorized")));
        };
        let reply = match handle_request(&self.state, full_jid, kind, child).await {
            Ok(reply) => reply,
            Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
                PubSubReply::Error("resource-constraint")
            }
            Err(error) => return Err(error),
        };
        Ok(match reply {
            PubSubReply::Result(payload) => Action::Send(iq_result_from(id, &service, &payload)),
            reply @ (PubSubReply::Error(_) | PubSubReply::ExtendedError(_)) => {
                Action::Send(pubsub_iq_error(id, &service, &reply))
            }
        })
    }

    pub(crate) async fn pubsub_authorization_response(&self, root: Node<'_, '_>) -> Result<bool> {
        let Some(to) = root.attribute("to") else {
            return Ok(false);
        };
        if crate::jid::canonicalize_bare(to).ok().as_deref()
            != crate::jid::canonicalize_bare(&self.pubsub_domain())
                .ok()
                .as_deref()
        {
            return Ok(false);
        }
        let Some(requester) = self.full_jid.as_deref() else {
            return Ok(true);
        };
        handle_authorization_response(&self.state, requester, root).await?;
        Ok(true)
    }

    /// XEP-0060 `send_last_published_item=on_sub_and_presence` delivery.
    /// Presence addressed to the service is consumed by the service and is
    /// never routed to a similarly named local account.
    pub(crate) async fn pubsub_presence(&mut self, kind: &str, from: &str) -> Result<Action> {
        if kind != "available" {
            return Ok(Action::None);
        }
        let requester_full = normalized_jid(from)?;
        let requester_id = self
            .authenticated
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("PubSub presence requires an authenticated account"))?
            .id;
        let active_privacy_list = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let connection_id = self.connection_id;
        let state = self.state.clone();
        let outbound = self.outbound.clone();
        let show = match self.show.load(std::sync::atomic::Ordering::Relaxed) {
            2 => "away",
            3 => "chat",
            4 => "dnd",
            5 => "xa",
            _ => "online",
        };
        self.defer_after_transport("pubsub-last-item-replay", async move {
            if let Err(error) = deliver_last_items_on_presence(
                state,
                outbound,
                requester_id,
                active_privacy_list,
                connection_id,
                requester_full,
                show,
            )
            .await
            {
                tracing::error!(
                    ?error,
                    "failed PubSub last-item replay on available presence"
                );
            }
        })?;
        Ok(Action::None)
    }
}

pub(crate) async fn handle_request(
    state: &AppState,
    requester: &str,
    kind: &str,
    child: Node<'_, '_>,
) -> Result<PubSubReply> {
    let parsed = match mam_pubsub_parsing::parse_pubsub_envelope(child, kind) {
        Ok(parsed) => parsed,
        Err(condition) => return Ok(PubSubReply::Error(condition)),
    };
    match (parsed.namespace, kind) {
        (PubSubNamespace::Entity, "get") => {
            handle_entity_get(state, requester, parsed.operations).await
        }
        (PubSubNamespace::Entity, "set") => {
            handle_entity_set(state, requester, parsed.operations).await
        }
        (PubSubNamespace::Owner, "get") => {
            handle_owner_get(state, requester, parsed.operations).await
        }
        (PubSubNamespace::Owner, "set") => {
            handle_owner_set(state, requester, parsed.operations).await
        }
        _ => unreachable!("shared PubSub envelope parser validates IQ kinds"),
    }
}

async fn handle_entity_get(
    state: &AppState,
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
                    match state.pubsub_service().get_node(name).await? {
                        Some(node) => Some(node),
                        None => return missing_node_reply(state, name).await,
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
            let Some(node) = state.pubsub_service().get_node(node_name).await? else {
                return missing_node_reply(state, node_name).await;
            };
            let Some(subscription) = state
                .pubsub_service()
                .get_subscription(node.id, &requested_jid)
                .await?
            else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "unexpected-request",
                    "not-subscribed",
                )));
            };
            if subscription.is_expired() {
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
                    .child(XmlElement::new("domain").attr("name", &state.config.domain));
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
            let Some(node) = state.pubsub_service().get_node(node_name).await? else {
                return missing_node_reply(state, node_name).await;
            };
            let affiliation = state
                .pubsub_service()
                .get_node_affiliation(node.id, &requester)
                .await?;
            let subscriptions = state
                .pubsub_service()
                .subscriptions_for_jid(&requester_full, Some(node_name))
                .await?
                .into_iter()
                .filter(PubSubSubscription::is_active)
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
                let visible_items = state
                    .pubsub_service()
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
            let all_stored = state
                .pubsub_service()
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
                if state.pubsub_service().get_node(name).await?.is_none() {
                    return missing_node_reply(state, name).await;
                }
            }
            let subscriptions = state
                .pubsub_service()
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
                if state.pubsub_service().get_node(name).await?.is_none() {
                    return missing_node_reply(state, name).await;
                }
            }
            let affiliations = state
                .pubsub_service()
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

async fn handle_entity_set(
    state: &AppState,
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
            let Some(node) = state.pubsub_service().get_node(node_name).await? else {
                return missing_node_reply(state, node_name).await;
            };
            let Some(subscription) = state
                .pubsub_service()
                .get_subscription(node.id, &requested_jid)
                .await?
            else {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "unexpected-request",
                    "not-subscribed",
                )));
            };
            if subscription.is_expired() {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "unexpected-request",
                    "not-subscribed",
                )));
            }
            let expected_subid = primary.attribute("subid");
            if expected_subid.is_some_and(|subid| subid != subscription.subid) {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "not-acceptable",
                    "invalid-subid",
                )));
            }
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
            if crate::jid::CanonicalJid::parse_bare(&requester)?.domainpart() != state.config.domain
                && !all_show_values(&options.show_values)
            {
                return Ok(invalid_subscription_options());
            }
            match state
                .pubsub_service()
                .update_subscription_options_checked(
                    node.id,
                    &requester,
                    &requested_jid,
                    expected_subid,
                    &options,
                )
                .await?
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
                max_nodes_per_owner: state.config.pubsub_max_nodes_per_owner,
            });
            match state
                .pubsub_service()
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
            let cmd = PubSubPublishCommand::from(PubSubPublishWrite {
                publisher_jid: &requester,
                node: node_name,
                items: &items,
                publish_options: publish_options.as_ref(),
                max_storage_bytes_per_owner: state.config.pubsub_max_storage_bytes_per_owner,
                max_nodes_per_owner: state.config.pubsub_max_nodes_per_owner,
            });
            let result = state.pubsub_service().execute_pubsub_publish(cmd).await?;
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
            let Some(node) = state.pubsub_service().get_node(node_name).await? else {
                return missing_node_reply(state, node_name).await;
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
                if crate::jid::CanonicalJid::parse_bare(&requester)?.domainpart()
                    != state.config.domain
                    && !all_show_values(&parsed.show_values)
                {
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
            let result = state.pubsub_service().execute_pubsub_subscribe(cmd).await?;
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
                PubSubSubscribeOutcome::NotFound => missing_node_reply(state, node_name).await,
                PubSubSubscribeOutcome::Forbidden => Ok(PubSubReply::Error("forbidden")),
                PubSubSubscribeOutcome::ClosedNode => Ok(PubSubReply::ExtendedError(
                    PubSubError::new("not-allowed", "closed-node"),
                )),
                PubSubSubscribeOutcome::PreconditionFailed => Ok(PubSubReply::Error("conflict")),
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
            let result = state
                .pubsub_service()
                .execute_pubsub_unsubscribe(cmd)
                .await?;
            match result.outcome {
                PubSubUnsubscribeOutcome::Unsubscribed { subid } => Ok(PubSubReply::Result(
                    subscription_payload(node_name, &requested_jid, "none", subid.as_deref(), None),
                )),
                PubSubUnsubscribeOutcome::NotFound => missing_node_reply(state, node_name).await,
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
            let result = state.pubsub_service().execute_pubsub_retract(cmd).await?;
            match result.outcome {
                PubSubRetractOutcome::Retracted => {}
                PubSubRetractOutcome::NotFound => {
                    return missing_node_reply(state, node_name).await
                }
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

async fn handle_owner_get(
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
    let Some(node) = state.pubsub_service().get_node(node_name).await? else {
        return missing_node_reply(state, node_name).await;
    };
    if !is_owner(state, node.id, &requester).await? {
        return Ok(PubSubReply::Error("forbidden"));
    }
    match operation.tag_name().name() {
        "configure" => {
            if !has_only_attributes(operation, &["node"]) || !has_no_element_content(operation) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let mut config = node.config();
            config.collections = state
                .pubsub_service()
                .collection_parents(node.id)
                .await?
                .into_iter()
                .map(|node| node.node)
                .collect();
            config.children = state
                .pubsub_service()
                .collection_children(node.id)
                .await?
                .into_iter()
                .map(|node| node.node)
                .collect();
            let form = node_config_form(&config, "form");
            let mut configure = XmlElement::new("configure").attr("node", node_name);
            configure.push_validated_fragment(&form)?;
            Ok(PubSubReply::Result(
                XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
                    .child(configure)
                    .finish(),
            ))
        }
        "subscriptions" => {
            if !has_only_attributes(operation, &["node"]) || !has_no_element_content(operation) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let subscriptions = state.pubsub_service().node_subscriptions(node.id).await?;
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
        "affiliations" => {
            if !has_only_attributes(operation, &["node"]) || !has_no_element_content(operation) {
                return Ok(PubSubReply::Error("bad-request"));
            }
            let affiliations = state.pubsub_service().node_affiliations(node.id).await?;
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
        _ => Ok(PubSubReply::Error("feature-not-implemented")),
    }
}

fn requested_default_node_type(operation: Node<'_, '_>) -> Result<&'static str, PubSubReply> {
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

async fn handle_owner_set(
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
        let Some(child_node) = state.pubsub_service().get_node(child_name).await? else {
            return Ok(PubSubReply::Error("item-not-found"));
        };
        let outcome = if action.tag_name().name() == "associate" {
            state
                .pubsub_service()
                .associate_collection_child(&node, &child_node, &requester)
                .await?
        } else {
            state
                .pubsub_service()
                .dissociate_collection_child(&node, &child_node, &requester)
                .await?
        };
        match outcome {
            CollectionUpdateOutcome::Updated => {}
            CollectionUpdateOutcome::NotFound => {
                return Ok(PubSubReply::Error("item-not-found"));
            }
            CollectionUpdateOutcome::NotAssociated => {
                // XEP-0248 section 7.6.3.1 uses bad-request when both nodes
                // exist but the requested edge does not.
                return Ok(PubSubReply::Error("bad-request"));
            }
            CollectionUpdateOutcome::NotCollection => {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "not-allowed",
                    "invalid-options",
                )));
            }
            CollectionUpdateOutcome::Forbidden => {
                return Ok(PubSubReply::Error("forbidden"));
            }
            CollectionUpdateOutcome::LimitExceeded => {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "not-allowed",
                    "max-nodes-exceeded",
                )));
            }
            CollectionUpdateOutcome::DepthExceeded => {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "not-allowed",
                    "invalid-options",
                )));
            }
            CollectionUpdateOutcome::Cycle => {
                return Ok(PubSubReply::ExtendedError(PubSubError::new(
                    "not-allowed",
                    "invalid-options",
                )));
            }
        }
        return Ok(PubSubReply::Result(String::new()));
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

pub(crate) async fn handle_authorization_response(
    state: &AppState,
    requester: &str,
    message: Node<'_, '_>,
) -> Result<()> {
    let mut forms = message.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "x"
            && node.tag_name().namespace() == Some(NS_DATA)
            && node.attribute("type") == Some("submit")
    });
    let Some(form) = forms.next() else {
        return Ok(());
    };
    if forms.next().is_some() || !valid_submit_form_structure(form) || has_duplicate_fields(form) {
        return Ok(());
    }
    let fields = data_form_fields(form);
    const AUTH_FIELDS: &[&str] = &[
        "FORM_TYPE",
        "pubsub#node",
        "pubsub#subscriber_jid",
        "pubsub#subid",
        "pubsub#allow",
    ];
    if fields
        .keys()
        .any(|field| !AUTH_FIELDS.contains(&field.as_str()))
        || AUTH_FIELDS
            .iter()
            .filter_map(|field| fields.get(*field))
            .any(|values| values.len() != 1)
    {
        return Ok(());
    }
    if first_field(&fields, "FORM_TYPE") != Some(SUBSCRIBE_AUTH_FORM) {
        return Ok(());
    }
    let Some(node_name) =
        first_field(&fields, "pubsub#node").and_then(|value| valid_node_id(Some(value)))
    else {
        return Ok(());
    };
    let Some(subscriber) =
        first_field(&fields, "pubsub#subscriber_jid").and_then(|value| normalized_jid(value).ok())
    else {
        return Ok(());
    };
    let Some(allow) =
        first_field(&fields, "pubsub#allow").and_then(|value| parse_bool(Some(value)))
    else {
        return Ok(());
    };
    let Some(node) = state.pubsub_service().get_node(node_name).await? else {
        return Ok(());
    };
    let Some(pending_subscription) = state
        .pubsub_service()
        .get_subscription(node.id, &subscriber)
        .await?
    else {
        return Ok(());
    };
    // XEP-0060 subscription authorization forms identify the request with
    // the node and subscriber JID; `pubsub#subid` is not a required response
    // field. Northstar currently permits one subscription per node/JID, so a
    // missing subid is unambiguous. If a client echoes it, still verify it to
    // reject stale or forged forms.
    if first_field(&fields, "pubsub#subid").is_some_and(|subid| subid != pending_subscription.subid)
    {
        return Ok(());
    }
    if !is_owner(state, node.id, &normalized_bare(requester)?).await?
        || pending_subscription.state != "pending"
    {
        return Ok(());
    }
    let _ = state
        .pubsub_service()
        .resolve_pending_subscription(
            node.id,
            &normalized_bare(requester)?,
            &subscriber,
            &pending_subscription.subid,
            allow,
        )
        .await?;
    Ok(())
}

pub(crate) async fn can_retrieve(state: &AppState, node: &PubSubNode, jid: &str) -> Result<bool> {
    let affiliation = state
        .pubsub_service()
        .get_node_affiliation(node.id, jid)
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
    let subscribed = state.pubsub_service().is_subscribed(node.id, jid).await?;
    Ok(northstar_xep_0060::can_retrieve_pure(
        access_model,
        affiliation,
        subscribed,
    ))
}

/// Apply the XEP-0060 item-retrieval access and SubID rules after the caller
/// has loaded all active subscriptions that address the requesting resource
/// (its exact full JID plus its bare JID).
fn item_retrieval_access(
    access_model: &str,
    affiliation: Option<&str>,
    subscriptions: &[PubSubSubscription],
    supplied_subid: Option<&str>,
) -> std::result::Result<(), PubSubReply> {
    let access_model = access_model
        .parse::<northstar_xep_0060::AccessModel>()
        .map_err(PubSubReply::ExtendedError)?;
    let affiliation = affiliation
        .map(str::parse::<northstar_xep_0060::Affiliation>)
        .transpose()
        .map_err(PubSubReply::ExtendedError)?;
    let subids = subscriptions
        .iter()
        .map(|subscription| subscription.subid.as_str())
        .collect::<Vec<_>>();
    northstar_xep_0060::item_retrieval_access(access_model, affiliation, &subids, supplied_subid)
        .map_err(PubSubReply::ExtendedError)
}

fn publish_batch_size_allowed(item_count: usize) -> bool {
    item_count <= MAX_PUBLISH_ITEMS
}

fn has_only_attributes(node: Node<'_, '_>, allowed: &[&str]) -> bool {
    node.attributes()
        .all(|attribute| attribute.namespace().is_none() && allowed.contains(&attribute.name()))
}

fn has_only_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
}

fn has_no_element_content(node: Node<'_, '_>) -> bool {
    has_only_whitespace_text(node) && !node.children().any(|child| child.is_element())
}

fn single_element_child<'a, 'input>(node: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    if !has_only_whitespace_text(node) {
        return None;
    }
    let mut children = node.children().filter(|child| child.is_element());
    let child = children.next()?;
    children.next().is_none().then_some(child)
}

fn valid_submit_form_structure(form: Node<'_, '_>) -> bool {
    if form.tag_name().name() != "x"
        || form.tag_name().namespace() != Some(NS_DATA)
        || !has_only_attributes(form, &["type"])
        || form.attribute("type") != Some("submit")
        || !has_only_whitespace_text(form)
    {
        return false;
    }
    let fields = form.children().filter(|child| child.is_element());
    if fields.clone().count() > 100 {
        return false;
    }
    fields.into_iter().all(|field| {
        field.tag_name().name() == "field"
            && field.tag_name().namespace() == Some(NS_DATA)
            && has_only_attributes(field, &["var", "type", "label"])
            && field
                .attribute("var")
                .is_some_and(|var| !var.is_empty() && var.len() <= 256)
            && has_only_whitespace_text(field)
            && field
                .children()
                .filter(|child| child.is_element())
                .all(|value| {
                    value.tag_name().name() == "value"
                        && value.tag_name().namespace() == Some(NS_DATA)
                        && value.attributes().len() == 0
                        && !value.children().any(|child| child.is_element())
                        && value
                            .text()
                            .is_none_or(|text| text.len() <= MAX_ITEM_XML_BYTES)
                })
    })
}

fn valid_cancel_form_structure(form: Node<'_, '_>) -> bool {
    form.tag_name().name() == "x"
        && form.tag_name().namespace() == Some(NS_DATA)
        && has_only_attributes(form, &["type"])
        && form.attribute("type") == Some("cancel")
        && has_no_element_content(form)
}

async fn is_owner(state: &AppState, node_id: uuid::Uuid, jid: &str) -> Result<bool> {
    state.pubsub_service().is_owner(node_id, jid).await
}

fn subscription_event_children(
    subscription: &PubSubSubscription,
    event: &str,
    collection: Option<&str>,
    delay: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<String> {
    let mut headers = XmlElement::namespaced("headers", "http://jabber.org/protocol/shim").child(
        XmlElement::new("header")
            .attr("name", "SubID")
            .text(subscription.subid.clone()),
    );
    if let Some(collection) = collection {
        headers.push_child(
            XmlElement::new("header")
                .attr("name", "Collection")
                .text(collection.to_owned()),
        );
    }
    let mut children = XmlElement::new("northstar-children");
    let mut event_wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
    event_wrapper.push_validated_fragment(event)?;
    children.push_child(event_wrapper);
    if subscription.include_body {
        if let Some(body) = event_body(event)? {
            children.push_child(XmlElement::new("body").text(body));
        }
    }
    children.push_child(headers);
    if let Some(stamp) = delay {
        children.push_child(
            XmlElement::namespaced("delay", "urn:xmpp:delay").attr("stamp", stamp.to_rfc3339()),
        );
    }
    Ok(children.finish_children())
}

fn event_body(event: &str) -> Result<Option<String>> {
    northstar_xep_0060::extract_atom_event_body(event)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

async fn route_pubsub_message_children(
    state: &AppState,
    recipient: &str,
    children: &str,
    show_values: Option<&[String]>,
) -> Result<()> {
    route_pubsub_message_children_with_id(
        state,
        recipient,
        children,
        show_values,
        uuid::Uuid::new_v4(),
    )
    .await
}

async fn route_pubsub_message_children_with_id(
    state: &AppState,
    recipient: &str,
    children: &str,
    show_values: Option<&[String]>,
    message_id: uuid::Uuid,
) -> Result<()> {
    let service = pubsub_domain(state);
    let target = crate::jid::CanonicalJid::parse(recipient)?;
    let target_domain = target.domainpart();
    if target_domain == state.config.domain {
        if local_account_blocks_pubsub(state, &target, &service).await? {
            return Ok(());
        }
        if let Some(show_values) = show_values {
            let mut delivered = false;
            let targets = state.session_entries_for(recipient);
            let mut show_eligible = 0_usize;
            let mut policy_eligible = 0_usize;
            for (full_jid, session) in targets.iter() {
                let show = match session.show.load(std::sync::atomic::Ordering::Relaxed) {
                    1 => "online",
                    2 => "away",
                    3 => "chat",
                    4 => "dnd",
                    5 => "xa",
                    _ => continue,
                };
                if !show_values.iter().any(|allowed| allowed == show) {
                    continue;
                }
                show_eligible += 1;
                if !state
                    .privacy_allows_session(session, &service, PrivacyStanzaKind::Message)
                    .await?
                {
                    continue;
                }
                policy_eligible += 1;
                let message = XmlElement::namespaced("message", "jabber:client")
                    .attr("type", "headline")
                    .attr("id", message_id)
                    .attr("from", &service)
                    .attr("to", full_jid)
                    .validated_fragment(children)?
                    .finish();
                delivered |= session.sender.try_send(message).is_ok();
            }
            if !delivered {
                if pubsub_policy_suppression_is_terminal(show_eligible, policy_eligible) {
                    // Policy suppression is a successful terminal outcome;
                    // durable digests must not retry a deliberately denied
                    // service notification forever. A bound but unavailable
                    // resource, or one whose show value is outside the
                    // subscription filter, is not a policy denial: keep the
                    // durable lease for a later eligible presence.
                    return Ok(());
                }
                anyhow::bail!("no eligible local PubSub resource accepted the notification");
            }
            return Ok(());
        }
    }
    let message = XmlElement::namespaced("message", "jabber:client")
        .attr("type", "headline")
        .attr("id", message_id)
        .attr("from", &service)
        .attr("to", recipient)
        .validated_fragment(children)?
        .finish();
    route_service_message(state, &service, recipient, message).await
}

fn pubsub_policy_suppression_is_terminal(
    show_eligible_resources: usize,
    policy_eligible_resources: usize,
) -> bool {
    northstar_xep_0060::pubsub_policy_suppression_is_terminal(
        show_eligible_resources,
        policy_eligible_resources,
    )
}

pub(crate) async fn deliver_due_pubsub_digests(state: &AppState) -> Result<usize> {
    let digests = state
        .pubsub_service()
        .claim_due_pubsub_digests(1_000)
        .await?;
    let count = digests.len();
    for digest in digests {
        let show_values = if let Some(snapshot) = digest.show_values.clone() {
            Some(snapshot)
        } else {
            state
                .pubsub_service()
                .get_subscription(digest.subscription_node_id, &digest.subscriber_jid)
                .await?
                .filter(|subscription| subscription.deliver && subscription.is_active())
                .map(|subscription| subscription.show_values)
        };
        if let Some(show_values) = show_values {
            let mut batches = Vec::<(Vec<uuid::Uuid>, String)>::new();
            let mut batch_ids = Vec::new();
            let mut batch_xml = String::new();
            for (id, event) in digest.ids.into_iter().zip(digest.event_xml) {
                if !batch_xml.is_empty()
                    && batch_xml.len().saturating_add(event.len()) > MAX_PUBLISH_XML_BYTES
                {
                    batches.push((
                        std::mem::take(&mut batch_ids),
                        std::mem::take(&mut batch_xml),
                    ));
                }
                batch_ids.push(id);
                batch_xml.push_str(&event);
            }
            if !batch_ids.is_empty() {
                batches.push((batch_ids, batch_xml));
            }
            for index in 0..batches.len() {
                let (ids, children) = &batches[index];
                if let Err(error) = route_pubsub_message_children(
                    state,
                    &digest.subscriber_jid,
                    children,
                    Some(&show_values),
                )
                .await
                {
                    let pending_ids = batches[index..]
                        .iter()
                        .flat_map(|(ids, _)| ids.iter().copied())
                        .collect::<Vec<_>>();
                    state
                        .pubsub_service()
                        .release_pubsub_digests(&pending_ids)
                        .await?;
                    return Err(error);
                }
                state
                    .pubsub_service()
                    .acknowledge_pubsub_digests(ids)
                    .await?;
            }
        } else {
            state
                .pubsub_service()
                .acknowledge_pubsub_digests(&digest.ids)
                .await?;
        }
    }
    Ok(count)
}

pub(crate) fn start_pubsub_digest_delivery(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    registry.supervise(
        "pubsub-digest-delivery",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(5)),
        cancel,
        move |heartbeat| {
            let state = Arc::clone(&state);
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut lease_cleanup_ticks = 0_u8;
                loop {
                    interval.tick().await;
                    if let Err(error) = deliver_due_pubsub_digests(&state).await {
                        heartbeat.error(&error);
                        tracing::error!(
                            ?error,
                            "failed to deliver durable PubSub notification digest"
                        );
                    } else {
                        heartbeat.ok();
                    }
                    lease_cleanup_ticks = lease_cleanup_ticks.wrapping_add(1);
                    if lease_cleanup_ticks >= 60 {
                        lease_cleanup_ticks = 0;
                        if let Err(error) = state
                            .pubsub_service()
                            .cleanup_expired_subscriptions(1_000)
                            .await
                        {
                            heartbeat.error(&error);
                            tracing::error!(
                                ?error,
                                "failed to clean expired PubSub subscription leases"
                            );
                        }
                    }
                }
            }
        },
    );
}

async fn deliver_pubsub_outbox_item(
    state: &AppState,
    item: &ClaimedPubSubOutboxDelivery,
) -> Result<()> {
    if !item.payload_binding_valid() {
        anyhow::bail!("PubSub outbox payload digest mismatch");
    }
    match item.delivery_kind {
        PubSubOutboxDeliveryKind::PubSubChildren => {
            route_pubsub_message_children_with_id(
                state,
                &item.recipient_jid,
                &item.payload_xml,
                item.show_values.as_deref(),
                item.event_id,
            )
            .await
        }
        PubSubOutboxDeliveryKind::PubSubDigest => {
            state
                .pubsub_service()
                .enqueue_pubsub_digest_snapshot(
                    item.delivery_id,
                    item.subscription_node_id.ok_or_else(|| {
                        anyhow::anyhow!("digest outbox row lacks subscription node")
                    })?,
                    &item.recipient_jid,
                    &item.payload_xml,
                    item.digest_frequency_ms
                        .ok_or_else(|| anyhow::anyhow!("digest outbox row lacks frequency"))?,
                    item.show_values.as_deref().unwrap_or(&[]),
                )
                .await
        }
        PubSubOutboxDeliveryKind::PubSubDirect => {
            let service = pubsub_domain(state);
            route_service_message(
                state,
                &service,
                &item.recipient_jid,
                item.payload_xml.clone(),
            )
            .await
        }
        PubSubOutboxDeliveryKind::PepStanza => {
            match state
                .pubsub_service()
                .authorize_pep_outbox_delivery(item)
                .await?
            {
                PepOutboxAuthorizationOutcome::Deliver => {}
                PepOutboxAuthorizationOutcome::Drop(reason) => {
                    tracing::warn!(
                        delivery_id = %item.delivery_id,
                        event_id = %item.event_id,
                        ?reason,
                        "ACK-dropping PEP outbox delivery after live authorization denial"
                    );
                    return Ok(());
                }
            }
            let Some(subject) = item.pep_subject.as_ref() else {
                // Authorization already fail-closes and counts every missing
                // subject before it can return Deliver. Keep this impossible
                // branch as a local invariant guard, not a repository bypass.
                tracing::error!(
                    delivery_id = %item.delivery_id,
                    "ACK-dropping PEP outbox delivery without a structured subject"
                );
                return Ok(());
            };
            super::pep::route_pep_outbox_message(
                state,
                &subject.sender_bare_jid,
                &item.recipient_jid,
                item.payload_xml.clone(),
            )
            .await
        }
    }
}

pub(crate) fn start_pubsub_event_outbox_delivery(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    registry.supervise(
        "pubsub-event-outbox-delivery",
        crate::workers::WorkerCriticality::Restartable,
        crate::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        cancel.clone(),
        move |heartbeat| {
            let state = Arc::clone(&state);
            let cancel = cancel.clone();
            async move {
                let mut maintenance_ticks = 0_u32;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                    let claimed = state.pubsub_service().claim_pubsub_outbox(256).await?;
                    for item in claimed {
                        let _delivery_timer =
                            state.metrics.outbox_delivery_duration_seconds.start_timer();
                        if !state
                            .pubsub_service()
                            .renew_pubsub_outbox_lease(item.delivery_id, item.lease_token)
                            .await?
                        {
                            tracing::warn!(
                                delivery_id = %item.delivery_id,
                                event_id = %item.event_id,
                                ordering_key = %item.ordering_key,
                                event_sequence = item.event_sequence,
                                target_domain = %item.target_domain,
                                attempt_count = item.attempt_count,
                                expires_at = %item.expires_at,
                                "PubSub event outbox claim lost before routing"
                            );
                            continue;
                        }
                        // Keep routing strictly inside the renewed 30-second
                        // lease.  An unresponsive remote/domain route must be
                        // retried with the same immutable event instead of
                        // completing after another worker has taken over.
                        let result = match tokio::time::timeout(
                            Duration::from_secs(20),
                            deliver_pubsub_outbox_item(&state, &item),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err(anyhow::anyhow!(
                                "PubSub outbox route exceeded its bounded delivery window"
                            )),
                        };
                        match result {
                            Ok(()) => {
                                if !state
                                    .pubsub_service()
                                    .acknowledge_pubsub_outbox(item.delivery_id, item.lease_token)
                                    .await?
                                {
                                    tracing::warn!(
                                        delivery_id = %item.delivery_id,
                                        "PubSub event outbox acknowledgement lost its lease"
                                    );
                                }
                            }
                            Err(error) if !item.payload_binding_valid() => {
                                state
                                    .pubsub_service()
                                    .dead_letter_pubsub_outbox(
                                        item.delivery_id,
                                        item.lease_token,
                                        "payload-integrity",
                                        &error.to_string(),
                                    )
                                    .await?;
                            }
                            Err(error) => {
                                state
                                    .pubsub_service()
                                    .retry_pubsub_outbox(&item, &error.to_string())
                                    .await?;
                            }
                        }
                    }
                    maintenance_ticks = maintenance_ticks.saturating_add(1);
                    if maintenance_ticks >= 20 {
                        maintenance_ticks = 0;
                        state.pubsub_service().expire_pubsub_outbox(1_000).await?;
                        state
                            .pubsub_service()
                            .cleanup_pubsub_dead_letters(1_000)
                            .await?;
                        state
                            .pubsub_service()
                            .cleanup_idle_pubsub_event_streams(1_000)
                            .await?;
                        let snapshot = state.pubsub_service().pubsub_outbox_snapshot().await?;
                        state.metrics.pubsub_event_outbox_pending_rows.store(
                            u64::try_from(snapshot.pending_rows.max(0)).unwrap_or(u64::MAX),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        state.metrics.pubsub_event_outbox_pending_bytes.store(
                            u64::try_from(snapshot.pending_bytes.max(0)).unwrap_or(u64::MAX),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        state.metrics.pubsub_event_outbox_dead_letter_rows.store(
                            u64::try_from(snapshot.dead_letter_rows.max(0)).unwrap_or(u64::MAX),
                            std::sync::atomic::Ordering::Relaxed,
                        );
                    }
                    heartbeat.ok();
                }
            }
        },
    );
}

async fn route_service_message(
    state: &AppState,
    service: &str,
    recipient: &str,
    message: String,
) -> Result<()> {
    let target = crate::jid::CanonicalJid::parse(recipient)?;
    let target_domain = target.domainpart();
    if target_domain == state.config.domain {
        if local_account_blocks_pubsub(state, &target, service).await? {
            return Ok(());
        }
        let mut delivered = false;
        let targets = state.session_entries_for(recipient);
        let mut policy_eligible = 0_usize;
        for (_, session) in &targets {
            if !state
                .privacy_allows_session(session, service, PrivacyStanzaKind::Message)
                .await?
            {
                continue;
            }
            policy_eligible += 1;
            delivered |= session.sender.try_send(message.clone()).is_ok();
        }
        let mut remote_nodes = 0_usize;
        if !delivered {
            for node_id in state.cluster.lookup_nodes(recipient).await? {
                if node_id != state.cluster.node_id {
                    remote_nodes += 1;
                    if state
                        .cluster
                        .send_to_node(&node_id, recipient, &message, false, None)
                        .await?
                    {
                        delivered = true;
                        break;
                    }
                }
            }
        }
        if !delivered {
            if remote_nodes == 0 && !targets.is_empty() && policy_eligible == 0 {
                return Ok(());
            }
            anyhow::bail!("no local PubSub resource accepted the notification");
        }
    } else if state.federation_domain_allowed(target_domain) {
        if !state
            .federation
            .send(target_domain, message, Some(service.to_owned()))
            .await
        {
            anyhow::bail!("federated PubSub notification was not admitted to the durable outbox");
        }
    } else {
        anyhow::bail!("federated PubSub notification is denied by domain policy");
    }
    Ok(())
}

async fn local_account_blocks_pubsub(
    state: &AppState,
    target: &crate::jid::CanonicalJid,
    service: &str,
) -> Result<bool> {
    let Some(username) = target.localpart() else {
        return Ok(false);
    };
    // XEP-0191 is account-wide and has non-overridable precedence over any
    // XEP-0016 allow rule. Resource-specific privacy is checked separately.
    state
        .pubsub_service()
        .local_account_blocks_pubsub(username, service)
        .await
}

async fn deliver_last_items_on_presence(
    state: Arc<AppState>,
    outbound: crate::outbound::OutboundSender,
    recipient_id: uuid::Uuid,
    active_privacy_list: Option<String>,
    connection_id: uuid::Uuid,
    recipient: String,
    show: &'static str,
) -> Result<()> {
    let requester_bare = normalized_bare(&recipient)?;
    let service = pubsub_domain(&state);
    if state
        .pubsub_service()
        .presence_delivery_denied(
            recipient_id,
            active_privacy_list.as_deref(),
            connection_id,
            &service,
        )
        .await?
    {
        return Ok(());
    }
    let mut cursor: Option<(String, String)> = None;
    loop {
        let page = state
            .pubsub_service()
            .subscriptions_addressing_jid_page(
                &recipient,
                cursor
                    .as_ref()
                    .map(|(node, jid)| (node.as_str(), jid.as_str())),
                100,
            )
            .await?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for subscription in page {
            cursor = Some((subscription.node.clone(), subscription.jid.clone()));
            if subscription.state != "subscribed"
                || !subscription.deliver
                || !subscription.show_values.iter().any(|value| value == show)
            {
                continue;
            }
            let Some(node) = state.pubsub_service().get_node(&subscription.node).await? else {
                continue;
            };
            if node.send_last_published_item != "on_sub_and_presence"
                || !can_retrieve(&state, &node, &requester_bare).await?
            {
                continue;
            }
            let Some(item) = state
                .pubsub_service()
                .get_items(node.id, &[], 1)
                .await?
                .into_iter()
                .next()
            else {
                continue;
            };
            let mut event = XmlElement::new("items").attr("node", &node.node);
            if node.deliver_payloads {
                event.push_validated_fragment(&event_item_xml(&item.xml_payload))?;
            } else {
                event.push_child(XmlElement::new("item").attr("id", &item.item_id));
            }
            let event = event.finish();
            let children =
                subscription_event_children(&subscription, &event, None, Some(item.created_at))?;
            if subscription.digest
                && state
                    .pubsub_service()
                    .enqueue_pubsub_digest(
                        node.id,
                        &subscription.jid,
                        &children,
                        subscription.digest_frequency,
                    )
                    .await?
            {
                continue;
            }
            let message = XmlElement::namespaced("message", "jabber:client")
                .attr("type", "headline")
                .attr("id", uuid::Uuid::new_v4())
                .attr("from", &service)
                .attr("to", &recipient)
                .validated_fragment(&children)?
                .finish();
            if outbound.send(message).await.is_err() {
                return Ok(());
            }
        }
        if page_len < 100 {
            break;
        }
    }
    Ok(())
}

fn event_item_xml(stored: &str) -> String {
    stored.replacen(&format!(" xmlns='{NS_PUBSUB}'"), "", 1)
}

async fn missing_node_reply(state: &AppState, node: &str) -> Result<PubSubReply> {
    Ok(match state.pubsub_service().node_redirect(node).await? {
        Some(uri) => PubSubReply::ExtendedError(PubSubError::moved(uri)),
        None => PubSubReply::Error("item-not-found"),
    })
}

fn subscription_options(subscription: &PubSubSubscription) -> PubSubSubscriptionOptions {
    PubSubSubscriptionOptions {
        deliver: subscription.deliver,
        digest: subscription.digest,
        digest_frequency: subscription.digest_frequency,
        expire: subscription.expire,
        include_body: subscription.include_body,
        show_values: subscription.show_values.clone(),
        subscription_type: subscription.subscription_type.clone(),
        subscription_depth: subscription.subscription_depth,
    }
}

fn parse_subscription_options(
    form: Node<'_, '_>,
    mut options: PubSubSubscriptionOptions,
    node_type: &str,
    supports_include_body: bool,
) -> std::result::Result<PubSubSubscriptionOptions, PubSubReply> {
    if !valid_submit_form_structure(form) || has_duplicate_fields(form) {
        return Err(PubSubReply::Error("bad-request"));
    }
    let fields = data_form_fields(form);
    if first_field(&fields, "FORM_TYPE") != Some(SUBSCRIBE_OPTIONS_FORM) {
        return Err(PubSubReply::Error("bad-request"));
    }
    for field in [
        "FORM_TYPE",
        "pubsub#deliver",
        "pubsub#digest",
        "pubsub#digest_frequency",
        "pubsub#expire",
        "pubsub#include_body",
        "pubsub#subscription_type",
        "pubsub#subscription_depth",
    ] {
        if fields.get(field).is_some_and(|values| values.len() != 1) {
            return Err(invalid_subscription_options());
        }
    }
    for (field, target) in [
        ("pubsub#deliver", &mut options.deliver),
        ("pubsub#digest", &mut options.digest),
        ("pubsub#include_body", &mut options.include_body),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or_else(invalid_subscription_options)?;
        }
    }
    if options.include_body && !supports_include_body {
        return Err(invalid_subscription_options());
    }
    if let Some(value) = first_field(&fields, "pubsub#digest_frequency") {
        options.digest_frequency = value
            .parse::<i32>()
            .ok()
            .filter(|value| (1_000..=86_400_000).contains(value))
            .ok_or_else(invalid_subscription_options)?;
    }
    if let Some(value) = first_field(&fields, "pubsub#expire") {
        options.expire = if value.is_empty() {
            None
        } else if value == "presence" {
            // Presence-scoped leases require full-JID subscription state,
            // which this service intentionally does not advertise.
            return Err(invalid_subscription_options());
        } else {
            let now = chrono::Utc::now();
            let expiry = chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|_| invalid_subscription_options())?
                .with_timezone(&chrono::Utc);
            if expiry <= now {
                return Err(invalid_subscription_options());
            }
            // XEP-0060 requires a service with a maximum lease term to clamp
            // an overlong request rather than reject it. A finite policy also
            // prevents effectively immortal rows chosen by remote entities.
            Some(expiry.min(now + chrono::Duration::days(MAX_SUBSCRIPTION_LEASE_DAYS)))
        };
    }
    if let Some(values) = fields.get("pubsub#show-values") {
        if values.is_empty()
            || values.len() > 5
            || values
                .iter()
                .any(|value| !matches!(value.as_str(), "away" | "chat" | "dnd" | "online" | "xa"))
        {
            return Err(invalid_subscription_options());
        }
        let mut unique = BTreeSet::new();
        unique.extend(values.iter().cloned());
        options.show_values = unique.into_iter().collect();
    }
    if let Some(value) = first_field(&fields, "pubsub#subscription_type") {
        let valid = if node_type == "collection" {
            matches!(value, "items" | "nodes" | "all")
        } else {
            value == "items"
        };
        if !valid {
            return Err(invalid_subscription_options());
        }
        options.subscription_type = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#subscription_depth") {
        if node_type != "collection" {
            return Err(invalid_subscription_options());
        }
        options.subscription_depth = if value == "all" {
            None
        } else {
            Some(
                value
                    .parse::<i32>()
                    .ok()
                    .filter(|value| *value >= 0)
                    .ok_or_else(invalid_subscription_options)?,
            )
        };
    }
    Ok(options)
}

fn subscription_options_form(
    options: &PubSubSubscriptionOptions,
    form_type: &str,
    supports_include_body: bool,
    node_type: &str,
) -> String {
    let expiry = options
        .expire
        .map(|value| value.to_rfc3339())
        .unwrap_or_default();
    let depth = options
        .subscription_depth
        .map(|value| value.to_string())
        .unwrap_or_else(|| "all".to_owned());
    let mut form = XmlElement::namespaced("x", NS_DATA)
        .attr("type", form_type)
        .child(data_field_element(
            "FORM_TYPE",
            Some("hidden"),
            [SUBSCRIBE_OPTIONS_FORM],
        ))
        .child(data_field_element(
            "pubsub#deliver",
            Some("boolean"),
            [bool_text(options.deliver)],
        ))
        .child(data_field_element(
            "pubsub#digest",
            Some("boolean"),
            [bool_text(options.digest)],
        ))
        .child(data_field_element(
            "pubsub#digest_frequency",
            Some("text-single"),
            [options.digest_frequency.to_string()],
        ))
        .child(data_field_element(
            "pubsub#expire",
            Some("text-single"),
            [expiry],
        ));
    if supports_include_body {
        form.push_child(data_field_element(
            "pubsub#include_body",
            Some("boolean"),
            [bool_text(options.include_body)],
        ));
    }
    form.push_child(data_field_element(
        "pubsub#show-values",
        Some("list-multi"),
        options.show_values.iter(),
    ));
    if node_type == "collection" {
        form.push_child(data_field_element(
            "pubsub#subscription_type",
            Some("list-single"),
            [&options.subscription_type],
        ));
        form.push_child(data_field_element(
            "pubsub#subscription_depth",
            Some("text-single"),
            [depth],
        ));
    }
    form.finish()
}

fn supports_include_body(node: &PubSubNode) -> bool {
    node.payload_type.as_deref() == Some("http://www.w3.org/2005/Atom")
}

fn all_show_values(values: &[String]) -> bool {
    ["away", "chat", "dnd", "online", "xa"]
        .iter()
        .all(|value| values.iter().any(|candidate| candidate == value))
}

fn parse_node_config(
    container: Node<'_, '_>,
    config: PubSubNodeConfig,
) -> std::result::Result<PubSubNodeConfig, &'static str> {
    parse_node_config_form(container, config, NODE_CONFIG_FORM, false)
}

fn parse_publish_options(
    container: Node<'_, '_>,
    config: PubSubNodeConfig,
) -> std::result::Result<PubSubNodeConfig, &'static str> {
    parse_node_config_form(container, config, PUBLISH_OPTIONS_FORM, true)
}

fn parse_node_config_form(
    container: Node<'_, '_>,
    mut config: PubSubNodeConfig,
    expected_form_type: &str,
    reject_unknown_fields: bool,
) -> std::result::Result<PubSubNodeConfig, &'static str> {
    if !has_only_whitespace_text(container) {
        return Err("bad-request");
    }
    let mut children = container.children().filter(|node| node.is_element());
    let Some(form) = children.next() else {
        return Ok(config);
    };
    if children.next().is_some()
        || !valid_submit_form_structure(form)
        || form.tag_name().namespace() != Some(NS_DATA)
    {
        return Err("bad-request");
    }
    if has_duplicate_fields(form) {
        return Err("bad-request");
    }
    let fields = data_form_fields(form);
    for name in [
        "FORM_TYPE",
        "pubsub#access_model",
        "pubsub#publish_model",
        "pubsub#max_items",
        "pubsub#title",
        "pubsub#description",
        "pubsub#deliver_payloads",
        "pubsub#notify_delete",
        "pubsub#notify_retract",
        "pubsub#persist_items",
        "pubsub#send_last_published_item",
        "pubsub#node_type",
        "pubsub#deliver_notifications",
        "pubsub#notify_config",
        "pubsub#notify_sub",
        "pubsub#language",
        "pubsub#type",
        "pubsub#max_payload_size",
        "pubsub#children_max",
        "pubsub#children_association_policy",
    ] {
        if fields.get(name).is_some_and(|values| values.len() != 1) {
            return Err("bad-request");
        }
    }
    if first_field(&fields, "FORM_TYPE") != Some(expected_form_type) {
        return Err("bad-request");
    }
    if reject_unknown_fields {
        const KNOWN: &[&str] = &[
            "FORM_TYPE",
            "pubsub#access_model",
            "pubsub#publish_model",
            "pubsub#max_items",
            "pubsub#title",
            "pubsub#description",
            "pubsub#deliver_payloads",
            "pubsub#notify_delete",
            "pubsub#notify_retract",
            "pubsub#persist_items",
            "pubsub#send_last_published_item",
            "pubsub#node_type",
            "pubsub#deliver_notifications",
            "pubsub#notify_config",
            "pubsub#notify_sub",
            "pubsub#language",
            "pubsub#type",
            "pubsub#max_payload_size",
            "pubsub#children_max",
            "pubsub#children_association_policy",
            "pubsub#children_association_whitelist",
            "pubsub#collection",
            "pubsub#children",
        ];
        if fields.keys().any(|name| !KNOWN.contains(&name.as_str())) {
            return Err("bad-request");
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#access_model") {
        if !matches!(value, "open" | "authorize" | "whitelist") {
            return Err("unsupported-access-model");
        }
        config.access_model = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#publish_model") {
        if !matches!(value, "open" | "publishers" | "subscribers") {
            return Err("not-acceptable");
        }
        config.publish_model = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#max_items") {
        config.max_items = if value == "max" {
            1_000
        } else {
            value
                .parse::<i32>()
                .ok()
                .filter(|value| (1..=1_000).contains(value))
                .ok_or("not-acceptable")?
        };
    }
    if let Some(value) = first_field(&fields, "pubsub#title") {
        if value.len() > MAX_TITLE_BYTES || value.chars().any(char::is_control) {
            return Err("not-acceptable");
        }
        config.title = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#description") {
        if value.len() > MAX_DESCRIPTION_BYTES || value.chars().any(char::is_control) {
            return Err("not-acceptable");
        }
        config.description = (!value.is_empty()).then(|| value.to_owned());
    }
    for (field, target) in [
        ("pubsub#deliver_payloads", &mut config.deliver_payloads),
        ("pubsub#notify_delete", &mut config.notify_delete),
        ("pubsub#notify_retract", &mut config.notify_retract),
        ("pubsub#persist_items", &mut config.persist_items),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or("not-acceptable")?;
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#send_last_published_item") {
        if !matches!(value, "never" | "on_sub" | "on_sub_and_presence") {
            return Err("not-acceptable");
        }
        config.send_last_published_item = value.to_owned();
    }
    if let Some(value) = first_field(&fields, "pubsub#node_type") {
        if !matches!(value, "leaf" | "collection") {
            return Err("not-acceptable");
        }
        config.node_type = value.to_owned();
    }
    for (field, target) in [
        (
            "pubsub#deliver_notifications",
            &mut config.deliver_notifications,
        ),
        ("pubsub#notify_config", &mut config.notify_config),
        ("pubsub#notify_sub", &mut config.notify_sub),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or("not-acceptable")?;
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#language") {
        if !value.is_empty() && !crate::xmpp::xml_util::valid_language_tag(value) {
            return Err("not-acceptable");
        }
        config.language = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#type") {
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err("not-acceptable");
        }
        config.payload_type = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#max_payload_size") {
        config.max_payload_size = value
            .parse::<i32>()
            .ok()
            .filter(|value| (0..=MAX_ITEM_XML_BYTES as i32).contains(value))
            .ok_or("not-acceptable")?;
    }
    if let Some(value) = first_field(&fields, "pubsub#children_max") {
        config.children_max = if value == "max" {
            1_000
        } else {
            value
                .parse::<i32>()
                .ok()
                .filter(|value| (0..=1_000).contains(value))
                .ok_or("not-acceptable")?
        };
    }
    if let Some(value) = first_field(&fields, "pubsub#children_association_policy") {
        config.children_association_policy = match value {
            // XEP-0248 registers the wire value as `owners`. PostgreSQL keeps
            // the older compact internal enum `owner`; normalize only at the
            // protocol boundary so existing durable rows need no migration.
            "owners" => "owner".to_owned(),
            "whitelist" | "all" => value.to_owned(),
            _ => return Err("not-acceptable"),
        };
    }
    if let Some(values) = fields.get("pubsub#children_association_whitelist") {
        if values.len() > 100
            || values
                .iter()
                .any(|jid| !valid_bare_jid(jid) || jid.len() > 3071)
        {
            return Err("not-acceptable");
        }
        config.children_association_whitelist = values
            .iter()
            .map(|jid| normalized_bare(jid).map_err(|_| "not-acceptable"))
            .collect::<std::result::Result<Vec<_>, _>>()?;
    }
    for (field, target) in [
        ("pubsub#collection", &mut config.collections),
        ("pubsub#children", &mut config.children),
    ] {
        if let Some(values) = fields.get(field) {
            if values.len() > 1_000
                || values
                    .iter()
                    .any(|node| !node.is_empty() && valid_node_id(Some(node)).is_none())
            {
                return Err("not-acceptable");
            }
            *target = values
                .iter()
                .filter(|node| !node.is_empty())
                .cloned()
                .collect();
        }
    }
    if config.node_type == "collection" {
        config.persist_items = false;
        config.deliver_payloads = false;
    } else if !config.children.is_empty() {
        return Err("not-allowed");
    }
    if !config.persist_items {
        config.send_last_published_item = "never".to_owned();
    }
    Ok(config)
}

fn data_form_fields(form: Node<'_, '_>) -> HashMap<String, Vec<String>> {
    let mut fields = HashMap::new();
    for field in form.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "field"
            && node.tag_name().namespace() == Some(NS_DATA)
    }) {
        let Some(var) = field.attribute("var") else {
            continue;
        };
        let values = field
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "value"
                    && node.tag_name().namespace() == Some(NS_DATA)
            })
            .map(|node| node.text().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        fields.insert(var.to_owned(), values);
    }
    fields
}

fn has_duplicate_fields(form: Node<'_, '_>) -> bool {
    let mut names = BTreeSet::new();
    form.children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some(NS_DATA)
        })
        .filter_map(|field| field.attribute("var"))
        .any(|name| !names.insert(name))
}

fn first_field<'a>(fields: &'a HashMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    fields.get(name)?.first().map(String::as_str)
}

fn node_config_form(config: &PubSubNodeConfig, form_type: &str) -> String {
    crate::services::pubsub::pubsub_node_config_form(config, form_type)
}

pub(crate) async fn node_metadata_form(state: &AppState, node: &PubSubNode) -> Result<String> {
    let title = node.title.as_deref().unwrap_or(&node.node);
    let description = node.description.as_deref().unwrap_or_default();
    let owners = state.pubsub_service().get_owner_jids(node.id).await?;
    let publishers = state.pubsub_service().get_publisher_jids(node.id).await?;
    let count = state
        .pubsub_service()
        .active_subscriber_count(node.id)
        .await?;
    let mut form = XmlElement::namespaced("x", NS_DATA)
        .attr("type", "result")
        .child(data_field_element(
            "FORM_TYPE",
            Some("hidden"),
            ["http://jabber.org/protocol/pubsub#meta-data"],
        ));
    for (variable, value) in [
        ("pubsub#title", title.to_owned()),
        ("pubsub#description", description.to_owned()),
        ("pubsub#type", node.payload_type.clone().unwrap_or_default()),
        ("pubsub#creator", node.creator_jid.clone()),
        ("pubsub#creation_date", node.created_at.to_rfc3339()),
        ("pubsub#language", node.language.clone().unwrap_or_default()),
        ("pubsub#access_model", node.access_model.clone()),
        ("pubsub#publish_model", node.publish_model.clone()),
        ("pubsub#max_items", node.max_items.to_string()),
        ("pubsub#num_subscribers", count.to_string()),
    ] {
        form.push_child(data_field_element(variable, None, [value]));
    }
    form.push_child(data_field_element(
        "pubsub#owner",
        Some("jid-multi"),
        owners.iter(),
    ));
    form.push_child(data_field_element(
        "pubsub#publisher",
        Some("jid-multi"),
        publishers.iter(),
    ));
    Ok(form.finish())
}

#[cfg(test)]
fn config_equivalent(left: &PubSubNodeConfig, right: &PubSubNodeConfig) -> bool {
    left.access_model == right.access_model
        && left.publish_model == right.publish_model
        && left.max_items == right.max_items
        && left.title == right.title
        && left.description == right.description
        && left.deliver_payloads == right.deliver_payloads
        && left.notify_delete == right.notify_delete
        && left.notify_retract == right.notify_retract
        && left.persist_items == right.persist_items
        && left.send_last_published_item == right.send_last_published_item
        && left.node_type == right.node_type
        && left.deliver_notifications == right.deliver_notifications
        && left.notify_config == right.notify_config
        && left.notify_sub == right.notify_sub
        && left.language == right.language
        && left.payload_type == right.payload_type
        && left.max_payload_size == right.max_payload_size
        && left.children_max == right.children_max
        && left.children_association_policy == right.children_association_policy
        && left.children_association_whitelist == right.children_association_whitelist
        && left.collections == right.collections
        && left.children == right.children
}

fn pubsub_domain(state: &AppState) -> String {
    format!("pubsub.{}", state.config.domain)
}

fn normalized_bare(jid: &str) -> Result<String> {
    crate::jid::canonical_bare_key(jid)
}

fn normalized_jid(jid: &str) -> Result<String> {
    crate::jid::canonicalize(jid)
}

fn parse_bool(value: Option<&str>) -> Option<bool> {
    northstar_xep_0060::parse_bool(value)
}

fn bool_text(value: bool) -> &'static str {
    northstar_xep_0060::bool_text(value)
}

fn valid_node_id(node: Option<&str>) -> Option<&str> {
    northstar_xep_0060::valid_node_id(node)
}

fn required_node_id(value: Option<&str>) -> std::result::Result<&str, PubSubReply> {
    let Some(value) = value else {
        return Err(PubSubReply::ExtendedError(PubSubError::new(
            "bad-request",
            "nodeid-required",
        )));
    };
    valid_node_id(Some(value)).ok_or(PubSubReply::Error("bad-request"))
}

fn valid_item_id(item_id: &str) -> bool {
    northstar_xep_0060::valid_item_id(item_id)
}

fn valid_redirect_uri(uri: &str) -> bool {
    northstar_xep_0060::valid_redirect_uri(uri)
}

fn parse_pubsub_rsm(set: Node<'_, '_>) -> std::result::Result<PubSubRsmRequest, PubSubReply> {
    mam_pubsub_parsing::parse_pubsub_rsm(set).map_err(PubSubReply::Error)
}

fn pubsub_rsm_page(
    items: Vec<PubSubItem>,
    request: &PubSubRsmRequest,
    fallback_max: usize,
) -> std::result::Result<(Vec<PubSubItem>, String), PubSubReply> {
    let total = items.len();
    let max = request.max.unwrap_or(fallback_max).min(1_000);
    let cursor_index = |cursor: &str| {
        items
            .iter()
            .position(|item| item.item_id == cursor)
            .ok_or(PubSubReply::Error("item-not-found"))
    };
    let (start, end) = if let Some(after) = request.after.as_deref() {
        let start = cursor_index(after)?.saturating_add(1).min(total);
        (start, start.saturating_add(max).min(total))
    } else if let Some(before) = request.before.as_ref() {
        let end = match before.as_deref() {
            Some(before) => cursor_index(before)?,
            None => total,
        };
        (end.saturating_sub(max), end)
    } else {
        (0, max.min(total))
    };
    let page = items
        .into_iter()
        .skip(start)
        .take(end - start)
        .collect::<Vec<_>>();
    let rsm = rsm_set_element(
        page.first().map(|item| (start, item.item_id.as_str())),
        page.last().map(|item| item.item_id.as_str()),
        total,
    )
    .finish();
    Ok((page, rsm))
}

fn disco_rsm_page(
    items: Vec<DiscoItem>,
    request: &PubSubRsmRequest,
    fallback_max: usize,
) -> std::result::Result<(Vec<DiscoItem>, String), PubSubReply> {
    let total = items.len();
    let max = request.max.unwrap_or(fallback_max).min(1_000);
    let cursor_index = |cursor: &str| {
        items
            .iter()
            .position(|item| item.node == cursor)
            .ok_or(PubSubReply::Error("item-not-found"))
    };
    let (start, end) = if let Some(after) = request.after.as_deref() {
        let start = cursor_index(after)?.saturating_add(1).min(total);
        (start, start.saturating_add(max).min(total))
    } else if let Some(before) = request.before.as_ref() {
        let end = match before.as_deref() {
            Some(before) => cursor_index(before)?,
            None => total,
        };
        (end.saturating_sub(max), end)
    } else {
        (0, max.min(total))
    };
    let page = items
        .into_iter()
        .skip(start)
        .take(end - start)
        .collect::<Vec<_>>();
    let rsm = rsm_set_element(
        page.first().map(|item| (start, item.node.as_str())),
        page.last().map(|item| item.node.as_str()),
        total,
    )
    .finish();
    Ok((page, rsm))
}

fn subscription_payload(
    node: &str,
    jid: &str,
    state: &str,
    subid: Option<&str>,
    expiry: Option<&chrono::DateTime<chrono::Utc>>,
) -> String {
    XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(subscription_element(
            node,
            jid,
            state,
            subid,
            expiry.copied(),
        ))
        .finish()
}

fn subscription_element(
    node: &str,
    jid: &str,
    state: &str,
    subid: Option<&str>,
    expiry: Option<chrono::DateTime<chrono::Utc>>,
) -> XmlElement {
    XmlElement::new("subscription")
        .attr("node", node)
        .attr("jid", jid)
        .attr("subscription", state)
        .optional_attr("subid", subid)
        .optional_attr("expiry", expiry.map(|value| value.to_rfc3339()))
}

fn serialize_pubsub_item(node: Node<'_, '_>, item_id: &str) -> Result<String> {
    northstar_xep_0060::serialize_pubsub_item(node, item_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        config_equivalent, data_form_fields, disco_item_xml, disco_rsm_page, error_condition,
        error_payload, event_body, item_retrieval_access, node_config_form, normalized_bare,
        parse_node_config, parse_publish_options, parse_pubsub_rsm, parse_subscription_options,
        publish_batch_size_allowed, pubsub_policy_suppression_is_terminal, pubsub_rsm_page,
        serialize_pubsub_item, subscription_options_form, subscription_payload, valid_item_id,
        valid_node_id, DiscoItem, PubSubError, PubSubReply, MAX_PUBLISH_ITEMS, NODE_CONFIG_FORM,
        PUBLISH_OPTIONS_FORM, SERVICE_FEATURES, SUBSCRIBE_OPTIONS_FORM,
    };
    use crate::services::pubsub::{
        PubSubItem, PubSubNodeConfig, PubSubSubscription, PubSubSubscriptionOptions,
    };
    use chrono::Utc;
    use roxmltree::Document;

    #[test]
    fn atom_event_body_limit_never_splits_a_utf8_character() {
        let summary = format!("{}ƞ", "a".repeat(1_023));
        let event = format!(
            "<entry xmlns='http://www.w3.org/2005/Atom'><summary>{summary}</summary></entry>"
        );
        let body = event_body(&event).unwrap().unwrap();
        assert_eq!(body.len(), 1_023);
        assert_eq!(body, "a".repeat(1_023));
    }

    #[test]
    fn pubsub_ownership_keys_use_precis_idna_and_bare_identity() {
        assert_eq!(
            normalized_bare("A\u{30a}LICE@B\u{fc}CHER.Example./Phone").unwrap(),
            normalized_bare("\u{e5}lice@b\u{fc}cher.example/tablet").unwrap()
        );
        assert_ne!(
            normalized_bare("alice@example.test/Phone").unwrap(),
            normalized_bare("alice@example.net/Phone").unwrap()
        );
        assert_ne!(
            normalized_bare("alice@example.test").unwrap(),
            normalized_bare("alice2@example.test").unwrap()
        );
    }

    #[test]
    fn validates_pubsub_identifiers_without_leaking_generated_strings() {
        assert_eq!(valid_node_id(Some("news/world")), Some("news/world"));
        assert!(valid_node_id(Some("")).is_none());
        assert!(valid_node_id(Some("bad\nnode")).is_none());
        assert!(valid_item_id("item-1"));
        assert!(!valid_item_id("bad\u{7f}"));
    }

    #[test]
    fn leaf_disco_items_use_name_and_never_masquerade_as_nodes() {
        let item = DiscoItem {
            node: "item<&1".to_owned(),
            title: None,
            published_item: true,
        };
        let xml = disco_item_xml("pubsub.example.test", &item);
        let document = Document::parse(&xml).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("jid"), Some("pubsub.example.test"));
        assert_eq!(root.attribute("name"), Some("item<&1"));
        assert_eq!(root.attribute("node"), None);
    }

    #[test]
    fn escapes_subscription_response_values() {
        let payload = subscription_payload(
            "a'node",
            "u&x@example.test",
            "subscribed",
            Some("sub&1"),
            None,
        );
        assert!(payload.contains("a&apos;node"));
        assert!(payload.contains("u&amp;x@example.test"));
        assert!(payload.contains("subid='sub&amp;1'"));
    }

    fn subscription(subid: &str) -> PubSubSubscription {
        PubSubSubscription {
            node: "n".to_owned(),
            jid: "alice@example.test/phone".to_owned(),
            state: "subscribed".to_owned(),
            subid: subid.to_owned(),
            deliver: true,
            digest: false,
            digest_frequency: 0,
            expire: None,
            include_body: false,
            show_values: Vec::new(),
            subscription_type: "items".to_owned(),
            subscription_depth: Some(1),
        }
    }

    #[test]
    fn item_retrieval_enforces_subids_and_access_specific_errors() {
        let subscriptions = [subscription("one"), subscription("two")];
        let missing_subid =
            item_retrieval_access("authorize", None, &subscriptions, None).unwrap_err();
        assert_eq!(error_condition(&missing_subid), Some("bad-request"));
        assert!(error_payload(&missing_subid)
            .unwrap()
            .1
            .contains("subid-required"));

        let invalid_subid =
            item_retrieval_access("authorize", None, &subscriptions, Some("wrong")).unwrap_err();
        assert_eq!(error_condition(&invalid_subid), Some("not-acceptable"));
        assert!(error_payload(&invalid_subid)
            .unwrap()
            .1
            .contains("invalid-subid"));
        assert!(item_retrieval_access("authorize", None, &subscriptions, Some("two")).is_ok());

        let closed = item_retrieval_access("whitelist", None, &[], None).unwrap_err();
        assert_eq!(error_condition(&closed), Some("not-allowed"));
        assert!(error_payload(&closed).unwrap().1.contains("closed-node"));

        let not_subscribed = item_retrieval_access("authorize", None, &[], None).unwrap_err();
        assert_eq!(error_condition(&not_subscribed), Some("not-authorized"));
        assert!(error_payload(&not_subscribed)
            .unwrap()
            .1
            .contains("not-subscribed"));

        assert_eq!(
            error_condition(
                &item_retrieval_access("open", Some("outcast"), &[], None).unwrap_err()
            ),
            Some("forbidden")
        );
    }

    #[test]
    fn parses_and_round_trips_node_configuration() {
        let xml = "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#access_model'><value>authorize</value></field><field var='pubsub#max_items'><value>42</value></field><field var='pubsub#persist_items'><value>0</value></field></x></configure>";
        let document = Document::parse(xml).unwrap();
        let parsed =
            parse_node_config(document.root_element(), PubSubNodeConfig::default()).unwrap();
        assert_eq!(parsed.access_model, "authorize");
        assert_eq!(parsed.max_items, 42);
        assert!(!parsed.persist_items);
        let rendered = node_config_form(&parsed, "form");
        let rendered_doc = Document::parse(&rendered).unwrap();
        let fields = data_form_fields(rendered_doc.root_element());
        assert_eq!(fields["pubsub#max_items"], ["42"]);
        assert_eq!(fields["pubsub#children_association_policy"], ["owners"]);
        assert!(config_equivalent(&parsed, &parsed.clone()));
    }

    #[test]
    fn rejects_non_submit_duplicate_and_multi_value_configuration_fields() {
        for xml in [
            "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field></x></configure>",
            "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#max_items'><value>1</value><value>2</value></field></x></configure>",
            "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#max_items'><value>1</value></field><field var='pubsub#max_items'><value>2</value></field></x></configure>",
            "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field></x><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field></x></configure>",
            "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value><unexpected/></field></x></configure>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                parse_node_config(document.root_element(), PubSubNodeConfig::default())
                    .unwrap_err(),
                "bad-request"
            );
        }
    }

    #[test]
    fn unsupported_access_models_use_the_required_pubsub_error() {
        let xml = "<configure xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#access_model'><value>presence</value></field></x></configure>";
        let document = Document::parse(xml).unwrap();
        let condition =
            parse_node_config(document.root_element(), PubSubNodeConfig::default()).unwrap_err();
        assert_eq!(condition, "unsupported-access-model");

        let reply = super::node_config_parse_error(condition);
        assert_eq!(error_condition(&reply), Some("not-acceptable"));
        assert!(error_payload(&reply)
            .unwrap()
            .1
            .contains("unsupported-access-model"));
    }

    #[test]
    fn collection_defaults_are_selected_with_the_registered_data_form() {
        let xml = format!(
            "<default xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{NODE_CONFIG_FORM}</value></field><field var='pubsub#node_type'><value>collection</value></field></x></default>"
        );
        let document = Document::parse(&xml).unwrap();
        assert_eq!(
            super::requested_default_node_type(document.root_element()).unwrap(),
            "collection"
        );

        for invalid in [
            "<default xmlns='http://jabber.org/protocol/pubsub#owner' type='collection'/>",
            "<default xmlns='http://jabber.org/protocol/pubsub#owner'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>wrong</value></field></x></default>",
        ] {
            let document = Document::parse(invalid).unwrap();
            assert_eq!(
                error_condition(
                    &super::requested_default_node_type(document.root_element()).unwrap_err()
                ),
                Some("bad-request")
            );
        }
    }

    #[test]
    fn published_items_keep_inherited_namespaces_and_normalize_ids() {
        let document = Document::parse(
            "<pubsub xmlns='http://jabber.org/protocol/pubsub' xmlns:p='urn:test'><publish node='n'><item><p:value p:kind='demo'>a&amp;b</p:value></item></publish></pubsub>",
        )
        .unwrap();
        let item = document
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "item")
            .unwrap();
        let serialized = serialize_pubsub_item(item, "generated&amp;id").unwrap();
        let reparsed = Document::parse(&serialized).unwrap();
        let root = reparsed.root_element();
        assert_eq!(root.tag_name().namespace(), None);
        assert_eq!(root.attribute("id"), Some("generated&amp;id"));
        let payload = root.children().find(|node| node.is_element()).unwrap();
        assert_eq!(payload.tag_name().namespace(), Some("urn:test"));
        assert_eq!(payload.attribute(("urn:test", "kind")), Some("demo"));
        assert_eq!(payload.text(), Some("a&b"));
    }

    #[test]
    fn subscription_options_round_trip_collection_fields() {
        let mut options = PubSubSubscriptionOptions::for_node_type("collection");
        options.digest = true;
        options.digest_frequency = 60_000;
        options.include_body = true;
        options.subscription_type = "all".to_owned();
        options.subscription_depth = None;
        options.show_values = vec!["chat".to_owned(), "online".to_owned()];
        let form = subscription_options_form(&options, "submit", true, "collection");
        let document = Document::parse(&form).unwrap();
        let parsed = parse_subscription_options(
            document.root_element(),
            PubSubSubscriptionOptions::for_node_type("collection"),
            "collection",
            true,
        )
        .unwrap();
        assert!(parsed.digest);
        assert_eq!(parsed.digest_frequency, 60_000);
        assert!(parsed.include_body);
        assert_eq!(parsed.subscription_type, "all");
        assert_eq!(parsed.subscription_depth, None);
        assert_eq!(parsed.show_values, ["chat", "online"]);

        let invalid = form.replace("<value>true</value>", "<value>not-a-boolean</value>");
        let document = Document::parse(&invalid).unwrap();
        let reply = parse_subscription_options(
            document.root_element(),
            PubSubSubscriptionOptions::for_node_type("collection"),
            "collection",
            true,
        )
        .unwrap_err();
        assert_eq!(error_condition(&reply), Some("bad-request"));
        assert!(error_payload(&reply).unwrap().1.contains("invalid-options"));
    }

    #[test]
    fn subscription_leases_are_clamped_to_the_service_maximum() {
        let xml = format!(
            "<x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{SUBSCRIBE_OPTIONS_FORM}</value></field><field var='pubsub#expire'><value>2099-01-01T00:00:00Z</value></field></x>"
        );
        let document = Document::parse(&xml).unwrap();
        let before = Utc::now();
        let parsed = parse_subscription_options(
            document.root_element(),
            PubSubSubscriptionOptions::for_node_type("leaf"),
            "leaf",
            false,
        )
        .unwrap();
        let expiry = parsed.expire.unwrap();
        assert!(expiry > before);
        assert!(expiry <= before + chrono::Duration::days(366));
    }

    #[test]
    fn durable_digest_waits_for_presence_but_stops_on_privacy_denial() {
        assert!(!pubsub_policy_suppression_is_terminal(0, 0));
        assert!(!pubsub_policy_suppression_is_terminal(0, 1));
        assert!(!pubsub_policy_suppression_is_terminal(1, 1));
        assert!(pubsub_policy_suppression_is_terminal(1, 0));
    }

    #[test]
    fn extended_errors_use_pubsub_namespace_and_gone_carries_uri_text() {
        let unsupported = PubSubReply::ExtendedError(PubSubError::unsupported("publish"));
        let (_, extra) = error_payload(&unsupported).unwrap();
        assert!(extra.contains("xmlns='http://jabber.org/protocol/pubsub#errors'"));
        assert!(extra.contains("feature='publish'"));

        let moved = super::pubsub_iq_error(
            "i1",
            "pubsub.example.test",
            &PubSubReply::ExtendedError(PubSubError::moved(
                "xmpp:pubsub.example.test?;node=new&amp;x".to_owned(),
            )),
        );
        let document = Document::parse(&moved).unwrap();
        let gone = document
            .descendants()
            .find(|node| node.tag_name().name() == "gone")
            .unwrap();
        assert_eq!(
            gone.text(),
            Some("xmpp:pubsub.example.test?;node=new&amp;x")
        );
    }

    #[test]
    fn publish_options_require_the_distinct_form_type_and_known_fields() {
        let valid = format!(
            "<publish-options xmlns='http://jabber.org/protocol/pubsub'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>{PUBLISH_OPTIONS_FORM}</value></field><field var='pubsub#max_items'><value>2</value></field></x></publish-options>"
        );
        let document = Document::parse(&valid).unwrap();
        let parsed =
            parse_publish_options(document.root_element(), PubSubNodeConfig::default()).unwrap();
        assert_eq!(parsed.max_items, 2);

        for invalid in [
            valid.replace(
                PUBLISH_OPTIONS_FORM,
                "http://jabber.org/protocol/pubsub#node_config",
            ),
            valid.replace(
                "</x>",
                "<field var='pubsub#vendor-extension'><value>1</value></field></x>",
            ),
        ] {
            let document = Document::parse(&invalid).unwrap();
            assert_eq!(
                parse_publish_options(document.root_element(), PubSubNodeConfig::default(),)
                    .unwrap_err(),
                "bad-request"
            );
        }
    }

    #[test]
    fn publish_batch_has_a_bounded_server_resource_ceiling() {
        // The protocol handler additionally compares this count with the
        // node's max_items and emits max-items-exceeded. This helper enforces
        // the independent hard ceiling before payload parsing/allocation.
        assert!(publish_batch_size_allowed(3));
        assert!(publish_batch_size_allowed(MAX_PUBLISH_ITEMS));
        assert!(!publish_batch_size_allowed(MAX_PUBLISH_ITEMS + 1));
    }

    #[test]
    fn rsm_pages_have_stable_bounds_counts_and_strict_cursors() {
        let make_item = |id: &str| PubSubItem {
            item_id: id.to_owned(),
            xml_payload: format!("<item id='{id}'/>"),
            created_at: Utc::now(),
        };
        let items = || {
            ["newest", "middle", "oldest"]
                .into_iter()
                .map(make_item)
                .collect::<Vec<_>>()
        };

        let document = Document::parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><after>newest</after></set>",
        )
        .unwrap();
        let request = parse_pubsub_rsm(document.root_element()).unwrap();
        let (page, metadata) = pubsub_rsm_page(items(), &request, 100).unwrap();
        assert_eq!(page[0].item_id, "middle");
        assert!(metadata.contains("<first index='1'>middle</first>"));
        assert!(metadata.contains("<count>3</count>"));

        let document = Document::parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><max>2</max><before/></set>",
        )
        .unwrap();
        let request = parse_pubsub_rsm(document.root_element()).unwrap();
        let (page, _) = pubsub_rsm_page(items(), &request, 100).unwrap();
        assert_eq!(
            page.iter()
                .map(|item| item.item_id.as_str())
                .collect::<Vec<_>>(),
            ["middle", "oldest"]
        );

        let document =
            Document::parse("<set xmlns='http://jabber.org/protocol/rsm'><max>0</max></set>")
                .unwrap();
        let request = parse_pubsub_rsm(document.root_element()).unwrap();
        let (page, metadata) = pubsub_rsm_page(items(), &request, 100).unwrap();
        assert!(page.is_empty());
        assert_eq!(
            metadata,
            "<set xmlns='http://jabber.org/protocol/rsm'><count>3</count></set>"
        );

        let document = Document::parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><after>missing</after></set>",
        )
        .unwrap();
        let request = parse_pubsub_rsm(document.root_element()).unwrap();
        assert!(matches!(
            pubsub_rsm_page(items(), &request, 100),
            Err(PubSubReply::Error("item-not-found"))
        ));
    }

    #[test]
    fn advertised_collection_and_rsm_feature_names_match_the_registry() {
        assert!(SERVICE_FEATURES.contains(&"multi-collections"));
        assert!(!SERVICE_FEATURES.contains(&"multi-collection"));
        assert!(SERVICE_FEATURES.contains(&"collections"));
        assert!(SERVICE_FEATURES.contains(&"rsm"));
    }

    #[test]
    fn disco_rsm_supports_forward_reverse_zero_and_strict_cursor_pages() {
        let items = || {
            ["alpha", "beta", "gamma", "serverinfo"]
                .into_iter()
                .map(|node| DiscoItem {
                    node: node.to_owned(),
                    title: None,
                    published_item: false,
                })
                .collect::<Vec<_>>()
        };
        let parse = |xml: &str| {
            let document = Document::parse(xml).unwrap();
            parse_pubsub_rsm(document.root_element()).unwrap()
        };
        let request = parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><after>alpha</after></set>",
        );
        let (page, metadata) = disco_rsm_page(items(), &request, 100).unwrap();
        assert_eq!(page[0].node, "beta");
        assert!(metadata.contains("<first index='1'>beta</first>"));
        assert!(metadata.contains("<last>beta</last><count>4</count>"));

        let request =
            parse("<set xmlns='http://jabber.org/protocol/rsm'><max>2</max><before/></set>");
        let (page, metadata) = disco_rsm_page(items(), &request, 100).unwrap();
        assert_eq!(
            page.iter()
                .map(|item| item.node.as_str())
                .collect::<Vec<_>>(),
            ["gamma", "serverinfo"]
        );
        assert!(metadata.contains("<first index='2'>gamma</first>"));

        let request = parse(
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><before>gamma</before></set>",
        );
        assert_eq!(
            disco_rsm_page(items(), &request, 100).unwrap().0[0].node,
            "beta"
        );
        let request = parse("<set xmlns='http://jabber.org/protocol/rsm'><max>0</max></set>");
        let (page, metadata) = disco_rsm_page(items(), &request, 100).unwrap();
        assert!(page.is_empty());
        assert_eq!(
            metadata,
            "<set xmlns='http://jabber.org/protocol/rsm'><count>4</count></set>"
        );

        let request =
            parse("<set xmlns='http://jabber.org/protocol/rsm'><after>missing</after></set>");
        assert!(matches!(
            disco_rsm_page(items(), &request, 100),
            Err(PubSubReply::Error("item-not-found"))
        ));
        for invalid in [
            "<set xmlns='http://jabber.org/protocol/rsm'><after>alpha</after><before>gamma</before></set>",
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1001</max></set>",
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><max>2</max></set>",
            "<set xmlns='http://jabber.org/protocol/rsm'>not-whitespace<max>1</max></set>",
        ] {
            let document = Document::parse(invalid).unwrap();
            assert!(matches!(
                parse_pubsub_rsm(document.root_element()),
                Err(PubSubReply::Error("bad-request"))
            ));
        }
    }
}
