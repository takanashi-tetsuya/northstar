use super::{Action, ProtocolSession};
use crate::services::xml_util::*;
use crate::state::{pubsub_digest_worker::PubSubDigestWorkerContext, AppState};
use crate::xmpp::mam_pubsub_parsing::{self, PubSubNamespace, PubSubRsmRequest};
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use northstar_pubsub_application::{
    service::{
        subscription_event_children, CollectionDiscoItems, LeafDiscoItems,
        PubSubSubscriptionOptionsRead,
    },
    PubSubAuthorizeSubscriptionCommand, PubSubCollectionEdgeCommand, PubSubCollectionEdgeOperation,
    PubSubCollectionEdgeResult, PubSubConfigureNodeCommand, PubSubCreateNodeCommand,
    PubSubDeleteNodeCommand, PubSubListPageQuery, PubSubOwnerRead, PubSubOwnerReadKind,
    PubSubPublishCommand, PubSubPurgeNodeCommand, PubSubRetractCommand, PubSubRootDiscoQuery,
    PubSubSetAffiliationsCommand, PubSubSetSubscriptionsCommand, PubSubSubscribeCommand,
    PubSubUnsubscribeCommand, PubSubUpdateSubscriptionOptionsCommand,
};
use northstar_pubsub_core::{
    CollectionUpdateOutcome, CreateNodeOutcome, OwnerMutationOutcome, PubSubConfigOutcome,
    PubSubConfigureNodeWrite, PubSubCreateNodeWrite, PubSubDeleteNodeWrite, PubSubItem, PubSubNode,
    PubSubNodeConfig, PubSubPublishOutcome, PubSubPublishWrite, PubSubPurgeNodeWrite,
    PubSubRetractOutcome, PubSubRetractWrite, PubSubSetAffiliationsWrite,
    PubSubSetSubscriptionsWrite, PubSubSubscribeOutcome, PubSubSubscribeWrite, PubSubSubscription,
    PubSubSubscriptionOptions, PubSubUnsubscribeOutcome, PubSubUnsubscribeWrite,
    SetAffiliationsOutcome, SetSubscriptionsOutcome, SubscriptionOptionsOutcome,
};
use roxmltree::Node;
use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

mod entity;
mod forms;
mod owner;

use self::entity::{handle_entity_get, handle_entity_set};
use self::forms::{
    data_form_fields, first_field, has_duplicate_fields, node_config_form, parse_node_config,
    parse_publish_options, parse_subscription_options, subscription_options,
    subscription_options_form, supports_include_body,
};
#[cfg(test)]
use self::owner::{collection_edge_reply, requested_default_node_type};
use self::owner::{handle_owner_get, handle_owner_set};

#[derive(Clone, Debug)]
struct DiscoItem {
    node: String,
    title: Option<String>,
    published_item: bool,
}

const NS_PUBSUB: &str = northstar_xep_0060::NS_PUBSUB;
const NS_PUBSUB_OWNER: &str = northstar_xep_0060::NS_PUBSUB_OWNER;
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

fn pubsub_iq_error(id: &str, from: &str, reply: &PubSubReply) -> String {
    northstar_xep_0060::build_iq_error(id, from, &reply_error(reply))
}

pub(crate) fn pubsub_s2s_iq_error(id: &str, from: &str, to: &str, reply: &PubSubReply) -> String {
    northstar_xep_0060::build_s2s_iq_error(id, from, to, &reply_error(reply))
}

fn reply_error(reply: &PubSubReply) -> Cow<'_, PubSubError> {
    match reply {
        PubSubReply::Result(_) => Cow::Owned(PubSubError::simple("undefined-condition")),
        PubSubReply::Error(condition) => Cow::Owned(PubSubError::simple(condition)),
        PubSubReply::ExtendedError(error) => Cow::Borrowed(error),
    }
}

pub(crate) fn service_disco_payload(state: &AppState) -> String {
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
        .child(
            XmlElement::new("identity")
                .attr("category", "pubsub")
                .attr("type", "service")
                .attr("name", format!("{} PubSub Service", state.server_name())),
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
    if !state
        .pubsub_service()
        .can_retrieve_node(&node, &normalized_bare(requester)?)
        .await?
    {
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
            if node.node_type == "collection" {
                let children = match state
                    .pubsub_service()
                    .collection_disco_items(node_name, &requester)
                    .await?
                {
                    CollectionDiscoItems::Items(children) => children,
                    CollectionDiscoItems::NotFound => {
                        return missing_node_reply(state, node_name).await;
                    }
                    CollectionDiscoItems::NotCollection | CollectionDiscoItems::Forbidden => {
                        return Ok(PubSubReply::Error("forbidden"));
                    }
                };
                for child in children {
                    // XEP-0248 defines collection visibility using the
                    // collection's access model, not each child's model.
                    visible.push(DiscoItem {
                        node: child.node,
                        title: child.title,
                        published_item: false,
                    });
                }
            } else if node.node_type == "leaf" {
                let item_ids = match state
                    .pubsub_service()
                    .leaf_disco_items(node_name, &requester)
                    .await?
                {
                    LeafDiscoItems::Items(item_ids) => item_ids,
                    LeafDiscoItems::NotFound => {
                        return missing_node_reply(state, node_name).await;
                    }
                    LeafDiscoItems::NotLeaf | LeafDiscoItems::Forbidden => {
                        return Ok(PubSubReply::Error("forbidden"));
                    }
                };
                for item_id in item_ids {
                    visible.push(DiscoItem {
                        node: item_id,
                        title: None,
                        published_item: true,
                    });
                }
            } else {
                return Ok(PubSubReply::Error("forbidden"));
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
    let cursor = rsm.and_then(|request| {
        request
            .after
            .as_deref()
            .or_else(|| request.before.as_ref().and_then(|value| value.as_deref()))
    });
    let backwards = rsm.is_some_and(|request| request.before.is_some());
    let Some(page) = state
        .pubsub_service()
        .discover_roots(PubSubRootDiscoQuery {
            requester,
            cursor,
            backwards,
            max: rsm.and_then(|request| request.max),
            rsm_requested: rsm.is_some(),
        })
        .await?
    else {
        return Ok(PubSubReply::Error("item-not-found"));
    };
    let visible = page
        .nodes
        .into_iter()
        .map(|node| DiscoItem {
            node: node.node,
            title: node.title,
            published_item: false,
        })
        .collect::<Vec<_>>();
    // A service-side default limit is always finite. If an old client omitted
    // RSM and the result was truncated, include the notation recommended by
    // XEP-0059/XEP-0060 so it can discover and continue the full set.
    let rsm_xml = if page.include_rsm {
        rsm_set_element(
            visible
                .first()
                .map(|item| (page.first_index, item.node.as_str())),
            visible.last().map(|item| item.node.as_str()),
            page.total,
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
            Err(error) if northstar_pubsub_application::is_pubsub_mutation_busy(&error) => {
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
        if northstar_xmpp_types::jid::canonicalize_bare(to)
            .ok()
            .as_deref()
            != northstar_xmpp_types::jid::canonicalize_bare(&self.pubsub_domain())
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
    // XEP-0060 subscription authorization forms identify the request with
    // the node and subscriber JID; `pubsub#subid` is not a required response
    // field. The service resolves the unique pending subscription and rejects
    // an echoed SubID that does not match it.
    let requester = normalized_bare(requester)?;
    let _ = state
        .pubsub_service()
        .execute_pubsub_authorize_subscription(PubSubAuthorizeSubscriptionCommand {
            requester: &requester,
            node: node_name,
            subscriber_jid: &subscriber,
            echoed_subid: first_field(&fields, "pubsub#subid"),
            allow,
        })
        .await?;
    Ok(())
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

#[cfg(test)]
fn pubsub_policy_suppression_is_terminal(
    show_eligible_resources: usize,
    policy_eligible_resources: usize,
) -> bool {
    northstar_xep_0060::pubsub_policy_suppression_is_terminal(
        show_eligible_resources,
        policy_eligible_resources,
    )
}

pub(crate) async fn deliver_due_pubsub_digests(
    context: &PubSubDigestWorkerContext,
) -> Result<usize> {
    let digests = context.claim_due().await?;
    let count = digests.len();
    for digest in digests {
        let show_values = if let Some(snapshot) = digest.show_values.clone() {
            Some(snapshot)
        } else {
            context
                .current_show_values(digest.subscription_node_id, &digest.subscriber_jid)
                .await?
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
                if let Err(error) = context
                    .notification()
                    .route_children(
                        &digest.subscriber_jid,
                        children,
                        Some(&show_values),
                        uuid::Uuid::new_v4(),
                    )
                    .await
                {
                    let pending_ids = batches[index..]
                        .iter()
                        .flat_map(|(ids, _)| ids.iter().copied())
                        .collect::<Vec<_>>();
                    context.release(&pending_ids).await?;
                    return Err(error);
                }
                context.acknowledge(ids).await?;
            }
        } else {
            context.acknowledge(&digest.ids).await?;
        }
    }
    Ok(count)
}

pub(crate) fn start_pubsub_digest_delivery(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    let context = Arc::new(state.pubsub_digest_worker_context());
    registry.supervise(
        "pubsub-digest-delivery",
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(5)),
        cancel,
        move |heartbeat| {
            let context = Arc::clone(&context);
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
                    if let Err(error) = deliver_due_pubsub_digests(&context).await {
                        heartbeat.error(&error);
                        tracing::error!(
                            ?error,
                            "failed to deliver durable PubSub notification digest"
                        );
                    } else {
                        heartbeat.ok();
                    }
                }
            }
        },
    );
}

pub(crate) fn start_pubsub_event_outbox_delivery(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let registry = Arc::clone(state.worker_registry());
    let context = Arc::new(state.pubsub_event_outbox_worker_context());
    registry.supervise(
        "pubsub-event-outbox-delivery",
        northstar_runtime::workers::WorkerCriticality::Restartable,
        northstar_runtime::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let cancel = cancel.clone();
            async move {
                let mut maintenance_ticks = 0_u32;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
                    }
                    let claimed = context.claim().await?;
                    for item in claimed {
                        let _delivery_timer = context.start_delivery_timer();
                        if !context.renew(&item).await? {
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
                            context.deliver(&item),
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
                                if !context.acknowledge(&item).await? {
                                    tracing::warn!(
                                        delivery_id = %item.delivery_id,
                                        "PubSub event outbox acknowledgement lost its lease"
                                    );
                                }
                            }
                            Err(error) if !item.payload_binding_valid() => {
                                context
                                    .dead_letter_integrity(&item, &error.to_string())
                                    .await?;
                            }
                            Err(error) => {
                                context.retry(&item, &error.to_string()).await?;
                            }
                        }
                    }
                    maintenance_ticks = maintenance_ticks.saturating_add(1);
                    if maintenance_ticks >= 20 {
                        maintenance_ticks = 0;
                        context.maintain().await?;
                    }
                    heartbeat.ok();
                }
            }
        },
    );
}

async fn deliver_last_items_on_presence(
    state: Arc<AppState>,
    outbound: crate::xmpp::outbound::OutboundSender,
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
                || !state
                    .pubsub_service()
                    .can_retrieve_node(&node, &requester_bare)
                    .await?
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

pub(crate) async fn node_metadata_form(state: &AppState, node: &PubSubNode) -> Result<String> {
    let title = node.title.as_deref().unwrap_or(&node.node);
    let description = node.description.as_deref().unwrap_or_default();
    let metadata = state.pubsub_service().node_metadata(node.id).await?;
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
        (
            "pubsub#num_subscribers",
            metadata.active_subscribers.to_string(),
        ),
    ] {
        form.push_child(data_field_element(variable, None, [value]));
    }
    form.push_child(data_field_element(
        "pubsub#owner",
        Some("jid-multi"),
        metadata.owners.iter(),
    ));
    form.push_child(data_field_element(
        "pubsub#publisher",
        Some("jid-multi"),
        metadata.publishers.iter(),
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
    format!("pubsub.{}", state.local_domain())
}

fn normalized_bare(jid: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonical_bare_key(jid)
}

fn normalized_jid(jid: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonicalize(jid)
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
    page_with_rsm(items, request, fallback_max, |item| &item.item_id)
}

fn disco_rsm_page(
    items: Vec<DiscoItem>,
    request: &PubSubRsmRequest,
    fallback_max: usize,
) -> std::result::Result<(Vec<DiscoItem>, String), PubSubReply> {
    page_with_rsm(items, request, fallback_max, |item| &item.node)
}

fn page_with_rsm<T>(
    items: Vec<T>,
    request: &PubSubRsmRequest,
    fallback_max: usize,
    id: impl Fn(&T) -> &str,
) -> std::result::Result<(Vec<T>, String), PubSubReply> {
    let page = northstar_pubsub_application::page_pubsub_list(
        items,
        PubSubListPageQuery {
            max: request.max,
            after: request.after.as_deref(),
            before: request.before.as_ref().map(|before| before.as_deref()),
        },
        fallback_max,
        id,
    )
    .map_err(|_| PubSubReply::Error("item-not-found"))?;
    let rsm = rsm_set_element(
        page.first.as_ref().map(|(index, id)| (*index, id.as_str())),
        page.last.as_deref(),
        page.total,
    )
    .finish();
    Ok((page.items, rsm))
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
mod tests;
