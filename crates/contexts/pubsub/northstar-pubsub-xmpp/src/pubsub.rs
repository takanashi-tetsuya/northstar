//! XEP-0060 PubSub service handlers, for client sessions and federated peers.

use anyhow::Result;
use northstar_pubsub_application::{
    service::{CollectionDiscoItems, LeafDiscoItems, PubSubSubscriptionOptionsRead},
    PubSubAuthorizeSubscriptionCommand, PubSubCollectionEdgeCommand, PubSubCollectionEdgeOperation,
    PubSubCollectionEdgeResult, PubSubConfigureNodeCommand, PubSubCreateNodeCommand,
    PubSubDeleteNodeCommand, PubSubListPageQuery, PubSubOwnerRead, PubSubOwnerReadKind,
    PubSubPublishCommand, PubSubPurgeNodeCommand, PubSubRetractCommand, PubSubRootDiscoQuery,
    PubSubService, PubSubSetAffiliationsCommand, PubSubSetSubscriptionsCommand,
    PubSubSubscribeCommand, PubSubUnsubscribeCommand, PubSubUpdateSubscriptionOptionsCommand,
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
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap},
};

mod entity;
mod forms;
mod owner;
mod parsing;

use self::entity::{handle_entity_get, handle_entity_set};
use self::forms::{
    data_form_fields, first_field, has_duplicate_fields, node_config_form, parse_node_config,
    parse_publish_options, parse_subscription_options, subscription_options,
    subscription_options_form, supports_include_body,
};
#[cfg(test)]
use self::owner::{collection_edge_reply, requested_default_node_type};
use self::owner::{handle_owner_get, handle_owner_set};
use self::parsing::{PubSubNamespace, PubSubRsmRequest};

/// What the server provides to the XEP-0060 service handlers.
pub trait PubSubHost: Sync {
    /// The server's local domain; the PubSub service's JID is `pubsub.` followed by it.
    fn pubsub_local_domain(&self) -> &str;
    /// The server's name, shown in the PubSub service identity.
    fn pubsub_server_name(&self) -> &str;
    /// The node and storage limits of one node owner.
    fn pubsub_node_owner_limits(&self) -> PubSubOwnerLimits;
    /// The PubSub application service, over the repository the composition root binds.
    fn pubsub_application_service(&self) -> &PubSubService<impl crate::PubSubRepositories>;
}

/// The node and storage limits of one PubSub node owner.
#[derive(Clone, Copy, Debug)]
pub struct PubSubOwnerLimits {
    /// The most nodes one owner may hold.
    pub max_nodes: i64,
    /// The most bytes of item storage one owner's nodes may hold.
    pub max_storage_bytes: i64,
}

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

/// The outcome of handling a PubSub service request.
#[derive(Debug)]
pub enum PubSubReply {
    /// The result payload.
    Result(String),
    /// A plain error condition.
    Error(&'static str),
    /// An error with an application condition.
    ExtendedError(PubSubError),
}

/// An XEP-0060 PubSub error with stanza and application conditions.
pub type PubSubError = northstar_xep_0060::PubSubError;

/// Extract the stanza error condition name from a PubSub reply.
pub fn error_condition(error: &PubSubReply) -> Option<&'static str> {
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

/// Build a client IQ error response for a PubSub reply.
pub fn pubsub_iq_error(id: &str, from: &str, reply: &PubSubReply) -> String {
    northstar_xep_0060::build_iq_error(id, from, &reply_error(reply))
}

/// Build a federated server-to-server IQ error response for a PubSub reply.
pub fn pubsub_s2s_iq_error(id: &str, from: &str, to: &str, reply: &PubSubReply) -> String {
    northstar_xep_0060::build_s2s_iq_error(id, from, to, &reply_error(reply))
}

fn reply_error(reply: &PubSubReply) -> Cow<'_, PubSubError> {
    match reply {
        PubSubReply::Result(_) => Cow::Owned(PubSubError::simple("undefined-condition")),
        PubSubReply::Error(condition) => Cow::Owned(PubSubError::simple(condition)),
        PubSubReply::ExtendedError(error) => Cow::Borrowed(error),
    }
}

/// Render the service discovery disco#info identity and feature query result.
pub fn service_disco_payload<H: PubSubHost>(host: &H) -> String {
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
        .child(
            XmlElement::new("identity")
                .attr("category", "pubsub")
                .attr("type", "service")
                .attr(
                    "name",
                    format!("{} PubSub Service", host.pubsub_server_name()),
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

/// Handle a disco#info request addressed to the PubSub service or one of its nodes.
pub async fn federated_disco_info<H: PubSubHost>(
    host: &H,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<PubSubReply> {
    let Some(node_name) = requested_node else {
        return Ok(PubSubReply::Result(service_disco_payload(host)));
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
    let Some(node) = host
        .pubsub_application_service()
        .get_node(node_name)
        .await?
    else {
        return missing_node_reply(host, node_name).await;
    };
    if !host
        .pubsub_application_service()
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
    query.push_validated_fragment(&node_metadata_form(host, &node).await?)?;
    Ok(PubSubReply::Result(query.finish()))
}

/// Handle a disco#items request addressed to the PubSub service or one of its nodes.
pub async fn federated_disco_items<H: PubSubHost>(
    host: &H,
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
    let service = pubsub_domain(host);
    let requester_full = normalized_jid(requester)?;
    let requester = normalized_bare(&requester_full)?;
    if requested_node.is_none() {
        return root_disco_items(host, &service, &requester, rsm.as_ref()).await;
    }
    let mut visible = Vec::new();
    if let Some(node_name) = requested_node {
        if node_name == "serverinfo" {
            // The synthetic serverinfo node has one current PubSub item, but
            // its data is retrieved via XEP-0060 rather than disco#items.
        } else {
            let Some(node) = host
                .pubsub_application_service()
                .get_node(node_name)
                .await?
            else {
                return missing_node_reply(host, node_name).await;
            };
            if node.node_type == "collection" {
                let children = match host
                    .pubsub_application_service()
                    .collection_disco_items(node_name, &requester)
                    .await?
                {
                    CollectionDiscoItems::Items(children) => children,
                    CollectionDiscoItems::NotFound => {
                        return missing_node_reply(host, node_name).await;
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
                let item_ids = match host
                    .pubsub_application_service()
                    .leaf_disco_items(node_name, &requester)
                    .await?
                {
                    LeafDiscoItems::Items(item_ids) => item_ids,
                    LeafDiscoItems::NotFound => {
                        return missing_node_reply(host, node_name).await;
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

async fn root_disco_items<H: PubSubHost>(
    host: &H,
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
    let Some(page) = host
        .pubsub_application_service()
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

/// Dispatch an incoming client or federated PubSub IQ request.
pub async fn handle_request<H: PubSubHost>(
    host: &H,
    requester: &str,
    kind: &str,
    child: Node<'_, '_>,
) -> Result<PubSubReply> {
    let parsed = match parsing::parse_pubsub_envelope(child, kind) {
        Ok(parsed) => parsed,
        Err(condition) => return Ok(PubSubReply::Error(condition)),
    };
    match (parsed.namespace, kind) {
        (PubSubNamespace::Entity, "get") => {
            handle_entity_get(host, requester, parsed.operations).await
        }
        (PubSubNamespace::Entity, "set") => {
            handle_entity_set(host, requester, parsed.operations).await
        }
        (PubSubNamespace::Owner, "get") => {
            handle_owner_get(host, requester, parsed.operations).await
        }
        (PubSubNamespace::Owner, "set") => {
            handle_owner_set(host, requester, parsed.operations).await
        }
        _ => unreachable!("shared PubSub envelope parser validates IQ kinds"),
    }
}

/// Process a subscription authorization form submission from a node owner.
pub async fn handle_authorization_response<H: PubSubHost>(
    host: &H,
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
    let _ = host
        .pubsub_application_service()
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

async fn is_owner<H: PubSubHost>(host: &H, node_id: uuid::Uuid, jid: &str) -> Result<bool> {
    host.pubsub_application_service()
        .is_owner(node_id, jid)
        .await
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

/// Strip the service's PubSub namespace from a stored item payload for event delivery.
pub fn event_item_xml(stored: &str) -> String {
    stored.replacen(&format!(" xmlns='{NS_PUBSUB}'"), "", 1)
}

async fn missing_node_reply<H: PubSubHost>(host: &H, node: &str) -> Result<PubSubReply> {
    Ok(
        match host
            .pubsub_application_service()
            .node_redirect(node)
            .await?
        {
            Some(uri) => PubSubReply::ExtendedError(PubSubError::moved(uri)),
            None => PubSubReply::Error("item-not-found"),
        },
    )
}

/// Render the XEP-0060 node metadata form for disco#info queries.
pub async fn node_metadata_form<H: PubSubHost>(host: &H, node: &PubSubNode) -> Result<String> {
    let title = node.title.as_deref().unwrap_or(&node.node);
    let description = node.description.as_deref().unwrap_or_default();
    let metadata = host
        .pubsub_application_service()
        .node_metadata(node.id)
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

/// The PubSub service's JID.
pub fn pubsub_domain<H: PubSubHost>(host: &H) -> String {
    format!("pubsub.{}", host.pubsub_local_domain())
}

fn normalized_bare(jid: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonical_bare_key(jid)
}

fn normalized_jid(jid: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonicalize(jid)
}

fn valid_bare_jid(value: &str) -> bool {
    northstar_xmpp_types::jid::CanonicalJid::parse_bare(value).is_ok()
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
    parsing::parse_pubsub_rsm(set).map_err(PubSubReply::Error)
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
