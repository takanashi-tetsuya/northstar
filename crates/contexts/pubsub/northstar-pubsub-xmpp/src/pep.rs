//! XEP-0163 Personal Eventing: the PEP handlers of client sessions, event fan-out and send-last delivery.

use crate::pubsub::PubSubHost;
use anyhow::Result;
#[cfg(test)]
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use northstar_pubsub_application::{
    profile::{
        AvatarPresenceUpdate, ProfileAudienceSnapshot, ProfilePublishResult, ProfilePublishStatus,
        ProfileRepository, ProfileService,
    },
    PepAccountItemsRead, PepAccountQuery, PepConfigureNodeCommand, PepCreateNodeCommand,
    PepDeleteNodeCommand, PepItemQuery, PepItemRead, PepItemSelection, PepNodeInfoRead,
    PepNodeItemsRead, PepNodeQuery, PepOwnerQuery, PepOwnerSubscriptionsRead,
    PepPublishItemsCommand, PepPurgeNodeCommand, PepRequester, PepRetractCommand,
    PepSetAffiliationsCommand, PepUnsubscribeBatchCommand, PubSubService,
};
use northstar_pubsub_core::pep_nodes::{BOOKMARKS2, VCARD4};
use northstar_pubsub_core::{
    PepAccessDenial, PepAudienceSnapshot, PepConfigureNodeWrite, PepCreateOutcome,
    PepDeleteNodeWrite, PepDirectStateSnapshot, PepDirectStateTransition, PepNodeConfig,
    PepOutboxAuthorizationMode, PepOutboxEventKind, PepOutboxFactory, PepOwnerMutationOutcome,
    PepProfileWrite, PepPublishOutcome, PepPublishWrite, PepPurgeNodeWrite, PepQuotas,
    PepReplayPage, PepReplayQuery, PepRetractWrite, PepSetAffiliationsWrite, PepSubscribeOutcome,
    PepSubscribeSnapshot, PepSubscribeWrite, PepSubscriptionActor, PepUnsubscribeOutcome,
    PepUnsubscribeWrite, PubSubAccount, PubSubOutboxInsert, PubSubTimeSources, PEP_MAX_ITEMS,
};
use northstar_xml_builder::rewrite::set_root_attribute;
use northstar_xml_builder::stanza::{
    child_text, iq_error, iq_error_from, iq_result, iq_result_from,
};
use northstar_xml_builder::XmlElement;
#[cfg(test)]
use northstar_xmpp_avatar::valid_png_image;
use northstar_xmpp_avatar::{AVATAR_DATA, AVATAR_METADATA};
use roxmltree::Node;
#[cfg(test)]
use sha1::{Digest, Sha1};
use std::collections::HashSet;

mod forms;
mod node_management;
mod notifications;
mod publishing;

use self::node_management::{parse_form_bool, pep_create, valid_node_name};
use self::notifications::{
    pep_subscription_element, published_event_items, render_pep_direct_state_messages,
};
use crate::events::{profile_item_event, strip_pubsub_item_root_namespaces};
use crate::payload::valid_pep_payload;

#[cfg(test)]
use self::notifications::published_event_item;
#[cfg(test)]
use self::publishing::{normalized_pep_item, publish_options};

pub use self::node_management::{pep_owner_get, pep_owner_set};
pub use self::notifications::{
    deliver_explicit_pep_last_items_for_resource, deliver_pep_last_items_for_federated_resource,
    deliver_pep_last_items_for_resource, pep_audience_messages, prepare_pep_last_item_outbox,
    profile_audience_messages, send_pep_last_item,
};
pub use self::publishing::{bookmarks2_items_event, pep_publish};

/// What the server provides to PEP event fan-out: its local domain and the routing hints of its
/// sessions.
pub trait PepAudienceRouting: Sync {
    /// The server's local domain.
    fn pep_routing_local_domain(&self) -> &str;
    /// The available local sessions of `bare_jid` whose entity capabilities ask for notifications
    /// of `node`, as full JIDs in session order.
    fn pep_available_resources_wanting(&self, bare_jid: &str, node: &str) -> Vec<String>;
    /// The resources of `bare_jid` whose entity capabilities, as last seen, ask for notifications
    /// of `node`.
    fn pep_interested_resources(&self, bare_jid: &str, node: &str) -> Vec<String>;
}

/// What a client session provides to the PEP handlers.
pub trait PepSession: Sync {
    /// The authenticated account, or `None` before authentication.
    fn pep_account(&self) -> Option<PubSubAccount>;
    /// The session's bound full JID, or `None` before resource binding.
    fn pep_full_jid(&self) -> Option<&str>;
    /// The id of the session's connection.
    fn pep_connection_id(&self) -> uuid::Uuid;
    /// The server's local domain.
    fn pep_local_domain(&self) -> &str;
    /// The PEP node and storage quotas of one account.
    fn pep_quotas(&self) -> PepQuotas;
    /// The PubSub service, over the repository the composition root binds.
    fn pep_pubsub_service(&self) -> &PubSubService<impl crate::PubSubRepositories>;
    /// The profile service, over the repository the composition root binds.
    fn pep_profile_service(&self) -> &ProfileService<impl ProfileRepository>;
    /// The routing hints PEP events fan out with.
    fn pep_audience_routing(&self) -> &impl PepAudienceRouting;
    /// Counts `count` items published.
    fn pep_record_published(&self, count: u64);
    /// Counts `count` items retracted.
    fn pep_record_retracted(&self, count: u64);
    /// Counts one item retrieval.
    fn pep_record_retrieved(&self);
    /// Refreshes each local session's last presence from the owner's committed avatar.
    fn pep_refresh_avatar_presence(
        &self,
        owner_id: uuid::Uuid,
        owner_bare: &northstar_pubsub_core::PubSubBareJid,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// What the server provides to the PEP send-last delivery that follows presence and entity
/// capabilities changes.
pub trait PepLastItemDelivery: Sync {
    /// The epoch of a local session's entity capabilities, checked again when a send-last message
    /// is routed.
    type CapsEpoch: Copy + Send + Sync;
    /// Read the next authorized page through the PubSub service.
    fn last_item_replay_page(
        &self,
        query: &PepReplayQuery,
    ) -> impl std::future::Future<Output = Result<PepReplayPage>> + Send;
    /// The PubSub service's clock and ID source.
    fn last_item_time_sources(&self) -> &PubSubTimeSources;
    /// The server's local domain.
    fn last_item_local_domain(&self) -> &str;
    /// The nodes the current entity capabilities of `full_jid` ask notifications for.
    fn last_item_notify_nodes(&self, full_jid: &str) -> Vec<String>;
    /// Routes one send-last `message` from `sender_bare_jid` to `recipient`; a local recipient
    /// receives it only while its entity capabilities are still at `expected_local_epoch`, when one
    /// is given.
    fn last_item_route(
        &self,
        sender_bare_jid: &str,
        recipient: &str,
        message: String,
        expected_local_epoch: Option<Self::CapsEpoch>,
        expected_recipient_account: Option<uuid::Uuid>,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_XDATA: &str = "jabber:x:data";

fn canonical_account_jid(username: &str, domain: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonicalize_bare(&format!("{username}@{domain}"))
}

async fn pep_subscribe<S: PepSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    requester: &PubSubAccount,
    subscribe: Node<'_, '_>,
) -> Result<String> {
    let Some(node) = subscribe
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
    let Some(requested_jid) = subscribe.attribute("jid") else {
        return Ok(pep_error(
            id,
            iq.attribute("to"),
            "modify",
            "bad-request",
            Some("jid-required"),
        ));
    };
    let Ok(requested_jid) = northstar_xmpp_types::jid::canonicalize(requested_jid) else {
        return Ok(pep_error(
            id,
            iq.attribute("to"),
            "modify",
            "bad-request",
            Some("invalid-jid"),
        ));
    };
    let Some(owner) = pep_target_owner(session, iq, requester).await? else {
        return Ok(iq_error(id, "item-not-found"));
    };
    let requester_account = requester.clone();
    let actor_jid = session
        .pep_full_jid()
        .map(str::to_owned)
        .unwrap_or_else(|| {
            canonical_account_jid(&requester.username, session.pep_local_domain())
                .expect("authenticated account must form a canonical JID")
        });
    let service = session.pep_pubsub_service();
    let time = service.time_sources();
    let requested_subid = time.new_uuid().to_string();
    let context = time.prepare_event();
    let outcome = service
        .subscribe_pep_node(
            northstar_pubsub_application::PepSubscribeCommand::from(PepSubscribeWrite {
                owner: &owner,
                actor: PepSubscriptionActor {
                    jid: &actor_jid,
                    local_account: Some(&requester_account),
                },
                node,
                subscriber_jid: &requested_jid,
                max_subscriptions: 1_000,
                requested_subid: &requested_subid,
            }),
            &move |snapshot: &PepSubscribeSnapshot| prepare_pep_last_item_outbox(snapshot, context),
        )
        .await?;
    let subscription = match outcome.outcome {
        PepSubscribeOutcome::Subscribed(subscription) => subscription,
        PepSubscribeOutcome::NotFound => {
            return Ok(iq_error_from_optional(
                id,
                iq.attribute("to"),
                "item-not-found",
            ));
        }
        PepSubscribeOutcome::Forbidden => {
            return Ok(iq_error(id, "forbidden"));
        }
        PepSubscribeOutcome::NotAuthorized(access_model) => {
            return Ok(pep_error(
                id,
                iq.attribute("to"),
                "auth",
                "not-authorized",
                Some(access_error_for_model(&access_model)),
            ));
        }
        PepSubscribeOutcome::LimitExceeded => {
            return Ok(pep_error(
                id,
                iq.attribute("to"),
                "wait",
                "policy-violation",
                Some("too-many-subscriptions"),
            ));
        }
    };
    let payload = XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(pep_subscription_element(
            node,
            &requested_jid,
            "subscribed",
            &subscription.subid,
        ))
        .finish();
    Ok(iq_result_from_optional(id, iq.attribute("to"), &payload))
}

async fn pep_unsubscribe<S: PepSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    requester: &PubSubAccount,
    unsubscribe: Node<'_, '_>,
) -> Result<String> {
    let Some(node) = unsubscribe
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
    let Some(jid) = unsubscribe.attribute("jid") else {
        return Ok(pep_error(
            id,
            iq.attribute("to"),
            "modify",
            "bad-request",
            Some("jid-required"),
        ));
    };
    let Ok(jid) = northstar_xmpp_types::jid::canonicalize(jid) else {
        return Ok(pep_error(
            id,
            iq.attribute("to"),
            "modify",
            "bad-request",
            Some("invalid-jid"),
        ));
    };
    let Some(owner) = pep_target_owner(session, iq, requester).await? else {
        return Ok(iq_error(id, "item-not-found"));
    };
    let requester_account = requester.clone();
    let actor_jid = session
        .pep_full_jid()
        .map(str::to_owned)
        .unwrap_or_else(|| {
            canonical_account_jid(&requester.username, session.pep_local_domain())
                .expect("authenticated account must form a canonical JID")
        });
    let outcome = session
        .pep_pubsub_service()
        .unsubscribe_pep_node(northstar_pubsub_application::PepUnsubscribeCommand::from(
            PepUnsubscribeWrite {
                owner: &owner,
                actor: PepSubscriptionActor {
                    jid: &actor_jid,
                    local_account: Some(&requester_account),
                },
                node,
                subscriber_jid: &jid,
                subid: unsubscribe.attribute("subid"),
            },
        ))
        .await?;
    let subid = match outcome.outcome {
        PepUnsubscribeOutcome::Unsubscribed(subid) => subid,
        PepUnsubscribeOutcome::NotFound => {
            return Ok(iq_error_from_optional(
                id,
                iq.attribute("to"),
                "item-not-found",
            ));
        }
        PepUnsubscribeOutcome::Forbidden => {
            return Ok(iq_error(id, "forbidden"));
        }
        PepUnsubscribeOutcome::InvalidSubid => {
            return Ok(pep_error(
                id,
                iq.attribute("to"),
                "cancel",
                "unexpected-request",
                Some("invalid-subid"),
            ));
        }
    };
    let payload = subid.map_or_else(
        || XmlElement::namespaced("pubsub", NS_PUBSUB).finish(),
        |subid| {
            XmlElement::namespaced("pubsub", NS_PUBSUB)
                .child(pep_subscription_element(node, &jid, "none", &subid))
                .finish()
        },
    );
    Ok(iq_result_from_optional(id, iq.attribute("to"), &payload))
}

async fn pep_target_owner<S: PepSession>(
    session: &S,
    iq: Node<'_, '_>,
    requester: &PubSubAccount,
) -> Result<Option<northstar_pubsub_core::PubSubAccount>> {
    let username = if let Some(to) = iq.attribute("to") {
        let Ok(to) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
            return Ok(None);
        };
        if to.resourcepart().is_some()
            || to.domainpart() != session.pep_local_domain()
            || to.localpart().is_none()
        {
            return Ok(None);
        }
        to.localpart().unwrap_or_default().to_owned()
    } else {
        requester.username.clone()
    };
    session
        .pep_pubsub_service()
        .find_enabled_user(&username)
        .await
}

pub async fn pep_get<S: PepSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    pubsub: Node<'_, '_>,
) -> Result<String> {
    let Some(requester) = session.pep_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    let Some(items) = pubsub.children().find(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(NS_PUBSUB)
            && node.tag_name().name() == "items"
    }) else {
        return Ok(iq_error(id, "bad-request"));
    };
    if pubsub.children().filter(Node::is_element).count() != 1
        || items
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "node" | "max_items" | "subid"))
    {
        return Ok(iq_error(id, "bad-request"));
    }
    let Some(node) = items.attribute("node").filter(|node| valid_node_name(node)) else {
        return Ok(pep_error(
            id,
            iq.attribute("to"),
            "modify",
            "bad-request",
            Some("nodeid-required"),
        ));
    };
    let owner_name = match iq.attribute("to") {
        Some(to) => match northstar_xmpp_types::jid::CanonicalJid::parse_bare(to) {
            Ok(target)
                if target.domainpart() == session.pep_local_domain()
                    && target.localpart().is_some() =>
            {
                target.localpart().unwrap_or_default().to_owned()
            }
            _ => {
                return Ok(iq_error(id, "item-not-found"));
            }
        },
        None => requester.username.clone(),
    };
    let from = iq.attribute("to");
    let requester_jid = canonical_account_jid(&requester.username, session.pep_local_domain())?;
    let query = PepItemQuery {
        owner_username: &owner_name,
        requester_jid: &requester_jid,
        node,
        selection: parse_pep_item_selection(items, Some(node)),
    };
    let read = session.pep_pubsub_service().pep_items_read(&query).await?;
    let stored = match c2s_pep_item_rows(id, from, query.selection.as_ref(), read) {
        Ok(items) => items,
        Err(reply) => return Ok(reply),
    };
    let mut items = XmlElement::new("items").attr("node", node);
    for (_, item) in stored {
        items.push_validated_fragment(&item)?;
    }
    let payload = XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(items)
        .finish();
    session.pep_record_retrieved();
    if let Some(from) = from {
        Ok(iq_result_from(id, from, &payload))
    } else {
        Ok(iq_result(id, &payload))
    }
}

pub(crate) fn parse_pep_item_selection(
    items: Node<'_, '_>,
    canonical_profile_node: Option<&str>,
) -> Option<PepItemSelection> {
    let mut item_ids = Vec::new();
    let mut unique = HashSet::new();
    for (index, item) in items.children().filter(Node::is_element).enumerate() {
        let id = item.attribute("id")?;
        if index >= PEP_MAX_ITEMS as usize
            || item.tag_name().namespace() != Some(NS_PUBSUB)
            || item.tag_name().name() != "item"
            || item.attributes().len() != 1
            || id.is_empty()
            || id.len() > 1_024
            || id.chars().any(char::is_control)
            || item.children().any(|child| child.is_element())
        {
            return None;
        }
        let id = match canonical_profile_node {
            Some(node) => northstar_pubsub_core::canonical_profile_item_id(node, id).ok()?,
            None => id.to_owned(),
        };
        if unique.insert(id.clone()) {
            item_ids.push(id);
        } else if canonical_profile_node.is_some() {
            return None;
        }
    }
    let cap = i64::from(PEP_MAX_ITEMS);
    let max_items = match items.attribute("max_items") {
        Some(value) => {
            let value = value.parse::<i64>().ok()?;
            (value > 0).then_some(value.min(cap))?
        }
        None => cap,
    };
    Some(PepItemSelection {
        item_ids,
        max_items,
    })
}

fn c2s_pep_item_rows(
    id: &str,
    from: Option<&str>,
    selection: Option<&PepItemSelection>,
    read: PepItemRead,
) -> std::result::Result<Vec<(String, String)>, String> {
    match read {
        PepItemRead::OwnerMissing => Err(iq_error(id, "item-not-found")),
        PepItemRead::NodeMissing => Err(iq_error_from_optional(id, from, "item-not-found")),
        PepItemRead::Denied(reason) => {
            let extension = match reason {
                PepAccessDenial::PresenceSubscriptionRequired => "presence-subscription-required",
                PepAccessDenial::NotInRosterGroup => "not-in-roster-group",
                PepAccessDenial::ClosedNode => "closed-node",
            };
            Err(pep_error(
                id,
                from,
                "auth",
                "not-authorized",
                Some(extension),
            ))
        }
        PepItemRead::Items { items, .. } => {
            let Some(selection) = selection else {
                return Err(iq_error_from_optional(id, from, "bad-request"));
            };
            if items.is_empty() && !selection.item_ids.is_empty() {
                return Err(iq_error_from_optional(id, from, "item-not-found"));
            }
            Ok(items)
        }
    }
}

fn iq_result_from_optional(id: &str, from: Option<&str>, payload: &str) -> String {
    from.map_or_else(
        || iq_result(id, payload),
        |from| iq_result_from(id, from, payload),
    )
}

fn iq_error_from_optional(id: &str, from: Option<&str>, condition: &str) -> String {
    from.map_or_else(
        || iq_error(id, condition),
        |from| iq_error_from(id, from, condition),
    )
}

fn access_error_for_model(access_model: &str) -> &'static str {
    match access_model {
        "presence" => "presence-subscription-required",
        "roster" => "not-in-roster-group",
        _ => "closed-node",
    }
}

fn xdata_field<'a, 'input>(form: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    form.children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some("jabber:x:data")
                && node.attribute("var") == Some(name)
        })
        .and_then(|node| child_text(node, "value"))
}

/// Discovers identity, features, and node metadata for federated PEP queries.
pub async fn federated_pep_disco_info<H: PubSubHost>(
    host: &H,
    owner_username: &str,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<Option<String>> {
    if let Some(node) = requested_node {
        let PepNodeInfoRead::Info { config } = host
            .pubsub_application_service()
            .pep_node_info(&PepNodeQuery {
                owner_username,
                requester: PepRequester::Jid(requester),
                node,
            })
            .await?
        else {
            return Ok(None);
        };
        let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
            .attr("node", node)
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
            .child(XmlElement::new("feature").attr(
                "var",
                format!(
                    "http://jabber.org/protocol/pubsub#access-{}",
                    config.access_model
                ),
            ));
        if config.persist_items {
            query.push_child(
                XmlElement::new("feature")
                    .attr("var", "http://jabber.org/protocol/pubsub#persistent-items"),
            );
        }
        return Ok(Some(query.finish()));
    }
    if host
        .pubsub_application_service()
        .find_enabled_user(owner_username)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let features = [
        "http://jabber.org/protocol/disco#info",
        "http://jabber.org/protocol/disco#items",
        "http://jabber.org/protocol/pubsub#pep",
        "http://jabber.org/protocol/pubsub#access-open",
        "http://jabber.org/protocol/pubsub#access-presence",
        "http://jabber.org/protocol/pubsub#access-roster",
        "http://jabber.org/protocol/pubsub#access-whitelist",
        "http://jabber.org/protocol/pubsub#auto-create",
        "http://jabber.org/protocol/pubsub#auto-subscribe",
        "http://jabber.org/protocol/pubsub#config-node",
        "http://jabber.org/protocol/pubsub#create-nodes",
        "http://jabber.org/protocol/pubsub#delete-items",
        "http://jabber.org/protocol/pubsub#delete-nodes",
        "http://jabber.org/protocol/pubsub#filtered-notifications",
        "http://jabber.org/protocol/pubsub#multi-items",
        "http://jabber.org/protocol/pubsub#persistent-items",
        "http://jabber.org/protocol/pubsub#publish",
        "http://jabber.org/protocol/pubsub#publish-options",
        "http://jabber.org/protocol/pubsub#purge-nodes",
        "http://jabber.org/protocol/pubsub#retract-items",
        "http://jabber.org/protocol/pubsub#retrieve-items",
        "http://jabber.org/protocol/pubsub#subscribe",
        "vcard-temp",
        "urn:xmpp:avatar:data",
        "urn:xmpp:avatar:metadata",
        "urn:ietf:params:xml:ns:vcard-4.0",
        "urn:xmpp:vcard4",
        "urn:xmpp:contacts",
        "urn:xmpp:bookmarks:1",
        "urn:xmpp:bookmarks:1#compat",
        "urn:xmpp:pep-vcard-conversion:0",
    ];
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#info")
        .child(
            XmlElement::new("identity")
                .attr("category", "account")
                .attr("type", "registered"),
        )
        .child(
            XmlElement::new("identity")
                .attr("category", "pubsub")
                .attr("type", "pep")
                .attr("name", "Personal Eventing Protocol"),
        );
    for feature in features {
        query.push_child(XmlElement::new("feature").attr("var", feature));
    }
    Ok(Some(query.finish()))
}

/// Discovers published PEP nodes for federated PEP queries.
pub async fn federated_pep_disco_items<H: PubSubHost>(
    host: &H,
    owner_username: &str,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<Option<String>> {
    if let Some(node) = requested_node {
        let read = host
            .pubsub_application_service()
            .pep_node_items(&PepNodeQuery {
                owner_username,
                requester: PepRequester::Jid(requester),
                node,
            })
            .await?;
        if read != PepNodeItemsRead::Visible {
            return Ok(None);
        }
        return Ok(Some(
            XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items")
                .attr("node", node)
                .finish(),
        ));
    }
    let PepAccountItemsRead::Nodes { owner_jid, nodes } = host
        .pubsub_application_service()
        .pep_account_items(&PepAccountQuery {
            owner_username,
            requester: PepRequester::Jid(requester),
        })
        .await?
    else {
        return Ok(None);
    };
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
    for node in nodes {
        query.push_child(
            XmlElement::new("item")
                .attr("jid", &owner_jid)
                .attr("node", &node),
        );
    }
    Ok(Some(query.finish()))
}

fn pep_error(
    id: &str,
    from: Option<&str>,
    error_type: &str,
    condition: &str,
    pubsub_condition: Option<&str>,
) -> String {
    let stanza_condition = XmlElement::dynamic(condition).map_or_else(
        |_| XmlElement::namespaced("undefined-condition", "urn:ietf:params:xml:ns:xmpp-stanzas"),
        |element| element.attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
    );
    let mut error = XmlElement::new("error")
        .attr("type", error_type)
        .child(stanza_condition);
    if let Some(condition) = pubsub_condition {
        let extension = XmlElement::dynamic(condition).map_or_else(
            |_| XmlElement::namespaced("undefined-condition", NS_PUBSUB),
            |element| element.attr("xmlns", "http://jabber.org/protocol/pubsub#errors"),
        );
        error.push_child(extension);
    }
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .optional_attr("from", from)
        .attr("id", id)
        .child(error)
        .finish()
}

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("pep", include_str!("pep.rs")),
    ("publishing", include_str!("pep/publishing.rs")),
    ("notifications", include_str!("pep/notifications.rs")),
    ("node_management", include_str!("pep/node_management.rs")),
    ("forms", include_str!("pep/forms.rs")),
];

#[cfg(test)]
fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod module_source_tests;
