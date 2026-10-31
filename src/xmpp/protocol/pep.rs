use super::{Action, ProtocolSession};
use crate::services::xml_util::*;
use crate::state::pep_last_items::PepLastItemsContext;
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
#[cfg(test)]
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use northstar_pubsub_application::PepPublishItemsCommand;
use northstar_pubsub_application::{
    profile::{
        AvatarPresenceUpdate, ProfileAudienceSnapshot, ProfilePublishResult, ProfilePublishStatus,
    },
    PepConfigureNodeCommand, PepCreateNodeCommand, PepDeleteNodeCommand, PepPurgeNodeCommand,
    PepRetractCommand, PepSetAffiliationsCommand, PepUnsubscribeBatchCommand, PubSubService,
};
use northstar_pubsub_core::{
    PepAudienceSnapshot, PepConfigureNodeWrite, PepCreateOutcome, PepDeleteNodeWrite,
    PepDirectStateSnapshot, PepDirectStateTransition, PepNodeConfig, PepOutboxAuthorizationMode,
    PepOutboxEventKind, PepOutboxFactory, PepOwnerMutationOutcome, PepProfileWrite,
    PepPublishOutcome, PepPublishWrite, PepPurgeNodeWrite, PepRetractWrite,
    PepSetAffiliationsWrite, PepSubscribeOutcome, PepSubscribeSnapshot, PepSubscribeWrite,
    PepSubscriptionActor, PepUnsubscribeOutcome, PepUnsubscribeWrite, PubSubAccount,
    PubSubOutboxInsert,
};
use roxmltree::Node;
#[cfg(test)]
use sha1::{Digest, Sha1};
use std::collections::HashSet;

mod node_management;
mod notifications;
mod publishing;

use self::node_management::{parse_form_bool, valid_node_name};
use self::notifications::{
    pep_subscription_element, published_event_items, render_pep_direct_state_messages,
    strip_pubsub_item_root_namespaces,
};
use northstar_pubsub_xmpp::payload::valid_pep_payload;

#[cfg(test)]
use self::notifications::published_event_item;
#[cfg(test)]
use self::publishing::{normalized_pep_item, publish_options};

pub(crate) use self::notifications::{
    deliver_explicit_pep_last_items_for_resource, deliver_pep_last_items_for_federated_resource,
    deliver_pep_last_items_for_resource, prepare_pep_last_item_outbox, profile_item_event,
};
#[cfg(test)]
pub(crate) use self::publishing::bookmarks2_items_event;
#[cfg(test)]
use northstar_pubsub_xmpp::payload::valid_png_image;
pub(crate) use northstar_pubsub_xmpp::payload::{valid_avatar_data, valid_avatar_metadata};

const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_XDATA: &str = "jabber:x:data";
const OMEMO_DEVICES: &str = "urn:xmpp:omemo:2:devices";
const OMEMO_BUNDLES: &str = "urn:xmpp:omemo:2:bundles";
const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
const VCARD4: &str = "urn:xmpp:vcard4";
const CONTACTS: &str = "urn:xmpp:contacts";

fn canonical_account_jid(username: &str, domain: &str) -> Result<String> {
    northstar_xmpp_types::jid::canonicalize_bare(&format!("{username}@{domain}"))
}

impl ProtocolSession {
    async fn pep_subscribe(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        requester: &crate::services::authentication::AuthenticatedAccount,
        subscribe: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(node) = subscribe
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
        let Some(requested_jid) = subscribe.attribute("jid") else {
            return Ok(Action::Send(pep_error(
                id,
                iq.attribute("to"),
                "modify",
                "bad-request",
                Some("jid-required"),
            )));
        };
        let Ok(requested_jid) = northstar_xmpp_types::jid::canonicalize(requested_jid) else {
            return Ok(Action::Send(pep_error(
                id,
                iq.attribute("to"),
                "modify",
                "bad-request",
                Some("invalid-jid"),
            )));
        };
        let Some(owner) = self.pep_target_owner(iq, requester).await? else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let requester_account = PubSubAccount {
            id: requester.id,
            username: requester.username.clone(),
            auth_generation: requester.auth_generation,
        };
        let actor_jid = self.full_jid.clone().unwrap_or_else(|| {
            canonical_account_jid(&requester.username, self.state.local_domain())
                .expect("authenticated account must form a canonical JID")
        });
        let requested_subid = uuid::Uuid::new_v4().to_string();
        let outcome = self
            .state
            .pubsub_service()
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
                &prepare_pep_last_item_outbox,
            )
            .await?;
        let subscription = match outcome.outcome {
            PepSubscribeOutcome::Subscribed(subscription) => subscription,
            PepSubscribeOutcome::NotFound => {
                return Ok(Action::Send(iq_error_from_optional(
                    id,
                    iq.attribute("to"),
                    "item-not-found",
                )));
            }
            PepSubscribeOutcome::Forbidden => {
                return Ok(Action::Send(iq_error(id, "forbidden")));
            }
            PepSubscribeOutcome::NotAuthorized(access_model) => {
                return Ok(Action::Send(pep_error(
                    id,
                    iq.attribute("to"),
                    "auth",
                    "not-authorized",
                    Some(access_error_for_model(&access_model)),
                )));
            }
            PepSubscribeOutcome::LimitExceeded => {
                return Ok(Action::Send(pep_error(
                    id,
                    iq.attribute("to"),
                    "wait",
                    "policy-violation",
                    Some("too-many-subscriptions"),
                )));
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
        Ok(Action::Send(iq_result_from_optional(
            id,
            iq.attribute("to"),
            &payload,
        )))
    }

    async fn pep_unsubscribe(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        requester: &crate::services::authentication::AuthenticatedAccount,
        unsubscribe: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(node) = unsubscribe
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
        let Some(jid) = unsubscribe.attribute("jid") else {
            return Ok(Action::Send(pep_error(
                id,
                iq.attribute("to"),
                "modify",
                "bad-request",
                Some("jid-required"),
            )));
        };
        let Ok(jid) = northstar_xmpp_types::jid::canonicalize(jid) else {
            return Ok(Action::Send(pep_error(
                id,
                iq.attribute("to"),
                "modify",
                "bad-request",
                Some("invalid-jid"),
            )));
        };
        let Some(owner) = self.pep_target_owner(iq, requester).await? else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let requester_account = PubSubAccount {
            id: requester.id,
            username: requester.username.clone(),
            auth_generation: requester.auth_generation,
        };
        let actor_jid = self.full_jid.clone().unwrap_or_else(|| {
            canonical_account_jid(&requester.username, self.state.local_domain())
                .expect("authenticated account must form a canonical JID")
        });
        let outcome = self
            .state
            .pubsub_service()
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
                return Ok(Action::Send(iq_error_from_optional(
                    id,
                    iq.attribute("to"),
                    "item-not-found",
                )));
            }
            PepUnsubscribeOutcome::Forbidden => {
                return Ok(Action::Send(iq_error(id, "forbidden")));
            }
            PepUnsubscribeOutcome::InvalidSubid => {
                return Ok(Action::Send(pep_error(
                    id,
                    iq.attribute("to"),
                    "cancel",
                    "unexpected-request",
                    Some("invalid-subid"),
                )));
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
        Ok(Action::Send(iq_result_from_optional(
            id,
            iq.attribute("to"),
            &payload,
        )))
    }

    async fn pep_target_owner(
        &self,
        iq: Node<'_, '_>,
        requester: &crate::services::authentication::AuthenticatedAccount,
    ) -> Result<Option<northstar_pubsub_core::PubSubAccount>> {
        let username = if let Some(to) = iq.attribute("to") {
            let Ok(to) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
                return Ok(None);
            };
            if to.resourcepart().is_some()
                || to.domainpart() != self.state.local_domain()
                || to.localpart().is_none()
            {
                return Ok(None);
            }
            to.localpart().unwrap_or_default().to_owned()
        } else {
            requester.username.clone()
        };
        self.state
            .pubsub_service()
            .find_enabled_user(&username)
            .await
    }

    pub(crate) async fn pep_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(requester) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(items) = pubsub.children().find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(NS_PUBSUB)
                && node.tag_name().name() == "items"
        }) else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if pubsub.children().filter(Node::is_element).count() != 1
            || items
                .attributes()
                .any(|attribute| !matches!(attribute.name(), "node" | "max_items" | "subid"))
        {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let Some(node) = items.attribute("node").filter(|node| valid_node_name(node)) else {
            return Ok(Action::Send(pep_error(
                id,
                iq.attribute("to"),
                "modify",
                "bad-request",
                Some("nodeid-required"),
            )));
        };
        let owner_name = match iq.attribute("to") {
            Some(to) => match northstar_xmpp_types::jid::CanonicalJid::parse_bare(to) {
                Ok(target)
                    if target.domainpart() == self.state.local_domain()
                        && target.localpart().is_some() =>
                {
                    target.localpart().unwrap_or_default().to_owned()
                }
                _ => {
                    return Ok(Action::Send(iq_error(id, "item-not-found")));
                }
            },
            None => requester.username.clone(),
        };
        let Some(owner) = self
            .state
            .pubsub_service()
            .find_enabled_user(&owner_name)
            .await?
        else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let from = iq.attribute("to");
        let Some(config) = self.state.pubsub_service().pep_node(owner.id, node).await? else {
            return Ok(Action::Send(if let Some(from) = from {
                iq_error_from(id, from, "item-not-found")
            } else {
                iq_error(id, "item-not-found")
            }));
        };
        let requester_jid = canonical_account_jid(&requester.username, self.state.local_domain())?;
        if !pep_access_allowed(
            self.state.pubsub_service(),
            &owner,
            self.state.local_domain(),
            node,
            &requester_jid,
        )
        .await?
        {
            return Ok(Action::Send(pep_error(
                id,
                from,
                "auth",
                "not-authorized",
                Some(access_error(&config)),
            )));
        }
        let requested = items
            .children()
            .filter(Node::is_element)
            .map(|item| {
                (item.tag_name().namespace() == Some(NS_PUBSUB)
                    && item.tag_name().name() == "item"
                    && item.attributes().len() == 1
                    && item.attribute("id").is_some_and(|id| {
                        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control)
                    })
                    && !item.children().any(|child| child.is_element()))
                .then(|| item.attribute("id").unwrap_or_default())
            })
            .collect::<Option<Vec<_>>>();
        let Some(requested) =
            requested.filter(|ids| ids.len() <= northstar_pubsub_core::PEP_MAX_ITEMS as usize)
        else {
            return Ok(Action::Send(iq_error_from_optional(
                id,
                from,
                "bad-request",
            )));
        };
        let mut canonical_requested = Vec::with_capacity(requested.len());
        let mut unique_requested = HashSet::new();
        for item_id in requested {
            let Ok(item_id) = northstar_pubsub_core::canonical_profile_item_id(node, item_id)
            else {
                return Ok(Action::Send(iq_error_from_optional(
                    id,
                    from,
                    "bad-request",
                )));
            };
            if !unique_requested.insert(item_id.clone()) {
                return Ok(Action::Send(iq_error_from_optional(
                    id,
                    from,
                    "bad-request",
                )));
            }
            canonical_requested.push(item_id);
        }
        let requested = canonical_requested
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let max_items = match items.attribute("max_items") {
            Some(value) => match value.parse::<i64>() {
                Ok(value) if value > 0 => value.min(northstar_pubsub_core::PEP_MAX_ITEMS as i64),
                _ => {
                    return Ok(Action::Send(iq_error_from_optional(
                        id,
                        from,
                        "bad-request",
                    )));
                }
            },
            None => northstar_pubsub_core::PEP_MAX_ITEMS as i64,
        };
        let stored = if requested.is_empty() {
            self.state
                .pubsub_service()
                .pep_items(owner.id, node, None, max_items)
                .await?
        } else {
            self.state
                .pubsub_service()
                .pep_items_by_ids(owner.id, node, &requested, max_items)
                .await?
        };
        if stored.is_empty() && !requested.is_empty() {
            return Ok(Action::Send(if let Some(from) = from {
                iq_error_from(id, from, "item-not-found")
            } else {
                iq_error(id, "item-not-found")
            }));
        }
        let mut items = XmlElement::new("items").attr("node", node);
        for (_, item) in stored {
            items.push_validated_fragment(&item)?;
        }
        let payload = XmlElement::namespaced("pubsub", NS_PUBSUB)
            .child(items)
            .finish();
        self.state.pep_telemetry().retrieved();
        if let Some(from) = from {
            Ok(Action::Send(iq_result_from(id, from, &payload)))
        } else {
            Ok(Action::Send(iq_result(id, &payload)))
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

fn access_error(config: &PepNodeConfig) -> &'static str {
    access_error_for_model(&config.access_model)
}

fn access_error_for_model(access_model: &str) -> &'static str {
    match access_model {
        "presence" => "presence-subscription-required",
        "roster" => "not-in-roster-group",
        _ => "closed-node",
    }
}

pub(crate) async fn pep_access_allowed(
    service: &PubSubService<impl northstar_pubsub_application::PepNodeQueryRepository>,
    owner: &northstar_pubsub_core::PubSubAccount,
    domain: &str,
    node: &str,
    requester_jid: &str,
) -> Result<bool> {
    pep_access_allowed_for_owner(
        service,
        owner.id,
        &owner.username,
        domain,
        node,
        requester_jid,
    )
    .await
}

async fn pep_access_allowed_for_owner(
    service: &PubSubService<impl northstar_pubsub_application::PepNodeQueryRepository>,
    owner_id: uuid::Uuid,
    owner_username: &str,
    domain: &str,
    node: &str,
    requester_jid: &str,
) -> Result<bool> {
    let owner_jid = canonical_account_jid(owner_username, domain)?;
    let requester_bare = match northstar_xmpp_types::jid::canonical_bare_key(requester_jid) {
        Ok(requester) => requester,
        Err(_) => return Ok(false),
    };
    if requester_bare == owner_jid {
        return Ok(true);
    }
    let Some(config) = service.pep_node(owner_id, node).await? else {
        return Ok(false);
    };
    pep_access_allowed_with_config(
        service,
        owner_id,
        owner_username,
        domain,
        &config,
        requester_jid,
    )
    .await
}

async fn pep_access_allowed_with_config(
    service: &PubSubService<impl northstar_pubsub_application::PepNodeQueryRepository>,
    owner_id: uuid::Uuid,
    owner_username: &str,
    domain: &str,
    config: &PepNodeConfig,
    requester_jid: &str,
) -> Result<bool> {
    let owner_jid = canonical_account_jid(owner_username, domain)?;
    let requester_bare = match northstar_xmpp_types::jid::canonical_bare_key(requester_jid) {
        Ok(requester) => requester,
        Err(_) => return Ok(false),
    };
    if requester_bare == owner_jid {
        return Ok(true);
    }
    if service.is_blocked(owner_id, &requester_bare).await? {
        return Ok(false);
    }
    match config.access_model.as_str() {
        "open" => return Ok(true),
        "whitelist" => {
            return Ok(config.access_whitelist.iter().any(|jid| {
                northstar_xmpp_types::jid::canonical_bare_key(jid)
                    .is_ok_and(|jid| jid == requester_bare)
            }));
        }
        "roster" => {
            return service
                .roster_group_allowed(owner_id, requester_jid, &config.roster_groups_allowed)
                .await;
        }
        "presence" => {}
        _ => return Ok(false),
    }
    Ok(service
        .roster_item(owner_id, &requester_bare)
        .await?
        .is_some_and(|(_, _, subscription, _)| matches!(subscription.as_str(), "from" | "both")))
}

pub(crate) async fn federated_pep_disco_info(
    state: &crate::state::AppState,
    owner: &northstar_pubsub_core::PubSubAccount,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<Option<String>> {
    if let Some(node) = requested_node {
        let Some(config) = state.pubsub_service().pep_node(owner.id, node).await? else {
            return Ok(None);
        };
        if !pep_access_allowed(
            state.pubsub_service(),
            owner,
            state.local_domain(),
            node,
            requester,
        )
        .await?
        {
            return Ok(None);
        }
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

pub(crate) async fn federated_pep_disco_items(
    state: &crate::state::AppState,
    owner: &northstar_pubsub_core::PubSubAccount,
    requester: &str,
    requested_node: Option<&str>,
) -> Result<Option<String>> {
    if let Some(node) = requested_node {
        let exists = state
            .pubsub_service()
            .pep_node(owner.id, node)
            .await?
            .is_some();
        if !exists
            || !pep_access_allowed(
                state.pubsub_service(),
                owner,
                state.local_domain(),
                node,
                requester,
            )
            .await?
        {
            return Ok(None);
        }
        return Ok(Some(
            XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items")
                .attr("node", node)
                .finish(),
        ));
    }
    let owner_jid = canonical_account_jid(&owner.username, state.local_domain())?;
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
    for node in state.pubsub_service().pep_nodes(owner.id).await? {
        if pep_access_allowed(
            state.pubsub_service(),
            owner,
            state.local_domain(),
            &node,
            requester,
        )
        .await?
        {
            query.push_child(
                XmlElement::new("item")
                    .attr("jid", &owner_jid)
                    .attr("node", &node),
            );
        }
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
