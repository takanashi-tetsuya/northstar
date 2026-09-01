use super::{Action, ProtocolSession};
use crate::services::{
    profile::{
        AvatarPresenceUpdate, ProfileAudienceSnapshot, ProfilePublishResult, ProfilePublishStatus,
    },
    pubsub::{
        PepAudienceSnapshot, PepCreateOutcome, PepDirectStateSnapshot, PepDirectStateTransition,
        PepNodeConfig, PepOutboxAuthorizationMode, PepOutboxEventKind, PepOwnerMutationOutcome,
        PepProfileWrite, PepPublishOutcome, PepPublishWrite, PepQuotas, PepSubscribeOutcome,
        PepSubscribeSnapshot, PepSubscribeWrite, PepSubscriptionActor, PepUnsubscribeOutcome,
        PepUnsubscribeWrite, PubSubAccount, PubSubOutboxInsert, PubSubService,
    },
};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use roxmltree::Node;
use sha1::{Digest, Sha1};
use std::{collections::HashSet, sync::Arc};

const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_XDATA: &str = "jabber:x:data";
const NS_OMEMO2: &str = "urn:xmpp:omemo:2";
const OMEMO_DEVICES: &str = "urn:xmpp:omemo:2:devices";
const OMEMO_BUNDLES: &str = "urn:xmpp:omemo:2:bundles";
const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";
const VCARD4: &str = "urn:xmpp:vcard4";
const CONTACTS: &str = "urn:xmpp:contacts";

fn profile_publish_error(id: &str, status: ProfilePublishStatus) -> Option<String> {
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

fn pep_subscription_element(node: &str, jid: &str, state: &str, subid: &str) -> XmlElement {
    XmlElement::new("subscription")
        .attr("node", node)
        .attr("jid", jid)
        .attr("subscription", state)
        .attr("subid", subid)
}

fn pep_event_message(
    from: &str,
    to: &str,
    message_id: impl ToString,
    event: &str,
    reply_to: Option<&str>,
) -> Result<String> {
    let mut event_wrapper = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
    event_wrapper.push_validated_fragment(event)?;
    let mut message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", "headline")
        .attr("id", message_id)
        .child(event_wrapper);
    if let Some(publisher) = reply_to {
        message.push_child(
            XmlElement::namespaced("addresses", "http://jabber.org/protocol/address").child(
                XmlElement::new("address")
                    .attr("type", "replyto")
                    .attr("jid", publisher),
            ),
        );
    }
    Ok(message.finish())
}

fn pep_data_field(
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

fn canonical_account_jid(username: &str, domain: &str) -> Result<String> {
    crate::jid::canonicalize_bare(&format!("{username}@{domain}"))
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
                !canonical_account_jid(&user.username, &self.state.config.domain).is_ok_and(
                    |owner| crate::jid::canonicalize_bare(to).is_ok_and(|target| target == owner),
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
        if items.len() > PubSubService::PEP_MAX_ITEMS as usize {
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
            let item_id = match PubSubService::canonical_profile_item_id(node, &wire_item_id) {
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
            let previous = self
                .state
                .pubsub_service()
                .pep_items(
                    user.id,
                    BOOKMARKS2,
                    None,
                    PubSubService::PEP_MAX_ITEMS as i64,
                )
                .await?
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>();
            normalized
                .iter()
                .filter(|(item_id, payload)| previous.get(item_id) != Some(payload))
                .map(|(_, payload)| payload.as_str())
                .collect::<String>()
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
        let quotas = PepQuotas {
            max_nodes: self.state.config.pep_max_nodes_per_account,
            max_storage_bytes: self.state.config.pep_max_storage_bytes_per_account,
        };
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
            let audience_state = std::sync::Arc::clone(&self.state);
            let publisher_full_jid = self.full_jid.clone();
            let event = generic_event.as_deref();
            let result = self
                .state
                .pubsub_service()
                .publish_pep_items(
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
                    &move |audience: &PepAudienceSnapshot| {
                        let Some(event) = event else {
                            return Ok(Vec::new());
                        };
                        ProtocolSession::prepare_pep_audience_messages(
                            audience_state.as_ref(),
                            publisher_full_jid.as_deref(),
                            node,
                            event,
                            audience,
                        )
                    },
                    node == BOOKMARKS2,
                )
                .await?;
            (Some(result.0), result.1)
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
                &canonical_account_jid(&user.username, &self.state.config.domain)?,
                hash.as_deref(),
            );
        }
        self.state.metrics.pep_items_published_total.fetch_add(
            normalized.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

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

    async fn pep_create(
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
            .create_pep_node(
                user.id,
                node,
                &PubSubService::default_pep_node_config(node),
                self.state.config.pep_max_nodes_per_account,
            )
            .await?
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
        let Ok(requested_jid) = crate::jid::canonicalize(requested_jid) else {
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
            canonical_account_jid(&requester.username, &self.state.config.domain)
                .expect("authenticated account must form a canonical JID")
        });
        let requested_subid = uuid::Uuid::new_v4().to_string();
        let outcome = self
            .state
            .pubsub_service()
            .subscribe_pep_node(
                PepSubscribeWrite {
                    owner: &owner,
                    actor: PepSubscriptionActor {
                        jid: &actor_jid,
                        local_account: Some(&requester_account),
                    },
                    node,
                    subscriber_jid: &requested_jid,
                    max_subscriptions: 1_000,
                    requested_subid: &requested_subid,
                },
                &prepare_pep_last_item_outbox,
            )
            .await?;
        let subscription = match outcome {
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
        let Ok(jid) = crate::jid::canonicalize(jid) else {
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
            canonical_account_jid(&requester.username, &self.state.config.domain)
                .expect("authenticated account must form a canonical JID")
        });
        let outcome = self
            .state
            .pubsub_service()
            .unsubscribe_pep_node(PepUnsubscribeWrite {
                owner: &owner,
                actor: PepSubscriptionActor {
                    jid: &actor_jid,
                    local_account: Some(&requester_account),
                },
                node,
                subscriber_jid: &jid,
                subid: unsubscribe.attribute("subid"),
            })
            .await?;
        let subid = match outcome {
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
    ) -> Result<Option<crate::services::pubsub::PubSubAccount>> {
        let username = if let Some(to) = iq.attribute("to") {
            let Ok(to) = crate::jid::CanonicalJid::parse(to) else {
                return Ok(None);
            };
            if to.resourcepart().is_some()
                || to.domainpart() != self.state.config.domain
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

    async fn pep_retract(
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
                && ids.len() <= PubSubService::PEP_MAX_ITEMS as usize
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
            let Ok(item_id) = PubSubService::canonical_profile_item_id(node, item_id) else {
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
        let outcome = self
            .state
            .pubsub_service()
            .retract_pep_items(
                &owner,
                self.connection_id,
                node,
                &item_ids,
                notify,
                &move |audience: &PepAudienceSnapshot| {
                    ProtocolSession::prepare_pep_audience_messages(
                        audience_state.as_ref(),
                        publisher_full_jid.as_deref(),
                        node,
                        &event,
                        audience,
                    )
                },
            )
            .await?;
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
        self.state
            .metrics
            .pep_items_retracted_total
            .fetch_add(retracted, std::sync::atomic::Ordering::Relaxed);
        Ok(Action::Send(iq_result(id, "")))
    }

    /// Render a generic PEP event from the service's transaction-owned
    /// authorization snapshot. Runtime caps/resources are soft routing hints:
    /// they may narrow or expand a bare authorized principal to its resources,
    /// but can never add another principal.
    pub(crate) fn prepare_pep_audience_messages(
        state: &crate::state::AppState,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &PepAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        let event_for = |recipient: &str, reply_to_publisher: bool| -> Result<String> {
            pep_event_message(
                &audience.owner_bare_jid,
                recipient,
                uuid::Uuid::new_v4(),
                event,
                reply_to_publisher.then_some(publisher_full_jid).flatten(),
            )
        };
        let mut delivered = HashSet::new();
        let mut plan = Vec::new();
        for (full_jid, target) in state.session_entries_for(&audience.owner_bare_jid) {
            if target.available.load(std::sync::atomic::Ordering::Relaxed)
                && super::caps::wants_pep_node(state, &full_jid, node)
                && delivered.insert(full_jid.clone())
            {
                plan.push((full_jid.clone(), event_for(&full_jid, false)?));
            }
        }
        for contact in &audience.roster_jids {
            let contact_jid = crate::jid::CanonicalJid::parse_bare(contact)?;
            let contact_bare = contact_jid.to_string();
            if contact_jid.domainpart() == state.config.domain {
                for (full_jid, target) in state.session_entries_for(&contact_bare) {
                    if target.available.load(std::sync::atomic::Ordering::Relaxed)
                        && super::caps::wants_pep_node(state, &full_jid, node)
                        && delivered.insert(full_jid.clone())
                    {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            } else {
                for full_jid in
                    super::caps::interested_resources_for_bare(state, &contact_bare, node)
                {
                    if delivered.insert(full_jid.clone()) {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            }
        }
        for subscription_jid in &audience.explicit_jids {
            let parsed = crate::jid::CanonicalJid::parse(subscription_jid)?;
            if parsed.resourcepart().is_some() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
                continue;
            }
            let subscription_bare = parsed.bare();
            let interested_resources =
                super::caps::interested_resources_for_bare(state, &subscription_bare, node);
            if interested_resources.is_empty() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
            } else {
                for resource in interested_resources {
                    if delivered.insert(resource.clone()) {
                        plan.push((resource.clone(), event_for(&resource, false)?));
                    }
                }
            }
        }
        Ok(plan)
    }

    /// Render a profile event from a transaction-owned authorization snapshot.
    /// Session and caps state only narrows delivery to useful resources; it
    /// cannot add a roster contact or explicit subscriber absent from the
    /// durable snapshot.
    pub(crate) fn prepare_profile_audience_messages(
        state: &crate::state::AppState,
        publisher_full_jid: Option<&str>,
        node: &str,
        event: &str,
        audience: &ProfileAudienceSnapshot,
    ) -> Result<Vec<(String, String)>> {
        let event_for = |recipient: &str, reply_to_publisher: bool| -> Result<String> {
            pep_event_message(
                &audience.owner_bare_jid,
                recipient,
                uuid::Uuid::new_v4(),
                event,
                reply_to_publisher.then_some(publisher_full_jid).flatten(),
            )
        };
        let mut delivered = HashSet::new();
        let mut plan = Vec::new();
        for (full_jid, target) in state.session_entries_for(&audience.owner_bare_jid) {
            if target.available.load(std::sync::atomic::Ordering::Relaxed)
                && super::caps::wants_pep_node(state, &full_jid, node)
                && delivered.insert(full_jid.clone())
            {
                plan.push((full_jid.clone(), event_for(&full_jid, false)?));
            }
        }
        for contact in &audience.roster_jids {
            let contact_jid = crate::jid::CanonicalJid::parse_bare(contact)?;
            let contact_bare = contact_jid.to_string();
            if contact_jid.domainpart() == state.config.domain {
                for (full_jid, target) in state.session_entries_for(&contact_bare) {
                    if target.available.load(std::sync::atomic::Ordering::Relaxed)
                        && super::caps::wants_pep_node(state, &full_jid, node)
                        && delivered.insert(full_jid.clone())
                    {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            } else {
                for full_jid in
                    super::caps::interested_resources_for_bare(state, &contact_bare, node)
                {
                    if delivered.insert(full_jid.clone()) {
                        plan.push((full_jid.clone(), event_for(&full_jid, true)?));
                    }
                }
            }
        }
        for subscription_jid in &audience.explicit_jids {
            let parsed = crate::jid::CanonicalJid::parse(subscription_jid)?;
            if parsed.resourcepart().is_some() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
                continue;
            }
            let subscription_bare = parsed.bare();
            let interested_resources =
                super::caps::interested_resources_for_bare(state, &subscription_bare, node);
            if interested_resources.is_empty() {
                if delivered.insert(subscription_jid.clone()) {
                    plan.push((
                        subscription_jid.clone(),
                        event_for(subscription_jid, false)?,
                    ));
                }
            } else {
                for resource in interested_resources {
                    if delivered.insert(resource.clone()) {
                        plan.push((resource.clone(), event_for(&resource, false)?));
                    }
                }
            }
        }
        Ok(plan)
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
            Some(to) => match crate::jid::CanonicalJid::parse_bare(to) {
                Ok(target)
                    if target.domainpart() == self.state.config.domain
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
        let requester_jid = canonical_account_jid(&requester.username, &self.state.config.domain)?;
        if !pep_access_allowed(
            self.state.pubsub_service(),
            &owner,
            &self.state.config.domain,
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
            requested.filter(|ids| ids.len() <= PubSubService::PEP_MAX_ITEMS as usize)
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
            let Ok(item_id) = PubSubService::canonical_profile_item_id(node, item_id) else {
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
                Ok(value) if value > 0 => value.min(PubSubService::PEP_MAX_ITEMS as i64),
                _ => {
                    return Ok(Action::Send(iq_error_from_optional(
                        id,
                        from,
                        "bad-request",
                    )));
                }
            },
            None => PubSubService::PEP_MAX_ITEMS as i64,
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
        self.state
            .metrics
            .pep_retrievals_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(from) = from {
            Ok(Action::Send(iq_result_from(id, from, &payload)))
        } else {
            Ok(Action::Send(iq_result(id, &payload)))
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
        let owner_jid = canonical_account_jid(&user.username, &self.state.config.domain)?;
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
                let outcome = self
                    .state
                    .pubsub_service()
                    .update_pep_node_config(
                        &owner,
                        self.connection_id,
                        node,
                        &current,
                        &config,
                        &move |audience: &PepAudienceSnapshot| {
                            ProtocolSession::prepare_pep_audience_messages(
                                audience_state.as_ref(),
                                publisher_full_jid.as_deref(),
                                node,
                                &event,
                                audience,
                            )
                        },
                    )
                    .await?;
                if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                    return Ok(Action::Send(error));
                }
            }
            "purge" => {
                let event = XmlElement::new("purge").attr("node", node).finish();
                let audience_state = std::sync::Arc::clone(&self.state);
                let publisher_full_jid = self.full_jid.clone();
                let outcome = self
                    .state
                    .pubsub_service()
                    .purge_pep_node(
                        &owner,
                        self.connection_id,
                        node,
                        &move |audience: &PepAudienceSnapshot| {
                            ProtocolSession::prepare_pep_audience_messages(
                                audience_state.as_ref(),
                                publisher_full_jid.as_deref(),
                                node,
                                &event,
                                audience,
                            )
                        },
                    )
                    .await?;
                if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                    return Ok(Action::Send(error));
                }
            }
            "delete" => {
                let event = XmlElement::new("delete").attr("node", node).finish();
                let audience_state = std::sync::Arc::clone(&self.state);
                let publisher_full_jid = self.full_jid.clone();
                let outcome = self
                    .state
                    .pubsub_service()
                    .delete_pep_node(
                        &owner,
                        self.connection_id,
                        node,
                        &move |audience: &PepAudienceSnapshot| {
                            ProtocolSession::prepare_pep_audience_messages(
                                audience_state.as_ref(),
                                publisher_full_jid.as_deref(),
                                node,
                                &event,
                                audience,
                            )
                        },
                    )
                    .await?;
                if let Some(error) = pep_owner_mutation_error(id, iq.attribute("to"), outcome) {
                    return Ok(Action::Send(error));
                }
            }
            "affiliations" => {
                let owner_jid = canonical_account_jid(&user.username, &self.state.config.domain)?;
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
                            .and_then(|jid| crate::jid::canonical_bare_key(jid).ok())?;
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
                let outcome = self
                    .state
                    .pubsub_service()
                    .update_pep_affiliations(
                        &owner,
                        self.connection_id,
                        node,
                        &current,
                        &changes,
                        &render_pep_direct_state_messages,
                    )
                    .await?;
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
                            .and_then(|jid| crate::jid::canonicalize(jid).ok())?;
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
                    .unsubscribe_pep_nodes_batch(
                        &owner,
                        self.connection_id,
                        node,
                        &changes,
                        &render_pep_direct_state_messages,
                    )
                    .await?;
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

fn pep_owner_mutation_error(
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

fn render_pep_direct_state_messages(
    snapshot: &PepDirectStateSnapshot,
) -> Result<Vec<(String, String)>> {
    snapshot
        .transitions
        .iter()
        .map(|transition| {
            let (recipient, event) = match transition {
                PepDirectStateTransition::Subscription {
                    recipient_jid,
                    subid,
                    state,
                } => (
                    recipient_jid,
                    pep_subscription_element(&snapshot.node, recipient_jid, state, subid).finish(),
                ),
                PepDirectStateTransition::Affiliation {
                    recipient_jid,
                    affiliation,
                } => (
                    recipient_jid,
                    XmlElement::new("affiliation")
                        .attr("node", &snapshot.node)
                        .attr("jid", recipient_jid)
                        .attr("affiliation", affiliation)
                        .finish(),
                ),
            };
            Ok((
                recipient.clone(),
                pep_event_message(
                    &snapshot.owner_bare_jid,
                    recipient,
                    uuid::Uuid::new_v4(),
                    &event,
                    None,
                )?,
            ))
        })
        .collect()
}

fn pep_owner_target_allowed(
    session: &ProtocolSession,
    iq: Node<'_, '_>,
    user: &crate::services::authentication::AuthenticatedAccount,
) -> bool {
    iq.attribute("to").is_none_or(|to| {
        canonical_account_jid(&user.username, &session.state.config.domain).is_ok_and(|owner| {
            crate::jid::canonicalize_bare(to).is_ok_and(|target| target == owner)
        })
    })
}

fn valid_node_name(node: &str) -> bool {
    !node.is_empty() && node.len() <= 1_024 && !node.chars().any(char::is_control)
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

async fn route_pep_message(
    state: &crate::state::AppState,
    sender_bare_jid: &str,
    recipient: &str,
    message: String,
    expected_local_epoch: Option<crate::state::LocalCapsEpoch>,
) -> Result<()> {
    let sender_bare_jid = crate::jid::canonicalize_bare(sender_bare_jid)?;
    let recipient_jid = crate::jid::CanonicalJid::parse(recipient)?;
    let domain = recipient_jid.domainpart();
    if domain == state.config.domain {
        let mut delivered = false;
        let recipient_key = recipient_jid.to_string();
        let targets = state.session_entries_for(&recipient_key);
        let same_account = recipient_jid.bare() == sender_bare_jid;
        let mut policy_eligible = 0_usize;
        for (_, target) in &targets {
            if expected_local_epoch.is_some_and(|epoch| target.connection_id != epoch.connection_id)
            {
                continue;
            }
            if !same_account
                && !state
                    .privacy_allows_session(
                        target,
                        &sender_bare_jid,
                        crate::services::privacy::PrivacyStanzaKind::Message,
                    )
                    .await?
            {
                continue;
            }
            policy_eligible += 1;
            if let Some(epoch) = expected_local_epoch {
                // The potentially slow policy/database work above stays
                // outside the resource gate. Only the final route check and
                // nonblocking send are linearized with a newer caps
                // observation or live SM takeover.
                let expected_gate = Arc::clone(&target.mix_presence_gate);
                let _epoch_guard = Arc::clone(&expected_gate).lock_owned().await;
                let exact_route = state.sessions.get(&recipient_key).is_some_and(|current| {
                    super::caps::local_caps_route_epoch_matches(
                        current.connection_id,
                        current
                            .caps_observation_generation
                            .load(std::sync::atomic::Ordering::Acquire),
                        current.routable.load(std::sync::atomic::Ordering::Acquire),
                        current.disconnect.is_cancelled(),
                        current.lifecycle.load(std::sync::atomic::Ordering::Acquire),
                        Arc::ptr_eq(&current.mix_presence_gate, &expected_gate),
                        epoch,
                    )
                });
                if !exact_route {
                    continue;
                }
                match target.sender.try_send(message.clone()) {
                    Ok(()) => delivered = true,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // The gate and epoch check above identify this exact
                        // transport incarnation. Saturation is a transport
                        // failure: retain the caps effect and tear down the
                        // slow route so it cannot be reported as delivered.
                        target.sender.disconnect_backpressured_transport();
                        anyhow::bail!(
                            "exact local PEP transport queue is full for {recipient_key}"
                        );
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        anyhow::bail!(
                            "exact local PEP transport queue is closed for {recipient_key}"
                        );
                    }
                }
                continue;
            }
            delivered |= target.sender.try_send(message.clone()).is_ok();
        }
        let mut remote_nodes = 0_usize;
        if !delivered && expected_local_epoch.is_none() {
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
            if expected_local_epoch.is_some() {
                return Ok(());
            }
            if remote_nodes == 0 && !targets.is_empty() && policy_eligible == 0 {
                return Ok(());
            }
            anyhow::bail!("no local PEP resource accepted the notification");
        }
    } else if state.federation_domain_allowed(domain) {
        if !state.federation.send(domain, message, None).await {
            anyhow::bail!("federated PEP notification was not admitted to the durable outbox");
        }
    } else {
        anyhow::bail!("federated PEP notification is denied by domain policy");
    }
    Ok(())
}

pub(super) async fn route_pep_outbox_message(
    state: &crate::state::AppState,
    sender_bare_jid: &str,
    recipient: &str,
    message: String,
) -> Result<()> {
    route_pep_message(state, sender_bare_jid, recipient, message, None).await
}

pub(crate) async fn send_pep_last_item(
    state: &crate::state::AppState,
    owner: &crate::services::pubsub::PubSubAccount,
    node: &str,
    recipient: &str,
    on_presence: bool,
    expected_local_epoch: Option<crate::state::LocalCapsEpoch>,
) -> Result<()> {
    send_pep_last_item_for_owner(
        state,
        owner.id,
        &owner.username,
        node,
        recipient,
        on_presence,
        expected_local_epoch,
    )
    .await
}

pub(crate) fn prepare_pep_last_item_outbox(
    snapshot: &PepSubscribeSnapshot,
) -> Result<Vec<PubSubOutboxInsert>> {
    let Some(item) = snapshot.last_item.as_ref() else {
        return Ok(Vec::new());
    };
    let payload = published_event_item(&snapshot.node, &item.item_id, &item.payload)?;
    let message_id = uuid::Uuid::new_v4();
    let mut items = XmlElement::new("items").attr("node", &snapshot.node);
    items.push_validated_fragment(&payload)?;
    let message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &snapshot.owner_bare_jid)
        .attr("to", &snapshot.subscriber_jid)
        .attr("type", "headline")
        .attr("id", message_id)
        .child(XmlElement::namespaced("event", NS_PUBSUB_EVENT).child(items))
        .child(
            XmlElement::namespaced("delay", "urn:xmpp:delay")
                .attr("stamp", item.updated_at.to_rfc3339()),
        )
        .finish();
    Ok(vec![PubSubOutboxInsert::new_pep_stanza(
        message_id,
        snapshot.owner_id,
        &snapshot.owner_bare_jid,
        None,
        snapshot.subscriber_jid.clone(),
        snapshot.subscriber_account_id,
        PepOutboxEventKind::LastItem,
        PepOutboxAuthorizationMode::CausalAudience,
        message,
        &snapshot.node,
        &snapshot.local_domain,
        chrono::Utc::now(),
    )?])
}

async fn send_pep_last_item_for_owner(
    state: &crate::state::AppState,
    owner_id: uuid::Uuid,
    owner_username: &str,
    node: &str,
    recipient: &str,
    on_presence: bool,
    expected_local_epoch: Option<crate::state::LocalCapsEpoch>,
) -> Result<()> {
    let Some(config) = state.pubsub_service().pep_node(owner_id, node).await? else {
        return Ok(());
    };
    if config.send_last_published_item == "never"
        || on_presence && config.send_last_published_item != "on_sub_and_presence"
        || !config.deliver_notifications
    {
        return Ok(());
    }
    let Some(item) = state
        .pubsub_service()
        .pep_items_with_timestamp(owner_id, node, 1)
        .await?
        .into_iter()
        .next()
    else {
        return Ok(());
    };
    let owner_jid = canonical_account_jid(owner_username, &state.config.domain)?;
    let payload = published_event_item(node, &item.item_id, &item.payload)?;
    let mut items = XmlElement::new("items").attr("node", node);
    items.push_validated_fragment(&payload)?;
    let message = XmlElement::namespaced("message", "jabber:client")
        .attr("from", &owner_jid)
        .attr("to", recipient)
        .attr("type", "headline")
        .attr("id", uuid::Uuid::new_v4())
        .child(XmlElement::namespaced("event", NS_PUBSUB_EVENT).child(items))
        .child(
            XmlElement::namespaced("delay", "urn:xmpp:delay")
                .attr("stamp", item.updated_at.to_rfc3339()),
        )
        .finish();
    route_pep_message(state, &owner_jid, recipient, message, expected_local_epoch).await
}

/// Delivers XEP-0060 send-last events for durable explicit subscriptions.
/// Unlike XEP-0163 automatic subscriptions, explicit subscriptions do not
/// depend on an XEP-0115 `node+notify` feature advertisement.
pub(crate) async fn deliver_explicit_pep_last_items_for_resource(
    state: &crate::state::AppState,
    full_jid: &str,
    expected_local_epoch: Option<crate::state::LocalCapsEpoch>,
) -> Result<()> {
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
    for subscription in state
        .pubsub_service()
        .pep_subscriptions_for_available_resource(&full_jid)
        .await?
    {
        if pep_access_allowed_for_owner(
            state.pubsub_service(),
            subscription.owner_id,
            &subscription.owner_username,
            &state.config.domain,
            &subscription.node,
            &full_jid,
        )
        .await?
        {
            send_pep_last_item_for_owner(
                state,
                subscription.owner_id,
                &subscription.owner_username,
                &subscription.node,
                &full_jid,
                true,
                expected_local_epoch,
            )
            .await?;
        }
    }
    Ok(())
}

pub(crate) async fn deliver_pep_last_items_for_resource(
    state: &crate::state::AppState,
    full_jid: &str,
    expected_local_epoch: crate::state::LocalCapsEpoch,
) -> Result<()> {
    let wanted = super::caps::pep_notify_nodes(state, full_jid);
    if wanted.is_empty() {
        return Ok(());
    }
    let full = crate::jid::CanonicalJid::parse(full_jid)?;
    let bare = full.bare();
    let Some(username) = full.localpart() else {
        return Ok(());
    };
    let Some(subscriber) = state.pubsub_service().find_enabled_user(username).await? else {
        return Ok(());
    };
    let explicit = state
        .pubsub_service()
        .pep_subscriptions_for_available_resource(full_jid)
        .await?
        .into_iter()
        .map(|subscription| (subscription.owner_id, subscription.node))
        .collect::<HashSet<_>>();
    for node in &wanted {
        if !explicit.contains(&(subscriber.id, node.clone()))
            && state
                .pubsub_service()
                .pep_node(subscriber.id, node)
                .await?
                .is_some()
        {
            send_pep_last_item(
                state,
                &subscriber,
                node,
                full_jid,
                true,
                Some(expected_local_epoch),
            )
            .await?;
        }
    }
    for (contact, _, subscription, _) in state.pubsub_service().roster(subscriber.id).await? {
        if !matches!(subscription.as_str(), "to" | "both") {
            continue;
        }
        let Ok(contact_jid) = crate::jid::CanonicalJid::parse_bare(&contact) else {
            continue;
        };
        if contact_jid.domainpart() != state.config.domain {
            continue;
        }
        let Some(contact_name) = contact_jid.localpart() else {
            continue;
        };
        let Some(owner) = state
            .pubsub_service()
            .find_enabled_user(contact_name)
            .await?
        else {
            continue;
        };
        if state.pubsub_service().is_blocked(owner.id, &bare).await? {
            continue;
        }
        for node in &wanted {
            if !explicit.contains(&(owner.id, node.clone()))
                && pep_access_allowed(
                    state.pubsub_service(),
                    &owner,
                    &state.config.domain,
                    node,
                    &bare,
                )
                .await?
            {
                send_pep_last_item(
                    state,
                    &owner,
                    node,
                    full_jid,
                    true,
                    Some(expected_local_epoch),
                )
                .await?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn deliver_pep_last_items_for_federated_resource(
    state: &crate::state::AppState,
    full_jid: &str,
) -> Result<()> {
    let wanted = super::caps::pep_notify_nodes(state, full_jid);
    if wanted.is_empty() {
        return Ok(());
    }
    let remote = crate::jid::CanonicalJid::parse(full_jid)?;
    if remote.resourcepart().is_none() || remote.domainpart() == state.config.domain {
        return Ok(());
    }
    let bare = remote.bare();
    let explicit = state
        .pubsub_service()
        .pep_subscriptions_for_available_resource(full_jid)
        .await?
        .into_iter()
        .map(|subscription| (subscription.owner_id, subscription.node))
        .collect::<HashSet<_>>();
    for username in state
        .pubsub_service()
        .pep_owner_usernames_for_presence_subscriber(&bare)
        .await?
    {
        let Some(owner) = state.pubsub_service().find_enabled_user(&username).await? else {
            continue;
        };
        if state.pubsub_service().is_blocked(owner.id, &bare).await? {
            continue;
        }
        for node in &wanted {
            if !explicit.contains(&(owner.id, node.clone()))
                && pep_access_allowed(
                    state.pubsub_service(),
                    &owner,
                    &state.config.domain,
                    node,
                    full_jid,
                )
                .await?
            {
                send_pep_last_item(state, &owner, node, full_jid, true, None).await?;
            }
        }
    }
    Ok(())
}

/// Removes only an `<item>` root's inherited PubSub namespace before the
/// item is embedded below `pubsub#event`. Nested payload namespace
/// declarations are deliberately preserved.
fn strip_pubsub_item_root_namespaces(payload: &str) -> Result<String> {
    let root = XmlElement::new("root");
    let prefix_len = root.open().len();
    let wrapped = root.validated_fragment(payload)?.finish();
    let document = roxmltree::Document::parse(&wrapped)?;
    let single = format!(" xmlns='{NS_PUBSUB}'");
    let double = format!(" xmlns=\"{NS_PUBSUB}\"");
    let mut openings = document
        .root_element()
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "item")
        .filter_map(|item| {
            let range = item.range();
            let start = range.start.checked_sub(prefix_len)?;
            let end = payload[start..].find('>').map(|end| start + end)?;
            Some((start, end))
        })
        .collect::<Vec<_>>();
    let mut output = payload.to_owned();
    openings.sort_unstable_by_key(|(start, _)| std::cmp::Reverse(*start));
    for (start, end) in openings {
        let opening = output[start..=end].to_owned();
        let cleaned = opening.replace(&single, "").replace(&double, "");
        output.replace_range(start..=end, &cleaned);
    }
    Ok(output)
}

fn parse_owner_config(
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
                    PubSubService::PEP_MAX_ITEMS
                } else {
                    value.parse().map_err(|_| ())?
                };
                if !(1..=PubSubService::PEP_MAX_ITEMS).contains(&config.max_items) {
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
            || node == OMEMO_BUNDLES && config.max_items != PubSubService::PEP_MAX_ITEMS)
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

fn pep_config_form(config: &PepNodeConfig, kind: &str) -> String {
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

pub(crate) async fn pep_access_allowed(
    service: &PubSubService,
    owner: &crate::services::pubsub::PubSubAccount,
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
    service: &PubSubService,
    owner_id: uuid::Uuid,
    owner_username: &str,
    domain: &str,
    node: &str,
    requester_jid: &str,
) -> Result<bool> {
    let owner_jid = canonical_account_jid(owner_username, domain)?;
    let requester_bare = match crate::jid::canonical_bare_key(requester_jid) {
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
    service: &PubSubService,
    owner_id: uuid::Uuid,
    owner_username: &str,
    domain: &str,
    config: &PepNodeConfig,
    requester_jid: &str,
) -> Result<bool> {
    let owner_jid = canonical_account_jid(owner_username, domain)?;
    let requester_bare = match crate::jid::canonical_bare_key(requester_jid) {
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
                crate::jid::canonical_bare_key(jid).is_ok_and(|jid| jid == requester_bare)
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
    owner: &crate::services::pubsub::PubSubAccount,
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
            &state.config.domain,
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
    owner: &crate::services::pubsub::PubSubAccount,
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
                &state.config.domain,
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
    let owner_jid = canonical_account_jid(&owner.username, &state.config.domain)?;
    let mut query = XmlElement::namespaced("query", "http://jabber.org/protocol/disco#items");
    for node in state.pubsub_service().pep_nodes(owner.id).await? {
        if pep_access_allowed(
            state.pubsub_service(),
            owner,
            &state.config.domain,
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

struct PublishOptions {
    config: PepNodeConfig,
    explicit: bool,
}

fn publish_options(pubsub: Node<'_, '_>, node: &str) -> std::result::Result<PublishOptions, ()> {
    let mut config = PubSubService::default_pep_node_config(node);
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
                    PubSubService::PEP_MAX_ITEMS
                } else {
                    value.parse().map_err(|_| ())?
                };
                if !(1..=PubSubService::PEP_MAX_ITEMS).contains(&config.max_items) {
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
            || node == OMEMO_BUNDLES && config.max_items != PubSubService::PEP_MAX_ITEMS)
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

fn valid_pep_payload(node: &str, item_id: &str, item: Node<'_, '_>) -> bool {
    let payloads = item
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if payloads.len() != 1 {
        return false;
    }
    let payload = payloads[0];
    match node {
        BOOKMARKS2 => valid_bookmark(item_id, payload),
        AVATAR_DATA => valid_avatar_data(item_id, payload),
        AVATAR_METADATA => valid_avatar_metadata(item_id, payload),
        VCARD4 => valid_vcard4(payload),
        CONTACTS => valid_bare_jid(item_id) && item_id.contains('@') && valid_vcard4(payload),
        OMEMO_DEVICES => {
            if payload.tag_name().name() != "devices"
                || payload.tag_name().namespace() != Some(NS_OMEMO2)
                || payload.attributes().len() != 0
            {
                return false;
            }
            let mut ids = HashSet::new();
            let devices = payload
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            devices.len() <= 1_000
                && devices.iter().all(|device| {
                    device.tag_name().name() == "device"
                        && device.tag_name().namespace() == Some(NS_OMEMO2)
                        && !device.children().any(|child| child.is_element())
                        && device.text().is_none_or(|text| text.trim().is_empty())
                        && device.attributes().all(|attribute| {
                            attribute.namespace().is_none()
                                && matches!(attribute.name(), "id" | "label" | "labelsig")
                        })
                        && device.attribute("label").is_none_or(|label| {
                            !label.chars().any(char::is_control) && label.chars().count() <= 256
                        })
                        // `label` and `labelsig` are public presentation
                        // metadata authenticated end to end by the device
                        // identity key. XEP-0384 requires a receiving client
                        // to ignore an unsigned or invalid label; the server
                        // must not turn that into rejection of the device
                        // announcement. Keep only a transport resource bound.
                        && device
                            .attribute("labelsig")
                            .is_none_or(|signature| signature.chars().count() <= 4_096)
                        && device
                            .attribute("id")
                            .and_then(parse_positive_i32)
                            .is_some_and(|id| ids.insert(id))
                })
        }
        OMEMO_BUNDLES => {
            parse_positive_i32(item_id).is_some()
                && payload.tag_name().name() == "bundle"
                && payload.tag_name().namespace() == Some(NS_OMEMO2)
                && valid_omemo_bundle(payload)
        }
        _ => true,
    }
}

fn published_event_items(node: &str, items: &[(String, String)]) -> Result<String> {
    let mut container = XmlElement::new("northstar-items");
    for (item_id, payload) in items {
        container.push_validated_fragment(&published_event_item(node, item_id, payload)?)?;
    }
    Ok(container.finish_children())
}

pub(crate) fn profile_item_event(node: &str, payload: &str) -> Result<String> {
    let payload = strip_pubsub_item_root_namespaces(payload)?;
    let mut event = XmlElement::new("items").attr("node", node);
    event.push_validated_fragment(&payload)?;
    Ok(event.finish())
}

fn published_event_item(node: &str, item_id: &str, payload: &str) -> Result<String> {
    if node == VCARD4 {
        Ok(XmlElement::new("item").attr("id", item_id).finish())
    } else {
        strip_pubsub_item_root_namespaces(payload)
    }
}

fn valid_vcard4(payload: Node<'_, '_>) -> bool {
    const VCARD4_NS: &str = "urn:ietf:params:xml:ns:vcard-4.0";
    if payload.tag_name().name() != "vcard"
        || payload.tag_name().namespace() != Some(VCARD4_NS)
        || xml_subtree_contains_unsafe_bidi_controls(payload)
        || payload.attributes().len() != 0
        || payload.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
        || payload
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(VCARD4_NS)
                    && node.tag_name().name() == "fn"
            })
            .count()
            == 0
    {
        return false;
    }

    // RFC 6351 requires core and registered xCard element names to be
    // lower-case, while also requiring parsers to preserve/ignore extension
    // namespaces they do not understand.  Validate the mandatory FN value
    // without rejecting such namespaced extensions.
    if payload.descendants().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(VCARD4_NS)
            && node
                .tag_name()
                .name()
                .bytes()
                .any(|byte| byte.is_ascii_uppercase())
    }) {
        return false;
    }
    payload
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(VCARD4_NS)
                && node.tag_name().name() == "fn"
        })
        .all(|formatted_name| {
            if formatted_name.children().any(|child| {
                child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
            }) {
                return false;
            }
            let children = formatted_name
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            matches!(
                children.as_slice(),
                [text]
                    if text.tag_name().namespace() == Some(VCARD4_NS)
                        && text.tag_name().name() == "text"
            ) || matches!(
                children.as_slice(),
                [parameters, text]
                    if parameters.tag_name().namespace() == Some(VCARD4_NS)
                        && parameters.tag_name().name() == "parameters"
                        && text.tag_name().namespace() == Some(VCARD4_NS)
                        && text.tag_name().name() == "text"
            )
        })
}

pub(crate) fn valid_avatar_data(item_id: &str, payload: Node<'_, '_>) -> bool {
    decode_avatar_data(payload)
        .is_some_and(|bytes| valid_png_image(&bytes) && sha1_matches(item_id, &bytes))
}

fn decode_avatar_data(payload: Node<'_, '_>) -> Option<Vec<u8>> {
    if payload.tag_name().name() != "data"
        || payload.tag_name().namespace() != Some(AVATAR_DATA)
        || payload.attributes().len() != 0
        || payload.children().any(|child| child.is_element())
    {
        return None;
    }
    let encoded = payload
        .children()
        .filter_map(|child| child.text())
        .collect::<String>()
        .replace(|character: char| character.is_whitespace(), "");
    let bytes = BASE64.decode(encoded).ok()?;
    (!bytes.is_empty() && bytes.len() <= 256 * 1024 && detected_avatar_media_type(&bytes).is_some())
        .then_some(bytes)
}

pub(crate) fn valid_avatar_metadata(item_id: &str, payload: Node<'_, '_>) -> bool {
    if payload.tag_name().name() != "metadata"
        || payload.tag_name().namespace() != Some(AVATAR_METADATA)
        || payload.attributes().len() != 0
        || payload.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    let children = payload
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if children.is_empty() {
        return true;
    }

    let mut saw_pointer = false;
    let mut png_matches_item = false;
    let mut has_png_representation = false;
    let mut info_count = 0usize;
    for child in children {
        if child.tag_name().namespace() != Some(AVATAR_METADATA) {
            return false;
        }
        match child.tag_name().name() {
            "info" if !saw_pointer => {
                info_count += 1;
                if child.children().any(|nested| nested.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                    || child.attributes().any(|attribute| {
                        !matches!(
                            attribute.name(),
                            "bytes" | "height" | "id" | "type" | "url" | "width"
                        )
                    })
                {
                    return false;
                }
                let Some(bytes) = child
                    .attribute("bytes")
                    .and_then(|value| value.parse::<usize>().ok())
                else {
                    return false;
                };
                let Some(hash) = child.attribute("id").filter(|hash| valid_sha1(hash)) else {
                    return false;
                };
                let Some(media_type) = child.attribute("type") else {
                    return false;
                };
                let has_url = child.attribute("url").is_some();
                if !valid_avatar_media_type(media_type, has_url) {
                    return false;
                }
                if bytes > 256 * 1024
                    || child
                        .attribute("height")
                        .is_some_and(|value| value.parse::<u16>().is_err())
                    || child
                        .attribute("width")
                        .is_some_and(|value| value.parse::<u16>().is_err())
                    || child
                        .attribute("url")
                        .is_some_and(|url| !valid_http_url(url))
                {
                    return false;
                }
                if media_type.eq_ignore_ascii_case("image/png") {
                    has_png_representation = true;
                    if hash.eq_ignore_ascii_case(item_id) {
                        png_matches_item = true;
                    }
                }
            }
            "pointer" if info_count > 0 => {
                saw_pointer = true;
                if child.attributes().any(|attribute| {
                    !matches!(
                        attribute.name(),
                        "bytes" | "height" | "id" | "type" | "width"
                    )
                }) || child
                    .attribute("bytes")
                    .is_some_and(|value| value.parse::<usize>().is_err())
                    || child
                        .attribute("height")
                        .is_some_and(|value| value.parse::<u32>().is_err())
                    || child
                        .attribute("width")
                        .is_some_and(|value| value.parse::<u32>().is_err())
                    || child
                        .attribute("id")
                        .is_some_and(|value| !valid_sha1(value))
                    || child
                        .attribute("type")
                        .is_some_and(|value| !valid_avatar_media_type(value, true))
                    || child.children().any(|nested| {
                        nested.is_text()
                            && nested.text().is_some_and(|text| !text.trim().is_empty())
                    })
                {
                    return false;
                }
                let nested = child
                    .children()
                    .filter(|nested| nested.is_element())
                    .collect::<Vec<_>>();
                if nested.len() != 1
                    || nested[0].tag_name().namespace().is_none_or(str::is_empty)
                    || nested[0].tag_name().namespace() == Some(AVATAR_METADATA)
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    // XEP-0084 binds the metadata ItemID to the mandatory PNG
    // representation. The PNG itself may be hosted at an HTTP URL; that is a
    // valid XEP-0084 publication even though it cannot be projected into
    // vCard-temp without the service becoming an HTTP fetcher.
    info_count > 0 && has_png_representation && png_matches_item
}

fn valid_sha1(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_avatar_media_type(value: &str, allow_video: bool) -> bool {
    let Some((top_level, subtype)) = value.split_once('/') else {
        return false;
    };
    value.len() <= 127
        && (top_level.eq_ignore_ascii_case("image")
            || allow_video && top_level.eq_ignore_ascii_case("video"))
        && !subtype.is_empty()
        && !subtype.contains('/')
        && subtype.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

fn valid_http_url(value: &str) -> bool {
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once("://") else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    !remainder
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .is_empty()
}

fn detected_avatar_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"BM") {
        Some("image/bmp")
    } else if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        Some("image/tiff")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/vnd.microsoft.icon")
    } else if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        match &bytes[8..12] {
            b"avif" | b"avis" => Some("image/avif"),
            b"heic" | b"heix" | b"hevc" | b"hevx" => Some("image/heic"),
            b"mif1" | b"msf1" => Some("image/heif"),
            _ => None,
        }
    } else {
        None
    }
}

/// Validate the PNG container before accepting it as an XEP-0084 image.
///
/// A magic-byte check is not sufficient: it permits arbitrary content to be
/// published under the mandatory `image/png` representation. This parser is
/// bounded by the avatar payload quota and verifies chunk bounds and CRCs, the
/// required chunk state machine, IHDR fields, critical-chunk names, and the
/// absence of trailing data. Image decompression remains the client's task.
pub(crate) fn valid_png_image(bytes: &[u8]) -> bool {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(SIGNATURE) {
        return false;
    }

    let mut offset = SIGNATURE.len();
    let mut saw_ihdr = false;
    let mut saw_plte = false;
    let mut saw_idat = false;
    let mut left_idat_run = false;
    let mut color_type = 0_u8;

    while offset < bytes.len() {
        let Some(header_end) = offset.checked_add(8) else {
            return false;
        };
        if header_end > bytes.len() {
            return false;
        }
        let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let chunk_type = &bytes[offset + 4..header_end];
        let Some(data_end) = header_end.checked_add(length) else {
            return false;
        };
        let Some(chunk_end) = data_end.checked_add(4) else {
            return false;
        };
        if chunk_end > bytes.len()
            || !chunk_type.iter().all(u8::is_ascii_alphabetic)
            || png_crc32(&bytes[offset + 4..data_end])
                != u32::from_be_bytes(bytes[data_end..chunk_end].try_into().unwrap())
        {
            return false;
        }

        match chunk_type {
            b"IHDR" => {
                if saw_ihdr || offset != SIGNATURE.len() || length != 13 {
                    return false;
                }
                let data = &bytes[header_end..data_end];
                let width = u32::from_be_bytes(data[0..4].try_into().unwrap());
                let height = u32::from_be_bytes(data[4..8].try_into().unwrap());
                let bit_depth = data[8];
                color_type = data[9];
                let valid_depth = match color_type {
                    0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
                    2 | 4 | 6 => matches!(bit_depth, 8 | 16),
                    3 => matches!(bit_depth, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if width == 0
                    || height == 0
                    || !valid_depth
                    || data[10] != 0
                    || data[11] != 0
                    || data[12] > 1
                {
                    return false;
                }
                saw_ihdr = true;
            }
            b"PLTE" => {
                if !saw_ihdr
                    || saw_plte
                    || saw_idat
                    || matches!(color_type, 0 | 4)
                    || length == 0
                    || length > 768
                    || !length.is_multiple_of(3)
                {
                    return false;
                }
                saw_plte = true;
            }
            b"IDAT" => {
                if !saw_ihdr || left_idat_run || color_type == 3 && !saw_plte {
                    return false;
                }
                saw_idat = true;
            }
            b"IEND" => {
                return saw_ihdr && saw_idat && length == 0 && chunk_end == bytes.len();
            }
            // Unknown critical chunks cannot be interpreted safely. Unknown
            // ancillary chunks are explicitly forward-compatible in PNG.
            _ if chunk_type[0].is_ascii_uppercase() => return false,
            _ => {
                if !saw_ihdr {
                    return false;
                }
            }
        }
        if saw_idat && chunk_type != b"IDAT" {
            left_idat_run = true;
        }
        offset = chunk_end;
    }
    false
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn sha1_matches(expected: &str, bytes: &[u8]) -> bool {
    let digest = Sha1::digest(bytes);
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    actual.eq_ignore_ascii_case(expected)
}

fn parse_form_bool(value: &str) -> std::result::Result<bool, ()> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(()),
    }
}

fn valid_bookmark(item_id: &str, conference: Node<'_, '_>) -> bool {
    if conference.tag_name().name() != "conference"
        || conference.tag_name().namespace() != Some(BOOKMARKS2)
        || conference.attribute("jid").is_some()
        || item_id.contains('/')
        || !item_id.contains('@')
        || !valid_bare_jid(item_id)
        || conference
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "autojoin" | "name"))
        || conference.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    if conference
        .attribute("autojoin")
        .is_some_and(|value| !matches!(value, "0" | "1" | "false" | "true"))
    {
        return false;
    }
    let mut previous_order = 0_u8;
    conference
        .children()
        .filter(|child| child.is_element())
        .all(|child| {
            if child.tag_name().namespace() != Some(BOOKMARKS2) {
                return false;
            }
            let order = match child.tag_name().name() {
                "nick" => 1,
                "password" => 2,
                "extensions" => 3,
                _ => return false,
            };
            if order <= previous_order {
                return false;
            }
            previous_order = order;
            if child.attributes().len() != 0
                || child.children().any(|nested| {
                    nested.is_text()
                        && nested
                            .text()
                            .is_some_and(|text| order == 3 && !text.trim().is_empty())
                })
            {
                return false;
            }
            if order < 3 {
                !child.children().any(|nested| nested.is_element())
            } else {
                child
                    .children()
                    .filter(|nested| nested.is_element())
                    .all(|nested| nested.tag_name().namespace() != Some(BOOKMARKS2))
            }
        })
}

fn valid_omemo_bundle(bundle: Node<'_, '_>) -> bool {
    if bundle.attributes().len() != 0 {
        return false;
    }
    let children = bundle
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if children.len() != 4
        || children
            .iter()
            .any(|child| child.tag_name().namespace() != Some(NS_OMEMO2))
    {
        return false;
    }
    let exactly_one = |name: &str| {
        children
            .iter()
            .filter(|child| child.tag_name().name() == name)
            .count()
            == 1
    };
    if !["spk", "spks", "ik", "prekeys"]
        .iter()
        .all(|name| exactly_one(name))
    {
        return false;
    }
    let spk = children
        .iter()
        .find(|child| child.tag_name().name() == "spk")
        .copied()
        .expect("checked above");
    let spks = children
        .iter()
        .find(|child| child.tag_name().name() == "spks")
        .copied()
        .expect("checked above");
    let identity = children
        .iter()
        .find(|child| child.tag_name().name() == "ik")
        .copied()
        .expect("checked above");
    if spk
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
        || spk.attribute("id").and_then(parse_positive_i32).is_none()
        || !valid_leaf_b64_exact(spk, 32)
        || spks.attributes().len() != 0
        || !valid_leaf_b64_exact(spks, 64)
        || identity.attributes().len() != 0
        || !valid_leaf_b64_exact(identity, 32)
    {
        return false;
    }
    let prekeys = children
        .iter()
        .find(|child| child.tag_name().name() == "prekeys")
        .copied()
        .expect("checked above");
    if prekeys.attributes().len() != 0 {
        return false;
    }
    let mut ids = HashSet::new();
    let keys = prekeys
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    keys.len() >= 25
        && keys.len() <= 1000
        && keys.iter().all(|key| {
            key.tag_name().name() == "pk"
                && key.tag_name().namespace() == Some(NS_OMEMO2)
                && key
                    .attributes()
                    .all(|attribute| attribute.namespace().is_none() && attribute.name() == "id")
                && valid_leaf_b64_exact(*key, 32)
                && key
                    .attribute("id")
                    .and_then(parse_positive_i32)
                    .is_some_and(|id| ids.insert(id))
        })
}

fn valid_leaf_b64_exact(node: Node<'_, '_>, decoded_len: usize) -> bool {
    !node.children().any(|child| child.is_element())
        && node
            .text()
            .is_some_and(|text| valid_b64_exact(text, decoded_len))
}

fn valid_b64_exact(value: &str, decoded_len: usize) -> bool {
    if value.len() > decoded_len.saturating_mul(2).saturating_add(16) {
        return false;
    }
    let compact = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    BASE64
        .decode(compact)
        .is_ok_and(|decoded| decoded.len() == decoded_len)
}

fn parse_positive_i32(value: &str) -> Option<i32> {
    value.parse::<i32>().ok().filter(|value| *value > 0)
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

fn normalized_pep_item(item_xml: &str, item_id: &str, rewrite_id: bool) -> String {
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
    fn c2s_pep_subscription_handlers_delegate_authority_to_the_service() {
        let source = include_str!("pep.rs");
        let subscribe = source
            .split_once("async fn pep_subscribe(")
            .expect("PEP subscribe handler must remain identifiable")
            .1
            .split_once("async fn pep_unsubscribe(")
            .expect("PEP subscribe handler must end before unsubscribe")
            .0;
        let unsubscribe = source
            .split_once("async fn pep_unsubscribe(")
            .expect("PEP unsubscribe handler must remain identifiable")
            .1
            .split_once("async fn pep_target_owner(")
            .expect("PEP unsubscribe handler must end before target resolution")
            .0;
        for handler in [subscribe, unsubscribe] {
            for forbidden in [
                ".pep_node(",
                "pep_access_allowed(",
                "subscribe_pep_node_with_outbox(",
            ] {
                assert!(
                    !handler.contains(forbidden),
                    "PEP subscription authority escaped the service transaction: {forbidden}"
                );
            }
        }
        assert!(subscribe.contains(".subscribe_pep_node("));
        assert!(unsubscribe.contains(".unsubscribe_pep_node("));
    }

    #[test]
    fn generated_or_canonicalized_pep_id_is_inserted_into_stored_item() {
        assert_eq!(
            normalized_pep_item("<item><value/></item>", "generated", true),
            "<item id='generated'><value/></item>"
        );
        assert_eq!(
            normalized_pep_item("<item/>", "generated", true),
            "<item id='generated'/>"
        );
        assert_eq!(
            normalized_pep_item(
                "<item id='ALICE@BÜCHER.example'><value/></item>",
                "alice@bücher.example",
                true,
            ),
            "<item id='alice@bücher.example'><value/></item>"
        );
    }

    #[test]
    fn omemo_device_list_rejects_duplicate_or_invalid_ids() {
        let valid = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub' id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='1'/><device id='2'/></devices></item>",
        )
        .unwrap();
        assert!(valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            valid.root_element()
        ));
        for xml in [
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1'/><device id='1'/></devices></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='0'/></devices></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'/><extra/></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2' xmlns:x='urn:example:attacker'><device id='1' x:label='spoofed'/></devices></item>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!valid_pep_payload(
                OMEMO_DEVICES,
                "current",
                document.root_element()
            ));
        }
    }

    #[test]
    fn omemo_payloads_bound_labels_and_require_well_formed_base64_bundles() {
        let public_key = BASE64.encode([7_u8; 32]);
        let signature = BASE64.encode([8_u8; 64]);
        let prekeys = (1..=25)
            .map(|id| format!("<pk id='{id}'>{public_key}</pk>"))
            .collect::<String>();
        let bundle_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub' id='42'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>{public_key}</spk><spks>{signature}</spks><ik>{public_key}</ik><prekeys>{prekeys}</prekeys></bundle></item>"
        );
        let bundle = Document::parse(&bundle_xml).unwrap();
        assert!(valid_pep_payload(
            OMEMO_BUNDLES,
            "42",
            bundle.root_element()
        ));
        let namespaced_bundle_xml = bundle_xml
            .replace(
                "<bundle xmlns='urn:xmpp:omemo:2'>",
                "<bundle xmlns='urn:xmpp:omemo:2' xmlns:x='urn:example:attacker'>",
            )
            .replace("<spk id='1'>", "<spk id='1' x:id='2'>");
        let namespaced_bundle = Document::parse(&namespaced_bundle_xml).unwrap();
        assert!(!valid_pep_payload(
            OMEMO_BUNDLES,
            "42",
            namespaced_bundle.root_element()
        ));

        for xml in [
            "<item xmlns='http://jabber.org/protocol/pubsub'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>not-base64!</spk><spks>BAUG</spks><ik>BwgJ</ik><prekeys><pk id='1'>CgsM</pk></prekeys></bundle></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>AQID</spk><spk id='2'>AQID</spk><spks>BAUG</spks><ik>BwgJ</ik><prekeys><pk id='1'>CgsM</pk></prekeys></bundle></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><bundle xmlns='urn:xmpp:omemo:2'><spk id='1'>AQID</spk><spks>BAUG</spks><ik>BwgJ</ik><prekeys><pk id='1'>CgsM</pk><pk id='1'>DQ4P</pk></prekeys></bundle></item>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!valid_pep_payload(
                OMEMO_BUNDLES,
                "42",
                document.root_element()
            ));
        }

        let too_few = bundle_xml.replace(
            &prekeys,
            &(1..=24)
                .map(|id| format!("<pk id='{id}'>{public_key}</pk>"))
                .collect::<String>(),
        );
        let document = Document::parse(&too_few).unwrap();
        assert!(!valid_pep_payload(
            OMEMO_BUNDLES,
            "42",
            document.root_element()
        ));
        let short_key = bundle_xml.replacen(&public_key, "AQID", 1);
        let document = Document::parse(&short_key).unwrap();
        assert!(!valid_pep_payload(
            OMEMO_BUNDLES,
            "42",
            document.root_element()
        ));

        let unsigned_label = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone'/></devices></item>",
        )
        .unwrap();
        // The receiving client, which has the referenced identity key, must
        // ignore an unsigned label. The server stores and forwards the device
        // announcement instead of blocking OMEMO initialization.
        assert!(valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            unsigned_label.root_element()
        ));
        let signed_label_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='{}'/></devices></item>",
            BASE64.encode([9_u8; 64])
        );
        let signed_label = Document::parse(&signed_label_xml).unwrap();
        assert!(valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            signed_label.root_element()
        ));
        let bad_signature = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='!'/></devices></item>",
        )
        .unwrap();
        assert!(valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            bad_signature.root_element()
        ));
        let short_signature = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='AQID'/></devices></item>",
        )
        .unwrap();
        assert!(valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            short_signature.root_element()
        ));
        let oversized_signature = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1' label='phone' labelsig='{}'/></devices></item>",
            "A".repeat(4_097)
        );
        let oversized_signature = Document::parse(&oversized_signature).unwrap();
        assert!(!valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            oversized_signature.root_element()
        ));
    }

    #[test]
    fn event_embedding_strips_only_item_root_pubsub_namespace() {
        let payload = "<item xmlns='http://jabber.org/protocol/pubsub' id='one'><payload xmlns='http://jabber.org/protocol/pubsub'><item xmlns='urn:nested'/></payload></item><items xmlns='http://jabber.org/protocol/pubsub'/>";
        assert_eq!(
            strip_pubsub_item_root_namespaces(payload).unwrap(),
            "<item id='one'><payload xmlns='http://jabber.org/protocol/pubsub'><item xmlns='urn:nested'/></payload></item><items xmlns='http://jabber.org/protocol/pubsub'/>"
        );
    }

    #[test]
    fn publish_options_apply_omemo_defaults_and_reject_unknown_fields() {
        let xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:bundles'/><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#access_model'><value>open</value></field><field var='pubsub#max_items'><value>max</value></field></x></publish-options></pubsub>";
        let document = Document::parse(xml).unwrap();
        let options = publish_options(document.root_element(), OMEMO_BUNDLES).unwrap();
        assert!(options.explicit);
        assert_eq!(options.config.access_model, "open");
        assert_eq!(options.config.max_items, PubSubService::PEP_MAX_ITEMS);

        let invalid = xml.replace("pubsub#max_items", "pubsub#unknown");
        let document = Document::parse(&invalid).unwrap();
        assert!(publish_options(document.root_element(), OMEMO_BUNDLES).is_err());
    }

    #[test]
    fn bookmarks_require_private_persistent_publish_options() {
        let xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:bookmarks:1'/><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#persist_items'><value>true</value></field><field var='pubsub#max_items'><value>max</value></field><field var='pubsub#send_last_published_item'><value>never</value></field><field var='pubsub#access_model'><value>whitelist</value></field></x></publish-options></pubsub>";
        let document = Document::parse(xml).unwrap();
        let options = publish_options(document.root_element(), BOOKMARKS2).unwrap();
        assert!(options.explicit);
        assert_eq!(options.config.access_model, "whitelist");
        assert_eq!(options.config.max_items, PubSubService::PEP_MAX_ITEMS);
        assert!(options.config.persist_items);
        assert_eq!(options.config.send_last_published_item, "never");

        for invalid in [
            xml.replace("<value>true</value>", "<value>false</value>"),
            xml.replace("<value>whitelist</value>", "<value>presence</value>"),
            xml.replace("<value>never</value>", "<value>sometimes</value>"),
        ] {
            let document = Document::parse(&invalid).unwrap();
            assert!(publish_options(document.root_element(), BOOKMARKS2).is_err());
        }
    }

    #[test]
    fn bookmarks_validate_item_ids_and_payload_shape() {
        let valid = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub' id='room@conference.example'><conference xmlns='urn:xmpp:bookmarks:1' autojoin='true' name='Room'><nick>alice</nick><extensions><state xmlns='urn:example:state'/></extensions></conference></item>",
        )
        .unwrap();
        assert!(valid_pep_payload(
            BOOKMARKS2,
            "room@conference.example",
            valid.root_element()
        ));

        for (id, xml) in [
            (
                "room@conference.example/device",
                "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'/></item>",
            ),
            (
                "room@conference.example",
                "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1' jid='other@example'/></item>",
            ),
            (
                "room@conference.example",
                "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1' autojoin='yes'/></item>",
            ),
            (
                "room@conference.example",
                "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><nick>a</nick><nick>b</nick></conference></item>",
            ),
            (
                "room@conference.example",
                "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><password>secret</password><nick>late</nick></conference></item>",
            ),
            (
                "room@conference.example",
                "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><nick><b xmlns='urn:example'>nested</b></nick></conference></item>",
            ),
            (
                "room@conference.example",
                "<item xmlns='http://jabber.org/protocol/pubsub'><conference xmlns='urn:xmpp:bookmarks:1'><state xmlns='urn:example:state'/></conference></item>",
            ),
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!valid_pep_payload(BOOKMARKS2, id, document.root_element()));
        }
    }

    #[test]
    fn avatar_items_require_decoded_sha1_and_consistent_metadata() {
        let png = BASE64
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgZGL+DwABFAEG1rmmRQAAAABJRU5ErkJggg==")
            .unwrap();
        let hash = Sha1::digest(&png)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let data_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><data xmlns='urn:xmpp:avatar:data'>{}</data></item>",
            BASE64.encode(&png)
        );
        let data = Document::parse(&data_xml).unwrap();
        assert!(valid_pep_payload(AVATAR_DATA, &hash, data.root_element()));
        let encoded = BASE64.encode(&png);
        let folded_data_xml =
            data_xml.replace(&encoded, &format!("{}\n{}", &encoded[..20], &encoded[20..]));
        let folded_data = Document::parse(&folded_data_xml).unwrap();
        assert!(valid_pep_payload(
            AVATAR_DATA,
            &hash,
            folded_data.root_element()
        ));
        let split_data_xml = data_xml.replace(
            &encoded,
            &format!("{}<![CDATA[{}]]>", &encoded[..20], &encoded[20..]),
        );
        let split_data = Document::parse(&split_data_xml).unwrap();
        assert!(valid_pep_payload(
            AVATAR_DATA,
            &hash,
            split_data.root_element()
        ));
        assert!(!valid_pep_payload(
            AVATAR_DATA,
            "0000000000000000000000000000000000000000",
            data.root_element()
        ));

        let fake_png = b"\x89PNG\r\n\x1a\nnot-an-image";
        let fake_hash = Sha1::digest(fake_png)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let fake_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><data xmlns='urn:xmpp:avatar:data'>{}</data></item>",
            BASE64.encode(fake_png)
        );
        let fake = Document::parse(&fake_xml).unwrap();
        assert!(!valid_pep_payload(
            AVATAR_DATA,
            &fake_hash,
            fake.root_element()
        ));

        let mut bad_crc = png.clone();
        bad_crc[30] ^= 1;
        assert!(!valid_png_image(&bad_crc));
        let mut trailing = png.clone();
        trailing.push(0);
        assert!(!valid_png_image(&trailing));

        let gif_only_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='5' id='{hash}' type='image/gif'/></metadata></item>"
        );
        let gif_only = Document::parse(&gif_only_xml).unwrap();
        assert!(!valid_pep_payload(
            AVATAR_METADATA,
            &hash,
            gif_only.root_element()
        ));

        let jpeg = [0xff, 0xd8, 0xff, 0xd9];
        let jpeg_hash = Sha1::digest(jpeg)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let jpeg_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><data xmlns='urn:xmpp:avatar:data'>{}</data></item>",
            BASE64.encode(jpeg)
        );
        let jpeg_data = Document::parse(&jpeg_xml).unwrap();
        assert!(!valid_pep_payload(
            AVATAR_DATA,
            &jpeg_hash,
            jpeg_data.root_element()
        ));

        let metadata_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='5' id='{hash}' type='image/png'/></metadata></item>"
        );
        let metadata = Document::parse(&metadata_xml).unwrap();
        assert!(valid_pep_payload(
            AVATAR_METADATA,
            &hash,
            metadata.root_element()
        ));
        assert!(!valid_pep_payload(
            AVATAR_METADATA,
            "0000000000000000000000000000000000000000",
            metadata.root_element()
        ));

        let clear = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'/></item>",
        )
        .unwrap();
        assert!(valid_pep_payload(
            AVATAR_METADATA,
            "current",
            clear.root_element()
        ));
    }

    #[test]
    fn avatar_metadata_accepts_external_alternates_and_strict_pointers() {
        let png = BASE64
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgZGL+DwABFAEG1rmmRQAAAABJRU5ErkJggg==")
            .unwrap();
        let hash = Sha1::digest(&png)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let external_only_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='{}' id='{hash}' type='IMAGE/PNG' url='HTTPS://avatars.example.test/a.png'/></metadata></item>",
            png.len()
        );
        let external_only = Document::parse(&external_only_xml).unwrap();
        assert!(valid_pep_payload(
            AVATAR_METADATA,
            &hash,
            external_only.root_element()
        ));

        let multiple_xml = format!(
            "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><info bytes='42' id='1111111111111111111111111111111111111111' type='video/mp4' url='https://avatars.example.test/a.mp4'/><pointer type='image/png'><x xmlns='urn:example:avatar-pointer'><account>alice</account></x></pointer></metadata></item>"
        );
        let multiple = Document::parse(&multiple_xml).unwrap();
        assert!(valid_pep_payload(
            AVATAR_METADATA,
            &hash,
            multiple.root_element()
        ));

        for invalid_xml in [
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><pointer><x xmlns=''/></pointer></metadata></item>"
            ),
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><pointer><x xmlns='urn:example:pointer'/></pointer><info bytes='8' id='{hash}' type='image/png'/></metadata></item>"
            ),
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/' url='https://avatars.example.test/a'/></metadata></item>"
            ),
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png;profile=x' url='https://avatars.example.test/a'/></metadata></item>"
            ),
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png' url='http://'/></metadata></item>"
            ),
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png' url='ftp://avatars.example.test/a'/></metadata></item>"
            ),
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'>unexpected<info bytes='8' id='{hash}' type='image/png'/></metadata></item>"
            ),
            format!(
                "<item xmlns='http://jabber.org/protocol/pubsub'><metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/><pointer>unexpected<x xmlns='urn:example:pointer'/></pointer></metadata></item>"
            ),
        ] {
            let invalid = Document::parse(&invalid_xml).unwrap();
            assert!(!valid_pep_payload(
                AVATAR_METADATA,
                &hash,
                invalid.root_element()
            ));
        }
    }

    #[test]
    fn avatar_and_vcard_nodes_reject_non_public_or_non_persistent_options() {
        let base = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:avatar:metadata'/><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#access_model'><value>open</value></field><field var='pubsub#max_items'><value>1</value></field><field var='pubsub#persist_items'><value>true</value></field></x></publish-options></pubsub>";
        let document = Document::parse(base).unwrap();
        assert!(publish_options(document.root_element(), AVATAR_METADATA).is_ok());
        for invalid in [
            base.replace("<value>open</value>", "<value>presence</value>"),
            base.replace("<value>true</value>", "<value>false</value>"),
            base.replace("<value>1</value>", "<value>2</value>"),
        ] {
            let document = Document::parse(&invalid).unwrap();
            assert!(publish_options(document.root_element(), AVATAR_METADATA).is_err());
        }
    }

    #[test]
    fn vcard4_event_is_a_pure_item_notification() {
        let stored = "<item id='current'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice</text></fn></vcard></item>";
        let payload =
            published_event_items(VCARD4, &[("current".to_owned(), stored.to_owned())]).unwrap();
        assert_eq!(payload, "<item id='current'/>");
        assert!(!payload.contains("vcard"));
        assert_eq!(
            published_event_item(VCARD4, "current", stored).unwrap(),
            "<item id='current'/>"
        );
    }

    #[test]
    fn vcard4_and_contact_nodes_reject_wrong_payload_shapes() {
        let card = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice</text></fn></vcard></item>",
        )
        .unwrap();
        assert!(valid_pep_payload(VCARD4, "generated", card.root_element()));
        assert!(valid_pep_payload(
            CONTACTS,
            "alice@example.test",
            card.root_element()
        ));
        assert!(!valid_pep_payload(
            CONTACTS,
            "not-a-jid",
            card.root_element()
        ));

        for xml in [
            "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>Alice\u{202e}txt.exe</text></fn></vcard></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'/></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><FN><text>Alice</text></FN></vcard></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn/></vcard></item>",
        ] {
            let invalid = Document::parse(xml).unwrap();
            assert!(!valid_pep_payload(
                VCARD4,
                "generated",
                invalid.root_element()
            ));
        }
    }
}
