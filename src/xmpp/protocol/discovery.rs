use super::{Action, ProtocolSession};
use crate::services::mix::{
    CORE_NODES, NODE_ALLOWED, NODE_AVATAR_DATA, NODE_AVATAR_METADATA, NODE_BANNED, NODE_CONFIG,
    NODE_JIDMAP,
};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;

const DISCO_INFO_NS: &str = "http://jabber.org/protocol/disco#info";
const DISCO_ITEMS_NS: &str = "http://jabber.org/protocol/disco#items";
const RSM_NS: &str = "http://jabber.org/protocol/rsm";
const XDATA_NS: &str = "jabber:x:data";

fn disco_info_query(node: Option<&str>) -> XmlElement {
    XmlElement::namespaced("query", DISCO_INFO_NS).optional_attr("node", node)
}

fn disco_items_query(node: Option<&str>) -> XmlElement {
    XmlElement::namespaced("query", DISCO_ITEMS_NS).optional_attr("node", node)
}

fn disco_identity(category: &str, kind: &str, name: Option<&str>) -> XmlElement {
    XmlElement::new("identity")
        .attr("category", category)
        .attr("type", kind)
        .optional_attr("name", name)
}

fn disco_feature(feature: &str) -> XmlElement {
    XmlElement::new("feature").attr("var", feature)
}

fn disco_item(jid: &str, node: Option<&str>, name: Option<&str>) -> XmlElement {
    XmlElement::new("item")
        .attr("jid", jid)
        .optional_attr("node", node)
        .optional_attr("name", name)
}

fn data_field<I, V>(variable: &str, values: I) -> XmlElement
where
    I: IntoIterator<Item = V>,
    V: ToString,
{
    let mut field = XmlElement::new("field").attr("var", variable);
    for value in values {
        field.push_child(XmlElement::new("value").text(value.to_string()));
    }
    field
}

fn result_form(form_type: &str) -> XmlElement {
    XmlElement::namespaced("x", XDATA_NS)
        .attr("type", "result")
        .child(data_field("FORM_TYPE", [form_type]).attr("type", "hidden"))
}

const ACCOUNT_DISCO_FEATURES: &[&str] = &[
    "http://jabber.org/protocol/disco#info",
    "http://jabber.org/protocol/disco#items",
    "http://jabber.org/protocol/pubsub#pep",
    "http://jabber.org/protocol/pubsub#access-open",
    "http://jabber.org/protocol/pubsub#access-presence",
    "http://jabber.org/protocol/pubsub#access-roster",
    "http://jabber.org/protocol/pubsub#multi-items",
    "http://jabber.org/protocol/pubsub#persistent-items",
    "http://jabber.org/protocol/pubsub#auto-create",
    "http://jabber.org/protocol/pubsub#auto-subscribe",
    "http://jabber.org/protocol/pubsub#filtered-notifications",
    "http://jabber.org/protocol/pubsub#access-whitelist",
    "http://jabber.org/protocol/pubsub#config-node",
    "http://jabber.org/protocol/pubsub#create-nodes",
    "http://jabber.org/protocol/pubsub#delete-nodes",
    "http://jabber.org/protocol/pubsub#delete-items",
    "http://jabber.org/protocol/pubsub#publish-options",
    "http://jabber.org/protocol/pubsub#publish",
    "http://jabber.org/protocol/pubsub#purge-nodes",
    "http://jabber.org/protocol/pubsub#retract-items",
    "http://jabber.org/protocol/pubsub#retrieve-items",
    "http://jabber.org/protocol/pubsub#subscribe",
    // XEP-0313 exposes a user's archive on the user's bare JID, not only on
    // the hosting domain. Advertise the exact query/RSM profile on that
    // entity so remote disco does not need to guess from server-root caps.
    "http://jabber.org/protocol/rsm",
    "urn:xmpp:sid:0",
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

// Features advertised by the server entity itself. End-to-end presentation
// protocols belong in each connected client's XEP-0115/XEP-0030 caps, not in
// the server root. XEP-0424 is deliberately present because an archive-aware
// server and a tombstone service MUST advertise these two features.
const SERVER_DISCO_FEATURES: &[&str] = &[
    "http://jabber.org/protocol/disco#info",
    "http://jabber.org/protocol/disco#items",
    "jabber:iq:roster",
    "jabber:iq:private",
    "http://jabber.org/protocol/rsm",
    "urn:xmpp:receipts",
    // XEP-0160 section 3: advertise durable offline-message storage on the
    // server entity. This is the historical disco feature name clients use.
    "msgoffline",
    "urn:xmpp:sid:0",
    "urn:xmpp:message-retract:1",
    "urn:xmpp:message-retract:1#tombstone",
    "urn:xmpp:hints",
    "http://jabber.org/protocol/muc",
    northstar_xep_0363::NAMESPACE,
    "vcard-temp",
    "urn:xmpp:avatar:data",
    "urn:xmpp:avatar:metadata",
    "urn:ietf:params:xml:ns:vcard-4.0",
    "urn:xmpp:vcard4",
    "urn:xmpp:bookmarks:1",
    "urn:xmpp:serverinfo:0",
    "urn:xmpp:mix:pam:2",
    "urn:xmpp:mix:pam:2#archive",
    "urn:xmpp:mix:roster:0",
];

impl ProtocolSession {
    pub(crate) async fn disco_info(
        &self,
        id: &str,
        to: Option<&str>,
        request: roxmltree::Node<'_, '_>,
    ) -> Result<Action> {
        let requested_from = to.unwrap_or(&self.state.config.domain);
        let Ok(target) = crate::jid::CanonicalJid::parse(requested_from) else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let from = target.to_string();
        let from = from.as_str();
        let pubsub_domain = self.pubsub_domain();
        let is_pubsub_service = target.localpart().is_none()
            && target.resourcepart().is_none()
            && target.domainpart() == pubsub_domain;
        if is_pubsub_service
            && !self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0060::XEP_ID)
        {
            return Ok(Action::Send(iq_error_from(id, from, "service-unavailable")));
        }
        if !is_pubsub_service && !valid_disco_query(request) {
            return Ok(Action::Send(iq_error_from(id, from, "bad-request")));
        }
        let muc_domain = self.muc_domain();
        if target.domainpart() == muc_domain
            && !self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0045::XEP_ID)
        {
            return Ok(Action::Send(iq_error_from(id, from, "service-unavailable")));
        }
        let upload_domain = self.upload_domain();
        let mix_domain = self.mix_domain();
        if target.localpart().is_none() && target.domainpart() == mix_domain {
            if request.attribute("node").is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let linked = self.state.config.mix_muc_mirror_enabled
                && self
                    .state
                    .mix_service()
                    .mix_muc_mirror_service_complete(&mix_domain)
                    .await?;
            let mirror = super::mix_muc::conditional_mirror_discovery_form(
                self.state.config.mix_muc_mirror_enabled,
                linked,
                super::mix_muc::MirrorDirection::Muc,
                &muc_domain,
            );
            let query = super::mix::mix_service_disco_info_payload(
                &self.state.config.server_name,
                &mirror,
            )?;
            return Ok(Action::Send(iq_result_from(id, from, &query)));
        }
        if target.localpart().is_some() && target.domainpart() == mix_domain {
            if request.attribute("node").is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let Some(channel) = self
                .state
                .mix_service()
                .mix_channel(
                    &mix_domain,
                    target.localpart().expect("MIX channel localpart checked"),
                )
                .await?
            else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            let Some(user) = self.authenticated.as_ref() else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            let requester = format!("{}@{}", user.username, self.state.config.domain);
            if !self
                .state
                .mix_service()
                .mix_channel_discoverable_to(&channel, &requester)
                .await?
            {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let linked = self.state.config.mix_muc_mirror_enabled
                && self
                    .state
                    .mix_service()
                    .mix_muc_mirror_for_mix(channel.id)
                    .await?
                    .is_some();
            let mirror = super::mix_muc::conditional_mirror_discovery_form(
                self.state.config.mix_muc_mirror_enabled,
                linked,
                super::mix_muc::MirrorDirection::Muc,
                &muc_domain,
            );
            let query = super::mix::mix_channel_disco_info_payload(
                channel.name.as_deref().unwrap_or(&channel.localpart),
                channel.allow_user_message_retraction
                    || channel.administrator_retraction_rights != "nobody",
                channel.allow_private_messages,
                self.state
                    .config
                    .xmpp_extensions
                    .enabled(northstar_xep_0313::XEP_ID),
                &mirror,
            )?;
            return Ok(Action::Send(iq_result_from(id, from, &query)));
        }
        if target.localpart().is_none() && target.domainpart() == pubsub_domain {
            if let Some(node_name) = request.attribute("node") {
                if node_name == "serverinfo" {
                    let mut query = disco_info_query(Some("serverinfo"));
                    query.push_child(disco_identity("pubsub", "leaf", None));
                    for feature in [
                        "http://jabber.org/protocol/pubsub",
                        "http://jabber.org/protocol/pubsub#retrieve-items",
                        "urn:xmpp:serverinfo:0",
                    ] {
                        query.push_child(disco_feature(feature));
                    }
                    let mut form = result_form("http://jabber.org/protocol/pubsub#meta-data");
                    form.push_child(data_field("pubsub#access_model", ["open"]));
                    form.push_child(data_field("pubsub#max_items", ["1"]));
                    query.push_child(form);
                    return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
                }
                let Some(node) = self.state.pubsub_service().get_node(node_name).await? else {
                    return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
                };
                let requester = self.full_jid.as_deref().unwrap_or_default();
                if !super::pubsub::can_retrieve(&self.state, &node, requester).await? {
                    return Ok(Action::Send(iq_error_from(id, from, "forbidden")));
                }
                let mut query = disco_info_query(Some(node_name));
                query.push_child(disco_identity("pubsub", &node.node_type, None));
                query.push_child(disco_feature("http://jabber.org/protocol/pubsub"));
                if node.persist_items && node.node_type == "leaf" {
                    query.push_child(disco_feature(
                        "http://jabber.org/protocol/pubsub#persistent-items",
                    ));
                }
                if node.node_type == "leaf" || node.node_type == "collection" {
                    query.push_child(disco_feature(
                        "http://jabber.org/protocol/pubsub#retrieve-items",
                    ));
                }
                query.push_validated_fragment(
                    &super::pubsub::node_metadata_form(&self.state, &node).await?,
                )?;
                return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
            }
            let query = super::pubsub::service_disco_payload(&self.state);
            return Ok(Action::Send(iq_result_from(id, from, &query)));
        }
        if self.http_upload_enabled()
            && target.localpart().is_none()
            && target.domainpart() == upload_domain
        {
            if request.attribute("node").is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let upload_name = format!("{} File Upload", self.state.config.server_name);
            let mut query = disco_info_query(None);
            query.push_child(disco_identity("store", "file", Some(&upload_name)));
            query.push_child(disco_feature(northstar_xep_0363::NAMESPACE));
            let mut form = result_form(northstar_xep_0363::NAMESPACE);
            form.push_child(data_field(
                "max-file-size",
                [self.state.config.upload_max_bytes],
            ));
            query.push_child(form);
            return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
        }
        if target.localpart().is_none() && target.domainpart() == muc_domain {
            if request.attribute("node").is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let linked = self.state.config.mix_muc_mirror_enabled
                && self
                    .state
                    .mix_service()
                    .mix_muc_mirror_service_complete(&mix_domain)
                    .await?;
            let mirror = super::mix_muc::conditional_mirror_discovery_form(
                self.state.config.mix_muc_mirror_enabled,
                linked,
                super::mix_muc::MirrorDirection::Mix,
                &mix_domain,
            );
            let muc_name = format!("{} Group Chat", self.state.config.server_name);
            let mut query = disco_info_query(None);
            query.push_child(disco_identity("conference", "text", Some(&muc_name)));
            for feature in [
                DISCO_INFO_NS,
                DISCO_ITEMS_NS,
                "http://jabber.org/protocol/muc",
                "http://jabber.org/protocol/muc#unique",
                "http://jabber.org/protocol/muc#stable_id",
                "urn:xmpp:occupant-id:0",
                "urn:xmpp:message-moderate:1",
                "urn:xmpp:message-retract:1",
                "urn:xmpp:message-retract:1#tombstone",
                "urn:xmpp:sid:0",
            ] {
                query.push_child(disco_feature(feature));
            }
            if self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0199::XEP_ID)
            {
                query.push_child(disco_feature(northstar_xep_0199::NAMESPACE));
            }
            query.push_validated_fragment(&mirror)?;
            return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
        }
        if target.localpart().is_some() && target.domainpart() == muc_domain {
            let requested_node = request.attribute("node");
            if requested_node.is_some_and(|node| node != "x-roomuser-item") {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let Some(room) = self
                .state
                .muc_service()
                .room(target.localpart().expect("MUC room localpart checked"))
                .await?
            else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            // A newly-created room is deliberately undiscoverable until its
            // exact creating session accepts the defaults or submits a
            // configuration form.  Revealing it here would undermine the
            // XEP-0045 locked-room `item-not-found` boundary used for joins.
            if room.is_locked()
                && self.full_jid.as_deref() != room.configuration_owner_jid.as_deref()
            {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            if requested_node == Some("x-roomuser-item") {
                let mut query = disco_info_query(Some("x-roomuser-item"));
                if let Some(user) = self.authenticated.as_ref() {
                    if let Some(nick) = self
                        .state
                        .muc_service()
                        .local_reserved_nick(room.id, user.id)
                        .await?
                    {
                        query.push_child(disco_identity("conference", "text", Some(&nick)));
                    }
                }
                return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
            }
            let mut query = disco_info_query(None);
            query.push_child(disco_identity(
                "conference",
                "text",
                Some(room.title.as_deref().unwrap_or(&room.localpart)),
            ));
            for feature in [
                DISCO_INFO_NS,
                "http://jabber.org/protocol/muc",
                "http://jabber.org/protocol/muc#stable_id",
                "urn:xmpp:sid:0",
                if room.public {
                    "muc_public"
                } else {
                    "muc_hidden"
                },
                if room.persistent {
                    "muc_persistent"
                } else {
                    "muc_temporary"
                },
                if room.members_only {
                    "muc_membersonly"
                } else {
                    "muc_open"
                },
                if room.moderated {
                    "muc_moderated"
                } else {
                    "muc_unmoderated"
                },
                if room.non_anonymous {
                    "muc_nonanonymous"
                } else {
                    "muc_semianonymous"
                },
                if room.password_hash.is_some() {
                    "muc_passwordprotected"
                } else {
                    "muc_unsecured"
                },
            ] {
                query.push_child(disco_feature(feature));
            }
            if self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0199::XEP_ID)
            {
                query.push_child(disco_feature(
                    "http://jabber.org/protocol/muc#self-ping-optimization",
                ));
                query.push_child(disco_feature(northstar_xep_0199::NAMESPACE));
            }
            if room.allow_registration {
                query.push_child(disco_feature("jabber:iq:register"));
            }
            for feature in [
                "urn:xmpp:occupant-id:0",
                "urn:xmpp:message-moderate:1",
                "urn:xmpp:message-retract:1",
                "urn:xmpp:message-retract:1#tombstone",
                RSM_NS,
            ] {
                query.push_child(disco_feature(feature));
            }
            if self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0313::XEP_ID)
            {
                query.push_child(disco_feature(northstar_xep_0313::DISCO_FEATURE_MAM));
                query.push_child(disco_feature(
                    northstar_xep_0313::DISCO_FEATURE_MAM_EXTENDED,
                ));
            }
            let linked = self.state.config.mix_muc_mirror_enabled
                && self
                    .state
                    .mix_service()
                    .mix_muc_mirror_for_muc(room.id)
                    .await?
                    .is_some();
            query.push_validated_fragment(&super::mix_muc::conditional_mirror_discovery_form(
                self.state.config.mix_muc_mirror_enabled,
                linked,
                super::mix_muc::MirrorDirection::Mix,
                &mix_domain,
            ))?;
            return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
        }
        let is_server = target.localpart().is_none()
            && target.resourcepart().is_none()
            && target.domainpart() == self.state.config.domain;
        let is_account = target.localpart().is_some()
            && target.resourcepart().is_none()
            && target.domainpart() == self.state.config.domain;
        let owner = if is_account {
            let Some(owner) = self
                .state
                .pubsub_service()
                .find_enabled_user(target.localpart().expect("account localpart checked"))
                .await?
            else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            Some(owner)
        } else {
            None
        };
        if !is_server && !is_account {
            return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
        }

        if is_server {
            if let Some(node) = request.attribute("node") {
                if node == "http://jabber.org/protocol/commands"
                    || super::commands::is_command(node)
                {
                    if let Some(reply) = super::commands::disco_info(self, id, from, node).await? {
                        return Ok(Action::Send(reply));
                    } else {
                        return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
                    }
                }
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
        }

        if let (Some(owner), Some(node)) = (owner.as_ref(), request.attribute("node")) {
            let Some(config) = self.state.pubsub_service().pep_node(owner.id, node).await? else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            let requester = self
                .authenticated
                .as_ref()
                .map(|requester| format!("{}@{}", requester.username, self.state.config.domain));
            let allowed = if let Some(requester) = requester.as_deref() {
                super::pep::pep_access_allowed(
                    self.state.pubsub_service(),
                    owner,
                    &self.state.config.domain,
                    node,
                    requester,
                )
                .await?
            } else {
                config.access_model == "open"
            };
            if !allowed {
                return Ok(Action::Send(iq_error_from(id, from, "forbidden")));
            }
            let mut query = disco_info_query(Some(node));
            query.push_child(disco_identity("pubsub", "leaf", None));
            for feature in [
                "http://jabber.org/protocol/pubsub",
                "http://jabber.org/protocol/pubsub#retrieve-items",
            ] {
                query.push_child(disco_feature(feature));
            }
            query.push_child(disco_feature(&format!(
                "http://jabber.org/protocol/pubsub#access-{}",
                config.access_model
            )));
            if config.persist_items {
                query.push_child(disco_feature(
                    "http://jabber.org/protocol/pubsub#persistent-items",
                ));
            }
            return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
        }

        let mut features = if is_account {
            ACCOUNT_DISCO_FEATURES.to_vec()
        } else {
            SERVER_DISCO_FEATURES.to_vec()
        };
        if is_account
            && !self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0060::XEP_ID)
        {
            features.retain(|feature| !feature.starts_with("http://jabber.org/protocol/pubsub"));
        }
        if !self
            .state
            .config
            .xmpp_extensions
            .enabled(northstar_xep_0045::XEP_ID)
        {
            features.retain(|feature| *feature != northstar_xep_0045::XMLNS_MUC);
        }
        if !self.http_upload_enabled() {
            features.retain(|feature| *feature != northstar_xep_0363::NAMESPACE);
        }
        if is_account
            && self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0313::XEP_ID)
        {
            features.push(northstar_xep_0313::DISCO_FEATURE_MAM);
            features.push(northstar_xep_0313::DISCO_FEATURE_MAM_EXTENDED);
        }
        if is_account
            && self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0357::XEP_ID)
        {
            features.push(northstar_xep_0357::DISCO_FEATURE_PUSH);
        }
        if is_server {
            // XEP-0077 remains available to authenticated accounts for
            // password changes and cancellation even when new registration is
            // closed. XEP-0389 is currently a registration-only flow and is
            // advertised only while that flow can actually be selected.
            features.push("jabber:iq:register");
            if !self.state.registration_is_closed() {
                features.push(super::ibr::IBR2_NS);
            }
            if super::commands::available_to(self).await? {
                features.push("http://jabber.org/protocol/commands");
            }
            features.extend(self.state.config.xmpp_extensions.server_disco_features());
        }
        if is_server
            && self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0215::XEP_ID)
            && (self.state.config.stun_service.is_some()
                || self.state.config.turn_service.is_some())
        {
            features.push(northstar_xep_0215::NAMESPACE);
        }
        let mut query = disco_info_query(None);
        for identity in disco_entity_identities(is_account, &self.state.config.server_name) {
            query.push_child(identity);
        }
        for feature in features {
            query.push_child(disco_feature(feature));
        }

        if !is_account {
            let config = &self.state.config;
            let mut form = result_form("http://jabber.org/network/serverinfo");
            let mut add_addresses = |variable: &str, addrs: &[String]| {
                if !addrs.is_empty() {
                    form.push_child(data_field(variable, addrs));
                }
            };

            add_addresses("admin-addresses", &config.admin_addresses);
            add_addresses("abuse-addresses", &config.abuse_addresses);
            add_addresses("support-addresses", &config.support_addresses);
            add_addresses("feedback-addresses", &config.feedback_addresses);
            add_addresses("sales-addresses", &config.sales_addresses);
            add_addresses("security-addresses", &config.security_addresses);

            form.push_child(data_field(
                "serverinfo-pubsub-node",
                [format!("xmpp:{pubsub_domain}?;node=serverinfo")],
            ));
            query.push_child(form);
        }

        Ok(Action::Send(iq_result_from(id, from, &query.finish())))
    }

    pub(crate) async fn disco_items(
        &self,
        id: &str,
        to: Option<&str>,
        request: roxmltree::Node<'_, '_>,
    ) -> Result<Action> {
        let requested_from = to.unwrap_or(&self.state.config.domain);
        let Ok(target) = crate::jid::CanonicalJid::parse(requested_from) else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let from = target.to_string();
        let from = from.as_str();
        let disco_request = match parse_disco_items_query(request) {
            Ok(request) => request,
            Err(condition) => return Ok(Action::Send(iq_error_from(id, from, condition))),
        };
        let muc_domain = self.muc_domain();
        if target.domainpart() == muc_domain
            && !self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0045::XEP_ID)
        {
            return Ok(Action::Send(iq_error_from(id, from, "service-unavailable")));
        }
        let upload_domain = self.upload_domain();
        let pubsub_domain = self.pubsub_domain();
        let mix_domain = self.mix_domain();
        let requested_node = disco_request.node.as_deref();
        let mut query = disco_items_query(requested_node);
        if target.localpart().is_none()
            && target.resourcepart().is_none()
            && target.domainpart() == self.state.config.domain
        {
            if let Some(node) = requested_node {
                if node == "http://jabber.org/protocol/commands" {
                    if let Some(reply) = super::commands::disco_items(self, id, from, node).await? {
                        return Ok(Action::Send(reply));
                    } else {
                        return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
                    }
                }
            }
        }
        if target.localpart().is_none() && target.domainpart() == mix_domain {
            if requested_node.is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            if let Some(user) = self.authenticated.as_ref() {
                let requester = format!("{}@{}", user.username, self.state.config.domain);
                let Some(page) = self
                    .state
                    .mix_service()
                    .discoverable_mix_channel_page(
                        &mix_domain,
                        &requester,
                        disco_request.after.as_deref(),
                        disco_request.before.as_ref().map(|value| value.as_deref()),
                        disco_request.max,
                    )
                    .await?
                else {
                    return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
                };
                for channel in &page.channels {
                    query.push_child(disco_item(&channel.jid(), None, channel.name.as_deref()));
                }
                query.push_child(disco_rsm_result_element(
                    page.channels
                        .first()
                        .map(|channel| channel.localpart.as_str()),
                    page.channels
                        .last()
                        .map(|channel| channel.localpart.as_str()),
                    page.first_index,
                    page.total,
                ));
            }
        } else if target.localpart().is_some() && target.domainpart() == mix_domain {
            let Some(channel) = self
                .state
                .mix_service()
                .mix_channel(
                    &mix_domain,
                    target.localpart().expect("MIX channel localpart checked"),
                )
                .await?
            else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            if requested_node != Some("mix") {
                if requested_node.is_some() {
                    return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
                }
                return Ok(Action::Send(iq_result_from(id, from, &query.finish())));
            }
            let requester = self
                .authenticated
                .as_ref()
                .map(|user| format!("{}@{}", user.username, self.state.config.domain));
            let Some(requester_jid) = requester.as_deref() else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            if !self
                .state
                .mix_service()
                .mix_channel_discoverable_to(&channel, requester_jid)
                .await?
            {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let is_admin = if let Some(requester) = requester.as_deref() {
                self.state
                    .mix_service()
                    .mix_role(channel.id, requester)
                    .await?
                    .is_some()
            } else {
                false
            };
            for node in CORE_NODES {
                query.push_child(disco_item(from, Some(node), None));
            }
            if is_admin {
                for node in [NODE_CONFIG, NODE_ALLOWED, NODE_BANNED, NODE_JIDMAP] {
                    query.push_child(disco_item(from, Some(node), None));
                }
            }
            for node in [NODE_AVATAR_DATA, NODE_AVATAR_METADATA] {
                query.push_child(disco_item(from, Some(node), None));
            }
        } else if target.localpart().is_none() && target.domainpart() == muc_domain {
            if requested_node.is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let page = match self
                .state
                .muc_service()
                .public_room_page(
                    disco_request.after.as_deref(),
                    disco_request.before.as_ref().map(|value| value.as_deref()),
                    disco_request.max,
                )
                .await?
            {
                Some(page) => page,
                None => return Ok(Action::Send(iq_error_from(id, from, "item-not-found"))),
            };
            for room in &page.rooms {
                query.push_child(disco_item(
                    &format!("{}@{muc_domain}", room.localpart),
                    None,
                    Some(room.title.as_deref().unwrap_or(&room.localpart)),
                ));
            }
            query.push_child(disco_rsm_result_element(
                page.rooms.first().map(|room| room.localpart.as_str()),
                page.rooms.last().map(|room| room.localpart.as_str()),
                page.first_index,
                page.total,
            ));
        } else if target.localpart().is_some() && target.domainpart() == muc_domain {
            if requested_node.is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let Some(room) = self
                .state
                .muc_service()
                .room(target.localpart().expect("MUC room localpart checked"))
                .await?
            else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            if room.is_locked()
                && self.full_jid.as_deref() != room.configuration_owner_jid.as_deref()
            {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let room_jid = target.bare();
            let mut occupant_map = self
                .state
                .cluster
                .get_muc_occupants(&room_jid)
                .await?
                .into_values()
                .filter_map(|json| {
                    serde_json::from_str::<crate::state::SerializableMucOccupant>(&json).ok()
                })
                .map(|occupant| (occupant.nick.clone(), occupant))
                .collect::<std::collections::HashMap<_, _>>();
            for (_, occupant) in self.state.muc_occupants_for(&room_jid) {
                let occupant = crate::state::SerializableMucOccupant::from(&occupant);
                occupant_map.insert(occupant.nick.clone(), occupant);
            }
            let mut occupants = occupant_map.into_values().collect::<Vec<_>>();
            occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
            let cursor = disco_request.after.as_deref().or_else(|| {
                disco_request
                    .before
                    .as_ref()
                    .and_then(|value| value.as_deref())
            });
            if cursor.is_some_and(|cursor| !occupants.iter().any(|item| item.nick == cursor)) {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let total = occupants.len() as i64;
            let mut page = occupants
                .iter()
                .filter(|occupant| {
                    disco_request
                        .after
                        .as_deref()
                        .is_none_or(|after| occupant.nick.as_str() > after)
                        && disco_request
                            .before
                            .as_ref()
                            .and_then(|value| value.as_deref())
                            .is_none_or(|before| occupant.nick.as_str() < before)
                })
                .collect::<Vec<_>>();
            if disco_request.before.is_some() {
                page.reverse();
            }
            page.truncate(disco_request.max.clamp(0, 100) as usize);
            if disco_request.before.is_some() {
                page.reverse();
            }
            let first_index = page
                .first()
                .and_then(|first| occupants.iter().position(|item| item.nick == first.nick))
                .map_or(0, |index| index as i64);
            for occupant in &page {
                query.push_child(disco_item(
                    &format!("{room_jid}/{}", occupant.nick),
                    None,
                    None,
                ));
            }
            query.push_child(disco_rsm_result_element(
                page.first().map(|occupant| occupant.nick.as_str()),
                page.last().map(|occupant| occupant.nick.as_str()),
                first_index,
                total,
            ));
        } else if self.http_upload_enabled()
            && target.localpart().is_none()
            && target.domainpart() == upload_domain
        {
            if requested_node.is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
        } else if target.localpart().is_none() && target.domainpart() == pubsub_domain {
            let requester = self.full_jid.as_deref().unwrap_or_default();
            let reply =
                super::pubsub::federated_disco_items(&self.state, requester, request).await?;
            return Ok(Action::Send(match reply {
                super::pubsub::PubSubReply::Result(payload) => iq_result_from(id, from, &payload),
                error => iq_error_from(
                    id,
                    from,
                    super::pubsub::error_condition(&error).unwrap_or("undefined-condition"),
                ),
            }));
        } else if target.localpart().is_none()
            && target.resourcepart().is_none()
            && target.domainpart() == self.state.config.domain
        {
            if requested_node.is_some() {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            }
            let mut services = vec![
                (muc_domain.as_str(), "Group Chat"),
                (pubsub_domain.as_str(), "PubSub Service"),
                (mix_domain.as_str(), "MIX Service"),
            ];
            if self.http_upload_enabled() {
                services.push((upload_domain.as_str(), "File Upload"));
            }
            for (jid, suffix) in services {
                query.push_child(disco_item(
                    jid,
                    None,
                    Some(&format!("{} {suffix}", self.state.config.server_name)),
                ));
            }
            for credential in &self.state.config.components {
                for domain in &credential.allowed_domains {
                    query.push_child(disco_item(
                        domain,
                        None,
                        Some(&format!("External Component ({domain})")),
                    ));
                }
            }
        } else if target.localpart().is_some()
            && target.resourcepart().is_none()
            && target.domainpart() == self.state.config.domain
        {
            let Some(owner) = self
                .state
                .pubsub_service()
                .find_enabled_user(target.localpart().expect("account localpart checked"))
                .await?
            else {
                return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
            };
            if let Some(node) = requested_node {
                let Some(config) = self.state.pubsub_service().pep_node(owner.id, node).await?
                else {
                    return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
                };
                let requester = self.authenticated.as_ref().map(|requester| {
                    format!("{}@{}", requester.username, self.state.config.domain)
                });
                let allowed = if let Some(requester) = requester.as_deref() {
                    super::pep::pep_access_allowed(
                        self.state.pubsub_service(),
                        &owner,
                        &self.state.config.domain,
                        node,
                        requester,
                    )
                    .await?
                } else {
                    config.access_model == "open"
                };
                if !allowed {
                    return Ok(Action::Send(iq_error_from(id, from, "forbidden")));
                }
            } else {
                let requester = self.authenticated.as_ref().map(|requester| {
                    format!("{}@{}", requester.username, self.state.config.domain)
                });
                for node in self.state.pubsub_service().pep_nodes(owner.id).await? {
                    let allowed = if let Some(requester) = requester.as_deref() {
                        super::pep::pep_access_allowed(
                            self.state.pubsub_service(),
                            &owner,
                            &self.state.config.domain,
                            &node,
                            requester,
                        )
                        .await?
                    } else {
                        self.state
                            .pubsub_service()
                            .pep_node(owner.id, &node)
                            .await?
                            .is_some_and(|config| config.access_model == "open")
                    };
                    if allowed {
                        query.push_child(pep_disco_item(from, &node));
                    }
                }
            }
        } else {
            return Ok(Action::Send(iq_error_from(id, from, "item-not-found")));
        }
        Ok(Action::Send(iq_result_from(id, from, &query.finish())))
    }
}

fn valid_disco_query(request: roxmltree::Node<'_, '_>) -> bool {
    request
        .attributes()
        .all(|attribute| attribute.name() == "node")
        && request
            .attribute("node")
            .is_none_or(|node| !node.is_empty() && node.len() <= 1_024)
        && !request.children().any(|child| child.is_element())
        && request.text().is_none_or(|text| text.trim().is_empty())
}

fn disco_entity_identities(is_account: bool, server_name: &str) -> Vec<XmlElement> {
    if is_account {
        vec![
            disco_identity("account", "registered", None),
            disco_identity("pubsub", "pep", Some("Personal Eventing Protocol")),
        ]
    } else {
        vec![disco_identity("server", "im", Some(server_name))]
    }
}

fn pep_disco_item(account: &str, node: &str) -> XmlElement {
    disco_item(account, Some(node), None)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiscoItemsRequest {
    pub(crate) node: Option<String>,
    pub(crate) max: i64,
    pub(crate) after: Option<String>,
    /// `Some(None)` represents an empty `<before/>`, i.e. the last page.
    pub(crate) before: Option<Option<String>>,
}

pub(crate) fn parse_disco_items_query(
    request: roxmltree::Node<'_, '_>,
) -> std::result::Result<DiscoItemsRequest, &'static str> {
    if !request
        .attributes()
        .all(|attribute| attribute.namespace().is_none() && attribute.name() == "node")
        || request
            .attribute("node")
            .is_some_and(|node| node.is_empty() || node.len() > 1_024)
        || request
            .children()
            .filter(|child| child.is_text())
            .any(|child| !child.text().unwrap_or_default().trim().is_empty())
    {
        return Err("bad-request");
    }
    let elements = request
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if elements.len() > 1 {
        return Err("bad-request");
    }
    let mut parsed = DiscoItemsRequest {
        node: request.attribute("node").map(str::to_owned),
        max: 100,
        after: None,
        before: None,
    };
    let Some(set) = elements.first().copied() else {
        return Ok(parsed);
    };
    if set.tag_name().name() != "set"
        || set.tag_name().namespace() != Some("http://jabber.org/protocol/rsm")
        || set.attributes().len() != 0
        || set
            .children()
            .filter(|child| child.is_text())
            .any(|child| !child.text().unwrap_or_default().trim().is_empty())
    {
        return Err("bad-request");
    }
    let mut seen = std::collections::HashSet::new();
    for child in set.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some("http://jabber.org/protocol/rsm")
            || !matches!(child.tag_name().name(), "max" | "after" | "before")
            || !seen.insert(child.tag_name().name())
            || child.attributes().len() != 0
            || child.children().any(|nested| nested.is_element())
        {
            return Err("bad-request");
        }
        let value = child.text().unwrap_or_default();
        match child.tag_name().name() {
            "max" => {
                let max = value.parse::<i64>().map_err(|_| "bad-request")?;
                if max < 0 {
                    return Err("bad-request");
                }
                parsed.max = max.min(100);
            }
            "after" => {
                if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
                    return Err("bad-request");
                }
                parsed.after = Some(value.to_owned());
            }
            "before" => {
                if value.len() > 1_024 || value.chars().any(char::is_control) {
                    return Err("bad-request");
                }
                parsed.before = Some((!value.is_empty()).then(|| value.to_owned()));
            }
            _ => unreachable!(),
        }
    }
    if parsed.after.is_some() && parsed.before.is_some() {
        return Err("bad-request");
    }
    Ok(parsed)
}

pub(crate) fn disco_rsm_result(
    first: Option<&str>,
    last: Option<&str>,
    first_index: i64,
    total: i64,
) -> String {
    disco_rsm_result_element(first, last, first_index, total).finish()
}

fn disco_rsm_result_element(
    first: Option<&str>,
    last: Option<&str>,
    first_index: i64,
    total: i64,
) -> XmlElement {
    let mut set = XmlElement::namespaced("set", RSM_NS);
    if let (Some(first), Some(last)) = (first, last) {
        set.push_child(
            XmlElement::new("first")
                .attr("index", first_index)
                .text(first.to_owned()),
        );
        set.push_child(XmlElement::new("last").text(last.to_owned()));
    }
    set.push_child(XmlElement::new("count").text(total.to_string()));
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disco_queries_are_empty_and_bounded() {
        for xml in [
            "<query xmlns='http://jabber.org/protocol/disco#info'/>",
            "<query xmlns='http://jabber.org/protocol/disco#info' node='caps#1'/>",
        ] {
            let doc = roxmltree::Document::parse(xml).unwrap();
            assert!(valid_disco_query(doc.root_element()));
        }
        for xml in [
            "<query xmlns='http://jabber.org/protocol/disco#info' node=''/>",
            "<query xmlns='http://jabber.org/protocol/disco#info' extra='x'/>",
            "<query xmlns='http://jabber.org/protocol/disco#info'><item/></query>",
        ] {
            let doc = roxmltree::Document::parse(xml).unwrap();
            assert!(!valid_disco_query(doc.root_element()));
        }
    }

    #[test]
    fn pep_identity_belongs_to_the_account_not_the_server_root() {
        let mut account = disco_info_query(None);
        for identity in disco_entity_identities(true, "Northstar") {
            account.push_child(identity);
        }
        let account = account.finish();
        assert!(account.contains("category='pubsub' type='pep'"));
        assert!(account.contains("category='account' type='registered'"));

        let mut server = disco_info_query(None);
        for identity in disco_entity_identities(false, "Northstar") {
            server.push_child(identity);
        }
        let server = server.finish();
        assert!(server.contains("category='server' type='im'"));
        assert!(!server.contains("type='pep'"));
    }

    #[test]
    fn pep_account_info_and_item_discovery_have_distinct_entities() {
        assert!(ACCOUNT_DISCO_FEATURES.contains(&"http://jabber.org/protocol/pubsub#pep"));
        assert!(ACCOUNT_DISCO_FEATURES.contains(&"http://jabber.org/protocol/disco#items"));
        assert!(ACCOUNT_DISCO_FEATURES
            .iter()
            .all(|feature| !feature.ends_with("+notify")));
        assert!(!ACCOUNT_DISCO_FEATURES.contains(&"urn:xmpp:omemo:2:devices"));

        let item =
            pep_disco_item("alice@example.test", "urn:xmpp:omemo:2:devices&amp;more").finish();
        assert_eq!(
            item,
            "<item jid='alice@example.test' node='urn:xmpp:omemo:2:devices&amp;amp;more'/>"
        );
        assert!(!item.contains("+notify"));
    }

    #[test]
    fn disco_items_and_rsm_round_trip_adversarial_runtime_values() {
        let requested_node = "urn:例:'\"<&>🙂";
        let jid = "room'\"<&>@example.test";
        let item_node = "urn:item:'\"<&>日本語";
        let name = "Visible ' \" < & > name";
        let first = "first'\"<&>🙂";
        let last = "last'\"<&>日本語";
        let mut query = disco_items_query(Some(requested_node));
        query.push_child(disco_item(jid, Some(item_node), Some(name)));
        query.push_child(disco_rsm_result_element(Some(first), Some(last), 7, 19));
        let xml = query.finish();
        let document = roxmltree::Document::parse(&xml).unwrap();
        let query = document.root_element();
        assert_eq!(query.tag_name().namespace(), Some(DISCO_ITEMS_NS));
        assert_eq!(query.attribute("node"), Some(requested_node));

        let item = query
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "item")
            .unwrap();
        assert_eq!(item.tag_name().namespace(), Some(DISCO_ITEMS_NS));
        assert_eq!(item.attribute("jid"), Some(jid));
        assert_eq!(item.attribute("node"), Some(item_node));
        assert_eq!(item.attribute("name"), Some(name));

        let set = query
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "set")
            .unwrap();
        assert_eq!(set.tag_name().namespace(), Some(RSM_NS));
        let first_node = set
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "first")
            .unwrap();
        let last_node = set
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "last")
            .unwrap();
        assert_eq!(first_node.attribute("index"), Some("7"));
        assert_eq!(first_node.text(), Some(first));
        assert_eq!(last_node.text(), Some(last));
    }

    #[test]
    fn server_discovery_claims_service_semantics_not_client_rendering() {
        for required in [
            "urn:xmpp:message-retract:1",
            "urn:xmpp:message-retract:1#tombstone",
            "urn:xmpp:receipts",
            "msgoffline",
        ] {
            assert!(
                SERVER_DISCO_FEATURES.contains(&required),
                "missing {required}"
            );
        }

        // These features are advertised by the endpoint that renders or
        // generates them (normally through XEP-0115 caps). Northstar validates,
        // routes, carbons and archives their payloads without impersonating a
        // user's client at the server root.
        for client_capability in [
            "http://jabber.org/protocol/chatstates",
            "urn:xmpp:message-correct:0",
            "urn:xmpp:chat-markers:0",
            "urn:xmpp:eme:0",
            "urn:xmpp:fallback:0",
            "urn:xmpp:reactions:0",
            "urn:xmpp:reply:0",
            "urn:xmpp:sce:1",
            "urn:xmpp:stickers:0",
            "urn:xmpp:tm:1",
            "urn:xmpp:atm:1",
            "urn:xmpp:omemo:2",
        ] {
            assert!(
                !SERVER_DISCO_FEATURES.contains(&client_capability),
                "server root must not claim client capability {client_capability}"
            );
        }
    }
}
