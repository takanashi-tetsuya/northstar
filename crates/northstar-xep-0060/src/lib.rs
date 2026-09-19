#![forbid(unsafe_code)]

//! Capability-free XEP-0060 Publish-Subscribe wire support for Northstar.
//!
//! This crate provides:
//! - Pure wire models for all XEP-0060 entity, owner, and event operations
//! - Deterministic XML parsing and safe XML builders
//! - Strict configuration normalization and constraint enforcement
//! - Pure authorization decision inputs and outputs without database or state coupling
//! - Result Set Management (XEP-0059) request validation and response formatting

pub mod auth;
pub mod builder;
pub mod config;
pub mod constants;
pub mod error;
pub mod models;
pub mod parser;
pub mod rsm;
pub mod wire;
pub mod xml;

// Re-exports of core constants and descriptors
pub use constants::{
    DESCRIPTOR, MAX_ATOM_BODY_BYTES, MAX_CHILDREN_NODES, MAX_CHILDREN_PER_CONFIG,
    MAX_COLLECTIONS_PER_CONFIG, MAX_COLLECTION_ASSOCIATION_WHITELIST, MAX_DESCRIPTION_BYTES,
    MAX_DIGEST_FREQUENCY_MS, MAX_ITEM_ID_BYTES, MAX_ITEM_XML_BYTES, MAX_JID_BYTES,
    MAX_NODE_ID_BYTES, MAX_PAYLOAD_TYPE_BYTES, MAX_PUBLISH_ITEMS, MAX_PUBLISH_XML_BYTES,
    MAX_REDIRECT_URI_BYTES, MAX_RSM_PAGE_SIZE, MAX_SUBSCRIPTIONS_PER_REQUEST,
    MAX_SUBSCRIPTION_LEASE_DAYS, MAX_TITLE_BYTES, MIN_DIGEST_FREQUENCY_MS, NODE_CONFIG_FORM,
    NODE_METADATA_FORM, NS_ATOM, NS_DATA, NS_DELAY, NS_DISCO_INFO, NS_DISCO_ITEMS, NS_PUBSUB,
    NS_PUBSUB_ERRORS, NS_PUBSUB_EVENT, NS_PUBSUB_OWNER, NS_RSM, NS_SHIM, NS_STANZAS,
    PUBLISH_OPTIONS_FORM, SERVICE_FEATURES, SUBSCRIBE_AUTH_FORM, SUBSCRIBE_OPTIONS_FORM, XEP_ID,
};

// Re-exports of errors and stanza mappings
pub use error::{
    build_iq_error, build_s2s_iq_error, invalid_subscription_options, node_config_parse_error,
    stanza_error_type_for_condition, PubSubError, StanzaErrorType,
};

// Re-exports of models and validation
pub use models::{
    all_show_strings, all_show_values, bool_text, parse_bool, required_node_id, valid_bare_jid,
    valid_item_id, valid_language_tag, valid_node_id, valid_redirect_uri, AccessModel, Affiliation,
    ChildrenAssociationPolicy, CollectionAction, NodeType, PublishModel, SendLastPublishedItem,
    ShowValue, SubscriptionState, SubscriptionType,
};

// Re-exports of config and options
pub use config::{
    build_node_config_form, build_node_metadata_form, build_subscription_options_form,
    config_equivalent, data_form_fields, first_field, has_duplicate_fields, parse_node_config,
    parse_node_config_form, parse_publish_options, parse_subscription_options,
    supports_include_body, NodeConfig, SubscriptionOptions,
};

// Re-exports of pure authorization helpers
pub use auth::{
    can_publish_pure, can_retrieve_pure, item_retrieval_access,
    pubsub_policy_suppression_is_terminal, subscription_initial_state,
};

// Re-exports of RSM
pub use rsm::{
    build_rsm_set, build_rsm_set_element, paginate_items, parse_rsm_element, RsmRequest,
    RsmResponse,
};

// Re-exports of wire structs
pub use wire::{
    AffiliationEntryWire, CreateNodeRequest, CreateNodeResponse, DiscoItemWire, EventItemWire,
    EventPayload, GetAffiliationsRequest, GetAffiliationsResponse, GetDefaultOptionsRequest,
    GetDefaultOptionsResponse, GetItemsRequest, GetItemsResponse, GetOptionsRequest,
    GetOptionsResponse, GetSubscriptionsRequest, GetSubscriptionsResponse, ItemEntryWire,
    OwnerAffiliationChangeWire, OwnerAffiliationEntryWire, OwnerCollectionRequest,
    OwnerDeleteNodeRequest, OwnerGetAffiliationsRequest, OwnerGetAffiliationsResponse,
    OwnerGetConfigureRequest, OwnerGetConfigureResponse, OwnerGetDefaultRequest,
    OwnerGetDefaultResponse, OwnerGetSubscriptionsRequest, OwnerGetSubscriptionsResponse,
    OwnerPurgeNodeRequest, OwnerSetAffiliationsRequest, OwnerSetConfigureRequest,
    OwnerSetSubscriptionsRequest, OwnerSubscriptionChangeWire, OwnerSubscriptionEntryWire,
    PublishItemWire, PublishRequest, PublishResponse, RetractRequest, SetOptionsRequest,
    SubscribeRequest, SubscribeResponse, SubscriptionAuthResponse, SubscriptionEntryWire,
    UnsubscribeRequest, UnsubscribeResponse,
};

// Re-exports of parsers and normalizers
pub use parser::{
    extract_atom_event_body, parse_create_operation, parse_get_items_operation,
    parse_publish_operation, parse_pubsub_envelope, parse_retract_operation,
    parse_subscribe_operation, parse_subscription_auth_response, parse_unsubscribe_operation,
    serialize_pubsub_item, serialized_item_payload_matches_type, truncate_utf8_to_bytes,
    EnvelopeNamespace, ParsedPubSubEnvelope,
};

// Re-exports of builders
pub use builder::{
    build_affiliations_response, build_create_response, build_default_options_response,
    build_disco_items, build_event_configuration, build_event_delete, build_event_items,
    build_event_purge, build_iq_result, build_items_response, build_node_disco_info,
    build_options_response, build_owner_affiliations_response, build_owner_configure_response,
    build_owner_default_response, build_owner_subscriptions_response, build_publish_response,
    build_s2s_iq_result, build_service_disco_info, build_subscribe_response,
    build_subscription_auth_request_form, build_subscription_element,
    build_subscription_event_children, build_subscriptions_response, build_unsubscribe_response,
};

// Re-exports of XML primitives
pub use xml::{attr_escape, escape_xml_attr, escape_xml_text, xml_escape, XmlElement};

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_xep_core::XepId;
    use roxmltree::Document;

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Publish-Subscribe");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30), XepId::new(59)]);
        assert_eq!(DESCRIPTOR.routes.len(), 4);
    }

    #[test]
    fn full_create_publish_retract_round_trip() {
        // 1. Create request with config form
        let create_xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='principle'/><configure><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field><field var='pubsub#access_model'><value>authorize</value></field><field var='pubsub#max_items'><value>50</value></field></x></configure></pubsub>";
        let doc = Document::parse(create_xml).unwrap();
        let envelope = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
        let create_req = parse_create_operation(&envelope.operations).unwrap();
        assert_eq!(create_req.node.as_deref(), Some("principle"));
        let config = create_req.configure.unwrap();
        assert_eq!(config.access_model, AccessModel::Authorize);
        assert_eq!(config.max_items, 50);

        // Build create response
        let create_resp = build_create_response("principle");
        assert_eq!(
            create_resp,
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='principle'/></pubsub>"
        );

        // 2. Publish request
        let publish_xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='principle'><item id='item-1'><entry xmlns='http://www.w3.org/2005/Atom'><title>Update 1</title></entry></item></publish></pubsub>";
        let doc = Document::parse(publish_xml).unwrap();
        let envelope = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
        let pub_req = parse_publish_operation(&envelope.operations).unwrap();
        assert_eq!(pub_req.node, "principle");
        assert_eq!(pub_req.items.len(), 1);
        assert_eq!(pub_req.items[0].id, "item-1");

        // Build publish response
        let pub_resp = build_publish_response("principle", &["item-1"]);
        assert_eq!(pub_resp, "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='principle'><item id='item-1'/></publish></pubsub>");

        // 3. Retract request
        let retract_xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='principle' notify='true'><item id='item-1'/></retract></pubsub>";
        let doc = Document::parse(retract_xml).unwrap();
        let envelope = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
        let retract_req = parse_retract_operation(&envelope.operations).unwrap();
        assert_eq!(retract_req.node, "principle");
        assert_eq!(retract_req.item_ids, vec!["item-1"]);
        assert!(retract_req.notify);
    }

    #[test]
    fn full_subscribe_and_auth_round_trip() {
        let sub_xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><subscribe node='principle' jid='juliet@capulet.lit'/></pubsub>";
        let doc = Document::parse(sub_xml).unwrap();
        let envelope = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
        let sub_req =
            parse_subscribe_operation(&envelope.operations, NodeType::Leaf, false).unwrap();
        assert_eq!(sub_req.node, "principle");
        assert_eq!(sub_req.jid, "juliet@capulet.lit");

        // Initial state on authorize access model
        let initial_state = subscription_initial_state(AccessModel::Authorize, None).unwrap();
        assert_eq!(initial_state, SubscriptionState::Pending);

        // Build response
        let resp = build_subscribe_response(
            "principle",
            "juliet@capulet.lit",
            SubscriptionState::Pending,
            Some("sub-xyz"),
            None,
        );
        assert!(resp.contains("subscription='pending'"));
        assert!(resp.contains("subid='sub-xyz'"));

        // Build auth request form
        let auth_form =
            build_subscription_auth_request_form("principle", "juliet@capulet.lit", "sub-xyz");
        assert!(auth_form.contains("pubsub#subscribe_authorization"));

        // Owner responds with approval
        let auth_response_xml = "<message from='owner@capulet.lit' to='pubsub.capulet.lit'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#subscribe_authorization</value></field><field var='pubsub#node'><value>principle</value></field><field var='pubsub#subscriber_jid'><value>juliet@capulet.lit</value></field><field var='pubsub#subid'><value>sub-xyz</value></field><field var='pubsub#allow'><value>1</value></field></x></message>";
        let doc = Document::parse(auth_response_xml).unwrap();
        let auth_resp = parse_subscription_auth_response(doc.root_element())
            .unwrap()
            .unwrap();
        assert_eq!(auth_resp.node, "principle");
        assert_eq!(auth_resp.subscriber_jid, "juliet@capulet.lit");
        assert_eq!(auth_resp.subid.as_deref(), Some("sub-xyz"));
        assert!(auth_resp.allow);
    }
}
