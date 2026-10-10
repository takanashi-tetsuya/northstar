//! Tests for federated MUC.

use super::owner::{parse_federated_owner_action, FederatedOwnerAction};
use super::*;
use std::sync::Mutex;

struct JoinProjectionFaultPort {
    calls: Mutex<Vec<&'static str>>,
    fail_join: bool,
    fail_registration: bool,
    fail_presence: bool,
}

impl JoinProjectionFaultPort {
    fn new(fail_join: bool, fail_registration: bool, fail_presence: bool) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail_join,
            fail_registration,
            fail_presence,
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl FederatedJoinProjectionPort for JoinProjectionFaultPort {
    async fn join_room(&self, room_jid: &str) -> Result<()> {
        assert_eq!(room_jid, "room@conference.example.test");
        self.calls.lock().unwrap().push("join");
        if self.fail_join {
            anyhow::bail!("injected room-index failure");
        }
        Ok(())
    }

    async fn register_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        exact_occupant_json: &str,
    ) -> Result<bool> {
        assert_eq!(room_jid, "room@conference.example.test");
        assert_eq!(nick, "RemoteBob");
        assert!(exact_occupant_json.contains("remote.test/Phone"));
        self.calls.lock().unwrap().push("register");
        if self.fail_registration {
            anyhow::bail!("injected exact-occupant failure");
        }
        Ok(true)
    }

    async fn publish_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        assert_eq!(room_jid, "room@conference.example.test");
        assert_eq!(occupant.nick, "RemoteBob");
        assert!(created);
        assert_eq!(id, Some("remote-join"));
        self.calls.lock().unwrap().push("presence");
        if self.fail_presence {
            anyhow::bail!("injected legacy presence failure");
        }
        Ok(())
    }
}

fn join_projection_occupant() -> SerializableMucOccupant {
    SerializableMucOccupant {
        full_jid: "bob@remote.test/Phone".to_owned(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: "RemoteBob".to_owned(),
        affiliation: "none".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: true,
        occupant_id: "occupant".to_owned(),
        cluster_epoch: uuid::Uuid::new_v4(),
        connection_id: uuid::Uuid::new_v4(),
        federated_domain: Some("remote.test".to_owned()),
        sm_session_id: None,
        payload: String::new(),
    }
}

async fn run_join_projection_fault(
    port: &JoinProjectionFaultPort,
    committed: bool,
) -> Result<FederatedJoinProjectionResult> {
    let occupant = join_projection_occupant();
    let json = serde_json::to_string(&occupant)?;
    project_federated_join(
        port,
        FederatedJoinProjectionRequest {
            committed,
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            exact_occupant_json: &json,
            occupant: &occupant,
            created: true,
            id: Some("remote-join"),
        },
    )
    .await
}

#[tokio::test]
async fn committed_federated_join_attempts_exact_repair_after_redis_room_failure() {
    let port = JoinProjectionFaultPort::new(true, false, false);
    let FederatedJoinProjectionResult::Committed {
        room_join,
        registration,
    } = run_join_projection_fault(&port, true).await.unwrap()
    else {
        panic!("expected committed join projection");
    };
    assert!(room_join.is_err());
    assert!(matches!(registration, Ok(true)));
    assert_eq!(port.calls(), ["join", "register"]);

    let port = JoinProjectionFaultPort::new(true, true, false);
    let FederatedJoinProjectionResult::Committed {
        room_join,
        registration,
    } = run_join_projection_fault(&port, true).await.unwrap()
    else {
        panic!("expected committed join projection");
    };
    assert!(room_join.is_err());
    assert!(registration.is_err());
    assert_eq!(port.calls(), ["join", "register"]);
}

#[tokio::test]
async fn legacy_federated_join_keeps_strict_projection_order() {
    let port = JoinProjectionFaultPort::new(false, false, false);
    assert!(matches!(
        run_join_projection_fault(&port, false).await.unwrap(),
        FederatedJoinProjectionResult::Legacy
    ));
    assert_eq!(port.calls(), ["join", "register", "presence"]);

    let port = JoinProjectionFaultPort::new(true, false, false);
    assert!(run_join_projection_fault(&port, false).await.is_err());
    assert_eq!(port.calls(), ["join"]);

    let port = JoinProjectionFaultPort::new(false, true, false);
    assert!(run_join_projection_fault(&port, false).await.is_err());
    assert_eq!(port.calls(), ["join", "register"]);

    let port = JoinProjectionFaultPort::new(false, false, true);
    assert!(run_join_projection_fault(&port, false).await.is_err());
    assert_eq!(port.calls(), ["join", "register", "presence"]);
}

#[test]
fn federated_affiliation_lists_follow_shared_muc_permissions() {
    for requester in ["owner", "admin"] {
        for requested in ["owner", "admin", "member", "outcast"] {
            assert!(can_retrieve_affiliations(
                requester, requested, false, false
            ));
        }
        assert!(!can_retrieve_affiliations(requester, "none", true, true));
    }
    for requested in ["owner", "admin", "member"] {
        assert!(can_retrieve_affiliations("member", requested, true, true));
    }
    for (requester, requested, members_only, non_anonymous) in [
        ("member", "outcast", true, true),
        ("member", "member", false, true),
        ("member", "member", true, false),
        ("none", "member", true, true),
        ("invalid", "member", true, true),
    ] {
        assert!(!can_retrieve_affiliations(
            requester,
            requested,
            members_only,
            non_anonymous
        ));
    }
}

fn extension_runtime() -> crate::xmpp::extensions::ExtensionRuntime {
    crate::xmpp::extensions::ExtensionRuntime::resolve(
        crate::xmpp::extensions::ExtensionSwitches::default(),
    )
}

#[test]
fn federated_mediated_invites_preserve_original_carbon_eligibility() {
    let invite = "<message from='alice@remote.test/Phone' to='room@conference.example.test'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x></message>";
    let document = roxmltree::Document::parse(invite).unwrap();
    let extensions = extension_runtime();
    assert!(
        FederatedMessageRequest::from_node(
            document.root_element(),
            invite,
            validate_routed_message(document.root_element(), &extensions),
        )
        .carbon_eligible
    );

    let private = "<message from='alice@remote.test/Phone' to='room@conference.example.test'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x><private xmlns='urn:xmpp:carbons:2'/></message>";
    let document = roxmltree::Document::parse(private).unwrap();
    assert!(
        !FederatedMessageRequest::from_node(
            document.root_element(),
            private,
            validate_routed_message(document.root_element(), &extensions),
        )
        .carbon_eligible
    );

    // XEP-0334 explicitly says no-copy never overrides RFC 6121 handling
    // for a bare destination. The original mediated invitation is sent
    // to the bare room JID, so this invalid sender hint is ignored.
    let bare_no_copy = "<message from='alice@remote.test/Phone' to='room@conference.example.test'><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x><no-copy xmlns='urn:xmpp:hints'/></message>";
    let document = roxmltree::Document::parse(bare_no_copy).unwrap();
    assert!(
        FederatedMessageRequest::from_node(
            document.root_element(),
            bare_no_copy,
            validate_routed_message(document.root_element(), &extensions),
        )
        .carbon_eligible
    );
}

fn remote_occupant(domain: &str) -> MucOccupant {
    MucOccupant {
        full_jid: format!("alice@{domain}/phone"),
        room_jid: "room@conference.example.test".to_owned(),
        nick: "Alice".to_owned(),
        endpoint: MucOccupantEndpoint::Federated {
            authenticated_domain: domain.to_owned(),
            connection_id: uuid::Uuid::nil(),
        },
        affiliation: "member".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: false,
        occupant_id: "opaque".to_owned(),
        cluster_epoch: uuid::Uuid::new_v4(),
        connection_id: uuid::Uuid::nil(),
        sm_session_id: None,
        payload: String::new(),
    }
}

fn room(non_anonymous: bool) -> MucRoom {
    MucRoom {
        id: uuid::Uuid::nil(),
        room_epoch: uuid::Uuid::nil(),
        config_version: 1,
        localpart: "room".to_owned(),
        title: None,
        description: None,
        persistent: true,
        members_only: false,
        public: true,
        moderated: false,
        non_anonymous,
        max_occupants: 100,
        subject: None,
        subject_changed_at: None,
        allow_subject_change: false,
        allow_invites: true,
        allow_private_messages: true,
        logging_enabled: true,
        allow_registration: true,
        password_hash: None,
        occupant_id_secret: vec![7_u8; 32],
        configuration_owner_jid: None,
        configuration_expires_at: None,
    }
}

#[test]
fn authenticated_domain_must_own_the_full_remote_jid() {
    assert!(authenticated_remote_actor(
        "remote.test",
        "alice@remote.test/phone"
    ));
    assert!(authenticated_remote_actor(
        "REMOTE.TEST",
        "alice@remote.test/phone"
    ));
    assert!(authenticated_remote_actor(
        "B\u{fc}CHER.Example.",
        "Alice@bücher.example/Phone"
    ));
    for forged in [
        "alice@evil.test/phone",
        "alice@remote.test",
        "alice@remote.test/",
        "remote.test",
        "remote.test/gateway",
        "alice@remote.test/\u{0007}",
        "alice@@remote.test/phone",
    ] {
        assert!(!authenticated_remote_actor("remote.test", forged));
    }
}

#[test]
fn duplicate_remote_join_is_idempotent_only_for_the_same_actor_nick_and_domain() {
    let occupant = remote_occupant("remote.test");
    assert!(is_idempotent_remote_join(
        &occupant,
        "REMOTE.TEST",
        "alice@remote.test/phone",
        "Alice",
    ));
    assert!(!is_idempotent_remote_join(
        &occupant,
        "remote.test",
        "alice@remote.test/phone",
        "alice",
    ));
    assert!(!is_idempotent_remote_join(
        &occupant,
        "evil.test",
        "alice@remote.test/phone",
        "Alice",
    ));
    assert!(!is_idempotent_remote_join(
        &occupant,
        "remote.test",
        "alice@remote.test/laptop",
        "Alice",
    ));
    assert!(!is_idempotent_remote_join(
        &occupant,
        "remote.test",
        "alice@remote.test/Phone",
        "Alice",
    ));
    assert!(!is_idempotent_remote_join(
        &occupant,
        "remote.test",
        "alice@remote.test/phone",
        "Alice2",
    ));
}

#[test]
fn federated_owner_actions_are_strict_and_support_instant_cancel_and_destroy() {
    let room = room(true);
    let instant = "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/></query></iq>";
    let FederatedOwnerAction::Configure(config) =
        parse_federated_owner_action(instant, &room).unwrap()
    else {
        panic!("empty submit must select instant-room defaults")
    };
    assert_eq!(config.title.as_deref(), Some("room"));
    assert!(config.public);
    assert!(config.non_anonymous);

    let cancel = "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='cancel'/></query></iq>";
    assert!(matches!(
        parse_federated_owner_action(cancel, &room),
        Ok(FederatedOwnerAction::Cancel)
    ));
    let destroy = "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#owner'><destroy jid='replacement@conference.example.test'><reason>closed</reason></destroy></query></iq>";
    assert!(matches!(
        parse_federated_owner_action(destroy, &room),
        Ok(FederatedOwnerAction::Destroy { alternate: Some(jid), reason: Some(reason) })
            if jid == "replacement@conference.example.test" && reason == "closed"
    ));
    for invalid in [
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'/></iq>",
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='submit'/><destroy/></query></iq>",
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'><destroy><unknown/></destroy></query></iq>",
            "<iq><query xmlns='http://jabber.org/protocol/muc#owner'><x xmlns='jabber:x:data' type='form'/></query></iq>",
        ] {
            assert!(parse_federated_owner_action(invalid, &room).is_err());
        }
}

#[test]
fn semi_anonymous_history_keeps_occupant_id_without_disclosing_real_jid() {
    let sender = "alice@remote.test/phone";
    let archived = "<message xmlns='jabber:client' from='room@conference.example.test/Alice' type='groupchat'><body>hello</body></message>";
    let anonymous = federated_history_stanza(&room(false), archived, sender);
    assert!(anonymous.contains("urn:xmpp:occupant-id:0"));
    assert!(!anonymous.contains("alice@remote.test"));
    assert!(!anonymous.contains("urn:northstar:muc:sender:0"));

    let disclosed = federated_history_stanza(&room(true), archived, sender);
    assert!(disclosed.contains("urn:xmpp:occupant-id:0"));
    assert!(disclosed.contains("urn:northstar:muc:sender:0"));
    assert!(disclosed.contains("alice@remote.test"));
    assert!(!disclosed.contains("/phone"));

    let privileged = federated_history_stanza_with_access(&room(false), archived, sender, true);
    assert!(privileged.contains("alice@remote.test"));
}

#[test]
fn federated_iq_parser_owns_admin_items_and_preserves_malformed_requests() {
    let xml = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set' id='a1'><query xmlns='http://jabber.org/protocol/muc#admin'><item jid='bad@@remote.test' affiliation='outcast'><reason>spam</reason></item><item role='none'/></query></iq>";
    let document = roxmltree::Document::parse(xml).unwrap();
    let parsed = FederatedIqRequest::from_node(document.root_element(), xml);
    drop(document);
    let FederatedIqPayload::AdminSet { items } = parsed.payload else {
        panic!("admin set was not parsed");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].jid.as_deref(), Some("bad@@remote.test"));
    assert_eq!(items[0].reason.as_deref(), Some("spam"));
    assert_eq!(items[1].jid, None);
    assert_eq!(items[1].nick, None);
    assert_eq!(parsed.stanza.id.as_deref(), Some("a1"));

    for malformed in [
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'><unknown/></query></iq>",
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Alice' role='none'><reason>a</reason><reason>b</reason></item></query></iq>",
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Alice' role='none' actor='forged'/></query></iq>",
            "<iq type='set'><query xmlns='http://jabber.org/protocol/muc#admin'/></iq>",
        ] {
            let document = roxmltree::Document::parse(malformed).unwrap();
            assert!(matches!(
                FederatedIqRequest::from_node(document.root_element(), malformed).payload,
                FederatedIqPayload::AdminError("bad-request")
            ));
        }
}

#[test]
fn federated_iq_parser_captures_bounded_mam_and_moderation_controls() {
    let mam = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set'><query xmlns='urn:xmpp:mam:2' queryid='q1'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value>alice@remote.test</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>999</max><before/></set></query></iq>";
    let document = roxmltree::Document::parse(mam).unwrap();
    let parsed = FederatedIqRequest::from_node(document.root_element(), mam);
    let FederatedIqPayload::MamQuery(query) = parsed.payload else {
        panic!("MAM query was not parsed");
    };
    assert_eq!(query.query_id.as_deref(), Some("q1"));
    assert_eq!(query.query.with_jid.as_deref(), Some("alice@remote.test"));
    assert_eq!(query.query.max, 100);
    assert!(crate::services::muc::archive_page_is_last(
        &query.query.page
    ));

    let metadata = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='get'><metadata xmlns='urn:xmpp:mam:2'/></iq>";
    let document = roxmltree::Document::parse(metadata).unwrap();
    assert!(matches!(
        FederatedIqRequest::from_node(document.root_element(), metadata).payload,
        FederatedIqPayload::MamMetadata
    ));

    let malformed = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='unknown'><value>x</value></field></x></query></iq>";
    let document = roxmltree::Document::parse(malformed).unwrap();
    assert!(matches!(
        FederatedIqRequest::from_node(document.root_element(), malformed).payload,
        FederatedIqPayload::MamError("feature-not-implemented")
    ));

    let moderate = "<iq from='owner@remote.test/Phone' to='room@conference.example.test' type='set'><moderate xmlns='urn:xmpp:message-moderate:1' id='de305d54-75b4-431b-adb2-eb6b9e546013'><retract xmlns='urn:xmpp:message-retract:1'/><reason>abuse</reason></moderate></iq>";
    let document = roxmltree::Document::parse(moderate).unwrap();
    let parsed = FederatedIqRequest::from_node(document.root_element(), moderate);
    let FederatedIqPayload::Moderate {
        target,
        reason,
        has_retract,
    } = parsed.payload
    else {
        panic!("moderation request was not parsed");
    };
    assert_eq!(
        target.as_deref(),
        Some("de305d54-75b4-431b-adb2-eb6b9e546013")
    );
    assert_eq!(reason.as_deref(), Some("abuse"));
    assert!(has_retract);
}

#[test]
fn federated_iq_parser_accepts_only_structurally_empty_unique_requests() {
    let valid = "<iq from='alice@remote.test/Phone' to='conference.example.test' type='get' id='u1'><unique xmlns='http://jabber.org/protocol/muc#unique'/></iq>";
    let document = roxmltree::Document::parse(valid).unwrap();
    assert!(matches!(
        FederatedIqRequest::from_node(document.root_element(), valid).payload,
        FederatedIqPayload::Unique
    ));

    let malformed = "<iq from='alice@remote.test/Phone' to='conference.example.test' type='get' id='u2'><unique xmlns='http://jabber.org/protocol/muc#unique' bogus='1'/></iq>";
    let document = roxmltree::Document::parse(malformed).unwrap();
    assert!(matches!(
        FederatedIqRequest::from_node(document.root_element(), malformed).payload,
        FederatedIqPayload::Unsupported
    ));
}

#[test]
fn federated_room_disco_preserves_reserved_nick_node_and_rejects_extra_shape() {
    let reserved = "<iq from='alice@remote.test/Phone' to='room@conference.example.test' type='get'><query xmlns='http://jabber.org/protocol/disco#info' node='x-roomuser-item'/></iq>";
    let document = roxmltree::Document::parse(reserved).unwrap();
    assert!(matches!(
        FederatedIqRequest::from_node(document.root_element(), reserved).payload,
        FederatedIqPayload::DiscoInfo { node: Some(node) } if node == "x-roomuser-item"
    ));

    for malformed in [
        "<iq type='get'><query xmlns='http://jabber.org/protocol/disco#info' bogus='1'/></iq>",
        "<iq type='get'><query xmlns='http://jabber.org/protocol/disco#info'><item/></query></iq>",
    ] {
        let document = roxmltree::Document::parse(malformed).unwrap();
        assert!(matches!(
            FederatedIqRequest::from_node(document.root_element(), malformed).payload,
            FederatedIqPayload::DiscoInfoError
        ));
    }
}
