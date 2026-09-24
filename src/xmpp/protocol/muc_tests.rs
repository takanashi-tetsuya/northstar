use super::{
    apply_muc_history_bounds, can_retrieve_muc_affiliation_list, canonical_local_muc_room,
    classify_muc_admin_items, is_exact_muc_removal_target, muc_admin_batch_error,
    muc_offline_affiliation_change_notice, muc_presence_payload, muc_sender_is_blocked,
    muc_voice_request, parse_moderation_request, parse_muc_admin_batch, parse_muc_admin_raw_items,
    parse_muc_author_retraction, parse_muc_history_request, parse_muc_invitation_decline,
    parse_muc_origin_id, parse_muc_subject_command, parse_muc_voice_form,
    should_broadcast_offline_affiliation_change, ModerationRequest, MucAdminBatchChange,
    MucAdminBatchOutcome, MucAdminChange, MucAdminMutationKind, MucAdminParseError,
    MucAdminRawItem, MucHistoryRequest, MucPostCommitAdmissionError, MucPostCommitPlan,
    MucVoiceForm,
};

#[test]
fn voice_request_preserves_room_and_occupant_fields() {
    let xml = muc_voice_request(
        "room@conference.example.test",
        "alice@example.test/phone",
        "Alice<&",
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("from"), Some("room@conference.example.test"));
    assert_eq!(root.attribute("type"), Some("normal"));
    let form = root.children().find(|node| node.is_element()).unwrap();
    assert_eq!(form.tag_name().namespace(), Some("jabber:x:data"));
    let fields = form
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "field")
        .map(|field| {
            (
                field.attribute("var").unwrap(),
                field
                    .children()
                    .find(|node| node.is_element())
                    .unwrap()
                    .text()
                    .unwrap(),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        fields["FORM_TYPE"],
        "http://jabber.org/protocol/muc#request"
    );
    assert_eq!(fields["muc#jid"], "alice@example.test/phone");
    assert_eq!(fields["muc#roomnick"], "Alice<&");
    assert_eq!(fields["muc#request_allow"], "false");
}

#[test]
fn post_commit_plan_has_a_hard_capacity_and_rejects_work_after_seal() {
    let mut plan = MucPostCommitPlan::<u8, 1>::new();
    assert_eq!(plan.try_push(1), Ok(()));
    assert_eq!(plan.try_push(2), Err(MucPostCommitAdmissionError::Full));
    plan.seal();
    assert_eq!(plan.try_push(3), Err(MucPostCommitAdmissionError::Sealed));
}

#[test]
fn standard_role_none_kick_is_not_an_affiliation_batch() {
    let document = roxmltree::Document::parse(
        "<iq xmlns='jabber:client' type='set' id='fed-muc-kick' to='federated-controls@conference.localhost'><query xmlns='http://jabber.org/protocol/muc#admin'><item nick='RemoteBob' role='none'><reason>Federated kick</reason></item></query></iq>",
    )
    .unwrap();
    let query = document
        .root_element()
        .children()
        .find(|node| node.is_element())
        .expect("test IQ has an admin query");
    let items = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();

    let mutation = classify_muc_admin_items(&items).expect("standard role kick is valid");
    assert_eq!(mutation, MucAdminMutationKind::Role);
    assert!(!mutation.requires_affiliation_batch());
}

#[test]
fn admin_batch_parser_preserves_order_and_normalizes_targets() {
    let document = roxmltree::Document::parse(
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item jid='BOB@Example.Test/phone' affiliation='member'><reason>Invite</reason></item><item nick='A\u{30a}' role='visitor'/><item jid='carol@example.test' affiliation='outcast'/></query>",
    )
    .unwrap();
    let items = document
        .root_element()
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    let batch = parse_muc_admin_batch(&items).unwrap();
    let raw_items = [
        MucAdminRawItem {
            jid: Some("BOB@Example.Test/phone"),
            nick: None,
            affiliation: Some("member"),
            role: None,
            reason: Some("Invite"),
        },
        MucAdminRawItem {
            jid: None,
            nick: Some("A\u{30a}"),
            affiliation: None,
            role: Some("visitor"),
            reason: None,
        },
        MucAdminRawItem {
            jid: Some("carol@example.test"),
            nick: None,
            affiliation: Some("outcast"),
            role: None,
            reason: None,
        },
    ];
    assert_eq!(parse_muc_admin_raw_items(&raw_items).unwrap(), batch);
    assert_eq!(
        batch.service_changes("example.test").unwrap(),
        vec![
            MucAdminBatchChange::Affiliation {
                target: super::MucAffiliationTarget::LocalUsername("bob".to_owned()),
                affiliation: "member".to_owned(),
                reason: Some("Invite".to_owned()),
            },
            MucAdminBatchChange::Role {
                target_nick: "Å".to_owned(),
                role: "visitor".to_owned(),
                reason: None,
            },
            MucAdminBatchChange::Affiliation {
                target: super::MucAffiliationTarget::LocalUsername("carol".to_owned()),
                affiliation: "outcast".to_owned(),
                reason: None,
            },
        ]
    );
    assert_eq!(batch.items.len(), 3);
    assert_eq!(batch.items[0].reason.as_deref(), Some("Invite"));
    assert_eq!(
        batch.items[0].change,
        MucAdminChange::Affiliation {
            target_bare_jid: "bob@example.test".to_owned(),
            affiliation: "member".to_owned(),
        }
    );
    assert_eq!(
        batch.items[1].change,
        MucAdminChange::Role {
            target_nick: "Å".to_owned(),
            role: "visitor".to_owned(),
        }
    );
    assert_eq!(
        batch.items[2].change,
        MucAdminChange::Affiliation {
            target_bare_jid: "carol@example.test".to_owned(),
            affiliation: "outcast".to_owned(),
        }
    );
    // The new shape is parsed, but no non-atomic writer is allowed to run it.
    assert_eq!(classify_muc_admin_items(&items), Err(()));
}

#[test]
fn admin_batch_parser_rejects_canonical_duplicates_and_combined_item() {
    for xml in [
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item jid='BOB@Example.Test/phone' affiliation='member'/><item jid='bob@example.test' affiliation='none'/></query>",
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item nick='A\u{30a}' role='visitor'/><item nick='Å' role='participant'/></query>",
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item jid='bob@example.test' affiliation='member' role='visitor' nick='Bob'/></query>",
    ] {
        let document = roxmltree::Document::parse(xml).unwrap();
        let items = document
            .root_element()
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        assert_eq!(
            parse_muc_admin_batch(&items),
            Err(MucAdminParseError::BadRequest)
        );
    }
}

#[test]
fn admin_batch_parser_rejects_foreign_item_and_reason_namespaces() {
    for xml in [
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item xmlns='urn:example:other' nick='Bob' role='visitor'/></query>",
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Bob' role='visitor'><reason xmlns='urn:example:other'>Ignored</reason></item></query>",
    ] {
        let document = roxmltree::Document::parse(xml).unwrap();
        let items = document
            .root_element()
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        assert_eq!(
            parse_muc_admin_batch(&items),
            Err(MucAdminParseError::BadRequest)
        );
    }
}

#[test]
fn admin_batch_parser_bounds_items_and_preserves_malformed_target_error() {
    let items = (0..63)
        .map(|index| format!("<item nick='Nick{index}' role='participant'/>"))
        .collect::<String>();
    let xml = format!("<query xmlns='http://jabber.org/protocol/muc#admin'>{items}</query>");
    let document = roxmltree::Document::parse(&xml).unwrap();
    let nodes = document
        .root_element()
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    assert_eq!(parse_muc_admin_batch(&nodes).unwrap().items.len(), 63);
    assert_eq!(classify_muc_admin_items(&nodes), Err(()));

    let xml = format!("<query xmlns='http://jabber.org/protocol/muc#admin'>{items}<item nick='Extra' role='none'/></query>");
    let document = roxmltree::Document::parse(&xml).unwrap();
    let nodes = document
        .root_element()
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    assert_eq!(
        parse_muc_admin_batch(&nodes),
        Err(MucAdminParseError::BadRequest)
    );

    let document = roxmltree::Document::parse(
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item jid='@example.test' affiliation='member'/></query>",
    )
    .unwrap();
    let nodes = document
        .root_element()
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    assert_eq!(
        parse_muc_admin_batch(&nodes),
        Err(MucAdminParseError::JidMalformed)
    );

    let oversized_reason = "x".repeat(4097);
    let xml = format!(
        "<query xmlns='http://jabber.org/protocol/muc#admin'><item nick='Bob' role='none'><reason>{oversized_reason}</reason></item></query>"
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    let nodes = document
        .root_element()
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    assert_eq!(
        parse_muc_admin_batch(&nodes),
        Err(MucAdminParseError::NotAcceptable)
    );
}

#[test]
fn admin_batch_outcomes_have_stable_iq_error_mapping() {
    assert_eq!(muc_admin_batch_error(MucAdminBatchOutcome::Applied), None);
    assert_eq!(muc_admin_batch_error(MucAdminBatchOutcome::Replay), None);
    assert_eq!(
        muc_admin_batch_error(MucAdminBatchOutcome::DuplicateTarget),
        Some("bad-request")
    );
    assert_eq!(
        muc_admin_batch_error(MucAdminBatchOutcome::TooManyProjections),
        Some("resource-constraint")
    );
    assert_eq!(
        muc_admin_batch_error(MucAdminBatchOutcome::LastOwner),
        Some("conflict")
    );
    assert_eq!(
        muc_admin_batch_error(MucAdminBatchOutcome::MissingTarget),
        Some("item-not-found")
    );
    assert_eq!(
        muc_admin_batch_error(MucAdminBatchOutcome::Unauthorized),
        Some("forbidden")
    );
    for outcome in [
        MucAdminBatchOutcome::Stale,
        MucAdminBatchOutcome::Destroyed,
        MucAdminBatchOutcome::Conflict,
    ] {
        assert_eq!(muc_admin_batch_error(outcome), Some("conflict"));
    }
}

#[test]
fn role_kick_excludes_only_the_exact_target_from_room_delivery() {
    fn occupant(
        full_jid: &str,
        connection_id: uuid::Uuid,
        cluster_epoch: uuid::Uuid,
    ) -> crate::state::MucOccupant {
        crate::state::MucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "RemoteBob".to_owned(),
            endpoint: crate::state::MucOccupantEndpoint::Federated {
                authenticated_domain: "remote.example.test".to_owned(),
                connection_id,
            },
            affiliation: "none".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: true,
            occupant_id: "occupant".to_owned(),
            cluster_epoch,
            connection_id,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    let connection_id = uuid::Uuid::new_v4();
    let cluster_epoch = uuid::Uuid::new_v4();
    let target = occupant(
        "bob@remote.example.test/phone",
        connection_id,
        cluster_epoch,
    );
    let exact_target = occupant(
        "bob@remote.example.test/phone",
        connection_id,
        cluster_epoch,
    );
    let replacement_connection = occupant(
        "bob@remote.example.test/phone",
        uuid::Uuid::new_v4(),
        cluster_epoch,
    );
    let replacement_epoch = occupant(
        "bob@remote.example.test/phone",
        connection_id,
        uuid::Uuid::new_v4(),
    );
    let other_occupant = occupant(
        "carol@remote.example.test/laptop",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );

    assert!(is_exact_muc_removal_target(&exact_target, &target));
    assert!(!is_exact_muc_removal_target(
        &replacement_connection,
        &target
    ));
    assert!(!is_exact_muc_removal_target(&replacement_epoch, &target));
    assert!(!is_exact_muc_removal_target(&other_occupant, &target));
}

#[tokio::test]
async fn post_commit_plan_preserves_order_and_observes_failure_without_stopping() {
    let mut plan = MucPostCommitPlan::<u8, 3>::new();
    for step in [1, 2, 3] {
        plan.try_push(step).unwrap();
    }
    let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let failures = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    plan.run(
        {
            let observed = observed.clone();
            move |step| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push(step);
                    if step == 2 {
                        Err(step)
                    } else {
                        Ok(())
                    }
                }
            }
        },
        {
            let failures = failures.clone();
            move |step| failures.lock().unwrap().push(step)
        },
    )
    .await;
    assert_eq!(*observed.lock().unwrap(), vec![1, 2, 3]);
    assert_eq!(*failures.lock().unwrap(), vec![2]);
}

#[test]
fn offline_affiliation_notices_are_identity_safe_and_structurally_exact() {
    assert!(should_broadcast_offline_affiliation_change(
        true, false, "none", "member"
    ));
    assert!(!should_broadcast_offline_affiliation_change(
        false, false, "none", "member"
    ));
    assert!(!should_broadcast_offline_affiliation_change(
        true, true, "none", "member"
    ));
    assert!(!should_broadcast_offline_affiliation_change(
        true, false, "member", "member"
    ));

    let xml = muc_offline_affiliation_change_notice(
        "room@conference.example.test",
        "new.member@example.test",
        "member",
        Some("New & Member"),
        Some("Invite <accepted>"),
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    let message = document.root_element();
    assert_eq!(message.tag_name().name(), "message");
    assert_eq!(message.tag_name().namespace(), Some("jabber:client"));
    assert_eq!(
        message.attribute("from"),
        Some("room@conference.example.test")
    );
    assert_eq!(message.attribute("type"), Some("normal"));
    assert_eq!(message.attribute("to"), None);
    let x = message
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
        })
        .unwrap();
    let item = x
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "item")
        .unwrap();
    assert_eq!(item.attribute("affiliation"), Some("member"));
    assert_eq!(item.attribute("jid"), Some("new.member@example.test"));
    assert_eq!(item.attribute("role"), Some("none"));
    assert_eq!(item.attribute("nick"), Some("New & Member"));
    assert_eq!(
        item.children()
            .find(|node| node.is_element() && node.tag_name().name() == "reason")
            .and_then(|node| node.text()),
        Some("Invite <accepted>")
    );
}

#[test]
fn moderated_retraction_shape_is_exact_and_ids_remain_opaque() {
    let target = "de305d54-75b4-431b-adb2-eb6b9e546013";
    let xml = format!(
        "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/><reason> Spam </reason></moderate>"
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    assert_eq!(
        parse_moderation_request(document.root_element()).unwrap(),
        ModerationRequest {
            target_id: uuid::Uuid::parse_str(target).unwrap(),
            reason: Some("Spam".to_owned()),
        }
    );

    for xml in [
        format!(
            "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/><retract xmlns='urn:xmpp:message-retract:1'/></moderate>"
        ),
        format!(
            "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'><payload/></retract></moderate>"
        ),
        format!(
            "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><unknown/></moderate>"
        ),
        format!(
            "<moderate xmlns='urn:xmpp:message-moderate:1' id='{target}'><reason>why</reason></moderate>"
        ),
    ] {
        let document = roxmltree::Document::parse(&xml).unwrap();
        assert_eq!(
            parse_moderation_request(document.root_element()).unwrap_err(),
            "bad-request",
            "{xml}"
        );
    }

    let uppercase = format!(
        "<moderate xmlns='urn:xmpp:message-moderate:1' id='{}'><retract xmlns='urn:xmpp:message-retract:1'/></moderate>",
        target.to_ascii_uppercase()
    );
    let document = roxmltree::Document::parse(&uppercase).unwrap();
    assert_eq!(
        parse_moderation_request(document.root_element()).unwrap_err(),
        "item-not-found"
    );
}

#[test]
fn room_addresses_use_rfc_7622_domain_and_bare_semantics() {
    assert_eq!(
        canonical_local_muc_room(
            "Lounge@Conference.B\u{fc}cher.Example.",
            "conference.bücher.example"
        ),
        Some((
            "lounge@conference.bücher.example".to_owned(),
            "lounge".to_owned()
        ))
    );
    assert!(canonical_local_muc_room(
        "lounge@conference.example.test/Nick",
        "conference.example.test"
    )
    .is_none());
    assert!(canonical_local_muc_room("lounge@example.test", "conference.example.test").is_none());
}

#[test]
fn client_presence_cannot_forge_server_asserted_muc_identity_or_delay() {
    let xml = "<presence xmlns='jabber:client'><x xmlns='http://jabber.org/protocol/muc'/><x xmlns='http://jabber.org/protocol/muc#user'><item jid='victim@example.test' affiliation='owner' role='moderator'/></x><occupant-id xmlns='urn:xmpp:occupant-id:0' id='forged'/><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='room@example.test'/><delay xmlns='urn:xmpp:delay' stamp='2000-01-01T00:00:00Z'/><c xmlns='http://jabber.org/protocol/caps' node='client' ver='1'/></presence>";
    let document = roxmltree::Document::parse(xml).unwrap();
    let payload = muc_presence_payload(document.root_element(), xml);
    assert_eq!(
        payload,
        "<c xmlns='http://jabber.org/protocol/caps' node='client' ver='1'/>"
    );
}

#[test]
fn voice_forms_distinguish_requests_from_strict_moderator_approvals() {
    let request = roxmltree::Document::parse(
        "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field></x></message>",
    )
    .unwrap();
    assert_eq!(
        parse_muc_voice_form(request.root_element()),
        Ok(Some(MucVoiceForm::Request))
    );

    let approval = roxmltree::Document::parse(
        "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field><field var='muc#jid'><value>visitor@example.test/Phone</value></field><field var='muc#roomnick'><value>Visitor</value></field><field var='muc#request_allow'><value>1</value></field></x></message>",
    )
    .unwrap();
    assert_eq!(
        parse_muc_voice_form(approval.root_element()),
        Ok(Some(MucVoiceForm::Approval {
            jid: "visitor@example.test/Phone".to_owned(),
            nick: "Visitor".to_owned(),
            allow: true,
        }))
    );

    for malformed in [
        "<message><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field></x></message>",
        "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>moderator</value></field></x></message>",
        "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field><field var='muc#role'><value>participant</value></field></x></message>",
        "<message><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field><field var='muc#role'><value>participant</value></field><field var='muc#jid'><value>bare@example.test</value></field><field var='muc#roomnick'><value>Visitor</value></field><field var='muc#request_allow'><value>yes</value></field></x></message>",
    ] {
        let document = roxmltree::Document::parse(malformed).unwrap();
        assert!(parse_muc_voice_form(document.root_element()).is_err());
    }
}

#[test]
fn mediated_invitation_declines_are_strict_and_keep_the_reason() {
    let decline = roxmltree::Document::parse(
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='inviter@example.test'><reason>Not today</reason></decline></x></message>",
    )
    .unwrap();
    assert_eq!(
        parse_muc_invitation_decline(decline.root_element()),
        Ok(Some((
            "inviter@example.test".to_owned(),
            Some("Not today".to_owned())
        )))
    );
    let absent = roxmltree::Document::parse("<message><body>hello</body></message>").unwrap();
    assert_eq!(
        parse_muc_invitation_decline(absent.root_element()),
        Ok(None)
    );
    for malformed in [
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline/></x></message>",
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='a@example.test'/><decline to='b@example.test'/></x></message>",
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='a@example.test' from='forged@example.test'/></x></message>",
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><decline to='a@example.test'><reason>one</reason><reason>two</reason></decline></x></message>",
    ] {
        let document = roxmltree::Document::parse(malformed).unwrap();
        assert!(parse_muc_invitation_decline(document.root_element()).is_err());
    }
}

#[test]
fn owners_and_admins_can_retrieve_persisted_affiliation_lists() {
    for requester in ["owner", "admin"] {
        for requested in ["owner", "admin", "member", "outcast"] {
            assert!(can_retrieve_muc_affiliation_list(
                requester, requested, false, false
            ));
        }
    }
}

#[test]
fn members_can_retrieve_omemo_recipient_lists_in_private_non_anonymous_rooms() {
    for requested in ["owner", "admin", "member"] {
        assert!(can_retrieve_muc_affiliation_list(
            "member", requested, true, true
        ));
    }
    assert!(!can_retrieve_muc_affiliation_list(
        "member", "outcast", true, true
    ));
}

#[test]
fn ordinary_members_cannot_expand_jid_visibility_in_other_room_types() {
    assert!(!can_retrieve_muc_affiliation_list(
        "member", "member", false, true
    ));
    assert!(!can_retrieve_muc_affiliation_list(
        "member", "member", true, false
    ));
    assert!(!can_retrieve_muc_affiliation_list(
        "none", "member", true, true
    ));
    assert!(!can_retrieve_muc_affiliation_list(
        "member", "invalid", true, true
    ));
}

#[test]
fn muc_blocking_matches_room_nick_and_real_sender_but_not_own_resources() {
    let owner = "alice@example.test";
    assert!(muc_sender_is_blocked(
        &["room@conference.example.test".to_owned()],
        owner,
        "room@conference.example.test/Romeo",
        Some("romeo@example.test/Phone"),
    ));
    assert!(muc_sender_is_blocked(
        &["romeo@example.test".to_owned()],
        owner,
        "room@conference.example.test/Romeo",
        Some("romeo@example.test/Phone"),
    ));
    assert!(!muc_sender_is_blocked(
        &["alice@example.test".to_owned()],
        owner,
        "room@conference.example.test/Alice",
        Some("alice@example.test/Phone"),
    ));
}

#[test]
fn history_identity_and_subject_commands_have_strict_unambiguous_shapes() {
    let document = roxmltree::Document::parse(
        "<message type='groupchat'><subject>new</subject><origin-id xmlns='urn:xmpp:sid:0' id='client-1'/></message>",
    )
    .unwrap();
    let root = document.root_element();
    assert_eq!(parse_muc_subject_command(root), Ok(Some("new".to_owned())));
    assert_eq!(parse_muc_origin_id(root), Ok(Some("client-1".to_owned())));

    let discussion = roxmltree::Document::parse(
        "<message type='groupchat'><subject>caption</subject><body>discussion</body></message>",
    )
    .unwrap();
    assert_eq!(
        parse_muc_subject_command(discussion.root_element()),
        Ok(None)
    );
    for malformed in [
        "<message><subject>a</subject><subject>b</subject></message>",
        "<message><subject xml:lang='en'>a</subject></message>",
        "<message><origin-id xmlns='urn:xmpp:sid:0'/></message>",
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='a'/><origin-id xmlns='urn:xmpp:sid:0' id='b'/></message>",
    ] {
        let malformed = roxmltree::Document::parse(malformed).unwrap();
        let root = malformed.root_element();
        assert!(parse_muc_subject_command(root).is_err() || parse_muc_origin_id(root).is_err());
    }
}

#[test]
fn author_retraction_parser_prefers_current_direct_shape_without_legacy_ambiguity() {
    let target = "de305d54-75b4-431b-adb2-eb6b9e546013";
    let direct_xml = format!(
        "<message type='groupchat'><retract xmlns='urn:xmpp:message-retract:1' id='{target}'/><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:message-retract:1'/><body>message retracted</body></message>"
    );
    let direct = roxmltree::Document::parse(&direct_xml).unwrap();
    assert_eq!(
        parse_muc_author_retraction(direct.root_element()),
        Ok(Some(uuid::Uuid::parse_str(target).unwrap()))
    );
    let valid_xml = format!(
        "<message type='groupchat'><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"
    );
    let valid = roxmltree::Document::parse(&valid_xml).unwrap();
    assert_eq!(
        parse_muc_author_retraction(valid.root_element()),
        Ok(Some(uuid::Uuid::parse_str(target).unwrap()))
    );
    for malformed in [
        format!("<message><body>x</body><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"),
        format!("<message><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"),
        format!("<message><retract xmlns='urn:xmpp:message-retract:1' id='{target}'/><apply-to xmlns='urn:xmpp:fasten:0' id='{target}'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>"),
        "<message><apply-to xmlns='urn:xmpp:fasten:0' id='not-a-uuid'><retract xmlns='urn:xmpp:message-retract:1'/></apply-to></message>".to_owned(),
    ] {
        let malformed = roxmltree::Document::parse(&malformed).unwrap();
        assert!(parse_muc_author_retraction(malformed.root_element()).is_err());
    }
}

#[test]
fn history_controls_are_strict_combined_and_bounded() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-08-26T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let document = roxmltree::Document::parse(
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history maxchars='4096' maxstanzas='500' seconds='3600' since='2026-08-26T11:30:00Z'/></x></presence>",
    )
    .unwrap();
    let request = parse_muc_history_request(document.root_element(), now).unwrap();
    assert_eq!(request.max_stanzas, 100);
    assert_eq!(request.max_chars, Some(4096));
    assert_eq!(
        request.since,
        Some(
            chrono::DateTime::parse_from_rfc3339("2026-08-26T11:30:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc)
        )
    );

    for malformed in [
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='-1'/></x></presence>",
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history seconds='1.5'/></x></presence>",
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history since='not-a-date'/></x></presence>",
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history unknown='1'/></x></presence>",
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history/><history/></x></presence>",
    ] {
        let document = roxmltree::Document::parse(malformed).unwrap();
        assert!(parse_muc_history_request(document.root_element(), now).is_err());
    }
}

#[test]
fn history_bounds_keep_the_newest_complete_stanzas_and_exclude_subject_events() {
    let request = MucHistoryRequest {
        max_stanzas: 3,
        max_chars: Some(4),
        since: None,
    };
    assert_eq!(
        apply_muc_history_bounds(
            vec!["old".to_owned(), "ab".to_owned(), "cd".to_owned()],
            request
        ),
        vec!["ab".to_owned(), "cd".to_owned()]
    );
}
