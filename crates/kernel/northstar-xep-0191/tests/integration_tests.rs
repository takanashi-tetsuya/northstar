#![forbid(unsafe_code)]

use northstar_xep_0191::{
    build_blocklist_result, build_payload, parse_blocklist_result, parse_iq, plan_blocking_effects,
    presence_targets, BlockPattern, BlockingCommand, BlockingError, BlockingMutation,
    BlockingSnapshot, PresencePeer, PresenceTransition, Subscription, DESCRIPTOR, MAX_ITEMS,
    NAMESPACE, XEP_ID,
};
use northstar_xep_core::{StanzaKind, XepId};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Document;

fn jid(value: &str) -> CanonicalJid {
    CanonicalJid::parse(value).expect("valid test JID")
}

fn pattern(value: &str) -> BlockPattern {
    BlockPattern::new(jid(value))
}

fn parse(xml: &str) -> Result<BlockingCommand, BlockingError> {
    let document = Document::parse(xml).expect("valid fixture XML");
    parse_iq(document.root_element())
}

#[test]
fn parses_the_three_command_forms() {
    assert_eq!(
        parse("<iq type='get'><blocklist xmlns='urn:xmpp:blocking'/></iq>").unwrap(),
        BlockingCommand::GetBlocklist
    );
    assert_eq!(
        parse("<iq type='set'><block xmlns='urn:xmpp:blocking'><item jid='Alice@Example.test'/></block></iq>").unwrap(),
        BlockingCommand::Mutate(BlockingMutation::Block(vec![pattern(
            "alice@example.test"
        )]))
    );
    assert_eq!(
        parse("<iq type='set'><unblock xmlns='urn:xmpp:blocking'><item jid='example.test'/></unblock></iq>").unwrap(),
        BlockingCommand::Mutate(BlockingMutation::Unblock(vec![pattern("example.test")]))
    );
    assert_eq!(
        parse("<iq type='set'><unblock xmlns='urn:xmpp:blocking'/></iq>").unwrap(),
        BlockingCommand::Mutate(BlockingMutation::UnblockAll)
    );
}

#[test]
fn block_requires_at_least_one_item() {
    assert_eq!(
        parse("<iq type='set'><block xmlns='urn:xmpp:blocking'/></iq>").unwrap_err(),
        BlockingError::EmptyBlock
    );
}

#[test]
fn command_iq_must_be_implicit_and_have_the_right_type() {
    assert_eq!(
        parse("<iq type='get' to='example.test'><blocklist xmlns='urn:xmpp:blocking'/></iq>")
            .unwrap_err(),
        BlockingError::ExplicitIqTarget
    );
    assert_eq!(
        parse("<iq type='set'><blocklist xmlns='urn:xmpp:blocking'/></iq>").unwrap_err(),
        BlockingError::WrongIqType
    );
    assert_eq!(
        parse("<iq type='get'><block xmlns='urn:xmpp:blocking'><item jid='example.test'/></block></iq>").unwrap_err(),
        BlockingError::WrongIqType
    );
}

#[test]
fn rejects_non_iq_and_ambiguous_payloads() {
    let document =
        Document::parse("<message><blocklist xmlns='urn:xmpp:blocking'/></message>").unwrap();
    assert_eq!(
        parse_iq(document.root_element()).unwrap_err(),
        BlockingError::NotIq
    );
    assert_eq!(
        parse("<iq type='get'/>").unwrap_err(),
        BlockingError::AmbiguousIqPayload
    );
    assert_eq!(
        parse(
            "<iq type='get'><query xmlns='urn:test'/><blocklist xmlns='urn:xmpp:blocking'/></iq>"
        )
        .unwrap_err(),
        BlockingError::AmbiguousIqPayload
    );
    assert_eq!(
        parse("<iq type='get'><query xmlns='urn:test'/></iq>").unwrap_err(),
        BlockingError::AmbiguousIqPayload
    );
}

#[test]
fn rejects_invalid_command_and_item_shapes() {
    for xml in [
        "<iq type='get'><blocklist xmlns='urn:xmpp:blocking' extra='x'/></iq>",
        "<iq type='set'><block xmlns='urn:xmpp:blocking'>text<item jid='example.test'/></block></iq>",
        "<iq type='set'><block xmlns='urn:xmpp:blocking'><other jid='example.test'/></block></iq>",
        "<iq type='set'><block xmlns='urn:xmpp:blocking'><item/></block></iq>",
        "<iq type='set'><block xmlns='urn:xmpp:blocking'><item jid='example.test' extra='x'/></block></iq>",
        "<iq type='set'><block xmlns='urn:xmpp:blocking'><item jid='example.test'><x/></item></block></iq>",
    ] {
        assert!(parse(xml).is_err(), "accepted {xml}");
    }
}

#[test]
fn rejects_invalid_jids_and_excessive_item_counts() {
    assert!(matches!(
        parse("<iq type='set'><block xmlns='urn:xmpp:blocking'><item jid='bad jid'/></block></iq>")
            .unwrap_err(),
        BlockingError::InvalidJid(_)
    ));
    let items = (0..=MAX_ITEMS)
        .map(|index| format!("<item jid='user{index}@example.test'/>"))
        .collect::<String>();
    let error = parse(&format!(
        "<iq type='set'><block xmlns='urn:xmpp:blocking'>{items}</block></iq>"
    ))
    .unwrap_err();
    assert_eq!(error, BlockingError::TooManyItems { limit: MAX_ITEMS });
}

#[test]
fn canonical_duplicates_are_collapsed_without_changing_first_seen_order() {
    let command = parse(
        "<iq type='set'><block xmlns='urn:xmpp:blocking'><item jid='Alice@B\u{fc}CHER.example'/><item jid='alice@xn--bcher-kva.example'/><item jid='remote.test'/></block></iq>",
    )
    .unwrap();
    let BlockingCommand::Mutate(BlockingMutation::Block(items)) = command else {
        panic!("expected a block mutation");
    };
    assert_eq!(
        items,
        vec![pattern("alice@b\u{fc}cher.example"), pattern("remote.test")]
    );
}

#[test]
fn block_patterns_follow_full_bare_and_domain_semantics() {
    assert!(pattern("alice@example.test/Phone").matches(&jid("alice@example.test/Phone")));
    assert!(!pattern("alice@example.test/Phone").matches(&jid("alice@example.test/phone")));
    assert!(pattern("alice@example.test").matches(&jid("alice@example.test/Phone")));
    assert!(!pattern("alice@example.test").matches(&jid("bob@example.test/Phone")));
    assert!(pattern("example.test").matches(&jid("bob@example.test/Phone")));
    assert!(!pattern("example.test").matches(&jid("bob@other.test/Phone")));
}

#[test]
fn snapshots_sort_deduplicate_and_match() {
    let snapshot = BlockingSnapshot::new(vec![
        pattern("example.test"),
        pattern("alice@example.test"),
        pattern("example.test"),
    ]);
    assert_eq!(snapshot.patterns().len(), 2);
    assert!(snapshot.is_blocked(&jid("bob@example.test/Phone")));
    assert!(!snapshot.is_blocked(&jid("bob@other.test/Phone")));
}

#[test]
fn parses_and_builds_blocklist_results() {
    let xml = build_blocklist_result(&[
        pattern("alice@example.test"),
        pattern("remote.test/Device&One"),
    ]);
    let document = Document::parse(&xml).unwrap();
    let snapshot = parse_blocklist_result(document.root_element()).unwrap();
    assert_eq!(snapshot.patterns().len(), 2);
    assert!(snapshot
        .patterns()
        .contains(&pattern("remote.test/Device&One")));
    assert!(snapshot.patterns().contains(&pattern("alice@example.test")));
}

#[test]
fn builders_round_trip_all_mutations() {
    for command in [
        BlockingCommand::GetBlocklist,
        BlockingCommand::Mutate(BlockingMutation::Block(vec![pattern(
            "alice@example.test/Phone&Tablet",
        )])),
        BlockingCommand::Mutate(BlockingMutation::Unblock(vec![pattern("example.test")])),
        BlockingCommand::Mutate(BlockingMutation::UnblockAll),
    ] {
        let iq_type = if command == BlockingCommand::GetBlocklist {
            "get"
        } else {
            "set"
        };
        let payload = build_payload(&command);
        let round_trip = parse(&format!("<iq type='{iq_type}'>{payload}</iq>")).unwrap();
        assert_eq!(round_trip, command);
    }
}

#[test]
fn presence_targets_require_roster_authorization_or_directed_presence() {
    let roster = vec![
        PresencePeer {
            jid: jid("alice@example.test"),
            subscription: Subscription::From,
        },
        PresencePeer {
            jid: jid("bob@example.test"),
            subscription: Subscription::Both,
        },
        PresencePeer {
            jid: jid("carol@example.test"),
            subscription: Subscription::To,
        },
    ];
    let directed = vec![jid("device@example.test/Phone")];
    let targets = presence_targets(&[pattern("example.test")], &roster, &directed);
    assert_eq!(
        targets,
        vec![
            jid("alice@example.test"),
            jid("bob@example.test"),
            jid("device@example.test/Phone")
        ]
    );
}

#[test]
fn full_jid_presence_requires_authorized_bare_roster_peer() {
    let changed = [pattern("alice@example.test/Phone")];
    let denied = [PresencePeer {
        jid: jid("alice@example.test"),
        subscription: Subscription::To,
    }];
    assert!(presence_targets(&changed, &denied, &[]).is_empty());
    let allowed = [PresencePeer {
        jid: jid("alice@example.test"),
        subscription: Subscription::From,
    }];
    assert_eq!(
        presence_targets(&changed, &allowed, &[]),
        vec![jid("alice@example.test/Phone")]
    );
}

#[test]
fn mutation_plans_have_explicit_presence_transitions() {
    let block = BlockingMutation::Block(vec![pattern("example.test")]);
    let block_effects = plan_blocking_effects(
        block.clone(),
        &[pattern("example.test")],
        &[],
        &[jid("alice@example.test/Phone")],
    );
    assert_eq!(block_effects.push_mutation, block);
    assert_eq!(
        block_effects.presence_transition,
        PresenceTransition::SendUnavailable
    );

    let unblock = BlockingMutation::UnblockAll;
    let unblock_effects = plan_blocking_effects(unblock, &[], &[], &[]);
    assert_eq!(
        unblock_effects.presence_transition,
        PresenceTransition::RestoreCurrent
    );
}

#[test]
fn descriptor_declares_the_complete_wire_surface() {
    assert_eq!(DESCRIPTOR.id, XEP_ID);
    assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
    assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
    assert_eq!(DESCRIPTOR.routes.len(), 3);
    assert_eq!(
        DESCRIPTOR
            .routes
            .iter()
            .filter(|route| route.stanza == StanzaKind::IqSet)
            .count(),
        2
    );
}
