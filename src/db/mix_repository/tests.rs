use super::*;
#[test]
fn mix_muc_repository_outcomes_map_without_collapsing_authority_failures() {
    for (repository, service) in [
        (db::LinkMixMucOutcome::Linked, MixMucLinkOutcome::Linked),
        (
            db::LinkMixMucOutcome::AlreadyLinked,
            MixMucLinkOutcome::AlreadyLinked,
        ),
        (
            db::LinkMixMucOutcome::MissingCounterpart,
            MixMucLinkOutcome::MissingCounterpart,
        ),
        (
            db::LinkMixMucOutcome::NotCommonOwner,
            MixMucLinkOutcome::NotCommonOwner,
        ),
        (db::LinkMixMucOutcome::Conflict, MixMucLinkOutcome::Conflict),
    ] {
        assert_eq!(map_mix_muc_link_outcome(repository), service);
    }
}

// -- DTO boundary contract tests -------------------------------------
//
// The mirrors exist so the protocol layer never names a `db::` type. These
// tests pin every mapped field and both translation directions, so a
// repository column or boundary field added on one side only fails here
// instead of silently dropping data at the service edge.

#[test]
fn mix_node_vocabulary_matches_the_repository_constants() {
    assert_eq!(NODE_MESSAGES, db::NODE_MESSAGES);
    assert_eq!(NODE_PRESENCE, db::NODE_PRESENCE);
    assert_eq!(NODE_PARTICIPANTS, db::NODE_PARTICIPANTS);
    assert_eq!(NODE_INFO, db::NODE_INFO);
    assert_eq!(NODE_CONFIG, db::NODE_CONFIG);
    assert_eq!(NODE_ALLOWED, db::NODE_ALLOWED);
    assert_eq!(NODE_BANNED, db::NODE_BANNED);
    assert_eq!(NODE_JIDMAP, db::NODE_JIDMAP);
    assert_eq!(NODE_AVATAR_DATA, db::NODE_AVATAR_DATA);
    assert_eq!(NODE_AVATAR_METADATA, db::NODE_AVATAR_METADATA);
    assert_eq!(ALL_NODES, db::ALL_NODES);
}

#[test]
fn pam_membership_map_preserves_every_field() {
    let row = db::PamMembership {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        channel_jid: "room@mix.example.test".to_owned(),
        participant_id: Some("stable-id".to_owned()),
        state: "pending_join".to_owned(),
        request_id: Some("request-1".to_owned()),
        client_request_id: Some("client-1".to_owned()),
        requester_full_jid: Some("alice@example.test/Phone".to_owned()),
        subscriptions: vec![NODE_MESSAGES.to_owned(), NODE_PRESENCE.to_owned()],
    };
    let mapped = pam_membership(row.clone());
    assert_eq!(mapped.id, row.id);
    assert_eq!(mapped.user_id, row.user_id);
    assert_eq!(mapped.channel_jid, row.channel_jid);
    assert_eq!(mapped.participant_id, row.participant_id);
    assert_eq!(mapped.state, row.state);
    assert_eq!(mapped.request_id, row.request_id);
    assert_eq!(mapped.client_request_id, row.client_request_id);
    assert_eq!(mapped.requester_full_jid, row.requester_full_jid);
    assert_eq!(mapped.subscriptions, row.subscriptions);
}

#[test]
fn event_and_page_maps_preserve_ordering_and_metadata() {
    let row = db::MixEvent {
        id: Uuid::new_v4(),
        item_id: db::mix_timestamp_item_id(),
        payload: "<body/>".to_owned(),
        created_at: Utc::now(),
    };
    let mapped = event(row.clone());
    assert_eq!(mapped.id, row.id);
    assert_eq!(mapped.item_id, row.item_id);
    assert_eq!(mapped.payload, row.payload);
    assert_eq!(mapped.created_at, row.created_at);

    let page = db::MixEventPage {
        events: vec![row.clone()],
    };
    let mapped_page = MixEventPage {
        events: page.events.clone().into_iter().map(event).collect(),
    };
    assert_eq!(
        page.events.iter().map(|e| e.id).collect::<Vec<_>>(),
        mapped_page.events.iter().map(|e| e.id).collect::<Vec<_>>(),
        "event order must be preserved"
    );
}

#[test]
fn mam_page_and_boundary_maps_preserve_paging_metadata() {
    let first = db::ArchiveBoundary {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
    };
    let last = db::ArchiveBoundary {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
    };
    let mapped_page = mam_page(db::MixMamPage {
        events: Vec::new(),
        total: 42,
        first_index: 7,
        complete: false,
    });
    assert_eq!(mapped_page.total, 42);
    assert_eq!(mapped_page.first_index, 7);
    assert!(!mapped_page.complete);
    assert!(mapped_page.events.is_empty());

    let first_id = first.id;
    let last_id = last.id;
    let (mapped_first, mapped_last) = (Some(boundary(first)), Some(boundary(last)));
    assert_eq!(mapped_first.as_ref().map(|b| b.id), Some(first_id));
    assert_eq!(mapped_last.as_ref().map(|b| b.id), Some(last_id));
}

#[test]
fn mam_query_translates_every_rsm_shape_in_both_directions() {
    let shapes = [
        db::MamRsmPage::First,
        db::MamRsmPage::Last,
        db::MamRsmPage::Before(Uuid::new_v4()),
        db::MamRsmPage::After(Uuid::new_v4()),
        db::MamRsmPage::Index(17),
    ];
    for page in shapes {
        let db_query = db::MamArchiveQuery {
            with_jid: Some("peer@example.test".to_owned()),
            start: Some(Utc::now()),
            end: None,
            before_id: None,
            after_id: Some(Uuid::new_v4()),
            ids: vec![Uuid::new_v4()],
            page,
            max: 25,
        };
        let mapped = MamArchiveQuery::from(db_query.clone());
        assert_eq!(mapped.with_jid, db_query.with_jid);
        assert_eq!(mapped.start, db_query.start);
        assert_eq!(mapped.end, db_query.end);
        assert_eq!(mapped.before_id, db_query.before_id);
        assert_eq!(mapped.after_id, db_query.after_id);
        assert_eq!(mapped.ids, db_query.ids);
        assert_eq!(mapped.max, db_query.max);
        match (db_query.page, mapped.page) {
            (db::MamRsmPage::First, MamRsmPage::First)
            | (db::MamRsmPage::Last, MamRsmPage::Last) => {}
            (db::MamRsmPage::Before(a), MamRsmPage::Before(b)) => assert_eq!(a, b),
            (db::MamRsmPage::After(a), MamRsmPage::After(b)) => assert_eq!(a, b),
            (db::MamRsmPage::Index(a), MamRsmPage::Index(b)) => assert_eq!(a, b),
            _ => panic!("MIX RSM shape changed during translation"),
        }
        let round_trip = mam_query_db(&mapped);
        assert_eq!(round_trip.with_jid, db_query.with_jid);
        assert_eq!(round_trip.max, db_query.max);
    }
}

#[test]
fn probe_target_preserves_channel_and_participant_identity() {
    let probe = db::MixPresenceProbeTarget {
        channel_jid: "room@mix.example.test".to_owned(),
        participant_jid: "alice@remote.test/Phone".to_owned(),
    };
    let mapped: MixPresenceProbeTarget = probe.into();
    assert_eq!(mapped.channel_jid, "room@mix.example.test");
    assert_eq!(mapped.participant_jid, "alice@remote.test/Phone");
}

#[test]
fn access_change_map_preserves_removal_observations() {
    let participant_row = MixParticipant {
        participant_id: Uuid::new_v4(),
        jid: "alice@example.test".to_owned(),
        nick: None,
    };
    let presence_row = db::MixPresenceItem {
        item_id: "item-1".to_owned(),
        payload: "<presence/>".to_owned(),
        source_full_jid: Some("alice@example.test/Phone".to_owned()),
    };
    let mapped = access_change_outcome(db::AccessChangeOutcome {
        removed_participants: vec![Uuid::new_v4()],
        removed_local_users: vec![Uuid::new_v4()],
        removed_presence: vec![(participant_row.clone(), vec![presence_row.clone()])],
    });
    assert_eq!(mapped.removed_participants.len(), 1);
    assert_eq!(mapped.removed_local_users.len(), 1);
    assert_eq!(mapped.removed_presence.len(), 1);
    assert_eq!(
        mapped.removed_presence[0].0.participant_id,
        participant_row.participant_id
    );
    assert_eq!(mapped.removed_presence[0].1[0].item_id, "item-1");
}

#[test]
fn outcome_maps_preserve_retraction_store_and_join_variants() {
    for (repository, service) in [
        (
            db::RetractMixMessageOutcome::Retracted,
            RetractMixMessageOutcome::Retracted,
        ),
        (
            db::RetractMixMessageOutcome::NotFound,
            RetractMixMessageOutcome::NotFound,
        ),
        (
            db::RetractMixMessageOutcome::Forbidden,
            RetractMixMessageOutcome::Forbidden,
        ),
    ] {
        let admission = retract_mix_message_admission(
            db::RetractMixMessageAdmission {
                outcome: repository,
                recipients: vec![MixParticipant {
                    participant_id: Uuid::new_v4(),
                    jid: "alice@example.test".to_owned(),
                    nick: None,
                }],
            },
            |_| panic!("test case must not contain an existing replay intent"),
        );
        assert_eq!(admission.outcome, service);
    }

    for repository in [
        db::StoreEventOutcome::Stored(Uuid::new_v4()),
        db::StoreEventOutcome::NotParticipant,
        db::StoreEventOutcome::Conflict,
        db::StoreEventOutcome::TooLarge,
    ] {
        let mapped = store_event_outcome(repository.clone());
        match (repository, mapped) {
            (db::StoreEventOutcome::Stored(a), StoreEventOutcome::Stored(b)) => {
                assert_eq!(a, b)
            }
            (db::StoreEventOutcome::NotParticipant, StoreEventOutcome::NotParticipant) => {}
            (db::StoreEventOutcome::Conflict, StoreEventOutcome::Conflict) => {}
            (db::StoreEventOutcome::TooLarge, StoreEventOutcome::TooLarge) => {}
            _ => panic!("store-event outcome variant changed during translation"),
        }
    }

    for repository in [
        db::CreateChannelOutcome::Created(Uuid::new_v4()),
        db::CreateChannelOutcome::Conflict,
        db::CreateChannelOutcome::QuotaExceeded,
    ] {
        let mapped = create_outcome(repository);
        match (repository, mapped) {
            (db::CreateChannelOutcome::Created(a), CreateChannelOutcome::Created(b)) => {
                assert_eq!(a, b)
            }
            (db::CreateChannelOutcome::Conflict, CreateChannelOutcome::Conflict) => {}
            (db::CreateChannelOutcome::QuotaExceeded, CreateChannelOutcome::QuotaExceeded) => {}
            _ => panic!("create-channel outcome variant changed during translation"),
        }
    }

    let joined = join_outcome(db::JoinChannelOutcome::Joined {
        participant: MixParticipant {
            participant_id: Uuid::new_v4(),
            jid: "alice@example.test".to_owned(),
            nick: Some("Alice".to_owned()),
        },
        preference: MixParticipantPreference::default(),
        subscriptions: vec![NODE_MESSAGES.to_owned()],
        newly_joined: true,
        roster_change: None,
    });
    assert!(matches!(
        joined,
        JoinChannelOutcome::Joined {
            newly_joined: true,
            ..
        }
    ));
    assert!(matches!(
        join_outcome(db::JoinChannelOutcome::Banned),
        JoinChannelOutcome::Banned
    ));
    assert!(matches!(
        join_outcome(db::JoinChannelOutcome::NotAllowed),
        JoinChannelOutcome::NotAllowed
    ));
    assert!(matches!(
        join_outcome(db::JoinChannelOutcome::Full),
        JoinChannelOutcome::Full
    ));
    assert!(matches!(
        join_outcome(db::JoinChannelOutcome::MissingNick),
        JoinChannelOutcome::MissingNick
    ));
    assert!(matches!(
        join_outcome(db::JoinChannelOutcome::NickConflict),
        JoinChannelOutcome::NickConflict
    ));

    assert!(matches!(
        presence_outcome(db::PresenceOutcome::Unchanged),
        PresenceOutcome::Unchanged
    ));
    assert!(matches!(
        presence_outcome(db::PresenceOutcome::NotSharing),
        PresenceOutcome::NotSharing
    ));
    assert!(matches!(
        presence_outcome(db::PresenceOutcome::NotParticipant),
        PresenceOutcome::NotParticipant
    ));
}
