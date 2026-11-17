use super::*;
use northstar_delivery_core::sm_ownership::{Purpose, Scope, Terminal};
use northstar_delivery_core::{DurableDelivery, MixDelivery};

#[test]
fn prepared_checkpoint_rejects_each_changed_projection_and_retired_turn() {
    let session = Uuid::from_u128(1);
    let connection = Uuid::from_u128(2);
    let c2s = TransportOwnershipSource::C2s(DurableDelivery {
        recipient_id: Uuid::from_u128(3),
        message_id: Uuid::from_u128(4),
        claim_id: Some(Uuid::from_u128(5)),
    });
    let mix = TransportOwnershipSource::Mix(MixDelivery {
        delivery_id: Uuid::from_u128(6),
        lease_token: Uuid::from_u128(7),
    });
    let acknowledged = vec![
        SmUnackedStanza::plain("<message id='plain'/>".into()),
        SmUnackedStanza::with_source("<message id='c2s'/>".into(), Some(c2s)),
    ];
    let snapshot = SmSessionSnapshot {
        inbound_h: 9,
        outbound_h: 1,
        acked_h: 0,
        available: true,
        carbons: true,
        priority: -3,
        blocklist_requested: true,
        roster_requested: true,
        active_privacy_list: Some("friends".into()),
        privacy_requested: true,
        peer_ip: "192.0.2.1".parse().unwrap(),
        user_agent_id: Some(Uuid::from_u128(8)),
        joined_rooms: vec![
            SmMucMembership::new("room@example.test".into(), "nick".into()),
            SmMucMembership::new("other@example.test".into(), "other".into()),
        ],
        directed_presence: vec![
            "friend@example.test/resource".into(),
            "other@example.test".into(),
        ],
        last_presence: Some("<presence/>".into()),
        unacked: vec![SmUnackedStanza::with_source(
            "<message id='mix'/>".into(),
            Some(mix),
        )],
    };
    let policy = CheckpointPolicy {
        ttl_seconds: 90,
        live_lease_seconds: 43,
        max_stanzas: 17,
        max_bytes: 801,
    };
    let whole: VecDeque<_> = acknowledged
        .iter()
        .chain(&snapshot.unacked)
        .cloned()
        .collect();
    let observation = Observation::new(Scope {
        purpose: Purpose::Acknowledge { h: 0 },
        session_id: Some(session),
        connection_id: connection,
        inbound_h: 9,
        outbound_h: 1,
        acked_h: u32::MAX - 1,
        queued: 3,
    });
    observation.h_decision(Some(2));
    let prepared = PreparedCheckpoint::bind(
        &observation,
        session,
        connection,
        &whole,
        &snapshot,
        &acknowledged,
        policy,
    )
    .unwrap();
    assert!(std::ptr::eq(prepared.snapshot(), &snapshot));
    assert_eq!(prepared.acknowledged(), acknowledged.as_slice());
    assert_eq!(prepared.policy(), policy);
    prepared
        .validate_projection(
            session,
            connection,
            SnapshotProjection::from(&snapshot),
            &acknowledged,
            policy,
        )
        .unwrap();

    for label in [
        "session",
        "connection",
        "inbound h",
        "outbound h",
        "acked h",
        "available",
        "carbons",
        "priority",
        "blocklist",
        "roster",
        "privacy selection",
        "privacy requested",
        "peer ip",
        "device",
        "room jid",
        "room nick",
        "room order",
        "directed presence",
        "last presence",
        "remaining bytes",
        "remaining source",
        "ack bytes",
        "ack source",
        "ack order",
        "ttl",
        "lease",
        "stanza limit",
        "byte limit",
    ] {
        let mut actual_session = session;
        let mut actual_connection = connection;
        let mut actual_snapshot = snapshot.clone();
        let mut actual_acknowledged = acknowledged.clone();
        let mut actual_policy = policy;
        match label {
            "session" => actual_session = Uuid::from_u128(99),
            "connection" => actual_connection = Uuid::from_u128(99),
            "inbound h" => actual_snapshot.inbound_h += 1,
            "outbound h" => actual_snapshot.outbound_h += 1,
            "acked h" => actual_snapshot.acked_h += 1,
            "available" => actual_snapshot.available = false,
            "carbons" => actual_snapshot.carbons = false,
            "priority" => actual_snapshot.priority += 1,
            "blocklist" => actual_snapshot.blocklist_requested = false,
            "roster" => actual_snapshot.roster_requested = false,
            "privacy selection" => actual_snapshot.active_privacy_list = None,
            "privacy requested" => actual_snapshot.privacy_requested = false,
            "peer ip" => actual_snapshot.peer_ip = "192.0.2.2".parse().unwrap(),
            "device" => actual_snapshot.user_agent_id = None,
            "room jid" => actual_snapshot.joined_rooms[0].room_jid.push_str("/other"),
            "room nick" => actual_snapshot.joined_rooms[0].nick.push_str("other"),
            "room order" => actual_snapshot.joined_rooms.reverse(),
            "directed presence" => actual_snapshot.directed_presence.reverse(),
            "last presence" => actual_snapshot.last_presence = None,
            "remaining bytes" => actual_snapshot.unacked[0].stanza.push(' '),
            "remaining source" => actual_snapshot.unacked[0].source = Some(c2s),
            "ack bytes" => actual_acknowledged[0].stanza.push(' '),
            "ack source" => actual_acknowledged[1].source = Some(mix),
            "ack order" => actual_acknowledged.reverse(),
            "ttl" => actual_policy.ttl_seconds += 1,
            "lease" => actual_policy.live_lease_seconds += 1,
            "stanza limit" => actual_policy.max_stanzas += 1,
            "byte limit" => actual_policy.max_bytes += 1,
            _ => unreachable!(),
        }
        assert!(
            prepared
                .validate_projection(
                    actual_session,
                    actual_connection,
                    SnapshotProjection::from(&actual_snapshot),
                    &actual_acknowledged,
                    actual_policy,
                )
                .is_err(),
            "{label}: changed projection accepted",
        );
    }

    observation.retire(Terminal::Returned);
    assert!(
        prepared
            .validate_projection(
                session,
                connection,
                SnapshotProjection::from(&snapshot),
                &acknowledged,
                policy,
            )
            .is_err(),
        "retired turn: matching projection accepted"
    );
}
