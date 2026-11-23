use super::*;
use northstar_room_core::occupancy::{MucOccupantEndpoint, SerializableMucOccupant};
use northstar_room_core::{stanza::muc_presence_stanza, ClusterMucOccupancy};
use northstar_time::DateTime;
use uuid::Uuid;

#[test]
fn join_presence_renders_committed_policy_not_the_preclaim_snapshot() {
    let actor = ClusterMucOccupancy {
        room_id: Uuid::from_u128(1),
        room_epoch: Uuid::from_u128(2),
        occupant_incarnation: Uuid::from_u128(3),
        occupancy_epoch: 4,
        config_version: 5,
        identity_kind: "local".to_owned(),
        local_user_id: Some(Uuid::from_u128(6)),
        bare_jid: "alice@example.test".to_owned(),
        full_jid: "alice@example.test/phone".to_owned(),
        nick: "Alice".to_owned(),
        authenticated_domain: None,
        owner_node_id: "node".to_owned(),
        connection_uuid: Uuid::from_u128(7),
        connection_epoch: 1,
        sm_session_id: None,
        role: "moderator".to_owned(),
        affiliation: "admin".to_owned(),
        state: "active".to_owned(),
        presence_payload: "<show>away</show>".to_owned(),
        lease_until: DateTime::from_timestamp(0, 0).unwrap(),
    };
    let mut room = MucRoom {
        id: actor.room_id,
        room_epoch: actor.room_epoch,
        config_version: actor.config_version,
        localpart: "room".to_owned(),
        title: None,
        description: None,
        persistent: false,
        members_only: false,
        public: true,
        moderated: false,
        non_anonymous: true,
        max_occupants: 100,
        subject: None,
        subject_changed_at: None,
        allow_subject_change: false,
        allow_invites: true,
        allow_private_messages: true,
        logging_enabled: true,
        allow_registration: true,
        password_hash: None,
        occupant_id_secret: vec![1; 32],
        configuration_owner_jid: None,
        configuration_expires_at: None,
    };
    let mut occupant = MucOccupant::<(), ()> {
        full_jid: actor.full_jid.clone(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: actor.nick.clone(),
        endpoint: MucOccupantEndpoint::Local(()),
        affiliation: "none".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: true,
        occupant_id: "preclaim".to_owned(),
        cluster_epoch: actor.occupant_incarnation,
        connection_id: Uuid::from_u128(8),
        sm_session_id: None,
        payload: String::new(),
    };
    let projection = MucJoinProjection {
        actor,
        occupant_id: "committed".to_owned(),
        non_anonymous: false,
        logging_enabled: true,
        max_occupants: 100,
        subject: None,
        subject_changed_at: None,
        occupant_id_secret: vec![2; 32],
        roster: Vec::new(),
        history: Vec::new(),
    };
    assert!(apply_committed_join(&mut occupant, &mut room, &projection).is_err());
    assert_eq!(occupant.role, "participant");
    occupant.connection_id = projection.actor.connection_uuid;
    apply_committed_join(&mut occupant, &mut room, &projection).unwrap();
    let xml = muc_presence_stanza(
        &SerializableMucOccupant::from(&occupant),
        &occupant.full_jid,
        false,
        true,
        false,
        None,
        true,
    );
    let document = roxmltree::Document::parse(&xml).unwrap();
    let item = document
        .descendants()
        .find(|node| node.has_tag_name("item"))
        .unwrap();
    assert_eq!(item.attribute("role"), Some("moderator"));
    assert_eq!(item.attribute("affiliation"), Some("admin"));
    assert!(!occupant.room_non_anonymous);
    assert_eq!(occupant.occupant_id, "committed");
}
