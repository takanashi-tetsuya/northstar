use super::*;
use northstar_room_core::mix::{
    MixAccessModel, MixAdministratorRetractionRights, MixChannelAddress, MixChannelId, MixRole,
};
use uuid::Uuid;

#[test]
fn hosted_items_hide_absence_and_map_nodes_by_role() {
    let mut view = HostedDiscoView {
        channel_id: MixChannelId::new(Uuid::nil()),
        address: MixChannelAddress::parse("channel@mix.test").unwrap(),
        name: None,
        revision: 0,
        discoverable: false,
        access_model: MixAccessModel::Open,
        actor_admitted: true,
        visible_to_actor: false,
        actor_role: None,
        allow_user_message_retraction: false,
        administrator_retraction_rights: MixAdministratorRetractionRights::Nobody,
        allow_private_messages: false,
        muc_room_id: None,
    };
    let render = |view: Option<&HostedDiscoView>, node: Option<&str>| {
        reply(
            view,
            node,
            "request",
            "channel@mix.test",
            super::super::disco_items_query(node),
        )
    };
    for node in [None, Some("mix"), Some("unknown")] {
        let absent = render(None, node);
        assert!(absent.contains("<item-not-found"));
        assert_eq!(render(Some(&view), node), absent);
    }
    view.visible_to_actor = true;
    let no_node = render(Some(&view), None);
    assert!(no_node.contains("type='result'"));
    assert!(!no_node.contains("<item"));
    assert!(render(Some(&view), Some("unknown")).contains("<item-not-found"));
    let ordinary = render(Some(&view), Some("mix"));
    for node in CORE_NODES
        .into_iter()
        .chain([NODE_AVATAR_DATA, NODE_AVATAR_METADATA])
    {
        assert!(ordinary.contains(node), "{node}");
    }
    view.actor_role = Some(MixRole::Administrator);
    let privileged = render(Some(&view), Some("mix"));
    for node in [NODE_CONFIG, NODE_ALLOWED, NODE_BANNED, NODE_JIDMAP] {
        assert!(!ordinary.contains(node), "{node}");
        assert!(privileged.contains(node), "{node}");
    }
}
