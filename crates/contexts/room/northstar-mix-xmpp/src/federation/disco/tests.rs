use super::*;
use northstar_room_core::mix::{MixAccessModel, MixChannelId};
use uuid::Uuid;

#[test]
fn hosted_info_features_follow_the_projection() {
    let mut view = HostedDiscoView {
        channel_id: MixChannelId::new(Uuid::nil()),
        address: MixChannelAddress::parse("channel@mix.test").unwrap(),
        name: None,
        revision: 0,
        discoverable: true,
        access_model: MixAccessModel::Open,
        actor_admitted: true,
        visible_to_actor: true,
        actor_role: None,
        allow_user_message_retraction: false,
        administrator_retraction_rights: MixAdministratorRetractionRights::Nobody,
        allow_private_messages: false,
        muc_room_id: None,
    };
    let without = hosted_info_payload(&view, true, false, "conference.test").unwrap();
    assert!(without.contains("name='channel'"));
    for absent in [
        "#muc-mirror",
        "#message-retract",
        "#private-messages",
        northstar_xep_0313::DISCO_FEATURE_MAM,
    ] {
        assert!(!without.contains(absent), "{absent}");
    }
    view.name = Some("Updated name".to_owned());
    view.muc_room_id = Some(Uuid::nil());
    view.allow_private_messages = true;
    view.administrator_retraction_rights = MixAdministratorRetractionRights::Owners;
    let with = hosted_info_payload(&view, true, true, "conference.test").unwrap();
    for present in [
        "name='Updated name'",
        "#muc-mirror",
        "#message-retract",
        "#private-messages",
        northstar_xep_0313::DISCO_FEATURE_MAM,
    ] {
        assert!(with.contains(present), "{present}");
    }
    let disabled = hosted_info_payload(&view, false, false, "conference.test").unwrap();
    assert!(!disabled.contains("#muc-mirror"));
}
