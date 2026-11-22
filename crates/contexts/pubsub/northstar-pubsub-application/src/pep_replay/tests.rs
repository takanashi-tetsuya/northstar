use super::*;
use northstar_pubsub_core::{default_pep_node_config, PubSubAccount, PubSubAddress};
use uuid::Uuid;

fn query(requester: &str, mode: PepReplayMode) -> PepReplayQuery {
    PepReplayQuery {
        requester: PubSubAddress::parse(requester).unwrap(),
        mode,
        local_domain: "example.test".to_owned(),
        after: None,
        limit: DEFAULT_PEP_REPLAY_LIMIT,
    }
}

#[test]
fn send_last_modes_and_notification_flag_apply_to_the_replay_trigger() {
    let mut config = default_pep_node_config("news");
    let mut direct = PepReplayMode::AfterSubscribe {
        owner: PubSubAccount {
            id: Uuid::nil(),
            username: "owner".to_owned(),
            auth_generation: 0,
        },
        node: "news".to_owned(),
        on_presence: false,
    };
    for (send_last, deliver, on_presence, on_subscribe) in [
        ("never", true, false, false),
        ("on_sub", true, false, true),
        ("on_sub_and_presence", true, true, true),
        ("on_sub_and_presence", false, false, false),
    ] {
        config.send_last_published_item = send_last.to_owned();
        config.deliver_notifications = deliver;
        assert_eq!(
            pep_replay_origin(&PepReplayMode::Explicit, &config, true).is_some(),
            on_presence,
        );
        assert_eq!(
            pep_replay_origin(&direct, &config, true).is_some(),
            on_subscribe,
        );
    }
    config.deliver_notifications = true;
    config.send_last_published_item = "on_sub".to_owned();
    if let PepReplayMode::AfterSubscribe { on_presence, .. } = &mut direct {
        *on_presence = true;
    }
    assert_eq!(pep_replay_origin(&direct, &config, true), None);
}

#[test]
fn explicit_subscription_suppresses_both_kinds_of_automatic_replay() {
    let mut config = default_pep_node_config("news");
    config.send_last_published_item = "on_sub_and_presence".to_owned();
    config.deliver_notifications = true;
    assert_eq!(
        pep_replay_origin(&PepReplayMode::Explicit, &config, true),
        Some(PepReplayOrigin::Explicit),
    );
    assert_eq!(
        pep_replay_origin(&PepReplayMode::Explicit, &config, false),
        None
    );
    for mode in [
        PepReplayMode::LocalCaps {
            wanted: vec!["news".to_owned()],
        },
        PepReplayMode::FederatedCaps {
            wanted: vec!["news".to_owned()],
        },
    ] {
        assert_eq!(pep_replay_origin(&mode, &config, true), None);
        assert_eq!(
            pep_replay_origin(&mode, &config, false),
            Some(PepReplayOrigin::Automatic),
        );
    }
}

#[test]
fn local_caps_replays_self_and_only_local_to_or_both_roster_contacts() {
    let local = query(
        "reader@example.test/desk",
        PepReplayMode::LocalCaps {
            wanted: vec!["news".to_owned()],
        },
    );
    assert_eq!(
        pep_replay_local_owner(&local, None).as_deref(),
        Some("reader")
    );
    for (contact, subscription, expected) in [
        ("OWNER@EXAMPLE.TEST", "to", Some("owner")),
        ("owner@example.test", "both", Some("owner")),
        ("owner@example.test", "from", None),
        ("owner@example.test", "none", None),
        ("owner@remote.test", "both", None),
        ("example.test", "both", None),
        ("owner@example.test/desk", "both", None),
    ] {
        assert_eq!(
            pep_replay_local_owner(&local, Some((contact, subscription))).as_deref(),
            expected,
        );
    }
}

#[test]
fn caps_replay_checks_resource_and_local_or_remote_domain() {
    for (requester, local, federated) in [
        ("reader@example.test/desk", true, false),
        ("reader@remote.test/desk", false, true),
        ("reader@example.test", false, false),
        ("reader@remote.test", false, false),
        ("example.test/desk", false, false),
        ("remote.test/desk", false, true),
    ] {
        let wanted = vec!["news".to_owned()];
        assert_eq!(
            pep_replay_request_allowed(&query(
                requester,
                PepReplayMode::LocalCaps {
                    wanted: wanted.clone()
                },
            )),
            local,
        );
        assert_eq!(
            pep_replay_request_allowed(&query(requester, PepReplayMode::FederatedCaps { wanted })),
            federated,
        );
    }
    assert!(!pep_replay_request_allowed(&query(
        "reader@example.test/desk",
        PepReplayMode::LocalCaps { wanted: Vec::new() },
    )));
}
