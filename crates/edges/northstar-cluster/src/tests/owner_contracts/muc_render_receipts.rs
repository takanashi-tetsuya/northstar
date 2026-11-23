use super::*;
use northstar_room_core::{
    ClusterMucEventOccupant, ClusterMucOccupancyTarget, ClusterMucPolicySnapshot,
};
use serde_json::json;

impl Ports {
    pub(super) fn check_render_item(&self, ordinal: i32, stable: &str) {
        assert!((0..self.0.render_items).contains(&ordinal));
        assert_eq!(stable, format!("{}:{ordinal}", self.0.row.event_id));
    }
}

fn event_fixture(
    kind: &str,
    committed_whois: Option<bool>,
    committed_role: &str,
    current_whois: bool,
    current_role: Option<&str>,
    self_presence: bool,
) -> Fixture {
    let count = if matches!(kind, "rename" | "config") {
        2
    } else {
        1
    };
    let fixture = Fixture::for_render(count, committed_role, committed_whois.is_some());
    let route = northstar_room_core::stanza::muc_occupant_key(
        &fixture.recipient.room_jid,
        &fixture.recipient.nick,
    );
    if let Some(role) = current_role {
        fixture
            .worker
            .endpoints
            .occupants
            .get_mut(&route)
            .unwrap()
            .role = role.into();
    } else {
        fixture.worker.endpoints.occupants.remove(&route).unwrap();
    }
    let row = &fixture.ports.0.row;
    let (jid, bare, nick, incarnation, occupancy, connection, epoch) = if self_presence {
        (
            fixture.recipient.full_jid.as_str(),
            "alice@example.test",
            fixture.recipient.nick.as_str(),
            fixture.recipient.cluster_epoch,
            23,
            fixture.recipient.connection_id,
            29,
        )
    } else {
        (
            "bob@example.test/Phone",
            "bob@example.test",
            "Bob",
            Uuid::from_u128(90),
            90,
            Uuid::from_u128(91),
            91,
        )
    };
    let target = ClusterMucOccupancyTarget {
        room_id: row.room_id,
        room_epoch: row.room_epoch,
        occupant_incarnation: incarnation,
        occupancy_epoch: occupancy,
        full_jid: jid.into(),
        nick: nick.into(),
        connection_uuid: connection,
        connection_epoch: epoch,
    };
    let snapshot = ClusterMucPolicySnapshot {
        room_id: row.room_id,
        room_epoch: row.room_epoch,
        occupant_incarnation: incarnation,
        occupancy_epoch: occupancy,
        full_jid: jid.into(),
        bare_jid: bare.into(),
        nick: nick.into(),
        connection_uuid: connection,
        connection_epoch: epoch,
        sm_session_id: None,
        role: "participant".into(),
        affiliation: "member".into(),
        state: "active".into(),
    };
    let change = json!({"kind":"presence", "target":target, "snapshot":snapshot});
    let mut context = fixture.ports.0.context.lock().unwrap();
    context.operation_kind = match kind {
        "affiliation_offline" => "affiliation",
        "admin_batch_offline" => "admin_batch",
        _ => kind,
    }
    .into();
    context.room_non_anonymous = current_whois;
    context.actor_full_jid = Some(fixture.recipient.full_jid.clone());
    context.details = match kind {
        "rename" => json!({"old_nick":"Before", "new_nick":nick}),
        "affiliation" => json!({"changes":[change]}),
        "affiliation_offline" => json!({"changes":[], "offline_affiliation":{
            "bare_jid":"bob@example.test", "affiliation":"member", "nick":"Bob", "reason":"invited"
        }}),
        "config" => json!({"affected":[change]}),
        "admin_batch" => {
            json!({"non_anonymous":committed_whois.unwrap_or(true), "changes":[change], "request_change_count":1})
        }
        "admin_batch_offline" => {
            json!({"non_anonymous":true, "request_change_count":1, "changes":[{
                "kind":"offline_affiliation", "bare_jid":"bob@example.test", "affiliation":"member",
                "nick":"Bob", "reason":"invited"
            }]})
        }
        _ => json!({}),
    };
    if let Some(non_anonymous) = committed_whois {
        context.details["render_policy"] =
            json!({"non_anonymous":non_anonymous,"actor_nick":"AtCommit"});
    }
    if matches!(
        kind,
        "join"
            | "resume"
            | "role"
            | "rename"
            | "kick"
            | "ban"
            | "leave"
            | "expire"
            | "account_delete"
    ) {
        context.target = Some(ClusterMucEventOccupant {
            full_jid: jid.into(),
            bare_jid: bare.into(),
            nick: nick.into(),
            affiliation: "member".into(),
            role: "participant".into(),
            presence_payload: String::new(),
            occupant_incarnation: incarnation,
            occupancy_epoch: occupancy,
            connection_uuid: connection,
            connection_epoch: epoch,
        });
    }
    drop(context);
    fixture
}

#[tokio::test(start_paused = true)]
async fn management_items_apply_both_policies_and_hide_legacy_rows() {
    let cases = [
        (
            Some(true),
            "participant",
            true,
            Some("participant"),
            false,
            true,
        ),
        (
            Some(true),
            "participant",
            false,
            Some("participant"),
            false,
            false,
        ),
        (
            Some(false),
            "moderator",
            false,
            Some("participant"),
            false,
            false,
        ),
        (
            Some(false),
            "participant",
            true,
            Some("moderator"),
            false,
            false,
        ),
        (
            Some(false),
            "moderator",
            false,
            Some("moderator"),
            false,
            true,
        ),
        (Some(false), "moderator", false, None, false, true),
        (None, "moderator", true, Some("moderator"), false, false),
        (None, "participant", false, Some("participant"), true, true),
    ];
    for kind in [
        "join",
        "resume",
        "role",
        "rename",
        "kick",
        "ban",
        "leave",
        "expire",
        "account_delete",
        "affiliation",
        "config",
        "admin_batch",
        "destroy",
        "locked_expiry",
    ] {
        for (committed, original_role, current, cached_role, self_presence, disclose) in cases {
            let mut fixture = event_fixture(
                kind,
                committed,
                original_role,
                current,
                cached_role,
                self_presence,
            );
            let delivery = deliver_cluster_muc_event(&fixture.worker, &fixture.ports.0.row);
            tokio::pin!(delivery);
            for ordinal in 0..fixture.ports.0.render_items {
                // The previous item's receipt is settled by other tasks: yield until this
                // item reaches transport, while the delivery itself stays pending.
                let mut sent = None;
                for _ in 0..64 {
                    assert!(
                        futures::poll!(delivery.as_mut()).is_pending(),
                        "{kind} ordinal {ordinal}"
                    );
                    match fixture.output.try_recv() {
                        Ok(output) => {
                            sent = Some(output);
                            break;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
                        Err(error) => panic!("{kind} ordinal {ordinal}: {error:?}"),
                    }
                }
                let output = sent.unwrap_or_else(|| {
                    panic!(
                        "{kind} ordinal {ordinal}: {committed:?}/{original_role}/{current}/\
                         {cached_role:?}/{self_presence}: nothing reached transport"
                    )
                });
                let xml = roxmltree::Document::parse(&output.stanza).unwrap();
                if kind == "config" && ordinal == 1 {
                    let status = xml
                        .descendants()
                        .find(|node| {
                            node.has_tag_name(("http://jabber.org/protocol/muc#user", "status"))
                        })
                        .unwrap();
                    assert_eq!(status.attribute("code"), Some("104"));
                } else {
                    let item = xml
                        .descendants()
                        .find(|node| {
                            node.has_tag_name(("http://jabber.org/protocol/muc#user", "item"))
                        })
                        .unwrap();
                    let visible_jid = (disclose && !matches!(kind, "destroy" | "locked_expiry"))
                        .then_some(if self_presence {
                            "alice@example.test/Phone"
                        } else {
                            "bob@example.test/Phone"
                        });
                    assert_eq!(
                        item.attribute("jid"),
                        visible_jid,
                        "{kind}: {committed:?}/{current}/{cached_role:?}"
                    );
                    if matches!(kind, "kick" | "ban") {
                        let actor = item.children().find(|node| {
                            node.has_tag_name(("http://jabber.org/protocol/muc#user", "actor"))
                        });
                        assert_eq!(
                            actor.and_then(|node| node.attribute("nick")),
                            committed.map(|_| "AtCommit")
                        );
                    }
                }
                output.confirm_transport_ownership();
            }
            delivery.await.unwrap();
            if committed.is_some() && cached_role.is_some() {
                assert!(!fixture.ports.calls().contains(&"original"));
                assert!(!fixture.ports.calls().contains(&"snapshot"));
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn offline_affiliation_notices_keep_their_ordinal_without_disclosing_the_bare_jid() {
    for kind in ["affiliation_offline", "admin_batch_offline"] {
        for (committed, current, expected) in [
            (Some(true), true, Some("bob@example.test")),
            (Some(true), false, None),
            (None, true, None),
        ] {
            let mut fixture = event_fixture(
                kind,
                committed,
                "participant",
                current,
                Some("participant"),
                false,
            );
            let delivery = deliver_cluster_muc_event(&fixture.worker, &fixture.ports.0.row);
            tokio::pin!(delivery);
            assert!(futures::poll!(delivery.as_mut()).is_pending());
            let output = fixture.output.try_recv().unwrap();
            let xml = roxmltree::Document::parse(&output.stanza).unwrap();
            let item = xml
                .descendants()
                .find(|node| node.has_tag_name(("http://jabber.org/protocol/muc#user", "item")))
                .unwrap();
            assert_eq!(item.attribute("jid"), expected);
            assert_eq!(item.attribute("nick"), Some("Bob"));
            assert_eq!(item.attribute("affiliation"), Some("member"));
            output.confirm_transport_ownership();
            delivery.await.unwrap();
        }
    }
}

#[tokio::test(start_paused = true)]
async fn stale_reservation_never_reaches_transport_or_completion() {
    let mut fixture = Fixture::new();
    fixture
        .ports
        .0
        .stale_reservation
        .store(true, Ordering::Relaxed);
    let error = deliver_cluster_muc_event(&fixture.worker, &fixture.ports.0.row)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "cluster MUC delivery item reservation lost its exact claim"
    );
    assert!(matches!(
        fixture.output.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(!fixture.ports.calls().contains(&"complete"));
    assert!(!fixture.ports.calls().contains(&"renew"));
}
