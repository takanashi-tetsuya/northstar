use northstar_auth_postgres::users::{change_password, create_user, User};
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_application::{
    mix_service::{
        BeginRemotePamJoin, BeginRemotePamLeave, MixPamRepository, RemotePamCompletionOutcome,
        RemotePamJoin, SourceArchiveAdmission, NODE_MESSAGES,
    },
    muc_delivery::MucDeliveryRepository,
    room_delivery_policy::{
        MixRelayPolicyReader, PrivacyStanzaKind, RoomDeliveryDecision, RoomDeliveryPolicyQuery,
        RoomDeliveryPolicyReader, RoomPolicyRoute, RoomPolicySubject,
    },
};
use northstar_room_core::mix::MixChannelAddress;
use northstar_room_postgres::muc;
use northstar_roster_postgres::{
    privacy::{replace_privacy_list, set_active_privacy_list, ReplacePrivacyListOutcome},
    roster::{block_jids, lock_block_policy_in_transaction, unblock_jids},
};
use northstar_workflows::{
    mix_archive::archive_mix_message_once,
    muc_delivery_repository::{PostgresMucDeliveryRepository, PostgresRoomDeliveryPolicy},
    room_effects::PostgresMixRepository,
    sm::{self, SmSessionSnapshot},
};
use northstar_xep_0016::{PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

const OWNER: &str = "owner@example.test";
const LIVE: &str = "owner@example.test/Phone";
const ROOM: &str = "room@conference.example.test";
const OCCUPANT: &str = "room@conference.example.test/Nick";
const REAL: &str = "sender@example.test/Desk";
const CHANNEL: &str = "channel@mix.remote.test";
const ENCODED: &str = "other#channel@mix.remote.test/Phone";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    owner: User,
    connection_id: Uuid,
    policy: PostgresRoomDeliveryPolicy,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").unwrap();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("room_delivery_policy_{}", Uuid::new_v4().simple());
        super::muc::create_harness_owned_schema(&admin, &schema).await;
        let options = url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .unwrap()
            .options([("search_path", schema.as_str())]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .unwrap();
        crate::support::migrate(&pool).await.unwrap();
        let owner = create_user(
            &pool,
            "owner",
            "Initial password for test!42",
            false,
            true,
            4096,
            false,
        )
        .await
        .unwrap();
        let policy = PostgresRoomDeliveryPolicy::new(pool.clone());
        Self {
            admin,
            pool,
            schema,
            owner,
            connection_id: Uuid::new_v4(),
            policy,
        }
    }

    fn query<'a>(
        &self,
        peer: &'a str,
        kind: Option<PrivacyStanzaKind>,
    ) -> RoomDeliveryPolicyQuery<'a> {
        RoomDeliveryPolicyQuery {
            route: RoomPolicyRoute {
                account_id: self.owner.id,
                auth_generation: Some(self.owner.auth_generation),
                subject: RoomPolicySubject::Connection {
                    id: self.connection_id,
                    expects_active: false,
                },
            },
            visible_peer: peer,
            real_peer: None,
            kind,
            recipient_jid: LIVE,
        }
    }

    async fn decide(&self, query: RoomDeliveryPolicyQuery<'_>) -> RoomDeliveryDecision {
        let decisions = self
            .policy
            .read_room_delivery_policies(&[query])
            .await
            .unwrap();
        assert_eq!(decisions.len(), 1);
        decisions[0]
    }

    async fn list(&self, name: &str, action: PrivacyAction, peer: &str) {
        assert_eq!(
            replace_privacy_list(
                &self.pool,
                self.owner.id,
                &PrivacyList {
                    name: name.into(),
                    items: vec![PrivacyItem {
                        order: 1,
                        action,
                        match_type: Some(PrivacyMatchType::Jid),
                        match_value: Some(peer.into()),
                        message: true,
                        iq: true,
                        presence_in: true,
                        presence_out: false,
                    }],
                },
            )
            .await
            .unwrap(),
            ReplacePrivacyListOutcome::Stored
        );
    }

    async fn select(&self, name: &str) {
        assert!(
            set_active_privacy_list(&self.pool, self.owner.id, self.connection_id, Some(name),)
                .await
                .unwrap()
        );
    }

    async fn close(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }

    async fn join_remote_mix(&self) {
        let repository = PostgresMixRepository::new(self.pool.clone());
        let nodes = vec![NODE_MESSAGES.to_owned()];
        repository
            .begin_remote_pam_join(BeginRemotePamJoin {
                user_id: self.owner.id,
                actor_jid: OWNER.into(),
                channel_jid: CHANNEL.into(),
                nick: None,
                nodes: nodes.clone(),
                request_id: "join".into(),
                client_request_id: "client-join".into(),
                requester_full_jid: LIVE.into(),
                request_digest: [1; 32],
                remote_domain: "mix.remote.test".into(),
                outbound_stanza: format!(
                    "<iq type='set' id='join' from='{OWNER}' to='{CHANNEL}'/>"
                ),
                policy: S2sOutboxPolicy::new(60, 100, 1_000_000, 100),
            })
            .await
            .unwrap();
        assert!(matches!(
            repository
                .complete_remote_pam_success(
                    "mix.remote.test",
                    CHANNEL,
                    OWNER,
                    "join",
                    &[2; 32],
                    Some(RemotePamJoin {
                        participant_id: "opaque",
                        subscriptions: &nodes,
                        nick: None
                    }),
                )
                .await
                .unwrap(),
            RemotePamCompletionOutcome::Applied(_)
        ));
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn muc_replay_history_and_presence_use_live_visible_peer_policy() {
    let fixture = Fixture::new().await;
    fixture
        .list("deny-room", PrivacyAction::Deny, OCCUPANT)
        .await;
    fixture.select("deny-room").await;
    let (room, _) = muc::get_or_create_muc_room(&fixture.pool, "room", fixture.owner.id, LIVE)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted)
         VALUES($1,$2,$3,'Nick',$4,FALSE)",
    )
    .bind(Uuid::new_v4())
    .bind(room.id)
    .bind(REAL)
    .bind(format!(
        "<message from='{OCCUPANT}'><body>history</body></message>"
    ))
    .execute(&fixture.pool)
    .await
    .unwrap();
    let archived = muc::muc_history_since(&fixture.pool, room.id, 100, None)
        .await
        .unwrap();
    assert_eq!(archived.len(), 1);
    let document = roxmltree::Document::parse(&archived[0].stanza).unwrap();
    let visible_peer = document.root_element().attribute("from").unwrap();
    let history = RoomDeliveryPolicyQuery {
        real_peer: Some(&archived[0].sender_jid),
        ..fixture.query(visible_peer, Some(PrivacyStanzaKind::Message))
    };
    let presence = RoomDeliveryPolicyQuery {
        kind: Some(PrivacyStanzaKind::PresenceIn),
        ..history
    };
    assert_eq!(
        fixture
            .policy
            .read_room_delivery_policies(&[history, presence])
            .await
            .unwrap(),
        [RoomDeliveryDecision::PrivacyDenies; 2],
    );
    fixture.list("deny-room", PrivacyAction::Deny, REAL).await;
    assert_eq!(fixture.decide(history).await, RoomDeliveryDecision::Allow);
    block_jids(&fixture.pool, fixture.owner.id, &[REAL.into()])
        .await
        .unwrap();
    assert_eq!(fixture.decide(history).await, RoomDeliveryDecision::Blocked);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn decline_block_handover_stays_denied() {
    let fixture = Fixture::new().await;
    let account_id = fixture.owner.id;
    block_jids(&fixture.pool, account_id, &[REAL.into()])
        .await
        .unwrap();
    let query = RoomDeliveryPolicyQuery {
        real_peer: Some(REAL),
        ..fixture.query(ROOM, Some(PrivacyStanzaKind::Message))
    };
    assert_eq!(fixture.decide(query).await, RoomDeliveryDecision::Blocked);
    let mut barrier = fixture.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *barrier)
        .await
        .unwrap();
    let policy = fixture.policy.clone();
    let task = tokio::spawn(async move { policy.read_room_delivery_policies(&[query]).await });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query("UPDATE blocked_jids SET blocked_jid=$1 WHERE owner_id=$2 AND blocked_jid=$3")
        .bind(ROOM)
        .bind(account_id)
        .bind(REAL)
        .execute(&mut *barrier)
        .await
        .unwrap();
    barrier.commit().await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap(),
        [RoomDeliveryDecision::Blocked]
    );
    assert_eq!(fixture.decide(query).await, RoomDeliveryDecision::Blocked);
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn suspended_muc_delivery_uses_the_sm_selection_and_room_blocks() {
    let fixture = Fixture::new().await;
    fixture.list("sm-list", PrivacyAction::Deny, OCCUPANT).await;
    let snapshot = SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 0,
        acked_h: 0,
        available: true,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: Some("sm-list".into()),
        privacy_requested: true,
        peer_ip: "192.0.2.1".parse().unwrap(),
        user_agent_id: None,
        joined_rooms: vec![],
        directed_presence: vec![],
        last_presence: None,
        unacked: vec![],
    };
    let id = sm::create_sm_session(
        &fixture.pool,
        &[3; 32],
        fixture.owner.id,
        fixture.owner.auth_generation,
        LIVE,
        "Phone",
        "example.test",
        fixture.connection_id,
        &snapshot,
        300,
        30,
        8,
        100,
    )
    .await
    .unwrap();
    assert!(sm::suspend_sm_session(
        &fixture.pool,
        id,
        fixture.connection_id,
        &snapshot,
        300,
        8,
        4096
    )
    .await
    .unwrap());
    let mut query = fixture.query(OCCUPANT, Some(PrivacyStanzaKind::Message));
    query.route.subject = RoomPolicySubject::Suspended { id };
    query.real_peer = Some(REAL);
    assert_eq!(
        fixture.decide(query).await,
        RoomDeliveryDecision::PrivacyDenies
    );
    fixture
        .list("sm-list", PrivacyAction::Allow, OCCUPANT)
        .await;
    assert_eq!(fixture.decide(query).await, RoomDeliveryDecision::Allow);
    let repository = PostgresMucDeliveryRepository::new(fixture.pool.clone());
    assert!(repository
        .append_suspended_stanza(
            id,
            Uuid::new_v4(),
            &format!("<message from='{OCCUPANT}'/>"),
            8,
            4096,
        )
        .await
        .unwrap());
    block_jids(&fixture.pool, fixture.owner.id, &[REAL.into()])
        .await
        .unwrap();
    assert_eq!(fixture.decide(query).await, RoomDeliveryDecision::Blocked);
    query.route.subject = RoomPolicySubject::Suspended { id: Uuid::new_v4() };
    assert_eq!(
        fixture.decide(query).await,
        RoomDeliveryDecision::StaleRoute
    );
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn mix_archive_live_policy_and_relay_follow_route_and_membership_changes() {
    let fixture = Fixture::new().await;
    fixture.join_remote_mix().await;
    let channel = MixChannelAddress::parse(CHANNEL).unwrap();
    let mut live = fixture.query(CHANNEL, Some(PrivacyStanzaKind::Message));
    let mut relay = RoomDeliveryPolicyQuery {
        visible_peer: ENCODED,
        real_peer: Some(CHANNEL),
        kind: Some(PrivacyStanzaKind::Iq),
        ..live
    };
    fixture
        .list("channel-list", PrivacyAction::Deny, "mix.remote.test")
        .await;
    fixture.select("channel-list").await;
    assert_eq!(
        fixture.decide(live).await,
        RoomDeliveryDecision::PrivacyDenies
    );
    assert!(fixture
        .policy
        .read_remote_mix_relay(&relay, &channel)
        .await
        .unwrap()
        .is_none());
    // The personal archive is account-scoped. A resource's privacy selection gates its live copy.
    let archive = RoomDeliveryPolicyQuery {
        route: RoomPolicyRoute {
            subject: RoomPolicySubject::AccountDefault,
            ..live.route
        },
        kind: None,
        ..live
    };
    assert_eq!(fixture.decide(archive).await, RoomDeliveryDecision::Allow);
    let archive_id = Uuid::new_v4();
    assert_eq!(
        archive_mix_message_once(
            &fixture.pool,
            archive_id,
            fixture.owner.id,
            CHANNEL,
            Uuid::new_v4(),
            &format!("<message from='{CHANNEL}'><body>hello</body></message>"),
            false,
            None,
        )
        .await
        .unwrap(),
        SourceArchiveAdmission::Stored(archive_id)
    );

    fixture
        .list("channel-list", PrivacyAction::Allow, "mix.remote.test")
        .await;
    assert_eq!(fixture.decide(live).await, RoomDeliveryDecision::Allow);
    assert!(fixture
        .policy
        .read_remote_mix_relay(&relay, &channel)
        .await
        .unwrap()
        .is_some());
    block_jids(&fixture.pool, fixture.owner.id, &[CHANNEL.into()])
        .await
        .unwrap();
    assert_eq!(fixture.decide(archive).await, RoomDeliveryDecision::Blocked);
    assert!(fixture
        .policy
        .read_remote_mix_relay(&relay, &channel)
        .await
        .unwrap()
        .is_none());
    unblock_jids(&fixture.pool, fixture.owner.id, Some(&[CHANNEL.into()]))
        .await
        .unwrap();

    change_password(
        &fixture.pool,
        fixture.owner.id,
        "Replacement test password!42",
        4096,
        false,
    )
    .await
    .unwrap();
    assert_eq!(fixture.decide(live).await, RoomDeliveryDecision::StaleRoute);
    assert!(fixture
        .policy
        .read_remote_mix_relay(&relay, &channel)
        .await
        .unwrap()
        .is_none());
    live.route.auth_generation = Some(fixture.owner.auth_generation + 1);
    live.route.subject = RoomPolicySubject::Connection {
        id: Uuid::new_v4(),
        expects_active: false,
    };
    relay.route = live.route;
    assert_eq!(fixture.decide(live).await, RoomDeliveryDecision::Allow);
    assert!(fixture
        .policy
        .read_remote_mix_relay(&relay, &channel)
        .await
        .unwrap()
        .is_some());
    let repository = PostgresMixRepository::new(fixture.pool.clone());
    repository
        .begin_remote_pam_leave(BeginRemotePamLeave {
            user_id: fixture.owner.id,
            actor_jid: OWNER.into(),
            channel_jid: CHANNEL.into(),
            request_id: "leave".into(),
            client_request_id: "client-leave".into(),
            requester_full_jid: LIVE.into(),
            request_digest: [3; 32],
            remote_domain: "mix.remote.test".into(),
            outbound_stanza: format!("<iq type='set' id='leave' from='{OWNER}' to='{CHANNEL}'/>"),
            policy: S2sOutboxPolicy::new(60, 100, 1_000_000, 100),
        })
        .await
        .unwrap();
    assert!(matches!(
        repository
            .complete_remote_pam_success("mix.remote.test", CHANNEL, OWNER, "leave", &[4; 32], None)
            .await
            .unwrap(),
        RemotePamCompletionOutcome::Applied(_)
    ));
    assert!(fixture
        .policy
        .read_remote_mix_relay(&relay, &channel)
        .await
        .unwrap()
        .is_none());
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn remote_mix_relay_cannot_combine_joined_membership_with_a_later_unblock() {
    let fixture = Fixture::new().await;
    fixture.join_remote_mix().await;
    let account_id = fixture.owner.id;
    let channel = MixChannelAddress::parse(CHANNEL).unwrap();
    let policy = RoomDeliveryPolicyQuery {
        real_peer: Some(CHANNEL),
        ..fixture.query(ENCODED, Some(PrivacyStanzaKind::Iq))
    };
    assert!(fixture
        .policy
        .read_remote_mix_relay(&policy, &channel)
        .await
        .unwrap()
        .is_some());
    block_jids(&fixture.pool, account_id, &[CHANNEL.into()])
        .await
        .unwrap();
    let mut barrier = fixture.pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE blocked_jids IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *barrier)
        .await
        .unwrap();
    let reader = fixture.policy.clone();
    let task = tokio::spawn(async move { reader.read_remote_mix_relay(&policy, &channel).await });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query("DELETE FROM mix_pam_memberships WHERE user_id=$1 AND channel_jid=$2")
        .bind(account_id)
        .bind(CHANNEL)
        .execute(&mut *barrier)
        .await
        .unwrap();
    sqlx::query("DELETE FROM blocked_jids WHERE owner_id=$1 AND blocked_jid=$2")
        .bind(account_id)
        .bind(CHANNEL)
        .execute(&mut *barrier)
        .await
        .unwrap();
    barrier.commit().await.unwrap();
    assert!(task.await.unwrap().unwrap().is_none());
    fixture.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn muc_policy_read_neither_waits_for_nor_renews_the_active_lease() {
    let fixture = Fixture::new().await;
    fixture
        .list("selected", PrivacyAction::Allow, OCCUPANT)
        .await;
    fixture.select("selected").await;
    let repository = PostgresMucDeliveryRepository::new(fixture.pool.clone());
    let lease = "SELECT updated_at::text, expires_at::text FROM privacy_active_sessions
                 WHERE owner_id=$1 AND connection_id=$2";
    let mut writer = fixture.pool.begin().await.unwrap();
    lock_block_policy_in_transaction(&mut writer, fixture.owner.id)
        .await
        .unwrap();
    let before: (String, String) =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{lease} FOR UPDATE")))
            .bind(fixture.owner.id)
            .bind(fixture.connection_id)
            .fetch_one(&mut *writer)
            .await
            .unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        repository.privacy_allows_session(
            fixture.owner.id,
            fixture.connection_id,
            Some("selected"),
            OCCUPANT,
            PrivacyStanzaKind::Message,
        ),
    )
    .await
    .expect("MUC policy waited for the lease lock")
    .unwrap());
    let query = fixture.query(OCCUPANT, Some(PrivacyStanzaKind::Message));
    let decisions = tokio::time::timeout(
        Duration::from_secs(5),
        repository.read_room_delivery_policies(&[query]),
    )
    .await
    .expect("room policy waited for a lease or advisory lock")
    .unwrap();
    assert_eq!(decisions, [RoomDeliveryDecision::Allow]);
    writer.rollback().await.unwrap();
    let after: (String, String) = sqlx::query_as(lease)
        .bind(fixture.owner.id)
        .bind(fixture.connection_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    sqlx::query(
        "UPDATE privacy_active_sessions SET expires_at=statement_timestamp()-interval '1 second'
                 WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(fixture.owner.id)
    .bind(fixture.connection_id)
    .execute(&fixture.pool)
    .await
    .unwrap();
    assert!(!repository
        .privacy_allows_session(
            fixture.owner.id,
            fixture.connection_id,
            Some("selected"),
            OCCUPANT,
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());
    let replacement = Uuid::new_v4();
    assert!(!repository
        .privacy_allows_session(
            fixture.owner.id,
            replacement,
            Some("selected"),
            OCCUPANT,
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());
    assert!(repository
        .privacy_allows_session(
            fixture.owner.id,
            replacement,
            None,
            OCCUPANT,
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());
    fixture.close().await;
}
