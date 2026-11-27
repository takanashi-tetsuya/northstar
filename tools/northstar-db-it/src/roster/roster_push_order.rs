use super::presence_service::IsolatedDatabase;
use northstar_abuse_application::guard::{
    test_mix_message_content_keyring, test_mix_retraction_content_keyring,
};
use northstar_auth_postgres::users::{change_password, create_user, User};
use northstar_room_application::mix_service::{
    HostedMixOutcome, JoinMixRequest, MixPayloads, MixService,
};
use northstar_room_core::mix::MixChannelId;
use northstar_room_postgres::mix;
use northstar_roster_application::{
    RosterGetCommand, RosterService, RosterUpsertCommand, S2sOutboxPolicy,
};
use northstar_roster_core::{
    RosterAuthorization, RosterChange, RosterFlushBatch, RosterGap, RosterPushDisposition,
    RosterReadSnapshot, RosterSyncGate, RosterVersion,
};
use northstar_roster_postgres::roster::read_roster_gap;
use northstar_workflows::{
    room_effects::{PostgresMixRepository, WorkflowRoomEffects},
    roster::{PostgresRosterRepository, WorkflowRosterEffects},
};
use sqlx::PgPool;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

struct Fixture {
    database: IsolatedDatabase,
    owner: User,
    roster: RosterService<PostgresRosterRepository>,
}

impl Fixture {
    async fn new() -> Self {
        let database = IsolatedDatabase::create("roster_push_order").await;
        let owner = create_user(
            &database.pool,
            "alice",
            "Initial password for test!42",
            false,
            true,
            4096,
            false,
        )
        .await
        .unwrap();
        let roster = RosterService::new(PostgresRosterRepository::new(
            database.pool.clone(),
            WorkflowRosterEffects,
        ));
        Self {
            database,
            owner,
            roster,
        }
    }

    async fn change(&self, contact_jid: &str, name: &str) -> RosterChange {
        let RosterAuthorization::Authorized(change) = self
            .roster
            .execute_roster_upsert(RosterUpsertCommand {
                owner_id: self.owner.id,
                expected_auth_generation: self.owner.auth_generation,
                jid: contact_jid.to_owned(),
                name: Some(name.to_owned()),
                groups: Vec::new(),
            })
            .await
            .unwrap()
        else {
            panic!("the test owner must be authorized")
        };
        change
    }

    async fn snapshot(&self, annotations_requested: bool) -> RosterReadSnapshot {
        let RosterAuthorization::Authorized(snapshot) = self
            .roster
            .execute_roster_get(RosterGetCommand {
                owner_id: self.owner.id,
                expected_auth_generation: self.owner.auth_generation,
                requested_version: None,
                annotations_requested,
            })
            .await
            .unwrap()
        else {
            panic!("the test owner must be authorized")
        };
        snapshot
    }
}

async fn join_annotated_channel(pool: &PgPool, owner: &User) -> (i64, String) {
    let (outcome, _) = mix::create_mix_channel(
        &WorkflowRoomEffects,
        pool,
        "mix.example.test",
        Some("room"),
        "creator@example.test",
        100,
        &MixPayloads,
        None,
    )
    .await
    .unwrap();
    let mix::CreateChannelOutcome::Created(channel_id) = outcome else {
        panic!("expected a new channel")
    };
    let service = MixService::new(
        PostgresMixRepository::new(pool.clone()),
        test_mix_message_content_keyring(),
        test_mix_retraction_content_keyring(),
        4,
        "roster-push-order".to_owned(),
    )
    .unwrap();
    let HostedMixOutcome::Present(joined) = service
        .join_hosted_mix_committed(
            &MixChannelId::new(channel_id),
            JoinMixRequest {
                actor_jid: "alice@example.test".to_owned(),
                nick: Some("alice".to_owned()),
                nodes: vec![mix::NODE_MESSAGES.to_owned()],
                pam_user_id: Some(owner.id),
                invitation: None,
                preference: None,
                anonymous_profile: false,
            },
            None,
        )
        .await
        .unwrap()
    else {
        panic!("expected a hosted join")
    };
    let delta = &joined.roster[0];
    assert_eq!(
        delta.change.owner_authority,
        Some((owner.id, owner.auth_generation))
    );
    (
        delta.version,
        delta.participant_annotation.as_ref().unwrap().to_string(),
    )
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn delayed_first_commit_is_covered_by_the_get_before_second_commit_is_flushed() {
    let fixture = Fixture::new().await;
    let gate = Arc::new(RosterSyncGate::default());
    let requested = Arc::new(AtomicBool::new(false));
    let annotations = Arc::new(AtomicBool::new(false));
    let sync = gate.begin(&requested, &annotations, false).unwrap();
    let first = fixture.change("bob@example.test", "First").await;
    let (release_first, delayed_first) = tokio::sync::oneshot::channel::<()>();
    let first_version = first.version;
    let (task_gate, task_requested, task_annotations) = (
        Arc::clone(&gate),
        Arc::clone(&requested),
        Arc::clone(&annotations),
    );
    let first_push = tokio::spawn(async move {
        delayed_first.await.unwrap();
        task_gate.route(
            &task_requested,
            &task_annotations,
            first_version,
            "first".into(),
            None,
            |_| unreachable!(),
        )
    });
    let snapshot = fixture.snapshot(false).await;
    assert_eq!(snapshot.version, first.version);
    assert_eq!(snapshot.items[0].display_name.as_deref(), Some("First"));
    let second = fixture.change("bob@example.test", "Second").await;
    assert_eq!(second.version, snapshot.version + 1);
    assert_eq!(
        gate.route(
            &requested,
            &annotations,
            second.version,
            "second".into(),
            None,
            |_| unreachable!()
        ),
        RosterPushDisposition::Buffered
    );
    assert_eq!(
        gate.start_flush(sync, snapshot.version),
        RosterFlushBatch::Batch(vec![(second.version, "second".into())])
    );
    release_first.send(()).unwrap();
    assert_eq!(first_push.await.unwrap(), RosterPushDisposition::Covered);
    assert!(gate.accept_flushed(sync, second.version));
    assert_eq!(gate.next_flush_batch(sync), RosterFlushBatch::Complete);
    assert_eq!(
        gate.route(
            &requested,
            &annotations,
            first.version,
            "first".into(),
            None,
            |_| unreachable!()
        ),
        RosterPushDisposition::Covered
    );
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn bounded_gap_returns_exact_versions_with_proven_get_annotations() {
    let fixture = Fixture::new().await;
    let pool = &fixture.database.pool;
    let baseline = fixture.change("before@example.test", "Before").await;
    let (channel_version, participant) = join_annotated_channel(pool, &fixture.owner).await;
    let tip = fixture.change("after@example.test", "After").await;
    let gap = RosterGap {
        after: RosterVersion(baseline.version),
        through: RosterVersion(tip.version),
    };
    let owner = (fixture.owner.id, fixture.owner.auth_generation);
    let snapshot = read_roster_gap(&WorkflowRosterEffects, pool, owner, gap, true)
        .await
        .unwrap()
        .unwrap();
    let changes = snapshot.changes.unwrap();
    assert_eq!(
        changes
            .iter()
            .map(|change| change.version)
            .collect::<Vec<_>>(),
        [channel_version, tip.version]
    );
    assert_eq!(changes[0].contact_jid, "room@mix.example.test");
    assert_eq!(changes[1].display_name.as_deref(), Some("After"));
    assert_eq!(
        snapshot.mix_participants,
        fixture.snapshot(true).await.mix_participants
    );
    assert_eq!(
        snapshot.mix_participants["room@mix.example.test"],
        participant
    );
    mix::begin_remote_pam_leave(
        &WorkflowRoomEffects,
        pool,
        mix::BeginRemotePamLeave {
            user_id: fixture.owner.id,
            actor_jid: "alice@example.test",
            channel_jid: "room@mix.example.test",
            request_id: "pam-leave",
            client_request_id: "client-leave",
            requester_full_jid: "alice@example.test/phone",
            request_digest: &[7; 32],
            remote_domain: "mix.example.test",
            outbound_stanza: "<iq xmlns='jabber:server' type='set' id='pam-leave' from='alice@example.test' to='room@mix.example.test'/>",
            policy: S2sOutboxPolicy {
                ttl_seconds: 300,
                max_rows: 100,
                max_bytes: 1_048_576,
                max_per_domain: 100,
            },
        },
    )
    .await
    .unwrap();
    let changed_projection = fixture.snapshot(true).await;
    assert_eq!(changed_projection.version, tip.version);
    assert!(changed_projection.mix_participants.is_empty());
    assert!(
        read_roster_gap(&WorkflowRosterEffects, pool, owner, gap, true)
            .await
            .unwrap()
            .is_none()
    );
    let newer = fixture.change("after@example.test", "Newer").await;
    assert!(newer.version > tip.version);
    assert!(
        read_roster_gap(&WorkflowRosterEffects, pool, owner, gap, true)
            .await
            .unwrap()
            .is_none()
    );
    let plain = read_roster_gap(&WorkflowRosterEffects, pool, owner, gap, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(plain.changes.unwrap(), changes);
    assert!(plain.mix_participants.is_empty());
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn password_change_between_commit_and_delivery_keeps_original_push_authority() {
    let fixture = Fixture::new().await;
    let pool = &fixture.database.pool;
    let snapshot = fixture.snapshot(false).await;
    let delayed = fixture
        .change("bob@example.test", "Before password change")
        .await;
    change_password(
        pool,
        fixture.owner.id,
        "Changed password for test!43",
        4096,
        false,
    )
    .await
    .unwrap();
    let generation: i64 = sqlx::query_scalar("SELECT auth_generation FROM users WHERE id=$1")
        .bind(fixture.owner.id)
        .fetch_one(pool)
        .await
        .unwrap();
    let committed = delayed.owner_authority.unwrap();
    assert_eq!(committed, (fixture.owner.id, fixture.owner.auth_generation));
    assert_ne!(committed, (fixture.owner.id, generation));
    let gap = RosterGap {
        after: RosterVersion(snapshot.version),
        through: RosterVersion(delayed.version),
    };
    assert!(
        read_roster_gap(&WorkflowRosterEffects, pool, committed, gap, false)
            .await
            .unwrap()
            .is_none()
    );
    assert!(read_roster_gap(
        &WorkflowRosterEffects,
        pool,
        (fixture.owner.id, generation),
        gap,
        false
    )
    .await
    .unwrap()
    .is_some());
    fixture.database.finish().await;
}
