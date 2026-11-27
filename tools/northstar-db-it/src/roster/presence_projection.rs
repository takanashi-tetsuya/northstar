use super::presence_service::IsolatedDatabase;
use northstar_pubsub_postgres::{set_vcard_with_converted_avatar, PepPublishOutcome, PepQuotas};
use northstar_roster_application::presence::PresenceService;
use northstar_session_application::replay::OfflineReplayLeaseAcquire;
use northstar_session_postgres::replay::{
    acquire_offline_replay_lease, REPLAY_OWNER_LEASE_SECONDS,
};
use northstar_stream::local_routes::session::test_online_session;
use northstar_workflows::presence_repository::PostgresPresenceRepository;
use northstar_xml_builder::rewrite::{project_presence_avatar, set_to};
use std::sync::atomic::Ordering;
use uuid::Uuid;

async fn insert_owner(database: &IsolatedDatabase) -> (Uuid, i64) {
    let owner_id = Uuid::new_v4();
    let generation = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')
         RETURNING auth_generation",
    )
    .bind(owner_id)
    .fetch_one(&database.pool)
    .await
    .unwrap();
    (owner_id, generation)
}

async fn commit_avatar(database: &IsolatedDatabase, owner_id: Uuid, hash: &str) {
    let metadata = format!(
        "<metadata xmlns='urn:xmpp:avatar:metadata'><info bytes='8' id='{hash}' type='image/png'/></metadata>"
    );
    assert!(matches!(
        set_vcard_with_converted_avatar(
            &database.pool,
            owner_id,
            "<vCard xmlns='vcard-temp'/>",
            Some(hash),
            None,
            ("current", &metadata),
            PepQuotas {
                max_nodes: 16,
                max_storage_bytes: 1024 * 1024,
            },
        )
        .await
        .unwrap(),
        PepPublishOutcome::Published
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn committed_avatar_is_projected_over_old_local_and_federated_probe_caches() {
    let database = IsolatedDatabase::create("probe_avatar_projection").await;
    let (owner_id, generation) = insert_owner(&database).await;
    let service = PresenceService::new(PostgresPresenceRepository::new(database.pool.clone()));
    let (route, _receiver) = test_online_session(owner_id, generation, Uuid::new_v4(), "phone", 1);
    let old = "1234567890123456789012345678901234567890";
    let new = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
    commit_avatar(&database, owner_id, old).await;
    let original = service.avatar_hash(owner_id).await.unwrap();
    assert_eq!(original.as_deref(), Some(old));
    let cached = project_presence_avatar(
        "<presence from='alice@example.test/phone' id='presence-1'><status>here</status></presence>",
        Some(original.as_deref()),
    );
    *route.last_presence.write().unwrap() = cached.clone();
    route.available.store(true, Ordering::Release);

    commit_avatar(&database, owner_id, new).await;
    for requester in ["bob@example.test/laptop", "romeo@remote.test/phone"] {
        let snapshot = route.current_presence().unwrap().unwrap();
        let authoritative = service.avatar_hash(route.user_id).await.unwrap();
        let response = set_to(
            &project_presence_avatar(&snapshot, Some(authoritative.as_deref())).unwrap(),
            requester,
        );
        let document = roxmltree::Document::parse(&response).unwrap();
        assert_eq!(document.root_element().attribute("to"), Some(requester));
        assert_eq!(document.root_element().attribute("id"), Some("presence-1"));
        assert_eq!(
            document
                .descendants()
                .find(|node| node.has_tag_name(("vcard-temp:x:update", "photo")))
                .and_then(|photo| photo.text()),
            Some(new)
        );
        assert!(!response.contains(old));
    }
    assert_eq!(route.current_presence(), Some(cached));
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn nonnegative_priority_is_visible_before_its_database_replay_cutoff() {
    let database = IsolatedDatabase::create("priority_cutoff").await;
    let (owner_id, generation) = insert_owner(&database).await;
    let service = PresenceService::new(PostgresPresenceRepository::new(database.pool.clone()));
    let (route, _receiver) = test_online_session(owner_id, generation, Uuid::new_v4(), "phone", 1);
    route.priority.store(-1, Ordering::Relaxed);
    route.available.store(true, Ordering::Release);
    assert_eq!(route.available_priority(), None);
    {
        let mut presence = route.last_presence.write().unwrap();
        *presence = Some("<presence><priority>1</priority></presence>".into());
        route.priority.store(1, Ordering::Relaxed);
    }
    assert_eq!(route.available_priority(), Some(1));
    let cutoff = service.replay_cutoff().await.unwrap();
    let lease = acquire_offline_replay_lease(
        &database.pool,
        owner_id,
        "phone",
        Uuid::new_v4(),
        Some(cutoff),
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await
    .unwrap();
    let OfflineReplayLeaseAcquire::Acquired(lease) = lease else {
        panic!("test resource unexpectedly already has a replay lease");
    };
    assert_eq!(lease.replay_started_at, cutoff);
    database.finish().await;
}
