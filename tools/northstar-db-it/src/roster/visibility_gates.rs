use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::{change_password, create_user, find_enabled_user, User};
use northstar_message_application::messaging::{
    ExactMessageRoute, MessageService, OutboundPolicyDecision, ResourceStanzaPolicy,
};
use northstar_roster_postgres::{privacy, roster};
use northstar_stream::local_routes::{
    session::test_online_session, session_table::LocalSessionTable,
};
use northstar_stream::protocol::iq_visibility::LocalIqAdmission;
use northstar_workflows::{
    message_repository::PostgresMessageRepository,
    roster::{transition_local_presence_subscription, upsert_roster},
};
use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const OWNER: &str = "bob@example.test";
const ROUTE: &str = "bob@example.test/Phone";
const PEER_BARE: &str = "alice@example.test";
const PEER: &str = "alice@example.test/Phone";

fn service(pool: &PgPool) -> MessageService<PostgresMessageRepository> {
    MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            northstar_abuse_application::guard::test_personal_message_content_keyring(),
            "example.test",
            100,
            8_000_000,
            30,
        ),
        false,
    )
}

async fn user(pool: &PgPool, name: &str) -> User {
    create_user(
        pool,
        name,
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap()
}

async fn list(pool: &PgPool, owner: Uuid, name: &str, action: PrivacyAction, group: Option<&str>) {
    assert_eq!(
        privacy::replace_privacy_list(
            pool,
            owner,
            &PrivacyList {
                name: name.to_owned(),
                items: vec![PrivacyItem {
                    order: 10,
                    action,
                    match_type: group.map(|_| PrivacyMatchType::Group),
                    match_value: group.map(str::to_owned),
                    message: false,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                }],
            }
        )
        .await
        .unwrap(),
        privacy::ReplacePrivacyListOutcome::Stored
    );
}

fn route(account_id: Uuid, auth_generation: i64, connection_id: Uuid) -> ExactMessageRoute {
    ExactMessageRoute {
        full_jid: ROUTE.to_owned(),
        account_id,
        auth_generation,
        connection_id,
        node_id: None,
        priority: None,
        available: None,
    }
}

fn iq_policy(route: &ExactMessageRoute) -> ResourceStanzaPolicy<'static> {
    ResourceStanzaPolicy {
        account: Some(OWNER),
        account_id: route.account_id,
        auth_generation: Some(route.auth_generation),
        connection_id: route.connection_id,
        expects_active: false,
        peer: PEER,
        kind: PrivacyStanzaKind::Iq,
    }
}

async fn pause_policy_read(pool: &PgPool) -> (Transaction<'static, Postgres>, i32) {
    // A plain SELECT takes no row or advisory locks. A relation lock lets
    // the test observe it waiting before the concurrent change is committed.
    let mut writer = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *writer)
        .await
        .unwrap();
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    (writer, pid)
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn iq_visibility_cannot_combine_an_old_roster_grant_with_a_new_policy_allow() {
    let database = IsolatedDatabase::create("vis_grant_swap").await;
    let pool = &database.pool;
    let owner = user(pool, "bob").await;
    let peer = user(pool, "alice").await;
    for (actor, actor_jid, target, target_jid, kind) in [
        (&peer, PEER_BARE, &owner, OWNER, "subscribe"),
        (&owner, OWNER, &peer, PEER_BARE, "subscribed"),
    ] {
        let stanza = format!("<presence from='{actor_jid}' to='{target_jid}' type='{kind}'/>");
        assert!(transition_local_presence_subscription(
            pool, actor.id, actor_jid, target.id, target_jid, kind, &stanza,
        )
        .await
        .unwrap()
        .is_some());
    }
    list(pool, owner.id, "swap", PrivacyAction::Deny, None).await;
    assert!(
        privacy::set_default_privacy_list(pool, owner.id, Some("swap"))
            .await
            .unwrap()
    );
    let service = service(pool);
    let route = route(owner.id, owner.auth_generation, Uuid::new_v4());
    assert!(!service
        .allows_resource_stanza(iq_policy(&route), true)
        .await
        .unwrap());

    let (mut writer, pid) = pause_policy_read(pool).await;
    let reader = service.clone();
    let request = iq_policy(&route);
    let operation = tokio::spawn(async move { reader.allows_resource_stanza(request, true).await });
    crate::support::blocked_backend(pool, pid).await;
    assert_eq!(sqlx::query(
        "UPDATE roster_items SET subscription='none' WHERE owner_id=$1 AND contact_jid=$2 AND subscription='from'",
    ).bind(owner.id).bind(PEER_BARE).execute(&mut *writer).await.unwrap().rows_affected(), 1);
    sqlx::query(
        "UPDATE privacy_list_items SET action='allow' WHERE owner_id=$1 AND list_name='swap'",
    )
    .bind(owner.id)
    .execute(&mut *writer)
    .await
    .unwrap();
    writer.commit().await.unwrap();
    assert!(!operation.await.unwrap().unwrap());
    assert!(service
        .allows_resource_stanza(iq_policy(&route), false)
        .await
        .unwrap());
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn ordinary_send_cannot_mix_block_and_privacy_during_default_edit_and_roster_change() {
    let database = IsolatedDatabase::create("vis_send_swap").await;
    let pool = &database.pool;
    let owner = user(pool, "bob").await;
    let service = service(pool);
    upsert_roster(pool, owner.id, PEER_BARE, None, &["before".to_owned()])
        .await
        .unwrap();
    list(pool, owner.id, "old", PrivacyAction::Deny, Some("before")).await;
    list(pool, owner.id, "next", PrivacyAction::Deny, Some("before")).await;
    assert!(
        privacy::set_default_privacy_list(pool, owner.id, Some("old"))
            .await
            .unwrap()
    );
    assert_eq!(
        service
            .authorize_outbound_message(owner.id, OWNER, None, None, PEER)
            .await
            .unwrap(),
        OutboundPolicyDecision::PrivacyDenied
    );

    let (mut writer, pid) = pause_policy_read(pool).await;
    let reader = service.clone();
    let owner_id = owner.id;
    let operation = tokio::spawn(async move {
        reader
            .authorize_outbound_message(owner_id, OWNER, None, None, PEER)
            .await
    });
    crate::support::blocked_backend(pool, pid).await;
    sqlx::query("UPDATE privacy_default_lists SET list_name='next' WHERE owner_id=$1")
        .bind(owner.id)
        .execute(&mut *writer)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE privacy_list_items SET match_value='after' WHERE owner_id=$1 AND list_name='next'",
    )
    .bind(owner.id)
    .execute(&mut *writer)
    .await
    .unwrap();
    sqlx::query("UPDATE roster_items SET groups=jsonb_build_array('unrelated'::text) WHERE owner_id=$1 AND contact_jid=$2")
        .bind(owner.id).bind(PEER_BARE).execute(&mut *writer).await.unwrap();
    sqlx::query("INSERT INTO blocked_jids (owner_id, blocked_jid) VALUES ($1,$2)")
        .bind(owner.id)
        .bind(PEER)
        .execute(&mut *writer)
        .await
        .unwrap();
    writer.commit().await.unwrap();
    assert!(matches!(
        operation.await.unwrap().unwrap(),
        OutboundPolicyDecision::Blocked | OutboundPolicyDecision::PrivacyDenied
    ));
    assert_eq!(
        service
            .authorize_outbound_message(owner.id, OWNER, None, None, PEER)
            .await
            .unwrap(),
        OutboundPolicyDecision::Blocked
    );
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn a_captured_iq_decision_cannot_authorize_a_replacement_connection_or_generation() {
    let database = IsolatedDatabase::create("vis_replacement").await;
    let pool = &database.pool;
    let owner = user(pool, "bob").await;
    let service = service(pool);
    let connection = Uuid::new_v4();
    let (session, mut old_output) =
        test_online_session(owner.id, owner.auth_generation, connection, "Phone", 4);
    session.directed_presence.insert(PEER.to_owned());
    let admission = LocalIqAdmission::capture(ROUTE.to_owned(), &session, PEER, true).unwrap();
    let sessions = std::sync::Arc::new(Default::default());
    let table = LocalSessionTable::new(std::sync::Arc::clone(&sessions));
    sessions.insert(ROUTE.to_owned(), session);
    let (read, policy_read) = tokio::sync::oneshot::channel();
    let (resume, paused) = tokio::sync::oneshot::channel();
    let reader = service.clone();
    let operation = tokio::spawn(async move {
        assert!(reader
            .allows_resource_stanza(admission.policy(), admission.requires_subscription())
            .await
            .unwrap());
        read.send(()).unwrap();
        paused.await.unwrap();
        admission.handoff(&table, Some("<iq type='get' id='old'/>"))
    });
    policy_read.await.unwrap();

    change_password(
        pool,
        owner.id,
        "Replacement password for test!97",
        4096,
        false,
    )
    .await
    .unwrap();
    let current = find_enabled_user(pool, "bob").await.unwrap().unwrap();
    let replacement = Uuid::new_v4();
    let (session, mut new_output) =
        test_online_session(current.id, current.auth_generation, replacement, "Phone", 4);
    sessions.insert(ROUTE.to_owned(), session);
    resume.send(()).unwrap();
    assert!(!operation.await.unwrap());
    assert!(old_output.try_recv().is_err());
    assert!(new_output.try_recv().is_err());
    let old = route(owner.id, owner.auth_generation, connection);
    let new = route(current.id, current.auth_generation, replacement);
    assert!(!service
        .allows_resource_stanza(iq_policy(&old), false)
        .await
        .unwrap());
    assert!(service
        .allows_resource_stanza(iq_policy(&new), false)
        .await
        .unwrap());
    database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn carbon_and_ordinary_resource_policy_agree_on_active_default_and_block() {
    let database = IsolatedDatabase::create("vis_carbon_parity").await;
    let pool = &database.pool;
    let owner = user(pool, "bob").await;
    let service = service(pool);
    let route = route(owner.id, owner.auth_generation, Uuid::new_v4());
    list(pool, owner.id, "default", PrivacyAction::Deny, None).await;
    list(pool, owner.id, "active", PrivacyAction::Allow, None).await;
    assert!(
        privacy::set_default_privacy_list(pool, owner.id, Some("default"))
            .await
            .unwrap()
    );
    for (active, blocked, allowed) in [
        (None, false, false),
        (Some("active"), false, true),
        (Some("active"), true, false),
    ] {
        assert!(
            privacy::set_active_privacy_list(pool, owner.id, route.connection_id, active)
                .await
                .unwrap()
        );
        if blocked {
            roster::block_jids(pool, owner.id, &[PEER.to_owned()])
                .await
                .unwrap();
        }
        let request = ResourceStanzaPolicy {
            kind: PrivacyStanzaKind::Message,
            expects_active: active.is_some(),
            ..iq_policy(&route)
        };
        assert_eq!(
            service
                .allows_resource_stanza(request, false)
                .await
                .unwrap(),
            allowed
        );
        assert_eq!(
            service
                .allows_carbon_on_route(&route, active, PEER)
                .await
                .unwrap(),
            allowed
        );
    }
    database.finish().await;
}
