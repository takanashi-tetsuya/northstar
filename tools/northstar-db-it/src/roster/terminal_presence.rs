use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::{create_user, User};
use northstar_roster_postgres::privacy::{replace_privacy_list, set_active_privacy_list};
use northstar_roster_postgres::roster::block_jids;
use northstar_session_application::sm_teardown_presence::{
    DirectedGrant, ExactPresenceAcceptance, SmTeardownPresenceService, TerminalOwner,
    TerminalPresenceRepository, TerminalPresenceRequest, TerminalPresenceTarget, TerminalRoute,
    TerminalRouteCandidate,
};
use northstar_stream::{
    local_routes::session::test_online_session,
    session_cleanup::unavailable::{SessionCleanupUnavailable, SessionCleanupUnavailablePorts},
};
use northstar_workflows::{
    sm, sm_teardown_presence_repository::PostgresSmTeardownPresenceRepository,
};
use northstar_xep_0016::{PrivacyAction, PrivacyItem, PrivacyList};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

const SOURCE: &str = "alice@example.test/phone";
const PEER: &str = "bob@example.test/phone";
const BARE_PEER: &str = "bob@example.test";

async fn user(pool: &PgPool, username: &str) -> User {
    create_user(
        pool,
        username,
        "Initial password for test!42",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap()
}

fn candidate(peer: &User) -> TerminalRouteCandidate {
    TerminalRouteCandidate {
        route: TerminalRoute {
            full_jid: PEER.to_owned(),
            account_id: peer.id,
            auth_generation: peer.auth_generation,
            connection_id: Uuid::new_v4(),
            node_id: None,
        },
        available: true,
        expects_active: false,
    }
}

fn grant(route: &TerminalRoute) -> String {
    DirectedGrant {
        scope: BARE_PEER.to_owned(),
        route: route.clone(),
    }
    .encode()
}

fn live<'a>(
    owner: &User,
    connection_id: Uuid,
    directed: &'a [String],
) -> TerminalPresenceRequest<'a> {
    TerminalPresenceRequest {
        owner_id: owner.id,
        owner: TerminalOwner::Live {
            auth_generation: owner.auth_generation,
            connection_id,
        },
        full_jid: SOURCE,
        active_privacy_list: None,
        available: false,
        directed,
        local_domain: "example.test",
    }
}

async fn disable(pool: &PgPool, account: &User) {
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT northstar_user_quiesce_deletion($1,$2)")
            .bind(account.id)
            .bind(account.auth_generation)
            .fetch_one(pool)
            .await
            .unwrap()
    );
}

async fn replace(pool: &PgPool, account: &User) -> User {
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT northstar_user_delete_quiesced($1,$2)")
            .bind(account.id)
            .bind(&account.username)
            .fetch_one(pool)
            .await
            .unwrap()
    );
    user(pool, &account.username).await
}

fn recipient_rule(action: PrivacyAction) -> PrivacyList {
    PrivacyList {
        name: "selected".into(),
        items: vec![PrivacyItem {
            order: 1,
            action,
            match_type: None,
            match_value: None,
            message: false,
            iq: false,
            presence_in: true,
            presence_out: false,
        }],
    }
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn replacement_while_terminal_policy_is_waiting_cannot_inherit_a_grant() {
    let db = IsolatedDatabase::create("terminal_replacement").await;
    let owner = user(&db.pool, "alice").await;
    let peer = user(&db.pool, "bob").await;
    let old_route = candidate(&peer);
    let directed = [grant(&old_route.route)];
    let connection = Uuid::new_v4();
    let repository = PostgresSmTeardownPresenceRepository::new(db.pool.clone());
    let mut blocker = db.pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    // Pause the statement on a relation lock. Disabling an account does
    // not modify privacy rows and can commit while the read waits.
    sqlx::query("LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let capture = tokio::spawn({
        let repository = repository.clone();
        let owner = owner.clone();
        let directed = directed.clone();
        let old_route = old_route.clone();
        async move {
            repository
                .capture_terminal_presence(&live(&owner, connection, &directed), &[old_route])
                .await
                .unwrap()
                .unwrap()
        }
    });
    crate::support::blocked_backend(&db.pool, blocker_pid).await;
    disable(&db.pool, &peer).await;
    blocker.commit().await.unwrap();
    let captured = capture.await.unwrap();
    let old_target = TerminalPresenceTarget::Route {
        route: old_route.route.clone(),
        scope: BARE_PEER.to_owned(),
    };
    assert!(captured.targets.is_empty() || captured.targets == [old_target]);
    let replacement = replace(&db.pool, &peer).await;
    assert_ne!(peer.id, replacement.id);
    assert!(repository
        .capture_terminal_presence(
            &live(&owner, connection, &directed),
            &[candidate(&replacement)],
        )
        .await
        .unwrap()
        .unwrap()
        .targets
        .is_empty());
    disable(&db.pool, &owner).await;
    let _ = replace(&db.pool, &owner).await;
    assert!(repository
        .capture_terminal_presence(&live(&owner, connection, &directed), &[old_route],)
        .await
        .unwrap()
        .is_none());
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn live_capture_freezes_terminal_selector_and_recipient_policy() {
    let db = IsolatedDatabase::create("terminal_policy").await;
    let owner = user(&db.pool, "alice").await;
    let peer = user(&db.pool, "bob").await;
    let mut route = candidate(&peer);
    route.expects_active = true;
    let connection = Uuid::new_v4();
    for (actor, from, target, to, kind) in [
        (
            peer.id,
            BARE_PEER,
            owner.id,
            "alice@example.test",
            "subscribe",
        ),
        (
            owner.id,
            "alice@example.test",
            peer.id,
            BARE_PEER,
            "subscribed",
        ),
    ] {
        let stanza = format!("<presence from='{from}' to='{to}' type='{kind}'/>");
        assert!(
            northstar_workflows::roster::transition_local_presence_subscription(
                &db.pool, actor, from, target, to, kind, &stanza,
            )
            .await
            .unwrap()
            .is_some()
        );
    }
    for (account, connection) in [(owner.id, connection), (peer.id, route.route.connection_id)] {
        assert!(matches!(
            replace_privacy_list(&db.pool, account, &recipient_rule(PrivacyAction::Allow))
                .await
                .unwrap(),
            northstar_roster_postgres::privacy::ReplacePrivacyListOutcome::Stored
        ));
        assert!(
            set_active_privacy_list(&db.pool, account, connection, Some("selected"))
                .await
                .unwrap()
        );
    }
    let repository = PostgresSmTeardownPresenceRepository::new(db.pool.clone());
    let mut request = live(&owner, connection, &[]);
    request.available = true;
    request.active_privacy_list = Some("selected");
    let captured = repository
        .capture_terminal_presence(&request, std::slice::from_ref(&route))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        captured.targets,
        [TerminalPresenceTarget::Route {
            route: route.route.clone(),
            scope: BARE_PEER.to_owned(),
        }]
    );

    replace_privacy_list(&db.pool, peer.id, &recipient_rule(PrivacyAction::Deny))
        .await
        .unwrap();
    assert!(repository
        .capture_terminal_presence(&request, std::slice::from_ref(&route))
        .await
        .unwrap()
        .unwrap()
        .targets
        .is_empty());
    block_jids(&db.pool, peer.id, &["alice@example.test".to_owned()])
        .await
        .unwrap();
    replace_privacy_list(&db.pool, peer.id, &recipient_rule(PrivacyAction::Allow))
        .await
        .unwrap();
    assert!(repository
        .capture_terminal_presence(&request, std::slice::from_ref(&route))
        .await
        .unwrap()
        .unwrap()
        .targets
        .is_empty());
    northstar_roster_postgres::roster::unblock_jids(
        &db.pool,
        peer.id,
        Some(&["alice@example.test".to_owned()]),
    )
    .await
    .unwrap();
    northstar_roster_postgres::privacy::clear_active_privacy_session(
        &db.pool, owner.id, connection,
    )
    .await
    .unwrap();
    assert!(repository
        .capture_terminal_presence(&request, &[route])
        .await
        .unwrap()
        .unwrap()
        .targets
        .is_empty());
    assert_eq!(captured.targets.len(), 1);
    db.finish().await;
}

struct LocalOnly;

impl SessionCleanupUnavailablePorts for LocalOnly {
    async fn capture_remote_routes(&self, _: &str) -> anyhow::Result<Vec<TerminalRouteCandidate>> {
        Ok(Vec::new())
    }

    async fn send_terminal_unavailable(
        &self,
        _: &TerminalRoute,
        _: &TerminalRoute,
        _: &str,
    ) -> anyhow::Result<ExactPresenceAcceptance> {
        panic!("unexpected remote route")
    }

    fn external_route_domain_allowed(&self, _: &str) -> bool {
        false
    }

    async fn send_federation(&self, _: &str, _: String, _: Option<String>) -> bool {
        panic!("unexpected federation route")
    }
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn rebind_during_directed_withdrawal_does_not_retarget_acceptance() {
    let db = IsolatedDatabase::create("terminal_rebind").await;
    let owner = user(&db.pool, "alice").await;
    let peer = user(&db.pool, "bob").await;
    let old = candidate(&peer);
    let new = candidate(&peer);
    let sessions = Arc::default();
    let unavailable = Arc::new(SessionCleanupUnavailable::new(
        SmTeardownPresenceService::new(PostgresSmTeardownPresenceRepository::new(db.pool.clone())),
        Arc::clone(&sessions),
        LocalOnly,
        "example.test".to_owned(),
    ));
    let (old_session, mut old_queue) = test_online_session(
        peer.id,
        peer.auth_generation,
        old.route.connection_id,
        "phone",
        4,
    );
    let (new_session, mut new_queue) = test_online_session(
        peer.id,
        peer.auth_generation,
        new.route.connection_id,
        "phone",
        4,
    );
    sessions.insert(PEER.to_owned(), old_session);
    let mut blocker = db.pool.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("LOCK TABLE privacy_list_items IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let withdraw = tokio::spawn({
        let unavailable = Arc::clone(&unavailable);
        async move {
            let directed = [grant(&old.route)];
            let audience = unavailable
                .capture(live(&owner, Uuid::new_v4(), &directed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(audience.targets.len(), 1);
            unavailable.publish(audience).await.unwrap();
        }
    });
    crate::support::blocked_backend(&db.pool, pid).await;
    sessions.insert(PEER.to_owned(), new_session);
    blocker.commit().await.unwrap();
    withdraw.await.unwrap();
    assert!(old_queue.try_recv().is_err());
    assert!(new_queue.try_recv().is_err());
    db.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn sm_expiry_captures_directed_only_grants_from_an_unavailable_source() {
    let db = IsolatedDatabase::create("terminal_sm_expiry").await;
    let owner = user(&db.pool, "alice").await;
    let peer = user(&db.pool, "bob").await;
    let route = candidate(&peer);
    let connection = Uuid::new_v4();
    let snapshot = sm::SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 0,
        acked_h: 0,
        available: false,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: None,
        privacy_requested: false,
        peer_ip: "127.0.0.1".parse().unwrap(),
        user_agent_id: None,
        joined_rooms: Vec::new(),
        directed_presence: vec![grant(&route.route)],
        last_presence: None,
        unacked: Vec::new(),
    };
    let session = sm::create_sm_session(
        &db.pool,
        &[21; 32],
        owner.id,
        owner.auth_generation,
        SOURCE,
        "phone",
        "example.test",
        connection,
        &snapshot,
        300,
        30,
        8,
        64,
    )
    .await
    .unwrap();
    assert!(
        sm::suspend_sm_session(&db.pool, session, connection, &snapshot, 300, 64, 65_536)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE sm_resume_sessions SET expires_at=clock_timestamp() WHERE id=$1")
        .bind(session)
        .execute(&db.pool)
        .await
        .unwrap();
    let claimed = sm::cleanup_expired_sm_sessions(&db.pool, 30)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let mut request = live(&owner, connection, &claimed.directed_presence);
    request.available = claimed.available;
    request.owner = TerminalOwner::Suspended {
        session_id: session,
        deadline: claimed.presence_deadline,
    };
    let repository = PostgresSmTeardownPresenceRepository::new(db.pool.clone());
    let captured = repository
        .capture_terminal_presence(&request, std::slice::from_ref(&route))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        captured.targets,
        [TerminalPresenceTarget::Route {
            route: route.route,
            scope: BARE_PEER.to_owned(),
        }]
    );
    assert!(
        sm::finalize_sm_teardown(&db.pool, session, claimed.teardown_token)
            .await
            .unwrap()
    );
    db.finish().await;
}
