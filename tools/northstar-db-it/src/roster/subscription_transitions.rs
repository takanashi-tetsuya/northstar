use super::presence_service::IsolatedDatabase;
use northstar_auth_postgres::users::create_user;
use northstar_roster_application::presence::{
    InboundSubscriptionRequest, InboundSubscriptionTransition, LocalSubscriptionRequest,
    PresenceMutation, PresenceService, SubscriptionOutboxAdmissionError, SubscriptionRoute,
};
use northstar_roster_application::{RosterRemovalRoute, S2sOutboxPolicy};
use northstar_roster_core::{
    AuthorizedRosterRemoval, InboundRemotePresenceEffect, PresenceAccount, SubscriptionAction,
    SubscriptionReply,
};
use northstar_roster_postgres::roster::{federated_presence_pending, roster_item};
use northstar_workflows::presence_repository::PostgresPresenceRepository;
use northstar_workflows::roster::{
    remove_roster_item_authorized, update_subscription, update_subscription_with_approval,
};
use northstar_xml_builder::XmlElement;
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "example.test";
const PEER: &str = "remote.test";
const CONTACT: &str = "sender@remote.test";
const PASSWORD: &str = "Initial password for test!42";

fn policy() -> S2sOutboxPolicy {
    S2sOutboxPolicy::new(300, 100, 1024 * 1024, 100)
}

fn service(pool: &PgPool) -> PresenceService<PostgresPresenceRepository> {
    PresenceService::new(PostgresPresenceRepository::new(pool.clone()))
}

async fn account(pool: &PgPool, username: &str, admin: bool) -> PresenceAccount {
    let user = create_user(pool, username, PASSWORD, admin, true, 4096, false)
        .await
        .unwrap();
    PresenceAccount {
        id: user.id,
        username: username.to_owned(),
        auth_generation: user.auth_generation,
    }
}

fn jid(account: &PresenceAccount) -> String {
    format!("{}@{DOMAIN}", account.username)
}

fn presence(from: &str, to: &str, kind: &str, id: Option<&str>) -> String {
    XmlElement::new("presence")
        .attr("xmlns", "jabber:server")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .optional_attr("id", id)
        .finish()
}

async fn inbound(
    pool: &PgPool,
    recipient: &PresenceAccount,
    action: SubscriptionAction,
    id: Option<&str>,
    outbox_policy: S2sOutboxPolicy,
) -> anyhow::Result<PresenceMutation<InboundSubscriptionTransition>> {
    let to = jid(recipient);
    service(pool)
        .transition_inbound(InboundSubscriptionRequest {
            recipient,
            local_domain: DOMAIN,
            contact: CONTACT,
            action,
            stanza: &presence(CONTACT, &to, action.as_str(), id),
            verified_peer: PEER,
            subscribed_reply: &presence(&to, CONTACT, "subscribed", id),
            unsubscribed_reply: &presence(&to, CONTACT, "unsubscribed", id),
            outbox_policy,
        })
        .await
}

async fn snapshot(pool: &PgPool, owner: Uuid) -> (i64, i64, i64, i64) {
    sqlx::query_as(
        "SELECT roster_version,
                (SELECT count(*) FROM roster_change_log WHERE owner_id=$1),
                (SELECT count(*) FROM s2s_outbox),
                (SELECT generation FROM s2s_outbox_enqueue_generation WHERE singleton)
         FROM users WHERE id=$1",
    )
    .bind(owner)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn approval_duplicates_and_revocation_commit_typed_replies() {
    let database = IsolatedDatabase::create("subscription_replies").await;
    let pool = &database.pool;
    let owner = account(pool, "owner", false).await;
    update_subscription_with_approval(pool, owner.id, CONTACT, "none", None, Some(true))
        .await
        .unwrap();
    for (action, id, reply, changed, unavailable, forward) in [
        (
            SubscriptionAction::Subscribe,
            Some("approve&1"),
            SubscriptionReply::Subscribed,
            true,
            false,
            false,
        ),
        (
            SubscriptionAction::Subscribe,
            Some("duplicate'2"),
            SubscriptionReply::Subscribed,
            false,
            false,
            false,
        ),
        (
            SubscriptionAction::Unsubscribe,
            Some("revoke-3"),
            SubscriptionReply::Unsubscribed,
            true,
            true,
            true,
        ),
        (
            SubscriptionAction::Unsubscribe,
            None,
            SubscriptionReply::Unsubscribed,
            false,
            false,
            false,
        ),
    ] {
        let before = snapshot(pool, owner.id).await;
        let PresenceMutation::Transition(transition) =
            inbound(pool, &owner, action, id, policy()).await.unwrap()
        else {
            panic!("valid transition rejected");
        };
        assert_eq!(transition.auto_reply, Some(reply));
        assert_eq!(transition.send_unavailable, unavailable);
        assert_eq!(
            transition.effect == InboundRemotePresenceEffect::Forward,
            forward
        );
        assert_eq!(transition.change.is_some(), changed);
        let after = snapshot(pool, owner.id).await;
        let journal_delta = if changed { 1 } else { 0 };
        assert_eq!(after.0 - before.0, journal_delta);
        assert_eq!(after.1 - before.1, journal_delta);
        assert_eq!(after.2 - before.2, 1);
        assert_eq!(after.3 - before.3, 1);
        let (outbox_id, target, stanza): (Uuid, String, String) =
            sqlx::query_as("SELECT id,target_domain,stanza FROM s2s_outbox")
                .fetch_one(pool)
                .await
                .unwrap();
        let document = roxmltree::Document::parse(&stanza).unwrap();
        let root = document.root_element();
        assert_eq!(target, PEER);
        assert_eq!(root.attribute("from"), Some(jid(&owner).as_str()));
        assert_eq!(root.attribute("to"), Some(CONTACT));
        assert_eq!(root.attribute("type"), Some(reply.as_str()));
        assert_eq!(root.attribute("id"), id);
        sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
            .bind(outbox_id)
            .execute(pool)
            .await
            .unwrap();
    }
    assert_eq!(
        roster_item(pool, owner.id, CONTACT)
            .await
            .unwrap()
            .unwrap()
            .2,
        "none"
    );
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn inbound_outbox_failure_rolls_back_approval_journal_pending_and_intent() {
    let database = IsolatedDatabase::create("subscription_rollback").await;
    let pool = &database.pool;
    let owner = account(pool, "owner", false).await;
    let request = presence(CONTACT, &jid(&owner), "subscribe", Some("original"));
    let first = inbound(
        pool,
        &owner,
        SubscriptionAction::Subscribe,
        Some("original"),
        policy(),
    )
    .await
    .unwrap();
    assert!(
        matches!(first, PresenceMutation::Transition(result) if result.effect == InboundRemotePresenceEffect::Forward)
    );
    update_subscription_with_approval(pool, owner.id, CONTACT, "none", None, Some(true))
        .await
        .unwrap();
    let before = snapshot(pool, owner.id).await;
    let failure = S2sOutboxPolicy {
        max_rows: 0,
        ..policy()
    };
    let error = inbound(
        pool,
        &owner,
        SubscriptionAction::Subscribe,
        Some("retry"),
        failure,
    )
    .await
    .unwrap_err();
    assert!(error.is::<SubscriptionOutboxAdmissionError>());
    assert_eq!(snapshot(pool, owner.id).await, before);
    let state: (String, Option<String>, bool) = sqlx::query_as(
        "SELECT subscription,ask,approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
    )
    .bind(owner.id)
    .bind(CONTACT)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(state, ("none".to_owned(), None, true));
    let pending = federated_presence_pending(pool, owner.id).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].stanza.as_deref(), Some(request.as_str()));
    let retry = inbound(
        pool,
        &owner,
        SubscriptionAction::Subscribe,
        Some("retry"),
        policy(),
    )
    .await
    .unwrap();
    assert!(
        matches!(retry, PresenceMutation::Transition(result) if result.subscription == "from" && result.auto_reply == Some(SubscriptionReply::Subscribed))
    );
    assert!(federated_presence_pending(pool, owner.id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        snapshot(pool, owner.id).await,
        (before.0 + 1, before.1 + 1, 1, before.3 + 1)
    );
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn component_subscription_uses_transactional_route_outbox() {
    let database = IsolatedDatabase::create("subscription_component").await;
    let pool = &database.pool;
    let owner = account(pool, "owner", false).await;
    let domain = "component.example.test";
    let contact = "service@component.example.test";
    let from = jid(&owner);
    let stanza = presence(&from, contact, "subscribe", Some("component-request"));
    assert_eq!(
        SubscriptionRoute::resolve(DOMAIN, domain, false, true),
        SubscriptionRoute::Component
    );
    let before = snapshot(pool, owner.id).await;
    let service = service(pool);
    let run = |policy| {
        service.transition_remote_with_outbox(
            owner.id,
            owner.auth_generation,
            Uuid::new_v4(),
            DOMAIN,
            contact,
            "subscribe",
            domain,
            &stanza,
            Some(&from),
            policy,
        )
    };
    assert!(run(S2sOutboxPolicy {
        max_per_domain: 0,
        ..policy()
    })
    .await
    .is_err());
    assert_eq!(snapshot(pool, owner.id).await, before);
    assert!(roster_item(pool, owner.id, contact)
        .await
        .unwrap()
        .is_none());
    let accepted = run(policy()).await.unwrap();
    assert!(
        matches!(accepted, PresenceMutation::Transition(result) if result.routed && result.change.is_some())
    );
    let queued: (String, String, Option<String>) =
        sqlx::query_as("SELECT target_domain,stanza,bounce_to FROM s2s_outbox")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(queued, (domain.to_owned(), stanza, Some(from)));
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn full_target_evidence_cannot_authorize_a_disabled_or_recreated_account() {
    let database = IsolatedDatabase::create("subscription_target_evidence").await;
    let pool = &database.pool;
    let actor = account(pool, "actor", false).await;
    let connection = Uuid::new_v4();
    for target_name in ["disabled", "recreated", "reauthenticated"] {
        let original = account(pool, target_name, false).await;
        let task_pool = pool.clone();
        let task_actor = actor.clone();
        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        let (admit_tx, admit_rx) = tokio::sync::oneshot::channel();
        let waiting = tokio::spawn(async move {
            let service = service(&task_pool);
            let captured = service
                .find_enabled_user(target_name)
                .await
                .unwrap()
                .unwrap();
            captured_tx.send(captured.id).unwrap();
            admit_rx.await.unwrap();
            service
                .transition_local(LocalSubscriptionRequest {
                    actor_id: task_actor.id,
                    expected_auth_generation: task_actor.auth_generation,
                    connection_id: connection,
                    local_domain: DOMAIN,
                    target_username: target_name,
                    kind: "subscribed",
                    stanza: &presence(&jid(&task_actor), &jid(&captured), "subscribed", None),
                    expected_target: &captured,
                })
                .await
        });
        assert_eq!(captured_rx.await.unwrap(), original.id);
        if target_name == "recreated" {
            sqlx::query("DELETE FROM users WHERE id=$1")
                .bind(original.id)
                .execute(pool)
                .await
                .unwrap();
            let replacement = account(pool, target_name, false).await;
            assert_ne!(replacement.id, original.id);
        } else {
            sqlx::query(
                "UPDATE users SET is_disabled=$2,auth_generation=auth_generation+1 WHERE id=$1",
            )
            .bind(original.id)
            .bind(target_name == "disabled")
            .execute(pool)
            .await
            .unwrap();
        }
        admit_tx.send(()).unwrap();
        assert!(matches!(
            waiting.await.unwrap().unwrap(),
            PresenceMutation::Missing
        ));
        assert!(roster_item(pool, actor.id, &jid(&original))
            .await
            .unwrap()
            .is_none());
    }
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn removal_settles_disabled_mirror_in_both_directions() {
    let database = IsolatedDatabase::create("subscription_disabled_removal").await;
    let pool = &database.pool;
    let owner = account(pool, "owner", true).await;
    let contact = account(pool, "contact", false).await;
    let owner_jid = jid(&owner);
    let contact_jid = jid(&contact);
    let service = service(pool);
    for (actor, target) in [(&owner, &contact), (&contact, &owner)] {
        let accepted = service
            .transition_local(LocalSubscriptionRequest {
                actor_id: actor.id,
                expected_auth_generation: actor.auth_generation,
                connection_id: Uuid::new_v4(),
                local_domain: DOMAIN,
                target_username: &target.username,
                kind: "subscribe",
                stanza: &presence(&jid(actor), &jid(target), "subscribe", None),
                expected_target: target,
            })
            .await
            .unwrap();
        assert!(matches!(accepted, PresenceMutation::Transition(_)));
    }
    update_subscription(pool, owner.id, &contact_jid, "both", Some("subscribe"))
        .await
        .unwrap();
    update_subscription(pool, contact.id, &owner_jid, "both", Some("subscribe"))
        .await
        .unwrap();
    northstar_workflows::account_lifecycle::set_user_status(
        pool,
        owner.id,
        contact.id,
        Some(true),
        None,
    )
    .await
    .unwrap();
    let result = remove_roster_item_authorized(
        pool,
        owner.id,
        owner.auth_generation,
        &contact_jid,
        RosterRemovalRoute::Local {
            owner_jid: &owner_jid,
            contact_username: Some(&contact.username),
        },
    )
    .await
    .unwrap();
    let AuthorizedRosterRemoval::Removed(removed) = result else {
        panic!("expected removal")
    };
    assert!(removed.local_contact.is_none());
    assert!(removed.send_unsubscribe && removed.send_unsubscribed);
    assert!(removed.contact_change.is_some());
    northstar_workflows::account_lifecycle::set_user_status(
        pool,
        owner.id,
        contact.id,
        Some(false),
        None,
    )
    .await
    .unwrap();
    let (_, _, subscription, ask) = roster_item(pool, contact.id, &owner_jid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(subscription, "none");
    assert_eq!(ask, None);
    assert!(roster_item(pool, owner.id, &contact_jid)
        .await
        .unwrap()
        .is_none());
    for account in [owner.id, contact.id] {
        assert!(
            northstar_roster_postgres::roster::pending_presence_subscriptions(pool, account)
                .await
                .unwrap()
                .is_empty()
        );
    }
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn removal_of_pending_only_remote_or_missing_item_does_not_cancel_request() {
    let database = IsolatedDatabase::create("subscription_missing_removal").await;
    let pool = &database.pool;
    let owner = account(pool, "owner", false).await;
    assert!(matches!(
        inbound(pool, &owner, SubscriptionAction::Subscribe, None, policy())
            .await
            .unwrap(),
        PresenceMutation::Transition(_)
    ));
    let before = snapshot(pool, owner.id).await;
    for target in [CONTACT, "missing@remote.test"] {
        let result = remove_roster_item_authorized(
            pool,
            owner.id,
            owner.auth_generation,
            target,
            RosterRemovalRoute::Remote {
                target_domain: PEER,
                unsubscribe_stanza: "",
                unsubscribed_stanza: "",
                bounce_to: None,
                policy: policy(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(result, AuthorizedRosterRemoval::Missing));
    }
    let pending = federated_presence_pending(pool, owner.id).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].requester, CONTACT);
    assert_eq!(snapshot(pool, owner.id).await, before);
    database.finish().await;
}
