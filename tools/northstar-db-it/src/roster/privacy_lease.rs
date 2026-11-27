use super::presence_service::IsolatedDatabase;
use crate::support::blocked_backend;
use northstar_roster_application::privacy::PrivacySelectionOutcome;
use northstar_roster_core::RosterActor;
use northstar_roster_postgres::privacy::{
    clear_active_privacy_session, reap_expired_active_privacy_selections, remove_privacy_list,
    renew_active_privacy_selection, replace_privacy_list, session_privacy_denies,
    set_active_privacy_list, set_default_privacy_list, PrivacyAction, PrivacyItem, PrivacyList,
    PrivacyStanzaKind, RemovePrivacyListOutcome,
};
use northstar_session_application::sm::{
    SmResumeFinalizationOutcome, SmResumeFinalizationRequest, SmService,
};
use northstar_workflows::privacy::privacy_denies_for_sm_session;
use northstar_workflows::sm::{self, SmClaimStatus, SmSessionSnapshot};
use northstar_workflows::sm_repository::{
    activate_privacy_selection, renew_capacity_and_privacy_leases, PostgresSmRepository,
    PrivacySelectionCheckpoint,
};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

const PEER: &str = "alice@example.test/Phone";
const TOKEN: [u8; 32] = [27; 32];

struct Fixture {
    database: IsolatedDatabase,
    actor: RosterActor,
    sm_id: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let database = IsolatedDatabase::create("privacy_lease").await;
        let pool = &database.pool;
        let owner = northstar_auth_postgres::users::create_user(
            pool,
            "bob",
            "Initial password for test!42",
            false,
            true,
            4096,
            false,
        )
        .await
        .unwrap();
        let actor = RosterActor {
            account_id: owner.id,
            auth_generation: owner.auth_generation,
            connection_id: Uuid::new_v4(),
            full_jid: "bob@example.test/Phone".to_owned(),
        };
        for (name, action) in [
            ("open", PrivacyAction::Allow),
            ("quiet", PrivacyAction::Deny),
        ] {
            replace_privacy_list(
                pool,
                actor.account_id,
                &PrivacyList {
                    name: name.to_owned(),
                    items: vec![PrivacyItem {
                        order: 1,
                        action,
                        match_type: None,
                        match_value: None,
                        message: true,
                        iq: false,
                        presence_in: false,
                        presence_out: false,
                    }],
                },
            )
            .await
            .unwrap();
        }
        assert!(
            set_default_privacy_list(pool, actor.account_id, Some("open"))
                .await
                .unwrap()
        );
        let sm_id = sm::create_sm_session(
            pool,
            &TOKEN,
            actor.account_id,
            actor.auth_generation,
            &actor.full_jid,
            "Phone",
            "example.test",
            actor.connection_id,
            &snapshot(None),
            300,
            120,
            8,
            64,
        )
        .await
        .unwrap();
        Self {
            database,
            actor,
            sm_id,
        }
    }

    fn pool(&self) -> &PgPool {
        &self.database.pool
    }

    async fn select(&self, list: Option<&str>) {
        assert_eq!(
            activate_privacy_selection(
                self.pool(),
                &self.actor,
                list,
                Some(checkpoint(self.sm_id))
            )
            .await
            .unwrap(),
            PrivacySelectionOutcome::Updated,
        );
    }

    async fn live_denies(&self, expects_active: bool) -> bool {
        session_privacy_denies(
            self.pool(),
            self.actor.account_id,
            Some(self.actor.connection_id),
            expects_active,
            PEER,
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap()
    }

    async fn sm_denies(&self) -> bool {
        privacy_denies_for_sm_session(self.pool(), self.sm_id, PEER, PrivacyStanzaKind::Message)
            .await
            .unwrap()
            .unwrap()
    }
}

fn snapshot(list: Option<&str>) -> SmSessionSnapshot {
    SmSessionSnapshot {
        inbound_h: 0,
        outbound_h: 0,
        acked_h: 0,
        available: true,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: list.map(str::to_owned),
        privacy_requested: true,
        peer_ip: "192.0.2.44".parse().unwrap(),
        user_agent_id: None,
        joined_rooms: Vec::new(),
        directed_presence: Vec::new(),
        last_presence: None,
        unacked: Vec::new(),
    }
}

fn checkpoint(session_id: Uuid) -> PrivacySelectionCheckpoint {
    PrivacySelectionCheckpoint {
        session_id,
        snapshot: snapshot(None),
        ttl_seconds: 300,
        live_lease_seconds: 120,
    }
}

async fn backend(tx: &mut Transaction<'_, Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

async fn lock_selector(tx: &mut Transaction<'_, Postgres>, connection: Uuid) {
    sqlx::query(
        "SELECT connection_id FROM privacy_active_sessions WHERE connection_id=$1 FOR UPDATE",
    )
    .bind(connection)
    .fetch_one(&mut **tx)
    .await
    .unwrap();
}

async fn selector(pool: &PgPool, connection: Uuid) -> Option<(String, String, String)> {
    sqlx::query_as(
        "SELECT list_name,updated_at::text,expires_at::text
           FROM privacy_active_sessions WHERE connection_id=$1",
    )
    .bind(connection)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn capacity(pool: &PgPool, connection: Uuid) -> (String, String) {
    sqlx::query_as(
        "SELECT updated_at::text,lease_until::text FROM deployment_session_leases WHERE connection_id=$1",
    )
    .bind(connection)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn renewal_waiting_on_a_selector_cannot_extend_it_after_expiry() {
    let fixture = Fixture::new().await;
    fixture.select(Some("open")).await;
    assert!(!fixture.live_denies(true).await);
    let connection = fixture.actor.connection_id;
    let pool = fixture.pool();
    let mut writer = pool.begin().await.unwrap();
    let blocker = backend(&mut writer).await;
    lock_selector(&mut writer, connection).await;
    let renew_pool = pool.clone();
    let renewal = tokio::spawn(async move {
        renew_active_privacy_selection(&renew_pool, &[connection])
            .await
            .unwrap();
    });
    let waiter = blocked_backend(pool, blocker).await;
    let expired = sqlx::query_as(
        "UPDATE privacy_active_sessions
            SET expires_at=(SELECT GREATEST(clock_timestamp(),query_start+INTERVAL '1 microsecond')
                              FROM pg_stat_activity WHERE pid=$2)
          WHERE connection_id=$1
          RETURNING list_name,updated_at::text,expires_at::text",
    )
    .bind(connection)
    .bind(waiter)
    .fetch_one(&mut *writer)
    .await
    .unwrap();
    writer.commit().await.unwrap();
    renewal.await.unwrap();
    assert_eq!(selector(pool, connection).await, Some(expired));
    assert!(fixture.live_denies(true).await);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn renewal_uses_only_capacity_winners_and_rolls_back_on_privacy_failure() {
    let fixture = Fixture::new().await;
    fixture.select(Some("quiet")).await;
    let pool = fixture.pool();
    let live = fixture.actor.connection_id;
    let orphan = Uuid::new_v4();
    assert!(
        set_active_privacy_list(pool, fixture.actor.account_id, orphan, Some("quiet"))
            .await
            .unwrap()
    );
    let orphan_before = selector(pool, orphan).await;
    let live_before = selector(pool, live).await;
    let winners = renew_capacity_and_privacy_leases(pool, &[live, orphan], 120)
        .await
        .unwrap();
    assert_eq!(winners, std::collections::HashSet::from([live]));
    assert_eq!(selector(pool, orphan).await, orphan_before);
    assert_ne!(selector(pool, live).await, live_before);

    sqlx::query(
        "CREATE FUNCTION fail_privacy_renewal() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'forced privacy renewal failure'; END $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_privacy_renewal BEFORE UPDATE ON privacy_active_sessions
          FOR EACH ROW EXECUTE FUNCTION fail_privacy_renewal()",
    )
    .execute(pool)
    .await
    .unwrap();
    let capacity_before = capacity(pool, live).await;
    let privacy_before = selector(pool, live).await;
    let error = renew_capacity_and_privacy_leases(pool, &[live], 600)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("forced privacy renewal failure"));
    assert_eq!(capacity(pool, live).await, capacity_before);
    assert_eq!(selector(pool, live).await, privacy_before);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn activation_and_decline_publish_sm_and_lease_together_before_checkpoint() {
    let fixture = Fixture::new().await;
    let pool = fixture.pool();
    sqlx::query(
        "CREATE FUNCTION pause_privacy_commit() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN PERFORM pg_advisory_xact_lock(752,9); RETURN NEW; END $$",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER pause_privacy_commit AFTER INSERT OR UPDATE OR DELETE ON privacy_active_sessions
          DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION pause_privacy_commit()",
    )
    .execute(pool)
    .await
    .unwrap();
    let mut hold_commit = pool.begin().await.unwrap();
    let commit_blocker = backend(&mut hold_commit).await;
    sqlx::query("SELECT pg_advisory_xact_lock(752,9)")
        .execute(&mut *hold_commit)
        .await
        .unwrap();
    let mut hold_sm = pool.begin().await.unwrap();
    let sm_blocker = backend(&mut hold_sm).await;
    sqlx::query("SELECT id FROM sm_resume_sessions WHERE id=$1 FOR UPDATE")
        .bind(fixture.sm_id)
        .execute(&mut *hold_sm)
        .await
        .unwrap();
    let task_pool = pool.clone();
    let actor = fixture.actor.clone();
    let sm_id = fixture.sm_id;
    let activation = tokio::spawn(async move {
        activate_privacy_selection(&task_pool, &actor, Some("quiet"), Some(checkpoint(sm_id)))
            .await
            .unwrap()
    });
    blocked_backend(pool, sm_blocker).await;
    assert!(!fixture.live_denies(false).await);
    assert!(!fixture.sm_denies().await);
    hold_sm.commit().await.unwrap();
    blocked_backend(pool, commit_blocker).await;
    assert!(!fixture.live_denies(false).await);
    assert!(!fixture.sm_denies().await);
    hold_commit.commit().await.unwrap();
    assert_eq!(activation.await.unwrap(), PrivacySelectionOutcome::Updated);
    assert!(fixture.live_denies(false).await);
    assert!(fixture.sm_denies().await);

    let mut hold_decline = pool.begin().await.unwrap();
    let blocker = backend(&mut hold_decline).await;
    sqlx::query("SELECT pg_advisory_xact_lock(752,9)")
        .execute(&mut *hold_decline)
        .await
        .unwrap();
    let task_pool = pool.clone();
    let actor = fixture.actor.clone();
    let decline = tokio::spawn(async move {
        activate_privacy_selection(&task_pool, &actor, None, Some(checkpoint(sm_id)))
            .await
            .unwrap()
    });
    blocked_backend(pool, blocker).await;
    assert!(fixture.live_denies(true).await);
    assert!(fixture.sm_denies().await);
    hold_decline.commit().await.unwrap();
    assert_eq!(decline.await.unwrap(), PrivacySelectionOutcome::Updated);
    assert!(fixture.live_denies(true).await);
    assert!(!fixture.live_denies(false).await);
    assert!(!fixture.sm_denies().await);
    assert!(selector(pool, fixture.actor.connection_id).await.is_none());
    let mut hold_checkpoint = pool.begin().await.unwrap();
    let blocker = backend(&mut hold_checkpoint).await;
    sqlx::query("SELECT id FROM sm_resume_sessions WHERE id=$1 FOR UPDATE")
        .bind(sm_id)
        .execute(&mut *hold_checkpoint)
        .await
        .unwrap();
    let task_pool = pool.clone();
    let connection = fixture.actor.connection_id;
    let checkpoint_task = tokio::spawn(async move {
        let mut declined = snapshot(None);
        declined.inbound_h = 1;
        sm::checkpoint_sm_session_with_ownership_resolution(
            &task_pool, sm_id, connection, &declined, 300, 120, 64, 65_536,
        )
        .await
        .unwrap()
    });
    blocked_backend(pool, blocker).await;
    assert!(!fixture.sm_denies().await);
    assert!(!fixture.live_denies(false).await);
    hold_checkpoint.commit().await.unwrap();
    assert!(checkpoint_task.await.unwrap().updated);
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn resume_rebuilds_only_the_new_selector_while_old_clear_and_reaper_overlap() {
    let fixture = Fixture::new().await;
    fixture.select(Some("quiet")).await;
    let pool = fixture.pool();
    let old = fixture.actor.connection_id;
    let owner = fixture.actor.account_id;
    let suspended = snapshot(Some("quiet"));
    assert!(
        sm::suspend_sm_session(pool, fixture.sm_id, old, &suspended, 300, 64, 65_536)
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE privacy_active_sessions SET expires_at=clock_timestamp() WHERE connection_id=$1",
    )
    .bind(old)
    .execute(pool)
    .await
    .unwrap();
    let mut holding_old = pool.begin().await.unwrap();
    let blocker = backend(&mut holding_old).await;
    lock_selector(&mut holding_old, old).await;
    let task_pool = pool.clone();
    let clear = tokio::spawn(async move {
        clear_active_privacy_session(&task_pool, owner, old)
            .await
            .unwrap();
    });
    blocked_backend(pool, blocker).await;
    assert_eq!(
        reap_expired_active_privacy_selections(pool, 1)
            .await
            .unwrap(),
        0
    );
    let SmClaimStatus::Claimed(claim) = sm::claim_sm_session_status(
        pool,
        &TOKEN,
        owner,
        suspended.peer_ip,
        None,
        sm::SmIpPolicy::Exact,
        false,
        30,
    )
    .await
    .unwrap() else {
        panic!("could not claim suspended SM session")
    };
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(pool)
        .await
        .unwrap();
    let service = SmService::new(
        PostgresSmRepository::new(pool.clone(), Arc::new(zeroize::Zeroizing::new(vec![9; 32]))),
        schema,
    )
    .unwrap();
    let new = Uuid::new_v4();
    let resumed = service
        .finalize_resume(SmResumeFinalizationRequest {
            session_id: fixture.sm_id,
            claim_token: claim.claim_token,
            connection_id: new,
            user_id: owner,
            expected_auth_generation: fixture.actor.auth_generation,
            client_h: 0,
            acknowledged_count: 0,
            peer_ip: suspended.peer_ip,
            user_agent_id: None,
            active_privacy_list: claim.active_privacy_list.as_deref(),
            ttl_seconds: 300,
            live_lease_seconds: 120,
            max_stanzas: 64,
            max_bytes: 65_536,
            fast_plan: None,
        })
        .await
        .unwrap();
    assert!(matches!(resumed, SmResumeFinalizationOutcome::Committed(_)));
    let winners = renew_capacity_and_privacy_leases(pool, &[old, new], 120)
        .await
        .unwrap();
    assert_eq!(winners, std::collections::HashSet::from([new]));
    holding_old.commit().await.unwrap();
    clear.await.unwrap();
    assert!(selector(pool, old).await.is_none());
    assert_eq!(selector(pool, new).await.unwrap().0, "quiet");
    fixture.database.finish().await;
}

#[tokio::test]
#[ignore = "requires a random-schema TEST_DATABASE_URL"]
async fn expired_sm_reference_conflicts_and_expired_sm_policy_fails_closed() {
    let fixture = Fixture::new().await;
    fixture.select(Some("quiet")).await;
    let pool = fixture.pool();
    assert!(fixture.sm_denies().await);
    sqlx::query(
        "UPDATE privacy_active_sessions SET expires_at=clock_timestamp() WHERE connection_id=$1",
    )
    .bind(fixture.actor.connection_id)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        reap_expired_active_privacy_selections(pool, 1)
            .await
            .unwrap(),
        1
    );
    sqlx::query("UPDATE sm_resume_sessions SET expires_at=clock_timestamp() WHERE id=$1")
        .bind(fixture.sm_id)
        .execute(pool)
        .await
        .unwrap();
    assert!(fixture.sm_denies().await);
    assert_eq!(
        remove_privacy_list(pool, fixture.actor.account_id, "quiet")
            .await
            .unwrap(),
        RemovePrivacyListOutcome::Conflict,
    );
    fixture.database.finish().await;
}
