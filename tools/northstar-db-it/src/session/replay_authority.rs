use northstar_auth_core::hash_password;
use northstar_auth_postgres::users::apply_password_credentials_in_tx;
use northstar_message_core::{OfflineStoreOutcome, OfflineStorePolicy};
use northstar_message_postgres::offline::store_offline;
use northstar_message_postgres::personal_history::{
    PersonalArchiveWrite, PersonalC2sDeliveryAdmission, PersonalHistoryAdmission,
};
use northstar_roster_postgres::{privacy, roster};
use northstar_session_application::outbound::{DurableDelivery, OutboundSender};
use northstar_session_application::replay::*;
use northstar_session_postgres::replay::acknowledge_durable_delivery;
use northstar_session_postgres::replay_repository::PostgresReplayRepository;
use northstar_workflows::{
    personal_history::admit_personal_history_and_c2s_delivery,
    retention::{purge_retention_batch, RetentionStore},
    roster::WorkflowRosterEffects,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

const RECIPIENT: &str = "recipient@local.test";
const RESOURCE: &str = "recipient@local.test/phone";
const SENDER: &str = "sender@remote.test/phone";
const SENDER_BARE: &str = "sender@remote.test";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    service: ReplayService<PostgresReplayRepository>,
    session: ReplaySession,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("replay_authority_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(60))
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::support::migrate(&pool).await.unwrap();
        let recipient_id = Uuid::new_v4();
        let auth_generation: i64 = sqlx::query_scalar(
            "INSERT INTO users(id,username,password_hash) VALUES($1,'recipient','test-only')
             RETURNING auth_generation",
        )
        .bind(recipient_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let service = ReplayService::new(
            PostgresReplayRepository::new(pool.clone()),
            "local.test",
            30,
        );
        let ReplayStartOutcome::Acquired(session) = service
            .start(
                ReplayRoute {
                    recipient_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    full_jid: RESOURCE.to_owned(),
                },
                None,
            )
            .await
            .unwrap()
        else {
            panic!("fresh replay route could not acquire its lease");
        };
        Self {
            admin,
            pool,
            schema,
            service,
            session,
        }
    }

    async fn refresh_cutoff(&mut self) {
        assert!(self.service.finish(&self.session).await.unwrap());
        let ReplayStartOutcome::Acquired(session) = self
            .service
            .start(self.session.route().clone(), None)
            .await
            .unwrap()
        else {
            panic!("released replay lease could not be reacquired");
        };
        self.session = session;
    }

    async fn close(self) {
        assert!(self.service.finish(&self.session).await.unwrap());
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }

    async fn claim(&self, active: Option<&str>, bind2: bool) -> AuthorizedReplayPage {
        let outcome = self
            .service
            .claim_current_page(
                &self.session,
                ReplayPageAuthority {
                    active_privacy_list: active,
                    is_current: &|| true,
                },
                bind2,
            )
            .await
            .unwrap();
        let AuthorizedReplayClaim::Claimed(page) = outcome else {
            panic!("expected a claimed page, got {outcome:?}");
        };
        page
    }

    async fn lock_account(&self) -> (Transaction<'static, Postgres>, i32) {
        let mut lock = self.pool.begin().await.unwrap();
        let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])")
            .bind(self.session.recipient_id())
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        (lock, blocker)
    }

    async fn assert_retained(&self, token: Uuid, id: Uuid) {
        assert_eq!(
            self.service
                .release_unsent(&self.session, token, &[id])
                .await
                .unwrap(),
            1
        );
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM offline_messages
               WHERE id=$1 AND recipient_id=$2 AND delivery_claim_id IS NULL)",
        )
        .bind(id)
        .bind(self.session.recipient_id())
        .fetch_one(&self.pool)
        .await
        .unwrap());
    }

    async fn expire_archive(&self) {
        let cutoff = sqlx::query_scalar("SELECT clock_timestamp() + INTERVAL '1 second'")
            .fetch_one(&self.pool)
            .await
            .unwrap();
        assert_eq!(
            purge_retention_batch(&self.pool, RetentionStore::PersonalMam, cutoff, 10)
                .await
                .unwrap(),
            1
        );
    }

    async fn seed(&self, archive_owner: Option<Uuid>, temporary: bool) -> Uuid {
        let id = Uuid::new_v4();
        let hint = if temporary {
            "<no-permanent-store xmlns='urn:xmpp:hints'/>"
        } else {
            ""
        };
        let stanza = format!(
            "<message from='{SENDER}' to='{RECIPIENT}'><body>example</body>{hint}\
             <stanza-id xmlns='urn:xmpp:sid:0' by='{RECIPIENT}' id='{id}'/></message>"
        );
        let projection = archive_owner.map(|owner_id| PersonalArchiveWrite {
            id,
            owner_id,
            peer_jid: SENDER,
            stanza: &stanza,
            encrypted: false,
            stanza_id: None,
        });
        let result = admit_personal_history_and_c2s_delivery(
            &self.pool,
            None,
            projection.as_slice(),
            &PersonalC2sDeliveryAdmission {
                id,
                recipient_id: self.session.recipient_id(),
                recipient_bare_jid: RECIPIENT,
                local_actor_id: None,
                sender_jid: SENDER,
                stanza: &stanza,
                target_full_jid: None,
                encrypted: false,
                policy: spool_policy(false),
            },
        )
        .await
        .unwrap();
        assert!(matches!(result, PersonalHistoryAdmission::Stored(_)));
        id
    }
}

fn spool_policy(mam_backed: bool) -> OfflineStorePolicy {
    OfflineStorePolicy {
        max_messages: 10,
        max_bytes: 16_384,
        ttl_days: 30,
        mam_backed,
    }
}

fn prepare_one(
    fixture: &Fixture,
    page: AuthorizedReplayPage,
    selected: Option<&'static str>,
    is_current: impl Fn() -> bool + Send + Sync + 'static,
) -> tokio::task::JoinHandle<ReplayPreparation> {
    let service = fixture.service.clone();
    let session = fixture.session.clone();
    tokio::spawn(async move {
        assert_eq!(page.messages.len(), 1);
        let (message, disposition) = &page.messages[0];
        service
            .prepare_current_message(
                &session,
                ReplayMessageAuthority {
                    route: ReplayPageAuthority {
                        active_privacy_list: selected,
                        is_current: &is_current,
                    },
                    policy_version: &page.policy_version,
                    claim_token: page.claim_token,
                    message_id: message.id,
                    disposition: *disposition,
                },
            )
            .await
            .unwrap()
    })
}

async fn assert_delivery(
    fixture: &Fixture,
    token: Uuid,
    message: ReplayMessage,
    prepared: ReplayPreparation,
) {
    let ReplayPreparation::Ready(guard) = prepared else {
        panic!("unproven MAM history must remain deliverable");
    };
    let (queue, mut receiver) = tokio::sync::mpsc::channel(1);
    let outbound = OutboundSender::new(queue);
    let delivery = DurableDelivery {
        recipient_id: fixture.session.recipient_id(),
        message_id: message.id,
        claim_id: Some(token),
    };
    assert!(outbound
        .send_durable_if_current(message.stanza.clone(), delivery, || true)
        .await
        .unwrap());
    guard.release().await.unwrap();
    let queued = receiver.try_recv().unwrap();
    assert_eq!(queued.stanza, message.stanza);
    acknowledge_durable_delivery(&fixture.pool, queued.c2s_delivery().unwrap())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn bind2_delivers_when_retention_wins_before_claim_or_suppression() {
    let mut fixture = Fixture::new().await;
    for before_claim in [true, false] {
        let id = fixture
            .seed(Some(fixture.session.recipient_id()), false)
            .await;
        fixture.refresh_cutoff().await;
        if before_claim {
            fixture.expire_archive().await;
        }
        let page = fixture.claim(None, true).await;
        let token = page.claim_token;
        assert_eq!(page.messages[0].0.id, id);
        assert_eq!(
            page.messages[0].1,
            if before_claim {
                ReplayDisposition::Deliver
            } else {
                ReplayDisposition::MamProjection(id)
            }
        );
        let message = page.messages[0].0.clone();
        let (lock, blocker) = fixture.lock_account().await;
        let prepare = prepare_one(&fixture, page, None, || true);
        crate::support::blocked_backend(&fixture.pool, blocker).await;
        if !before_claim {
            fixture.expire_archive().await;
        }
        lock.commit().await.unwrap();
        assert_delivery(&fixture, token, message, prepare.await.unwrap()).await;
    }
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn bind2_requires_recipient_projection_and_delivers_temporary_spool() {
    let mut fixture = Fixture::new().await;
    let recipient = fixture.session.recipient_id();
    assert_eq!(
        store_offline(
            &fixture.pool,
            recipient,
            SENDER,
            "<message id='legacy'/>",
            false,
            spool_policy(true)
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::Stored
    );
    let other_owner = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'other','test-only')")
        .bind(other_owner)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let foreign = fixture.seed(Some(other_owner), false).await;
    sqlx::query("UPDATE offline_messages SET mam_backed=TRUE WHERE id=$1")
        .bind(foreign)
        .execute(&fixture.pool)
        .await
        .unwrap();
    let temporary = fixture.seed(None, true).await;
    let archived = fixture.seed(Some(recipient), false).await;
    fixture.refresh_cutoff().await;
    let page = fixture.claim(None, true).await;
    let mut seen = 0;
    for (message, disposition) in page.messages {
        let expected = if message.id == archived {
            ReplayDisposition::MamProjection(archived)
        } else {
            ReplayDisposition::Deliver
        };
        assert_eq!(disposition, expected);
        let prepared = fixture
            .service
            .prepare_current_message(
                &fixture.session,
                ReplayMessageAuthority {
                    route: ReplayPageAuthority {
                        active_privacy_list: None,
                        is_current: &|| true,
                    },
                    policy_version: &page.policy_version,
                    claim_token: page.claim_token,
                    message_id: message.id,
                    disposition,
                },
            )
            .await
            .unwrap();
        if message.id == archived {
            assert!(matches!(prepared, ReplayPreparation::Suppressed));
        } else {
            assert!(
                message.id == temporary
                    || message.id == foreign
                    || message.stanza == "<message id='legacy'/>"
            );
            assert_delivery(&fixture, page.claim_token, message, prepared).await;
        }
        seen += 1;
    }
    assert_eq!(seen, 4);
    assert_eq!(
        northstar_message_postgres::offline::offline_message_count(&fixture.pool, recipient)
            .await
            .unwrap(),
        0
    );
    fixture.close().await;
}

async fn store_list(
    fixture: &Fixture,
    name: &str,
    action: privacy::PrivacyAction,
    group: Option<&str>,
) {
    privacy::replace_privacy_list(
        &fixture.pool,
        fixture.session.recipient_id(),
        &privacy::PrivacyList {
            name: name.to_owned(),
            items: vec![privacy::PrivacyItem {
                order: 1,
                action,
                match_type: group.map(|_| privacy::PrivacyMatchType::Group),
                match_value: group.map(str::to_owned),
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        },
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn replay_revalidates_block_active_default_roster_and_password() {
    let mut fixture = Fixture::new().await;
    let route = fixture.session.route().clone();
    let owner = route.recipient_id;
    store_list(&fixture, "allow", privacy::PrivacyAction::Allow, None).await;
    store_list(&fixture, "deny", privacy::PrivacyAction::Deny, None).await;
    store_list(
        &fixture,
        "group",
        privacy::PrivacyAction::Deny,
        Some("muted"),
    )
    .await;
    let id = fixture.seed(None, false).await;
    fixture.refresh_cutoff().await;
    let mut replacement =
        Some(hash_password("changed-test-credential", false, 4096, false).unwrap());
    for (change, selected, default, before, after) in [
        (
            "block",
            None,
            None,
            ReplayDisposition::Deliver,
            ReplayDisposition::Denied,
        ),
        (
            "active",
            Some("deny"),
            None,
            ReplayDisposition::Denied,
            ReplayDisposition::Deliver,
        ),
        (
            "default",
            None,
            Some("deny"),
            ReplayDisposition::Denied,
            ReplayDisposition::Deliver,
        ),
        (
            "roster",
            None,
            Some("group"),
            ReplayDisposition::Deliver,
            ReplayDisposition::Denied,
        ),
        (
            "password",
            None,
            Some("deny"),
            ReplayDisposition::Denied,
            ReplayDisposition::Denied,
        ),
    ] {
        assert!(
            privacy::set_default_privacy_list(&fixture.pool, owner, default)
                .await
                .unwrap()
        );
        assert!(privacy::set_active_privacy_list(
            &fixture.pool,
            owner,
            route.connection_id,
            selected
        )
        .await
        .unwrap());
        let page = fixture.claim(selected, false).await;
        assert_eq!(page.messages[0].1, before, "{change}");
        let token = page.claim_token;
        let (mut lock, blocker) = fixture.lock_account().await;
        let prepare = prepare_one(&fixture, page, selected, || true);
        crate::support::blocked_backend(&fixture.pool, blocker).await;
        match change {
            "block" => {
                sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
                    .bind(owner)
                    .bind(SENDER_BARE)
                    .execute(&mut *lock)
                    .await
                    .unwrap();
            }
            "active" => assert!(privacy::set_active_privacy_list_in_transaction(
                &mut lock,
                owner,
                route.connection_id,
                Some("allow"),
            )
            .await
            .unwrap()),
            "default" => {
                sqlx::query("UPDATE privacy_default_lists SET list_name='allow' WHERE owner_id=$1")
                    .bind(owner)
                    .execute(&mut *lock)
                    .await
                    .unwrap();
            }
            "roster" => {
                roster::upsert_roster_in_transaction(
                    &WorkflowRosterEffects,
                    &mut lock,
                    owner,
                    SENDER_BARE,
                    None,
                    &["muted".to_owned()],
                )
                .await
                .unwrap();
            }
            "password" => assert!(apply_password_credentials_in_tx(
                &mut lock,
                owner,
                route.auth_generation,
                replacement.take().unwrap(),
            )
            .await
            .unwrap()),
            _ => unreachable!(),
        }
        lock.commit().await.unwrap();
        let prepared = prepare.await.unwrap();
        if change == "password" {
            assert!(matches!(prepared, ReplayPreparation::StaleRoute));
        } else {
            assert!(matches!(prepared, ReplayPreparation::RetryPage), "{change}");
        }
        fixture.assert_retained(token, id).await;
        if change != "password" {
            let fresh = fixture
                .claim(
                    if change == "active" {
                        Some("allow")
                    } else {
                        selected
                    },
                    false,
                )
                .await;
            assert_eq!(fresh.messages[0].1, after, "{change}");
            fixture.assert_retained(fresh.claim_token, id).await;
        }
        if change == "block" {
            roster::unblock_jids(&fixture.pool, owner, Some(&[SENDER_BARE.to_owned()]))
                .await
                .unwrap();
        }
    }
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn sm_resume_suffix_refuses_a_replaced_connection() {
    let mut fixture = Fixture::new().await;
    let id = fixture.seed(None, false).await;
    fixture.refresh_cutoff().await;
    let page = fixture.claim(None, false).await;
    let token = page.claim_token;
    let expected = fixture.session.route().clone();
    let bound = Arc::new(Mutex::new(expected.clone()));
    let observable = Arc::clone(&bound);
    let (lock, blocker) = fixture.lock_account().await;
    let prepare = prepare_one(&fixture, page, None, move || {
        *observable.lock().unwrap() == expected
    });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    bound.lock().unwrap().connection_id = Uuid::new_v4();
    lock.commit().await.unwrap();
    assert!(matches!(
        prepare.await.unwrap(),
        ReplayPreparation::RetryPage
    ));
    fixture.assert_retained(token, id).await;
    fixture.close().await;
}
