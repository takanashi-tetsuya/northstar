//! Drives the personal archive admission ports over PostgreSQL.

use super::message_repository::{drop_isolated_message_pool, isolated_message_pool};
use northstar_message_application::messaging::*;
use northstar_workflows::message_repository::PostgresMessageRepository;
use sqlx::PgPool;
use uuid::Uuid;

const SENDER: Uuid = Uuid::from_u128(1);
const RECIPIENT: Uuid = Uuid::from_u128(2);
const FROM: &str = "alice@local.test/Phone";
const TO: &str = "bob@local.test";
const REMOTE: &str = "carol@remote.test/Laptop";
const LOCAL_XML: &str =
    "<message from='alice@local.test/Phone' to='bob@local.test'><body>local</body></message>";
const INBOUND_XML: &str =
    "<message from='carol@remote.test/Laptop' to='bob@local.test'><body>inbound</body></message>";
const OUTBOUND_XML: &str =
    "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop'><body>outbound</body></message>";

async fn insert_accounts(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test'),($2,'bob','test')",
    )
    .bind(SENDER)
    .bind(RECIPIENT)
    .execute(pool)
    .await
    .unwrap();
}

async fn set_default(pool: &PgPool, owner_id: Uuid, policy: &str) {
    let (username, auth_generation): (String, i64) =
        sqlx::query_as("SELECT username, auth_generation FROM users WHERE id=$1")
            .bind(owner_id)
            .fetch_one(pool)
            .await
            .unwrap();
    northstar_archive_postgres::set_mam_preferences(
        pool,
        &northstar_archive_core::MamLocalAuthority {
            id: owner_id,
            username,
            auth_generation,
        },
        &northstar_archive_postgres::MamPreferences {
            default_policy: policy.to_owned(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

fn service(pool: &PgPool, max_bytes: i64) -> MessageService<PostgresMessageRepository> {
    MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            northstar_abuse_application::guard::test_personal_message_content_keyring(),
            "local.test",
            100,
            max_bytes,
            30,
        ),
        false,
    )
}

fn candidate(
    owner_id: Uuid,
    direction: ArchiveDirection,
    peer_jid: &'static str,
    stanza: &'static str,
) -> ArchiveCandidate<'static> {
    ArchiveCandidate {
        direction,
        projection: ArchiveWrite {
            id: Uuid::new_v4(),
            owner_id,
            peer_jid,
            stanza,
            encrypted: false,
            stanza_id: None,
        },
    }
}

fn local_delivery(
    delivery_id: Uuid,
    sender_jid: &'static str,
    stanza: &'static str,
) -> LocalDelivery<'static> {
    LocalDelivery {
        delivery_id,
        recipient_id: RECIPIENT,
        recipient_bare_jid: TO,
        sender_jid,
        stanza,
        encrypted: false,
    }
}

async fn archive_owners(pool: &PgPool, candidates: &[ArchiveCandidate<'_>]) -> Vec<Uuid> {
    let ids = candidates
        .iter()
        .map(|candidate| candidate.projection.id)
        .collect::<Vec<_>>();
    sqlx::query_scalar("SELECT owner_id FROM message_archive WHERE id=ANY($1) ORDER BY owner_id")
        .bind(&ids)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn mam_backed(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT mam_backed FROM offline_messages WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn paired_preferences_are_sampled_after_history_account_fence() {
    let (admin, pool, schema) = isolated_message_pool().await;
    insert_accounts(&pool).await;
    set_default(&pool, SENDER, "always").await;
    set_default(&pool, RECIPIENT, "never").await;
    assert!(
        northstar_archive_postgres::archive_allowed(&pool, SENDER, TO)
            .await
            .unwrap()
    );
    assert!(
        !northstar_archive_postgres::archive_allowed(&pool, RECIPIENT, FROM)
            .await
            .unwrap()
    );

    let candidates = [
        candidate(SENDER, ArchiveDirection::Outbound, TO, LOCAL_XML),
        candidate(RECIPIENT, ArchiveDirection::Inbound, FROM, LOCAL_XML),
    ];
    let delivery_id = candidates[1].projection.id;
    let mut policy = pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *policy)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(SENDER)
        .fetch_one(&mut *policy)
        .await
        .unwrap();

    let commit = tokio::spawn({
        let service = service(&pool, 4096);
        let candidates = candidates.clone();
        async move {
            service
                .admit_personal_message(&ValidatedPersonalMessage {
                    local_actor_id: Some(SENDER),
                    local_actor_fence: None,
                    policy: None,
                    identity: None,
                    archives: &candidates,
                    destination: PersonalMessageDestination::Local(local_delivery(
                        delivery_id,
                        FROM,
                        LOCAL_XML,
                    )),
                })
                .await
        }
    });
    crate::support::blocked_backend(&pool, blocker).await;
    sqlx::query(
        "UPDATE mam_preferences SET default_policy=CASE WHEN user_id=$1 THEN 'never' ELSE 'always' END
         WHERE user_id IN ($1,$2)",
    )
    .bind(SENDER)
    .bind(RECIPIENT)
    .execute(&mut *policy)
    .await
    .unwrap();
    policy.commit().await.unwrap();

    // A sender sample before the switch and a recipient sample after it
    // would both say allow. The persisted owners must match the new pair.
    assert!(
        northstar_archive_postgres::archive_allowed(&pool, RECIPIENT, FROM)
            .await
            .unwrap()
    );
    assert_eq!(
        commit.await.unwrap().unwrap(),
        DurableAdmissionOutcome::Stored {
            archive_written: true,
            post_commit: MessagePostCommit::RouteLocalDelivery {
                delivery_id,
                recipient_id: RECIPIENT,
            },
        }
    );
    assert_eq!(archive_owners(&pool, &candidates).await, [RECIPIENT]);
    assert!(mam_backed(&pool, delivery_id).await);

    let volatile = [
        candidate(SENDER, ArchiveDirection::Outbound, TO, LOCAL_XML),
        candidate(RECIPIENT, ArchiveDirection::Inbound, FROM, LOCAL_XML),
    ];
    let service = service(&pool, 4096);
    assert_eq!(
        service.admit_history(&volatile).await.unwrap(),
        ArchiveAdmissionOutcome::Projected(vec![volatile[1].projection.id])
    );
    assert_eq!(archive_owners(&pool, &volatile).await, [RECIPIENT]);
    drop_isolated_message_pool(admin, pool, schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn federated_admission_uses_committed_opt_out_and_opt_in() {
    let (admin, pool, schema) = isolated_message_pool().await;
    insert_accounts(&pool).await;
    let service = service(&pool, 4096);
    for (policy, allowed) in [("never", false), ("always", true)] {
        let inbound = [candidate(
            RECIPIENT,
            ArchiveDirection::Inbound,
            REMOTE,
            INBOUND_XML,
        )];
        let outbound = [candidate(
            SENDER,
            ArchiveDirection::Outbound,
            REMOTE,
            OUTBOUND_XML,
        )];
        let delivery_id = inbound[0].projection.id;
        set_default(&pool, RECIPIENT, policy).await;
        set_default(&pool, SENDER, policy).await;
        let expected_recipient: Vec<_> = allowed.then_some(RECIPIENT).into_iter().collect();
        let expected_sender: Vec<_> = allowed.then_some(SENDER).into_iter().collect();
        assert_eq!(
            service
                .admit_personal_message(&ValidatedPersonalMessage {
                    local_actor_id: None,
                    local_actor_fence: None,
                    policy: None,
                    identity: None,
                    archives: &inbound,
                    destination: PersonalMessageDestination::Local(local_delivery(
                        delivery_id,
                        REMOTE,
                        INBOUND_XML,
                    )),
                })
                .await
                .unwrap(),
            DurableAdmissionOutcome::Stored {
                archive_written: allowed,
                post_commit: MessagePostCommit::RouteLocalDelivery {
                    delivery_id,
                    recipient_id: RECIPIENT,
                },
            }
        );
        assert_eq!(archive_owners(&pool, &inbound).await, expected_recipient);
        assert_eq!(mam_backed(&pool, delivery_id).await, allowed);
        assert_eq!(
            service
                .admit_personal_message(&ValidatedPersonalMessage {
                    local_actor_id: Some(SENDER),
                    local_actor_fence: None,
                    policy: None,
                    identity: None,
                    archives: &outbound,
                    destination: PersonalMessageDestination::Federation(FederationDelivery {
                        local_actor_id: SENDER,
                        target_domain: "remote.test",
                        stanza: OUTBOUND_XML,
                        bounce_to: Some(FROM),
                        limits: northstar_federation_core::S2sOutboxPolicy::new(300, 10, 4096, 10),
                    }),
                })
                .await
                .unwrap(),
            DurableAdmissionOutcome::Stored {
                archive_written: allowed,
                post_commit: MessagePostCommit::WakeFederationOutbox,
            }
        );
        assert_eq!(archive_owners(&pool, &outbound).await, expected_sender);
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        2
    );
    drop_isolated_message_pool(admin, pool, schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn failed_delivery_rolls_back_selected_archive_rows_and_identity() {
    let (admin, pool, schema) = isolated_message_pool().await;
    insert_accounts(&pool).await;
    let candidates = [
        candidate(SENDER, ArchiveDirection::Outbound, TO, LOCAL_XML),
        candidate(RECIPIENT, ArchiveDirection::Inbound, FROM, LOCAL_XML),
    ];
    let delivery_id = candidates[1].projection.id;
    let request = ValidatedPersonalMessage {
        local_actor_id: Some(SENDER),
        local_actor_fence: None,
        policy: None,
        identity: Some(MessageIdentity {
            authority: IdentityAuthority::LocalOrigin,
            actor_scope_raw: "alice@local.test",
            actor_scope: "alice@local.test",
            target_scope: TO,
            value: "origin-capacity-failure",
            payload: LOCAL_XML,
        }),
        archives: &candidates,
        destination: PersonalMessageDestination::Local(local_delivery(
            delivery_id,
            FROM,
            LOCAL_XML,
        )),
    };
    let error = service(&pool, 1)
        .admit_personal_message(&request)
        .await
        .unwrap_err();
    assert!(error.is::<northstar_message_postgres::personal_history::C2sDeliveryCapacityExceeded>());
    assert!(archive_owners(&pool, &candidates).await.is_empty());
    assert_eq!(
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT (SELECT COUNT(*) FROM offline_messages),
                    (SELECT COUNT(*) FROM personal_message_admissions)",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        (0, 0)
    );

    let service = service(&pool, 4096);
    assert!(matches!(
        service.admit_personal_message(&request).await.unwrap(),
        DurableAdmissionOutcome::Stored {
            archive_written: true,
            ..
        }
    ));
    assert_eq!(
        archive_owners(&pool, &candidates).await,
        [SENDER, RECIPIENT]
    );
    assert!(mam_backed(&pool, delivery_id).await);
    assert_eq!(
        service.admit_personal_message(&request).await.unwrap(),
        DurableAdmissionOutcome::Replay
    );
    drop_isolated_message_pool(admin, pool, schema).await;
}
