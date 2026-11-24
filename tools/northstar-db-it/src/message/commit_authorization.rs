use super::message_repository::{drop_isolated_message_pool, isolated_message_pool_for};
use futures::future::BoxFuture;
use northstar_auth_postgres::users::{change_password, create_user, User};
use northstar_message_application::messaging::{
    ArchiveAdmissionOutcome, ArchiveCandidate, ArchiveDirection, ArchiveWrite, MessageService,
    OfflineMessageAdmission,
};
use northstar_message_core::{
    ActorGenerationFence, DirectMessagePolicy, DirectPersonalMessageAdmission, DirectPolicyDenial,
    DirectPostCommitMode, DirectSpoolEligibility, IdentityAuthority, LocalDelivery, MessageCommit,
    MessageIdentity, PersonalMessageDestination, PrivacySelection, ValidatedPersonalMessage,
};
use northstar_message_postgres::direct_cluster::{DirectCommitCluster, DirectCommitPermit};
use northstar_postgres::cluster_lock::CLUSTER_KEY_AUTHORITY_LOCK;
use northstar_roster_postgres::{
    privacy::{replace_privacy_list, set_active_privacy_list, set_default_privacy_list},
    roster::{block_jids, unblock_jids},
};
use northstar_security::cluster_keys::ClusterReadinessAuthority;
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_xep_0016::{
    PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const FROM: &str = "alice@local.test/Phone";
const TO: &str = "bob@local.test";
const XML: &str = "<message from='alice@local.test/Phone' to='bob@local.test' type='chat'><body>hello</body></message>";

struct Cluster(DirectPostCommitMode);

impl DirectCommitPermit for Cluster {
    fn admitted_mode(&self) -> DirectPostCommitMode {
        self.0
    }

    fn finish(self: Box<Self>) -> DirectPostCommitMode {
        self.0
    }
}

impl DirectCommitCluster for Cluster {
    fn is_enabled(&self) -> bool {
        true
    }

    fn direct_mode(&self) -> DirectPostCommitMode {
        self.0
    }

    fn check_direct_eligibility(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> anyhow::Result<Option<&ClusterReadinessAuthority>> {
        anyhow::ensure!(
            self.0 != DirectPostCommitMode::SpoolOnly
                || eligibility == DirectSpoolEligibility::Eligible
        );
        Ok(None)
    }

    fn begin_direct_commit_turn(
        &self,
        eligibility: DirectSpoolEligibility,
    ) -> anyhow::Result<(
        Box<dyn DirectCommitPermit>,
        Option<&ClusterReadinessAuthority>,
    )> {
        Ok((
            Box::new(Self(self.0)),
            self.check_direct_eligibility(eligibility)?,
        ))
    }

    fn fence_authority<'a>(
        &'a self,
        _: &'a mut Transaction<'_, Postgres>,
        _: &'a ClusterReadinessAuthority,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        unreachable!()
    }
}

fn service(pool: &PgPool, mode: DirectPostCommitMode) -> MessageService<PostgresMessageRepository> {
    MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            northstar_abuse_application::guard::test_personal_message_content_keyring(),
            "local.test",
            100,
            8_000_000,
            30,
        )
        .with_cluster_admission(Cluster(mode)),
        false,
    )
}

async fn insert_user(pool: &PgPool, username: &str, admin: bool) -> User {
    create_user(
        pool,
        username,
        "Initial password for test!42",
        admin,
        true,
        4096,
        false,
    )
    .await
    .unwrap()
}

async fn block_commit(pool: &PgPool) -> (Transaction<'static, Postgres>, i32) {
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CLUSTER_KEY_AUTHORITY_LOCK)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    (blocker, pid)
}

fn start_commit(
    service: MessageService<PostgresMessageRepository>,
    sender: &User,
    recipient: &User,
    selection: Option<PrivacySelection>,
) -> tokio::task::JoinHandle<anyhow::Result<DirectPersonalMessageAdmission>> {
    let recipient_id = recipient.id;
    let fence = ActorGenerationFence {
        account_id: sender.id,
        auth_generation: sender.auth_generation,
    };
    tokio::spawn(async move {
        let recipient_sessions: Vec<_> = selection.into_iter().collect();
        let delivery_id = Uuid::new_v4();
        let archives = [ArchiveCandidate {
            direction: ArchiveDirection::Inbound,
            projection: ArchiveWrite {
                id: delivery_id,
                owner_id: recipient_id,
                peer_jid: FROM,
                stanza: XML,
                encrypted: false,
                stanza_id: None,
            },
        }];
        let request = ValidatedPersonalMessage {
            local_actor_id: Some(fence.account_id),
            local_actor_fence: Some(fence),
            policy: Some(DirectMessagePolicy {
                from: FROM,
                to: TO,
                sender: None,
                recipient_sessions: &recipient_sessions,
                remote_recipient_route: false,
            }),
            identity: Some(MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: "alice@local.test",
                actor_scope: "alice@local.test",
                target_scope: TO,
                value: "authorization-race",
                payload: XML,
            }),
            archives: &archives,
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id,
                recipient_id,
                recipient_bare_jid: TO,
                sender_jid: FROM,
                stanza: XML,
                encrypted: false,
            }),
        };
        service
            .admit_personal_message_with_mode(&request, DirectSpoolEligibility::Eligible)
            .await
    })
}

async fn assert_no_projections(pool: &PgPool) {
    let count: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM personal_message_admissions)
              + (SELECT count(*) FROM message_archive)
              + (SELECT count(*) FROM offline_messages)
              + (SELECT count(*) FROM s2s_outbox)
              + (SELECT count(*) FROM direct_spool_wake_outbox)",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn actor_generation_changes_refuse_without_projections() {
    let (admin, pool, schema) = isolated_message_pool_for("commit_actor").await;
    let operator = insert_user(&pool, "operator", true).await;
    let recipient = insert_user(&pool, "bob", false).await;
    for change in ["password", "reset", "disable", "reenable", "delete"] {
        let sender = insert_user(&pool, "alice", false).await;
        let (blocker, pid) = block_commit(&pool).await;
        let commit = start_commit(
            service(&pool, DirectPostCommitMode::Live),
            &sender,
            &recipient,
            None,
        );
        crate::support::blocked_backend(&pool, pid).await;
        match change {
            "password" => change_password(
                &pool,
                sender.id,
                "Replacement password for test!97",
                4096,
                false,
            )
            .await
            .unwrap(),
            "reset" => {
                let result: String = sqlx::query_scalar(
                    "SELECT northstar_admin_reset_user_password($1,'operator',$2,account.id,'alice',
                        account.password_hash,account.scram_sha256_salt,account.scram_sha256_iterations,
                        account.scram_sha256_stored_key,account.scram_sha256_server_key,
                        account.scram_sha1_salt,account.scram_sha1_iterations,
                        account.scram_sha1_stored_key,account.scram_sha1_server_key)
                     FROM users account WHERE account.id=$3",
                )
                .bind(operator.id)
                .bind(operator.auth_generation)
                .bind(sender.id)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(result, "applied");
            }
            "disable" | "reenable" => {
                let actions: &[_] = if change == "disable" {
                    &["disable"]
                } else {
                    &["disable", "reenable"]
                };
                for action in actions {
                    let result: String = sqlx::query_scalar(
                        "SELECT northstar_admin_user_lifecycle($1,'operator',$2,$3,'alice',$4)",
                    )
                    .bind(operator.id)
                    .bind(operator.auth_generation)
                    .bind(sender.id)
                    .bind(*action)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                    assert_eq!(result, "applied");
                }
            }
            "delete" => (),
            _ => unreachable!(),
        }
        if change == "delete" {
            delete_sender(&pool, &operator, &sender).await;
        }
        blocker.commit().await.unwrap();
        assert_eq!(
            commit.await.unwrap().unwrap().commit,
            MessageCommit::AccountUnavailable,
            "{change}"
        );
        assert_no_projections(&pool).await;
        if change != "delete" {
            delete_sender(&pool, &operator, &sender).await;
        }
    }
    drop_isolated_message_pool(admin, pool, schema).await;
}

async fn delete_sender(pool: &PgPool, operator: &User, sender: &User) {
    let result: String =
        sqlx::query_scalar("SELECT northstar_admin_delete_user($1,'operator',$2,$3,'alice')")
            .bind(operator.id)
            .bind(operator.auth_generation)
            .bind(sender.id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(result, "applied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn policy_changes_before_commit_cannot_leave_mixed_projections() {
    let (admin, pool, schema) = isolated_message_pool_for("commit_policy").await;
    let sender = insert_user(&pool, "alice", false).await;
    let recipient = insert_user(&pool, "bob", false).await;
    let connection = Uuid::new_v4();
    for (name, action, group) in [
        ("allow", PrivacyAction::Allow, None),
        ("deny", PrivacyAction::Deny, None),
        ("group", PrivacyAction::Deny, Some("Friends")),
    ] {
        replace_privacy_list(
            &pool,
            recipient.id,
            &PrivacyList {
                name: name.to_owned(),
                items: vec![PrivacyItem {
                    order: 10,
                    action,
                    match_type: group.map(|_| PrivacyMatchType::Group),
                    match_value: group.map(str::to_owned),
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
    for change in [
        "active",
        "default",
        "spool",
        "degraded",
        "group",
        "outbound_block",
        "block",
    ] {
        let mode = if matches!(change, "spool" | "degraded") {
            DirectPostCommitMode::SpoolOnly
        } else {
            DirectPostCommitMode::Live
        };
        let selection = matches!(change, "active" | "degraded").then_some(PrivacySelection {
            connection_id: connection,
            expects_active: true,
        });
        let service = service(&pool, mode);
        let default = if change == "group" { "group" } else { "allow" };
        assert!(set_default_privacy_list(&pool, recipient.id, Some(default))
            .await
            .unwrap());
        assert!(
            set_active_privacy_list(&pool, recipient.id, connection, Some("allow"))
                .await
                .unwrap()
        );
        assert!(!service
            .default_recipient_privacy_denies(recipient.id, FROM)
            .await
            .unwrap());
        if selection.is_some() {
            assert!(service
                .privacy_allows_session(
                    recipient.id,
                    connection,
                    Some("allow"),
                    FROM,
                    PrivacyStanzaKind::Message
                )
                .await
                .unwrap());
        }
        let (blocker, pid) = block_commit(&pool).await;
        let commit = start_commit(service, &sender, &recipient, selection);
        crate::support::blocked_backend(&pool, pid).await;
        let denial = match change {
            "active" => {
                assert!(
                    set_active_privacy_list(&pool, recipient.id, connection, Some("deny"))
                        .await
                        .unwrap()
                );
                DirectPolicyDenial::RecipientPrivacy
            }
            "default" | "spool" | "degraded" => {
                assert!(set_default_privacy_list(&pool, recipient.id, Some("deny"))
                    .await
                    .unwrap());
                if change == "degraded" {
                    DirectPolicyDenial::DegradedSpool
                } else {
                    DirectPolicyDenial::RecipientPrivacy
                }
            }
            "group" => {
                northstar_workflows::roster::upsert_roster_authorized(
                    &pool,
                    recipient.id,
                    recipient.auth_generation,
                    "alice@local.test",
                    None,
                    &["Friends".to_owned()],
                )
                .await
                .unwrap()
                .unwrap();
                DirectPolicyDenial::RecipientPrivacy
            }
            "block" => {
                block_jids(&pool, recipient.id, &["alice@local.test".to_owned()])
                    .await
                    .unwrap();
                DirectPolicyDenial::RecipientBlock
            }
            "outbound_block" => {
                block_jids(&pool, sender.id, &[TO.to_owned()])
                    .await
                    .unwrap();
                DirectPolicyDenial::OutboundBlock
            }
            _ => unreachable!(),
        };
        blocker.commit().await.unwrap();
        let error = commit.await.unwrap().unwrap_err();
        assert_eq!(
            error.downcast_ref::<DirectPolicyDenial>(),
            Some(&denial),
            "{change}: {error:#}"
        );
        assert_no_projections(&pool).await;
        if change == "outbound_block" {
            unblock_jids(&pool, sender.id, None).await.unwrap();
        }
    }
    drop_isolated_message_pool(admin, pool, schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn offline_fallback_rechecks_default_policy_and_actor_before_inserting() {
    let (admin, pool, schema) = isolated_message_pool_for("commit_fallback").await;
    let sender = insert_user(&pool, "alice", false).await;
    let recipient = insert_user(&pool, "bob", false).await;
    replace_privacy_list(
        &pool,
        recipient.id,
        &PrivacyList {
            name: "deny".to_owned(),
            items: vec![PrivacyItem {
                order: 10,
                action: PrivacyAction::Deny,
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
    for denial in [
        DirectPolicyDenial::RecipientPrivacy,
        DirectPolicyDenial::ActorUnavailable,
    ] {
        let service = service(&pool, DirectPostCommitMode::Live);
        assert!(!service
            .default_recipient_privacy_denies(recipient.id, FROM)
            .await
            .unwrap());
        let (blocker, pid) = block_commit(&pool).await;
        let recipient_id = recipient.id;
        let actor_fence = Some(ActorGenerationFence {
            account_id: sender.id,
            auth_generation: sender.auth_generation,
        });
        let commit = tokio::spawn(async move {
            service
                .store_offline(OfflineMessageAdmission {
                    recipient_id,
                    recipient_bare_jid: TO,
                    sender_jid: FROM,
                    stanza: XML,
                    encrypted: false,
                    mam_backed: false,
                    identity: None,
                    actor_fence,
                    policy: DirectMessagePolicy {
                        from: FROM,
                        to: TO,
                        sender: None,
                        recipient_sessions: &[],
                        remote_recipient_route: false,
                    },
                })
                .await
        });
        crate::support::blocked_backend(&pool, pid).await;
        if denial == DirectPolicyDenial::RecipientPrivacy {
            assert!(set_default_privacy_list(&pool, recipient.id, Some("deny"))
                .await
                .unwrap());
        } else {
            change_password(
                &pool,
                sender.id,
                "Replacement password for test!97",
                4096,
                false,
            )
            .await
            .unwrap();
        }
        blocker.commit().await.unwrap();
        let error = commit.await.unwrap().unwrap_err();
        assert_eq!(error.downcast_ref::<DirectPolicyDenial>(), Some(&denial));
        assert_no_projections(&pool).await;
        assert!(set_default_privacy_list(&pool, recipient.id, None)
            .await
            .unwrap());
    }
    drop_isolated_message_pool(admin, pool, schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn volatile_history_keeps_its_pre_route_archive_selection() {
    let (admin, pool, schema) = isolated_message_pool_for("prepared_history").await;
    let sender = insert_user(&pool, "alice", false).await;
    let recipient = insert_user(&pool, "bob", false).await;
    let authority = northstar_archive_core::MamLocalAuthority {
        id: recipient.id,
        username: recipient.username.clone(),
        auth_generation: recipient.auth_generation,
    };
    let service = service(&pool, DirectPostCommitMode::Live);
    let id = Uuid::new_v4();
    let candidates = [ArchiveCandidate {
        direction: ArchiveDirection::Inbound,
        projection: ArchiveWrite {
            id,
            owner_id: recipient.id,
            peer_jid: FROM,
            stanza: XML,
            encrypted: false,
            stanza_id: None,
        },
    }];
    let preferences = |policy: &str| northstar_archive_postgres::MamPreferences {
        default_policy: policy.to_owned(),
        ..Default::default()
    };
    northstar_archive_postgres::set_mam_preferences(&pool, &authority, &preferences("always"))
        .await
        .unwrap();
    let history = service.prepare_archive_history(&candidates).await.unwrap();
    northstar_archive_postgres::set_mam_preferences(&pool, &authority, &preferences("never"))
        .await
        .unwrap();
    assert_eq!(
        service
            .write_prepared_archive_history(
                history,
                Some(ActorGenerationFence {
                    account_id: sender.id,
                    auth_generation: sender.auth_generation,
                })
            )
            .await
            .unwrap(),
        ArchiveAdmissionOutcome::Projected(vec![id]),
    );
    let owners: Vec<Uuid> = sqlx::query_scalar("SELECT owner_id FROM message_archive WHERE id=$1")
        .bind(id)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(owners, vec![recipient.id]);
    drop_isolated_message_pool(admin, pool, schema).await;
}
