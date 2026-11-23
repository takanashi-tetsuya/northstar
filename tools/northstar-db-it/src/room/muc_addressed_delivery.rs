use super::muc::create_harness_owned_schema;
use northstar_message_application::messaging::{
    invitation_admission::{
        DirectInvitation, DirectInvitationGrant, DirectInvitationOutcome,
        DirectInvitationRepository,
    },
    LocalDelivery, PersonalMessageDestination, ValidatedPersonalMessage,
};
use northstar_room_application::muc_service::{
    ClusterMucAffiliationSubject as InviteSubject, ClusterMucInviteAuthority as InviteAuthority,
    ClusterMucPrincipal as InvitePrincipal, DurableMucInviteOutcome, FederatedInvitePolicy,
    FederatedMediatedInvitation, FederatedMediatedInvitationOutcome, LocalMediatedInvitation,
    LocalMediatedInvitationOutcome, MucAddressedActor, MucAddressedOutcome, MucAddressedRequest,
    MucInvitationAdmissionRepository, OfflineStorePolicy,
};
use northstar_room_core::muc_authority::MucOccupancyTransition;
use northstar_room_core::occupancy::MucOccupantRoute;
use northstar_room_postgres::room::addressed_delivery::{
    current_muc_moderators, muc_addressed_authority,
};
use northstar_room_postgres::{cluster_muc::*, muc::get_or_create_muc_room};
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_workflows::room_effects::PostgresMucRepository;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

const ROOM: &str = "addressed-delivery";
const NODE: &str = "addressed-node";
const VISITOR: &str = "visitor@remote.test/Phone";
const MODERATOR: &str = "owner@local.test/Phone";
const ROOM_JID: &str = "addressed-delivery@conference.local.test";

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    schema: String,
    room_id: Uuid,
    room_epoch: Uuid,
    config_version: i64,
    owner: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("muc_invite_test_{}", Uuid::new_v4().simple());
        create_harness_owned_schema(&admin, &schema).await;
        let search_path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _| {
                let statement = search_path.clone();
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
        let owner = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'owner','test')")
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
        let (room, _) = get_or_create_muc_room(&pool, ROOM, owner, MODERATOR)
            .await
            .unwrap();
        let config_version = sqlx::query_scalar(
            "UPDATE muc_rooms SET configuration_state='active',configuration_owner_jid=NULL,
                    configuration_expires_at=NULL,moderated=true,allow_private_messages=true
              WHERE id=$1 RETURNING config_version",
        )
        .bind(room.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        Self {
            admin,
            pool,
            schema,
            room_id: room.id,
            room_epoch: room.room_epoch,
            config_version,
            owner,
        }
    }

    async fn join(&self, full_jid: &str, nick: &str) -> ClusterMucOccupancyTarget {
        let bare_jid = full_jid.split_once('/').unwrap().0.to_owned();
        let principal = if full_jid == MODERATOR {
            ClusterMucPrincipal::Local {
                user_id: self.owner,
                bare_jid,
            }
        } else {
            ClusterMucPrincipal::Federated {
                bare_jid,
                authenticated_domain: "remote.test".into(),
            }
        };
        let outcome = claim_cluster_muc_occupancy(
            &self.pool,
            ClusterMucJoin {
                operation_id: Uuid::new_v4(),
                room_id: self.room_id,
                expected_room_epoch: self.room_epoch,
                expected_config_version: self.config_version,
                principal,
                full_jid,
                nick,
                owner_node_id: NODE,
                connection_uuid: Uuid::new_v4(),
                connection_epoch: 1,
                sm_session_id: None,
                occupant_incarnation: Uuid::new_v4(),
                presence_payload: "<presence/>",
                lease: Duration::from_secs(90),
            },
        )
        .await
        .unwrap();
        let ClusterMucJoinOutcome::Joined(joined) = outcome else {
            panic!("join failed: {outcome:?}")
        };
        ClusterMucOccupancyTarget::from(&joined)
    }

    async fn cleanup(self) {
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

    async fn invitee(&self, username: &str) -> Uuid {
        let account = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(account)
            .bind(username)
            .execute(&self.pool)
            .await
            .unwrap();
        account
    }

    fn invitation(
        &self,
        inviter: &ClusterMucOccupancyTarget,
        recipient_id: Uuid,
        recipient: &str,
    ) -> InviteAuthority {
        InviteAuthority {
            operation_id: Uuid::new_v4(),
            expected_room_epoch: self.room_epoch,
            expected_config_version: self.config_version,
            actor: InvitePrincipal::Local {
                user_id: self.owner,
                bare_jid: "owner@local.test".into(),
            },
            actor_full_jid: MODERATOR.into(),
            actor_target: Some(inviter.clone()),
            subject: InviteSubject::Local {
                user_id: recipient_id,
                bare_jid: recipient.into(),
            },
            reason: None,
        }
    }
}

fn local_actor(
    fixture: &Fixture,
    target: &ClusterMucOccupancyTarget,
) -> MucAddressedActor<'static> {
    MucAddressedActor::Local {
        account_id: fixture.owner,
        full_jid: MODERATOR,
        connection_id: target.connection_uuid,
        occupant_incarnation: target.occupant_incarnation,
    }
}

const VISITOR_ACTOR: MucAddressedActor<'static> = MucAddressedActor::Federated {
    authenticated_domain: "remote.test",
    full_jid: VISITOR,
};

async fn private_target(
    pool: &PgPool,
    actor: MucAddressedActor<'_>,
    nick: &str,
) -> MucOccupantRoute {
    let outcome = muc_addressed_authority(pool, ROOM, MucAddressedRequest::Private { actor, nick })
        .await
        .unwrap();
    let MucAddressedOutcome::Private {
        target: Some(route),
        ..
    } = outcome
    else {
        panic!("private route not admitted: {outcome:?}");
    };
    route
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn private_authority_names_the_exact_target_incarnation() {
    let fixture = Fixture::new().await;
    let owner = fixture.join(MODERATOR, "Owner").await;
    let previous = fixture.join(VISITOR, "Target").await;
    let actor = local_actor(&fixture, &owner);
    let old = private_target(&fixture.pool, actor, "Target").await;
    assert_eq!(old.cluster_epoch, previous.occupant_incarnation);
    assert_eq!(old.connection_id, previous.connection_uuid);
    assert!(matches!(
        transition_cluster_muc_occupancy(
            &fixture.pool,
            Uuid::new_v4(),
            &previous,
            MucOccupancyTransition::Leave,
            NODE,
            None,
            None,
            None,
            Duration::from_secs(90),
        )
        .await
        .unwrap(),
        ClusterMucTransitionOutcome::Applied
    ));
    assert!(matches!(
        muc_addressed_authority(
            &fixture.pool,
            ROOM,
            MucAddressedRequest::Decline {
                nick: Some("Target")
            }
        )
        .await
        .unwrap(),
        MucAddressedOutcome::Decline { target: None }
    ));
    let replacement = fixture.join(VISITOR, "Target").await;
    let new = private_target(&fixture.pool, actor, "Target").await;
    assert_eq!(new.cluster_epoch, replacement.occupant_incarnation);
    assert_eq!((&new.nick, &new.full_jid), (&old.nick, &old.full_jid));
    assert_ne!(new, old);
    let old_snapshot = cluster_muc_exact_occupancy_snapshot(&fixture.pool, &previous)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old_snapshot.state, "left");
    assert!(matches!(
        muc_addressed_authority(
            &fixture.pool,
            ROOM,
            MucAddressedRequest::Private {
                actor: MucAddressedActor::Federated {
                    authenticated_domain: "wrong.test",
                    full_jid: VISITOR
                },
                nick: "Owner",
            }
        )
        .await
        .unwrap(),
        MucAddressedOutcome::NotAuthorized
    ));
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn private_authority_serializes_against_a_policy_change() {
    let fixture = Fixture::new().await;
    let owner = fixture.join(MODERATOR, "Owner").await;
    let target = fixture.join(VISITOR, "Target").await;
    let actor = local_actor(&fixture, &owner);
    let mut writer = fixture.pool.begin().await.unwrap();
    sqlx::query("UPDATE muc_rooms SET allow_private_messages=false WHERE id=$1")
        .bind(fixture.room_id)
        .execute(&mut *writer)
        .await
        .unwrap();
    let reader_pool = fixture.pool.clone();
    let reader = tokio::spawn(async move { private_target(&reader_pool, actor, "Target").await });
    let before = tokio::time::timeout(Duration::from_secs(10), reader)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.cluster_epoch, target.occupant_incarnation);
    writer.commit().await.unwrap();
    assert!(matches!(
        muc_addressed_authority(
            &fixture.pool,
            ROOM,
            MucAddressedRequest::Private {
                actor,
                nick: "Target"
            }
        )
        .await
        .unwrap(),
        MucAddressedOutcome::Forbidden
    ));
    fixture.cleanup().await;
}

async fn voice(pool: &PgPool) -> MucAddressedOutcome {
    muc_addressed_authority(
        pool,
        ROOM,
        MucAddressedRequest::Voice {
            actor: VISITOR_ACTOR,
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn voice_request_skips_a_moderator_demoted_before_delivery() {
    let fixture = Fixture::new().await;
    let owner = fixture.join(MODERATOR, "Owner").await;
    fixture.join(VISITOR, "Visitor").await;
    let outcome = voice(&fixture.pool).await;
    let MucAddressedOutcome::Voice {
        moderators,
        requester,
    } = outcome
    else {
        panic!("voice request not admitted: {outcome:?}");
    };
    assert_eq!(requester.full_jid, VISITOR);
    assert_eq!(moderators.len(), 1);
    assert_eq!(moderators[0].cluster_epoch, owner.occupant_incarnation);
    assert_eq!(
        current_muc_moderators(&fixture.pool, ROOM, &moderators)
            .await
            .unwrap(),
        moderators
    );
    sqlx::query("UPDATE cluster_muc_occupancies SET role='participant' WHERE room_id=$1 AND occupant_incarnation=$2")
        .bind(fixture.room_id).bind(owner.occupant_incarnation).execute(&fixture.pool).await.unwrap();
    assert!(current_muc_moderators(&fixture.pool, ROOM, &moderators)
        .await
        .unwrap()
        .is_empty());
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn voice_request_authority_rejects_a_requester_granted_voice_concurrently() {
    let fixture = Fixture::new().await;
    fixture.join(MODERATOR, "Owner").await;
    let visitor = fixture.join(VISITOR, "Visitor").await;
    let mut writer = fixture.pool.begin().await.unwrap();
    sqlx::query("UPDATE cluster_muc_occupancies SET role='participant' WHERE room_id=$1 AND occupant_incarnation=$2")
        .bind(fixture.room_id).bind(visitor.occupant_incarnation).execute(&mut *writer).await.unwrap();
    let reader_pool = fixture.pool.clone();
    let reader = tokio::spawn(async move { voice(&reader_pool).await });
    let before = tokio::time::timeout(Duration::from_secs(10), reader)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(before, MucAddressedOutcome::Voice { requester, moderators }
        if requester.cluster_epoch == visitor.occupant_incarnation && moderators.len() == 1)
    );
    writer.commit().await.unwrap();
    assert!(matches!(
        voice(&fixture.pool).await,
        MucAddressedOutcome::Forbidden
    ));
    fixture.cleanup().await;
}

async fn admit_invitation(
    pool: &PgPool,
    authority: &InviteAuthority,
    max_messages: i64,
) -> LocalMediatedInvitationOutcome {
    let InviteSubject::Local { user_id, bare_jid } = &authority.subject else {
        unreachable!()
    };
    let stanza = format!("<message from='{ROOM_JID}' to='{bare_jid}' type='normal'><stanza-id xmlns='urn:xmpp:sid:0' by='{bare_jid}' id='{}'/></message>", authority.operation_id);
    PostgresMucRepository::new(pool.clone())
        .admit_local_mediated_invitation(LocalMediatedInvitation {
            room_id: authority.actor_target.as_ref().unwrap().room_id,
            recipient_id: *user_id,
            recipient_bare_jid: bare_jid,
            room_jid: ROOM_JID,
            grant_stanza: &stanza,
            delay_grant_stanza: &|| stanza.clone(),
            storage_permitted: true,
            grant_available: true,
            policy: OfflineStorePolicy {
                max_messages,
                max_bytes: 1_000_000,
                ttl_days: 7,
                mam_backed: false,
            },
            authority,
        })
        .await
        .unwrap()
}

async fn invitation_rows(pool: &PgPool, id: Uuid, room: Uuid, recipient: Uuid) -> (bool, bool) {
    sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM muc_affiliations WHERE room_id=$1 AND user_id=$2 AND affiliation='member'),
                EXISTS(SELECT 1 FROM offline_messages WHERE id=$3 AND recipient_id=$2)",
    ).bind(room).bind(recipient).bind(id).fetch_one(pool).await.unwrap()
}

async fn admit_direct_grant(
    repository: &PostgresMessageRepository,
    request: &DirectInvitation<'_>,
    delivery_id: Uuid,
    recipient_id: Uuid,
) -> DirectInvitationOutcome {
    let stanza = format!(
        "<message from='{}' to='{}'><x xmlns='jabber:x:conference' jid='{ROOM_JID}'/></message>",
        request.actor_jid, request.invitee_jid,
    );
    let message = ValidatedPersonalMessage {
        local_actor_id: Some(request.actor_id),
        identity: None,
        archives: &[],
        destination: PersonalMessageDestination::Local(LocalDelivery {
            delivery_id,
            recipient_id,
            recipient_bare_jid: request.invitee_jid,
            sender_jid: request.actor_jid,
            stanza: &stanza,
            encrypted: false,
        }),
    };
    repository
        .admit_direct_invitation(
            request,
            Some(DirectInvitationGrant {
                message: &message,
                cluster_authority: None,
            }),
        )
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn invitation_mode_follows_the_locked_room_revision() {
    let fixture = Fixture::new().await;
    let inviter = fixture.join(MODERATOR, "Owner").await;
    let open_recipient = fixture.invitee("open-recipient").await;
    let grant_recipient = fixture.invitee("grant-recipient").await;
    let open = fixture.invitation(&inviter, open_recipient, "open-recipient@local.test");
    let grant = fixture.invitation(&inviter, grant_recipient, "grant-recipient@local.test");
    assert!(matches!(
        admit_invitation(&fixture.pool, &open, 100).await,
        LocalMediatedInvitationOutcome::Open
    ));
    let mut writer = fixture.pool.begin().await.unwrap();
    let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE muc_rooms SET members_only=true,config_version=config_version+1 WHERE id=$1",
    )
    .bind(fixture.room_id)
    .execute(&mut *writer)
    .await
    .unwrap();
    let invite_pool = fixture.pool.clone();
    let grant_id = grant.operation_id;
    let invite = tokio::spawn(async move { admit_invitation(&invite_pool, &grant, 100).await });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    writer.commit().await.unwrap();
    assert!(
        matches!(invite.await.unwrap(), LocalMediatedInvitationOutcome::Durable(DurableMucInviteOutcome::Stored { id, .. }) if id == grant_id)
    );
    assert_eq!(
        invitation_rows(
            &fixture.pool,
            open.operation_id,
            fixture.room_id,
            open_recipient
        )
        .await,
        (false, false)
    );
    assert_eq!(
        invitation_rows(&fixture.pool, grant_id, fixture.room_id, grant_recipient).await,
        (true, true)
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn invitations_commit_per_invitee_after_a_later_failure() {
    tokio::task::spawn_blocking(
        super::muc::durable_invitation_admission_is_atomic_under_injected_failures,
    )
    .await
    .unwrap();
    let fixture = Fixture::new().await;
    let inviter = fixture.join(MODERATOR, "Owner").await;
    let first_recipient = fixture.invitee("first-recipient").await;
    let later_recipient = fixture.invitee("later-recipient").await;
    sqlx::query(
        "UPDATE muc_rooms SET members_only=true,config_version=config_version+1 WHERE id=$1",
    )
    .bind(fixture.room_id)
    .execute(&fixture.pool)
    .await
    .unwrap();
    let first = fixture.invitation(&inviter, first_recipient, "first-recipient@local.test");
    let later = fixture.invitation(&inviter, later_recipient, "later-recipient@local.test");
    assert!(matches!(
        admit_invitation(&fixture.pool, &first, 100).await,
        LocalMediatedInvitationOutcome::Durable(DurableMucInviteOutcome::Stored { .. })
    ));
    assert!(matches!(
        admit_invitation(&fixture.pool, &later, 0).await,
        LocalMediatedInvitationOutcome::Durable(DurableMucInviteOutcome::QuotaExceeded)
    ));
    assert_eq!(
        invitation_rows(
            &fixture.pool,
            first.operation_id,
            fixture.room_id,
            first_recipient
        )
        .await,
        (true, true)
    );
    assert_eq!(
        invitation_rows(
            &fixture.pool,
            later.operation_id,
            fixture.room_id,
            later_recipient
        )
        .await,
        (false, false)
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn federated_mediated_invitation_grants_only_on_the_locked_members_only_revision() {
    let fixture = Fixture::new().await;
    let inviter = fixture.join(MODERATOR, "Owner").await;
    let invitee = "invitee@remote.test";
    let authority = InviteAuthority {
        operation_id: Uuid::new_v4(),
        expected_room_epoch: fixture.room_epoch,
        expected_config_version: fixture.config_version,
        actor: InvitePrincipal::Local {
            user_id: fixture.owner,
            bare_jid: "owner@local.test".into(),
        },
        actor_full_jid: MODERATOR.into(),
        actor_target: Some(inviter),
        subject: InviteSubject::Federated {
            bare_jid: invitee.into(),
        },
        reason: None,
    };
    let stanza = "<message from='addressed-delivery@conference.local.test' to='invitee@remote.test' type='normal'/>";
    let request = || FederatedMediatedInvitation {
        room_id: fixture.room_id,
        invitee_bare_jid: invitee,
        target_domain: "remote.test",
        stanza,
        bounce_to: ROOM_JID,
        grant_available: true,
        policy: FederatedInvitePolicy {
            ttl_seconds: 60,
            max_rows: 100,
            max_bytes: 1_000_000,
            max_per_domain: 100,
        },
        authority: &authority,
    };
    let repository = PostgresMucRepository::new(fixture.pool.clone());
    let rows = || async {
        sqlx::query_as::<_, (bool, bool)>(
            "SELECT EXISTS(SELECT 1 FROM muc_external_affiliations WHERE room_id=$1 AND jid=$2 AND affiliation='member'),
                    EXISTS(SELECT 1 FROM s2s_outbox WHERE target_domain='remote.test' AND bounce_to=$3)",
        ).bind(fixture.room_id).bind(invitee).bind(ROOM_JID).fetch_one(&fixture.pool).await.unwrap()
    };
    assert_eq!(
        repository
            .admit_federated_mediated_invitation(request())
            .await
            .unwrap(),
        FederatedMediatedInvitationOutcome::Open
    );
    assert_eq!(rows().await, (false, false));
    sqlx::query(
        "UPDATE muc_rooms SET members_only=true,config_version=config_version+1 WHERE id=$1",
    )
    .bind(fixture.room_id)
    .execute(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(
        repository
            .admit_federated_mediated_invitation(request())
            .await
            .unwrap(),
        FederatedMediatedInvitationOutcome::Granted
    );
    assert_eq!(rows().await, (true, true));
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn direct_invitation_mode_follows_the_locked_room_revision() {
    let fixture = Fixture::new().await;
    let open_recipient_id = fixture.invitee("open-direct-target").await;
    let recipient_id = fixture.invitee("direct-target").await;
    let repository = PostgresMessageRepository::new(
        fixture.pool.clone(),
        northstar_abuse_application::guard::test_personal_message_content_keyring(),
        "local.test",
        100,
        8_000_000,
        30,
    );
    let open = DirectInvitation {
        room: ROOM,
        actor_id: fixture.owner,
        actor_jid: MODERATOR,
        invitee_jid: "open-direct-target@local.test",
        local_recipient_name: Some("open-direct-target"),
        active_privacy: None,
    };
    let open_delivery_id = Uuid::new_v4();
    assert!(matches!(
        repository.admit_direct_invitation(&open, None).await.unwrap(),
        DirectInvitationOutcome::Open { recipient: Some(recipient) } if recipient.id == open_recipient_id
    ));
    let mut writer = fixture.pool.begin().await.unwrap();
    let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
        .bind(fixture.room_id)
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let grant_delivery_id = Uuid::new_v4();
    let request = DirectInvitation {
        invitee_jid: "direct-target@local.test",
        local_recipient_name: Some("direct-target"),
        ..open
    };
    let grant_repository = repository.clone();
    let actor_id = fixture.owner;
    let admission = tokio::spawn(async move {
        assert!(matches!(
            grant_repository.admit_direct_invitation(&request, None).await.unwrap(),
            DirectInvitationOutcome::GrantRequired { recipient: Some(recipient), .. } if recipient.id == recipient_id
        ));
        admit_direct_grant(&grant_repository, &request, grant_delivery_id, recipient_id).await
    });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query(
        "UPDATE muc_rooms SET members_only=true,config_version=config_version+1 WHERE id=$1",
    )
    .bind(fixture.room_id)
    .execute(&mut *writer)
    .await
    .unwrap();
    writer.commit().await.unwrap();
    assert!(matches!(
        admission.await.unwrap(),
        DirectInvitationOutcome::Granted {
            live_claim_id: None
        }
    ));
    assert_eq!(
        invitation_rows(
            &fixture.pool,
            open_delivery_id,
            fixture.room_id,
            open_recipient_id
        )
        .await,
        (false, false)
    );
    assert_eq!(
        invitation_rows(
            &fixture.pool,
            grant_delivery_id,
            fixture.room_id,
            recipient_id
        )
        .await,
        (true, true)
    );

    let reopening = DirectInvitation {
        room: ROOM,
        actor_id,
        actor_jid: MODERATOR,
        invitee_jid: "open-direct-target@local.test",
        local_recipient_name: Some("open-direct-target"),
        active_privacy: None,
    };
    assert!(matches!(
        repository
            .admit_direct_invitation(&reopening, None)
            .await
            .unwrap(),
        DirectInvitationOutcome::GrantRequired { .. }
    ));
    let mut writer = fixture.pool.begin().await.unwrap();
    let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
        .bind(fixture.room_id)
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    let reopened_delivery_id = Uuid::new_v4();
    let admission = tokio::spawn(async move {
        admit_direct_grant(
            &repository,
            &reopening,
            reopened_delivery_id,
            open_recipient_id,
        )
        .await
    });
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query(
        "UPDATE muc_rooms SET members_only=false,config_version=config_version+1 WHERE id=$1",
    )
    .bind(fixture.room_id)
    .execute(&mut *writer)
    .await
    .unwrap();
    writer.commit().await.unwrap();
    assert!(matches!(
        admission.await.unwrap(),
        DirectInvitationOutcome::Open { recipient: Some(recipient) } if recipient.id == open_recipient_id
    ));
    assert_eq!(
        invitation_rows(
            &fixture.pool,
            reopened_delivery_id,
            fixture.room_id,
            open_recipient_id
        )
        .await,
        (false, false)
    );
    fixture.cleanup().await;
}
