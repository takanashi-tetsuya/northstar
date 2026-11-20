use super::muc::{await_authorization_pause, create_harness_owned_schema};
use northstar_archive_core::{MamLocalAuthority, MamRoomReadAuthority};
use northstar_archive_postgres::{MamArchiveQuery, MamRoomReadOutcome, MamRsmPage};
use northstar_room_application::{discussion::Observation, muc_service::MucService};
use northstar_room_core::{
    stanza::apply_muc_discussion_reflection, MucActorAuthority, MucActorPrincipal, MucDiscussion,
    MucDiscussionAdmission,
};
use northstar_room_postgres::muc::{install_muc_authorization_test_pause, muc_room};
use northstar_workflows::{
    mam_room::{mam_federated_room_archive_page_authorized, mam_room_archive_page_authorized},
    room_effects::PostgresMucRepository,
};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn local_and_federated_discussions_follow_locked_logging() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("muc_history_test_{}", Uuid::new_v4().simple());
    create_harness_owned_schema(&admin, &schema).await;
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

    let user_id = Uuid::new_v4();
    let auth_generation: i64 = sqlx::query_scalar(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'alice','test')
         RETURNING auth_generation",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let account = MamLocalAuthority {
        id: user_id,
        username: "alice".to_owned(),
        auth_generation,
    };
    let service = MucService::new(PostgresMucRepository::new(pool.clone()), "local.test");
    let query = MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page: MamRsmPage::First,
        max: 50,
    };

    for federated in [false, true] {
        let (scope, nick, principal) = if federated {
            (
                "bob@remote.test",
                "Bob",
                MucActorPrincipal::Federated {
                    bare_jid: "bob@remote.test".into(),
                    authenticated_domain: "remote.test".into(),
                },
            )
        } else {
            (
                "alice@local.test",
                "Alice",
                MucActorPrincipal::Local {
                    user_id,
                    local_domain: "local.test".into(),
                },
            )
        };
        let sender = format!("{scope}/Phone");
        for origin_id in [None, Some("logging-race")] {
            for logging_enabled in [false, true] {
                let room_id = Uuid::new_v4();
                let localpart = format!("logging-{}", room_id.simple());
                let room_jid = format!("{localpart}@conference.local.test");
                sqlx::query(
                    "INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret,logging_enabled)
                     VALUES($1,$2,$3,$4,$5)",
                )
                .bind(room_id)
                .bind(&localpart)
                .bind(user_id)
                .bind(vec![7_u8; 32])
                .bind(!logging_enabled)
                .execute(&pool)
                .await
                .unwrap();
                let room = muc_room(&pool, &localpart).await.unwrap().unwrap();
                assert_ne!(room.logging_enabled, logging_enabled);

                let id = Uuid::new_v4();
                let origin = origin_id.map_or_else(String::new, |value| {
                    format!("<origin-id xmlns='urn:xmpp:sid:0' id='{value}'/>")
                });
                let mut reflected = format!(
                    "<message xmlns='jabber:client' from='{room_jid}/{nick}' to='{room_jid}' type='groupchat'><body>logging race</body>{origin}<stanza-id xmlns='urn:xmpp:sid:0' by='{room_jid}' id='{id}'/></message>"
                );
                let command = MucDiscussion {
                    id,
                    room_id,
                    actor_scope: scope.into(),
                    origin_id: origin_id.map(str::to_owned),
                    sender_jid: sender.clone(),
                    nick: nick.into(),
                    stanza: reflected.clone(),
                    encrypted: false,
                    archive_eligible: true,
                    unarchived_stanza_bytes: None,
                    retention_days: 30,
                    authority: MucActorAuthority {
                        clustered: false,
                        expected_room_epoch: room.room_epoch,
                        principal: principal.clone(),
                        actor_scope: scope.into(),
                        full_jid: sender.clone(),
                        nick: nick.into(),
                        occupant_incarnation: Uuid::nil(),
                        connection_uuid: Uuid::nil(),
                        expected_role: "participant".into(),
                        expected_affiliation: "none".into(),
                        cluster_target: None,
                    },
                };
                let (entered, resume) = install_muc_authorization_test_pause("discussion");
                let service = service.clone();
                let discussion = tokio::spawn(async move {
                    if federated {
                        service.admit_local_discussion(command).await.unwrap()
                    } else {
                        let observation = Observation::new(service.prepare_muc_discussion(command));
                        let request = observation.request().unwrap();
                        service
                            .execute_muc_discussion_observed(&request)
                            .await
                            .unwrap()
                            .outcome()
                    }
                });
                await_authorization_pause(&entered, "discussion logging change").await;
                sqlx::query("UPDATE muc_rooms SET logging_enabled=$2 WHERE id=$1")
                    .bind(room_id)
                    .bind(logging_enabled)
                    .execute(&pool)
                    .await
                    .unwrap();
                resume.notify_one();
                let admission = discussion.await.unwrap();
                assert_eq!(
                    admission,
                    MucDiscussionAdmission::Stored {
                        id,
                        archived: logging_enabled,
                    },
                    "fresh admission with origin {origin_id:?} and federated={federated}",
                );

                let viewer = MamRoomReadAuthority {
                    full_jid: sender.clone(),
                    occupancy: None,
                };
                let outcome = if federated {
                    mam_federated_room_archive_page_authorized(&pool, &localpart, &viewer, &query)
                        .await
                } else {
                    mam_room_archive_page_authorized(&pool, &localpart, &account, &viewer, &query)
                        .await
                }
                .unwrap();
                let MamRoomReadOutcome::Allowed {
                    value: Some(page), ..
                } = outcome
                else {
                    panic!("expected an authorized MUC MAM page: {outcome:?}");
                };
                let archived = page.rows.first();
                assert_eq!(archived.is_some(), logging_enabled);
                assert!(page.rows.len() <= 1);
                if let Some(row) = archived {
                    assert_eq!(row.id, id);
                    assert_eq!(row.stanza, reflected);
                }
                apply_muc_discussion_reflection(
                    &mut reflected,
                    &room_jid,
                    admission,
                    room.logging_enabled,
                );
                let document = roxmltree::Document::parse(&reflected).unwrap();
                let reflected_id = document.root_element().children().find_map(|child| {
                    (child.has_tag_name(("urn:xmpp:sid:0", "stanza-id"))
                        && child.attribute("by") == Some(room_jid.as_str()))
                    .then(|| child.attribute("id").unwrap().parse::<Uuid>().unwrap())
                });
                assert_eq!(reflected_id, archived.map(|row| row.id));
                let admitted_origin: Option<Uuid> = sqlx::query_scalar(
                    "SELECT stanza_id FROM muc_origin_admissions WHERE room_id=$1",
                )
                .bind(room_id)
                .fetch_optional(&pool)
                .await
                .unwrap();
                assert_eq!(admitted_origin, origin_id.map(|_| id));
            }
        }
    }

    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
