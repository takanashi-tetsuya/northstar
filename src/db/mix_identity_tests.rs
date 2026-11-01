use crate::db;
use northstar_room_postgres::mix_identity::*;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a random isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn postgres_mix_graph_is_atomic_fk_safe_resource_exact_and_idempotent() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a random isolated PostgreSQL schema");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let user = northstar_auth_postgres::users::create_user(
        &pool,
        &format!("mixid{}", &Uuid::new_v4().simple().to_string()[..12]),
        "test-password-long-enough",
        false,
        false,
        4096,
        false,
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
        .bind(MIGRATION)
        .execute(&pool)
        .await
        .unwrap();

    let channel_id = Uuid::new_v4();
    let participant_id = Uuid::new_v4();
    let legacy_domain = "mix.bücher.example";
    let legacy_actor = "alice@bücher.example";
    let legacy_channel = format!("café@{legacy_domain}");
    sqlx::query(
        "INSERT INTO mix_channels(id,service_domain,localpart,creator_jid,contacts)
         VALUES($1,$2,'café',$3,$4)",
    )
    .bind(channel_id)
    .bind(legacy_domain)
    .bind(legacy_actor)
    .bind(json!(["support@bücher.example"]))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_participant_identities(channel_id,jid,participant_id) VALUES($1,$2,$3)",
    )
    .bind(channel_id)
    .bind(legacy_actor)
    .bind(participant_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_participants(channel_id,participant_id,jid,nick,role) VALUES($1,$2,$3,'Alice','owner')",
    )
    .bind(channel_id)
    .bind(participant_id)
    .bind(legacy_actor)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO mix_channel_roles(channel_id,jid,role) VALUES($1,$2,'owner')")
        .bind(channel_id)
        .bind(legacy_actor)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO mix_allowed(channel_id,jid_pattern,added_by) VALUES($1,'bücher.example','admin@bücher.example')",
    )
    .bind(channel_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_banned(channel_id,jid_pattern,added_by) VALUES($1,'mallory@bücher.example','admin@bücher.example')",
    )
    .bind(channel_id)
    .execute(&pool)
    .await
    .unwrap();
    let pam_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_pam_memberships
           (id,user_id,channel_jid,state,request_id,client_request_id,requester_full_jid)
         VALUES($1,$2,$3,'pending_join','remote-1','client-1','alice@bücher.example/Phone')",
    )
    .bind(pam_id)
    .bind(user.id)
    .bind(&legacy_channel)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO mix_registered_nicks(service_domain,jid,nick) VALUES($1,$2,'Alice')")
        .bind(legacy_domain)
        .bind(legacy_actor)
        .execute(&pool)
        .await
        .unwrap();
    let active_invitation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_invitations
           (id,channel_id,inviter_jid,invitee_jid,token_hash,expires_at)
         VALUES($1,$2,$3,'bob@bücher.example',$4,NOW()+INTERVAL '1 hour')",
    )
    .bind(active_invitation)
    .bind(channel_id)
    .bind(legacy_actor)
    .bind(vec![7_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let expired_invitation = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_invitations
           (id,channel_id,inviter_jid,invitee_jid,token_hash,created_at,expires_at)
         VALUES($1,$2,$3,'old@bücher.example',$4,NOW()-INTERVAL '2 days',NOW()-INTERVAL '1 day')",
    )
    .bind(expired_invitation)
    .bind(channel_id)
    .bind(legacy_actor)
    .bind(vec![8_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    for (resource, item) in [("Phone", "presence-phone"), ("phone", "presence-lower")] {
        sqlx::query(
            "INSERT INTO mix_events
               (id,channel_id,node,item_id,publisher_id,publisher_jid,payload,source_full_jid)
             VALUES($1,$2,$3,$4,$5,$6,'<presence/>',$7)",
        )
        .bind(Uuid::new_v4())
        .bind(channel_id)
        .bind(PRESENCE_NODE)
        .bind(item)
        .bind(participant_id)
        .bind(legacy_actor)
        .bind(format!("{legacy_actor}/{resource}"))
        .execute(&pool)
        .await
        .unwrap();
    }
    let history_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_events
           (id,channel_id,node,item_id,publisher_id,publisher_jid,payload)
         VALUES($1,$2,'urn:xmpp:mix:nodes:messages',$3,$4,$5,'<message>历史</message>')",
    )
    .bind(history_id)
    .bind(channel_id)
    .bind(history_id.to_string())
    .bind(participant_id)
    .bind(legacy_actor)
    .execute(&pool)
    .await
    .unwrap();

    canonicalize_mix_identity_storage(&pool).await.unwrap();
    let canonical_domain = northstar_xmpp_types::jid::prepare_domainpart(legacy_domain).unwrap();
    let canonical_actor = northstar_xmpp_types::jid::canonicalize_bare(legacy_actor).unwrap();
    let channel: (String, String, Value) =
        sqlx::query_as("SELECT service_domain,creator_jid,contacts FROM mix_channels WHERE id=$1")
            .bind(channel_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(channel.0, canonical_domain);
    assert_eq!(channel.1, canonical_actor);
    assert_eq!(channel.2, json!(["support@bücher.example"]));
    let identity_jid: String = sqlx::query_scalar(
        "SELECT jid FROM mix_participant_identities WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let participant_jid: String = sqlx::query_scalar(
        "SELECT jid FROM mix_participants WHERE channel_id=$1 AND participant_id=$2",
    )
    .bind(channel_id)
    .bind(participant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(identity_jid, canonical_actor);
    assert_eq!(participant_jid, canonical_actor);
    let fk_valid: bool = sqlx::query_scalar(
        "SELECT convalidated FROM pg_constraint
         WHERE conrelid='mix_participants'::regclass
           AND conname='mix_participants_channel_id_jid_fkey'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(fk_valid);
    let orphans: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mix_participants AS p
         LEFT JOIN mix_participant_identities AS i USING(channel_id,jid)
         WHERE i.channel_id IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(orphans, 0);
    let sources: Vec<String> = sqlx::query_scalar::<_, String>(
        "SELECT source_full_jid FROM mix_events WHERE channel_id=$1 AND node=$2 ORDER BY source_full_jid",
    )
    .bind(channel_id)
    .bind(PRESENCE_NODE)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        sources,
        vec!["alice@bücher.example/Phone", "alice@bücher.example/phone"]
    );
    let requester: String =
        sqlx::query_scalar("SELECT requester_full_jid FROM mix_pam_memberships WHERE id=$1")
            .bind(pam_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(requester, "alice@bücher.example/Phone");
    let attribution: String =
        sqlx::query_scalar("SELECT added_by FROM mix_allowed WHERE channel_id=$1")
            .bind(channel_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(attribution, "admin@bücher.example");
    let history: (String, String) =
        sqlx::query_as("SELECT publisher_jid,payload FROM mix_events WHERE id=$1")
            .bind(history_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(history.0, legacy_actor);
    assert_eq!(history.1, "<message>历史</message>");
    let expired: String = sqlx::query_scalar("SELECT inviter_jid FROM mix_invitations WHERE id=$1")
        .bind(expired_invitation)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(expired, legacy_actor);
    canonicalize_mix_identity_storage(&pool).await.unwrap();
    let payloads = northstar_room_application::mix_service::MixPayloads;
    assert!(northstar_room_postgres::mix::set_mix_access_entry(
        &crate::db::room_effects::RootRoomEffects,
        &pool,
        northstar_room_postgres::mix::MixAccessEntryUpdate {
            channel_id,
            actor: &canonical_actor,
            pattern: "bücher.example",
            list: northstar_room_postgres::mix::MixAccessList::Banned,
            operation: northstar_room_postgres::mix::MixAccessEntryOperation::Publish {
                reason: Some("must remain disjoint"),
            },
        },
        &payloads,
        None,
    )
    .await
    .is_err());

    sqlx::query("DELETE FROM jid_identity_migrations WHERE migration=$1")
        .bind(MIGRATION)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO mix_banned(channel_id,jid_pattern,added_by)
         VALUES($1,'bücher.example','admin@example.test')",
    )
    .bind(channel_id)
    .execute(&pool)
    .await
    .unwrap();
    let error = canonicalize_mix_identity_storage(&pool)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("cross-list collision"), "{error}");
    let untouched: String = sqlx::query_scalar(
        "SELECT jid_pattern FROM mix_banned WHERE channel_id=$1 AND jid_pattern='bücher.example'",
    )
    .bind(channel_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(untouched, "bücher.example");
    let marker: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM jid_identity_migrations WHERE migration=$1)",
    )
    .bind(MIGRATION)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!marker);
}
