use crate::db::{self};
use northstar_room_postgres::mix::CreateChannelOutcome;
use northstar_room_postgres::mix_muc::{
    link_mix_muc_by_localpart, mix_muc_mirror_for_mix, mix_muc_mirror_service_complete,
    LinkMixMucOutcome,
};
use sqlx::PgPool;
use uuid::Uuid;

async fn cleanup(pool: &PgPool, mix_channel_id: Uuid, room_id: Uuid, user_id: Uuid) {
    sqlx::query("DELETE FROM mix_channels WHERE id = $1")
        .bind(mix_channel_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM muc_rooms WHERE id = $1")
        .bind(room_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mirror_link_is_common_owner_only_one_to_one_and_idempotent() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("mirror-{}", &suffix[..16]);
    let localpart = format!("room-{}", &suffix[..16]);
    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin) VALUES ($1, $2, 'test-only', FALSE)",
    )
    .bind(user_id)
    .bind(&username)
    .execute(&pool)
    .await
    .unwrap();
    let creator = format!("{username}@example.invalid/Test");
    let (room, created) =
        northstar_room_postgres::muc::get_or_create_muc_room(&pool, &localpart, user_id, &creator)
            .await
            .unwrap();
    assert!(created);
    let actor = format!("{username}@example.invalid");
    let payloads = northstar_room_application::mix_service::MixPayloads;
    let (created, _) = northstar_room_postgres::mix::create_mix_channel(
        &northstar_workflows::room_effects::WorkflowRoomEffects,
        &pool,
        "mix.example.invalid",
        Some(&localpart),
        &actor,
        100,
        &payloads,
        None,
    )
    .await
    .unwrap();
    let CreateChannelOutcome::Created(channel) = created else {
        panic!("unique test channel was not created")
    };

    assert_eq!(
        link_mix_muc_by_localpart(
            &pool,
            "mix.example.invalid",
            &localpart,
            "mallory@example.invalid",
            "example.invalid",
        )
        .await
        .unwrap(),
        LinkMixMucOutcome::NotCommonOwner,
    );
    assert_eq!(
        link_mix_muc_by_localpart(
            &pool,
            "mix.example.invalid",
            &localpart,
            &actor,
            "example.invalid",
        )
        .await
        .unwrap(),
        LinkMixMucOutcome::Linked,
    );
    assert_eq!(
        link_mix_muc_by_localpart(
            &pool,
            "mix.example.invalid",
            &localpart,
            &actor,
            "example.invalid",
        )
        .await
        .unwrap(),
        LinkMixMucOutcome::AlreadyLinked,
    );
    assert!(mix_muc_mirror_for_mix(&pool, channel)
        .await
        .unwrap()
        .is_some());
    assert!(
        mix_muc_mirror_service_complete(&pool, "mix.example.invalid")
            .await
            .unwrap()
    );

    cleanup(&pool, channel, room.id, user_id).await;
}
