use northstar_archive_core::{MamArchiveQuery, MamRsmPage};
use northstar_room_postgres::mix::{
    create_mix_channel, mix_mam_page, prune_mix_events_tx, CreateChannelOutcome, NODE_MESSAGES,
};
use sqlx::PgPool;
use uuid::Uuid;

async fn create_fixture() -> (PgPool, Uuid) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::support::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let owner = format!("owner-{suffix}@example.test");
    let localpart = format!("paging-{}", &suffix[..16]);
    let (outcome, _) = create_mix_channel(
        &northstar_workflows::room_effects::WorkflowRoomEffects,
        &pool,
        "mix.example.test",
        Some(&localpart),
        &owner,
        100,
        &northstar_room_application::mix_service::MixPayloads,
        None,
    )
    .await
    .unwrap();
    let CreateChannelOutcome::Created(channel) = outcome else {
        panic!("unique paging test channel was not created");
    };
    (pool, channel)
}

async fn delete_channel(pool: &PgPool, channel: Uuid) {
    sqlx::query("DELETE FROM mix_channels WHERE id=$1")
        .bind(channel)
        .execute(pool)
        .await
        .unwrap();
}

async fn insert_event(
    pool: &PgPool,
    channel: Uuid,
    storage_id: Uuid,
    public_id: Uuid,
    second: i32,
) {
    sqlx::query(
        "INSERT INTO mix_events(id,channel_id,node,item_id,publisher_jid,payload,created_at)
         VALUES($1,$2,$3,$4,'publisher@example.test',$5,
                TIMESTAMPTZ '2026-01-01 00:00:00Z' + $6::integer * INTERVAL '1 second')",
    )
    .bind(storage_id)
    .bind(channel)
    .bind(NODE_MESSAGES)
    .bind(public_id.to_string())
    .bind(format!("<message id='{public_id}'/>"))
    .bind(second)
    .execute(pool)
    .await
    .unwrap();
}

fn query(page: MamRsmPage, max: i64) -> MamArchiveQuery {
    MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page,
        max,
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mix_mam_paging_across_deletion_preserves_surviving_cursors() {
    use MamRsmPage::{After, Before, First, Index};

    let (pool, channel) = create_fixture().await;
    let [a, b, c, d, e, f, g] = [(); 7].map(|()| Uuid::new_v4());
    for (id, second) in [a, b, c, d, e, f, g].into_iter().zip(0..7) {
        insert_event(&pool, channel, Uuid::new_v4(), id, second).await;
    }

    let read = async |page, max| {
        mix_mam_page(&pool, channel, &query(page, max))
            .await
            .unwrap()
    };
    let check = async |page, max, ids: &[Uuid], total, index, complete| {
        let Some(result) = read(page, max).await else {
            panic!("expected a MIX MAM page for {page:?}");
        };
        let actual: Vec<_> = result.events.iter().map(|event| event.id).collect();
        assert_eq!(actual.as_slice(), ids, "{page:?}");
        assert_eq!(
            (result.total, result.first_index, result.complete),
            (total, index, complete),
            "{page:?}"
        );
    };
    let delete = async |id: Uuid| {
        assert_eq!(
            sqlx::query(
                "DELETE FROM mix_events WHERE channel_id=$1 AND node=$2 AND authoritative_id=$3"
            )
            .bind(channel)
            .bind(NODE_MESSAGES)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
            1
        );
        for cursor in [Before(id), After(id)] {
            assert!(read(cursor, 2).await.is_none(), "{cursor:?}");
        }
    };

    check(First, 4, &[a, b, c, d], 7, 0, false).await;
    check(After(d), 2, &[e, f], 7, 4, false).await;
    check(Before(d), 2, &[b, c], 7, 1, false).await;
    check(Index(4), 2, &[e, f], 7, 4, false).await;

    delete(b).await;
    check(After(d), 2, &[e, f], 6, 3, false).await;
    check(Before(d), 2, &[a, c], 6, 0, true).await;
    // Resuming after four consumed rows by offset skips the unseen event e.
    check(Index(4), 2, &[f, g], 6, 4, true).await;

    delete(f).await;
    check(After(d), 2, &[e, g], 5, 3, true).await;
    check(Before(d), 2, &[a, c], 5, 0, true).await;

    check(After(e), 2, &[g], 5, 4, true).await;
    check(Before(e), 2, &[c, d], 5, 1, false).await;
    delete(d).await;
    check(After(e), 2, &[g], 4, 3, true).await;
    check(Before(e), 2, &[a, c], 4, 0, true).await;

    check(First, 0, &[], 4, 0, false).await;
    check(After(g), 0, &[], 4, 0, true).await;
    check(Before(a), 0, &[], 4, 0, true).await;
    delete_channel(&pool, channel).await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn mix_mam_count_pruning_uses_storage_uuid_for_timestamp_ties() {
    let (pool, channel) = create_fixture().await;
    let mut public_ids = [(); 5].map(|()| Uuid::new_v4());
    public_ids.sort_unstable();
    let [newest, first, middle, last, old] = public_ids;
    let mut storage_ids = [(); 5].map(|()| Uuid::new_v4());
    storage_ids.sort_unstable();
    // Among the tied events, first has the largest storage UUID, then last,
    // then middle. A suffix of the MAM page would keep middle and last.
    for (id, storage_index, second) in [
        (old, 4, 0),
        (first, 3, 1),
        (middle, 1, 1),
        (last, 2, 1),
        (newest, 0, 2),
    ] {
        insert_event(&pool, channel, storage_ids[storage_index], id, second).await;
    }

    let read = async || {
        let Some(page) = mix_mam_page(&pool, channel, &query(MamRsmPage::First, 10))
            .await
            .unwrap()
        else {
            panic!("expected a MIX MAM page");
        };
        assert_eq!(page.first_index, 0);
        assert!(page.complete);
        assert!(page.events.windows(2).all(|events| {
            (events[0].created_at, events[0].id) < (events[1].created_at, events[1].id)
        }));
        (
            page.events
                .into_iter()
                .map(|event| event.id)
                .collect::<Vec<_>>(),
            page.total,
        )
    };
    assert_eq!(read().await, (vec![old, first, middle, last, newest], 5));

    let mut tx = pool.begin().await.unwrap();
    prune_mix_events_tx(&mut tx, channel, 3).await.unwrap();
    tx.commit().await.unwrap();

    let survivors: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM mix_events WHERE channel_id=$1 AND node=$2 ORDER BY id")
            .bind(channel)
            .bind(NODE_MESSAGES)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(survivors, [storage_ids[0], storage_ids[2], storage_ids[3]]);
    assert_eq!(read().await, (vec![first, last, newest], 3));
    delete_channel(&pool, channel).await;
}
