use chrono::DateTime;
use chrono::Utc;
use northstar_workflows::api_pages::*;
use uuid::Uuid;

#[test]
fn page_limit_and_boundary_are_strictly_bounded() {
    assert!(checked_fetch_limit(1).is_ok());
    assert!(checked_fetch_limit(100).is_ok());
    assert!(checked_fetch_limit(0).is_err());
    assert!(checked_fetch_limit(101).is_err());
    assert!(checked_report_fetch_limit(1).is_ok());
    assert!(checked_report_fetch_limit(25).is_ok());
    assert!(checked_report_fetch_limit(0).is_err());
    assert!(checked_report_fetch_limit(26).is_err());

    let migration = include_str!("../../migrations/0060_api_keyset_pages.sql");
    assert!(!migration.contains("CREATE INDEX message_archive"));
    assert!(!migration.contains("CREATE INDEX users"));
    assert!(!migration.contains("CREATE INDEX invitation_tokens"));
    assert!(!migration.contains("CREATE INDEX muc_rooms"));
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_keyset_pages_are_stable_isolated_and_indexed() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let marker = Uuid::new_v4();
    let started_at = database_cursor_clock(&pool).await.unwrap();
    let tied: DateTime<Utc> = sqlx::query_scalar("SELECT date_trunc('second',clock_timestamp())")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut user_ids = (0..7).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    user_ids.sort_unstable();
    let owner = user_ids[0];
    let other = user_ids[1];
    for (ordinal, id) in user_ids.iter().copied().enumerate() {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,created_at) VALUES($1,$2,'test-only',$3)",
        )
        .bind(id)
        .bind(format!(
            "page-user-{ordinal}-{}",
            &marker.simple().to_string()[..8]
        ))
        .bind(tied)
        .execute(&pool)
        .await
        .unwrap();
    }
    for _ in 0..7 {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'peer@example.test','peer@example.test/phone','<message/>',FALSE,$3)")
            .bind(id).bind(owner).bind(tied).execute(&pool).await.unwrap();
    }
    let other_history = Uuid::new_v4();
    sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'peer@example.test','peer@example.test/phone','<message/>',FALSE,$3)")
        .bind(other_history).bind(other).bind(tied).execute(&pool).await.unwrap();
    let different_peer_history = Uuid::new_v4();
    sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'different@example.test','different@example.test/phone','<message/>',FALSE,$3)")
        .bind(different_peer_history).bind(owner).bind(tied).execute(&pool).await.unwrap();

    let first = history_page(&pool, owner, Some("peer@example.test"), None, 3)
        .await
        .unwrap();
    assert_eq!(first.rows.len(), 3);
    assert!(first.database_now >= started_at);
    let first_ids = first
        .rows
        .iter()
        .map(|row| row.id)
        .collect::<std::collections::HashSet<_>>();
    let boundary = first.next.unwrap();
    // A newer concurrent insert must not shift the continuation window.
    let inserted = Uuid::new_v4();
    sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at) VALUES($1,$2,'peer@example.test','peer@example.test/phone','<message/>',FALSE,$3+INTERVAL '1 second')")
        .bind(inserted).bind(owner).bind(tied).execute(&pool).await.unwrap();
    // Deleting an already-returned row also must not duplicate survivors.
    sqlx::query("DELETE FROM message_archive WHERE id=$1")
        .bind(first.rows[0].id)
        .execute(&pool)
        .await
        .unwrap();
    let second = history_page(&pool, owner, Some("peer@example.test"), Some(boundary), 100)
        .await
        .unwrap();
    assert!(second.rows.iter().all(|row| !first_ids.contains(&row.id)));
    assert!(first
        .rows
        .iter()
        .chain(&second.rows)
        .all(|row| row.id != inserted
            && row.id != other_history
            && row.id != different_peer_history));
    assert_eq!(second.rows.len(), 4);

    // Reporter visibility is fail-closed at the public function boundary.
    let own_report_ids = (0..7).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let other_report_ids = (0..2).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    for (id, reporter, status) in own_report_ids
        .iter()
        .copied()
        .map(|id| (id, owner, "submitted"))
        .chain(
            other_report_ids
                .iter()
                .copied()
                .map(|id| (id, other, "reviewing")),
        )
    {
        sqlx::query("INSERT INTO abuse_reports(id,reporter_id,reported_jid,category,description,status,created_at,updated_at) VALUES($1,$2,'reported@example.test','spam','fixture',$3,$4,$4)")
            .bind(id).bind(reporter).bind(status).bind(tied).execute(&pool).await.unwrap();
    }
    let own = own_reports_page(&pool, owner, None, None, 3).await.unwrap();
    assert_eq!(own.rows.len(), 3);
    let own_first_ids = own
        .rows
        .iter()
        .map(|row| row.id)
        .collect::<std::collections::HashSet<_>>();
    let own_boundary = own.next.expect("seven reports require a continuation");
    let concurrent_report = Uuid::new_v4();
    sqlx::query("INSERT INTO abuse_reports(id,reporter_id,reported_jid,category,description,status,created_at,updated_at) VALUES($1,$2,'reported@example.test','spam','fixture','submitted',$3+INTERVAL '1 second',$3+INTERVAL '1 second')")
        .bind(concurrent_report).bind(owner).bind(tied).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM abuse_reports WHERE id=$1")
        .bind(own.rows[0].id)
        .execute(&pool)
        .await
        .unwrap();
    let own_second = own_reports_page(&pool, owner, None, Some(own_boundary), 25)
        .await
        .unwrap();
    assert_eq!(own_second.rows.len(), 4);
    assert!(own_second
        .rows
        .iter()
        .all(|row| !own_first_ids.contains(&row.id) && row.id != concurrent_report));
    assert!(own_second.rows.iter().all(|row| row.reporter_id == owner));
    let admin = admin_reports_page(&pool, None, None, 25).await.unwrap();
    assert!(admin.rows.iter().any(|row| row.id == concurrent_report));
    assert!(other_report_ids
        .iter()
        .all(|id| admin.rows.iter().any(|row| row.id == *id)));
    let reviewing = admin_reports_page(&pool, Some("reviewing"), None, 25)
        .await
        .unwrap();
    assert_eq!(reviewing.rows.len(), 2);
    assert!(reviewing.rows.iter().all(|row| row.reporter_id == other));
    assert!(admin_reports_page(&pool, None, None, 26).await.is_err());

    // The remaining admin collections use the same timestamp/id tie-break.
    let invitation_ids = (0..5).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    for (ordinal, id) in invitation_ids.iter().copied().enumerate() {
        sqlx::query("INSERT INTO invitation_tokens(id,token_hash,label,created_by,max_uses,created_at) VALUES($1,$2,$3,$4,1,$5)")
            .bind(id)
            .bind(id.as_bytes().to_vec())
            .bind(format!("page-{ordinal}-{marker}"))
            .bind(owner)
            .bind(tied)
            .execute(&pool)
            .await
            .unwrap();
    }
    let invite_first = invitations_page(&pool, None, 2).await.unwrap();
    let invite_first_ids = invite_first
        .rows
        .iter()
        .map(|row| row.id)
        .collect::<std::collections::HashSet<_>>();
    let invite_boundary = invite_first
        .next
        .expect("five invitations require a continuation");
    let concurrent_invite = Uuid::new_v4();
    sqlx::query("INSERT INTO invitation_tokens(id,token_hash,label,created_by,max_uses,created_at) VALUES($1,$2,$3,$4,1,$5+INTERVAL '1 second')")
        .bind(concurrent_invite)
        .bind(concurrent_invite.as_bytes().to_vec())
        .bind(format!("page-concurrent-{marker}"))
        .bind(other)
        .bind(tied)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM invitation_tokens WHERE id=$1")
        .bind(invite_first.rows[0].id)
        .execute(&pool)
        .await
        .unwrap();
    let invite_second = invitations_page(&pool, Some(invite_boundary), 100)
        .await
        .unwrap();
    let invite_seen = invite_first
        .rows
        .iter()
        .chain(&invite_second.rows)
        .map(|row| row.id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(invite_seen.len(), 5);
    assert!(invite_second
        .rows
        .iter()
        .all(|row| !invite_first_ids.contains(&row.id) && row.id != concurrent_invite));
    assert!(invitations_page(&pool, None, 100)
        .await
        .unwrap()
        .rows
        .iter()
        .any(|row| row.id == concurrent_invite
            && row
                .created_by
                .as_deref()
                .is_some_and(|name| name.starts_with("page-user-1-"))));

    let room_ids = (0..5).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    for (ordinal, id) in room_ids.iter().copied().enumerate() {
        sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id,created_at) VALUES($1,$2,$3,$4)")
            .bind(id)
            .bind(format!(
                "page-{ordinal}-{}",
                &marker.simple().to_string()[..8]
            ))
            .bind(owner)
            .bind(tied)
            .execute(&pool)
            .await
            .unwrap();
    }
    let room_first = admin_muc_rooms_page(&pool, None, 2).await.unwrap();
    let room_first_ids = room_first
        .rows
        .iter()
        .map(|row| row.id)
        .collect::<std::collections::HashSet<_>>();
    let room_boundary = room_first.next.expect("five rooms require a continuation");
    let concurrent_room = Uuid::new_v4();
    sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id,public,created_at) VALUES($1,$2,$3,FALSE,$4+INTERVAL '1 second')")
        .bind(concurrent_room)
        .bind(format!("page-concurrent-{}", &marker.simple().to_string()[..8]))
        .bind(other)
        .bind(tied)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room_first.rows[0].id)
        .execute(&pool)
        .await
        .unwrap();
    let room_second = admin_muc_rooms_page(&pool, Some(room_boundary), 100)
        .await
        .unwrap();
    let room_seen = room_first
        .rows
        .iter()
        .chain(&room_second.rows)
        .map(|row| row.id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(room_seen.len(), 5);
    assert!(room_second
        .rows
        .iter()
        .all(|row| !room_first_ids.contains(&row.id) && row.id != concurrent_room));
    assert!(admin_muc_rooms_page(&pool, None, 100)
        .await
        .unwrap()
        .rows
        .iter()
        .any(|row| row.id == concurrent_room && !row.public));

    let user_first = users_page(&pool, None, 2).await.unwrap();
    let user_first_ids = user_first
        .rows
        .iter()
        .map(|row| row.id)
        .collect::<std::collections::HashSet<_>>();
    let user_boundary = user_first.next.expect("seven users require a continuation");
    let concurrent_user = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash,created_at) VALUES($1,$2,'test-only',$3+INTERVAL '1 second')")
        .bind(concurrent_user)
        .bind(format!("page-concurrent-user-{}", &marker.simple().to_string()[..8]))
        .bind(tied)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_first.rows[0].id)
        .execute(&pool)
        .await
        .unwrap();
    let user_second = users_page(&pool, Some(user_boundary), 100).await.unwrap();
    assert_eq!(user_first.rows.len(), 2);
    assert_eq!(user_second.rows.len(), 5);
    assert!(user_second
        .rows
        .iter()
        .all(|row| !user_first_ids.contains(&row.id) && row.id != concurrent_user));

    let mut explain_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan=off")
        .execute(&mut *explain_tx)
        .await
        .unwrap();
    let (archive_peer_index_valid, archive_peer_index_ready, archive_peer_index_definition): (
        bool,
        bool,
        String,
    ) = sqlx::query_as(
        "SELECT definition.indisvalid,
                definition.indisready,
                pg_get_indexdef(definition.indexrelid)
           FROM pg_index definition
          WHERE definition.indexrelid =
                to_regclass('message_archive_owner_peer_bare_time_id_idx')",
    )
    .fetch_one(&mut *explain_tx)
    .await
    .unwrap();
    assert!(archive_peer_index_valid && archive_peer_index_ready);
    assert_eq!(
        archive_peer_index_definition
            .rsplit_once(" USING btree ")
            .map(|(_, columns)| columns),
        Some("(owner_id, peer_jid, created_at, id)"),
        "archive peer keyset index definition drifted: {archive_peer_index_definition}"
    );
    let plan: Vec<String> = sqlx::query_scalar("EXPLAIN (COSTS OFF) SELECT id FROM message_archive WHERE owner_id=$1 AND peer_jid=$2 AND (created_at,id)<($3,$4) ORDER BY created_at DESC,id DESC LIMIT 101")
        .bind(owner).bind("peer@example.test").bind(tied).bind(Uuid::from_u128(u128::MAX)).fetch_all(&mut *explain_tx).await.unwrap();
    let rendered_plan = plan.join("\n");
    assert!(
        rendered_plan.contains("Index Scan") || rendered_plan.contains("Index Only Scan"),
        "archive keyset query did not have an ordered index path:\n{rendered_plan}"
    );
    assert!(
        !rendered_plan.contains("Sort"),
        "archive keyset query required an explicit sort:\n{rendered_plan}"
    );
    let archive_keyset_indexes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_indexes
         WHERE schemaname=current_schema()
           AND indexname IN ('message_archive_owner_time_id_idx',
                             'message_archive_owner_peer_bare_time_id_idx')",
    )
    .fetch_one(&mut *explain_tx)
    .await
    .unwrap();
    assert_eq!(archive_keyset_indexes, 2);
    explain_tx.rollback().await.unwrap();
    pool.close().await;
}
