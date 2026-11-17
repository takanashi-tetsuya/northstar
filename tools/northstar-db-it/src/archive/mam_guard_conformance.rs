use northstar_room_postgres::mam_authorization::FederatedMamRoomGuard;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn cancelled_mam_lock_wait_and_dropped_guard_close_the_original_backend() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_3001);
    let room = Uuid::from_u128(0x573_3002);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'mam-guard','test-only')")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret) VALUES($1,'mam-guard',$2,$3)")
        .bind(room).bind(user).bind(vec![7_u8; 32]).execute(&pool).await.unwrap();
    for label in ["cancelled lock wait", "dropped acquired guard"] {
        let mut blocker = pool.begin().await.unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,29))")
            .bind(room.to_string())
            .execute(&mut *blocker)
            .await
            .unwrap();
        let reader_pool = pool.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let reader = tokio::spawn(async move {
            let mut guard = FederatedMamRoomGuard::acquire(&reader_pool, "mam-guard")
                .await
                .unwrap()
                .unwrap();
            let mut snapshot = guard.begin_snapshot().await.unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *snapshot)
                .await
                .unwrap();
            snapshot.commit().await.unwrap();
            ready_tx.send(pid).unwrap();
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        let waiting_pid = crate::support::blocked_backend(&pool, blocker_pid).await;
        if label == "dropped acquired guard" {
            blocker.rollback().await.unwrap();
            assert_eq!(
                ready_rx.await.unwrap(),
                waiting_pid,
                "guard retained its exact connection"
            );
            reader.abort();
            assert!(reader.await.unwrap_err().is_cancelled(), "{label}");
        } else {
            drop(ready_rx);
            reader.abort();
            assert!(reader.await.unwrap_err().is_cancelled(), "{label}");
            blocker.rollback().await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let alive: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                )
                .bind(waiting_pid)
                .fetch_one(&pool)
                .await
                .unwrap();
                if !alive {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("abandoned MAM backend was returned to the pool instead of closed");
    }
    sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
        .bind(room)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
