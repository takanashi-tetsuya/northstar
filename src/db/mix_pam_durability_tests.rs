use super::*;
use crate::db;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pam_restart_and_result_claims_preserve_authority_and_token_fencing() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let user_id = Uuid::new_v4();
    let username = format!("pam-{suffix}");
    let requester = format!("{username}@example.test/device");
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();

    let pending_id = Uuid::new_v4();
    let pending_request = format!("pending-{suffix}");
    sqlx::query(
        "INSERT INTO mix_pam_memberships(
                 id,user_id,channel_jid,state,request_id,client_request_id,requester_full_jid
             ) VALUES($1,$2,'pending@remote.example','pending_join',$3,'client-pending',$4)",
    )
    .bind(pending_id)
    .bind(user_id)
    .bind(&pending_request)
    .bind(&requester)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_pam_operations(
                 operation_id,user_id,channel_jid,remote_domain,operation,
                 remote_request_id,client_request_id,requester_full_jid,
                 request_digest,request_outbox_id,deadline_at,expires_at
             ) VALUES($1,$2,'pending@remote.example','remote.example','join',$3,
                      'client-pending',$4,$5,$6,
                      clock_timestamp()+INTERVAL '1 hour',clock_timestamp()+INTERVAL '8 days')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&pending_request)
    .bind(&requester)
    .bind(vec![7_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    recover_remote_pam_after_restart(&pool).await.unwrap();
    let pending_state: String =
        sqlx::query_scalar("SELECT state FROM mix_pam_memberships WHERE id=$1")
            .bind(pending_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pending_state, "pending_join");

    let terminal_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_pam_operations(
                 operation_id,user_id,channel_jid,remote_domain,operation,
                 remote_request_id,client_request_id,requester_full_jid,
                 request_digest,request_outbox_id,state,remote_response_digest,
                 response_xml,deadline_at,expires_at
             ) VALUES($1,$2,'done@remote.example','remote.example','leave',$3,
                      'client-done',$4,$5,$6,'terminal',$7,
                      '<iq xmlns=\"jabber:client\" type=\"result\"/>',
                      clock_timestamp()+INTERVAL '1 hour',clock_timestamp()+INTERVAL '8 days')",
    )
    .bind(terminal_id)
    .bind(user_id)
    .bind(format!("done-{suffix}"))
    .bind(&requester)
    .bind(vec![8_u8; 32])
    .bind(Uuid::new_v4())
    .bind(vec![9_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let (left, right) = tokio::join!(claim_pam_results(&pool, 1), claim_pam_results(&pool, 1));
    let mut claimed = left.unwrap();
    claimed.extend(right.unwrap());
    assert_eq!(
        claimed.len(),
        1,
        "concurrent claims must have one lease owner"
    );
    let claimed = claimed.pop().unwrap();
    assert!(!acknowledge_pam_result(&pool, terminal_id, Uuid::new_v4())
        .await
        .unwrap());
    assert!(
        renew_pam_result_lease(&pool, terminal_id, claimed.lease_token)
            .await
            .unwrap()
    );
    assert!(
        acknowledge_pam_result(&pool, terminal_id, claimed.lease_token)
            .await
            .unwrap()
    );
    assert!(
        !acknowledge_pam_result(&pool, terminal_id, claimed.lease_token)
            .await
            .unwrap()
    );

    let reconciliation_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_pam_operations(
                 operation_id,user_id,channel_jid,remote_domain,operation,
                 remote_request_id,client_request_id,requester_full_jid,
                 request_digest,request_outbox_id,state,response_xml,
                 delivered_at,created_at,deadline_at,expires_at
             ) VALUES($1,$2,'uncertain@remote.example','remote.example','join',$3,
                      'client-uncertain',$4,$5,$6,'reconciliation',
                      '<iq xmlns=\"jabber:client\" type=\"error\"/>',
                      clock_timestamp()-INTERVAL '2 days',
                      clock_timestamp()-INTERVAL '8 days',
                      clock_timestamp()-INTERVAL '7 days',
                      clock_timestamp()-INTERVAL '1 day')",
    )
    .bind(reconciliation_id)
    .bind(user_id)
    .bind(format!("uncertain-{suffix}"))
    .bind(&requester)
    .bind(vec![10_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    prune_expired_pam_results(&pool, 512).await.unwrap();
    let retained: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mix_pam_operations WHERE operation_id=$1)")
            .bind(reconciliation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        retained,
        "unresolved reconciliation authority must survive result retention cleanup"
    );

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}
