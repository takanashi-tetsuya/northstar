//! The key deployment authority over its PostgreSQL adapter and the tables of the other contexts.
use crate::db::abuse_effects::RootAbuseEffects;
use anyhow::Result;
use northstar_abuse_application::guard::records::AbuseKeyDeploymentIdentity;
use northstar_abuse_postgres::keys::validate_abuse_key_deployment;
use sqlx::PgPool;
use std::time::Duration;

const OLD: &str = "AAAAAAAAAAAAAAAA";
const NEW: &str = "BBBBBBBBBBBBBBBB";
const WRONG: &str = "CCCCCCCCCCCCCCCC";

fn identity(epoch: i64, current: &str, previous: Option<&str>) -> AbuseKeyDeploymentIdentity {
    AbuseKeyDeploymentIdentity {
        xmpp_domain: "example.test".to_owned(),
        epoch,
        current_key_id: current.to_owned(),
        previous_key_id: previous.map(str::to_owned),
        retire_previous: false,
        minimum_overlap: Duration::from_secs(3_600),
    }
}

async fn reconcile_abuse_key_deployment(
    pool: &PgPool,
    identity: &AbuseKeyDeploymentIdentity,
) -> Result<()> {
    northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
        pool,
        identity,
        &RootAbuseEffects,
    )
    .await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_authority_enforces_bootstrap_overlap_and_retirement() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    assert!(url.contains("xmpp_test"));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let test_domain = format!(
        "key-{}.example.test",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let for_test_domain = |mut value: AbuseKeyDeploymentIdentity| {
        value.xmpp_domain.clone_from(&test_domain);
        value
    };

    let old = for_test_domain(identity(1, OLD, None));
    let (first_bootstrap, second_bootstrap) = tokio::join!(
        reconcile_abuse_key_deployment(&pool, &old),
        reconcile_abuse_key_deployment(&pool, &old)
    );
    first_bootstrap.unwrap();
    second_bootstrap.unwrap();
    validate_abuse_key_deployment(&pool, &old).await.unwrap();
    assert!(
        validate_abuse_key_deployment(&pool, &for_test_domain(identity(1, WRONG, None)))
            .await
            .is_err()
    );

    let mut rotating = for_test_domain(identity(2, NEW, Some(OLD)));
    rotating.minimum_overlap = Duration::from_secs(1);
    let (first_rotation, second_rotation) = tokio::join!(
        reconcile_abuse_key_deployment(&pool, &rotating),
        reconcile_abuse_key_deployment(&pool, &rotating)
    );
    first_rotation.unwrap();
    second_rotation.unwrap();
    validate_abuse_key_deployment(&pool, &old).await.unwrap();
    validate_abuse_key_deployment(&pool, &rotating)
        .await
        .unwrap();
    rotating.retire_previous = true;
    reconcile_abuse_key_deployment(&pool, &rotating)
        .await
        .unwrap();
    validate_abuse_key_deployment(&pool, &rotating)
        .await
        .unwrap();
    assert!(validate_abuse_key_deployment(&pool, &old).await.is_err());
    assert!(
        reconcile_abuse_key_deployment(&pool, &for_test_domain(identity(2, NEW, None)))
            .await
            .is_err()
    );

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let current = for_test_domain(identity(2, NEW, None));
    let marker = uuid::Uuid::new_v4();
    let user_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(user_id)
        .bind(format!("keyfence-{}", &marker.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO abuse_pow_challenges(
             id,action,subject_hash,key_id,prefix,work_factor,not_before,
             expires_at,actor_sequences,requirement,capacity_actor_keys)
         VALUES($1,'report',decode(md5($1::text) || md5('subject:' || $1::text),'hex'),
                $2,'rotation-fence:',1,clock_timestamp(),
                clock_timestamp()+INTERVAL '1 hour','{}'::jsonb,'{}'::jsonb,'{}')",
    )
    .bind(marker)
    .bind(OLD)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_message_admissions(
             admission_key,key_id,actor_id,capacity_shard,payload_mac,state,
             lease_token,lease_expires_at,expires_at)
         VALUES(decode(md5('admission:' || $1::text) || md5('key:' || $1::text),'hex'),
                $2,$3,0,
                decode(md5('payload:' || $1::text) || md5('mac:' || $1::text),'hex'),
                'pending',$1,clock_timestamp()+INTERVAL '1 hour',
                clock_timestamp()+INTERVAL '1 hour')",
    )
    .bind(marker)
    .bind(OLD)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO offline_message_admissions(
             identity_digest,payload_key_id,recipient_id,capacity_shard,payload_mac,expires_at)
         VALUES(decode(md5('offline:' || $1::text) || md5('identity:' || $1::text),'hex'),
                $2,$3,0,
                decode(md5('offline-payload:' || $1::text) || md5('offline-mac:' || $1::text),'hex'),
                NULL)",
    )
    .bind(marker)
    .bind(OLD)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    let archive_id = uuid::Uuid::new_v4();
    let personal_admission_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive(
             id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
         VALUES($1,$2,'peer@example.test','peer@example.test/phone',
                '<message xmlns=\"jabber:client\"/>',FALSE,'key-fence-message')",
    )
    .bind(archive_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO personal_message_admissions(
             id,identity_kind,actor_scope_raw,actor_scope,target_scope,
             identity_value,identity_digest,payload_key_id,payload_mac,
             sender_archive_id)
         VALUES($1,'local-origin','key-fence@example.test',
                'key-fence@example.test','peer@example.test',$2,
                decode(md5('personal-identity:' || $2) || md5('personal-key:' || $2),'hex'),
                $3,decode(md5('personal-payload:' || $2) || md5('personal-mac:' || $2),'hex'),
                $4)",
    )
    .bind(personal_admission_id)
    .bind(marker.to_string())
    .bind(OLD)
    .bind(archive_id)
    .execute(&pool)
    .await
    .unwrap();
    let retraction_intent_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO personal_retraction_intents(
             id,sender_bare_jid,action_id,action_digest,target_id,
             semantic_key_id,semantic_mac,
             owner_projection_sha256,owner_projection_sha512,
             owner_projection_length,outbound_requested)
         VALUES($1,'key-fence@example.test',$2,
                decode(md5('retraction-action:' || $2) || md5('retraction-key:' || $2),'hex'),
                'target-message',$3,
                decode(md5('retraction-semantic:' || $2) || md5('retraction-mac:' || $2),'hex'),
                decode(md5('owner-sha256:' || $2) || md5('owner-key:' || $2),'hex'),
                decode(md5('owner-sha512-a:' || $2) || md5('owner-sha512-b:' || $2) ||
                       md5('owner-sha512-c:' || $2) || md5('owner-sha512-d:' || $2),'hex'),
                1,FALSE)",
    )
    .bind(retraction_intent_id)
    .bind(marker.to_string())
    .bind(OLD)
    .execute(&pool)
    .await
    .unwrap();
    let c2s_only_retraction_intent_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO personal_retraction_intents(
             id,sender_bare_jid,action_id,action_digest,target_id,
             semantic_key_id,semantic_mac,
             owner_projection_key_id,owner_projection_mac,
             outbound_requested,c2s_delivery_requested,
             c2s_projection_key_id,c2s_projection_mac)
         VALUES($1,'c2s-key-fence@example.test',$2,
                decode(md5('c2s-action:' || $2) || md5('c2s-action-key:' || $2),'hex'),
                'target-message',$3,
                decode(md5('c2s-semantic:' || $2) || md5('c2s-semantic-mac:' || $2),'hex'),
                $3,decode(md5('c2s-owner:' || $2) || md5('c2s-owner-mac:' || $2),'hex'),
                FALSE,TRUE,$4,
                decode(md5('c2s-projection:' || $2) || md5('c2s-projection-mac:' || $2),'hex'))",
    )
    .bind(c2s_only_retraction_intent_id)
    .bind(format!("c2s-{marker}"))
    .bind(NEW)
    .bind(OLD)
    .execute(&pool)
    .await
    .unwrap();
    let owner_only_retraction_intent_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO personal_retraction_intents(
             id,sender_bare_jid,action_id,action_digest,target_id,
             semantic_key_id,semantic_mac,
             owner_projection_key_id,owner_projection_mac,
             outbound_requested)
         VALUES($1,'owner-key-fence@example.test',$2,
                decode(md5('owner-action:' || $2) || md5('owner-action-key:' || $2),'hex'),
                'target-message',$3,
                decode(md5('owner-semantic:' || $2) || md5('owner-semantic-mac:' || $2),'hex'),
                $4,decode(md5('owner-projection:' || $2) || md5('owner-projection-mac:' || $2),'hex'),
                FALSE)",
    )
    .bind(owner_only_retraction_intent_id)
    .bind(format!("owner-{marker}"))
    .bind(NEW)
    .bind(OLD)
    .execute(&pool)
    .await
    .unwrap();
    let mix_channel_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_channels(id,service_domain,localpart,creator_jid)
         VALUES($1,'mix.example.test',$2,'key-fence@example.test')",
    )
    .bind(mix_channel_id)
    .bind(format!("key-fence-{}", &marker.to_string()[..8]))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_business_intents(
             channel_id,actor_jid,client_id,operation,semantic_key_id,
             semantic_mac,authoritative_id)
         VALUES($1,'key-fence@example.test',$2,'message',$3,
                decode(md5('mix-active:' || $2) || md5('mix-active-mac:' || $2),'hex'),$4)",
    )
    .bind(mix_channel_id)
    .bind(format!("mix-active-{marker}"))
    .bind(OLD)
    .bind(uuid::Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_business_intents(
             channel_id,actor_jid,client_id,operation,semantic_key_id,
             semantic_mac,authoritative_id,created_at,expires_at)
         VALUES($1,'key-fence@example.test',$2,'message',$3,
                decode(md5('mix-expired:' || $2) || md5('mix-expired-mac:' || $2),'hex'),$4,
                clock_timestamp()-INTERVAL '2 days',
                clock_timestamp()-INTERVAL '1 day')",
    )
    .bind(mix_channel_id)
    .bind(format!("mix-expired-{marker}"))
    .bind(OLD)
    .bind(uuid::Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    let fenced = reconcile_abuse_key_deployment(&pool, &current)
        .await
        .unwrap_err()
        .to_string();
    assert!(fenced.contains("challenges 1"), "{fenced}");
    assert!(fenced.contains("message admissions 1"), "{fenced}");
    assert!(fenced.contains("offline admissions 1"), "{fenced}");
    assert!(fenced.contains("personal message identities 1"), "{fenced}");
    assert!(fenced.contains("retraction identities 3"), "{fenced}");
    assert!(fenced.contains("MIX business identities 1"), "{fenced}");
    sqlx::query("DELETE FROM abuse_pow_challenges WHERE id=$1")
        .bind(marker)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM personal_message_admissions WHERE id=$1")
        .bind(personal_admission_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM abuse_message_admissions WHERE lease_token=$1")
        .bind(marker)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM offline_message_admissions WHERE recipient_id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM personal_retraction_intents WHERE id=$1")
        .bind(retraction_intent_id)
        .execute(&pool)
        .await
        .unwrap();
    let c2s_and_owner_fenced = reconcile_abuse_key_deployment(&pool, &current)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        c2s_and_owner_fenced.contains("retraction identities 2"),
        "{c2s_and_owner_fenced}"
    );
    sqlx::query("DELETE FROM personal_retraction_intents WHERE id=$1")
        .bind(c2s_only_retraction_intent_id)
        .execute(&pool)
        .await
        .unwrap();
    let owner_fenced = reconcile_abuse_key_deployment(&pool, &current)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        owner_fenced.contains("retraction identities 1"),
        "{owner_fenced}"
    );
    sqlx::query("DELETE FROM personal_retraction_intents WHERE id=$1")
        .bind(owner_only_retraction_intent_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mix_channels WHERE id=$1")
        .bind(mix_channel_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    reconcile_abuse_key_deployment(&pool, &current)
        .await
        .unwrap();
    validate_abuse_key_deployment(&pool, &current)
        .await
        .unwrap();
    assert!(validate_abuse_key_deployment(&pool, &old).await.is_err());

    let deletion = sqlx::query("DELETE FROM abuse_key_deployments WHERE xmpp_domain=$1")
        .bind(&test_domain)
        .execute(&pool)
        .await
        .unwrap_err()
        .to_string();
    assert!(deletion.contains("append-only"), "{deletion}");
    validate_abuse_key_deployment(&pool, &current)
        .await
        .unwrap();
    let history: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_key_deployment_history WHERE xmpp_domain=$1",
    )
    .bind(&test_domain)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        history >= 4,
        "expected every authority transition in history"
    );
}
