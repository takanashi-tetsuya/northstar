use northstar_abuse_policy::model::AbuseKeyDeploymentIdentity;
use northstar_message_application::retractions::*;
use northstar_workflows::abuse_effects::WorkflowAbuseEffects;
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn keyed_owner_evidence_survives_archive_removal_and_fences_key_retirement() {
    let pool = crate::support::operation_mutation_pool().await;
    let owner = Uuid::from_u128(0x573_4101);
    let original = Uuid::from_u128(0x573_4102);
    let identity = Uuid::from_u128(0x573_4103);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'retraction-evidence','test-only')",
    )
    .bind(owner)
    .execute(&pool)
    .await
    .unwrap();
    // This exercises the bounded stanza-ID index through the real owner
    // lookup, including an ID at the service's maximum supported byte length.
    let target = "x".repeat(1024);
    let original_xml = format!("<message from='retraction-evidence@local.test/phone' to='peer@remote.test/device' id='{target}'><body>original</body></message>");
    sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id) VALUES($1,$2,'peer@remote.test','peer@remote.test/device',$3,FALSE,$4)")
        .bind(original).bind(owner).bind(&original_xml).bind(&target).execute(&pool).await.unwrap();
    let keyring = northstar_abuse_policy::content_identity::PersonalRetractionContentKeyring::new(
        std::sync::Arc::new(vec![
            northstar_abuse_policy::content_identity::ContentIdentityGeneration {
                key_id: "RETRACTION573KEY".into(),
                key: zeroize::Zeroizing::new(vec![73; 32]),
            },
        ]),
    );
    let action = format!("<message from='retraction-evidence@local.test/phone' to='peer@remote.test/device' id='evidence-action'><retract xmlns='urn:xmpp:message-retract:1' id='{target}'/></message>");
    let command = RetractionCommand {
        target_id: &target,
        action_id: "evidence-action",
        semantic_payload: &action,
    };
    let semantics = canonical_retraction_semantics(
        &action,
        "retraction-evidence@local.test",
        command.action_id,
        command.target_id,
    )
    .unwrap();
    let authenticators = keyring.authenticators(&semantics);
    let old_key = authenticators.primary().key_id().to_owned();
    let service = RetractionService::new(
        northstar_workflows::retraction_repository::PostgresRetractionRepository::new(pool.clone()),
        keyring,
        "local.test",
    );
    let owners = [OwnerProjection {
        owner_id: owner,
        peer_jid: "peer@remote.test/device",
    }];
    assert!(matches!(
        service
            .apply(
                &owners,
                "retraction-evidence@local.test/phone",
                &command,
                &[],
                None
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 1, .. }
    ));
    let mut observer = pool.acquire().await.unwrap();
    type Evidence = (
        String,
        Vec<u8>,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<i64>,
    );
    let evidence: Evidence = sqlx::query_as(
        "SELECT semantic_key_id,semantic_mac,owner_projection_key_id,owner_projection_mac,
         owner_projection_sha256,owner_projection_sha512,owner_projection_length
         FROM personal_retraction_intents WHERE action_id='evidence-action'",
    )
    .fetch_one(&mut *observer)
    .await
    .unwrap();
    assert_eq!(evidence.0, old_key);
    assert_eq!(evidence.1, authenticators.primary().mac().to_vec());
    assert_eq!(evidence.2, old_key);
    assert_eq!(evidence.3.len(), 32);
    assert_eq!(
        (evidence.4, evidence.5, evidence.6),
        (None, None, None),
        "new owner evidence uses the keyed shape"
    );
    drop(observer);
    // Keep an independently referenced message identity after its archive
    // projection is removed; retirement must account for each owner.
    sqlx::query(
        "INSERT INTO personal_message_admissions(id,identity_kind,actor_scope_raw,actor_scope,target_scope,identity_value,identity_digest,payload_key_id,payload_mac,sender_archive_id)
         VALUES($1,'local-origin','retraction-evidence@local.test','retraction-evidence@local.test','peer@remote.test','evidence-origin',$2,$3,$4,$5)",
    ).bind(identity).bind(vec![11_u8; 32]).bind(&old_key).bind(vec![12_u8; 32]).bind(original).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM message_archive WHERE id=$1")
        .bind(original)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        service
            .apply(
                &owners,
                "retraction-evidence@local.test/phone",
                &command,
                &[],
                None
            )
            .await
            .unwrap(),
        RetractionOutcome::Replay,
        "retained owner commitment authenticates replay after archive retention"
    );

    let bootstrap = AbuseKeyDeploymentIdentity {
        xmpp_domain: "retraction-conformance.test".into(),
        epoch: 1,
        current_key_id: old_key.clone(),
        previous_key_id: None,
        retire_previous: false,
        minimum_overlap: Duration::from_secs(1),
    };
    northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
        &pool,
        &bootstrap,
        &WorkflowAbuseEffects,
    )
    .await
    .unwrap();
    let rotating = AbuseKeyDeploymentIdentity {
        epoch: 2,
        current_key_id: "BBBBBBBBBBBBBBBB".into(),
        previous_key_id: Some(old_key),
        ..bootstrap.clone()
    };
    northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
        &pool,
        &rotating,
        &WorkflowAbuseEffects,
    )
    .await
    .unwrap();
    let sealing = AbuseKeyDeploymentIdentity {
        retire_previous: true,
        ..rotating.clone()
    };
    northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
        &pool,
        &sealing,
        &WorkflowAbuseEffects,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let retiring = AbuseKeyDeploymentIdentity {
        previous_key_id: None,
        retire_previous: false,
        ..rotating
    };
    let error = northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
        &pool,
        &retiring,
        &WorkflowAbuseEffects,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("personal message identities 1")
            && error.contains("retraction identities 1"),
        "{error}"
    );
    sqlx::query("DELETE FROM personal_message_admissions WHERE id=$1")
        .bind(identity)
        .execute(&pool)
        .await
        .unwrap();
    let error = northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
        &pool,
        &retiring,
        &WorkflowAbuseEffects,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("personal message identities 0")
            && error.contains("retraction identities 1"),
        "{error}"
    );
    sqlx::query("DELETE FROM personal_retraction_intents WHERE action_id='evidence-action'")
        .execute(&pool)
        .await
        .unwrap();
    northstar_abuse_postgres::keys::reconcile_abuse_key_deployment(
        &pool,
        &retiring,
        &WorkflowAbuseEffects,
    )
    .await
    .unwrap();
    northstar_abuse_postgres::keys::validate_abuse_key_deployment(&pool, &retiring)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
