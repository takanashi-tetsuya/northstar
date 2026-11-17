use northstar_roster_application::{
    RosterAuthorization, RosterGetCommand, RosterService, S2sOutboxPolicy,
};
use northstar_roster_postgres::{roster::PostgresRosterRepository, RosterTransactionEffects};
use northstar_workflows::roster::WorkflowRosterEffects;
use sqlx::{Postgres, Transaction};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Notify;
use uuid::Uuid;

struct SnapshotEffects {
    owner: Uuid,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

impl RosterTransactionEffects for SnapshotEffects {
    async fn cancel_inaccessible_pep_subscriptions(
        &self,
        _: &mut Transaction<'_, Postgres>,
        _: Uuid,
        _: &str,
    ) -> anyhow::Result<()> {
        panic!("read-only snapshot called a mutation port");
    }
    async fn enqueue_federated_stanza(
        &self,
        _: &mut Transaction<'_, Postgres>,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: S2sOutboxPolicy,
    ) -> anyhow::Result<()> {
        panic!("read-only snapshot called federation");
    }
    async fn mix_participants(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        owner: Uuid,
    ) -> anyhow::Result<HashMap<String, String>> {
        assert_eq!(owner, self.owner, "annotations retain the original owner");
        self.entered.notify_one();
        self.release.notified().await;
        WorkflowRosterEffects.mix_participants(tx, owner).await
    }
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn roster_body_version_and_annotations_share_the_authorized_snapshot() {
    let pool = crate::support::operation_mutation_pool().await;
    let owner = Uuid::from_u128(0x573_2201);
    sqlx::query("INSERT INTO users(id,username,password_hash,roster_version) VALUES($1,'roster-snapshot','test-only',7)")
        .bind(owner).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,display_name,subscription,groups) VALUES($1,'channel@mix.remote.test','Original','both','[]'::jsonb)")
        .bind(owner).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO mix_pam_memberships(id,user_id,channel_jid,participant_id,state) VALUES($1,$2,'channel@mix.remote.test','original-participant','joined')")
        .bind(Uuid::from_u128(0x573_2202)).bind(owner).execute(&pool).await.unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let service = RosterService::new(PostgresRosterRepository::new(
        pool.clone(),
        SnapshotEffects {
            owner,
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        },
    ));
    let read = tokio::spawn(async move {
        service
            .execute_roster_get(RosterGetCommand {
                owner_id: owner,
                expected_auth_generation: 0,
                requested_version: Some(7),
                annotations_requested: true,
            })
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .expect("roster read did not reach its annotation port");
    let mut mutation = pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET is_disabled=TRUE,auth_generation=1,roster_version=8 WHERE id=$1")
        .bind(owner)
        .execute(&mut *mutation)
        .await
        .unwrap();
    sqlx::query("UPDATE roster_items SET display_name='Replacement' WHERE owner_id=$1")
        .bind(owner)
        .execute(&mut *mutation)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE mix_pam_memberships SET participant_id='replacement-participant' WHERE user_id=$1",
    )
    .bind(owner)
    .execute(&mut *mutation)
    .await
    .unwrap();
    mutation.commit().await.unwrap();
    release.notify_one();
    let RosterAuthorization::Authorized(snapshot) = read.await.unwrap() else {
        panic!("original authorization snapshot was lost");
    };
    assert_eq!(snapshot.version, 7);
    assert_eq!(snapshot.items.len(), 1);
    assert_eq!(snapshot.items[0].version, 7);
    assert_eq!(snapshot.items[0].display_name.as_deref(), Some("Original"));
    assert_eq!(
        snapshot
            .mix_participants
            .get("channel@mix.remote.test")
            .map(String::as_str),
        Some("original-participant")
    );
    assert!(
        snapshot.changes.is_none(),
        "annotated requests always return a complete snapshot"
    );
    let denied = northstar_roster_postgres::roster::roster_read_snapshot(
        &WorkflowRosterEffects,
        &pool,
        owner,
        0,
        None,
        true,
    )
    .await
    .unwrap();
    assert!(
        denied.is_none(),
        "a later read cannot reuse the original authorization"
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(owner)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
