//! PostgreSQL adapter for committed local direct-spool revision wakes.

use crate::{
    cluster::ClusterReadinessAuthority,
    services::direct_spool_wake::{
        ClaimedDirectSpoolWake, DirectSpoolWakeRepository, DirectSpoolWakeRoute,
    },
};
use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresDirectSpoolWakeRepository {
    pool: PgPool,
}

impl PostgresDirectSpoolWakeRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// The caller holds the shared node-claim advisory lock from transaction
/// start. This write shares the message's commit or rollback fate.
pub(crate) async fn record_direct_spool_wake_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    domain: &str,
    recipient_id: Uuid,
) -> Result<()> {
    let _: i64 = sqlx::query_scalar("SELECT northstar_record_direct_spool_wake($1,$2)")
        .bind(domain)
        .bind(recipient_id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(())
}

impl DirectSpoolWakeRepository for PostgresDirectSpoolWakeRepository {
    async fn cleanup(&self, limit: i32) -> Result<i64> {
        ensure!(
            (1..=256).contains(&limit),
            "invalid direct spool wake cleanup page"
        );
        Ok(
            sqlx::query_scalar("SELECT northstar_cleanup_direct_spool_wakes($1)")
                .bind(limit)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    async fn claim(
        &self,
        authority: &ClusterReadinessAuthority,
        limit: i32,
    ) -> Result<Vec<ClaimedDirectSpoolWake>> {
        ensure!(
            (1..=256).contains(&limit),
            "invalid direct spool wake claim page"
        );
        let rows: Vec<(Uuid, Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT recipient_id,revision,claim_token,replay_cutoff FROM northstar_claim_direct_spool_wakes($1,$2,$3,$4,$5)",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.instance_node_id)
        .bind(authority.instance_uuid)
        .bind(authority.instance_epoch)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(recipient_id, revision, claim_token, cutoff)| ClaimedDirectSpoolWake {
                    recipient_id,
                    revision,
                    claim_token,
                    cutoff,
                },
            )
            .collect())
    }

    async fn routes_page(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        after: Option<&str>,
        limit: i32,
    ) -> Result<Vec<DirectSpoolWakeRoute>> {
        ensure!(
            (1..=256).contains(&limit),
            "invalid direct spool route page"
        );
        let rows: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT full_jid,connection_id FROM northstar_direct_spool_routes_page($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.instance_node_id)
        .bind(authority.instance_uuid)
        .bind(authority.instance_epoch)
        .bind(recipient_id)
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(full_jid, connection_id)| DirectSpoolWakeRoute {
                full_jid,
                connection_id,
            })
            .collect())
    }

    async fn acknowledge_if_empty(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        revision: Uuid,
        claim_token: Uuid,
    ) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT northstar_ack_direct_spool_wake_if_empty($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&authority.key_identity.xmpp_domain)
        .bind(&authority.instance_node_id)
        .bind(authority.instance_uuid)
        .bind(authority.instance_epoch)
        .bind(recipient_id)
        .bind(revision)
        .bind(claim_token)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn defer(
        &self,
        authority: &ClusterReadinessAuthority,
        recipient_id: Uuid,
        revision: Uuid,
        claim_token: Uuid,
        delay: Duration,
    ) -> Result<bool> {
        ensure!(
            (1..=300).contains(&delay.as_secs()) && delay.subsec_nanos() == 0,
            "invalid direct spool wake retry delay"
        );
        Ok(
            sqlx::query_scalar("SELECT northstar_defer_direct_spool_wake($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(&authority.key_identity.xmpp_domain)
                .bind(&authority.instance_node_id)
                .bind(authority.instance_uuid)
                .bind(authority.instance_epoch)
                .bind(recipient_id)
                .bind(revision)
                .bind(claim_token)
                .bind(delay.as_secs() as i32)
                .fetch_one(&self.pool)
                .await?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::cluster_keys::{
        claim_cluster_node_instance, reconcile_cluster_key_deployment_before_instance_claim,
        release_cluster_node_instance, ClusterKeyDeploymentIdentity, CLUSTER_KEY_AUTHORITY_LOCK,
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires disposable TEST_DATABASE_URL; migrates and removes an isolated schema"]
    async fn direct_spool_wake_commit_ack_takeover_and_cleanup_are_fenced() {
        let url = std::env::var("TEST_DATABASE_URL").expect("set disposable TEST_DATABASE_URL");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("direct_spool_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        eprintln!("isolated_schema_created={schema}");
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {connection_schema}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let domain = format!("wake-{suffix}.test");
        let node = format!("node-{suffix}");
        let key = ClusterKeyDeploymentIdentity {
            xmpp_domain: domain.clone(),
            node_id: node.clone(),
            epoch: 1,
            current_key_id: "AAAAAAAAAAAAAAAA".into(),
            current_public_key_sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            previous_key_id: None,
            previous_public_key_sha256: None,
            staged_next_key_id: None,
            staged_next_public_key_sha256: None,
        };
        reconcile_cluster_key_deployment_before_instance_claim(&pool, &key)
            .await
            .unwrap();
        let instance_uuid = Uuid::new_v4();
        let instance = claim_cluster_node_instance(
            &pool,
            &domain,
            &node,
            instance_uuid,
            &key.current_key_id,
            1,
            Duration::from_secs(90),
        )
        .await
        .unwrap();
        let authority = ClusterReadinessAuthority {
            key_identity: key,
            instance_node_id: node.clone(),
            instance_uuid,
            instance_epoch: instance.instance_epoch,
            signing_key_id: "AAAAAAAAAAAAAAAA".into(),
            signing_key_epoch: 1,
        };
        let recipient_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
            .bind(recipient_id)
            .bind(format!("recipient-{}", &suffix[..8]))
            .execute(&pool)
            .await
            .unwrap();
        let repository = PostgresDirectSpoolWakeRepository::new(pool.clone());

        // An offline row and its wake share a transaction's rollback fate.
        let mut rolled_back = pool.begin().await.unwrap();
        crate::db::cluster_keys::lock_direct_spool_instance_claims_in_transaction(&mut rolled_back)
            .await
            .unwrap();
        sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted) VALUES($1,$2,'sender@test','<message/>',FALSE)")
            .bind(Uuid::new_v4())
            .bind(recipient_id)
            .execute(&mut *rolled_back)
            .await
            .unwrap();
        record_direct_spool_wake_in_transaction(&mut rolled_back, &domain, recipient_id)
            .await
            .unwrap();
        rolled_back.rollback().await.unwrap();
        assert!(repository.claim(&authority, 1).await.unwrap().is_empty());
        let offline_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM offline_messages WHERE recipient_id=$1")
                .bind(recipient_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(offline_count, 0);

        let mut listener = sqlx::postgres::PgListener::connect(&url).await.unwrap();
        listener
            .listen("northstar_direct_spool_wake_v1")
            .await
            .unwrap();
        let mut committed = pool.begin().await.unwrap();
        crate::db::cluster_keys::lock_direct_spool_instance_claims_in_transaction(&mut committed)
            .await
            .unwrap();
        sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted) VALUES($1,$2,'sender@test','<message/>',FALSE)")
            .bind(Uuid::new_v4())
            .bind(recipient_id)
            .execute(&mut *committed)
            .await
            .unwrap();
        record_direct_spool_wake_in_transaction(&mut committed, &domain, recipient_id)
            .await
            .unwrap();
        committed.commit().await.unwrap();
        let notification = tokio::time::timeout(Duration::from_secs(5), listener.recv())
            .await
            .expect("committed direct spool wake notification timed out")
            .unwrap();
        assert_eq!(notification.channel(), "northstar_direct_spool_wake_v1");
        assert_eq!(notification.payload(), schema);
        let first = repository.claim(&authority, 1).await.unwrap().remove(0);
        assert!(!repository
            .acknowledge_if_empty(&authority, recipient_id, first.revision, first.claim_token)
            .await
            .unwrap());

        // A producer that updates the stable row before an old ACK makes the
        // old revision ineligible, even after all offline rows are drained.
        sqlx::query("DELETE FROM offline_messages WHERE recipient_id=$1")
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut second = pool.begin().await.unwrap();
        crate::db::cluster_keys::lock_direct_spool_instance_claims_in_transaction(&mut second)
            .await
            .unwrap();
        record_direct_spool_wake_in_transaction(&mut second, &domain, recipient_id)
            .await
            .unwrap();
        let ack_repository = repository.clone();
        let ack_authority = authority.clone();
        let first_revision = first.revision;
        let first_claim_token = first.claim_token;
        let old_ack = tokio::spawn(async move {
            ack_repository
                .acknowledge_if_empty(
                    &ack_authority,
                    recipient_id,
                    first_revision,
                    first_claim_token,
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!old_ack.is_finished());
        second.commit().await.unwrap();
        assert!(!old_ack.await.unwrap().unwrap());

        // Stable node key survives exact instance replacement; the new epoch
        // can claim the still-pending newer revision.
        assert!(release_cluster_node_instance(
            &pool,
            &domain,
            &node,
            instance_uuid,
            instance.instance_epoch,
            "AAAAAAAAAAAAAAAA",
            1,
        )
        .await
        .unwrap());
        let replacement_uuid = Uuid::new_v4();
        let replacement = claim_cluster_node_instance(
            &pool,
            &domain,
            &node,
            replacement_uuid,
            "AAAAAAAAAAAAAAAA",
            1,
            Duration::from_secs(90),
        )
        .await
        .unwrap();
        let replacement_authority = ClusterReadinessAuthority {
            instance_uuid: replacement_uuid,
            instance_epoch: replacement.instance_epoch,
            ..authority
        };
        let latest = repository
            .claim(&replacement_authority, 1)
            .await
            .unwrap()
            .remove(0);
        assert_ne!(latest.revision, first_revision);
        assert!(repository
            .acknowledge_if_empty(
                &replacement_authority,
                recipient_id,
                latest.revision,
                latest.claim_token,
            )
            .await
            .unwrap());

        // A replacement claim holding the exclusive advisory gate prevents
        // stale-row cleanup from deleting a wake on its newly live node.
        let mut expired = pool.begin().await.unwrap();
        crate::db::cluster_keys::lock_direct_spool_instance_claims_in_transaction(&mut expired)
            .await
            .unwrap();
        record_direct_spool_wake_in_transaction(&mut expired, &domain, recipient_id)
            .await
            .unwrap();
        expired.commit().await.unwrap();
        sqlx::query("UPDATE direct_spool_wake_outbox SET updated_at=clock_timestamp()-INTERVAL '8 days' WHERE recipient_id=$1")
            .bind(recipient_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE cluster_node_instances SET lease_until=clock_timestamp()-INTERVAL '8 days' WHERE xmpp_domain=$1 AND node_id=$2")
            .bind(&domain)
            .bind(&node)
            .execute(&pool)
            .await
            .unwrap();
        let mut claim_turn = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CLUSTER_KEY_AUTHORITY_LOCK)
            .execute(&mut *claim_turn)
            .await
            .unwrap();
        sqlx::query("UPDATE cluster_node_instances SET lease_until=clock_timestamp()+INTERVAL '90 seconds' WHERE xmpp_domain=$1 AND node_id=$2")
            .bind(&domain)
            .bind(&node)
            .execute(&mut *claim_turn)
            .await
            .unwrap();
        let cleanup_repository = repository.clone();
        let cleanup = tokio::spawn(async move { cleanup_repository.cleanup(1).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!cleanup.is_finished());
        claim_turn.commit().await.unwrap();
        assert_eq!(cleanup.await.unwrap().unwrap(), 0);

        // A bounded 257th live node fails the message transaction instead of
        // allowing unbounded per-message fanout.
        sqlx::query(
            "INSERT INTO cluster_key_deployments
               (xmpp_domain,node_id,epoch,current_key_id,current_public_key_sha256)
             SELECT $1,'extra-'||n,1,'AAAAAAAAAAAAAAAA',
                    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
               FROM generate_series(1,256) AS n",
        )
        .bind(&domain)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO cluster_node_instances
               (xmpp_domain,node_id,instance_uuid,instance_epoch,
                signing_key_id,signing_key_epoch,lease_until)
             SELECT $1,'extra-'||n,pg_catalog.gen_random_uuid(),1,
                    'AAAAAAAAAAAAAAAA',1,clock_timestamp()+INTERVAL '90 seconds'
               FROM generate_series(1,256) AS n",
        )
        .bind(&domain)
        .execute(&pool)
        .await
        .unwrap();
        let mut over_capacity = pool.begin().await.unwrap();
        crate::db::cluster_keys::lock_direct_spool_instance_claims_in_transaction(
            &mut over_capacity,
        )
        .await
        .unwrap();
        assert!(
            record_direct_spool_wake_in_transaction(&mut over_capacity, &domain, recipient_id,)
                .await
                .is_err()
        );
        over_capacity.rollback().await.unwrap();

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }
}
