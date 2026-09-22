//! PostgreSQL adapters for account recovery and its isolated poll reader.
use crate::{db, services::omemo_recovery::*};
use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresOmemoRecoveryRepository {
    pool: PgPool,
}
impl PostgresOmemoRecoveryRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    async fn begin_read(
        &self,
        actor: OmemoRecoveryActor<'_>,
    ) -> Result<Option<Transaction<'_, Postgres>>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        if !db::authorize_user_in_tx(
            &mut tx,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(None);
        }
        Ok(Some(tx))
    }
}
impl OmemoRecoveryRepository for PostgresOmemoRecoveryRepository {
    async fn prepare(
        &self,
        request: PrepareOmemoRecoveryRequest<'_>,
    ) -> Result<PrepareOmemoRecovery> {
        db::prepare_omemo_recovery_transfer(&self.pool, request).await
    }
    async fn seal(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
        digest: &[u8; 32],
    ) -> Result<SealOmemoRecovery> {
        db::seal_omemo_recovery_transfer(
            &self.pool,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
            transfer_id,
            digest,
        )
        .await
    }
    async fn consume(
        &self,
        request: ConsumeOmemoRecoveryRequest<'_>,
    ) -> Result<ConsumeOmemoRecovery> {
        db::consume_omemo_recovery_transfer(&self.pool, request).await
    }
    async fn revoke(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
    ) -> Result<RevokeOmemoRecovery> {
        db::revoke_omemo_recovery_transfer(
            &self.pool,
            actor.user_id,
            actor.auth_generation,
            actor.session_token,
            transfer_id,
        )
        .await
    }
    async fn transfer(
        &self,
        actor: OmemoRecoveryActor<'_>,
        transfer_id: Uuid,
    ) -> Result<OmemoRecoveryRead<Option<OmemoRecoveryTransfer>>> {
        let user_id = actor.user_id;
        let Some(mut tx) = self.begin_read(actor).await? else {
            return Ok(OmemoRecoveryRead::Unauthorized);
        };
        let value = db::omemo_recovery_transfer_in_tx(&mut tx, user_id, transfer_id).await?;
        tx.commit().await?;
        Ok(OmemoRecoveryRead::Authorized(value))
    }
    async fn authority(
        &self,
        actor: OmemoRecoveryActor<'_>,
    ) -> Result<OmemoRecoveryRead<OmemoRecoveryAuthority>> {
        let user_id = actor.user_id;
        let Some(mut tx) = self.begin_read(actor).await? else {
            return Ok(OmemoRecoveryRead::Unauthorized);
        };
        let value = db::omemo_recovery_authority_in_tx(&mut tx, user_id).await?;
        tx.commit().await?;
        Ok(OmemoRecoveryRead::Authorized(value))
    }
}

#[derive(Clone)]
pub(crate) struct PostgresOmemoRecoveryPollRepository {
    pool: PgPool,
}
impl PostgresOmemoRecoveryPollRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl OmemoRecoveryPollRepository for PostgresOmemoRecoveryPollRepository {
    async fn poll(
        &self,
        domain: &str,
        transfer_id: Uuid,
        poll_secret: &[u8; 32],
    ) -> Result<Option<OmemoRecoveryPollStatus>> {
        db::poll_omemo_recovery_transfer(&self.pool, domain, transfer_id, poll_secret).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires an isolated PostgreSQL schema"]
    async fn recovery_reads_recheck_owner_generation_and_exact_bearer() {
        let url = std::env::var("TEST_DATABASE_URL").expect("isolated PostgreSQL URL");
        let pool = PgPool::connect(&url).await.unwrap();
        db::migrate(&pool).await.unwrap();
        let owner = Uuid::new_v4();
        let other = Uuid::new_v4();
        for id in [owner, other] {
            sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
                .bind(id)
                .bind(format!("recovery_{}", id.simple()))
                .execute(&pool)
                .await
                .unwrap();
        }
        let token = db::create_api_session(&pool, owner, 1).await.unwrap();
        let other_token = db::create_api_session(&pool, other, 1).await.unwrap();
        let principal = db::user_for_token(&pool, &token).await.unwrap().unwrap();
        let service = OmemoRecoveryService::new(PostgresOmemoRecoveryRepository::new(pool.clone()));
        let actor = || OmemoRecoveryActor {
            user_id: owner,
            auth_generation: principal.auth_generation,
            session_token: &token,
        };
        let transfer_id = Uuid::new_v4();
        let account = format!("{}@localhost", principal.username);
        let prepared = service
            .prepare(PrepareOmemoRecoveryRequest {
                user_id: owner,
                canonical_account: &account,
                expected_auth_generation: principal.auth_generation,
                presented_session: &token,
                transfer_id,
                source_device_id: 7,
                poll_secret: &[3; 32],
            })
            .await
            .unwrap();
        assert!(matches!(prepared, PrepareOmemoRecovery::Prepared(_)));
        assert!(
            matches!(service.transfer(actor(), transfer_id).await.unwrap(),
            OmemoRecoveryRead::Authorized(Some(transfer)) if transfer.id == transfer_id)
        );
        assert!(matches!(service.authority(actor()).await.unwrap(),
            OmemoRecoveryRead::Authorized(authority) if authority.next_generation == 2));
        assert!(matches!(
            service
                .transfer(
                    OmemoRecoveryActor {
                        user_id: other,
                        auth_generation: principal.auth_generation,
                        session_token: &other_token,
                    },
                    transfer_id
                )
                .await
                .unwrap(),
            OmemoRecoveryRead::Authorized(None)
        ));

        for invalid in [
            OmemoRecoveryActor {
                auth_generation: principal.auth_generation + 1,
                ..actor()
            },
            OmemoRecoveryActor {
                session_token: &other_token,
                ..actor()
            },
        ] {
            assert!(matches!(
                service.transfer(invalid, transfer_id).await.unwrap(),
                OmemoRecoveryRead::Unauthorized
            ));
        }
        // The HTTP identity lookup has already succeeded. Revocation before the
        // repository read must still prevent either projection from escaping.
        sqlx::query("DELETE FROM api_sessions WHERE token_hash=$1")
            .bind(crate::auth::token_hash(&token))
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            service.transfer(actor(), transfer_id).await.unwrap(),
            OmemoRecoveryRead::Unauthorized
        ));
        assert!(matches!(
            service.authority(actor()).await.unwrap(),
            OmemoRecoveryRead::Unauthorized
        ));
        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind(&[owner, other][..])
            .execute(&pool)
            .await
            .unwrap();
    }
}
