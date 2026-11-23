use anyhow::{Context, Result};
use northstar_delivery_core::MixDelivery;
use northstar_room_application::mix_service::MixPayloads;
use northstar_room_core::mix::MixRealJid;
use northstar_room_postgres::mix::*;
use northstar_workflows::room_effects::WorkflowRoomEffects;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::borrow::Cow;
use uuid::Uuid;

const LOCAL: &str = "bound@example.test";
const REMOTE: &str = "bound@remote.test";

pub(super) struct Fixture {
    owner: PgPool,
    pub(super) pool: PgPool,
    schema: String,
}

impl Fixture {
    pub(super) async fn new() -> Result<Self> {
        let fixture = Self::schema().await?;
        crate::support::migrate(&fixture.pool).await?;
        Ok(fixture)
    }

    async fn schema() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_delivery_identity_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&owner)
            .await?;
        let options = url.parse::<sqlx::postgres::PgConnectOptions>()?.options([
            ("search_path", schema.as_str()),
            ("statement_timeout", "10000"),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options)
            .await?;
        Ok(Self {
            owner,
            pool,
            schema,
        })
    }

    pub(super) async fn close(self) -> Result<()> {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.owner)
        .await?;
        self.owner.close().await;
        Ok(())
    }

    pub(super) async fn account(&self) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'bound','test-only')")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    pub(super) async fn enqueue_local(&self) -> Result<Uuid> {
        self.enqueue(LOCAL).await
    }

    async fn enqueue(&self, address: &str) -> Result<Uuid> {
        let (created, _) = create_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            "mix.example.test",
            Some("identity"),
            "creator@remote.test",
            100,
            &MixPayloads,
            None,
        )
        .await?;
        let CreateChannelOutcome::Created(id) = created else {
            anyhow::bail!("fixture channel was not created");
        };
        let channel = mix_channel_by_id(&self.pool, id)
            .await?
            .context("fixture channel")?;
        let (mut transaction, fence) = begin_mix_delivery_admission(&self.pool).await?;
        let projection = enqueue_mix_deliveries_tx_with_facts(
            &mut transaction,
            &fence,
            MixDeliveryProjection {
                channel: &channel,
                event_id: Uuid::new_v4(),
                recipients: &[MixParticipant {
                    participant_id: Uuid::new_v4(),
                    jid: address.into(),
                    nick: None,
                }],
                stanza_template: "<message><control/></message>",
                authoritative_stanza_id: None,
                archive: false,
                encrypted: false,
            },
        )
        .await?
        .context("fixture recipient was not projected")?;
        transaction.commit().await?;
        Ok(projection.recipients[0].delivery_id)
    }

    pub(super) async fn claim(&self, delivery_id: Uuid) -> Result<ClaimedMixDelivery> {
        claim_mix_deliveries(&self.pool, 128, 65_536)
            .await?
            .into_iter()
            .find(|row| row.delivery_id == delivery_id)
            .context("claim missing")
    }

    pub(super) async fn stored_account(&self, delivery_id: Uuid) -> Result<Option<Uuid>> {
        Ok(sqlx::query_scalar(
            "SELECT recipient_local_user_id FROM mix_delivery_recipients WHERE delivery_id=$1",
        )
        .bind(delivery_id)
        .fetch_one(&self.pool)
        .await?)
    }

    async fn assert_unavailable(&self, row: &ClaimedMixDelivery) -> Result<()> {
        assert_eq!(
            claimed_recipient_account(&self.pool, source(row), &MixRealJid::parse(LOCAL)?).await?,
            None
        );
        assert!(
            dead_letter_mix_delivery(
                &self.pool,
                row.delivery_id,
                row.lease_token,
                "account-unavailable",
                "recipient authority unavailable"
            )
            .await?
        );
        assert!(claim_mix_deliveries(&self.pool, 128, 65_536)
            .await?
            .is_empty());
        let reason: String = sqlx::query_scalar(
            "SELECT terminal_reason FROM mix_delivery_dead_letters WHERE delivery_id=$1",
        )
        .bind(row.delivery_id)
        .fetch_one(&self.pool)
        .await?;
        assert_eq!(reason, "account-unavailable");
        Ok(())
    }
}

pub(super) fn source(row: &ClaimedMixDelivery) -> MixDelivery {
    MixDelivery {
        delivery_id: row.delivery_id,
        lease_token: row.lease_token,
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn reassigned_address_does_not_receive_the_old_accounts_delivery() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let original = fixture.account().await?;
        let id = fixture.enqueue_local().await?;
        let row = fixture.claim(id).await?;
        let address = MixRealJid::parse(LOCAL)?;
        assert_eq!(
            claimed_recipient_account(&fixture.pool, source(&row), &address).await?,
            Some(original)
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(original)
            .execute(&fixture.pool)
            .await?;
        assert_ne!(fixture.account().await?, original);
        assert_eq!(fixture.stored_account(id).await?, Some(original));
        fixture.assert_unavailable(&row).await
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn disabled_recipient_is_settled_without_delivery() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let account = fixture.account().await?;
        let id = fixture.enqueue_local().await?;
        let row = fixture.claim(id).await?;
        sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
            .bind(account)
            .execute(&fixture.pool)
            .await?;
        assert_eq!(fixture.stored_account(id).await?, Some(account));
        fixture.assert_unavailable(&row).await
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn legacy_row_without_account_is_not_delivered_to_a_new_account() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let (_, id) =
            super::mix_delivery_route_wake::insert_delivery(&fixture.pool, LOCAL, 1).await;
        fixture.account().await?;
        assert_eq!(fixture.stored_account(id).await?, None);
        fixture.assert_unavailable(&fixture.claim(id).await?).await
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn remote_recipient_rows_keep_address_delivery() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        fixture.account().await?;
        let id = fixture.enqueue(REMOTE).await?;
        let row = fixture.claim(id).await?;
        assert_eq!(fixture.stored_account(id).await?, None);
        assert_eq!(row.recipient.jid, REMOTE);
        assert!(acknowledge_mix_delivery(&fixture.pool, id, row.lease_token).await?);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn migration_backfills_existing_local_recipients() -> Result<()> {
    let fixture = Fixture::schema().await?;
    let result = async {
        let predecessor = sqlx::migrate::Migrator {
            migrations: Cow::Owned(
                northstar_postgres::MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 163)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        predecessor.run(&fixture.pool).await?;
        let account = fixture.account().await?;
        let (_, local) =
            super::mix_delivery_route_wake::insert_delivery(&fixture.pool, LOCAL, 1).await;
        let (_, remote) =
            super::mix_delivery_route_wake::insert_delivery(&fixture.pool, REMOTE, 1).await;
        let (_, missing) = super::mix_delivery_route_wake::insert_delivery(
            &fixture.pool,
            "missing@example.test",
            1,
        )
        .await;
        crate::support::migrate(&fixture.pool).await?;
        assert_eq!(fixture.stored_account(local).await?, Some(account));
        assert_eq!(fixture.stored_account(remote).await?, None);
        assert_eq!(fixture.stored_account(missing).await?, None);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}
