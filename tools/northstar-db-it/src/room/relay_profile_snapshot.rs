//! Force profile reads to wait after MIX admission while a revocation commits.

use anyhow::Result;
use northstar_room_application::mix_service::{
    MixRelayProfileDenial, MixRelayProfileKind, MixRelayProfileQuery, MixRelayProfileRequester,
    MixRelayProfileResult, MixRepository,
};
use northstar_workflows::room_effects::PostgresMixRepository;
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

const LOCAL_DOMAIN: &str = "example.test";
const LOCAL_CHANNEL: &str = "room@mix.example.test";
const REQUESTER: &str = "requester@example.test";
const REMOTE_SERVICE: &str = "mix.remote.test";
const REMOTE_CHANNEL: &str = "room@mix.remote.test";
const VCARD4: &str = "urn:xmpp:vcard4";
const OLD_CARD: &str = "<vCard xmlns='vcard-temp'><FN>Before</FN></vCard>";
const NEW_CARD: &str = "<vCard xmlns='vcard-temp'><FN>After</FN></vCard>";
const OLD_ITEM: &str = "<item id='old'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'/></item>";
const NEW_ITEM: &str = "<item id='new'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'/></item>";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    url: String,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_profile_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&owner)
            .await?;
        let options = url.parse::<sqlx::postgres::PgConnectOptions>()?.options([
            ("search_path", schema.as_str()),
            ("statement_timeout", "10000"),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?;
        crate::support::migrate(&pool).await?;
        Ok(Self {
            owner,
            pool,
            url,
            schema,
        })
    }

    async fn reader(&self, read_only: bool) -> Result<PgPool> {
        let options = self
            .url
            .parse::<sqlx::postgres::PgConnectOptions>()?
            .options([
                ("search_path", self.schema.as_str()),
                ("statement_timeout", "10000"),
                (
                    "default_transaction_read_only",
                    if read_only { "on" } else { "off" },
                ),
            ]);
        Ok(PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?)
    }

    async fn close(self) -> Result<()> {
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

    async fn wait_for_profile_lock(&self, barrier: &mut Transaction<'_, Postgres>) -> Result<()> {
        let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut **barrier)
            .await?;
        crate::support::blocked_backend(&self.pool, blocker).await;
        Ok(())
    }

    async fn account(&self, username: &str) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test-only')")
            .bind(id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    async fn local_relay(&self) -> Result<(Uuid, MixRelayProfileQuery)> {
        self.account("requester").await?;
        let owner = self.account("target").await?;
        let channel_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO mix_channels (id, service_domain, localpart, creator_jid)
             VALUES ($1, 'mix.example.test', 'room', $2)",
        )
        .bind(channel_id)
        .bind(REQUESTER)
        .execute(&self.pool)
        .await?;
        for (id, jid) in [
            (Uuid::new_v4(), REQUESTER),
            (target_id, "target@example.test"),
        ] {
            sqlx::query(
                "INSERT INTO mix_participant_identities (channel_id, participant_id, jid)
                 VALUES ($1, $2, $3)",
            )
            .bind(channel_id)
            .bind(id)
            .bind(jid)
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "INSERT INTO mix_participants (channel_id, participant_id, jid) VALUES ($1, $2, $3)",
            )
            .bind(channel_id)
            .bind(id)
            .bind(jid)
            .execute(&self.pool)
            .await?;
        }
        sqlx::query(
            "INSERT INTO mix_participant_preferences (channel_id, participant_id, vcard)
             VALUES ($1, $2, 'allow')",
        )
        .bind(channel_id)
        .bind(target_id)
        .execute(&self.pool)
        .await?;
        Ok((
            owner,
            MixRelayProfileQuery {
                channel: CanonicalJid::parse_bare(LOCAL_CHANNEL)?,
                requester: MixRelayProfileRequester::ChannelParticipant {
                    actor: CanonicalJid::parse(&format!("{REQUESTER}/Phone"))?,
                    local_domain: LOCAL_DOMAIN.to_owned(),
                },
                target: CanonicalJid::parse_bare(&format!("{target_id}#{LOCAL_CHANNEL}"))?,
                kind: MixRelayProfileKind::VCardTemp,
            },
        ))
    }

    async fn pam_relay(
        &self,
        username: &str,
        access_model: &str,
    ) -> Result<(Uuid, MixRelayProfileQuery)> {
        let owner = self.account(username).await?;
        sqlx::query(
            "INSERT INTO mix_pam_memberships (id, user_id, channel_jid, participant_id, state)
             VALUES ($1, $2, $3, 'opaque', 'joined')",
        )
        .bind(Uuid::new_v4())
        .bind(owner)
        .bind(REMOTE_CHANNEL)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "INSERT INTO pep_nodes (owner_id, node, access_model, max_items) VALUES ($1, $2, $3, 2)",
        )
        .bind(owner)
        .bind(VCARD4)
        .bind(access_model)
        .execute(&self.pool)
        .await?;
        insert_item(&self.pool, owner, "old", OLD_ITEM, 0).await?;
        Ok((
            owner,
            MixRelayProfileQuery {
                channel: CanonicalJid::parse_bare(REMOTE_CHANNEL)?,
                requester: MixRelayProfileRequester::FederatedPam {
                    authenticated_service: REMOTE_SERVICE.to_owned(),
                },
                target: CanonicalJid::parse_bare(&format!("{username}@{LOCAL_DOMAIN}"))?,
                kind: MixRelayProfileKind::VCard4 { item_id: None },
            },
        ))
    }
}

async fn insert_item<'e>(
    executor: impl sqlx::Executor<'e, Database = Postgres>,
    owner: Uuid,
    id: &str,
    payload: &str,
    revision: i32,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO pep_items (owner_id, node, item_id, payload, updated_at)
         VALUES ($1, $2, $3, $4, TIMESTAMPTZ '2026-01-01 00:00:00Z' + $5::integer * INTERVAL '1 day')",
    )
    .bind(owner)
    .bind(VCARD4)
    .bind(id)
    .bind(payload)
    .bind(revision)
    .execute(executor)
    .await?;
    Ok(())
}

async fn local_block_case(blocked: &str) -> Result<()> {
    let fixture = Fixture::new().await?;
    let result: Result<()> = async {
        let (owner, query) = fixture.local_relay().await?;
        sqlx::query("INSERT INTO vcards (user_id, payload) VALUES ($1, $2)")
            .bind(owner)
            .bind(OLD_CARD)
            .execute(&fixture.pool)
            .await?;
        let reader = PostgresMixRepository::new(fixture.reader(false).await?);
        let mut barrier = fixture.pool.begin().await?;
        sqlx::query("LOCK TABLE vcards IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *barrier)
            .await?;
        let in_flight = tokio::spawn({
            let query = query.clone();
            async move { reader.relay_profile_snapshot(query).await }
        });
        fixture.wait_for_profile_lock(&mut barrier).await?;
        sqlx::query("INSERT INTO blocked_jids (owner_id, blocked_jid) VALUES ($1, $2)")
            .bind(owner)
            .bind(blocked)
            .execute(&mut *barrier)
            .await?;
        sqlx::query("UPDATE vcards SET payload = $2 WHERE user_id = $1")
            .bind(owner)
            .bind(NEW_CARD)
            .execute(&mut *barrier)
            .await?;
        barrier.commit().await?;
        // The split reads used to admit before the block and select NEW_CARD after it.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), in_flight).await???,
            MixRelayProfileResult::VCardTemp(OLD_CARD.to_owned())
        );
        assert_eq!(
            PostgresMixRepository::new(fixture.pool.clone())
                .relay_profile_snapshot(query)
                .await?,
            MixRelayProfileResult::Denied(MixRelayProfileDenial::Forbidden)
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn local_channel_block_does_not_relay_a_new_vcard() -> Result<()> {
    local_block_case(LOCAL_CHANNEL).await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn local_requester_block_does_not_relay_a_new_vcard() -> Result<()> {
    local_block_case(REQUESTER).await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn federated_pam_leave_does_not_relay_a_new_vcard4_item() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result: Result<()> = async {
        let (owner, query) = fixture.pam_relay("target", "open").await?;
        let reader = PostgresMixRepository::new(fixture.reader(false).await?);
        let mut barrier = fixture.pool.begin().await?;
        sqlx::query("LOCK TABLE pep_items IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *barrier)
            .await?;
        let in_flight = tokio::spawn({
            let query = query.clone();
            async move { reader.relay_profile_snapshot(query).await }
        });
        fixture.wait_for_profile_lock(&mut barrier).await?;
        sqlx::query("DELETE FROM mix_pam_memberships WHERE user_id = $1 AND channel_jid = $2")
            .bind(owner)
            .bind(REMOTE_CHANNEL)
            .execute(&fixture.pool)
            .await?;
        insert_item(&mut *barrier, owner, "new", NEW_ITEM, 1).await?;
        barrier.commit().await?;
        // The split reads used to admit the joined PAM and select NEW_ITEM after the leave.
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), in_flight).await???,
            MixRelayProfileResult::VCard4(OLD_ITEM.to_owned())
        );
        assert_eq!(
            PostgresMixRepository::new(fixture.pool.clone())
                .relay_profile_snapshot(query)
                .await?,
            MixRelayProfileResult::Denied(MixRelayProfileDenial::Forbidden)
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn deleted_vcard4_node_is_missing_for_an_authorized_relay() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result: Result<()> = async {
        let (owner, query) = fixture.pam_relay("target", "open").await?;
        let repository = PostgresMixRepository::new(fixture.pool.clone());
        assert_eq!(
            repository.relay_profile_snapshot(query.clone()).await?,
            MixRelayProfileResult::VCard4(OLD_ITEM.to_owned())
        );
        sqlx::query("DELETE FROM pep_nodes WHERE owner_id = $1 AND node = $2")
            .bind(owner)
            .bind(VCARD4)
            .execute(&fixture.pool)
            .await?;
        assert_eq!(
            repository.relay_profile_snapshot(query).await?,
            MixRelayProfileResult::VCard4Missing
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn legacy_non_open_vcard4_relays_latest_or_requested_item() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result: Result<()> = async {
        let (owner, mut query) = fixture.pam_relay("target", "presence").await?;
        insert_item(&fixture.pool, owner, "new", NEW_ITEM, 1).await?;
        let repository = PostgresMixRepository::new(fixture.pool.clone());
        assert_eq!(
            repository.relay_profile_snapshot(query.clone()).await?,
            MixRelayProfileResult::VCard4(NEW_ITEM.to_owned())
        );
        query.kind = MixRelayProfileKind::VCard4 {
            item_id: Some("old".to_owned()),
        };
        assert_eq!(
            repository.relay_profile_snapshot(query.clone()).await?,
            MixRelayProfileResult::VCard4(OLD_ITEM.to_owned())
        );
        query.kind = MixRelayProfileKind::VCard4 {
            item_id: Some("absent".to_owned()),
        };
        assert_eq!(
            repository.relay_profile_snapshot(query).await?,
            MixRelayProfileResult::VCard4Missing
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn relay_profile_snapshots_work_on_a_read_only_connection() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result: Result<()> = async {
        let (_, local_query) = fixture.local_relay().await?;
        let (_, pam_query) = fixture.pam_relay("pam-target", "open").await?;
        let reader = fixture.reader(true).await?;
        let read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
            .fetch_one(&reader)
            .await?;
        assert_eq!(read_only, "on");
        let repository = PostgresMixRepository::new(reader);
        assert_eq!(
            repository.relay_profile_snapshot(local_query).await?,
            MixRelayProfileResult::EmptyCard
        );
        assert_eq!(
            repository.relay_profile_snapshot(pam_query).await?,
            MixRelayProfileResult::VCard4(OLD_ITEM.to_owned())
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}
