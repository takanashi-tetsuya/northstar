use anyhow::{ensure, Result};
use northstar_abuse_application::guard::{
    test_mix_message_content_keyring, test_mix_retraction_content_keyring,
};
use northstar_room_application::mix_muc::link_created_mix;
use northstar_room_application::mix_service::{
    CreateChannelOutcome, HostedDiscoView, JoinChannelOutcome, JoinMixRequest,
    MixHostedDiscoRepository, MixMucLinkOutcome, MixService, NODE_MESSAGES,
};
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixRealJid, MixRole};
use northstar_room_postgres::muc::get_or_create_muc_room;
use northstar_workflows::room_effects::PostgresMixRepository;
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const DOMAIN: &str = "example.test";
const SERVICE: &str = "mix.example.test";
const OWNER: &str = "owner@example.test";
const VISITOR: &str = "visitor@example.test";
const ROOM: &str = "mirror";
const HOLD_READ_GATE: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended(current_schema()::text, 711))";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_discovery_{}", Uuid::new_v4().simple());
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
        crate::support::migrate(&pool).await?;
        Ok(Self {
            owner,
            pool,
            schema,
        })
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

    fn service(&self) -> Result<MixService<PostgresMixRepository>> {
        MixService::new(
            PostgresMixRepository::new(self.pool.clone()),
            test_mix_message_content_keyring(),
            test_mix_retraction_content_keyring(),
            3,
            self.schema.clone(),
        )
    }

    async fn channel(&self, localpart: Option<&str>) -> Result<(MixChannelId, MixChannelAddress)> {
        let (created, localpart) = self
            .service()?
            .create_mix_channel(SERVICE, localpart, OWNER, 100, None)
            .await?;
        let CreateChannelOutcome::Created(channel_id) = created else {
            anyhow::bail!("fixture channel was not created");
        };
        Ok((
            MixChannelId::new(channel_id),
            MixChannelAddress::parse(&format!("{localpart}@{SERVICE}"))?,
        ))
    }

    async fn muc(&self) -> Result<Uuid> {
        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, username, password_hash, is_admin) VALUES ($1, 'owner', 'test-only', FALSE)")
            .bind(owner_id)
            .execute(&self.pool)
            .await?;
        let (room, created) =
            get_or_create_muc_room(&self.pool, ROOM, owner_id, "owner@example.test/pc").await?;
        ensure!(created);
        Ok(room.id)
    }

    async fn read_gate(&self) -> Result<()> {
        sqlx::query("ALTER TABLE mix_channels RENAME TO test_channels")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE FUNCTION test_hold_disco() RETURNS boolean LANGUAGE sql VOLATILE AS
             $$ SELECT true FROM pg_advisory_xact_lock(hashtextextended(current_schema()::text, 711)) $$",
        ).execute(&self.pool).await?;
        sqlx::query(
            "CREATE VIEW mix_channels AS SELECT * FROM test_channels WHERE test_hold_disco()",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

async fn disco(
    repository: &PostgresMixRepository,
    address: &MixChannelAddress,
    actor: &CanonicalJid,
) -> Result<Option<HostedDiscoView>> {
    repository.hosted_disco(address, actor).await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn disco_projection_is_one_snapshot_under_config_change() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (channel_id, address) = fixture.channel(Some(ROOM)).await?;
    let muc_room_id = fixture.muc().await?;
    let actor = CanonicalJid::parse_bare(OWNER)?;
    let repository = PostgresMixRepository::new(fixture.pool.clone());
    fixture.read_gate().await?;

    let mut writer = fixture.pool.begin().await?;
    let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    sqlx::query(HOLD_READ_GATE).execute(&mut *writer).await?;
    let pending = {
        let (repository, address, actor) = (repository.clone(), address.clone(), actor.clone());
        tokio::spawn(async move { disco(&repository, &address, &actor).await })
    };
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query("UPDATE test_channels SET name = 'Updated', allow_private_messages = NOT allow_private_messages, revision = revision + 1 WHERE id = $1")
        .bind(channel_id.as_uuid()).execute(&mut *writer).await?;
    sqlx::query(
        "INSERT INTO mix_muc_mirrors (mix_channel_id, muc_room_id, created_by) VALUES ($1, $2, $3)",
    )
    .bind(channel_id.as_uuid())
    .bind(muc_room_id)
    .bind(OWNER)
    .execute(&mut *writer)
    .await?;
    writer.commit().await?;

    let old = pending.await??.expect("old projection");
    let new = disco(&repository, &address, &actor)
        .await?
        .expect("new projection");
    assert_eq!(old.channel_id, channel_id);
    assert_eq!(old.address, address);
    assert_eq!(old.name, None);
    assert_eq!(old.muc_room_id, None);
    assert_eq!(new.name.as_deref(), Some("Updated"));
    assert_eq!(new.muc_room_id, Some(muc_room_id));
    assert_ne!(old.allow_private_messages, new.allow_private_messages);
    assert_eq!(new.revision, old.revision + 1);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn role_promotion_paired_with_visibility_change_is_one_snapshot() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (channel_id, address) = fixture.channel(Some(ROOM)).await?;
    let actor = CanonicalJid::parse_bare(VISITOR)?;
    let repository = PostgresMixRepository::new(fixture.pool.clone());
    fixture.read_gate().await?;

    let mut writer = fixture.pool.begin().await?;
    let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    sqlx::query(HOLD_READ_GATE).execute(&mut *writer).await?;
    let pending = {
        let (repository, address, actor) = (repository.clone(), address.clone(), actor.clone());
        tokio::spawn(async move { disco(&repository, &address, &actor).await })
    };
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query("UPDATE test_channels SET discoverable = FALSE WHERE id = $1")
        .bind(channel_id.as_uuid())
        .execute(&mut *writer)
        .await?;
    sqlx::query(
        "INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'administrator')",
    )
    .bind(channel_id.as_uuid())
    .bind(VISITOR)
    .execute(&mut *writer)
    .await?;
    writer.commit().await?;

    let old = pending.await??.expect("old projection");
    let new = disco(&repository, &address, &actor)
        .await?
        .expect("new projection");
    assert_eq!(
        (old.discoverable, old.visible_to_actor, old.actor_role),
        (true, true, None)
    );
    assert_eq!(
        (new.discoverable, new.visible_to_actor, new.actor_role),
        (false, true, Some(MixRole::Administrator))
    );
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn hidden_and_absent_channels_answer_alike() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (channel_id, address) = fixture.channel(None).await?;
    let service = fixture.service()?;
    let visitor = CanonicalJid::parse_bare(VISITOR)?;
    let owner = CanonicalJid::parse_bare(OWNER)?;
    let hidden = service.hosted_disco(&address, &visitor).await?;
    assert!(hidden
        .as_ref()
        .is_some_and(|view| view.actor_admitted && !view.visible_to_actor));
    let missing = MixChannelAddress::parse(&format!("missing@{SERVICE}"))?;
    let absent = service.hosted_disco(&missing, &visitor).await?;
    assert!(absent.is_none());
    assert_eq!(hidden.filter(|view| view.visible_to_actor), absent);

    assert!(service
        .hosted_disco(&address, &owner)
        .await?
        .is_some_and(|view| view.visible_to_actor));
    let joined = service
        .join_mix_channel(
            channel_id.as_uuid(),
            JoinMixRequest {
                actor_jid: VISITOR.to_owned(),
                nick: Some("Visitor".to_owned()),
                nodes: vec![NODE_MESSAGES.to_owned()],
                pam_user_id: None,
                invitation: None,
                preference: None,
                anonymous_profile: false,
            },
            None,
        )
        .await?;
    assert!(matches!(joined, JoinChannelOutcome::Joined { .. }));
    assert!(service
        .hosted_disco(&address, &visitor)
        .await?
        .is_some_and(|view| view.visible_to_actor && view.actor_role.is_none()));
    sqlx::query("INSERT INTO mix_banned (channel_id, jid_pattern, added_by) VALUES ($1, $2, $2), ($1, $3, $2)")
        .bind(channel_id.as_uuid()).bind(OWNER).bind(VISITOR).execute(&fixture.pool).await?;
    let owner_view = service.hosted_disco(&address, &owner).await?.unwrap();
    assert!(owner_view.visible_to_actor && owner_view.actor_admitted);
    assert_eq!(owner_view.actor_role, Some(MixRole::Owner));
    let visitor_view = service.hosted_disco(&address, &visitor).await?.unwrap();
    assert!(!visitor_view.visible_to_actor && !visitor_view.actor_admitted);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn link_error_after_create_keeps_the_create_success() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.muc().await?;
    sqlx::query("CREATE FUNCTION test_fail_link() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test link failure'; END; $$")
        .execute(&fixture.pool).await?;
    sqlx::query("CREATE TRIGGER test_fail_link BEFORE INSERT ON mix_muc_mirrors FOR EACH ROW EXECUTE FUNCTION test_fail_link()")
        .execute(&fixture.pool).await?;
    let (channel_id, address) = fixture.channel(Some(ROOM)).await?;
    let owner = MixRealJid::parse(OWNER)?;
    let repository = PostgresMixRepository::new(fixture.pool.clone());
    let error = repository
        .link_created_mix(&channel_id, &owner, DOMAIN)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("test link failure"));

    let service = fixture.service()?;
    link_created_mix(&service, &channel_id, &owner, DOMAIN).await;
    let committed = service
        .hosted_disco(&address, &CanonicalJid::parse_bare(OWNER)?)
        .await?
        .unwrap();
    assert_eq!(committed.channel_id, channel_id);
    assert_eq!(committed.muc_room_id, None);
    fixture.close().await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn recreated_localpart_is_not_linked_by_a_waiting_link() -> Result<()> {
    let fixture = Fixture::new().await?;
    let (channel_id, address) = fixture.channel(Some(ROOM)).await?;
    let muc_room_id = fixture.muc().await?;
    let owner = MixRealJid::parse(OWNER)?;
    let repository = PostgresMixRepository::new(fixture.pool.clone());
    let mut writer = fixture.pool.begin().await?;
    let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await?;
    sqlx::query("LOCK TABLE mix_channels IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *writer)
        .await?;
    let pending = {
        let (repository, channel_id, owner) =
            (repository.clone(), channel_id.clone(), owner.clone());
        tokio::spawn(async move {
            repository
                .link_created_mix(&channel_id, &owner, DOMAIN)
                .await
        })
    };
    crate::support::blocked_backend(&fixture.pool, blocker).await;
    sqlx::query("DELETE FROM mix_channels WHERE id = $1")
        .bind(channel_id.as_uuid())
        .execute(&mut *writer)
        .await?;
    let replacement_id = MixChannelId::new(Uuid::new_v4());
    sqlx::query("INSERT INTO mix_channels (id, service_domain, localpart, creator_jid, discoverable) VALUES ($1, $2, $3, $4, TRUE)")
        .bind(replacement_id.as_uuid()).bind(SERVICE).bind(ROOM).bind(OWNER).execute(&mut *writer).await?;
    sqlx::query("INSERT INTO mix_channel_roles (channel_id, jid, role) VALUES ($1, $2, 'owner')")
        .bind(replacement_id.as_uuid())
        .bind(OWNER)
        .execute(&mut *writer)
        .await?;
    writer.commit().await?;

    assert_eq!(pending.await??, MixMucLinkOutcome::MissingCounterpart);
    assert_eq!(
        repository
            .link_created_mix(&channel_id, &owner, DOMAIN)
            .await?,
        MixMucLinkOutcome::MissingCounterpart
    );
    let actor = CanonicalJid::parse_bare(OWNER)?;
    let replacement = disco(&repository, &address, &actor).await?.unwrap();
    assert_eq!(replacement.channel_id, replacement_id);
    assert_eq!(replacement.muc_room_id, None);
    assert_eq!(
        repository
            .link_created_mix(&replacement_id, &owner, DOMAIN)
            .await?,
        MixMucLinkOutcome::Linked
    );
    assert_eq!(
        disco(&repository, &address, &actor)
            .await?
            .unwrap()
            .muc_room_id,
        Some(muc_room_id)
    );
    fixture.close().await
}
