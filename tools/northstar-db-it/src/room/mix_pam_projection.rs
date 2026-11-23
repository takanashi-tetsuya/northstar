use anyhow::Result;
use northstar_abuse_application::guard::{
    test_mix_message_content_keyring, test_mix_retraction_content_keyring,
};
use northstar_room_application::mix_service::{
    CommittedMixChange, HostedMixOutcome, HostedMixRefusal, JoinChannelOutcome, JoinMixRequest,
    MixAccessEntryOperation, MixAccessList, MixPayloads, MixService,
};
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixParticipantId, MixRealJid};
use northstar_room_postgres::mix as db;
use northstar_workflows::room_effects::{PostgresMixRepository, WorkflowRoomEffects};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const OWNER: &str = "creator@projection.test";
const SERVICE: &str = "mix.projection.test";
const LOCALPART: &str = "room";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_pam_projection_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&owner)
            .await?;
        let options = url.parse::<sqlx::postgres::PgConnectOptions>()?.options([
            ("search_path", schema.as_str()),
            ("statement_timeout", "10000"),
        ]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
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
            4,
            self.schema.clone(),
        )
    }

    async fn channel(&self) -> Result<MixChannelId> {
        let (outcome, _) = db::create_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            SERVICE,
            Some(LOCALPART),
            OWNER,
            100,
            &MixPayloads,
            None,
        )
        .await?;
        let db::CreateChannelOutcome::Created(id) = outcome else {
            anyhow::bail!("projection fixture channel was not created");
        };
        Ok(MixChannelId::new(id))
    }

    async fn user(&self, name: &str) -> Result<(Uuid, i64, MixRealJid)> {
        let user = northstar_auth_postgres::users::create_user(
            &self.pool,
            name,
            "projection-fixture-password",
            false,
            false,
            4096,
            false,
        )
        .await?;
        Ok((
            user.id,
            user.auth_generation,
            MixRealJid::parse(&format!("{name}@projection.test"))?,
        ))
    }
}

fn address() -> Result<MixChannelAddress> {
    MixChannelAddress::parse(&format!("{LOCALPART}@{SERVICE}"))
}

async fn join(
    service: &MixService<PostgresMixRepository>,
    channel: &MixChannelId,
    actor: &MixRealJid,
    user: Option<Uuid>,
) -> Result<CommittedMixChange<JoinChannelOutcome>> {
    present(
        service
            .join_hosted_mix_committed(channel, join_request(actor, user), None)
            .await?,
    )
}

fn join_request(actor: &MixRealJid, user: Option<Uuid>) -> JoinMixRequest {
    JoinMixRequest {
        actor_jid: actor.to_string(),
        nick: actor
            .as_str()
            .split_once('@')
            .map(|(name, _)| name.to_owned()),
        nodes: vec![db::NODE_MESSAGES.to_owned()],
        pam_user_id: user,
        invitation: None,
        preference: None,
        anonymous_profile: false,
    }
}

fn present<T>(outcome: HostedMixOutcome<T>) -> Result<T> {
    match outcome {
        HostedMixOutcome::Present(value) => Ok(value),
        HostedMixOutcome::MissingChannel => anyhow::bail!("fixture channel unexpectedly missing"),
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn local_pam_join_then_core_subscribe_keeps_one_subscription_set() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let channel = fixture.channel().await?;
        let (user, _, actor) = fixture.user("member").await?;
        let service = fixture.service()?;
        assert_eq!(
            join(&service, &channel, &actor, Some(user))
                .await?
                .roster
                .len(),
            1
        );
        let updated = service
            .update_mix_subscriptions(
                channel.as_uuid(),
                actor.as_str(),
                &[db::NODE_PRESENCE.to_owned()],
                &[db::NODE_MESSAGES.to_owned()],
                None,
            )
            .await?
            .expect("joined participant");
        assert_eq!(updated.subscriptions, [db::NODE_PRESENCE]);
        let pam = db::pam_membership(&fixture.pool, user, address()?.as_str())
            .await?
            .expect("PAM membership");
        assert_eq!(pam.subscriptions, updated.subscriptions);
        assert!(matches!(
            join(&service, &channel, &actor, None).await?.outcome,
            JoinChannelOutcome::Joined { .. }
        ));
        assert_eq!(
            join(&service, &channel, &actor, Some(user))
                .await?
                .roster
                .len(),
            1
        );
        let pam = db::pam_membership(&fixture.pool, user, address()?.as_str())
            .await?
            .expect("PAM membership");
        assert_eq!(pam.subscriptions, [db::NODE_MESSAGES, db::NODE_PRESENCE]);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn direct_core_leave_removes_pam_and_roster_projection() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let channel = fixture.channel().await?;
        let (user, _, actor) = fixture.user("member").await?;
        let service = fixture.service()?;
        let joined = join(&service, &channel, &actor, Some(user)).await?;
        let left = present(
            service
                .leave_mix_channel_committed(&channel, &actor, None, None)
                .await?,
        )?;
        assert!(left.outcome.is_some());
        assert_eq!(left.roster.len(), 1);
        assert_eq!(left.roster[0].account.id, user);
        assert_eq!(left.roster[0].version, joined.roster[0].version + 1);
        assert!(left.roster[0].change.removed);
        assert!(db::pam_membership(&fixture.pool, user, address()?.as_str())
            .await?
            .is_none());
        let roster_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM roster_items WHERE owner_id=$1 AND contact_jid=$2)",
        )
        .bind(user)
        .bind(address()?.as_str())
        .fetch_one(&fixture.pool)
        .await?;
        assert!(!roster_exists);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn repeated_pam_cleanup_is_idempotent() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let channel = fixture.channel().await?;
        let (user, _, actor) = fixture.user("member").await?;
        let service = fixture.service()?;
        join(&service, &channel, &actor, Some(user)).await?;
        sqlx::query("DELETE FROM mix_participants WHERE channel_id=$1 AND jid=$2")
            .bind(channel.as_uuid())
            .bind(actor.as_str())
            .execute(&fixture.pool)
            .await?;
        let first = present(
            service
                .leave_mix_channel_committed(&channel, &actor, Some(user), None)
                .await?,
        )?;
        assert_eq!(first.roster.len(), 1);
        assert!(first.roster[0].change.removed);
        let again = present(
            service
                .leave_mix_channel_committed(&channel, &actor, Some(user), None)
                .await?,
        )?;
        assert!(again.outcome.is_none());
        assert!(again.roster.is_empty());
        let version: i64 = sqlx::query_scalar("SELECT roster_version FROM users WHERE id=$1")
            .bind(user)
            .fetch_one(&fixture.pool)
            .await?;
        assert_eq!(version, first.roster[0].version);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn destroy_racing_join_returns_a_removal_for_every_committed_member() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let channel = fixture.channel().await?;
        let (first, _, first_actor) = fixture.user("first").await?;
        let (second, _, second_actor) = fixture.user("second").await?;
        let first_joined = join(&fixture.service()?, &channel, &first_actor, Some(first)).await?;
        assert_eq!(
            sqlx::query("DELETE FROM roster_items WHERE owner_id=$1 AND contact_jid=$2")
                .bind(first)
                .bind(address()?.as_str())
                .execute(&fixture.pool)
                .await?
                .rows_affected(),
            1
        );
        let mut lock = fixture.pool.begin().await?;
        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await?;
        sqlx::query("SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])")
            .bind(second)
            .fetch_one(&mut *lock)
            .await?;
        let join_service = fixture.service()?;
        let join_channel = channel.clone();
        let joining = tokio::spawn(async move {
            join(&join_service, &join_channel, &second_actor, Some(second)).await
        });
        let join_pid = crate::support::blocked_backend(&fixture.pool, blocker).await;
        assert_eq!(
            db::local_pam_users_for_channel(&fixture.pool, address()?.as_str()).await?,
            [first]
        );
        let destroy_service = fixture.service()?;
        let destroying = tokio::spawn(async move {
            destroy_service
                .destroy_mix_channel_committed(&channel, &MixRealJid::parse(OWNER)?, None)
                .await
        });
        crate::support::blocked_backend(&fixture.pool, join_pid).await;
        lock.commit().await?;
        let second_joined = joining.await??;
        assert_eq!(second_joined.roster.len(), 1);
        let destroyed = present(destroying.await??)?;
        assert!(destroyed.outcome);
        let mut removed = destroyed
            .roster
            .iter()
            .map(|delta| {
                assert!(delta.change.removed && delta.participant_annotation.is_none());
                let joined = if delta.account.id == first {
                    &first_joined
                } else {
                    &second_joined
                };
                assert_eq!(delta.version, joined.roster[0].version + 1);
                delta.account.id
            })
            .collect::<Vec<_>>();
        removed.sort_unstable();
        let mut expected = [first, second];
        expected.sort_unstable();
        assert_eq!(removed, expected);
        assert!(
            db::local_pam_users_for_channel(&fixture.pool, address()?.as_str())
                .await?
                .is_empty()
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn ban_then_rejoin_pairs_each_roster_version_with_its_annotation() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let channel = fixture.channel().await?;
        let (user, _, actor) = fixture.user("member").await?;
        let service = fixture.service()?;
        let first = join(&service, &channel, &actor, Some(user)).await?;
        let owner = MixRealJid::parse(OWNER)?;
        let removed = service
            .set_mix_access_entry_committed(
                &channel,
                &owner,
                actor.as_str(),
                MixAccessList::Banned,
                MixAccessEntryOperation::Publish { reason: None },
                None,
            )
            .await?;
        assert_eq!(removed.roster.len(), 1);
        assert!(service
            .set_mix_access_entry_committed(
                &channel,
                &owner,
                actor.as_str(),
                MixAccessList::Banned,
                MixAccessEntryOperation::Retract,
                None,
            )
            .await?
            .outcome
            .is_some());
        let rejoined = join(&service, &channel, &actor, Some(user)).await?;
        let removal = &removed.roster[0];
        let latest = &rejoined.roster[0];
        assert_eq!(removal.version, first.roster[0].version + 1);
        assert_eq!(latest.version, removal.version + 1);
        assert!(removal.change.removed && removal.participant_annotation.is_none());
        assert!(!latest.change.removed);
        assert_eq!(
            latest.participant_annotation,
            first.roster[0].participant_annotation
        );
        assert!(matches!(
            &latest.participant_annotation,
            Some(MixParticipantId::Local(_))
        ));
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_disable_before_roster_write_rejects_the_membership_change() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let channel = fixture.channel().await?;
        let (user, generation, actor) = fixture.user("member").await?;
        let initial_version: i64 =
            sqlx::query_scalar("SELECT roster_version FROM users WHERE id=$1")
                .bind(user)
                .fetch_one(&fixture.pool)
                .await?;
        let mut lock = fixture.pool.begin().await?;
        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await?;
        sqlx::query("SELECT id FROM northstar_lock_user_rows_update(ARRAY[$1::uuid])")
            .bind(user)
            .fetch_one(&mut *lock)
            .await?;
        let service = fixture.service()?;
        let worker_channel = channel.clone();
        let worker_actor = actor.clone();
        let joining = tokio::spawn(async move {
            join(&service, &worker_channel, &worker_actor, Some(user)).await
        });
        crate::support::blocked_backend(&fixture.pool, blocker).await;
        let disabled: bool = sqlx::query_scalar("SELECT northstar_user_quiesce_deletion($1,$2)")
            .bind(user)
            .bind(generation)
            .fetch_one(&mut *lock)
            .await?;
        assert!(disabled);
        lock.commit().await?;
        let error = joining.await?.expect_err("disabled account must not join");
        assert_eq!(
            error.downcast_ref(),
            Some(&HostedMixRefusal::AccountChanged)
        );
        assert!(
            db::mix_participant(&fixture.pool, channel.as_uuid(), actor.as_str())
                .await?
                .is_none()
        );
        assert!(db::pam_membership(&fixture.pool, user, address()?.as_str())
            .await?
            .is_none());
        let version: i64 = sqlx::query_scalar("SELECT roster_version FROM users WHERE id=$1")
            .bind(user)
            .fetch_one(&fixture.pool)
            .await?;
        assert_eq!(version, initial_version);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn channel_destroyed_after_lookup_is_typed_not_found() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let channel = fixture.channel().await?;
        let lookup = db::mix_channel_by_id(&fixture.pool, channel.as_uuid())
            .await?
            .expect("channel before race");
        let mut lock = fixture.pool.begin().await?;
        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *lock)
            .await?;
        sqlx::query("SELECT id FROM mix_channels WHERE id=$1 FOR UPDATE")
            .bind(lookup.id)
            .fetch_one(&mut *lock)
            .await?;
        let service = fixture.service()?;
        let joining = tokio::spawn(async move {
            service
                .join_hosted_mix_committed(
                    &channel,
                    join_request(&MixRealJid::parse(OWNER)?, None),
                    None,
                )
                .await
        });
        crate::support::blocked_backend(&fixture.pool, blocker).await;
        sqlx::query("DELETE FROM mix_channels WHERE id=$1")
            .bind(lookup.id)
            .execute(&mut *lock)
            .await?;
        lock.commit().await?;
        assert!(matches!(joining.await??, HostedMixOutcome::MissingChannel));
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}
