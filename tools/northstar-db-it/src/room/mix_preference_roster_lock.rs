use anyhow::{Context, Result};
use northstar_abuse_application::guard::{
    test_mix_message_content_keyring, test_mix_retraction_content_keyring,
};
use northstar_room_application::mix_service::{
    CommittedMixRosterDelta, CommittedPreference, HostedMixOutcome, JoinMixRequest, MixPayloads,
    MixService, PreferencePatch,
};
use northstar_room_core::mix::{MixChannelId, MixRealJid};
use northstar_room_postgres::mix;
use northstar_roster_postgres::roster;
use northstar_workflows::{
    room_effects::{PostgresMixRepository, WorkflowRoomEffects},
    roster::WorkflowRosterEffects,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use uuid::Uuid;

const CHANNEL: &str = "room@mix.preference.test";
const MEMBER: &str = "member@preference.test";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_preference_roster_lock_{}", Uuid::new_v4().simple());
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

    async fn joined_user(&self) -> Result<(MixChannelId, CommittedMixRosterDelta, i64)> {
        let (created, _) = mix::create_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            "mix.preference.test",
            Some("room"),
            "creator@preference.test",
            100,
            &MixPayloads,
            None,
        )
        .await?;
        let mix::CreateChannelOutcome::Created(channel_id) = created else {
            anyhow::bail!("fixture MIX channel was not created");
        };
        let user = northstar_auth_postgres::users::create_user(
            &self.pool,
            "member",
            "preference-fixture-password",
            false,
            false,
            4096,
            false,
        )
        .await?;
        let channel = MixChannelId::new(channel_id);
        let joined = self
            .service()?
            .join_hosted_mix_committed(
                &channel,
                JoinMixRequest {
                    actor_jid: MEMBER.into(),
                    nick: Some("member".into()),
                    nodes: vec![mix::NODE_MESSAGES.to_owned()],
                    pam_user_id: Some(user.id),
                    invitation: None,
                    preference: None,
                    anonymous_profile: false,
                },
                None,
            )
            .await?;
        let HostedMixOutcome::Present(joined) = joined else {
            anyhow::bail!("fixture MIX channel disappeared");
        };
        let [delta]: [CommittedMixRosterDelta; 1] = joined
            .roster
            .try_into()
            .expect("PAM join must create a roster item");
        assert_eq!(delta.account.id, user.id);
        assert_eq!(delta.change.subscription.as_deref(), Some("to"));
        Ok((channel, delta, user.auth_generation))
    }

    fn stop_sharing(
        &self,
        channel: MixChannelId,
    ) -> Result<tokio::task::JoinHandle<Result<CommittedPreference>>> {
        let service = self.service()?;
        Ok(tokio::spawn(async move {
            service
                .update_preference(
                    channel,
                    &MixRealJid::parse(MEMBER)?,
                    PreferencePatch {
                        share_presence: Some(false),
                        ..PreferencePatch::default()
                    },
                    None,
                )
                .await?
                .context("preference write was refused")
        }))
    }

    async fn assert_waiting_for_account(&self, lock: &mut Transaction<'_, Postgres>) -> Result<()> {
        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut **lock)
            .await?;
        let waiting = crate::support::blocked_backend(&self.pool, blocker).await;
        let query: String = sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1")
            .bind(waiting)
            .fetch_one(&self.pool)
            .await?;
        anyhow::ensure!(
            query.contains("northstar_lock_user_rows_update"),
            "preference must wait before touching the roster item, got {query}"
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn share_presence_waits_before_ordinary_roster_set_touches_the_same_item() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let (channel, joined, generation) = fixture.joined_user().await?;
        let user = joined.account.id;
        let mut roster_set =
            roster::begin_authorized_roster_mutation(&fixture.pool, user, generation)
                .await?
                .context("fixture account must be enabled")?;
        let preference = fixture.stop_sharing(channel)?;
        fixture.assert_waiting_for_account(&mut roster_set).await?;

        let groups = ["Channels".to_owned()];
        let ordinary = roster::upsert_roster_in_transaction(
            &WorkflowRosterEffects,
            &mut roster_set,
            user,
            CHANNEL,
            Some("Client label"),
            &groups,
        )
        .await?;
        roster_set.commit().await?;

        let committed = preference.await??;
        assert!(!committed.preference.share_presence);
        let [delta] = committed.roster_changes.as_slice() else {
            anyhow::bail!("expected one committed preference delta");
        };
        assert_eq!(delta.account, joined.account);
        assert_eq!(delta.auth_generation, Some(generation));
        assert_eq!(delta.participant_annotation, joined.participant_annotation);
        assert_eq!(ordinary.version, joined.version + 1);
        assert_eq!(ordinary.display_name.as_deref(), Some("Client label"));
        assert_eq!(ordinary.subscription.as_deref(), Some("to"));
        assert_eq!(delta.version, ordinary.version + 1);
        assert_eq!(delta.change.version, delta.version);
        assert_eq!(delta.change.groups, groups);
        assert_eq!(delta.change.subscription.as_deref(), Some("none"));
        assert_eq!(
            roster::get_roster_version(&fixture.pool, user).await?,
            delta.version
        );
        assert_eq!(
            roster::latest_roster_change_for_contact(&fixture.pool, user, CHANNEL).await?,
            Some(delta.change.clone())
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

async fn candidate_quiesces_during_preference_write(delete: bool) -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let (channel, joined, generation) = fixture.joined_user().await?;
        let user = joined.account.id;
        let mut lock = roster::begin_authorized_roster_mutation(&fixture.pool, user, generation)
            .await?
            .context("fixture account must be enabled")?;
        let preference = fixture.stop_sharing(channel.clone())?;
        fixture.assert_waiting_for_account(&mut lock).await?;
        let disabled: bool = sqlx::query_scalar("SELECT northstar_user_quiesce_deletion($1,$2)")
            .bind(user)
            .bind(generation)
            .fetch_one(&mut *lock)
            .await?;
        assert!(disabled);
        if delete {
            let deleted: bool = sqlx::query_scalar("SELECT northstar_user_delete_quiesced($1,$2)")
                .bind(user)
                .bind(&joined.account.username)
                .fetch_one(&mut *lock)
                .await?;
            assert!(deleted);
        }
        lock.commit().await?;

        let committed = preference.await??;
        assert!(!committed.preference.share_presence);
        assert!(committed.roster_changes.is_empty());
        let stored = mix::mix_participant_preference(&fixture.pool, channel.as_uuid(), MEMBER)
            .await?
            .context("participant preference was not committed")?;
        assert!(!stored.share_presence);
        let item = roster::roster_item(&fixture.pool, user, CHANNEL).await?;
        if delete {
            assert!(item.is_none());
            assert!(mix::pam_membership(&fixture.pool, user, CHANNEL)
                .await?
                .is_none());
        } else {
            assert_eq!(
                item.context("disabled user's roster item was removed")?.2,
                "none"
            );
            assert_eq!(
                roster::get_roster_version(&fixture.pool, user).await?,
                joined.version + 1
            );
        }
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn disabled_candidate_keeps_the_roster_mirror_without_a_push() -> Result<()> {
    candidate_quiesces_during_preference_write(false).await
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn deleted_candidate_is_not_recreated_by_the_preference_write() -> Result<()> {
    candidate_quiesces_during_preference_write(true).await
}
