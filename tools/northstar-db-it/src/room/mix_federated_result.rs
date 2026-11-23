use anyhow::Result;
use northstar_room_application::mix_service::{
    CreateChannelOutcome, FederatedMixIqAlreadyFinalized, FederatedMixIqConflict,
    FederatedMixIqReplay, FederatedMixMutation, IssueMixInvitation, JoinChannelOutcome,
    JoinMixRequest, MixInvitationProof, MixInvitationRepository, MixRepository,
    PreparedMixInvitationToken, S2sOutboxPolicy, NODE_MESSAGES,
};
use northstar_room_core::mix::{MixChannelAddress, MixChannelId, MixRealJid};
use northstar_room_postgres::mix_repository::PostgresMixRepository;
use northstar_workflows::room_effects::WorkflowRoomEffects;
use northstar_xml_builder::stanza::iq_error_to;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

const SERVICE: &str = "mix.example.test";
const OWNER: &str = "owner@remote.test";
const GUEST: &str = "guest@remote.test";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    repository: PostgresMixRepository<WorkflowRoomEffects>,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_federated_result_{}", Uuid::new_v4().simple());
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
        let repository = PostgresMixRepository::new(pool.clone());
        Ok(Self {
            owner,
            pool,
            repository,
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

    async fn command(
        &self,
        localpart: &str,
        owner: &str,
        inviter: &str,
    ) -> Result<IssueMixInvitation> {
        let (outcome, _) = self
            .repository
            .create_mix_channel(SERVICE, Some(localpart), owner, 100, None)
            .await?;
        let CreateChannelOutcome::Created(channel_id) = outcome else {
            anyhow::bail!("fixture channel was not created");
        };
        Ok(IssueMixInvitation {
            channel: MixChannelAddress::parse(&format!("{localpart}@{SERVICE}"))?,
            channel_id: MixChannelId::new(channel_id),
            inviter: MixRealJid::parse(inviter)?,
            invitee: MixRealJid::parse("invitee@remote.test")?,
        })
    }

    async fn issue(
        &self,
        command: &IssueMixInvitation,
        token: &PreparedMixInvitationToken,
        admission: &FederatedMixMutation,
    ) -> Result<bool> {
        self.repository
            .execute_mix_invitation(command, token, Some(admission))
            .await
    }

    async fn replay(&self, admission: &FederatedMixMutation) -> Result<FederatedMixIqReplay> {
        self.repository
            .federated_mix_iq_replay(
                &admission.authenticated_domain,
                &admission.actor_jid,
                &admission.request_id,
                &admission.request_digest,
            )
            .await
    }

    async fn invitation_count(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("SELECT count(*) FROM mix_invitations")
            .fetch_one(&self.pool)
            .await?)
    }
}

fn admission(command: &IssueMixInvitation, digest: u8) -> FederatedMixMutation {
    let actor = format!("{}/console", command.inviter.as_str());
    FederatedMixMutation {
        authenticated_domain: "remote.test".to_owned(),
        actor_jid: actor.clone(),
        request_id: "invite".to_owned(),
        request_digest: [digest; 32],
        addressed: command.channel.as_str().to_owned(),
        reply_to: actor,
        policy: S2sOutboxPolicy::new(600, 100, 1_000_000, 100),
    }
}

fn forbidden(admission: &FederatedMixMutation) -> String {
    iq_error_to(
        &admission.request_id,
        &admission.addressed,
        &admission.reply_to,
        "auth",
        "forbidden",
    )
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn denied_invitation_issues_no_token() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let command = fixture.command("denied", OWNER, GUEST).await?;
        let admission = admission(&command, 1);
        let token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
        assert!(!fixture.issue(&command, &token, &admission).await?);
        assert_eq!(fixture.invitation_count().await?, 0);
        let response = forbidden(&admission);
        assert_eq!(
            fixture.replay(&admission).await?,
            FederatedMixIqReplay::Replay(response.clone())
        );
        let queued: String = sqlx::query_scalar("SELECT stanza FROM s2s_outbox")
            .fetch_one(&fixture.pool)
            .await?;
        assert_eq!(queued, response);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn invitation_replay_returns_the_same_token() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let command = fixture.command("replay", OWNER, OWNER).await?;
        let admission = admission(&command, 1);
        let token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
        assert!(fixture.issue(&command, &token, &admission).await?);
        let FederatedMixIqReplay::Replay(first) = fixture.replay(&admission).await? else {
            anyhow::bail!("invitation was not journaled");
        };
        assert!(first.contains(&format!("<token>{}</token>", token.secret())));
        let retry_token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
        let replay = fixture.issue(&command, &retry_token, &admission).await.unwrap_err();
        let replay = replay.downcast_ref::<FederatedMixIqAlreadyFinalized>()
            .expect("concurrent replay stopped by the result fence");
        assert!(replay.response() == first);
        assert!(!format!("{replay:?}").contains(token.secret()));
        assert_eq!(fixture.replay(&admission).await?, FederatedMixIqReplay::Replay(first));
        let (id, hash, lifetime): (Uuid, Vec<u8>, i64) = sqlx::query_as(
            "SELECT id, token_hash, EXTRACT(EPOCH FROM expires_at-created_at)::bigint FROM mix_invitations",
        ).fetch_one(&fixture.pool).await?;
        assert_eq!(id, token.id());
        assert_eq!(hash.as_slice(), token.hash().as_slice());
        assert_eq!(lifetime, 3_600);
        assert_eq!(fixture.invitation_count().await?, 1);
        Ok::<_, anyhow::Error>(())
    }.await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn invited_token_is_consumed_once() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let command = fixture.command("allowlist", OWNER, OWNER).await?;
        let channel_id = command.channel_id.as_uuid();
        sqlx::query("UPDATE mix_channels SET access_model='allowlist' WHERE id=$1")
            .bind(channel_id)
            .execute(&fixture.pool)
            .await?;
        let token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
        assert!(
            fixture
                .issue(&command, &token, &admission(&command, 1))
                .await?
        );
        let request = JoinMixRequest {
            actor_jid: command.invitee.as_str().to_owned(),
            nick: Some("Invitee".to_owned()),
            nodes: vec![NODE_MESSAGES.to_owned()],
            pam_user_id: None,
            invitation: Some(MixInvitationProof {
                inviter_jid: command.inviter.as_str().to_owned(),
                invitee_jid: command.invitee.as_str().to_owned(),
                channel_jid: command.channel.as_str().to_owned(),
                token: token.secret().to_owned(),
            }),
            preference: None,
            anonymous_profile: false,
        };
        let joined = fixture
            .repository
            .join_mix_channel(channel_id, request.clone(), None)
            .await?;
        assert!(matches!(
            joined,
            JoinChannelOutcome::Joined {
                newly_joined: true,
                ..
            }
        ));
        let consumed: bool =
            sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM mix_invitations WHERE id=$1")
                .bind(token.id())
                .fetch_one(&fixture.pool)
                .await?;
        assert!(consumed);
        assert_eq!(
            sqlx::query("DELETE FROM mix_allowed WHERE channel_id=$1 AND jid_pattern=$2")
                .bind(channel_id)
                .bind(command.invitee.as_str())
                .execute(&fixture.pool)
                .await?
                .rows_affected(),
            1
        );
        assert_eq!(
            fixture
                .repository
                .join_mix_channel(channel_id, request, None)
                .await?,
            JoinChannelOutcome::NotAllowed
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn denial_racing_a_different_digest_success_has_one_outcome() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let denied = fixture.command("denied", OWNER, GUEST).await?;
        let allowed = fixture.command("allowed", GUEST, GUEST).await?;
        let denial_admission = admission(&denied, 1);
        let success_admission = admission(&allowed, 2);
        let mut barrier = fixture.pool.begin().await?;
        let blocker: i32 =
            sqlx::query_scalar("SELECT pg_backend_pid() FROM mix_channels WHERE id=$1 FOR UPDATE")
                .bind(denied.channel_id.as_uuid())
                .fetch_one(&mut *barrier)
                .await?;
        let repository = fixture.repository.clone();
        let pending = denial_admission.clone();
        let denial = tokio::spawn(async move {
            let token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
            repository
                .execute_mix_invitation(&denied, &token, Some(&pending))
                .await
        });
        let denial_pid = crate::support::blocked_backend(&fixture.pool, blocker).await;
        let repository = fixture.repository.clone();
        let pending = success_admission.clone();
        let success = tokio::spawn(async move {
            let token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
            repository
                .execute_mix_invitation(&allowed, &token, Some(&pending))
                .await
        });
        crate::support::blocked_backend(&fixture.pool, denial_pid).await;
        barrier.commit().await?;
        assert!(!tokio::time::timeout(Duration::from_secs(5), denial).await???);
        let error = tokio::time::timeout(Duration::from_secs(5), success)
            .await??
            .unwrap_err();
        assert!(error.is::<FederatedMixIqConflict>());
        assert_eq!(fixture.invitation_count().await?, 0);
        assert_eq!(
            fixture.replay(&denial_admission).await?,
            FederatedMixIqReplay::Replay(forbidden(&denial_admission))
        );
        assert_eq!(
            fixture.replay(&success_admission).await?,
            FederatedMixIqReplay::Conflict
        );
        assert_eq!(
            fixture
                .repository
                .admit_federated_mix_iq_result(
                    &success_admission.authenticated_domain,
                    &success_admission.actor_jid,
                    &success_admission.request_id,
                    &success_admission.request_digest,
                    &forbidden(&success_admission),
                    success_admission.policy,
                )
                .await?,
            FederatedMixIqReplay::Conflict
        );
        let queued: Vec<String> = sqlx::query_scalar("SELECT stanza FROM s2s_outbox")
            .fetch_all(&fixture.pool)
            .await?;
        assert_eq!(queued, vec![forbidden(&denial_admission)]);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn denial_replay_does_not_mutate() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let command = fixture.command("replay-denial", OWNER, GUEST).await?;
        let admission = admission(&command, 1);
        let token = PreparedMixInvitationToken::prepare(Uuid::new_v4);
        assert!(!fixture.issue(&command, &token, &admission).await?);
        sqlx::query(
            "INSERT INTO mix_channel_roles (channel_id,jid,role) VALUES ($1,$2,'administrator')",
        )
        .bind(command.channel_id.as_uuid())
        .bind(command.inviter.as_str())
        .execute(&fixture.pool)
        .await?;
        assert_eq!(
            fixture.replay(&admission).await?,
            FederatedMixIqReplay::Replay(forbidden(&admission))
        );
        assert!(fixture.issue(&command, &token, &admission).await.is_err());
        assert_eq!(fixture.invitation_count().await?, 0);
        let fresh = FederatedMixMutation {
            request_id: "fresh".to_owned(),
            ..admission
        };
        assert!(fixture.issue(&command, &token, &fresh).await?);
        assert_eq!(fixture.invitation_count().await?, 1);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fixture.close().await?;
    result
}
