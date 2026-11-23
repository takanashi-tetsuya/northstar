use anyhow::{Context, Result};
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_application::mix_service::{
    ConfigPatch, FederatedMixMutation, InfoPatch, MixAdministrationRepository, MixMutationOutcome,
    MixPayloads, PreferencePatch,
};
use northstar_room_core::mix::{
    FixedMixClock, MixAllowBlock, MixChannelId, MixClock, MixJidVisibility, MixRealJid,
};
use northstar_room_postgres::mix::{
    create_mix_channel, create_mix_channel_at, join_mix_channel, mix_channel_by_id,
    mix_participant_preference, CreateChannelOutcome, JoinChannelOutcome, JoinMixRequest,
    NODE_CONFIG, NODE_INFO,
};
use northstar_time::{DateTime, Utc};
use northstar_workflows::room_effects::{PostgresMixRepository, WorkflowRoomEffects};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use uuid::Uuid;

const SERVICE: &str = "mix.example.test";
const OWNER: &str = "owner@remote.test";
const ADMIN: &str = "admin@remote.test";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_admin_patches_{}", Uuid::new_v4().simple());
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

    fn repository(&self) -> PostgresMixRepository {
        PostgresMixRepository::new(self.pool.clone())
    }

    async fn channel(&self) -> Result<MixChannelId> {
        let (outcome, _) = create_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            SERVICE,
            Some("room"),
            OWNER,
            100,
            &MixPayloads,
            None,
        )
        .await?;
        let CreateChannelOutcome::Created(channel) = outcome else {
            anyhow::bail!("fixture channel was not created");
        };
        let joined = join_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            channel,
            JoinMixRequest {
                actor_jid: OWNER,
                nick: Some("Owner"),
                nodes: &[NODE_INFO.to_owned()],
                pam_user_id: None,
                invitation: None,
                preference: None,
                anonymous_profile: false,
            },
            &MixPayloads,
            None,
        )
        .await?;
        anyhow::ensure!(matches!(joined, JoinChannelOutcome::Joined { .. }));
        Ok(MixChannelId::new(channel))
    }

    async fn hold_channel(
        &self,
        channel: &MixChannelId,
    ) -> Result<(Transaction<'_, Postgres>, i32)> {
        let mut barrier = self.pool.begin().await?;
        let blocker =
            sqlx::query_scalar("SELECT pg_backend_pid() FROM mix_channels WHERE id=$1 FOR UPDATE")
                .bind(channel.as_uuid())
                .fetch_one(&mut *barrier)
                .await?;
        Ok((barrier, blocker))
    }

    async fn wait_for_channel(&self, blocker: i32) -> Result<i32> {
        let waiter = crate::support::blocked_backend(&self.pool, blocker).await;
        let query: String = sqlx::query_scalar("SELECT query FROM pg_stat_activity WHERE pid=$1")
            .bind(waiter)
            .fetch_one(&self.pool)
            .await?;
        assert!(
            query.contains("FROM mix_channels") && query.contains("FOR UPDATE"),
            "{query}"
        );
        Ok(waiter)
    }

    async fn artifacts(&self) -> Result<(i64, i64, i64, i64, i64)> {
        Ok(sqlx::query_as(
            "SELECT (SELECT count(*) FROM mix_events),
                    (SELECT count(*) FROM mix_delivery_events),
                    (SELECT count(*) FROM mix_delivery_recipients),
                    (SELECT count(*) FROM mix_federated_iq_results),
                    (SELECT count(*) FROM s2s_outbox)",
        )
        .fetch_one(&self.pool)
        .await?)
    }
}

fn result_context(request_id: &str) -> FederatedMixMutation {
    FederatedMixMutation {
        authenticated_domain: "remote.test".to_owned(),
        actor_jid: format!("{OWNER}/device"),
        request_id: request_id.to_owned(),
        request_digest: [42; 32],
        addressed: format!("room@{SERVICE}"),
        reply_to: format!("{OWNER}/device"),
        policy: S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 100,
            max_bytes: 1_048_576,
            max_per_domain: 100,
        },
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn disjoint_preference_patches_both_survive() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let (barrier, blocker) = fixture.hold_channel(&channel).await?;
    let first = {
        let repository = fixture.repository();
        let channel = channel.clone();
        tokio::spawn(async move {
            repository
                .update_preference(
                    channel,
                    &MixRealJid::parse(OWNER)?,
                    PreferencePatch {
                        private_messages: Some(MixAllowBlock::Block),
                        ..PreferencePatch::default()
                    },
                    None,
                )
                .await
        })
    };
    let first_waiter = fixture.wait_for_channel(blocker).await?;
    let second = {
        let repository = fixture.repository();
        let channel = channel.clone();
        tokio::spawn(async move {
            repository
                .update_preference(
                    channel,
                    &MixRealJid::parse(OWNER)?,
                    PreferencePatch {
                        vcard: Some(MixAllowBlock::Allow),
                        ..PreferencePatch::default()
                    },
                    Some(&result_context("preference-second")),
                )
                .await
        })
    };
    crate::support::blocked_backend(&fixture.pool, first_waiter).await;
    barrier.commit().await?;

    let first = first.await??.context("first preference was refused")?;
    let second = second.await??.context("second preference was refused")?;
    let stored = mix_participant_preference(&fixture.pool, channel.as_uuid(), OWNER)
        .await?
        .context("missing preference")?;
    let journal: String =
        sqlx::query_scalar("SELECT response FROM mix_federated_iq_results WHERE request_id=$1")
            .bind("preference-second")
            .fetch_one(&fixture.pool)
            .await?;
    fixture.close().await?;
    assert_eq!(first.preference.private_messages, "block");
    assert_eq!(first.preference.vcard, "block");
    assert_eq!(second.preference.private_messages, "block");
    assert_eq!(second.preference.vcard, "allow");
    assert_eq!(second.preference, stored);
    assert!(
        journal.contains("var='Private Messages'><value>block</value>"),
        "{journal}"
    );
    assert!(
        journal.contains("var='vCard'><value>allow</value>"),
        "{journal}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn preference_patch_races_identity_visibility() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let (mut barrier, blocker) = fixture.hold_channel(&channel).await?;
    let change = {
        let repository = fixture.repository();
        let channel = channel.clone();
        tokio::spawn(async move {
            repository
                .update_preference(
                    channel,
                    &MixRealJid::parse(OWNER)?,
                    PreferencePatch {
                        vcard: Some(MixAllowBlock::Allow),
                        ..PreferencePatch::default()
                    },
                    None,
                )
                .await
        })
    };
    fixture.wait_for_channel(blocker).await?;
    sqlx::query(
        "UPDATE mix_participant_preferences SET jid_visibility='always' WHERE channel_id=$1",
    )
    .bind(channel.as_uuid())
    .execute(&mut *barrier)
    .await?;
    sqlx::query("UPDATE mix_channels SET jid_visibility='hidden', revision=revision+1 WHERE id=$1")
        .bind(channel.as_uuid())
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    let result = change.await??;
    let stored = mix_participant_preference(&fixture.pool, channel.as_uuid(), OWNER)
        .await?
        .context("missing preference")?;
    fixture.close().await?;
    assert!(result.is_none());
    assert_eq!(stored.jid_visibility, "always");
    assert_eq!(stored.vcard, "block");
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn info_fixed_field_mismatch_racing_config_is_rejected() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let before = fixture.artifacts().await?;
    let (mut barrier, blocker) = fixture.hold_channel(&channel).await?;
    let change = {
        let repository = fixture.repository();
        let channel = channel.clone();
        tokio::spawn(async move {
            repository
                .update_info(
                    channel,
                    &MixRealJid::parse(OWNER)?,
                    InfoPatch {
                        name: Some("must not commit".to_owned()),
                        visibility: Some(MixJidVisibility::Visible),
                        ..InfoPatch::default()
                    },
                    "info-mismatch".to_owned(),
                    Some(&result_context("info-mismatch")),
                )
                .await
        })
    };
    fixture.wait_for_channel(blocker).await?;
    sqlx::query("UPDATE mix_channels SET jid_visibility='hidden', revision=revision+1 WHERE id=$1")
        .bind(channel.as_uuid())
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    let result = change.await?;
    let stored = mix_channel_by_id(&fixture.pool, channel.as_uuid())
        .await?
        .context("missing channel")?;
    let after = fixture.artifacts().await?;
    fixture.close().await?;
    assert_eq!(
        result.unwrap_err().to_string(),
        "unsupported MIX configuration value"
    );
    assert_eq!(stored.jid_visibility, "hidden");
    assert_eq!(stored.name, None);
    assert_eq!(before, after);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn info_patch_matches_the_locked_payload() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let (mut barrier, blocker) = fixture.hold_channel(&channel).await?;
    let change = {
        let repository = fixture.repository();
        let channel = channel.clone();
        tokio::spawn(async move {
            repository
                .update_info(
                    channel,
                    &MixRealJid::parse(OWNER)?,
                    InfoPatch {
                        name: Some("New & name".to_owned()),
                        visibility: Some(MixJidVisibility::Maybe),
                        ..InfoPatch::default()
                    },
                    "info-match".to_owned(),
                    None,
                )
                .await
        })
    };
    fixture.wait_for_channel(blocker).await?;
    sqlx::query("UPDATE mix_channels SET jid_visibility='maybe', description=$2, revision=revision+1 WHERE id=$1")
        .bind(channel.as_uuid()).bind("committed by the blocker").execute(&mut *barrier).await?;
    barrier.commit().await?;
    let MixMutationOutcome::Applied(result) = change.await?? else {
        anyhow::bail!("matching assertion did not apply");
    };
    let (payload, stanza): (String, String) = sqlx::query_as(
        "SELECT event.payload, delivery.stanza_template FROM mix_events event
         JOIN mix_delivery_events delivery ON delivery.event_id=event.id
         WHERE event.channel_id=$1 AND event.node=$2 AND event.item_id=$3",
    )
    .bind(channel.as_uuid())
    .bind(NODE_INFO)
    .bind("info-match")
    .fetch_one(&fixture.pool)
    .await?;
    fixture.close().await?;
    assert_eq!(result.payload, payload);
    assert!(stanza.contains(payload.as_str()), "{stanza}");
    assert!(payload.contains("New &amp; name"), "{payload}");
    assert!(payload.contains("committed by the blocker"), "{payload}");
    assert!(payload.contains("jid-maybe-visible"), "{payload}");
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn config_change_racing_owner_change_is_refused_without_artifacts() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let before = fixture.artifacts().await?;
    let current = mix_channel_by_id(&fixture.pool, channel.as_uuid())
        .await?
        .context("missing channel")?;
    let (mut barrier, blocker) = fixture.hold_channel(&channel).await?;
    let change = {
        let repository = fixture.repository();
        let channel = channel.clone();
        tokio::spawn(async move {
            repository
                .update_config(
                    channel,
                    &MixRealJid::parse(OWNER)?,
                    ConfigPatch {
                        expected_revision: current.revision,
                        fields: [("Private Messages".to_owned(), vec!["0".to_owned()])].into(),
                    },
                    "owner-race".to_owned(),
                    Some(&result_context("owner-race")),
                )
                .await
        })
    };
    fixture.wait_for_channel(blocker).await?;
    sqlx::query("UPDATE mix_channels SET revision=revision+1 WHERE id=$1")
        .bind(channel.as_uuid())
        .execute(&mut *barrier)
        .await?;
    sqlx::query("UPDATE mix_channel_roles SET jid=$2 WHERE channel_id=$1 AND role='owner'")
        .bind(channel.as_uuid())
        .bind(ADMIN)
        .execute(&mut *barrier)
        .await?;
    sqlx::query("UPDATE mix_participants SET role='participant' WHERE channel_id=$1 AND jid=$2")
        .bind(channel.as_uuid())
        .bind(OWNER)
        .execute(&mut *barrier)
        .await?;
    barrier.commit().await?;
    let result = change.await??;
    let stored = mix_channel_by_id(&fixture.pool, channel.as_uuid())
        .await?
        .context("missing channel")?;
    let after = fixture.artifacts().await?;
    fixture.close().await?;
    assert!(matches!(result, MixMutationOutcome::Forbidden));
    assert!(stored.allow_private_messages);
    assert_eq!(before, after);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_cannot_apply_owner_only_config() -> Result<()> {
    let fixture = Fixture::new().await?;
    let channel = fixture.channel().await?;
    let repository = fixture.repository();
    let current = mix_channel_by_id(&fixture.pool, channel.as_uuid())
        .await?
        .context("missing channel")?;
    let setup = repository
        .update_config(
            channel.clone(),
            &MixRealJid::parse(OWNER)?,
            ConfigPatch {
                expected_revision: current.revision,
                fields: [("Administrator".to_owned(), vec![ADMIN.to_owned()])].into(),
            },
            "add-admin".to_owned(),
            None,
        )
        .await?;
    let MixMutationOutcome::Applied(setup) = setup else {
        anyhow::bail!("fixture admin role was refused");
    };
    let before = fixture.artifacts().await?;
    let result = repository
        .update_config(
            channel.clone(),
            &MixRealJid::parse(ADMIN)?,
            ConfigPatch {
                expected_revision: setup.channel.revision,
                fields: [("Private Messages".to_owned(), vec!["invalid".to_owned()])].into(),
            },
            "admin-denied".to_owned(),
            None,
        )
        .await?;
    let stale = repository
        .update_config(
            channel,
            &MixRealJid::parse(OWNER)?,
            ConfigPatch {
                expected_revision: current.revision,
                fields: Default::default(),
            },
            "owner-stale".to_owned(),
            None,
        )
        .await?;
    let after = fixture.artifacts().await?;
    drop(repository);
    fixture.close().await?;
    assert_eq!(setup.node, NODE_CONFIG);
    assert!(matches!(result, MixMutationOutcome::Forbidden));
    assert!(matches!(stale, MixMutationOutcome::Conflict));
    assert_eq!(before, after);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn initial_items_share_the_prepared_public_timestamp() -> Result<()> {
    let fixture = Fixture::new().await?;
    let clock = FixedMixClock(DateTime::<Utc>::from_timestamp(0, 42).unwrap());
    let (outcome, _) = create_mix_channel_at(
        &WorkflowRoomEffects,
        &fixture.pool,
        SERVICE,
        Some("room"),
        &MixRealJid::parse(OWNER)?,
        100,
        clock.now_utc(),
        &MixPayloads,
        None,
    )
    .await?;
    let CreateChannelOutcome::Created(channel) = outcome else {
        anyhow::bail!("fixture channel was not created");
    };
    let items: Vec<(String, String)> =
        sqlx::query_as("SELECT node,item_id FROM mix_events WHERE channel_id=$1 ORDER BY node")
            .bind(channel)
            .fetch_all(&fixture.pool)
            .await?;
    fixture.close().await?;
    let expected_id = "1970-01-01T00:00:00.000000042Z";
    assert_eq!(
        items,
        [
            (NODE_CONFIG.to_owned(), expected_id.to_owned()),
            (NODE_INFO.to_owned(), expected_id.to_owned()),
        ]
    );
    Ok(())
}
