//! Force profile reads to wait after MIX admission while a revocation commits.

use anyhow::Result;
use northstar_abuse_application::guard::{
    test_mix_message_content_keyring, test_mix_retraction_content_keyring,
};
use northstar_room_application::mix_service::{
    CreateChannelOutcome, JoinChannelOutcome, JoinMixRequest, MixParticipantPreference,
    MixRelayProfileDenial, MixRelayProfileKind, MixRelayProfileQuery, MixRelayProfileRequester,
    MixRelayProfileResult, MixRelayReturnRepository, MixRepository, MixService,
};
use northstar_room_core::mix::{
    MixChannelAddress, MixChannelId, MixLocalParticipantId, MixParticipantId, MixRelayAddress,
};
use northstar_room_core::mix_iq_relay::{RelayReturnAuthority, RelayReturnRoute};
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

fn return_service(fixture: &Fixture) -> Result<MixService<PostgresMixRepository>> {
    MixService::new(
        PostgresMixRepository::new(fixture.pool.clone()),
        test_mix_message_content_keyring(),
        test_mix_retraction_content_keyring(),
        4,
        fixture.schema.clone(),
    )
}

async fn hosted_remote_relay(
    repository: &PostgresMixRepository,
    address: &MixChannelAddress,
) -> Result<(MixChannelId, MixRelayProfileQuery)> {
    let (outcome, _) = repository
        .create_mix_channel(
            address.domain(),
            Some(address.localpart()),
            REQUESTER,
            4,
            None,
        )
        .await?;
    let CreateChannelOutcome::Created(channel) = outcome else {
        anyhow::bail!("expected an empty channel address, got {outcome:?}");
    };
    let mut target = None;
    for (actor, nick) in [(REQUESTER, "Requester"), ("target@remote.test", "Target")] {
        let outcome = repository
            .join_mix_channel(
                channel,
                JoinMixRequest {
                    actor_jid: actor.to_owned(),
                    nick: Some(nick.to_owned()),
                    nodes: Vec::new(),
                    pam_user_id: None,
                    invitation: None,
                    preference: Some(MixParticipantPreference {
                        vcard: "allow".into(),
                        ..MixParticipantPreference::default()
                    }),
                    anonymous_profile: false,
                },
                None,
            )
            .await?;
        let JoinChannelOutcome::Joined { participant, .. } = outcome else {
            anyhow::bail!("failed to join {actor}: {outcome:?}");
        };
        if actor != REQUESTER {
            target = Some(MixParticipantId::Local(MixLocalParticipantId::new(
                participant.participant_id,
            )));
        }
    }
    let target =
        MixRelayAddress::new(address.clone(), target.expect("remote target joined"), None)?;
    Ok((
        MixChannelId::new(channel),
        MixRelayProfileQuery {
            channel: CanonicalJid::parse_bare(address.as_str())?,
            requester: MixRelayProfileRequester::ChannelParticipant {
                actor: CanonicalJid::parse(&format!("{REQUESTER}/phone"))?,
                local_domain: LOCAL_DOMAIN.to_owned(),
            },
            target: CanonicalJid::parse_bare(target.as_str())?,
            kind: MixRelayProfileKind::VCardTemp,
        },
    ))
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn recreated_channel_with_the_same_jid_does_not_receive_a_relay_reply() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result: Result<()> = async {
        let account = fixture.account("requester").await?;
        let repository = PostgresMixRepository::new(fixture.pool.clone());
        let service = return_service(&fixture)?;
        let address = MixChannelAddress::parse(LOCAL_CHANNEL)?;
        let (original, query) = hosted_remote_relay(&repository, &address).await?;
        let snapshot = repository.relay_profile_with_incarnation(query).await?;
        assert!(matches!(
            snapshot.result,
            MixRelayProfileResult::RemoteRoute { .. }
        ));
        assert_eq!(snapshot.channel_incarnation.as_ref(), Some(&original));
        let admitted = RelayReturnAuthority {
            exact_route: RelayReturnRoute::Local {
                jid: CanonicalJid::parse(&format!("{REQUESTER}/phone"))?,
                account,
                auth_generation: 0,
                connection: Uuid::new_v4(),
            },
            channel: address.clone(),
            channel_incarnation: snapshot.channel_incarnation,
            pam_incarnation: None,
        };
        assert!(service.relay_return_is_current(&admitted).await?);
        assert!(
            repository
                .destroy_mix_channel(original.as_uuid(), REQUESTER, None)
                .await?
        );
        let (replacement, query) = hosted_remote_relay(&repository, &address).await?;
        assert_ne!(original, replacement);
        assert!(matches!(
            repository.relay_profile_snapshot(query).await?,
            MixRelayProfileResult::RemoteRoute { .. },
        ));
        assert!(!service.relay_return_is_current(&admitted).await?);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn pam_replacement_with_the_same_jid_does_not_receive_a_relay_reply() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result: Result<()> = async {
        let (account, query) = fixture.pam_relay("target", "open").await?;
        let service = return_service(&fixture)?;
        let original = service
            .pam_membership(account, REMOTE_CHANNEL)
            .await?
            .unwrap();
        let admitted = RelayReturnAuthority {
            exact_route: RelayReturnRoute::Local {
                jid: CanonicalJid::parse(&format!("target@{LOCAL_DOMAIN}/phone"))?,
                account,
                auth_generation: 0,
                connection: Uuid::new_v4(),
            },
            channel: MixChannelAddress::parse(REMOTE_CHANNEL)?,
            channel_incarnation: None,
            pam_incarnation: Some(original.relay_incarnation()?),
        };
        assert!(service.relay_return_is_current(&admitted).await?);
        sqlx::query("DELETE FROM mix_pam_memberships WHERE id = $1")
            .bind(original.id)
            .execute(&fixture.pool)
            .await?;
        assert!(service.relay_return_is_current(&admitted).await?);
        sqlx::query(
            "INSERT INTO mix_pam_memberships (id, user_id, channel_jid, participant_id, state)
             VALUES ($1, $2, $3, $4, 'joined')",
        )
        .bind(Uuid::new_v4())
        .bind(account)
        .bind(REMOTE_CHANNEL)
        .bind(original.participant_id)
        .execute(&fixture.pool)
        .await?;
        assert_eq!(
            service.relay_profile_snapshot(query).await?,
            MixRelayProfileResult::VCard4(OLD_ITEM.to_owned()),
        );
        assert!(!service.relay_return_is_current(&admitted).await?);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}
