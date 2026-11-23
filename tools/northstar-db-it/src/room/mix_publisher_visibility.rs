//! Force an identity policy change between rendering and the locked MIX store.

use anyhow::Result;
use northstar_archive_core::{MamArchiveQuery, MamRsmPage};
use northstar_room_application::mix_service::{
    participant_jid_visible, LockedPublisher, MixPayloads, MixPublisherIdentity, MixReplayIdentity,
    MixService, PreparedMessage, PublicationOutcome,
};
use northstar_room_core::mix::{MixChannelId, MixRealJid};
use northstar_room_postgres::mix::*;
use northstar_workflows::room_effects::{PostgresMixRepository, WorkflowRoomEffects};
use northstar_xml_builder::XmlElement;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

const ACTOR: &str = "publisher@remote.test";
const SERVICE: &str = "mix.example.test";

struct Fixture {
    owner: PgPool,
    pool: PgPool,
    schema: String,
}

impl Fixture {
    async fn new() -> Result<Self> {
        let url = std::env::var("TEST_DATABASE_URL")?;
        let owner = PgPool::connect(&url).await?;
        let schema = format!("mix_visibility_{}", Uuid::new_v4().simple());
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

    async fn channel(&self, localpart: &str, visibility: &str) -> Result<Uuid> {
        let (outcome, _) = create_mix_channel(
            &WorkflowRoomEffects,
            &self.pool,
            SERVICE,
            Some(localpart),
            ACTOR,
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
                actor_jid: ACTOR,
                nick: Some("Publisher"),
                nodes: &[NODE_MESSAGES.to_owned()],
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
        sqlx::query("UPDATE mix_channels SET jid_visibility=$2 WHERE id=$1")
            .bind(channel)
            .bind(visibility)
            .execute(&self.pool)
            .await?;
        Ok(channel)
    }
}

struct PendingWrite {
    channel: Uuid,
    item: Uuid,
    target: Option<Uuid>,
    client_id: &'static str,
    publisher: MixPublisherIdentity,
    live_jid: Option<&'static str>,
    payload: String,
    tombstone: Option<String>,
    body: String,
}

impl PendingWrite {
    async fn render(
        pool: &PgPool,
        channel_id: Uuid,
        item: Uuid,
        target: Option<Uuid>,
        client_id: &'static str,
    ) -> Result<Self> {
        let channel = mix_channel_by_id(pool, channel_id).await?.expect("channel");
        let participant = mix_participant(pool, channel_id, ACTOR)
            .await?
            .expect("publisher");
        let preference = mix_participant_preference(pool, channel_id, ACTOR)
            .await?
            .unwrap_or_default();
        let publisher = MixPublisherIdentity::from_state(&channel, &participant);
        let live_jid = participant_jid_visible(&channel, &preference).then_some(ACTOR);
        let body = match target {
            Some(target) => XmlElement::namespaced("retract", "urn:xmpp:mix:misc:0")
                .attr("id", target)
                .finish(),
            None => XmlElement::new("body").text("original").finish(),
        };
        let mut identity = XmlElement::namespaced("mix", "urn:xmpp:mix:core:1");
        if let Some(nick) = publisher.nick.as_deref() {
            identity.push_child(XmlElement::new("nick").text(nick));
        }
        if publisher.archive_jid_visible {
            identity.push_child(XmlElement::new("jid").text(ACTOR));
        }
        let channel_jid = channel.jid();
        let payload = XmlElement::namespaced("message", "jabber:client")
            .attr("from", &channel_jid)
            .attr("id", item)
            .attr("type", "groupchat")
            .validated_fragment(&body)?
            .child(identity)
            .finish();
        let tombstone = target.map(|target| {
            let by = if publisher.archive_jid_visible {
                ACTOR.to_owned()
            } else {
                format!("{}#{channel_jid}", publisher.participant_id)
            };
            XmlElement::namespaced("message", "jabber:client")
                .attr("id", target)
                .child(XmlElement::namespaced("retracted", "urn:xmpp:mix:misc:0").attr("by", by))
                .finish()
        });
        Ok(Self {
            channel: channel_id,
            item,
            target,
            client_id,
            publisher,
            live_jid,
            payload,
            tombstone,
            body,
        })
    }

    async fn store(&self, pool: &PgPool) -> Result<bool> {
        let intent = Some(MixBusinessIdentity {
            client_id: self.client_id,
            semantic_key_id: "fixture-key-0001",
            semantic_mac: &[7; 32],
        });
        if let Some(target) = self.target {
            let admission = retract_mix_message(
                pool,
                self.channel,
                ACTOR,
                target,
                self.item,
                self.tombstone.as_deref().expect("retraction tombstone"),
                &self.payload,
                intent,
                &self.publisher,
                self.live_jid,
                &WorkflowRoomEffects,
                &MixPayloads,
            )
            .await?;
            match admission.outcome {
                RetractMixMessageOutcome::Retracted => assert_eq!(admission.recipients.len(), 1),
                RetractMixMessageOutcome::IdentityPolicyChanged => {
                    assert!(admission.recipients.is_empty());
                    return Ok(false);
                }
                outcome => anyhow::bail!("unexpected retraction outcome {outcome:?}"),
            }
        } else {
            let admission = store_mix_message(
                pool,
                self.channel,
                ACTOR,
                &self.item.to_string(),
                &self.payload,
                intent,
                &self.body,
                &self.publisher,
                self.live_jid,
                false,
                &MixPayloads,
            )
            .await?;
            match admission.outcome {
                StoreEventOutcome::Stored(id) => {
                    assert_eq!(id, self.item);
                    assert_eq!(admission.recipients.len(), 1);
                }
                StoreEventOutcome::IdentityPolicyChanged => {
                    assert!(admission.recipients.is_empty());
                    return Ok(false);
                }
                outcome => anyhow::bail!("unexpected message outcome {outcome:?}"),
            }
        }
        Ok(true)
    }
}

async fn artifacts(pool: &PgPool, channel: Uuid) -> Result<(i64, i64, i64, i64, i64)> {
    Ok(sqlx::query_as(
        "SELECT
          (SELECT count(*) FROM mix_events WHERE channel_id=$1 AND node=$2),
          (SELECT count(*) FROM mix_delivery_events WHERE channel_id=$1),
          (SELECT count(*) FROM mix_delivery_recipients r JOIN mix_delivery_events e USING(event_id)
            WHERE e.channel_id=$1),
          (SELECT count(*) FROM mix_business_intents WHERE channel_id=$1),
          (SELECT count(*) FROM mix_source_retractions f JOIN mix_channels c
             ON f.source_by=c.localpart || '@' || c.service_domain WHERE c.id=$1)",
    )
    .bind(channel)
    .bind(NODE_MESSAGES)
    .fetch_one(pool)
    .await?)
}

async fn payload(pool: &PgPool, channel: Uuid, item: Uuid) -> Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT payload FROM mix_events WHERE channel_id=$1 AND node=$2 AND item_id=$3",
    )
    .bind(channel)
    .bind(NODE_MESSAGES)
    .bind(item.to_string())
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn locked_visibility_rejects_stale_message_and_retraction_payloads_without_writes(
) -> Result<()> {
    let fixture = Fixture::new().await?;
    let pool = &fixture.pool;
    let result = async {
        for (case, before, after, nick) in [
            ("hide", "visible", "hidden", "Publisher"),
            ("show", "hidden", "visible", "Publisher"),
            ("rename", "visible", "visible", "Updated"),
        ] {
            for retract in [false, true] {
                let localpart = format!("policy-{case}-{retract}");
                let channel = fixture.channel(&localpart, before).await?;
                let target = if retract {
                    let original =
                        PendingWrite::render(pool, channel, Uuid::new_v4(), None, "target").await?;
                    assert!(original.store(pool).await?);
                    Some(original)
                } else {
                    None
                };
                let target_id = target.as_ref().map(|original| original.item);
                let baseline = artifacts(pool, channel).await?;
                let mut barrier = pool.begin().await?;
                let blocker: i32 = sqlx::query_scalar(
                    "SELECT pg_backend_pid() FROM mix_channels WHERE id=$1 FOR UPDATE",
                )
                .bind(channel)
                .fetch_one(&mut *barrier)
                .await?;
                let item = Uuid::new_v4();
                let stale = PendingWrite::render(pool, channel, item, target_id, "raced").await?;
                assert_eq!(stale.publisher.archive_jid_visible, before == "visible");
                let writer_pool = pool.clone();
                let writer = tokio::spawn(async move { stale.store(&writer_pool).await });
                crate::support::blocked_backend(pool, blocker).await;
                if before == after {
                    sqlx::query(
                        "UPDATE mix_participants SET nick=$3 WHERE channel_id=$1 AND jid=$2",
                    )
                    .bind(channel)
                    .bind(ACTOR)
                    .bind(nick)
                    .execute(&mut *barrier)
                    .await?;
                } else {
                    sqlx::query("UPDATE mix_channels SET jid_visibility=$2 WHERE id=$1")
                        .bind(channel)
                        .bind(after)
                        .execute(&mut *barrier)
                        .await?;
                }
                barrier.commit().await?;
                let stored = tokio::time::timeout(Duration::from_secs(5), writer).await???;
                assert!(!stored, "{case}, retraction={retract}");
                assert_eq!(artifacts(pool, channel).await?, baseline);
                if let Some(original) = &target {
                    assert_eq!(
                        payload(pool, channel, original.item).await?,
                        original.payload
                    );
                }

                let fresh = PendingWrite::render(pool, channel, item, target_id, "raced").await?;
                assert!(fresh.store(pool).await?);
                let archived = payload(pool, channel, item).await?;
                assert_eq!(archived, fresh.payload);
                let delivery: String = sqlx::query_scalar(
                    "SELECT stanza_template FROM mix_delivery_events WHERE event_id=$1",
                )
                .bind(item)
                .fetch_one(pool)
                .await?;
                for stanza in [&archived, &delivery] {
                    assert_eq!(
                        stanza.contains("<jid>publisher@remote.test</jid>"),
                        after == "visible"
                    );
                    assert!(stanza.contains(&format!("<nick>{nick}</nick>")));
                }
                if let Some(target_id) = target_id {
                    let tombstone = payload(pool, channel, target_id).await?;
                    assert_eq!(Some(tombstone.as_str()), fresh.tombstone.as_deref());
                    assert_eq!(
                        tombstone.contains("by='publisher@remote.test'"),
                        after == "visible"
                    );
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn unfiltered_mix_mam_preserves_payload_committed_under_visible_policy() -> Result<()> {
    let fixture = Fixture::new().await?;
    let pool = &fixture.pool;
    let result = async {
        let channel = fixture.channel("event-time", "visible").await?;
        let original =
            PendingWrite::render(pool, channel, Uuid::new_v4(), None, "original").await?;
        assert!(original.store(pool).await?);
        assert!(original
            .payload
            .contains("<jid>publisher@remote.test</jid>"));
        sqlx::query("UPDATE mix_channels SET jid_visibility='hidden' WHERE id=$1")
            .bind(channel)
            .execute(pool)
            .await?;
        let query = MamArchiveQuery {
            with_jid: None,
            start: None,
            end: None,
            before_id: None,
            after_id: None,
            ids: Vec::new(),
            page: MamRsmPage::First,
            max: 10,
        };
        let Some(page) = mix_mam_page(pool, channel, &query).await? else {
            anyhow::bail!("the unfiltered MIX page is missing");
        };
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].item_id, original.item.to_string());
        assert_eq!(page.events[0].payload, original.payload);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fixture.close().await?;
    result
}

fn publication_service(fixture: &Fixture) -> Result<MixService<PostgresMixRepository>> {
    use northstar_abuse_application::guard::{
        test_mix_message_content_keyring, test_mix_retraction_content_keyring,
    };
    MixService::new(
        PostgresMixRepository::new(fixture.pool.clone()),
        test_mix_message_content_keyring(),
        test_mix_retraction_content_keyring(),
        3,
        fixture.schema.clone(),
    )
}

fn prepare_message(channel: MixChannelId) -> Result<PreparedMessage> {
    Ok(PreparedMessage {
        channel_id: channel,
        actor: MixRealJid::parse(ACTOR)?,
        item_id: Uuid::new_v4(),
        children: "<body>single</body>".into(),
        identity: Some(MixReplayIdentity {
            client_id: "single".into(),
            canonical_semantics: b"single".to_vec(),
        }),
        encrypted: false,
    })
}

fn render_published_message(message: &PreparedMessage, author: &LockedPublisher) -> Result<String> {
    let mut identity = XmlElement::namespaced("mix", "urn:xmpp:mix:core:1");
    if let Some(nick) = &author.nick {
        identity.push_child(XmlElement::new("nick").text(nick.as_str()));
    }
    if let Some(jid) = &author.archive_jid {
        identity.push_child(XmlElement::new("jid").text(jid.as_str()));
    }
    Ok(XmlElement::namespaced("message", "jabber:client")
        .attr("from", author.channel.as_str())
        .attr("id", message.item_id)
        .attr("type", "groupchat")
        .validated_fragment(&message.children)?
        .child(identity)
        .finish())
}

fn unexpected_publication_render(_: &PreparedMessage, _: &LockedPublisher) -> Result<String> {
    panic!("replayed or absent publication must not render")
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn two_stale_observations_then_one_locked_admission_publishes_once() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let pool = &fixture.pool;
        let channel = fixture.channel("locked-publisher", "visible").await?;
        let first = PendingWrite::render(pool, channel, Uuid::new_v4(), None, "first").await?;
        sqlx::query("UPDATE mix_channels SET jid_visibility='hidden' WHERE id=$1")
            .bind(channel)
            .execute(pool)
            .await?;
        let second = PendingWrite::render(pool, channel, Uuid::new_v4(), None, "second").await?;
        assert!(first.publisher.archive_jid_visible);
        assert!(!second.publisher.archive_jid_visible);
        assert_eq!(second.publisher.nick.as_deref(), Some("Publisher"));
        let before = artifacts(pool, channel).await?;
        let mut change = pool.begin().await?;
        let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *change)
            .await?;
        sqlx::query("SELECT id FROM mix_channels WHERE id=$1 FOR UPDATE")
            .bind(channel)
            .execute(&mut *change)
            .await?;
        let service = publication_service(&fixture)?;
        let message = prepare_message(MixChannelId::new(channel))?;
        let publisher = service.clone();
        let task = tokio::spawn(async move {
            let outcome = publisher
                .publish_message(&message, render_published_message, None)
                .await;
            (message, outcome)
        });
        crate::support::blocked_backend(pool, blocker).await;
        sqlx::query(
            "UPDATE mix_participants SET nick='Locked Nick' WHERE channel_id=$1 AND jid=$2",
        )
        .bind(channel)
        .bind(ACTOR)
        .execute(&mut *change)
        .await?;
        change.commit().await?;
        let (message, outcome) = task.await?;
        assert_eq!(outcome?, PublicationOutcome::Published(message.item_id));
        let stored = payload(pool, channel, message.item_id).await?;
        assert!(stored.contains("<nick>Locked Nick</nick>"));
        assert!(!stored.contains("<jid>"));
        let (stanza, recipient): (String, String) = sqlx::query_as(
            "SELECT event.stanza_template, recipient.recipient_jid
               FROM mix_delivery_events event JOIN mix_delivery_recipients recipient USING(event_id)
              WHERE event.event_id=$1",
        )
        .bind(message.item_id)
        .fetch_one(pool)
        .await?;
        assert!(stanza.contains("<nick>Locked Nick</nick>"));
        assert!(!stanza.contains("<jid>"));
        assert_eq!(recipient, ACTOR);
        assert_eq!(
            service
                .publish_message(&message, unexpected_publication_render, None)
                .await?,
            PublicationOutcome::Replay(message.item_id)
        );
        assert_eq!(
            artifacts(pool, channel).await?,
            (
                before.0 + 1,
                before.1 + 1,
                before.2 + 1,
                before.3 + 1,
                before.4
            )
        );
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn destroy_during_publication_is_typed_not_found() -> Result<()> {
    let fixture = Fixture::new().await?;
    let result = async {
        let pool = &fixture.pool;
        let channel = fixture.channel("destroyed-publisher", "visible").await?;
        let message = prepare_message(MixChannelId::new(channel))?;
        let event = message.item_id;
        let mut destroy = pool.begin().await?;
        let blocker = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *destroy)
            .await?;
        sqlx::query("DELETE FROM mix_channels WHERE id=$1")
            .bind(channel)
            .execute(&mut *destroy)
            .await?;
        let service = publication_service(&fixture)?;
        let task = tokio::spawn(async move {
            service
                .publish_message(&message, unexpected_publication_render, None)
                .await
        });
        crate::support::blocked_backend(pool, blocker).await;
        destroy.commit().await?;
        assert_eq!(task.await??, PublicationOutcome::Absent);
        let projected: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mix_delivery_events WHERE event_id=$1)",
        )
        .bind(event)
        .fetch_one(pool)
        .await?;
        assert!(!projected);
        Ok(())
    }
    .await;
    fixture.close().await?;
    result
}
