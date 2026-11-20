use northstar_room_application::mix_service::{MixPayloads, MixPublisherIdentity};
use northstar_room_postgres::mix::*;
use northstar_workflows::room_effects::WorkflowRoomEffects;
use sqlx::PgPool;
use uuid::Uuid;

const CHANNEL: Uuid = Uuid::from_u128(0x573_1801);
const ACTOR: &str = "producer@remote.test";
const ITEM: &str = "00000000-0000-0000-0000-000005731802";

const ABSENT_PUBLISHER: MixPublisherIdentity = MixPublisherIdentity {
    archive_jid_visible: true,
    nick: None,
    participant_id: Uuid::nil(),
};

async fn producer(pool: &PgPool, label: &str) -> anyhow::Result<()> {
    let effects = WorkflowRoomEffects;
    let payloads = MixPayloads;
    match label {
        "destroy" => {
            destroy_mix_channel(&effects, pool, CHANNEL, ACTOR, &payloads, None).await?;
        }
        "join" => {
            join_mix_channel(
                &effects,
                pool,
                CHANNEL,
                JoinMixRequest {
                    actor_jid: ACTOR,
                    nick: Some("Producer"),
                    nodes: &[],
                    pam_user_id: None,
                    invitation: None,
                    preference: None,
                    anonymous_profile: false,
                },
                &payloads,
                None,
            )
            .await?;
        }
        "expire presence" => {
            expire_unrefreshed_mix_presence(
                pool,
                northstar_time::DateTime::from_timestamp(0, 0).unwrap(),
                &payloads,
            )
            .await?;
        }
        "subscriptions" => {
            update_mix_subscriptions(&effects, pool, CHANNEL, ACTOR, &[], &[], &payloads, None)
                .await?;
        }
        "nickname" => {
            let _ =
                set_mix_nick(&effects, pool, CHANNEL, ACTOR, "Producer", &payloads, None).await?;
        }
        "leave" => {
            leave_mix_channel(&effects, pool, CHANNEL, ACTOR, None, &payloads, None).await?;
        }
        "presence wrapper" => {
            store_mix_presence(
                pool,
                CHANNEL,
                ACTOR,
                "producer@remote.test/phone",
                "<presence/>",
                false,
                &payloads,
            )
            .await?;
        }
        "presence absent wrapper" => {
            ensure_mix_presence(
                pool,
                CHANNEL,
                ACTOR,
                "producer@remote.test/phone",
                "<presence/>",
                &payloads,
            )
            .await?;
        }
        "presence transaction" => {
            store_mix_presence_with_policy(
                pool,
                CHANNEL,
                ACTOR,
                "producer@remote.test/phone",
                "<presence/>",
                false,
                false,
                &payloads,
            )
            .await?;
        }
        "message wrapper" => {
            store_mix_message(
                pool,
                CHANNEL,
                ACTOR,
                ITEM,
                "<body>producer</body>",
                None,
                "<body>producer</body>",
                &ABSENT_PUBLISHER,
                None,
                false,
                &payloads,
            )
            .await?;
        }
        "message transaction" => {
            store_mix_message_inner(
                pool,
                CHANNEL,
                ACTOR,
                ITEM,
                "<body>producer</body>",
                None,
                "<body>producer</body>",
                &ABSENT_PUBLISHER,
                None,
                false,
                &payloads,
                None,
            )
            .await?;
        }
        "publish avatar" => {
            publish_mix_avatar(
                &effects,
                pool,
                CHANNEL,
                ACTOR,
                NODE_AVATAR_DATA,
                "avatar",
                "<data/>",
                &payloads,
                None,
            )
            .await?;
        }
        "retract avatar" => {
            retract_mix_avatar(
                &effects,
                pool,
                CHANNEL,
                ACTOR,
                NODE_AVATAR_DATA,
                "avatar",
                &payloads,
                None,
            )
            .await?;
        }
        "information" => {
            update_mix_info(
                &effects,
                pool,
                CHANNEL,
                ACTOR,
                MixInfoUpdate {
                    item_id: "info",
                    expected_revision: 0,
                    name: Some("Producer"),
                    description: None,
                    contacts: &[],
                },
                &payloads,
                None,
            )
            .await?;
        }
        "configuration" => {
            update_mix_config(
                &effects,
                pool,
                CHANNEL,
                ACTOR,
                MixConfigUpdate {
                    item_id: "config",
                    expected_revision: 0,
                    access_model: "open",
                    jid_visibility: "visible",
                    nick_required: false,
                    max_participants: 10,
                    max_events: 100,
                    allow_private_messages: true,
                    allow_participant_invites: false,
                    allow_user_message_retraction: false,
                    administrator_retraction_rights: "owners",
                    enforce_registered_nick: false,
                },
                MixRoleUpdate {
                    owners: None,
                    administrators: None,
                },
                &payloads,
                None,
            )
            .await?;
        }
        "access list" => {
            set_mix_access_entry(
                &effects,
                pool,
                MixAccessEntryUpdate {
                    channel_id: CHANNEL,
                    actor: ACTOR,
                    pattern: "other@remote.test",
                    list: MixAccessList::Allowed,
                    operation: MixAccessEntryOperation::Publish { reason: None },
                },
                &payloads,
                None,
            )
            .await?;
        }
        "registered nickname" => {
            register_mix_nick(
                &effects,
                pool,
                "mix.example.test",
                ACTOR,
                "Producer",
                &payloads,
                None,
            )
            .await?;
        }
        "participant preference" => {
            update_mix_participant_preference(
                &effects,
                pool,
                CHANNEL,
                ACTOR,
                &MixParticipantPreference::default(),
                &payloads,
                None,
            )
            .await?;
        }
        "message retraction" => {
            retract_mix_message(
                pool,
                CHANNEL,
                ACTOR,
                Uuid::from_u128(0x573_1802),
                Uuid::from_u128(0x573_1803),
                "<retracted/>",
                "<retract/>",
                None,
                &ABSENT_PUBLISHER,
                None,
                &payloads,
            )
            .await?;
        }
        "dead letter requeue" => {
            requeue_mix_delivery_dead_letter(pool, Uuid::from_u128(0x573_1804)).await?;
        }
        _ => panic!("unknown producer case: {label}"),
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn producers_and_wrappers_take_the_delivery_fence_before_business_rows() {
    let pool = crate::support::operation_mutation_pool().await;
    sqlx::query("INSERT INTO mix_channels(id,service_domain,localpart,creator_jid,access_model) VALUES($1,'mix.example.test','producer-fence','owner@remote.test','allowlist')")
        .bind(CHANNEL).execute(&pool).await.unwrap();
    for label in [
        "destroy",
        "join",
        "expire presence",
        "subscriptions",
        "nickname",
        "leave",
        "presence wrapper",
        "presence absent wrapper",
        "presence transaction",
        "message wrapper",
        "message transaction",
        "publish avatar",
        "retract avatar",
        "information",
        "configuration",
        "access list",
        "registered nickname",
        "participant preference",
        "message retraction",
        "dead letter requeue",
    ] {
        let (mut fence, _proof) = begin_mix_delivery_fenced_transaction(&pool).await.unwrap();
        let fence_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *fence)
            .await
            .unwrap();
        let mut business = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM mix_channels WHERE id=$1 FOR UPDATE")
            .bind(CHANNEL)
            .fetch_one(&mut *business)
            .await
            .unwrap();
        let producer_pool = pool.clone();
        let task = tokio::spawn(async move { producer(&producer_pool, label).await });
        let waiting = crate::support::blocked_backend(&pool, fence_pid).await;
        assert_ne!(waiting, fence_pid, "{label}");
        business.rollback().await.unwrap();
        // Releasing the candidate row must not let the waiting producer take
        // it while another session still owns the delivery fence.
        let mut probe = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM mix_channels WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(CHANNEL)
            .fetch_one(&mut *probe)
            .await
            .expect(label);
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mix_events WHERE channel_id=$1")
            .bind(CHANNEL)
            .fetch_one(&mut *probe)
            .await
            .unwrap();
        assert_eq!(events, 0, "{label}: no mutation before the fence");
        probe.rollback().await.unwrap();
        fence.commit().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .expect(label);
    }
    sqlx::query("DELETE FROM mix_channels WHERE id=$1")
        .bind(CHANNEL)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn committed_reconciliation_survives_a_refused_message_producer() {
    let pool = crate::support::operation_mutation_pool().await;
    let channel = Uuid::from_u128(0x573_1902);
    sqlx::query("INSERT INTO mix_channels(id,service_domain,localpart,creator_jid) VALUES($1,'mix.example.test','reconcile-producer','owner@remote.test')")
        .bind(channel).execute(&pool).await.unwrap();
    let orphan = Uuid::from_u128(0x573_1901);
    let (mut tx, fence) = begin_mix_delivery_admission(&pool).await.unwrap();
    sqlx::query("INSERT INTO mix_delivery_events(event_id,channel_id,channel_jid,stanza_template,archive,encrypted) VALUES($1,$2,'reconcile-producer@mix.example.test','<message/>',FALSE,FALSE)")
        .bind(orphan).bind(channel).execute(&mut *tx).await.unwrap();
    let mut deltas = std::collections::BTreeMap::new();
    add_mix_delivery_capacity_delta(&mut deltas, mix_delivery_capacity_bucket(orphan), 0, 10)
        .unwrap();
    reserve_mix_delivery_capacity_tx(&mut tx, &fence, &deltas)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let result = store_mix_message(
        &pool,
        channel,
        ACTOR,
        ITEM,
        "<body>refused</body>",
        None,
        "<body>refused</body>",
        &ABSENT_PUBLISHER,
        None,
        false,
        &MixPayloads,
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, StoreEventOutcome::NotParticipant);
    let mut observer = pool.acquire().await.unwrap();
    let remains: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mix_delivery_events WHERE event_id=$1)")
            .bind(orphan)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert!(
        !remains,
        "producer rollback did not resurrect the reconciled orphan"
    );
    let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mix_events WHERE channel_id=$1")
        .bind(channel)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
    assert_eq!(messages, 0, "refused mutation stayed rolled back");
    drop(observer);
    audit_mix_delivery_capacity_ledger(&pool).await.unwrap();
    sqlx::query("DELETE FROM mix_channels WHERE id=$1")
        .bind(channel)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn wrappers_preserve_original_presence_and_message_projections_after_the_fence() {
    let pool = crate::support::operation_mutation_pool().await;
    for (label, localpart) in [
        ("presence wrapper", "wrapper-presence"),
        ("presence absent wrapper", "wrapper-absent"),
        ("message wrapper", "wrapper-message"),
    ] {
        let (created, _) = create_mix_channel(
            &WorkflowRoomEffects,
            &pool,
            "mix.example.test",
            Some(localpart),
            ACTOR,
            100,
            &MixPayloads,
            None,
        )
        .await
        .unwrap();
        let CreateChannelOutcome::Created(channel) = created else {
            panic!("{label}: fixture channel was not created");
        };
        let nodes = vec![NODE_MESSAGES.to_owned(), NODE_PRESENCE.to_owned()];
        let JoinChannelOutcome::Joined { participant, .. } = join_mix_channel(
            &WorkflowRoomEffects,
            &pool,
            channel,
            JoinMixRequest {
                actor_jid: ACTOR,
                nick: Some("Original"),
                nodes: &nodes,
                pam_user_id: None,
                invitation: None,
                preference: None,
                anonymous_profile: false,
            },
            &MixPayloads,
            None,
        )
        .await
        .unwrap() else {
            panic!("{label}: fixture participant did not join");
        };
        sqlx::query("DELETE FROM mix_delivery_recipients WHERE event_id IN (SELECT event_id FROM mix_delivery_events WHERE channel_id=$1)")
            .bind(channel).execute(&pool).await.unwrap();
        reconcile_mix_delivery_capacity_committed(&pool)
            .await
            .unwrap();
        let (mut blocker, _proof) = begin_mix_delivery_fenced_transaction(&pool).await.unwrap();
        let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let writer_pool = pool.clone();
        let channel_state = mix_channel_by_id(&pool, channel).await.unwrap().unwrap();
        let publisher_identity = MixPublisherIdentity::from_state(&channel_state, &participant);
        let writer = tokio::spawn(async move {
            match label {
                "message wrapper" => {
                    let saved = store_mix_message(
                        &writer_pool,
                        channel,
                        ACTOR,
                        ITEM,
                        "<body>original archive</body>",
                        None,
                        "<body>original delivery</body>",
                        &publisher_identity,
                        Some(ACTOR),
                        true,
                        &MixPayloads,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        saved.outcome,
                        StoreEventOutcome::Stored(Uuid::from_u128(0x573_1802))
                    );
                }
                "presence wrapper" => assert!(matches!(
                    store_mix_presence(
                        &writer_pool,
                        channel,
                        ACTOR,
                        "producer@remote.test/phone",
                        "<show>away</show>",
                        false,
                        &MixPayloads
                    )
                    .await
                    .unwrap(),
                    PresenceOutcome::Published
                )),
                "presence absent wrapper" => assert!(matches!(
                    ensure_mix_presence(
                        &writer_pool,
                        channel,
                        ACTOR,
                        "producer@remote.test/phone",
                        "<show>away</show>",
                        &MixPayloads
                    )
                    .await
                    .unwrap(),
                    PresenceOutcome::Published
                )),
                _ => unreachable!(),
            }
        });
        crate::support::blocked_backend(&pool, blocker_pid).await;
        let mut observer = pool.acquire().await.unwrap();
        let before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mix_events WHERE channel_id=$1 AND node=ANY($2::text[])",
        )
        .bind(channel)
        .bind(&nodes)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            before, 0,
            "{label}: wrapper has no projection before the fence"
        );
        drop(observer);
        blocker.commit().await.unwrap();
        writer.await.unwrap();
        let mut observer = pool.acquire().await.unwrap();
        let (payload, source): (String, Option<String>) = sqlx::query_as(
            "SELECT payload,source_full_jid FROM mix_events WHERE channel_id=$1 AND node=$2",
        )
        .bind(channel)
        .bind(if label == "message wrapper" {
            NODE_MESSAGES
        } else {
            NODE_PRESENCE
        })
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        if label == "message wrapper" {
            assert_eq!(payload, "<body>original archive</body>");
        } else {
            assert_eq!(payload, "<show>away</show>");
            assert_eq!(source.as_deref(), Some("producer@remote.test/phone"));
        }
        let rows: Vec<(String, Uuid, String, Option<Uuid>, String, bool)> = sqlx::query_as(
            "SELECT e.channel_jid,r.recipient_participant_id,r.recipient_jid,e.authoritative_stanza_id,e.stanza_template,e.encrypted
             FROM mix_delivery_events e JOIN mix_delivery_recipients r USING(event_id) WHERE e.channel_id=$1",
        ).bind(channel).fetch_all(&mut *observer).await.unwrap();
        assert_eq!(rows.len(), 1, "{label}: one original audience");
        let (jid, recipient, bare, authoritative_id, template, encrypted) = &rows[0];
        if label == "message wrapper" {
            assert!(*encrypted, "{label}: original encryption flag");
        }
        assert_eq!(jid, &format!("{localpart}@mix.example.test"), "{label}");
        assert_eq!(*recipient, participant.participant_id, "{label}");
        assert_eq!(bare, ACTOR, "{label}");
        assert_eq!(
            *authoritative_id,
            (label == "message wrapper").then_some(Uuid::from_u128(0x573_1802)),
            "{label}"
        );
        assert!(
            template.contains(if label == "message wrapper" {
                "original delivery"
            } else {
                "away"
            }),
            "{label}: original delivery payload"
        );
        drop(observer);
        sqlx::query("DELETE FROM mix_delivery_recipients WHERE event_id IN (SELECT event_id FROM mix_delivery_events WHERE channel_id=$1)")
            .bind(channel).execute(&pool).await.unwrap();
        reconcile_mix_delivery_capacity_committed(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM mix_channels WHERE id=$1")
            .bind(channel)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}
