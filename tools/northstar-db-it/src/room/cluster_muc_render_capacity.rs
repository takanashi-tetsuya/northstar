use crate::support::{blocked_backend, operation_mutation_pool};
use northstar_room_application::{
    cluster_muc_delivery_item::ItemAdmission, cluster_muc_delivery_read::EventRenderPolicy,
};
use northstar_room_core::{
    occupancy::SerializableMucOccupant,
    stanza::{muc_occupant_id, muc_presence_stanza},
};
use northstar_room_postgres::{
    cluster_muc::{
        ack_cluster_muc_outbox, change_cluster_muc_role, claim_cluster_muc_occupancy,
        claim_cluster_muc_outbox, cluster_muc_delivery_item_completed, cluster_muc_event_context,
        cluster_muc_exact_occupancy_snapshot, complete_cluster_muc_delivery_item,
        expire_due_in_room, reserve_cluster_muc_delivery_item, update_cluster_muc_config,
        ClusterMucAudienceSnapshot, ClusterMucConfigurationOutcome, ClusterMucJoin,
        ClusterMucJoinOutcome, ClusterMucOccupancy, ClusterMucOccupancyTarget,
        ClusterMucOutboxDelivery, ClusterMucPrincipal, ClusterMucTransitionOutcome,
    },
    muc::{delete_expired_locked_muc_rooms, get_or_create_muc_room, MucConfigUpdate, MucRoom},
};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

async fn created_room(pool: &PgPool, localpart: &str) -> (MucRoom, ClusterMucOccupancy) {
    let owner = Uuid::new_v4();
    let bare_jid = format!("{localpart}@example.test");
    let full_jid = format!("{bare_jid}/phone");
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(owner)
        .bind(localpart)
        .execute(pool)
        .await
        .unwrap();
    let (room, created) = get_or_create_muc_room(pool, localpart, owner, &full_jid)
        .await
        .unwrap();
    assert!(created);
    let occupant = join(
        pool,
        &room,
        ClusterMucPrincipal::Local {
            user_id: owner,
            bare_jid,
        },
        &full_jid,
        "Owner",
        localpart,
    )
    .await;
    ack(pool, &claim_one(pool, localpart).await).await;
    (room, occupant)
}

async fn join(
    pool: &PgPool,
    room: &MucRoom,
    principal: ClusterMucPrincipal,
    full_jid: &str,
    nick: &str,
    node: &str,
) -> ClusterMucOccupancy {
    let outcome = claim_cluster_muc_occupancy(
        pool,
        ClusterMucJoin {
            operation_id: Uuid::new_v4(),
            room_id: room.id,
            expected_room_epoch: room.room_epoch,
            expected_config_version: room.config_version,
            principal,
            full_jid,
            nick,
            owner_node_id: node,
            connection_uuid: Uuid::new_v4(),
            connection_epoch: 1,
            sm_session_id: None,
            occupant_incarnation: Uuid::new_v4(),
            presence_payload: "<presence/>",
            lease: Duration::from_secs(300),
        },
    )
    .await
    .unwrap();
    let ClusterMucJoinOutcome::Joined(occupant) = outcome else {
        panic!("fixture join failed: {outcome:?}");
    };
    occupant
}

async fn guest(pool: &PgPool, room: &MucRoom, node: &str) -> ClusterMucOccupancy {
    join(
        pool,
        room,
        ClusterMucPrincipal::Federated {
            bare_jid: "guest@remote.test".into(),
            authenticated_domain: "remote.test".into(),
        },
        "guest@remote.test/phone",
        "Guest",
        node,
    )
    .await
}

async fn observer(pool: &PgPool, room: &MucRoom) -> ClusterMucOccupancy {
    let occupant = join(
        pool,
        room,
        ClusterMucPrincipal::Federated {
            bare_jid: "observer@remote.test".into(),
            authenticated_domain: "remote.test".into(),
        },
        "observer@remote.test/phone",
        "Observer",
        "wp700-observer",
    )
    .await;
    ack(pool, &claim_one(pool, &occupant.owner_node_id).await).await;
    occupant
}

async fn set_whois(
    pool: &PgPool,
    room: &mut MucRoom,
    owner: &ClusterMucOccupancy,
    non_anonymous: bool,
) {
    let outcome = update_cluster_muc_config(
        pool,
        Uuid::new_v4(),
        room.id,
        room.room_epoch,
        room.config_version,
        &ClusterMucOccupancyTarget::from(owner),
        &ClusterMucPrincipal::Local {
            user_id: owner.local_user_id.unwrap(),
            bare_jid: owner.bare_jid.clone(),
        },
        &owner.full_jid,
        MucConfigUpdate {
            title: room.title.as_deref(),
            description: room.description.as_deref(),
            persistent: room.persistent,
            members_only: room.members_only,
            public: room.public,
            moderated: room.moderated,
            non_anonymous,
            max_occupants: room.max_occupants,
            password_hash: room.password_hash.as_deref(),
            allow_subject_change: room.allow_subject_change,
            allow_invites: room.allow_invites,
            allow_private_messages: room.allow_private_messages,
            logging_enabled: room.logging_enabled,
            allow_registration: room.allow_registration,
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, ClusterMucConfigurationOutcome::Applied);
    room.config_version += 1;
}

async fn open_room(
    pool: &PgPool,
    room: &mut MucRoom,
    owner: &ClusterMucOccupancy,
    non_anonymous: bool,
) {
    set_whois(pool, room, owner, non_anonymous).await;
    ack(pool, &claim_one(pool, &owner.owner_node_id).await).await;
}

async fn set_role(
    pool: &PgPool,
    owner: &ClusterMucOccupancy,
    recipient: &ClusterMucOccupancy,
    role: &str,
) {
    let outcome = change_cluster_muc_role(
        pool,
        Uuid::new_v4(),
        &ClusterMucOccupancyTarget::from(owner),
        &ClusterMucOccupancyTarget::from(recipient),
        role,
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome, ClusterMucTransitionOutcome::Applied);
}

async fn claim_one(pool: &PgPool, node: &str) -> ClusterMucOutboxDelivery {
    let mut rows = claim_cluster_muc_outbox(pool, node, 2, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    rows.pop().unwrap()
}

async fn ack(pool: &PgPool, delivery: &ClusterMucOutboxDelivery) {
    assert!(
        ack_cluster_muc_outbox(pool, delivery.delivery_id, delivery.claim_token)
            .await
            .unwrap()
    );
}

async fn drain_join(
    pool: &PgPool,
    recipient: &ClusterMucOccupancy,
    committed: Option<(bool, &str)>,
    current: (bool, &str),
) -> String {
    let delivery = claim_one(pool, &recipient.owner_node_id).await;
    let context = cluster_muc_event_context(pool, delivery.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.operation_kind, "join");
    let policy = EventRenderPolicy::from_details(&context.details);
    let payload: serde_json::Value = serde_json::from_str(&delivery.payload).unwrap();
    let original: ClusterMucAudienceSnapshot =
        serde_json::from_value(payload["original_audience"].clone()).unwrap();
    assert_eq!(
        policy
            .as_ref()
            .map(|fact| (fact.non_anonymous, original.role.as_str())),
        committed
    );
    let recipient =
        cluster_muc_exact_occupancy_snapshot(pool, &ClusterMucOccupancyTarget::from(recipient))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        (context.room_non_anonymous, recipient.role.as_str()),
        current
    );
    let disclose = EventRenderPolicy::discloses_real_jid(
        policy.as_ref(),
        Some(&original.role),
        context.room_non_anonymous,
        Some(&recipient.role),
    );
    let target = context.target.unwrap();
    let subject = SerializableMucOccupant {
        full_jid: target.full_jid,
        room_jid: format!("{}@conference.example.test", context.room_localpart),
        nick: target.nick,
        affiliation: target.affiliation,
        role: target.role,
        room_non_anonymous: context.room_non_anonymous,
        occupant_id: muc_occupant_id(&context.occupant_id_secret, &target.bare_jid),
        cluster_epoch: target.occupant_incarnation,
        connection_id: target.connection_uuid,
        federated_domain: None,
        sm_session_id: None,
        payload: target.presence_payload,
    };
    let stable_id = format!("{}:0", delivery.event_id);
    assert_eq!(
        reserve_cluster_muc_delivery_item(pool, &delivery, 0, &stable_id)
            .await
            .unwrap(),
        ItemAdmission::Ready
    );
    let stanza = muc_presence_stanza(
        &subject,
        &recipient.full_jid,
        false,
        false,
        false,
        None,
        disclose,
    );
    assert!(
        complete_cluster_muc_delivery_item(pool, &delivery, 0, &stable_id)
            .await
            .unwrap()
    );
    ack(pool, &delivery).await;
    stanza
}

fn assert_hidden(stanza: &str) {
    let xml = roxmltree::Document::parse(stanza).unwrap();
    let item = xml
        .descendants()
        .find(|node| node.has_tag_name(("http://jabber.org/protocol/muc#user", "item")))
        .unwrap();
    assert_eq!(item.attribute("jid"), None, "{stanza}");
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn delayed_event_hides_a_real_jid_when_whois_turns_anonymous() {
    let pool = operation_mutation_pool().await;
    let node = "wp700-whois-tightens";
    let (mut room, owner) = created_room(&pool, node).await;
    open_room(&pool, &mut room, &owner, true).await;
    let observer = observer(&pool, &room).await;
    guest(&pool, &room, "wp700-tightens-guest").await;
    set_whois(&pool, &mut room, &owner, false).await;
    assert_hidden(
        &drain_join(
            &pool,
            &observer,
            Some((true, "participant")),
            (false, "participant"),
        )
        .await,
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn delayed_event_hides_a_real_jid_when_the_recipient_is_demoted() {
    let pool = operation_mutation_pool().await;
    let node = "wp700-demoted";
    let (mut room, owner) = created_room(&pool, node).await;
    open_room(&pool, &mut room, &owner, false).await;
    let observer = observer(&pool, &room).await;
    set_role(&pool, &owner, &observer, "moderator").await;
    ack(&pool, &claim_one(&pool, &observer.owner_node_id).await).await;
    guest(&pool, &room, "wp700-demoted-guest").await;
    set_role(&pool, &owner, &observer, "participant").await;
    assert_hidden(
        &drain_join(
            &pool,
            &observer,
            Some((false, "moderator")),
            (false, "participant"),
        )
        .await,
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn delayed_event_keeps_the_committed_hiding_when_policy_relaxes() {
    let pool = operation_mutation_pool().await;
    let node = "wp700-whois-relaxes";
    let (mut room, owner) = created_room(&pool, node).await;
    open_room(&pool, &mut room, &owner, false).await;
    let observer = observer(&pool, &room).await;
    guest(&pool, &room, "wp700-relaxes-guest").await;
    set_whois(&pool, &mut room, &owner, true).await;
    assert_hidden(
        &drain_join(
            &pool,
            &observer,
            Some((false, "participant")),
            (true, "participant"),
        )
        .await,
    );
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn legacy_pending_event_without_render_facts_hides_real_jids() {
    let pool = operation_mutation_pool().await;
    let node = "wp700-legacy";
    let (mut room, owner) = created_room(&pool, node).await;
    open_room(&pool, &mut room, &owner, true).await;
    sqlx::query(
        "CREATE FUNCTION wp700_legacy_muc_render() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN NEW.details := NEW.details - 'render_policy'; RETURN NEW; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER wp700_legacy_muc_render BEFORE INSERT ON cluster_muc_operations
        FOR EACH ROW WHEN (NEW.operation_kind='join' AND NEW.actor_bare_jid='guest-legacy@remote.test')
        EXECUTE FUNCTION wp700_legacy_muc_render()")
        .execute(&pool).await.unwrap();
    join(
        &pool,
        &room,
        ClusterMucPrincipal::Federated {
            bare_jid: "guest-legacy@remote.test".into(),
            authenticated_domain: "remote.test".into(),
        },
        "guest-legacy@remote.test/phone",
        "Guest",
        "wp700-legacy-guest",
    )
    .await;
    sqlx::query("DROP TRIGGER wp700_legacy_muc_render ON cluster_muc_operations")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION wp700_legacy_muc_render()")
        .execute(&pool)
        .await
        .unwrap();
    assert_hidden(&drain_join(&pool, &owner, None, (true, "moderator")).await);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn ordinal_reservation_rejects_a_replaced_claim() {
    let pool = operation_mutation_pool().await;
    let node = "wp700-claim";
    let (mut room, owner) = created_room(&pool, node).await;
    open_room(&pool, &mut room, &owner, false).await;
    guest(&pool, &room, "wp700-claim-guest").await;
    let old = claim_one(&pool, node).await;
    let stable_id = format!("{}:0", old.event_id);
    assert!(
        !cluster_muc_delivery_item_completed(&pool, old.delivery_id, 0, &stable_id)
            .await
            .unwrap()
    );
    let mut blocker = pool.begin().await.unwrap();
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT delivery_id FROM cluster_muc_event_outbox WHERE delivery_id=$1 FOR UPDATE")
        .bind(old.delivery_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let reservation = tokio::spawn({
        let pool = pool.clone();
        let old = old.clone();
        let stable_id = stable_id.clone();
        async move { reserve_cluster_muc_delivery_item(&pool, &old, 0, &stable_id).await }
    });
    blocked_backend(&pool, pid).await;
    let replacement = ClusterMucOutboxDelivery {
        claim_token: Uuid::new_v4(),
        ..old.clone()
    };
    sqlx::query("UPDATE cluster_muc_event_outbox SET claim_token=$2 WHERE delivery_id=$1")
        .bind(old.delivery_id)
        .bind(replacement.claim_token)
        .execute(&mut *blocker)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(reservation.await.unwrap().unwrap(), ItemAdmission::Stale);
    let item_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cluster_muc_event_delivery_items WHERE delivery_id=$1",
    )
    .bind(old.delivery_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(item_rows, 0);
    assert_ne!(replacement.claim_token, old.claim_token);
    assert_eq!(
        reserve_cluster_muc_delivery_item(&pool, &old, 0, &stable_id)
            .await
            .unwrap(),
        ItemAdmission::Stale
    );
    assert_eq!(
        reserve_cluster_muc_delivery_item(&pool, &replacement, 0, &stable_id)
            .await
            .unwrap(),
        ItemAdmission::Ready
    );
    assert!(
        !complete_cluster_muc_delivery_item(&pool, &old, 0, &stable_id)
            .await
            .unwrap()
    );
    assert!(
        complete_cluster_muc_delivery_item(&pool, &replacement, 0, &stable_id)
            .await
            .unwrap()
    );
    assert_eq!(
        reserve_cluster_muc_delivery_item(&pool, &replacement, 0, &stable_id)
            .await
            .unwrap(),
        ItemAdmission::Completed
    );
    ack(&pool, &replacement).await;
    pool.close().await;
}

async fn due_room(pool: &PgPool, localpart: &str, seconds_ago: i32) -> MucRoom {
    let (room, _) = created_room(pool, localpart).await;
    sqlx::query("UPDATE muc_rooms SET configuration_expires_at=clock_timestamp()-make_interval(secs=>$2) WHERE id=$1")
        .bind(room.id).bind(f64::from(seconds_ago)).execute(pool).await.unwrap();
    room
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn multi_event_transaction_locks_capacity_shards_in_ascending_order() {
    let pool = operation_mutation_pool().await;
    let first = due_room(&pool, "wp700-high-first", 120).await;
    let second = due_room(&pool, "wp700-low-second", 60).await;
    let (mut competing, owner) = created_room(&pool, "wp700-competing").await;
    open_room(&pool, &mut competing, &owner, false).await;
    let expired = guest(&pool, &competing, "wp700-competing-guest").await;
    ack(&pool, &claim_one(&pool, "wp700-competing").await).await;
    sqlx::query("UPDATE cluster_muc_occupancies SET lease_until=clock_timestamp() WHERE room_id=$1 AND occupant_incarnation=$2")
        .bind(competing.id).bind(expired.occupant_incarnation).execute(&pool).await.unwrap();
    sqlx::query(
        "CREATE FUNCTION wp700_sweep_shards() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN NEW.capacity_shard := CASE NEW.recipient_nick WHEN 'Owner' THEN
          CASE NEW.target_node_id WHEN 'wp700-high-first' THEN 63 ELSE 0 END
          ELSE NEW.capacity_shard END; RETURN NEW; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER a_wp700_sweep_shards BEFORE INSERT ON cluster_muc_event_outbox
        FOR EACH ROW WHEN (NEW.target_node_id IN ('wp700-high-first','wp700-low-second'))
        EXECUTE FUNCTION wp700_sweep_shards()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM muc_rooms WHERE id=$1 FOR UPDATE")
        .bind(competing.id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT shard FROM cluster_muc_outbox_capacity WHERE shard=0 FOR UPDATE")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let sweep = tokio::spawn({
        let pool = pool.clone();
        async move { delete_expired_locked_muc_rooms(&pool, 2).await }
    });
    let waiter = blocked_backend(&pool, pid).await;
    let waiting: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=$1 AND NOT granted)")
            .bind(waiter)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(waiting);
    let mut observer = pool.begin().await.unwrap();
    let unlocked: Vec<i16> = sqlx::query_scalar(
        "SELECT shard FROM cluster_muc_outbox_capacity WHERE shard>0 ORDER BY shard FOR UPDATE NOWAIT",
    )
    .fetch_all(&mut *observer)
    .await
    .expect("the sweep locked a higher shard before shard 0");
    assert_eq!(unlocked, (1..64).collect::<Vec<i16>>());
    observer.rollback().await.unwrap();
    assert_eq!(
        expire_due_in_room(&mut blocker, competing.id)
            .await
            .unwrap(),
        1
    );
    blocker.commit().await.unwrap();
    assert_eq!(
        sweep
            .await
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|retirement| retirement.localpart)
            .collect::<Vec<_>>(),
        [first.localpart, second.localpart]
    );
    let queued: Vec<(Uuid, i16)> = sqlx::query_as("SELECT room_id,capacity_shard FROM cluster_muc_event_outbox WHERE room_id IN ($1,$2) ORDER BY capacity_shard")
        .bind(first.id).bind(second.id).fetch_all(&pool).await.unwrap();
    assert_eq!(queued, [(second.id, 0), (first.id, 63)]);
    let competing_delivery = claim_one(&pool, "wp700-competing").await;
    assert_eq!(
        cluster_muc_event_context(&pool, competing_delivery.operation_id)
            .await
            .unwrap()
            .unwrap()
            .operation_kind,
        "expire"
    );
    sqlx::query("DROP TRIGGER a_wp700_sweep_shards ON cluster_muc_event_outbox")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION wp700_sweep_shards()")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn capacity_refusal_rolls_back_the_whole_multi_event_transaction() {
    let pool = operation_mutation_pool().await;
    let first = due_room(&pool, "wp700-rollback-first", 120).await;
    let second = due_room(&pool, "wp700-rollback-second", 60).await;
    sqlx::query(
        "INSERT INTO cluster_muc_room_outbox_capacity(room_id,queued_rows) VALUES($1,10000)",
    )
    .bind(second.id)
    .execute(&pool)
    .await
    .unwrap();
    let rooms = vec![first.id, second.id];
    let sequences = "SELECT next_event_sequence FROM muc_rooms WHERE id=ANY($1) ORDER BY id";
    let sequences_before: Vec<i64> = sqlx::query_scalar(sequences)
        .bind(&rooms)
        .fetch_all(&pool)
        .await
        .unwrap();
    let shards = "SELECT queued_rows FROM cluster_muc_outbox_capacity ORDER BY shard";
    let before: Vec<i64> = sqlx::query_scalar(shards).fetch_all(&pool).await.unwrap();
    let error = delete_expired_locked_muc_rooms(&pool, 2).await.unwrap_err();
    assert!(format!("{error:#}").contains("cluster_muc_room_outbox_capacity"));
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM muc_rooms WHERE id=ANY($1) AND destroyed_at IS NULL AND configuration_state='locked'")
        .bind(&rooms).fetch_one(&pool).await.unwrap();
    let occupants: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cluster_muc_occupancies WHERE room_id=ANY($1) AND state='active'",
    )
    .bind(&rooms)
    .fetch_one(&pool)
    .await
    .unwrap();
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM cluster_muc_operations WHERE room_id=ANY($1) AND operation_kind='locked_expiry'")
        .bind(&rooms).fetch_one(&pool).await.unwrap();
    let deliveries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cluster_muc_event_outbox WHERE room_id=ANY($1)")
            .bind(&rooms)
            .fetch_one(&pool)
            .await
            .unwrap();
    let after: Vec<i64> = sqlx::query_scalar(shards).fetch_all(&pool).await.unwrap();
    let sequences_after: Vec<i64> = sqlx::query_scalar(sequences)
        .bind(&rooms)
        .fetch_all(&pool)
        .await
        .unwrap();
    let room_ledgers: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT room_id,queued_rows FROM cluster_muc_room_outbox_capacity WHERE room_id=ANY($1)",
    )
    .bind(&rooms)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!((live, occupants, events, deliveries), (2, 2, 0, 0));
    assert_eq!(after, before);
    assert_eq!(sequences_after, sequences_before);
    assert_eq!(room_ledgers, [(second.id, 10000)]);
    sqlx::query("DELETE FROM cluster_muc_room_outbox_capacity WHERE room_id=$1")
        .bind(second.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        delete_expired_locked_muc_rooms(&pool, 2)
            .await
            .unwrap()
            .into_iter()
            .map(|retirement| retirement.localpart)
            .collect::<Vec<_>>(),
        [first.localpart, second.localpart]
    );
    pool.close().await;
}
