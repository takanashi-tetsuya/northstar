//! Fixtures shared by the PostgreSQL transport receipt tests.
use northstar_delivery_core::{
    bosh_ownership::{self, response},
    native_write, DurableDelivery, MixDelivery, TransportOwnershipSource,
};
use northstar_room_postgres::mix as db;
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) async fn seed_c2s(pool: &PgPool, source: DurableDelivery) {
    sqlx::query(
        "INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,
             delivery_claim_id,delivery_claim_expires_at)
         VALUES($1,$2,'peer@remote.test','<message/>',FALSE,$3,
             CASE WHEN $3::uuid IS NULL THEN NULL
                  ELSE clock_timestamp()+INTERVAL '5 minutes' END)",
    )
    .bind(source.message_id)
    .bind(source.recipient_id)
    .bind(source.claim_id)
    .execute(pool)
    .await
    .unwrap();
}

pub(crate) async fn seed_mix(pool: &PgPool, base: u128) -> (Uuid, MixDelivery) {
    let event = Uuid::from_u128(base);
    let source = MixDelivery {
        delivery_id: Uuid::from_u128(base + 1),
        lease_token: Uuid::from_u128(base + 2),
    };
    let stanza = "<message xmlns='jabber:client' type='groupchat'><body>receipt</body></message>";
    let recipient = format!("transport-{base}@example.test");
    let (mut tx, fence) = db::begin_mix_delivery_admission(pool).await.unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_events(event_id,channel_id,channel_jid,stanza_template,
             authoritative_stanza_id,archive,encrypted)
         VALUES($1,$2,'receipts@mix.example.test',$3,NULL,FALSE,FALSE)",
    )
    .bind(event)
    .bind(Uuid::from_u128(base + 3))
    .bind(stanza)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_delivery_recipients(delivery_id,event_id,recipient_participant_id,
             recipient_jid,delivery_sequence,lease_token,lease_until)
         VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(source.delivery_id)
    .bind(event)
    .bind(Uuid::from_u128(base + 4))
    .bind(&recipient)
    .bind(source.lease_token)
    .execute(&mut *tx)
    .await
    .unwrap();
    let mut deltas = BTreeMap::new();
    db::add_mix_delivery_capacity_delta(
        &mut deltas,
        db::mix_delivery_capacity_bucket(event),
        0,
        i64::try_from(stanza.len()).unwrap(),
    )
    .unwrap();
    db::add_mix_delivery_capacity_delta(
        &mut deltas,
        db::mix_delivery_capacity_bucket(source.delivery_id),
        1,
        i64::try_from(recipient.len() + 128).unwrap(),
    )
    .unwrap();
    db::reserve_mix_delivery_capacity_tx(&mut tx, &fence, &deltas)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (event, source)
}

pub(crate) fn native_ack(
    source: TransportOwnershipSource,
) -> (native_write::Observation, native_write::AckRequest) {
    let observation = native_write::Observation::new(Some(source));
    observation.begin_record(Some(source)).unwrap();
    assert_eq!(observation.recorded(false).unwrap(), Some(source));
    observation.fenced(source).unwrap();
    observation.begin_write().unwrap();
    let written = observation
        .writer_completed(native_write::WriterResult::FullWrite)
        .unwrap()
        .unwrap();
    let request = written.begin_ack().unwrap().unwrap();
    (observation, request)
}

pub(crate) fn bosh_operation(session: Uuid, ttl_seconds: u64) -> bosh_ownership::Operation {
    bosh_ownership::Operation::new(bosh_ownership::Scope {
        session_id: session,
        ttl_seconds,
        kind: bosh_ownership::OperationKind::Request,
    })
}

pub(crate) fn bosh_bind(
    operation: &bosh_ownership::Operation,
    rid: u64,
    sources: Vec<TransportOwnershipSource>,
) -> response::BindRequest {
    let mut lineage = vec![None];
    lineage.extend(sources.iter().copied().map(Some));
    operation
        .begin_response(rid, response::ResponseKind::Payload, lineage.clone())
        .unwrap()
        .attempt(sources, lineage.into_iter())
        .unwrap()
}
