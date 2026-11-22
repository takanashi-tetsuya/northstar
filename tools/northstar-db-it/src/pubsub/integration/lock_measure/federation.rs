use super::Scenario;
use anyhow::Result;
use northstar_archive_application::{
    FederatedMamAdmissionOutcome, FederatedMamOutboxLimits, FederatedMamStreamRequest,
    MamArchiveQuery, MamRoomReadAuthority, MamRsmPage, MamService,
};
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_postgres::effects::RoomEffects;
use northstar_workflows::{
    mam_repository::PostgresMamRepository, room_effects::WorkflowRoomEffects,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const WORKERS: usize = 8;
const OPS_PER_WORKER: usize = 32;
const BACKLOG_PAIRS: usize = 128;
const OUTBOX_ADVISORY_KEY: i64 = 0x4e53_5332_534f_5554;
const DOMAIN: &str = "remote-0.measure.invalid";
const LIMITS: FederatedMamOutboxLimits = FederatedMamOutboxLimits {
    ttl_seconds: 3600,
    max_rows: 4_096,
    max_bytes: 4 * 1024 * 1024,
    max_per_domain: 4_096,
};
const POLICY: S2sOutboxPolicy = S2sOutboxPolicy {
    ttl_seconds: LIMITS.ttl_seconds,
    max_rows: LIMITS.max_rows,
    max_bytes: LIMITS.max_bytes,
    max_per_domain: LIMITS.max_per_domain,
};

fn responses(domain: &str, archive_id: Uuid) -> [String; 2] {
    [
        format!("<message xmlns='jabber:server' from='room@conference.local.test' to='viewer@{domain}/Phone'><result xmlns='urn:xmpp:mam:2' id='{archive_id}'/></message>"),
        "<iq xmlns='jabber:server' type='result' id='fin'><fin xmlns='urn:xmpp:mam:2'/></iq>".to_owned(),
    ]
}

async fn enqueue_pair(tx: &mut Transaction<'_, Postgres>, domain: &str) -> Result<()> {
    for stanza in responses(domain, Uuid::nil()) {
        WorkflowRoomEffects
            .enqueue_federated_stanza(tx, domain, &stanza, None, POLICY)
            .await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Phase {
    SingleWriter,
    SameDomain,
    DifferentDomains,
    RoomSnapshots,
}

#[derive(Debug)]
enum Operation {
    ReadCommitted,
    QueuedOnce,
    QueuedAfterRetry,
    RejectedAfterRetry,
}

async fn measure_operation(pool: PgPool, phase: Phase, worker: usize) -> Result<Operation> {
    let domain = match phase {
        Phase::DifferentDomains | Phase::RoomSnapshots => {
            format!("remote-{worker}.measure.invalid")
        }
        Phase::SingleWriter | Phase::SameDomain => DOMAIN.to_owned(),
    };
    if !matches!(phase, Phase::RoomSnapshots) || worker.is_multiple_of(2) {
        let mut tx = pool.begin().await?;
        enqueue_pair(&mut tx, &domain).await?;
        tx.commit().await?;
        return Ok(Operation::ReadCommitted);
    }

    let (wake, mut receiver) = tokio::sync::mpsc::channel(2);
    let service = MamService::new(PostgresMamRepository::new(pool), LIMITS, wake);
    let room = format!("measure-room-{worker}");
    let authority = MamRoomReadAuthority {
        full_jid: format!("viewer@{domain}/Phone"),
        occupancy: None,
    };
    let query = MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page: MamRsmPage::First,
        max: 1,
    };
    let mut renders = 0;
    let outcome = service
        .admit_federated_room_stream(
            FederatedMamStreamRequest::new(&domain, &room, &authority, &query),
            |page| {
                renders += 1;
                anyhow::ensure!(page.rows().len() == 1, "expected one measured MAM result");
                Ok(responses(&domain, page.rows()[0].id()).into())
            },
        )
        .await?;
    if outcome == FederatedMamAdmissionOutcome::Queued {
        receiver.try_recv()?;
    }
    anyhow::ensure!(receiver.try_recv().is_err(), "unexpected measured wake");
    match (outcome, renders) {
        (FederatedMamAdmissionOutcome::Queued, 1) => Ok(Operation::QueuedOnce),
        (FederatedMamAdmissionOutcome::Queued, 2) => Ok(Operation::QueuedAfterRetry),
        (FederatedMamAdmissionOutcome::OutboxRejected, 2) => Ok(Operation::RejectedAfterRetry),
        _ => anyhow::bail!("unexpected measured outcome: {outcome:?}, {renders} renders"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn federation_enqueue_generation_contention() {
    let mut scenario =
        Scenario::new("federation_enqueue_generation_contention", WORKERS as u32).await;
    scenario.sample_advisory_key = Some(OUTBOX_ADVISORY_KEY);
    let pool = &scenario.pool;
    let domains: Vec<_> = (0..WORKERS)
        .map(|worker| format!("remote-{worker}.measure.invalid"))
        .collect();
    for worker in (1..WORKERS).step_by(2) {
        let room: Uuid = sqlx::query_scalar(
            "INSERT INTO muc_rooms(id,localpart,occupant_id_secret)
             VALUES(gen_random_uuid(),$1,$2) RETURNING id",
        )
        .bind(format!("measure-room-{worker}"))
        .bind(vec![7_u8; 32])
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
             VALUES(gen_random_uuid(),$1,'sender@remote.test/Phone','Sender','<message/>',
                    FALSE,'discussion','sender@remote.test')",
        )
        .bind(room)
        .execute(pool)
        .await
        .unwrap();
    }

    for (label, phase, concurrency) in [
        ("rc-uncontended", Phase::SingleWriter, 1),
        ("rc-same-domain", Phase::SameDomain, WORKERS),
        ("rc-different-domains", Phase::DifferentDomains, WORKERS),
        ("rc-with-rr-mam", Phase::RoomSnapshots, WORKERS),
    ] {
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM s2s_outbox")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "measurement requires an empty isolated S2S outbox");
        let mut backlog = pool.begin().await.unwrap();
        for _ in 0..BACKLOG_PAIRS {
            enqueue_pair(&mut backlog, DOMAIN).await.unwrap();
        }
        backlog.commit().await.unwrap();
        let workers = pool.clone();
        scenario
            .run(
                label,
                concurrency,
                OPS_PER_WORKER,
                move |worker, _| measure_operation(workers.clone(), phase, worker),
                move |operation| {
                    matches!(phase, Phase::RoomSnapshots)
                        || matches!(operation, Operation::ReadCommitted)
                },
            )
            .await;
        sqlx::query("DELETE FROM s2s_outbox WHERE target_domain=ANY($1::text[])")
            .bind(&domains)
            .execute(pool)
            .await
            .unwrap();
    }
    scenario.close().await;
}
