use super::replay_store::{Call, Outcome, ReplayStore};
use crate::response_owner::{ReplayPort, ServiceReplay};
use anyhow::Result;
use northstar_delivery_core::bosh_ownership::{
    response::{BindKnowledge, Knowledge, ResponseKind},
    BoshResponseOwnership, Operation, OperationKind, Scope,
};
use northstar_delivery_core::{DurableDelivery, MixDelivery, TransportOwnershipSource as Source};
use northstar_session_application::replay::ReplayService;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use uuid::Uuid;

fn drive_call<T>(
    future: impl Future<Output = Result<T>>,
    outcome: Outcome,
    label: &str,
) -> Option<T> {
    let mut future = Box::pin(future);
    let result = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    match (outcome, result) {
        (Outcome::Committed, Poll::Ready(Ok(value))) => Some(value),
        (Outcome::Rejected, Poll::Ready(Err(error))) => {
            let error = error.downcast_ref::<std::io::Error>().expect(label);
            assert_eq!(error.kind(), std::io::ErrorKind::Other, "{label}");
            assert_eq!(error.to_string(), "recorded replay failure", "{label}");
            None
        }
        (Outcome::Pending, Poll::Pending) => None,
        _ => panic!("{label}: service changed the repository result"),
    }
}

#[test]
fn replay_port_forwards_original_requests_results_and_cancellation_through_service() {
    for (label, outcome, session_id, ttl_seconds, rid) in [
        ("committed requests", Outcome::Committed, 7001, 91, 41),
        ("repository errors", Outcome::Rejected, 7002, 173, 73),
        ("cancelled requests", Outcome::Pending, 7003, 281, 106),
    ] {
        let session_id = Uuid::from_u128(session_id);
        let scope = Scope {
            session_id,
            ttl_seconds,
            kind: OperationKind::Request,
        };
        let operation = Operation::new(scope);
        let sources = vec![
            Source::Mix(MixDelivery {
                delivery_id: Uuid::from_u128(8101),
                lease_token: Uuid::from_u128(8102),
            }),
            Source::C2s(DurableDelivery {
                recipient_id: Uuid::from_u128(8201),
                message_id: Uuid::from_u128(8202),
                claim_id: Some(Uuid::from_u128(8203)),
            }),
            Source::C2s(DurableDelivery {
                recipient_id: Uuid::from_u128(8301),
                message_id: Uuid::from_u128(8302),
                claim_id: None,
            }),
        ];
        let ownership = BoshResponseOwnership {
            c2s_message_ids: vec![Uuid::from_u128(8202), Uuid::from_u128(8302)],
            mix_delivery_ids: vec![Uuid::from_u128(8101)],
        };
        let build = operation
            .begin_response(
                rid,
                ResponseKind::Payload,
                sources.iter().copied().map(Some).collect(),
            )
            .unwrap();
        let bind = build
            .attempt(sources.clone(), sources.iter().copied().map(Some))
            .unwrap();
        let renewal = operation
            .begin_renew(Some((rid, Arc::new(ownership.clone()))))
            .unwrap();
        let fresh_renewal = operation.begin_renew(None).unwrap();

        // ACK construction requires an independently completed fresh renewal.
        let ack_operation = Operation::new(scope);
        let ack_renewal = ack_operation.begin_renew(None).unwrap();
        ack_renewal.enter_commit().unwrap().received();
        let ack = ack_renewal.returned().unwrap().begin_ack(rid - 1).unwrap();

        let store = ReplayStore::new(outcome);
        let service = ReplayService::new(store.clone(), "example.test", 30);
        let port = ServiceReplay { service: &service };
        let committed = outcome == Outcome::Committed;
        assert_eq!(
            drive_call(port.bind(&bind), outcome, label),
            committed.then_some(ownership.clone()),
            "{label}"
        );
        assert_eq!(
            drive_call(port.renew(&renewal), outcome, label),
            committed.then_some(()),
            "{label}"
        );
        assert_eq!(
            drive_call(port.renew(&fresh_renewal), outcome, label),
            committed.then_some(()),
            "{label}"
        );
        assert_eq!(
            drive_call(port.acknowledge(&ack), outcome, label),
            committed.then_some(()),
            "{label}"
        );
        assert_eq!(
            drive_call(port.release(session_id), outcome, label),
            committed.then_some(()),
            "{label}"
        );
        assert_eq!(
            store.calls(),
            vec![
                Call::Bind {
                    address: std::ptr::from_ref(&bind) as usize,
                    session_id,
                    rid,
                    ttl_seconds,
                    sources,
                },
                Call::Dropped("bind"),
                Call::Renew {
                    address: std::ptr::from_ref(&renewal) as usize,
                    session_id,
                    ttl_seconds,
                    expected: Some((rid, ownership.clone())),
                },
                Call::Dropped("renew"),
                Call::Renew {
                    address: std::ptr::from_ref(&fresh_renewal) as usize,
                    session_id,
                    ttl_seconds,
                    expected: None,
                },
                Call::Dropped("renew"),
                Call::Acknowledge {
                    address: std::ptr::from_ref(&ack) as usize,
                    session_id,
                    rid: rid - 1,
                },
                Call::Dropped("acknowledge"),
                Call::Release(session_id),
                Call::Dropped("release"),
            ],
            "{label}"
        );

        // A receipt must belong to the request's original operation, including
        // when the repository is reached through both forwarding layers.
        let snapshot = operation.snapshot();
        assert_eq!(
            snapshot.responses[0].attempts[0].knowledge,
            if committed {
                BindKnowledge::ReceiptKnown(Arc::new(ownership))
            } else {
                BindKnowledge::NoCommitRequested
            },
            "{label}"
        );
        let knowledge = if committed {
            Knowledge::ReceiptKnown
        } else {
            Knowledge::NoCommitRequested
        };
        assert_eq!(snapshot.renewals.len(), 2, "{label}");
        for renewal in &snapshot.renewals {
            assert_eq!(renewal.knowledge, knowledge, "{label}");
            assert!(!renewal.returned, "{label}");
        }
        assert_eq!(
            ack_operation.snapshot().acknowledgements[0].knowledge,
            knowledge,
            "{label}"
        );
        assert!(!snapshot.responses[0].exposure_entered, "{label}");
        assert!(snapshot.terminal.is_none(), "{label}");
    }
}
