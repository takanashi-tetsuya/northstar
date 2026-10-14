use super::*;
fn source(claim: u128) -> DurableDelivery {
    DurableDelivery {
        recipient_id: Uuid::from_u128(2),
        message_id: Uuid::from_u128(13),
        claim_id: Some(Uuid::from_u128(claim)),
    }
}
fn control() -> ReplacementControl {
    ReplacementControl::new(
        Arc::new(Mutex::new(Some(source(6)))),
        Uuid::from_u128(3),
        Uuid::from_u128(11),
        source(6),
        source(10),
        Arc::new(Mutex::new(wire::Sequence::default())),
    )
}

// These exercise only the private row/gate/channel fixture seam. They do
// not execute an original, application, native writer, saved Case or SQL.
#[tokio::test]
async fn wrong_source_does_not_consume_gate_and_abandoned_read_does_not_replace() {
    let control = control();
    assert!(control
        .before_read(Uuid::from_u128(3), source(99))
        .await
        .is_err());
    assert!(control.gate_receiver.lock().unwrap().is_some());
    assert!(!control.waiting.load(Ordering::SeqCst));
    let mut old = Box::pin(control.before_read(Uuid::from_u128(3), source(6)));
    assert!(futures::poll!(&mut old).is_pending());
    drop(old);
    assert!(control.release_old().is_err());
    assert!(*control.row.lock().unwrap() == Some(source(6)));
    assert!(control.events.lock().unwrap().is_empty());
    assert!(control.dequeued.lock().unwrap().is_none());
}

#[tokio::test]
async fn replacement_dequeue_preserves_actual_bytes_and_current_claim_comparison() {
    let control = control();
    let mut old = Box::pin(control.before_read(Uuid::from_u128(3), source(6)));
    assert!(futures::poll!(&mut old).is_pending());
    let xml = "<message id='replacement'/>";
    control.replace_and_dequeue(xml).unwrap();
    let (item, observed) = control.dequeued.lock().unwrap().take().unwrap();
    assert_eq!(item.stanza, xml);
    assert_eq!(observed.xml, item.stanza);
    assert!(item.c2s_delivery() == Some(source(10)));
    assert!(observed.source.as_ref().unwrap().actual() == item.durable_source.unwrap());
    control.release_old().unwrap();
    assert!(matches!(
        futures::poll!(&mut old),
        std::task::Poll::Ready(Ok(()))
    ));
    drop(old);
    let current = control.row.lock().unwrap().unwrap();
    assert!(
        !northstar_delivery_core::native_write::claimed_c2s_ack_matches(
            Uuid::from_u128(6),
            current.claim_id
        )
    );
    assert!(
        northstar_delivery_core::native_write::claimed_c2s_ack_matches(
            Uuid::from_u128(10),
            current.claim_id
        )
    );
    assert_eq!(control.events.lock().unwrap().len(), 1);
    assert!(matches!(
        control.events.lock().unwrap()[0],
        wire::RowEvent::Replace { .. }
    ));
}
