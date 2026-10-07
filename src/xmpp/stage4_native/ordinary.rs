//! Ordinary controls for bounded native write and flush operations.
use super::*;
use crate::xmpp::auth_publication::stage4_saved::ordinary::{drain, recorder as capture};
use std::task::Waker;

fn script(fail_after: Option<u32>) -> wire::WriteScript {
    wire::WriteScript {
        chunk_limit: 1,
        fail_after_accepted_bytes: facts::nullable(fail_after),
        flush: wire::FlushReply::Ok,
    }
}
fn owner() -> wire::ItemOwner<wire::EvidenceId> {
    wire::ItemOwner::Muc(wire::MucItemOwner {
        frame: facts::id(Uuid::from_u128(1)),
        recipient_ordinal: 0,
    })
}

#[tokio::test]
async fn actual_writer_preflight_keeps_scripted_failure_and_terminal_call32_distinct() {
    for (length, fail_after, expected_calls, expected_ok) in [
        (33, Some(31), 32, false),
        (33, Some(0), 1, false),
        (32, None, 32, true),
        (32, Some(32), 32, true),
    ] {
        let recorder = capture();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let item = OutboundItem::with_transport_write_receipt("x".repeat(length), sender);
        let actual = write_item(
            item,
            Uuid::from_u128(2),
            NativeSite::new(0).unwrap(),
            owner(),
            script(fail_after),
            None,
            recorder.clone(),
        )
        .await
        .unwrap();
        assert_eq!(actual.is_ok(), expected_ok);
        assert_eq!(receiver.try_recv().is_ok(), expected_ok);
        let envelope = drain(&recorder);
        assert!(envelope.resource_stop.get().is_none());
        let writes: Vec<_> = envelope
            .facts
            .as_slice()
            .iter()
            .filter_map(|f| match &f.fact {
                wire::Fact::Native(wire::NativeFact::Write(w)) => Some(w),
                _ => None,
            })
            .collect();
        assert_eq!(writes.len(), expected_calls);
        assert_eq!(
            writes.last().unwrap().result,
            if expected_ok {
                wire::IoResult::Ok
            } else {
                wire::IoResult::Error
            }
        );
    }
    let recorder = capture();
    wire::driver::lost(&recorder);
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let item = OutboundItem::with_transport_write_receipt("x".repeat(33), sender);
    let stop = write_item(
        item,
        Uuid::from_u128(2),
        NativeSite::new(0).unwrap(),
        owner(),
        script(Some(32)),
        None,
        recorder.clone(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        stop.resource_stop,
        wire::ResourceStop::NativeWrite(wire::NativeResourceStop {
            item_ordinal: 0,
            admitted_calls: 0
        })
    );
    assert!(receiver.try_recv().is_err());
    let envelope = drain(&recorder);
    assert_eq!(envelope.resource_stop.get(), Some(&stop.resource_stop));
    assert!(envelope.execution.get().is_none() && envelope.rejection.get().is_none());
    assert!(matches!(
        envelope.observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}

#[test]
fn unexpected_nonterminal_call32_yields_zero_bytes_and_stops_before_call33_after_loss() {
    let recorder = capture();
    wire::driver::lost(&recorder);
    let site = NativeSite::new(0).unwrap();
    let mut io = MemoryWrite::new(script(None), site, recorder.clone());
    // Deliberately bypass preflight at the byte-device component seam. The
    // offered two-byte slices remain nonterminal; only 31 writes may accept.
    let mut call = Box::pin(std::future::poll_fn(|cx| loop {
        match Pin::new(&mut io).poll_write(cx, b"xx") {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err::<(), _>(error)),
            Poll::Pending => return Poll::Pending,
        }
    }));
    let mut context = Context::from_waker(Waker::noop());
    let stop = wire::driver::poll_once(&recorder, site.0, call.as_mut(), &mut context).unwrap_err();
    drop(call); // No retry or scheduled poll after the nested latch.
    assert_eq!(
        stop.resource_stop,
        wire::ResourceStop::NativeWrite(wire::NativeResourceStop {
            item_ordinal: 0,
            admitted_calls: 32
        })
    );
    assert_eq!(
        (io.counters.writes, io.counters.flushes, io.accepted),
        (32, 0, 31)
    );
    let envelope = drain(&recorder);
    assert_eq!(envelope.resource_stop.get(), Some(&stop.resource_stop));
    assert!(envelope.execution.get().is_none());
    assert!(matches!(
        envelope.observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}

#[test]
fn second_flush_is_a_resource_cut_while_first_supplied_flush_error_is_preserved() {
    let recorder = capture();
    let site = NativeSite::new(0).unwrap();
    let mut io = MemoryWrite::new(script(None), site, recorder.clone());
    let mut first = false;
    let mut call = Box::pin(std::future::poll_fn(|cx| {
        if !first {
            match Pin::new(&mut io).poll_flush(cx) {
                Poll::Ready(Ok(())) => first = true,
                other => return other,
            }
        }
        Pin::new(&mut io).poll_flush(cx)
    }));
    let mut context = Context::from_waker(Waker::noop());
    let stop = wire::driver::poll_once(&recorder, site.0, call.as_mut(), &mut context).unwrap_err();
    drop(call);
    assert_eq!(
        stop.resource_stop,
        wire::ResourceStop::NativeFlush(wire::NativeResourceStop {
            item_ordinal: 0,
            admitted_calls: 1
        })
    );
    assert_eq!(io.counters.flushes, 1);
    let envelope = drain(&recorder);
    assert_eq!(
        envelope
            .facts
            .as_slice()
            .iter()
            .filter(|f| matches!(&f.fact, wire::Fact::Native(wire::NativeFact::Flush(_))))
            .count(),
        1
    );
    let recorder = capture();
    let mut supplied = script(None);
    supplied.flush = wire::FlushReply::Error;
    let mut io = MemoryWrite::new(supplied, site, recorder.clone());
    let mut call = Box::pin(std::future::poll_fn(|cx| Pin::new(&mut io).poll_flush(cx)));
    assert!(matches!(
        wire::driver::poll_once(&recorder, site.0, call.as_mut(), &mut context),
        Ok(Poll::Ready(Err(_)))
    ));
    drop(call);
    assert_eq!(io.counters.flushes, 1);
    assert!(drain(&recorder).resource_stop.get().is_none());
}
