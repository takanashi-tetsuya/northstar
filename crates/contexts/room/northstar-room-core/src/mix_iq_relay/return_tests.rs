use super::*;
use crate::mix::{MixChannelAddress, MixChannelId};
use northstar_xmpp_types::jid::CanonicalJid;
use std::future::{poll_fn, Future};
use std::task::{Context, Poll, Waker};
use uuid::Uuid;

struct ManualMixRelayMonotonic(Mutex<Instant>);

impl MixRelayMonotonic for ManualMixRelayMonotonic {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}

impl ManualMixRelayMonotonic {
    fn advance(&self, elapsed: Duration) {
        *self.0.lock().unwrap() += elapsed;
    }
}

fn authority() -> RelayReturnAuthority {
    RelayReturnAuthority {
        exact_route: RelayReturnRoute::Federated(
            CanonicalJid::parse("alice@example.test/phone").unwrap(),
        ),
        channel: MixChannelAddress::parse("room@mix.example.test").unwrap(),
        channel_incarnation: Some(MixChannelId::new(Uuid::new_v4())),
        pam_incarnation: None,
    }
}

fn admit(index: &MixIqRelayIndex) {
    assert!(index.admit_with_authority(
        "relay".into(),
        MixIqRelayStage::Channel {
            requester_full_jid: "alice@example.test/phone".into(),
            requester_encoded_jid: "alice#room@mix.example.test/phone".into(),
            original_id: "original".into(),
            target_real_jid: "bob@remote.test".into(),
            target_encoded_jid: "bob#room@mix.example.test".into(),
            channel_jid: "room@mix.example.test".into(),
        },
        authority(),
    ));
}

#[test]
fn relay_deadline_crossed_during_await_loses_even_without_a_worker_tick() {
    let clock = Arc::new(ManualMixRelayMonotonic(Mutex::new(Instant::now())));
    let index = MixIqRelayIndex::with_clock(1, MIX_IQ_RELAY_TTL, clock.clone());
    admit(&index);
    let mut first_poll = true;
    let mut response = std::pin::pin!(async {
        let expected = index.get("relay").unwrap();
        assert!(expected.expires_at > index.now());
        poll_fn(|_| {
            if std::mem::take(&mut first_poll) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        index.take_response("relay", &expected, index.now())
    });
    let mut context = Context::from_waker(Waker::noop());
    assert!(response.as_mut().poll(&mut context).is_pending());
    clock.advance(MIX_IQ_RELAY_TTL);
    assert!(matches!(
        response.poll(&mut context),
        Poll::Ready(ResponseTake::Expired(_))
    ));
    assert!(index.take_expired(index.now()).is_empty());
}

#[test]
fn relay_response_and_worker_expiry_share_one_consume_token() {
    for worker_first in [false, true] {
        let clock = Arc::new(ManualMixRelayMonotonic(Mutex::new(Instant::now())));
        let index = MixIqRelayIndex::with_clock(1, MIX_IQ_RELAY_TTL, clock.clone());
        admit(&index);
        let expected = index.get("relay").unwrap();
        if worker_first {
            clock.advance(MIX_IQ_RELAY_TTL);
            assert_eq!(index.take_expired(index.now()).len(), 1);
            admit(&index);
            assert!(matches!(
                index.take_response("relay", &expected, index.now()),
                ResponseTake::MissingOrReplaced,
            ));
            assert_eq!(index.len(), 1);
        } else {
            assert!(matches!(
                index.take_response("relay", &expected, index.now()),
                ResponseTake::Response(_),
            ));
            clock.advance(MIX_IQ_RELAY_TTL);
            assert!(index.take_expired(index.now()).is_empty());
        }
    }
}

#[test]
fn hosted_return_requires_the_admitted_channel_incarnation() {
    let admitted = authority();
    assert!(admitted.matches_channel(admitted.channel_incarnation.clone()));
    assert!(!admitted.matches_channel(None));
    assert!(!admitted.matches_channel(Some(MixChannelId::new(Uuid::new_v4()))));
}
