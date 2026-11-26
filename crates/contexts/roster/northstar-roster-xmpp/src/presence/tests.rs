use super::availability::{
    directed_presence_capacity_reached, directed_presence_target_is_outside_bare_scope,
    unsubscribed_probe_response,
};
use super::avatar::refresh_avatar_presence_with_hash;
use super::broadcast::{set_last_broadcast_presence, should_probe_contact_on_presence};
use super::subscriptions::{
    should_resend_pending_outbound_subscription, stamped_subscription_presence,
};
use super::{full_jid_probe_available_response, AvatarPresenceGate};
use northstar_presence_core::{directed_recipient_matches, offline_replay_became_eligible};
use northstar_stream::local_routes::session::{test_online_session, OnlineSession};
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Waker};
use tokio::sync::oneshot;
use uuid::Uuid;

const OWNER_BARE: &str = "alice@example.test";
const OWNER_FULL: &str = "alice@example.test/phone";

#[derive(Default)]
struct FakePresenceService {
    committed_hash: RefCell<Option<String>>,
    reads: Cell<usize>,
}

impl FakePresenceService {
    fn commit(&self, hash: Option<&str>) {
        *self.committed_hash.borrow_mut() = hash.map(str::to_owned);
    }

    async fn avatar_hash(&self) -> anyhow::Result<Option<String>> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.committed_hash.borrow().clone())
    }

    async fn pause_after_avatar_read(
        &self,
        resume: oneshot::Receiver<()>,
    ) -> anyhow::Result<Option<String>> {
        let hash = self.avatar_hash().await?;
        resume.await.unwrap();
        Ok(hash)
    }
}

fn assert_cached_photo(session: &OnlineSession, hash: &str) {
    let cached = session.last_presence.read().unwrap();
    let document = roxmltree::Document::parse(cached.as_deref().unwrap()).unwrap();
    let photo = document
        .descendants()
        .find(|node| node.has_tag_name(("vcard-temp:x:update", "photo")))
        .unwrap();
    assert_eq!(photo.text(), Some(hash));
}

#[tokio::test]
async fn avatar_refresh_rewrites_parsable_presence_and_keeps_unparsable() {
    let gate = AvatarPresenceGate::default();
    let service = FakePresenceService::default();
    for hash in [Some("stored-hash"), None] {
        let (parsable, mut parsable_rx) =
            test_online_session(Uuid::new_v4(), 7, Uuid::new_v4(), "parsable", 1);
        let (unparsable, mut unparsable_rx) =
            test_online_session(Uuid::new_v4(), 7, Uuid::new_v4(), "unparsable", 1);
        let raw = "<presence from='alice@example.test/parsable'><status>Here</status><x xmlns='vcard-temp:x:update'><photo>old-hash</photo></x></presence>";
        let malformed = "<presence from='alice@example.test/unparsable'";
        *parsable.last_presence.write().unwrap() = Some(raw.into());
        *unparsable.last_presence.write().unwrap() = Some(malformed.into());

        service.commit(hash);
        refresh_avatar_presence_with_hash(&gate, OWNER_BARE, service.avatar_hash(), || {
            vec![parsable.clone(), unparsable.clone()]
        })
        .await
        .unwrap();

        let refreshed = parsable.last_presence.read().unwrap();
        let document = roxmltree::Document::parse(refreshed.as_deref().unwrap()).unwrap();
        assert_eq!(
            document.root_element().attribute("from"),
            Some("alice@example.test/parsable")
        );
        assert_eq!(document.root_element().attribute("to"), None);
        assert_eq!(
            document
                .descendants()
                .find(|node| node.has_tag_name("status"))
                .unwrap()
                .text(),
            Some("Here")
        );
        let photos = document
            .descendants()
            .filter(|node| node.has_tag_name(("vcard-temp:x:update", "photo")))
            .collect::<Vec<_>>();
        assert_eq!(photos.len(), 1);
        assert_eq!(photos[0].text(), hash);
        assert_eq!(
            unparsable.last_presence.read().unwrap().as_deref(),
            Some(malformed)
        );
        assert!(parsable_rx.try_recv().is_err());
        assert!(unparsable_rx.try_recv().is_err());
        assert!(!parsable.disconnect.is_cancelled());
        assert!(!unparsable.disconnect.is_cancelled());
    }
}

#[tokio::test]
async fn avatar_refresh_without_presence_is_a_no_op() {
    let gate = AvatarPresenceGate::default();
    let service = FakePresenceService::default();
    let (session, mut receiver) =
        test_online_session(Uuid::new_v4(), 7, Uuid::new_v4(), "absent", 1);
    for hash in [Some("stored-hash"), None] {
        service.commit(hash);
        refresh_avatar_presence_with_hash(&gate, OWNER_BARE, service.avatar_hash(), || {
            vec![session.clone()]
        })
        .await
        .unwrap();
        assert_eq!(*session.last_presence.read().unwrap(), None);
        assert!(receiver.try_recv().is_err());
        assert!(!session.disconnect.is_cancelled());
    }
}

#[tokio::test]
async fn avatar_refresh_from_the_older_commit_can_finish_last() {
    let gate = AvatarPresenceGate::default();
    let service = FakePresenceService::default();
    let (session, _) = test_online_session(Uuid::new_v4(), 7, Uuid::new_v4(), "phone", 1);
    *session.last_presence.write().unwrap() = Some("<presence/>".into());

    service.commit(Some("older"));
    let (resume, delayed) = oneshot::channel();
    let mut older_refresh = pin!(async {
        delayed.await.unwrap();
        refresh_avatar_presence_with_hash(&gate, OWNER_BARE, service.avatar_hash(), || {
            vec![session.clone()]
        })
        .await
        .unwrap();
    });
    let mut context = Context::from_waker(Waker::noop());
    assert!(older_refresh.as_mut().poll(&mut context).is_pending());

    service.commit(Some("newest"));
    refresh_avatar_presence_with_hash(&gate, OWNER_BARE, service.avatar_hash(), || {
        vec![session.clone()]
    })
    .await
    .unwrap();
    assert_cached_photo(&session, "newest");

    resume.send(()).unwrap();
    older_refresh.await;
    assert_cached_photo(&session, "newest");
    assert_eq!(service.reads.get(), 2);
}

#[tokio::test]
async fn avatar_refresh_cannot_overtake_another_refresh_after_its_read() {
    let gate = AvatarPresenceGate::default();
    let service = FakePresenceService::default();
    let (session, _) = test_online_session(Uuid::new_v4(), 7, Uuid::new_v4(), "phone", 1);
    *session.last_presence.write().unwrap() = Some("<presence/>".into());

    service.commit(Some("older"));
    let (resume, delayed) = oneshot::channel();
    let mut first = pin!(refresh_avatar_presence_with_hash(
        &gate,
        OWNER_BARE,
        service.pause_after_avatar_read(delayed),
        || vec![session.clone()],
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert!(first.as_mut().poll(&mut context).is_pending());
    assert_eq!(service.reads.get(), 1);

    service.commit(Some("newest"));
    let mut second = pin!(refresh_avatar_presence_with_hash(
        &gate,
        OWNER_BARE,
        service.avatar_hash(),
        || vec![session.clone()],
    ));
    assert!(second.as_mut().poll(&mut context).is_pending());
    assert_eq!(service.reads.get(), 1);

    resume.send(()).unwrap();
    first.await.unwrap();
    second.await.unwrap();
    assert_cached_photo(&session, "newest");
}

#[tokio::test]
async fn own_presence_and_avatar_refresh_share_the_owner_gate() {
    let gate = AvatarPresenceGate::default();
    let service = FakePresenceService::default();
    let (session, _) = test_online_session(Uuid::new_v4(), 7, Uuid::new_v4(), "phone", 1);
    let raw = "<presence><status>Here</status></presence>";
    let document = roxmltree::Document::parse(raw).unwrap();

    service.commit(Some("older"));
    let (resume, delayed) = oneshot::channel();
    let mut own_presence = pin!(set_last_broadcast_presence(
        &gate,
        document.root_element(),
        raw,
        true,
        OWNER_FULL,
        service.pause_after_avatar_read(delayed),
        |presence| *session.last_presence.write().unwrap() = presence,
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert!(own_presence.as_mut().poll(&mut context).is_pending());
    assert_eq!(service.reads.get(), 1);

    service.commit(Some("newest"));
    let mut refresh = pin!(refresh_avatar_presence_with_hash(
        &gate,
        OWNER_BARE,
        service.avatar_hash(),
        || vec![session.clone()],
    ));
    assert!(refresh.as_mut().poll(&mut context).is_pending());
    assert_eq!(service.reads.get(), 1);

    resume.send(()).unwrap();
    assert!(own_presence
        .await
        .unwrap()
        .contains("<status>Here</status>"));
    assert_cached_photo(&session, "older");
    refresh.await.unwrap();
    assert_cached_photo(&session, "newest");
    assert!(session
        .last_presence
        .read()
        .unwrap()
        .as_deref()
        .unwrap()
        .contains("<status>Here</status>"));
}

#[tokio::test]
async fn avatar_presence_gate_uses_the_same_stripe_for_the_same_owner() {
    let gate = AvatarPresenceGate::default();
    let first = gate.lock(OWNER_BARE).await;
    let mut same_owner = pin!(gate.lock(OWNER_BARE));
    let mut other_owner = pin!(gate.lock("bob@example.test"));
    let mut context = Context::from_waker(Waker::noop());
    assert!(same_owner.as_mut().poll(&mut context).is_pending());
    assert!(other_owner.as_mut().poll(&mut context).is_ready());
    drop(first);
    assert!(same_owner.as_mut().poll(&mut context).is_ready());
}

#[test]
fn offline_replay_starts_on_first_nonnegative_available_priority() {
    assert!(!offline_replay_became_eligible(false, 0, true, -1));
    assert!(offline_replay_became_eligible(true, -1, true, 0));
    assert!(offline_replay_became_eligible(false, 0, true, 0));
    assert!(!offline_replay_became_eligible(true, 0, true, 5));
    assert!(!offline_replay_became_eligible(true, -1, false, 0));
}

#[test]
fn directed_presence_admission_matches_the_resume_snapshot_bound() {
    assert!(!directed_presence_capacity_reached(1_023, false));
    assert!(directed_presence_capacity_reached(1_024, false));
    assert!(!directed_presence_capacity_reached(1_024, true));
}

#[test]
fn roster_broadcast_scope_removes_bare_and_full_directed_targets() {
    assert!(!directed_presence_target_is_outside_bare_scope(
        "Alice@BÜCHER.example/Phone",
        "alice@bücher.example",
    ));
    assert!(directed_presence_target_is_outside_bare_scope(
        "bob@example.test/Phone",
        "alice@example.test",
    ));
    assert!(!directed_presence_target_is_outside_bare_scope(
        "not a jid",
        "alice@example.test",
    ));
}

#[test]
fn automatic_contact_probes_are_initial_presence_only() {
    assert!(should_probe_contact_on_presence(true, "to"));
    assert!(should_probe_contact_on_presence(true, "both"));
    assert!(!should_probe_contact_on_presence(false, "both"));
    assert!(!should_probe_contact_on_presence(true, "from"));
}

#[test]
fn pending_outbound_subscriptions_are_recovered_on_initial_presence_only() {
    assert!(should_resend_pending_outbound_subscription(
        true,
        Some("subscribe")
    ));
    assert!(!should_resend_pending_outbound_subscription(
        false,
        Some("subscribe")
    ));
    assert!(!should_resend_pending_outbound_subscription(true, None));
}

#[test]
fn directed_presence_authorization_is_bare_or_exact_resource_scoped() {
    assert!(directed_recipient_matches(
        "Alice@BÜCHER.example",
        "alice@bücher.example/Phone"
    ));
    assert!(directed_recipient_matches(
        "alice@example.test/Phone",
        "alice@example.test/Phone"
    ));
    assert!(!directed_recipient_matches(
        "alice@example.test/Phone",
        "alice@example.test/phone"
    ));
    assert!(!directed_recipient_matches(
        "alice@example.test/Phone",
        "alice@example.test/Tablet"
    ));
}

#[test]
fn subscription_stamping_uses_bare_jids_and_preserves_extensions() {
    let stamped = stamped_subscription_presence(
        "<presence to='bob@example.test/Tablet' type='subscribe'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>",
        "alice@example.test",
        "bob@example.test",
    );
    assert!(stamped.contains("from='alice@example.test'"));
    assert!(stamped.contains("to='bob@example.test'"));
    assert!(!stamped.contains("Tablet"));
    assert!(stamped.contains("<nick xmlns='http://jabber.org/protocol/nick'>Alice</nick>"));
}

#[test]
fn unauthorized_probe_response_does_not_expose_a_resource() {
    assert_eq!(
        unsubscribed_probe_response(
            "missing@example.test",
            "alice@example.test/Phone",
            Some("probe-1"),
        ),
        "<presence xmlns='jabber:client' from='missing@example.test' to='alice@example.test/Phone' type='unsubscribed' id='probe-1'/>"
    );
}

#[test]
fn full_jid_probe_response_exposes_only_availability() {
    let response = full_jid_probe_available_response(
        "romeo@example.test/Phone",
        "alice@example.test/Tablet",
        Some("presence-1"),
    );
    assert_eq!(
        response,
        "<presence xmlns='jabber:client' from='romeo@example.test/Phone' to='alice@example.test/Tablet' id='presence-1'/>"
    );
    assert!(!response.contains("<show>"));
    assert!(!response.contains("<status>"));
    assert!(!response.contains("<priority>"));
}
