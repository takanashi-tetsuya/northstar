use super::*;
use crate::xmpp::auth_publication::{fixture_control, publish_unbound_fixture};
const AUTH_CONNECTION: Uuid = Uuid::from_u128(701);
use crate::xmpp::outbound::{
    DurableDelivery, DurableDeliverySuperseded, MixDelivery, TransportOwnershipSource as Source,
};
use northstar_delivery_core::bosh_ownership::{OperationKind, Scope, Terminal};
use std::{
    collections::BTreeSet,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};
use uuid::Uuid;

fn operation() -> Operation {
    Operation::new(Scope {
        session_id: Uuid::from_u128(501),
        ttl_seconds: 600,
        kind: OperationKind::Request,
    })
}
fn c2s(id: u128) -> DurableDelivery {
    DurableDelivery {
        recipient_id: Uuid::from_u128(502),
        message_id: Uuid::from_u128(id),
        claim_id: Some(Uuid::from_u128(503)),
    }
}
fn mix() -> MixDelivery {
    MixDelivery {
        delivery_id: Uuid::from_u128(504),
        lease_token: Uuid::from_u128(505),
    }
}
fn request(rid: u64) -> BoshRequest {
    super::super::parse_body(
        &format!("<body xmlns='http://jabber.org/protocol/httpbind' rid='{rid}' sid='fixture'/>"),
        64,
    )
    .unwrap()
}
fn metadata(rid: u64) -> Metadata {
    Metadata {
        rid,
        fingerprint: request(rid).fingerprint,
        cache: true,
    }
}
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn membership(sources: &[Source]) -> BoshResponseOwnership {
    BoshResponseOwnership {
        c2s_message_ids: sources
            .iter()
            .filter_map(|source| source.c2s().map(|source| source.message_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        mix_delivery_ids: sources
            .iter()
            .filter_map(|source| source.mix().map(|source| source.delivery_id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum Cut {
    #[default]
    Success,
    BeforeCommit,
    DuringCommit,
    CommitError,
    AfterReceiptPending,
    AfterReceiptError,
    BareSuccess,
    WrongReturn,
    WrongReceipt,
    Superseded,
    SupersededAfterEntry,
    SupersededAfterReceipt,
    SupersededMissing,
}
struct FakeReplay {
    binds: Mutex<VecDeque<Cut>>,
    renew: Cut,
    ack: Cut,
    deleted: Vec<response::DeletedSource>,
    events: Mutex<Vec<&'static str>>,
    bound_sources: Mutex<Vec<Vec<Source>>>,
    expected: Mutex<Vec<Option<(u64, BoshResponseOwnership)>>>,
    other: Operation,
}
impl Default for FakeReplay {
    fn default() -> Self {
        Self {
            binds: Mutex::new(VecDeque::new()),
            renew: Cut::Success,
            ack: Cut::Success,
            deleted: vec![],
            events: Mutex::new(vec![]),
            bound_sources: Mutex::new(vec![]),
            expected: Mutex::new(vec![]),
            other: operation(),
        }
    }
}
impl FakeReplay {
    fn bind_cuts(cuts: impl IntoIterator<Item = Cut>) -> Self {
        Self {
            binds: Mutex::new(cuts.into_iter().collect()),
            ..Self::default()
        }
    }
    async fn commit(&self, cut: Cut, event: &'static str) -> std::io::Result<()> {
        self.events.lock().unwrap().push(event);
        if cut == Cut::DuringCommit {
            std::future::pending::<()>().await;
        }
        if cut == Cut::CommitError || cut == Cut::SupersededAfterEntry {
            return Err(std::io::Error::other("controlled COMMIT reply loss"));
        }
        Ok(())
    }
    async fn after_receipt(cut: Cut) -> Result<()> {
        // These cuts are deliberately synthetic post-receipt continuations,
        // not additional awaits in the real SQL wrappers.
        if cut == Cut::AfterReceiptPending {
            std::future::pending::<()>().await;
        }
        if cut == Cut::AfterReceiptError {
            anyhow::bail!("controlled post-receipt error");
        }
        Ok(())
    }
}
impl ReplayPort for FakeReplay {
    async fn bind(&self, request: &BindRequest) -> Result<BoshResponseOwnership> {
        self.events.lock().unwrap().push("bind");
        request.validate_for_io()?;
        assert_eq!(request.session_id(), Uuid::from_u128(501));
        assert_eq!(request.ttl_seconds(), 600);
        self.bound_sources
            .lock()
            .unwrap()
            .push(request.sources().to_vec());
        let cut = self.binds.lock().unwrap().pop_front().unwrap_or_default();
        let receipt = membership(request.sources());
        let stale = || {
            request
                .sources()
                .iter()
                .find_map(|source| source.c2s())
                .unwrap()
                .message_id
        };
        if cut == Cut::BeforeCommit {
            anyhow::bail!("controlled pre-COMMIT error");
        }
        if cut == Cut::Superseded || cut == Cut::SupersededMissing {
            return Err(DurableDeliverySuperseded {
                message_id: if cut == Cut::SupersededMissing {
                    Uuid::nil()
                } else {
                    stale()
                },
            }
            .into());
        }
        if cut == Cut::BareSuccess {
            return Ok(receipt);
        }
        let other = if cut == Cut::WrongReceipt {
            Some(
                self.other
                    .begin_response(
                        request.rid(),
                        ResponseKind::Payload,
                        request.sources().iter().copied().map(Some).collect(),
                    )?
                    .attempt(
                        request.sources().to_vec(),
                        request.sources().iter().copied().map(Some),
                    )?,
            )
        } else {
            None
        };
        let result = response::bind_commit_observed(
            self.commit(cut, "bind_commit"),
            other.as_ref().unwrap_or(request),
            receipt.clone(),
        )
        .await;
        if cut == Cut::SupersededAfterEntry || cut == Cut::SupersededAfterReceipt {
            if cut == Cut::SupersededAfterEntry {
                assert!(result.is_err());
            } else {
                result?;
            }
            return Err(DurableDeliverySuperseded {
                message_id: stale(),
            }
            .into());
        }
        result?;
        Self::after_receipt(cut).await?;
        if cut == Cut::WrongReturn {
            return Ok(BoshResponseOwnership::default());
        }
        Ok(receipt)
    }
    async fn renew(&self, request: &RenewRequest) -> Result<()> {
        self.events.lock().unwrap().push("renew");
        request.validate_for_io()?;
        self.expected
            .lock()
            .unwrap()
            .push(request.expected().map(|(rid, value)| (rid, value.clone())));
        if self.renew == Cut::BeforeCommit {
            anyhow::bail!("renew pre-COMMIT");
        }
        if self.renew == Cut::BareSuccess {
            return Ok(());
        }
        let other = if self.renew == Cut::WrongReceipt {
            Some(
                self.other.begin_renew(
                    request
                        .expected()
                        .map(|(rid, value)| (rid, Arc::new(value.clone()))),
                )?,
            )
        } else {
            None
        };
        response::renew_commit_observed(
            self.commit(self.renew, "renew_commit"),
            other.as_ref().unwrap_or(request),
        )
        .await?;
        Self::after_receipt(self.renew).await
    }
    async fn acknowledge(&self, request: &AckRequest) -> Result<()> {
        self.events.lock().unwrap().push("ack");
        request.validate_for_io()?;
        if self.ack == Cut::BeforeCommit {
            anyhow::bail!("ACK pre-COMMIT");
        }
        if self.ack == Cut::BareSuccess {
            return Ok(());
        }
        let other = if self.ack == Cut::WrongReceipt {
            let renew = self.other.begin_renew(None)?;
            response::renew_commit_observed(async { Ok::<_, std::io::Error>(()) }, &renew).await?;
            Some(renew.returned()?.begin_ack(request.rid())?)
        } else {
            None
        };
        response::ack_commit_observed(
            self.commit(self.ack, "ack_commit"),
            other.as_ref().unwrap_or(request),
            self.deleted.clone(),
        )
        .await?;
        Self::after_receipt(self.ack).await
    }
    async fn release(&self, session_id: Uuid) -> Result<()> {
        assert_eq!(session_id, Uuid::from_u128(501));
        self.events.lock().unwrap().push("release");
        // Existing policy deliberately ignores this result. No release
        // receipt is fabricated in the observed response operation.
        anyhow::bail!("controlled ignored release error")
    }
}
struct Harness {
    output: VecDeque<OutboundItem>,
    bytes: usize,
    replay: VecDeque<CachedResponse>,
    governor: Arc<SmMemoryGovernor>,
    max_bytes: usize,
    max_stanzas: usize,
}
impl Harness {
    fn new(items: impl IntoIterator<Item = OutboundItem>) -> Self {
        let output: VecDeque<_> = items.into_iter().collect();
        let bytes = output.iter().map(|item| item.stanza.len()).sum();
        Self {
            output,
            bytes,
            replay: VecDeque::new(),
            governor: SmMemoryGovernor::new(
                1024 * 1024,
                256 * 1024,
                16,
                256 * 1024,
                Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default()),
            )
            .unwrap(),
            max_bytes: 64 * 1024,
            max_stanzas: 512,
        }
    }
    async fn prepare(
        &mut self,
        operation: &Operation,
        port: &FakeReplay,
        rid: u64,
        condition: Option<&str>,
    ) -> Result<BoundResponse, PreparationFailure> {
        let bound = prepare(
            &mut Fields {
                output: &mut self.output,
                output_bytes: &mut self.bytes,
                replay: &mut self.replay,
                governor: &self.governor,
                max_response_bytes: self.max_bytes,
                max_output_stanzas: self.max_stanzas,
                content_type: "text/xml; charset=utf-8",
                received_rid: Some(rid),
            },
            metadata(rid),
            condition,
            operation,
            port,
        )
        .await?;
        Ok(bound
            .for_connection(AUTH_CONNECTION)
            .expect("fixture auth controls belong to the declared connection"))
    }
}
fn durable_item(id: u128) -> OutboundItem {
    OutboundItem::durable(
        format!("<message id='{id}'><body>private payload</body></message>"),
        c2s(id),
    )
}
fn cache(rid: u64, receipts: Vec<mpsc::UnboundedSender<()>>) -> CachedResponse {
    CachedResponse {
        rid,
        fingerprint: request(rid).fingerprint,
        response: BoshHttpResponse {
            body: Bytes::from_static(
                b"<body xmlns='http://jabber.org/protocol/httpbind'><message/></body>",
            ),
            content_type: "text/xml; charset=utf-8".to_owned(),
        },
        durable_ownership: Arc::new(BoshResponseOwnership::default()),
        transport_receipts: receipts,
        owned_at: Instant::now(),
        response_bytes: 64,
        replays: 0,
    }
}
fn body(response: &BoshHttpResponse) -> &str {
    std::str::from_utf8(&response.body).unwrap()
}

fn auth_control() -> OutboundItem {
    let control = "<success xmlns='urn:xmpp:sasl:2'/>";
    let (holder, _) = fixture_control(control, AUTH_CONNECTION);
    OutboundItem::plain(control.to_owned())
        .with_auth_publication(holder)
        .unwrap()
}

#[tokio::test]
async fn actual_bounded_selection_publishes_unbound_u_without_taking_queued_bind_b() {
    use northstar_auth_application::authentication::publication::{Knowledge, Terminal};
    let u_bytes = "<success xmlns='urn:xmpp:sasl:2'/>";
    let b_bytes = "<iq type='result' id='B'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>";
    let (u_holder, u) = fixture_control(u_bytes, AUTH_CONNECTION);
    let (b_holder, b) =
        crate::xmpp::auth_publication::fixture_bound_control(b_bytes, AUTH_CONNECTION, false);
    u_holder.recording().unwrap();
    b_holder.recording().unwrap();
    let prior_b = b.snapshot();
    let prior_b_joins = b_holder.join_observation().snapshot();
    let u_association = u_holder.join_observation().snapshot().introduced.unwrap();
    let limit = 16 * 1024;
    let padding_bytes = limit - 256 - u_bytes.len();
    let wrapper = "<presence><status></status></presence>";
    let prefix = format!(
        "<presence><status>{}</status></presence>",
        "x".repeat(padding_bytes - wrapper.len())
    );
    let mut harness = Harness::new([
        OutboundItem::plain(prefix),
        OutboundItem::plain(u_bytes.to_owned())
            .with_auth_publication(u_holder)
            .unwrap(),
        OutboundItem::plain("<features/>".to_owned()),
        OutboundItem::plain(b_bytes.to_owned())
            .with_auth_publication(b_holder)
            .unwrap(),
    ]);
    harness.max_bytes = limit;
    assert!(harness.bytes <= 64 * 1024);
    let operation = operation();
    let bound = harness
        .prepare(&operation, &FakeReplay::default(), 10, None)
        .await
        .unwrap();
    let selection = bound.selection_observation();
    let selected = selection.snapshot();
    assert_eq!(selected.status, SelectionReadStatus::Complete);
    assert_eq!(selected.selected_count, 2);
    assert_eq!(selected.items[0].unwrap().ordinal, 0);
    assert!(!selected.items[0].unwrap().auth_marker);
    assert_eq!(selected.items[0].unwrap().utf8_length, padding_bytes);
    assert_eq!(selected.items[1].unwrap().ordinal, 1);
    assert!(selected.items[1].unwrap().auth_marker);
    assert_eq!(
        selected.items[1].unwrap().sealed_association,
        Some(u_association)
    );
    assert_eq!(selected.items[1].unwrap().source, None);
    assert_eq!(selected.items[2], None);
    assert_eq!(selected.items[3], None);
    assert_ne!(Some(u_association), prior_b_joins.introduced);
    let queued_b = harness.output[1]
        .auth_publication()
        .unwrap()
        .join_observation();
    assert_eq!(queued_b.snapshot(), prior_b_joins);
    let (tx, rx) = oneshot::channel();
    let ready = bound
        .expose(vec![tx])
        .unwrap()
        .publish_authentication(publish_unbound_fixture)
        .await
        .unwrap();
    let response = rx.await.unwrap();
    assert!(body(&response).contains(u_bytes));
    assert!(!body(&response).contains(b_bytes));
    assert_eq!(harness.output.len(), 2);
    assert_eq!(harness.output[0].stanza, "<features/>");
    assert_eq!(harness.output[1].stanza, b_bytes);
    assert_eq!(b.snapshot(), prior_b);
    assert_eq!(u.snapshot().publication, Knowledge::NotRequired);
    assert_eq!(u.snapshot().terminal, Some(Terminal::Completed));
    assert!(u.snapshot().effects.unbound);
    assert!(!u.snapshot().effects.caps_entered);
    ready
        .finish(&mut Instant::now(), &mut 0, &mut harness.replay)
        .unwrap();
    assert_eq!(b.snapshot(), prior_b);
    assert_eq!(queued_b.snapshot(), prior_b_joins);
    let after_cache = selection.snapshot();
    assert_eq!(
        after_cache.items[1].unwrap().sealed_association,
        Some(u_association)
    );
    assert_eq!(
        after_cache.items[1]
            .unwrap()
            .holder_joins
            .unwrap()
            .transferred,
        Some(u_association),
    );
}

#[tokio::test]
async fn selected_facts_keep_actual_fifo_bytes_sources_and_distinct_same_byte_controls() {
    use sha2::{Digest, Sha256};
    let control = "<success note='é'/>";
    let plain = "<presence><status>é</status></presence>";
    let (first, first_publication) = fixture_control(control, AUTH_CONNECTION);
    let (second, second_publication) = fixture_control(control, AUTH_CONNECTION);
    let introduced = [
        first.join_observation().snapshot().introduced.unwrap(),
        second.join_observation().snapshot().introduced.unwrap(),
    ];
    assert_ne!(introduced[0].control, introduced[1].control);
    assert_ne!(introduced[0].receipt, introduced[1].receipt);
    let mut harness = Harness::new([
        durable_item(506),
        OutboundItem::plain(plain.to_owned()),
        OutboundItem::plain(control.to_owned())
            .with_auth_publication(first)
            .unwrap(),
        OutboundItem::plain(control.to_owned())
            .with_auth_publication(second)
            .unwrap(),
    ]);
    let operation = operation();
    let bound = harness
        .prepare(&operation, &FakeReplay::default(), 41, None)
        .await
        .unwrap();
    let selection = bound.selection_observation();
    let before = selection.snapshot();
    assert_eq!(before.session, operation.session_id());
    assert_eq!(before.rid, 41);
    assert_eq!(before.fingerprint, metadata(41).fingerprint);
    assert_eq!(before.validated_connection, Some(AUTH_CONNECTION));
    assert_eq!(before.status, SelectionReadStatus::Complete);
    assert_eq!(before.selected_count, MAX_SELECTED_FACTS);
    assert_eq!(before.items[0].unwrap().source, Some(Source::C2s(c2s(506))));
    let plain_facts = before.items[1].unwrap();
    assert_eq!(plain_facts.utf8_length, plain.len());
    assert_ne!(plain_facts.utf8_length, plain.chars().count());
    assert_eq!(
        plain_facts.sha256,
        <[u8; 32]>::from(Sha256::digest(plain.as_bytes()))
    );
    assert!(!plain_facts.auth_marker);
    assert_eq!(plain_facts.sealed_association, None);
    assert_eq!(plain_facts.holder_joins, None);
    for (offset, association) in introduced.iter().copied().enumerate() {
        let item = before.items[offset + 2].unwrap();
        assert_eq!(item.ordinal, offset + 2);
        assert_eq!(item.source, None);
        assert_eq!(item.utf8_length, control.len());
        assert_eq!(
            item.sha256,
            <[u8; 32]>::from(Sha256::digest(control.as_bytes()))
        );
        assert!(item.auth_marker);
        assert_eq!(item.sealed_association, Some(association));
        assert_eq!(item.holder_joins.unwrap().transferred, None);
        assert_eq!(association.publication.credential, None);
    }
    // Swapped equal-byte controls remain different actual associations.
    assert_ne!(
        before.items[2].unwrap().sealed_association,
        Some(introduced[1])
    );
    assert_ne!(
        before.items[3].unwrap().sealed_association,
        Some(introduced[0])
    );
    assert_eq!(selection.snapshot(), before);
    let (tx, rx) = oneshot::channel();
    let exposed = bound.expose(vec![tx]).unwrap();
    assert_eq!(selection.snapshot(), before);
    let response = rx.await.unwrap();
    assert!(body(&response).contains(plain));
    assert_eq!(body(&response).matches(control).count(), 2);
    let ready = exposed
        .publish_authentication(publish_unbound_fixture)
        .await
        .unwrap();
    let before_finish = selection.snapshot();
    for (offset, association) in introduced.iter().copied().enumerate() {
        assert_eq!(
            before_finish.items[offset + 2].unwrap().sealed_association,
            Some(association)
        );
        assert_eq!(
            before_finish.items[offset + 2]
                .unwrap()
                .holder_joins
                .unwrap()
                .transferred,
            Some(association),
        );
    }
    assert_eq!(
        first_publication.joins().begun_receipt,
        Some(introduced[0].receipt)
    );
    assert_eq!(
        second_publication.joins().begun_receipt,
        Some(introduced[1].receipt)
    );
    ready
        .finish(&mut Instant::now(), &mut 0, &mut harness.replay)
        .unwrap();
    assert_eq!(selection.snapshot(), before_finish);
    assert_eq!(harness.replay[0].rid, before.rid);
    assert_eq!(harness.replay[0].fingerprint, before.fingerprint);
    assert_eq!(harness.replay[0].response.body, response.body);
}

#[tokio::test]
async fn selected_facts_record_connection_only_after_actual_successful_validation() {
    for valid in [false, true] {
        let operation = operation();
        let port = FakeReplay::default();
        let mut harness = Harness::new([auth_control()]);
        let bound = prepare(
            &mut Fields {
                output: &mut harness.output,
                output_bytes: &mut harness.bytes,
                replay: &mut harness.replay,
                governor: &harness.governor,
                max_response_bytes: harness.max_bytes,
                max_output_stanzas: harness.max_stanzas,
                content_type: "text/xml; charset=utf-8",
                received_rid: Some(42),
            },
            metadata(42),
            None,
            &operation,
            &port,
        )
        .await
        .unwrap();
        let selection = bound.selection_observation();
        assert_eq!(selection.snapshot().validated_connection, None);
        let result = bound.for_connection(if valid {
            AUTH_CONNECTION
        } else {
            Uuid::from_u128(999)
        });
        if valid {
            let bound = result.unwrap();
            assert_eq!(
                selection.snapshot().validated_connection,
                Some(AUTH_CONNECTION)
            );
            let before = selection.snapshot();
            assert!(bound.for_connection(Uuid::from_u128(999)).is_err());
            assert_eq!(selection.snapshot(), before);
        } else {
            assert!(result.is_err());
            assert_eq!(selection.snapshot().validated_connection, None);
        }
        assert_eq!(operation.summary().responses.accepted_responders, 0);
    }
}

#[tokio::test]
async fn selected_fact_rebinding_keeps_actual_connections_and_sticky_history_loss() {
    // Empty auth selection legitimately permits repeated successful binds.
    // Observation must not turn that existing behavior into rejection.
    for overflow in [false, true] {
        let count = if overflow { MAX_SELECTED_FACTS + 1 } else { 1 };
        let mut harness = Harness::new(
            (0..count).map(|id| OutboundItem::plain(format!("<presence id='{id}'/>"))),
        );
        let operation = operation();
        let bound = harness
            .prepare(&operation, &FakeReplay::default(), 49, None)
            .await
            .unwrap();
        let selection = bound.selection_observation();
        let first = selection.snapshot();
        assert_eq!(first.first_validated_connection, Some(AUTH_CONNECTION));
        assert_eq!(first.validated_connection, Some(AUTH_CONNECTION));
        let bound = bound.for_connection(AUTH_CONNECTION).unwrap();
        assert_eq!(selection.snapshot(), first);
        let other = Uuid::from_u128(999);
        let bound = bound.for_connection(other).unwrap();
        let second = selection.snapshot();
        assert_eq!(second.first_validated_connection, Some(AUTH_CONNECTION));
        assert_eq!(second.validated_connection, Some(other));
        assert_eq!(bound.auth_connection, Some(other));
        let loss = SelectionReadStatus::Incomplete {
            omitted_items: if overflow { 1 } else { 0 },
            missing_auth_associations: 0,
            connection_changed: true,
        };
        assert_eq!(second.status, loss);
        let bound = bound.for_connection(AUTH_CONNECTION).unwrap();
        assert_eq!(
            selection.snapshot().first_validated_connection,
            Some(AUTH_CONNECTION)
        );
        assert_eq!(
            selection.snapshot().validated_connection,
            Some(AUTH_CONNECTION)
        );
        assert_eq!(selection.snapshot().status, loss);
        assert_eq!(bound.auth_connection, Some(AUTH_CONNECTION));
        let (tx, rx) = oneshot::channel();
        let exposed = bound.expose(vec![tx]).unwrap();
        assert!(rx.await.is_ok());
        let ready = exposed
            .publish_authentication(|_| async {
                panic!("plain response must not invoke publication")
            })
            .await
            .unwrap();
        ready
            .finish(&mut Instant::now(), &mut 0, &mut harness.replay)
            .unwrap();
        assert_eq!(harness.replay.len(), 1);
        assert_eq!(selection.snapshot().status, loss);
    }
}

#[tokio::test]
async fn selected_fact_handle_cannot_keep_bound_or_exposed_auth_authority_alive() {
    use northstar_auth_application::authentication::publication::{Knowledge, Terminal, Transport};
    for expose in [false, true] {
        let control = "<success/>";
        let (holder, publication) = fixture_control(control, AUTH_CONNECTION);
        let mut harness = Harness::new([OutboundItem::plain(control.to_owned())
            .with_auth_publication(holder)
            .unwrap()]);
        let operation = operation();
        let bound = harness
            .prepare(&operation, &FakeReplay::default(), 43, None)
            .await
            .unwrap();
        let selection = bound.selection_observation();
        let alias = selection.clone();
        let before = selection.snapshot();
        if expose {
            let (tx, rx) = oneshot::channel();
            let exposed = bound.expose(vec![tx]).unwrap();
            assert!(body(&rx.await.unwrap()).contains(control));
            assert_eq!(
                publication.snapshot().transport,
                Transport::BoshAccepted { rid: 43 }
            );
            // Ordinary owner drop, not a bypass implementation: no callback
            // is constructed and no selected-owner transfer can be inferred.
            assert_eq!(selection.snapshot(), before);
            drop(exposed);
        } else {
            drop(bound);
        }
        assert_eq!(selection.snapshot(), before);
        assert_eq!(alias.snapshot(), before);
        assert_eq!(
            before.items[0].unwrap().holder_joins.unwrap().transferred,
            None
        );
        assert_eq!(publication.joins().begun_receipt, None);
        assert_eq!(publication.snapshot().publication, Knowledge::NotStarted);
        assert_eq!(
            publication.snapshot().terminal,
            Some(if expose {
                Terminal::ExposedNotAttempted
            } else {
                Terminal::Abandoned
            })
        );
        assert!(harness.replay.is_empty());
    }
}

#[tokio::test]
async fn selected_fact_handle_survives_publication_callback_error_and_pending_drop() {
    use northstar_auth_application::authentication::publication::Knowledge;
    for pending in [false, true] {
        let (holder, publication) = fixture_control("<success/>", AUTH_CONNECTION);
        let mut harness = Harness::new([OutboundItem::plain("<success/>".to_owned())
            .with_auth_publication(holder)
            .unwrap()]);
        let operation = operation();
        let bound = harness
            .prepare(&operation, &FakeReplay::default(), 44, None)
            .await
            .unwrap();
        let selection = bound.selection_observation();
        let introduced = selection.snapshot().items[0]
            .unwrap()
            .sealed_association
            .unwrap();
        let (tx, rx) = oneshot::channel();
        let exposed = bound.expose(vec![tx]).unwrap();
        let response = rx.await.unwrap();
        let mut future = Box::pin(exposed.publish_authentication(|owners| async move {
            let _owners = owners;
            if pending {
                std::future::pending::<()>().await;
            }
            false
        }));
        let polled = poll_once(future.as_mut());
        if pending {
            assert!(polled.is_pending());
        } else {
            assert!(matches!(polled, Poll::Ready(Err(_))));
        }
        let before_drop = selection.snapshot();
        assert_eq!(
            before_drop.items[0].unwrap().sealed_association,
            Some(introduced)
        );
        assert_eq!(
            before_drop.items[0]
                .unwrap()
                .holder_joins
                .unwrap()
                .transferred,
            Some(introduced)
        );
        drop(future);
        assert_eq!(selection.snapshot(), before_drop);
        assert_eq!(publication.joins().begun_receipt, None);
        assert_eq!(publication.snapshot().publication, Knowledge::NotStarted);
        assert!(body(&response).contains("<success/>"));
        assert!(harness.replay.is_empty());
        assert!(!operation.snapshot().responses[0].bookkeeping);
    }
}

#[tokio::test]
async fn selected_facts_use_only_successful_superseded_rebuild_final_membership() {
    let operation = operation();
    let port = FakeReplay::bind_cuts([Cut::Superseded, Cut::Success]);
    let mut harness = Harness::new([durable_item(506), durable_item(507), auth_control()]);
    let bound = harness.prepare(&operation, &port, 45, None).await.unwrap();
    let selection = bound.selection_observation();
    let snapshot = selection.snapshot();
    assert_eq!(operation.snapshot().responses[0].attempts.len(), 2);
    assert_eq!(snapshot.status, SelectionReadStatus::Complete);
    assert_eq!(snapshot.selected_count, 2);
    assert_eq!(snapshot.items[0].unwrap().ordinal, 0);
    assert_eq!(
        snapshot.items[0].unwrap().source,
        Some(Source::C2s(c2s(507)))
    );
    assert_eq!(snapshot.items[1].unwrap().ordinal, 1);
    assert_eq!(snapshot.items[1].unwrap().source, None);
    assert!(snapshot.items[1].unwrap().auth_marker);
    assert_eq!(snapshot.items[2], None);
    assert_eq!(snapshot.items[3], None);
    let (tx, rx) = oneshot::channel();
    let exposed = bound.expose(vec![tx]).unwrap();
    let response = rx.await.unwrap();
    assert!(!body(&response).contains("id='506'"));
    assert!(body(&response).contains("id='507'"));
    drop(exposed);
    assert_eq!(selection.snapshot(), snapshot);
}

#[tokio::test]
async fn selected_fact_overflow_is_explicit_and_does_not_truncate_actual_selection() {
    for count in [MAX_SELECTED_FACTS, MAX_SELECTED_FACTS + 1] {
        let (holder, publication) = fixture_control("<success/>", AUTH_CONNECTION);
        let mut items: Vec<_> = (0..count - 1)
            .map(|id| OutboundItem::plain(format!("<presence id='{id}'/>")))
            .collect();
        items.push(
            OutboundItem::plain("<success/>".to_owned())
                .with_auth_publication(holder)
                .unwrap(),
        );
        let mut harness = Harness::new(items);
        let operation = operation();
        let bound = harness
            .prepare(&operation, &FakeReplay::default(), 46, None)
            .await
            .unwrap();
        let selection = bound.selection_observation();
        let before = selection.snapshot();
        assert_eq!(before.selected_count, count);
        assert_eq!(before.items.iter().flatten().count(), MAX_SELECTED_FACTS);
        assert_eq!(
            before.status,
            if count == MAX_SELECTED_FACTS {
                SelectionReadStatus::Complete
            } else {
                SelectionReadStatus::Incomplete {
                    omitted_items: 1,
                    missing_auth_associations: 0,
                    connection_changed: false,
                }
            }
        );
        assert_eq!(
            before.items[3].unwrap().auth_marker,
            count == MAX_SELECTED_FACTS
        );
        let (tx, rx) = oneshot::channel();
        let exposed = bound.expose(vec![tx]).unwrap();
        let response = rx.await.unwrap();
        assert_eq!(body(&response).matches("<presence ").count(), count - 1);
        assert!(body(&response).contains("<success/>"));
        assert!(harness.output.is_empty());
        let ready = exposed
            .publish_authentication(publish_unbound_fixture)
            .await
            .unwrap();
        assert!(publication.completed());
        ready
            .finish(&mut Instant::now(), &mut 0, &mut harness.replay)
            .unwrap();
        assert_eq!(harness.replay[0].response.body, response.body);
        assert_eq!(selection.snapshot().status, before.status);
        assert_eq!(selection.snapshot().selected_count, count);
    }
}

#[tokio::test]
async fn altered_selected_control_bytes_cannot_produce_a_successful_selection_view() {
    let (holder, publication) = fixture_control("<success id='original'/>", AUTH_CONNECTION);
    let joins = holder.join_observation();
    let before = joins.snapshot();
    let mut item = OutboundItem::plain("<success id='original'/>".to_owned())
        .with_auth_publication(holder)
        .unwrap();
    item.stanza = "<success id='altered'/>".to_owned();
    let operation = operation();
    let mut harness = Harness::new([item]);
    assert!(harness
        .prepare(&operation, &FakeReplay::default(), 47, None)
        .await
        .is_err());
    assert_eq!(joins.snapshot(), before);
    assert_eq!(publication.joins().begun_receipt, None);
    assert_eq!(operation.summary().responses.accepted_responders, 0);
    assert!(harness.replay.is_empty());
}

#[tokio::test]
async fn true_callback_without_selected_owner_completion_cannot_cache() {
    use northstar_auth_application::authentication::publication::{Knowledge, Terminal};
    for forge_terminal in [false, true] {
        let operation = operation();
        let control = "<success xmlns='urn:xmpp:sasl:2'/>";
        let (holder, observation) = fixture_control(control, AUTH_CONNECTION);
        let mut harness = Harness::new([OutboundItem::plain(control.to_owned())
            .with_auth_publication(holder)
            .unwrap()]);
        let bound = harness
            .prepare(&operation, &FakeReplay::default(), 10, None)
            .await
            .unwrap();
        let (tx, rx) = oneshot::channel();
        let observed = &observation;
        let result = bound
            .expose(vec![tx])
            .unwrap()
            .publish_authentication(|owners| async move {
                if forge_terminal {
                    observed.retire(Terminal::Completed);
                }
                drop(owners);
                true
            })
            .await;
        assert!(result.is_err());
        assert!(rx.await.is_ok());
        assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
        assert_eq!(
            observation.snapshot().terminal,
            Some(if forge_terminal {
                Terminal::Completed
            } else {
                Terminal::ExposedNotAttempted
            })
        );
        assert!(!observation.completed());
        assert!(harness.replay.is_empty());
        assert!(!operation.snapshot().responses[0].bookkeeping);
    }
}

#[tokio::test]
async fn wrong_connection_or_repeated_selected_alias_cannot_expose_auth_bytes() {
    let operation = operation();
    let mut harness = Harness::new([auth_control()]);
    let bound = harness
        .prepare(&operation, &FakeReplay::default(), 10, None)
        .await
        .unwrap();
    assert!(bound.for_connection(Uuid::from_u128(999)).is_err());
    assert_eq!(operation.summary().responses.accepted_responders, 0);

    let operation = self::operation();
    let item = auth_control();
    let mut first = Harness::new([item.clone()]);
    let mut second = Harness::new([item]);
    let first = first
        .prepare(&operation, &FakeReplay::default(), 11, None)
        .await
        .unwrap();
    let second = second
        .prepare(&operation, &FakeReplay::default(), 12, None)
        .await
        .unwrap();
    let (tx, rx) = oneshot::channel();
    let exposed = first.expose(vec![tx]).unwrap();
    assert!(rx.await.is_ok());
    let (tx, mut rx) = oneshot::channel();
    assert!(second.expose(vec![tx]).is_err());
    assert!(rx.try_recv().is_err());
    let ready = exposed
        .publish_authentication(publish_unbound_fixture)
        .await
        .unwrap();
    drop(ready);
    assert_eq!(operation.summary().responses.accepted_responders, 1);
}

#[test]
fn auth_control_clone_copies_selection_membership_only() {
    let control = auth_control();
    let cloned = control.clone();
    assert!(control.is_bosh_auth_control());
    assert!(cloned.is_bosh_auth_control());
    assert_eq!(cloned.stanza, control.stanza);
    assert!(cloned.durable_source.is_none());
    assert!(!OutboundItem::plain(control.stanza.clone()).is_bosh_auth_control());
    // This asserts metadata copying only. Independently enqueuing cloned
    // controls is not a global exactly-once publication contract.
}

#[tokio::test]
async fn auth_publication_selected_prefix_has_same_input_old_gate_witness() {
    let operation = operation();
    let port = FakeReplay::default();
    let prefix = OutboundItem::plain(format!(
        "<presence><status>{}</status></presence>",
        "x".repeat(64)
    ));
    let limit = prefix.stanza.len() + 256;
    let mut harness = Harness::new([prefix, auth_control()]);
    harness.max_bytes = limit;
    let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
    let (tx, rx) = oneshot::channel();
    let exposed = bound.expose(vec![tx]).unwrap();
    assert!(!body(&rx.await.unwrap()).contains("success"));
    assert!(harness.output[0].is_bosh_auth_control());

    // Source-bound old-gate witness, not an old compiled implementation.
    // Evaluate its historical predicate on the same actual FIFO selection
    // and responder result: the queued auth action had set this bit.
    let old_actor_pending = true;
    assert!(old_actor_pending && exposed.any_accepted());
    let calls = std::cell::Cell::new(0);
    let ready = exposed
        .publish_authentication(|owners| {
            calls.set(calls.get() + 1);
            publish_unbound_fixture(owners)
        })
        .await
        .unwrap();
    assert_eq!(
        calls.get(),
        0,
        "unselected gate must not construct its future"
    );
    let mut last = Instant::now();
    let mut highest = 0;
    ready
        .finish(&mut last, &mut highest, &mut harness.replay)
        .unwrap();
    assert_eq!(highest, 10);

    let bound = harness.prepare(&operation, &port, 11, None).await.unwrap();
    let (tx, rx) = oneshot::channel();
    let exposed = bound.expose(vec![tx]).unwrap();
    assert!(body(&rx.await.unwrap()).contains("success"));
    let ready = exposed
        .publish_authentication(|owners| {
            calls.set(calls.get() + 1);
            publish_unbound_fixture(owners)
        })
        .await
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(highest, 10, "publication precedes response bookkeeping");
    ready
        .finish(&mut last, &mut highest, &mut harness.replay)
        .unwrap();
    assert_eq!(highest, 11);
    assert!(harness.output.is_empty());
}

#[tokio::test]
async fn auth_publication_requires_actual_acceptance_and_calls_once() {
    for accepts in [
        vec![],
        vec![false, false],
        vec![false, true],
        vec![true, true],
    ] {
        let operation = operation();
        let port = FakeReplay::default();
        let mut harness = Harness::new([auth_control()]);
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        let mut responders = Vec::new();
        let mut receivers = Vec::new();
        for accept in &accepts {
            let (tx, rx) = oneshot::channel();
            responders.push(tx);
            if *accept {
                receivers.push(rx);
            } else {
                drop(rx);
            }
        }
        let exposed = bound.expose(responders).unwrap();
        let calls = std::cell::Cell::new(0);
        let result = exposed
            .publish_authentication(|owners| {
                calls.set(calls.get() + 1);
                publish_unbound_fixture(owners)
            })
            .await;
        let accepted = accepts.iter().filter(|accept| **accept).count();
        assert_eq!(calls.get(), usize::from(accepted != 0));
        assert_eq!(result.is_ok(), accepted != 0);
        assert_eq!(operation.summary().responses.accepted_responders, accepted);
        if let Ok(ready) = result {
            ready
                .finish(&mut Instant::now(), &mut 0, &mut harness.replay)
                .unwrap();
        }
        assert_eq!(harness.replay.len(), usize::from(accepted != 0));
        drop(receivers);
    }
}

#[tokio::test]
async fn auth_publication_terminal_and_pause_controls_leave_marker_unselected() {
    for condition in ["terminate", "policy-violation", "internal-server-error"] {
        let operation = operation();
        let port = FakeReplay::default();
        let mut harness = Harness::new([auth_control()]);
        let bound = harness
            .prepare(&operation, &port, 10, Some(condition))
            .await
            .unwrap();
        let (tx, rx) = oneshot::channel();
        let exposed = bound.expose(vec![tx]).unwrap();
        assert!(!body(&rx.await.unwrap()).contains("success"));
        let calls = std::cell::Cell::new(0);
        let ready = exposed
            .publish_authentication(|owners| {
                calls.set(calls.get() + 1);
                publish_unbound_fixture(owners)
            })
            .await
            .unwrap();
        assert_eq!(calls.get(), 0);
        assert!(harness.output[0].is_bosh_auth_control());
        drop(ready);

        let (tx, rx) = oneshot::channel();
        finish_empty_control(
            11,
            vec![tx],
            "text/xml",
            &mut Instant::now(),
            &mut 0,
            &operation,
        );
        assert!(!body(&rx.await.unwrap()).contains("success"));
        assert!(harness.output[0].is_bosh_auth_control());
        assert!(harness.replay.is_empty());
    }
}

#[tokio::test]
async fn auth_remote_stream_error_uses_actual_selected_control() {
    for include_control in [false, true] {
        let operation = operation();
        let port = FakeReplay::default();
        let prefix = OutboundItem::plain(format!(
            "<presence><status>{}</status></presence>",
            "x".repeat(64)
        ));
        let limit = prefix.stanza.len() + 256;
        let mut harness = Harness::new([prefix, auth_control()]);
        if !include_control {
            harness.max_bytes = limit;
        }
        let bound = harness
            .prepare(&operation, &port, 10, Some("remote-stream-error"))
            .await
            .unwrap();
        let (tx, rx) = oneshot::channel();
        let exposed = bound.expose(vec![tx]).unwrap();
        assert_eq!(
            body(&rx.await.unwrap()).contains("success"),
            include_control
        );
        let calls = std::cell::Cell::new(0);
        let ready = exposed
            .publish_authentication(|owners| {
                calls.set(calls.get() + 1);
                publish_unbound_fixture(owners)
            })
            .await
            .unwrap();
        assert_eq!(calls.get(), usize::from(include_control));
        drop(ready);
    }
}

#[tokio::test]
async fn auth_control_membership_survives_construction_and_supersession_restoration() {
    let operation = operation();
    let port = FakeReplay::default();
    let (holder, malformed_observation) = fixture_control("<success>", AUTH_CONNECTION);
    let malformed = OutboundItem::plain("<success>".to_owned())
        .with_auth_publication(holder)
        .unwrap();
    let pointer = malformed.stanza.as_ptr();
    let mut harness = Harness::new([malformed]);
    assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
    assert!(harness.output[0].is_bosh_auth_control());
    assert_eq!(harness.output[0].stanza.as_ptr(), pointer);
    assert_eq!(operation.summary().responses.accepted_responders, 0);
    assert_eq!(malformed_observation.snapshot().terminal, None);

    let operation = self::operation();
    let port = FakeReplay::bind_cuts([Cut::Superseded]);
    let mut harness = Harness::new([durable_item(506), auth_control()]);
    let bound = harness.prepare(&operation, &port, 11, None).await.unwrap();
    assert!(bound.auth_control_selected);
    assert!(harness.output.is_empty());
    assert_eq!(operation.snapshot().responses[0].attempts.len(), 2);
    let (tx, rx) = oneshot::channel();
    let exposed = bound.expose(vec![tx]).unwrap();
    assert!(body(&rx.await.unwrap()).contains("success"));
    let calls = std::cell::Cell::new(0);
    let ready = exposed
        .publish_authentication(|owners| {
            calls.set(calls.get() + 1);
            publish_unbound_fixture(owners)
        })
        .await
        .unwrap();
    assert_eq!(calls.get(), 1);
    drop(ready);
}

#[tokio::test]
async fn auth_publication_failure_and_pending_drop_preserve_exposure_without_bookkeeping() {
    for pending in [false, true] {
        let operation = operation();
        let port = FakeReplay::default();
        let mut harness = Harness::new([auth_control()]);
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        let (tx, rx) = oneshot::channel();
        let exposed = bound.expose(vec![tx]).unwrap();
        assert!(body(&rx.await.unwrap()).contains("success"));
        let calls = std::cell::Cell::new(0);
        let mut last = Instant::now();
        let initial_last = last;
        let mut highest = 7;
        let mut continuation = Box::pin(async {
            let ready = exposed
                .publish_authentication(|owners| {
                    calls.set(calls.get() + 1);
                    async move {
                        let _owners = owners;
                        if pending {
                            std::future::pending::<()>().await;
                        }
                        false
                    }
                })
                .await?;
            ready.finish(&mut last, &mut highest, &mut harness.replay)
        });
        let result = poll_once(continuation.as_mut());
        if pending {
            assert!(result.is_pending());
        } else {
            assert!(matches!(result, Poll::Ready(Err(_))));
        }
        drop(continuation);
        assert_eq!(calls.get(), 1);
        assert_eq!(last, initial_last);
        assert_eq!(highest, 7);
        assert!(harness.replay.is_empty());
        let snapshot = operation.snapshot();
        assert_eq!(snapshot.responses[0].accepted_responders, 1);
        assert!(!snapshot.responses[0].bookkeeping);
        assert!(!snapshot.responses[0].cached);
        // Exposure is known; this local callback result supplies no SQL
        // publication, rollback, route-activation or recovery evidence.
    }
}

#[tokio::test]
async fn selected_auth_control_cannot_use_plain_finish_to_bypass_publication() {
    let operation = operation();
    let port = FakeReplay::default();
    let mut harness = Harness::new([auth_control()]);
    let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
    let (tx, rx) = oneshot::channel();
    let exposed = bound.expose(vec![tx]).unwrap();
    let mut last = Instant::now();
    let initial_last = last;
    let mut highest = 7;
    assert!(exposed
        .finish(&mut last, &mut highest, &mut harness.replay)
        .is_err());
    assert_eq!(highest, 7);
    assert_eq!(last, initial_last);
    assert!(harness.replay.is_empty());
    assert!(rx.await.is_ok());
    assert!(!operation.snapshot().responses[0].bookkeeping);
}

#[tokio::test]
async fn auth_publication_cache_replay_and_plain_suffix_cannot_reissue_gate() {
    let operation = operation();
    let port = FakeReplay::default();
    let mut harness = Harness::new([auth_control()]);
    let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
    let (tx, rx) = oneshot::channel();
    let calls = std::cell::Cell::new(0);
    let ready = bound
        .expose(vec![tx])
        .unwrap()
        .publish_authentication(|owners| {
            calls.set(calls.get() + 1);
            publish_unbound_fixture(owners)
        })
        .await
        .unwrap();
    let first = rx.await.unwrap();
    let mut last = Instant::now();
    let mut highest = 0;
    ready
        .finish(&mut last, &mut highest, &mut harness.replay)
        .unwrap();
    let (tx, rx) = oneshot::channel();
    assert!(matches!(
        replay_cached(
            &mut harness.replay,
            &request(10),
            tx,
            &mut last,
            &operation,
            &port
        )
        .await,
        ReplayOutcome::Sent { terminate: false }
    ));
    assert_eq!(rx.await.unwrap().body.as_ptr(), first.body.as_ptr());
    assert_eq!(calls.get(), 1);

    let plain = OutboundItem::plain("<success xmlns='urn:xmpp:sasl:2'/>".to_owned());
    harness.bytes += plain.stanza.len();
    harness.output.push_back(plain);
    let bound = harness.prepare(&operation, &port, 11, None).await.unwrap();
    let (tx, rx) = oneshot::channel();
    let ready = bound
        .expose(vec![tx])
        .unwrap()
        .publish_authentication(|owners| {
            calls.set(calls.get() + 1);
            publish_unbound_fixture(owners)
        })
        .await
        .unwrap();
    assert!(rx.await.is_ok());
    assert_eq!(calls.get(), 1, "XML content is not publication authority");
    ready
        .finish(&mut last, &mut highest, &mut harness.replay)
        .unwrap();
}

#[tokio::test]
async fn exact_bind_exposure_and_cache_share_bytes_membership_and_real_receipts() {
    let operation = operation();
    let port = FakeReplay::default();
    let (receipt, mut received) = mpsc::unbounded_channel();
    let (mix_item, _handoff) = OutboundItem::durable_mix("<message id='mix'/>".to_owned(), mix());
    let mut harness = Harness::new([
        durable_item(506),
        OutboundItem::with_transport_receipt("<presence/>".to_owned(), receipt),
        mix_item,
    ]);
    let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
    assert!(harness.output.is_empty());
    assert_eq!(harness.bytes, 0);
    let debug = format!("{bound:?}");
    assert!(!debug.contains("private payload"));
    assert!(!debug.contains(&mix().lease_token.to_string()));
    assert_eq!(
        port.bound_sources.lock().unwrap()[0],
        [Source::C2s(c2s(506)), Source::Mix(mix())]
    );
    let retained = operation.snapshot();
    assert!(Arc::ptr_eq(
        retained.responses[0].attempts[0].returned.as_ref().unwrap(),
        &bound.ownership
    ));
    assert!(!Arc::ptr_eq(
        match &retained.responses[0].attempts[0].knowledge {
            response::BindKnowledge::ReceiptKnown(value) => value,
            _ => panic!("missing receipt"),
        },
        &bound.ownership
    ));
    let pointer = bound.response.body.as_ptr();
    let (first, first_rx) = oneshot::channel();
    let (second, second_rx) = oneshot::channel();
    let exposed = bound.expose(vec![first, second]).unwrap();
    assert!(exposed.any_accepted());
    assert!(harness.replay.is_empty());
    let first = first_rx.await.unwrap();
    let second = second_rx.await.unwrap();
    assert_eq!(first.body.as_ptr(), pointer);
    assert_eq!(second.body.as_ptr(), pointer);
    assert!(body(&first).contains("private payload"));
    assert!(received.try_recv().is_err());
    let mut last = Instant::now();
    let mut highest = 0;
    exposed
        .finish(&mut last, &mut highest, &mut harness.replay)
        .unwrap();
    assert_eq!(highest, 10);
    assert_eq!(harness.replay[0].response.body.as_ptr(), pointer);
    assert_eq!(harness.replay[0].transport_receipts.len(), 1);
    assert_eq!(operation.summary().responses.accepted_responders, 2);
    assert_eq!(operation.summary().responses.cached, 1);
    assert_eq!(*port.events.lock().unwrap(), ["bind", "bind_commit"]);
}

#[tokio::test]
async fn bind_cut_owner_retains_unknown_or_receipt_without_exposure_or_cache() {
    for cut in [
        Cut::BeforeCommit,
        Cut::DuringCommit,
        Cut::CommitError,
        Cut::AfterReceiptPending,
        Cut::AfterReceiptError,
    ] {
        let operation = operation();
        let port = FakeReplay::bind_cuts([cut]);
        let mut harness = Harness::new([durable_item(506)]);
        let mut runner = Box::pin(super::super::ownership::OperationRunner::new(
            operation.clone(),
            tokio::time::timeout(super::super::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                harness.prepare(&operation, &port, 10, None).await.is_ok()
            }),
        ));
        let polled = poll_once(runner.as_mut());
        let pending = matches!(cut, Cut::DuringCommit | Cut::AfterReceiptPending);
        assert_eq!(polled.is_pending(), pending);
        if !pending {
            assert!(matches!(polled, Poll::Ready(Ok(false))));
        }
        drop(runner);
        assert!(harness.replay.is_empty());
        assert!(harness.output.is_empty());
        let summary = operation.summary();
        assert_eq!(
            summary.terminal,
            Some(if pending {
                Terminal::Cancelled
            } else {
                Terminal::Returned
            })
        );
        assert_eq!(
            summary.keep_running,
            if pending { None } else { Some(false) }
        );
        assert_eq!(
            summary.responses.bind_receipts,
            usize::from(matches!(
                cut,
                Cut::AfterReceiptPending | Cut::AfterReceiptError
            ))
        );
        assert_eq!(
            summary.responses.bind_unknown,
            usize::from(matches!(cut, Cut::DuringCommit | Cut::CommitError))
        );
        assert_eq!(summary.responses.accepted_responders, 0);
        assert_eq!(summary.responses.cached, 0);
    }
}

#[tokio::test]
async fn bare_wrong_invocation_and_mismatched_bind_returns_cannot_expose() {
    for cut in [Cut::BareSuccess, Cut::WrongReceipt, Cut::WrongReturn] {
        let operation = operation();
        let port = FakeReplay::bind_cuts([cut]);
        let mut harness = Harness::new([durable_item(506)]);
        let failure = harness
            .prepare(&operation, &port, 10, None)
            .await
            .unwrap_err();
        let (tx, rx) = oneshot::channel();
        failure.send(vec![tx], "text/xml");
        let response = rx.await.unwrap();
        assert!(body(&response).contains("internal-server-error"));
        assert!(!body(&response).contains("private payload"));
        let snapshot = operation.snapshot();
        let attempt = &snapshot.responses[0].attempts[0];
        assert!(attempt.returned.is_some());
        assert!(!attempt.return_matches);
        assert_eq!(
            snapshot.summary().responses.bind_receipts,
            usize::from(cut == Cut::WrongReturn)
        );
        assert!(!snapshot.responses[0].exposure_entered);
        assert_eq!(snapshot.responses[0].control_accepted, 1);
        assert!(harness.replay.is_empty());
    }
}

#[tokio::test]
async fn responder_refusal_and_abandoned_post_exposure_continuation_remain_distinct() {
    for abandon in [false, true] {
        let operation = operation();
        let port = FakeReplay::default();
        let mut harness = Harness::new([durable_item(506)]);
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        let (tx, rx) = oneshot::channel();
        if !abandon {
            drop(rx);
        }
        let exposed = bound.expose(vec![tx]).unwrap();
        assert_eq!(exposed.any_accepted(), abandon);
        if abandon {
            // This is the real exposed continuation dropped at the actor's
            // existing later publication boundary, without a fake callback.
            drop(exposed);
            operation.retire(Terminal::Cancelled);
        } else {
            let mut last = Instant::now();
            let mut highest = 0;
            exposed
                .finish(&mut last, &mut highest, &mut harness.replay)
                .unwrap();
            assert_eq!(highest, 10);
        }
        assert_eq!(harness.replay.len(), usize::from(!abandon));
        let snapshot = operation.snapshot();
        assert_eq!(
            snapshot.responses[0].accepted_responders,
            usize::from(abandon)
        );
        assert_eq!(
            snapshot.responses[0].refused_responders,
            usize::from(!abandon)
        );
        assert_eq!(snapshot.responses[0].bookkeeping, !abandon);
    }
}

#[tokio::test]
async fn typed_supersession_restores_peers_and_removes_every_matching_message() {
    // A controlled typed-adapter result exercises the actual restoration
    // predicate across duplicate IDs. Real bind SQL rejects duplicates
    // before row inspection; this is not a reachable SQL supersession case.
    let operation = operation();
    let port = FakeReplay::bind_cuts([Cut::Superseded]);
    let (receipt, mut received) = mpsc::unbounded_channel();
    let different_claim = DurableDelivery {
        recipient_id: Uuid::from_u128(599),
        claim_id: Some(Uuid::from_u128(598)),
        ..c2s(506)
    };
    let mut harness = Harness::new([
        OutboundItem::with_transport_receipt("<presence id='before'/>".to_owned(), receipt),
        durable_item(506),
        OutboundItem::durable(
            "<message id='same-id-other-claim'/>".to_owned(),
            different_claim,
        ),
        durable_item(507),
        OutboundItem::plain("<presence id='after'/>".to_owned()),
    ]);
    let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
    let text = body(&bound.response);
    assert!(!text.contains("id='506'"));
    assert!(!text.contains("same-id-other-claim"));
    assert!(text.find("before").unwrap() < text.find("507").unwrap());
    assert!(text.find("507").unwrap() < text.find("after").unwrap());
    assert_eq!(bound.receipts.len(), 1);
    assert!(received.try_recv().is_err());
    assert_eq!(bound.ownership.c2s_message_ids, [Uuid::from_u128(507)]);
    let snapshot = operation.snapshot();
    let attempts = &snapshot.responses[0].attempts;
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].removed_indices, [2, 1]);
    assert!(attempts[0].sources.is_none());
    assert!(attempts[0].restore_matches);
    assert_eq!(
        port.bound_sources.lock().unwrap()[1],
        [Source::C2s(c2s(507))]
    );
    assert_eq!(harness.bytes, 0);
}

#[tokio::test]
async fn supersession_after_commit_knowledge_never_restores_or_rebuilds() {
    for cut in [Cut::SupersededAfterEntry, Cut::SupersededAfterReceipt] {
        let operation = operation();
        let port = FakeReplay::bind_cuts([cut]);
        let mut harness = Harness::new([
            durable_item(506),
            OutboundItem::plain("<presence/>".to_owned()),
        ]);
        assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
        assert!(harness.output.is_empty());
        assert_eq!(harness.bytes, 0);
        let snapshot = operation.snapshot();
        let attempts = &snapshot.responses[0].attempts;
        assert_eq!(attempts.len(), 1);
        assert!(!attempts[0].restored);
        assert_eq!(
            snapshot.summary().responses.bind_unknown,
            usize::from(cut == Cut::SupersededAfterEntry)
        );
        assert_eq!(
            snapshot.summary().responses.bind_receipts,
            usize::from(cut == Cut::SupersededAfterReceipt)
        );
        assert_eq!(*port.events.lock().unwrap(), ["bind", "bind_commit"]);
    }
}

#[tokio::test]
async fn missing_supersession_and_rebuild_exhaustion_preserve_actual_restoration() {
    for missing in [false, true] {
        let operation = operation();
        let port = FakeReplay::bind_cuts([if missing {
            Cut::SupersededMissing
        } else {
            Cut::Superseded
        }]);
        let mut harness = Harness::new([durable_item(506), durable_item(507)]);
        // Controlled exhaustion of the existing configurable loop guard;
        // no new production limit or alternate restoration algorithm.
        harness.max_stanzas = 0;
        assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
        assert_eq!(harness.output.len(), if missing { 2 } else { 1 });
        assert_eq!(
            harness.bytes,
            harness
                .output
                .iter()
                .map(|item| item.stanza.len())
                .sum::<usize>()
        );
        let snapshot = operation.snapshot();
        let attempt = &snapshot.responses[0].attempts[0];
        assert!(attempt.restored);
        assert!(attempt.restore_matches);
        assert_eq!(attempt.removed_indices.len(), usize::from(!missing));
        assert_eq!(snapshot.responses[0].attempts.len(), 1);
    }
}

#[tokio::test]
async fn repeated_single_removals_retain_linear_measured_vector_capacity() {
    for count in [16usize, 64] {
        let operation = operation();
        let port = FakeReplay::bind_cuts(std::iter::repeat_n(Cut::Superseded, count));
        let mut harness = Harness::new((0..count).map(|index| durable_item(1_000 + index as u128)));
        let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
        assert!(bound.ownership.is_empty());
        // Read the live retained allocation, not a Snapshot clone that
        // could shrink Vec spare capacity and conceal a quadratic history.
        let summary = operation.summary().responses;
        let mut one = Vec::<usize>::new();
        for index in 0..1 {
            one.push(index);
        }
        assert_eq!(summary.restored_indices, count);
        assert_eq!(summary.retained_removal_capacity, one.capacity() * count);
        assert!(summary.retained_removal_capacity < count * (count + 1) / 2);
        let snapshot = operation.snapshot();
        assert_eq!(snapshot.responses[0].attempts.len(), count + 1);
        assert!(snapshot.responses[0].attempts[..count]
            .iter()
            .all(|attempt| attempt.sources.is_none()));
        assert_eq!(snapshot.responses[0].lineage.len(), count);
        // This reports retained usize capacity only, not allocator/RSS.
        println!(
            "BOSH removal storage: count={count}, capacity={}, element_bytes={}",
            summary.retained_removal_capacity,
            std::mem::size_of::<usize>()
        );
    }
}

#[tokio::test]
async fn malformed_output_restores_same_items_and_byte_limit_precedes_selection() {
    let operation = operation();
    let port = FakeReplay::default();
    let malformed = OutboundItem::plain("<message>".to_owned());
    let pointer = malformed.stanza.as_ptr();
    let mut harness = Harness::new([malformed, durable_item(506)]);
    assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
    assert_eq!(harness.output.len(), 2);
    assert_eq!(harness.output[0].stanza.as_ptr(), pointer);
    assert_eq!(operation.snapshot().responses[0].construction_restored, 2);
    assert!(port.events.lock().unwrap().is_empty());
    let mut harness = Harness::new([durable_item(506)]);
    harness.max_bytes = 256;
    let bytes = harness.bytes;
    assert!(harness.prepare(&operation, &port, 11, None).await.is_err());
    assert_eq!(harness.output.len(), 1);
    assert_eq!(harness.bytes, bytes);
    assert!(port.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn plain_payload_and_pause_control_keep_distinct_no_bind_paths() {
    let operation = operation();
    let port = FakeReplay::default();
    let mut harness = Harness::new([OutboundItem::plain("<presence/>".to_owned())]);
    let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
    assert!(bound.ownership.is_empty());
    assert!(port.events.lock().unwrap().is_empty());
    drop(bound);
    let (tx, rx) = oneshot::channel();
    let mut last = Instant::now();
    let mut highest = 3;
    finish_empty_control(
        11,
        vec![tx],
        "text/xml",
        &mut last,
        &mut highest,
        &operation,
    );
    let empty = rx.await.unwrap();
    assert!(!body(&empty).contains("presence"));
    assert_eq!(highest, 11);
    assert!(harness.replay.is_empty());
    let snapshot = operation.snapshot();
    assert_eq!(snapshot.responses[1].kind, ResponseKind::EmptyControl);
    assert!(snapshot.responses[1].attempts.is_empty());
    assert_eq!(snapshot.responses[1].control_accepted, 1);
}

#[tokio::test]
async fn unacknowledged_limit_preserves_release_before_terminal_without_bind() {
    let operation = operation();
    let port = FakeReplay::default();
    let mut harness = Harness::new([durable_item(506)]);
    for rid in [8, 9] {
        let mut cached = cache(rid, vec![]);
        cached.durable_ownership = Arc::new(BoshResponseOwnership {
            c2s_message_ids: vec![Uuid::from_u128(rid as u128)],
            mix_delivery_ids: vec![],
        });
        harness.replay.push_back(cached);
    }
    let failure = harness
        .prepare(&operation, &port, 10, None)
        .await
        .unwrap_err();
    assert!(matches!(failure.stage, FailureStage::Limit));
    assert_eq!(*port.events.lock().unwrap(), ["release"]);
    assert_eq!(harness.replay.len(), 2);
    assert!(harness.output.is_empty());
    assert!(operation.snapshot().responses[0].attempts.is_empty());
    let (tx, rx) = oneshot::channel();
    failure.send(vec![tx], "text/xml");
    assert!(body(&rx.await.unwrap()).contains("policy-violation"));
}

#[tokio::test]
async fn cached_replay_renews_exact_membership_and_same_bytes_without_fresh_ack() {
    let operation = operation();
    let port = FakeReplay::default();
    let mut cached = cache(10, vec![]);
    cached.durable_ownership = Arc::new(membership(&[Source::C2s(c2s(506)), Source::Mix(mix())]));
    let expected = cached.durable_ownership.clone();
    let pointer = cached.response.body.as_ptr();
    let mut replay = VecDeque::from([cached]);
    let mut last = Instant::now();
    let (tx, rx) = oneshot::channel();
    assert!(matches!(
        replay_cached(&mut replay, &request(10), tx, &mut last, &operation, &port).await,
        ReplayOutcome::Sent { terminate: false }
    ));
    assert_eq!(rx.await.unwrap().body.as_ptr(), pointer);
    assert_eq!(replay[0].replays, 1);
    assert_eq!(
        *port.expected.lock().unwrap(),
        [Some((10, expected.as_ref().clone()))]
    );
    assert_eq!(*port.events.lock().unwrap(), ["renew", "renew_commit"]);
    let snapshot = operation.snapshot();
    assert!(snapshot.acknowledgements.is_empty());
    assert_eq!(snapshot.renewals[0].replay_accepted, 1);
    assert!(snapshot.renewals[0].replay_bookkeeping);
}

#[tokio::test]
async fn replay_policy_controls_and_renewal_failure_never_expose_cached_payload() {
    for mode in 0..5 {
        let operation = operation();
        let port = FakeReplay {
            renew: if mode == 3 {
                Cut::BareSuccess
            } else {
                Cut::BeforeCommit
            },
            ..FakeReplay::default()
        };
        let mut cached = cache(10, vec![]);
        let mut input = request(10);
        if mode == 0 {
            input.fingerprint[0] ^= 1;
        }
        if mode == 1 {
            cached.replays = super::super::MAX_RESPONSE_REPLAYS;
        }
        if mode == 4 {
            input.rid = 11;
        }
        let mut replay = VecDeque::from([cached]);
        let mut last = Instant::now();
        let before_last = last;
        let (tx, mut rx) = oneshot::channel();
        match replay_cached(&mut replay, &input, tx, &mut last, &operation, &port).await {
            ReplayOutcome::Sent { terminate } => {
                assert!(mode < 2 && terminate);
                let response = rx.await.unwrap();
                assert!(!body(&response).contains("<message"));
                assert!(port.events.lock().unwrap().is_empty());
                assert_eq!(
                    operation.snapshot().responses[0].kind,
                    ResponseKind::TerminalControl
                );
            }
            ReplayOutcome::Failed {
                responder,
                error: _,
            } => {
                assert!(mode == 2 || mode == 3);
                assert!(rx.try_recv().is_err());
                drop(responder);
                assert_eq!(replay[0].replays, 1);
                assert_eq!(operation.snapshot().renewals[0].replay_calls, 0);
            }
            ReplayOutcome::Miss(responder) => {
                assert_eq!(mode, 4);
                drop(responder);
                assert!(port.events.lock().unwrap().is_empty());
            }
        }
        assert_eq!(last, before_last);
    }
}

#[tokio::test]
async fn fresh_ack_renews_then_applies_cache_and_each_actual_receipt_result() {
    let operation = operation();
    let port = FakeReplay {
        deleted: vec![
            response::DeletedSource::C2s {
                recipient_id: c2s(506).recipient_id,
                message_id: c2s(506).message_id,
            },
            response::DeletedSource::Mix(mix()),
        ],
        ..FakeReplay::default()
    };
    let (good, mut got) = mpsc::unbounded_channel();
    let (closed, closed_rx) = mpsc::unbounded_channel();
    drop(closed_rx);
    let mut replay = VecDeque::from([cache(9, vec![good, closed]), cache(11, vec![])]);
    renew_and_acknowledge(&mut replay, Some(10), &operation, &port)
        .await
        .unwrap();
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].rid, 11);
    assert!(got.try_recv().is_ok());
    assert!(got.try_recv().is_err());
    assert_eq!(
        *port.events.lock().unwrap(),
        ["renew", "renew_commit", "ack", "ack_commit"]
    );
    let snapshot = operation.snapshot();
    let ack = &snapshot.acknowledgements[0];
    assert_eq!(ack.knowledge, response::Knowledge::ReceiptKnown);
    assert_eq!(ack.cache_evictions, 1);
    assert_eq!(ack.receipt_calls, 2);
    assert_eq!(ack.receipts_sent, 1);
    assert_eq!(ack.receipts_refused, 1);
    assert_eq!(snapshot.summary().responses.deleted, 2);
}

#[tokio::test]
async fn none_and_empty_source_ack_preserve_existing_persistence_paths() {
    for ack in [None, Some(10)] {
        let operation = operation();
        let port = FakeReplay::default();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut replay = VecDeque::from([cache(10, vec![tx])]);
        renew_and_acknowledge(&mut replay, ack, &operation, &port)
            .await
            .unwrap();
        assert_eq!(replay.is_empty(), ack.is_some());
        assert_eq!(rx.try_recv().is_ok(), ack.is_some());
        assert_eq!(operation.summary().responses.renew_receipts, 1);
        assert_eq!(
            operation.summary().responses.ack_receipts,
            usize::from(ack.is_some())
        );
        assert_eq!(operation.summary().responses.deleted, 0);
        assert_eq!(
            port.events.lock().unwrap().len(),
            if ack.is_some() { 4 } else { 2 }
        );
    }
}

#[tokio::test]
async fn ack_or_renewal_unknown_mismatch_and_postreceipt_drop_preserve_cache() {
    for renewal in [false, true] {
        for cut in [
            Cut::BeforeCommit,
            Cut::DuringCommit,
            Cut::CommitError,
            Cut::AfterReceiptPending,
            Cut::AfterReceiptError,
            Cut::BareSuccess,
            Cut::WrongReceipt,
        ] {
            let operation = operation();
            let port = FakeReplay {
                renew: if renewal { cut } else { Cut::Success },
                ack: if renewal { Cut::Success } else { cut },
                ..FakeReplay::default()
            };
            let (tx, mut rx) = mpsc::unbounded_channel();
            let mut replay = VecDeque::from([cache(10, vec![tx])]);
            let mut runner = Box::pin(super::super::ownership::OperationRunner::new(
                operation.clone(),
                tokio::time::timeout(super::super::BOSH_BACKEND_OPERATION_TIMEOUT, async {
                    renew_and_acknowledge(&mut replay, Some(10), &operation, &port)
                        .await
                        .is_ok()
                }),
            ));
            let polled = poll_once(runner.as_mut());
            assert_eq!(
                polled.is_pending(),
                matches!(cut, Cut::DuringCommit | Cut::AfterReceiptPending)
            );
            drop(runner);
            assert_eq!(replay.len(), 1);
            assert!(rx.try_recv().is_err());
            let snapshot = operation.snapshot();
            assert_eq!(snapshot.summary().responses.evictions, 0);
            assert_eq!(snapshot.summary().responses.receipt_sends, 0);
            if renewal {
                assert!(snapshot.acknowledgements.is_empty());
                assert_eq!(
                    snapshot.summary().responses.renew_receipts,
                    usize::from(matches!(
                        cut,
                        Cut::AfterReceiptPending | Cut::AfterReceiptError
                    ))
                );
            } else {
                assert_eq!(
                    snapshot.summary().responses.ack_receipts,
                    usize::from(matches!(
                        cut,
                        Cut::AfterReceiptPending | Cut::AfterReceiptError
                    ))
                );
            }
        }
    }
}

#[tokio::test]
async fn real_resume_governor_holds_follow_shared_response_bytes_until_last_drop() {
    let operation = operation();
    let port = FakeReplay::default();
    let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
    let governor =
        SmMemoryGovernor::new(1024 * 1024, 256 * 1024, 16, 256 * 1024, metrics.clone()).unwrap();
    let source = VecDeque::from([crate::xmpp::outbound::SmUnackedStanza::plain(
        "<message><body>".to_owned() + &"x".repeat(4096) + "</body></message>",
    )]);
    let action = crate::xmpp::protocol::ResumePayload::from_sm_unacked(
        &governor,
        "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='fixture'/>".to_owned(),
        vec![],
        &source,
        false,
    )
    .unwrap();
    let mut harness = Harness::new([]);
    harness.governor = governor;
    assert!(super::super::queue_bosh_resume_payload(
        &mut harness.output,
        &mut harness.bytes,
        16,
        64 * 1024,
        action.into_transport_parts()
    ));
    assert!(Arc::ptr_eq(
        harness.output[0].transient_sm_capacity.as_ref().unwrap(),
        harness.output[1].transient_sm_capacity.as_ref().unwrap()
    ));
    let bound = harness.prepare(&operation, &port, 10, None).await.unwrap();
    let retained = metrics
        .reserved_bytes
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(retained > 0);
    let (tx, rx) = oneshot::channel();
    let exposed = bound.expose(vec![tx]).unwrap();
    let transport = rx.await.unwrap();
    let pointer = transport.body.as_ptr();
    let mut last = Instant::now();
    let mut highest = 0;
    exposed
        .finish(&mut last, &mut highest, &mut harness.replay)
        .unwrap();
    assert_eq!(harness.replay[0].response.body.as_ptr(), pointer);
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        retained
    );
    harness.replay.clear();
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        retained
    );
    drop(transport);
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn real_governor_rejection_preserves_fifo_before_response_buffer_allocation() {
    let operation = operation();
    let port = FakeReplay::default();
    let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
    let governor =
        SmMemoryGovernor::new(1024 * 1024, 256 * 1024, 16, 256 * 1024, metrics.clone()).unwrap();
    let hold = Arc::new(governor.try_reserve_transient(512).unwrap());
    let mut harness = Harness::new([OutboundItem::resume_fragment(
        "<presence/>".to_owned(),
        hold.clone(),
    )]);
    harness.governor = governor.clone();
    let blocker = governor.try_reserve_transient(1024 * 1024 - 512).unwrap();
    let pointer = harness.output[0].stanza.as_ptr();
    let before_bytes = harness.bytes;
    assert!(harness.prepare(&operation, &port, 10, None).await.is_err());
    assert_eq!(harness.output.len(), 1);
    assert_eq!(harness.output[0].stanza.as_ptr(), pointer);
    assert_eq!(harness.bytes, before_bytes);
    assert!(port.events.lock().unwrap().is_empty());
    assert!(operation.snapshot().responses[0].attempts.is_empty());
    drop(blocker);
    harness.output.clear();
    drop(hold);
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}
