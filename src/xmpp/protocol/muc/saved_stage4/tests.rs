use super::*;
fn fixed(n: u128) -> wire::Id {
    wire::Id(Uuid::from_u128(n))
}
fn text<const N: usize>(s: &str) -> wire::Text<N> {
    wire::Text::new(s).unwrap()
}
fn list<T, const N: usize>(xs: Vec<T>) -> wire::List<T, N> {
    wire::List::new(xs).unwrap()
}
fn input(drive: wire::MucDrive, original: Option<wire::Id>) -> wire::MucInput {
    let volatile = drive == wire::MucDrive::DropSecondEndpoint;
    let stanza = format!("<message xmlns='jabber:client' from='room@conference.example.test/a' to='room@conference.example.test' type='groupchat'><body>hi</body><stanza-id xmlns='urn:xmpp:sid:0' by='room@conference.example.test' id='{}'/></message>", fixed(63).0);
    let mut recipients = vec![wire::RecipientInput {
        user_id: fixed(4),
        full_jid: text("a@example.test/one"),
        connection_id: fixed(2),
        blocked: false,
        endpoint: wire::EndpointCut::Return,
    }];
    if volatile {
        recipients.push(wire::RecipientInput {
            user_id: fixed(6),
            full_jid: text("b@example.test/two"),
            connection_id: fixed(7),
            blocked: false,
            endpoint: wire::EndpointCut::Pending,
        });
    }
    if original.is_some() || drive == wire::MucDrive::DropCommit {
        recipients.clear();
    }
    wire::MucInput {
        frame: wire::Frame { frame_id: fixed(1), connection_id: fixed(2), transport: wire::TransportKind::Tcp,
            input: text("<message xmlns='jabber:client' to='room@conference.example.test' type='groupchat'><body>hi</body></message>") },
        configured_domain: text("example.test"),
        command: wire::MucCommand { id: fixed(63), room_id: fixed(60), actor_scope: text("a@example.test"),
            origin_id: if volatile { wire::Nullable::Null(()) } else { wire::Nullable::Value(text("origin")) },
            sender_jid: text("a@example.test/one"), nick: text("a"), stanza: text(&stanza), encrypted: false,
            archive: !volatile, retention_days: 7,
            authority: wire::Authority { clustered: false, expected_room_epoch: fixed(61),
                principal: wire::MucPrincipal::Local(wire::LocalPrincipal { user_id: fixed(4), local_domain: text("example.test") }),
                actor_scope: text("a@example.test"), full_jid: text("a@example.test/one"), nick: text("a"),
                occupant_incarnation: fixed(62), connection_uuid: fixed(2), expected_role: text("participant"),
                expected_affiliation: text("member"), cluster_target: wire::Nullable::Null(()) } },
        admission: wire::RatedAdmission { fence: wire::AdmissionFenceInput {
            admission_key: wire::Hex::of(&[0; 32]).unwrap(), payload_mac: wire::Hex::of(&[1; 32]).unwrap(),
            lease_token: fixed(64), dedupe_digest: wire::Hex::of(&[2; 32]).unwrap() },
            requirement: wire::AdmissionRequirement { action: text("message"), step: 0, work_factor: 1,
                max_work_factor: 1, hard_wait_seconds: 0, retry_after_seconds: 0, cooldown_seconds: 0,
                approximate_max_device_seconds: 0, notice: text("synthetic") },
            begin_commit: wire::CommitCut::Complete, finalize_commit: wire::CommitCut::Complete },
        repository: wire::MucRepository { original_id: nullable(original),
            commit: if drive == wire::MucDrive::DropCommit { wire::CommitCut::Pending } else { wire::CommitCut::Complete } },
        recipients: list(recipients),
        native: if drive == wire::MucDrive::Complete && original.is_none() { wire::Nullable::Value(wire::PlainNative {
            connection_id: fixed(2), write: wire::WriteScript { chunk_limit: 4096,
                fail_after_accepted_bytes: wire::Nullable::Null(()), flush: wire::FlushReply::Ok } }) }
            else { wire::Nullable::Null(()) }, drive,
    }
}
fn case(input: wire::MucInput, name: &str) -> wire::Case {
    wire::Case {
        schema: text(wire::CASE_SCHEMA),
        case_id: text(name),
        adapter_contract: text(wire::ADAPTER_CONTRACT),
        composition: wire::Composition::Muc(input),
    }
}
async fn execute(input: wire::MucInput, name: &str) -> wire::Envelope {
    let bytes = serde_json::to_vec(&case(input, name)).unwrap();
    let validated = wire::decode(&bytes).unwrap();
    let wire::Composition::Muc(input) = &validated.case().composition else {
        unreachable!()
    };
    let recorder = Arc::new(Mutex::new(wire::Recorder::new(&validated)));
    let actual = run(input.clone(), recorder.clone()).await;
    let recorder = match Arc::try_unwrap(recorder) {
        Ok(x) => x,
        Err(_) => panic!("recorder escaped adapter"),
    };
    let recorder = recorder.into_inner().unwrap();
    let envelope = match actual {
        Ok(execution) => recorder.finish(execution).unwrap(),
        Err(_) => recorder.finish_resource_stopped().unwrap(),
    };
    wire::validate_envelope(&envelope, &bytes, Some(&validated)).unwrap();
    envelope
}
fn frames(e: &wire::Envelope) -> Vec<(u32, &wire::FrameCapture<E>)> {
    e.facts
        .as_slice()
        .iter()
        .filter_map(|x| match &x.fact {
            wire::Fact::Frame(f) => Some((x.seq, f)),
            _ => None,
        })
        .collect()
}
fn mucs(e: &wire::Envelope) -> Vec<(u32, &wire::MucCapture<E>)> {
    e.facts
        .as_slice()
        .iter()
        .filter_map(|x| match &x.fact {
            wire::Fact::Muc(wire::MucFact::Snapshot(f)) => Some((x.seq, f)),
            _ => None,
        })
        .collect()
}
fn endpoints(e: &wire::Envelope) -> Vec<(u32, &wire::MucEndpoint<E>)> {
    e.facts
        .as_slice()
        .iter()
        .filter_map(|x| match &x.fact {
            wire::Fact::Muc(wire::MucFact::Endpoint(f)) => Some((x.seq, f)),
            _ => None,
        })
        .collect()
}
fn complete(e: &wire::Envelope) {
    assert!(matches!(
        e.observation_status,
        wire::ObservationStatus::Complete(_)
    ));
}
fn fixed_e(n: u128) -> E {
    E::Encoded(wire::IdentityLabel::Fixed(wire::FixedIdentity {
        uuid: fixed(n),
    }))
}
fn assert_child_before_retirement(e: &wire::Envelope, terminal: wire::OwnerTerminal) {
    let muc = mucs(e);
    let terminal_cut = muc
        .iter()
        .find(|(_, f)| f.cut == wire::Cut::AfterRunnerDrop)
        .unwrap();
    assert_eq!(terminal_cut.1.snapshot.terminal.get(), Some(&terminal));
    let drops: Vec<_> = muc
        .iter()
        .filter(|(_, f)| f.cut == wire::Cut::ChildDrop)
        .collect();
    assert!(!drops.is_empty());
    for (seq, f) in drops {
        assert!(*seq < terminal_cut.0);
        assert!(f.snapshot.terminal.get().is_none());
    }
}
#[tokio::test]
async fn stored_receipt_exact_queue_native_flush_and_finalize_are_observed() {
    let e = execute(input(wire::MucDrive::Complete, None), "ordinary-muc-stored").await;
    complete(&e);
    assert_eq!(e.execution.get(), Some(&wire::Execution::Complete));
    let frames = frames(&e);
    let final_frame = frames.last().unwrap().1;
    assert_eq!(final_frame.frame, fixed_e(1));
    assert_eq!(
        final_frame.outcome.get(),
        Some(&wire::FrameOutcome::Completed)
    );
    assert!(matches!(
        final_frame.admission_begin.get().unwrap().knowledge,
        wire::AdmissionKnowledge::ReceiptKnown(_)
    ));
    assert!(matches!(
        final_frame.admission_finalize.get().unwrap().knowledge,
        wire::AdmissionKnowledge::ReceiptKnown(_)
    ));
    let muc = mucs(&e);
    let final_muc = muc.last().unwrap().1;
    assert!(
        matches!(&final_muc.snapshot.knowledge, wire::MucKnowledge::ReceiptKnown(x)
        if matches!(&x.outcome, wire::MucOutcome::Stored(y) if y.id == fixed_e(63))
            && x.fresh_class.get() == Some(&wire::AcceptanceClass::ArchiveAndIdentity))
    );
    assert_eq!(final_muc.snapshot.fanout.accepted, 1);
    let endpoints = endpoints(&e);
    let queued = endpoints
        .iter()
        .find(|(_, x)| x.queued_item.get().is_some())
        .unwrap();
    let (dequeue_seq, dequeued) = e
        .facts
        .as_slice()
        .iter()
        .find_map(|x| match &x.fact {
            wire::Fact::Native(wire::NativeFact::Dequeue(d)) => Some((x.seq, d)),
            _ => None,
        })
        .unwrap();
    assert!(queued.0 < dequeue_seq);
    assert_eq!(queued.1.queued_item.get(), Some(&dequeued.item));
    assert!(dequeued.item.source.get().is_none());
    let flush_seq = e
        .facts
        .as_slice()
        .iter()
        .find_map(|x| match &x.fact {
            wire::Fact::Native(wire::NativeFact::Flush(f)) if f.result == wire::IoResult::Ok => {
                Some(x.seq)
            }
            _ => None,
        })
        .unwrap();
    let finalize_seq = frames
        .iter()
        .find(|(_, f)| f.admission_finalize.get().is_some())
        .unwrap()
        .0;
    assert!(flush_seq < finalize_seq);
    assert_child_before_retirement(&e, wire::OwnerTerminal::Completed);
}
#[tokio::test]
async fn replay_retains_original_identity_and_never_enters_fanout_or_native() {
    let e = execute(
        input(wire::MucDrive::Complete, Some(fixed(65))),
        "ordinary-muc-replay",
    )
    .await;
    complete(&e);
    assert_eq!(e.execution.get(), Some(&wire::Execution::Complete));
    let muc = mucs(&e);
    assert!(matches!(&muc.last().unwrap().1.snapshot.returned,
        wire::Nullable::Value(wire::MucReturned::Outcome(wire::MucOutcome::Replay(x))) if x.id == fixed_e(65)));
    assert_eq!(
        muc.last().unwrap().1.snapshot.fanout.stage,
        wire::FanoutStage::Unavailable
    );
    assert!(endpoints(&e).is_empty());
    assert!(!e.facts.as_slice().iter().any(|x| matches!(
        &x.fact,
        wire::Fact::Native(_) | wire::Fact::Muc(wire::MucFact::Recipients(_))
    )));
    assert!(frames(&e)
        .last()
        .unwrap()
        .1
        .admission_finalize
        .get()
        .is_some());
}
#[tokio::test]
async fn volatile_second_endpoint_is_polled_pending_and_actual_drop_preserves_prefix() {
    let e = execute(
        input(wire::MucDrive::DropSecondEndpoint, None),
        "ordinary-muc-endpoint-drop",
    )
    .await;
    complete(&e);
    assert_eq!(e.execution.get(), Some(&wire::Execution::Cancelled));
    let endpoints = endpoints(&e);
    let first = endpoints
        .iter()
        .find(|(_, x)| x.ordinal == 0 && x.returned.get() == Some(&true))
        .unwrap();
    let second = endpoints
        .iter()
        .find(|(_, x)| x.ordinal == 1 && x.entered)
        .unwrap();
    assert!(first.0 < second.0);
    assert!(first.1.queued_item.get().is_some());
    assert!(endpoints
        .iter()
        .filter(|(_, x)| x.ordinal == 1)
        .all(|(_, x)| x.returned.get().is_none() && x.queued_item.get().is_none()));
    let muc = mucs(&e);
    let final_muc = muc.last().unwrap().1;
    assert!(
        matches!(&final_muc.snapshot.knowledge, wire::MucKnowledge::ReceiptKnown(x)
        if x.fresh_class.get() == Some(&wire::AcceptanceClass::Volatile))
    );
    assert_eq!(final_muc.snapshot.fanout.next_recipient, 1);
    assert_eq!(final_muc.snapshot.fanout.accepted, 1);
    assert!(final_muc.snapshot.fanout.endpoint_pending);
    assert!(frames(&e)
        .last()
        .unwrap()
        .1
        .admission_finalize
        .get()
        .is_none());
    assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
    assert_eq!(e.facts.as_slice().iter().filter(|x| matches!(&x.fact,
        wire::Fact::Driver(p) if p.owner == wire::DriverOwner::Muc && p.result == wire::PollResult::Pending)).count(), 1);
    assert!(
        muc.iter()
            .filter(|(_, x)| x.cut == wire::Cut::ChildDrop)
            .count()
            >= 2
    );
}
#[tokio::test]
async fn commit_is_polled_pending_without_receipt_and_drop_keeps_unknown() {
    let e = execute(
        input(wire::MucDrive::DropCommit, None),
        "ordinary-muc-commit-drop",
    )
    .await;
    complete(&e);
    assert_eq!(e.execution.get(), Some(&wire::Execution::Cancelled));
    let muc = mucs(&e);
    let before = muc
        .iter()
        .find(|(_, x)| x.cut == wire::Cut::AfterPoll)
        .unwrap()
        .1;
    let after = muc.last().unwrap().1;
    assert!(matches!(
        before.snapshot.knowledge,
        wire::MucKnowledge::CommitCallEntered(_)
    ));
    assert_eq!(before.snapshot.knowledge, after.snapshot.knowledge);
    assert!(after.snapshot.returned.get().is_none());
    assert_eq!(after.snapshot.fanout.stage, wire::FanoutStage::Unavailable);
    assert!(endpoints(&e).is_empty());
    let frame = frames(&e).last().unwrap().1;
    assert!(matches!(
        frame.admission_begin.get().unwrap().knowledge,
        wire::AdmissionKnowledge::ReceiptKnown(_)
    ));
    assert!(frame.admission_finalize.get().is_none());
    assert_eq!(frame.outcome.get(), Some(&wire::FrameOutcome::Cancelled));
    assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
    assert_eq!(e.facts.as_slice().iter().filter(|x| matches!(&x.fact,
        wire::Fact::Driver(p) if p.owner == wire::DriverOwner::Muc && p.result == wire::PollResult::Pending)).count(), 1);
    assert!(
        muc.iter()
            .filter(|(_, x)| x.cut == wire::Cut::ChildDrop)
            .count()
            >= 2
    );
}
// The draft1 raw_frame_mapping_is_exhaustive_without_unknown_fallback
// control moved with its only real implementation to shared frame capture:
// every_actual_stage_discriminant_has_its_exact_closed_projection,
// outcome_mapping_is_closed_and_never_defaults_unknown_to_pending, and
// actual_publication_outcomes_project_without_boolean_collapse.
#[tokio::test]
async fn partial_native_calls_report_exact_accepted_bytes_before_one_flush() {
    let mut i = input(wire::MucDrive::Complete, None);
    let wire::Nullable::Value(native) = &mut i.native else {
        unreachable!()
    };
    native.write.chunk_limit = 32;
    let e = execute(i, "ordinary-muc-partial-write").await;
    complete(&e);
    let stanza = e
        .facts
        .as_slice()
        .iter()
        .find_map(|x| match &x.fact {
            wire::Fact::Native(wire::NativeFact::Dequeue(d)) => Some(d.item.stanza.as_str()),
            _ => None,
        })
        .unwrap();
    let mut accepted = Vec::new();
    let mut writes = 0;
    let mut flushes = 0;
    for x in e.facts.as_slice() {
        match &x.fact {
            wire::Fact::Native(wire::NativeFact::Write(w)) => {
                assert_eq!(w.result, wire::IoResult::Ok);
                let hex: String =
                    serde_json::from_str(&serde_json::to_string(&w.accepted_bytes_hex).unwrap())
                        .unwrap();
                accepted.extend(
                    hex.as_bytes()
                        .chunks_exact(2)
                        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()),
                );
                writes += 1;
            }
            wire::Fact::Native(wire::NativeFact::Flush(f)) => {
                assert_eq!(f.result, wire::IoResult::Ok);
                flushes += 1;
            }
            _ => {}
        }
    }
    assert!(writes > 1);
    assert_eq!(accepted, stanza.as_bytes());
    assert_eq!(flushes, 1);
}
#[tokio::test]
async fn short_parser_xml_is_explicit_loss_instead_of_synthesized_live_output() {
    let mut i = input(wire::MucDrive::Complete, None);
    i.command.stanza = text("<message type='groupchat'><body>hi</body></message>");
    let e = execute(i, "ordinary-missing-live-envelope").await;
    assert_eq!(e.execution.get(), Some(&wire::Execution::Failed));
    assert!(matches!(
        e.observation_status,
        wire::ObservationStatus::Lost(_)
    ));
    assert!(e.facts.is_empty());
}
#[tokio::test]
async fn case_label_does_not_select_behavior_or_seed_observed_facts() {
    let a = execute(input(wire::MucDrive::DropSecondEndpoint, None), "label-one").await;
    let b = execute(input(wire::MucDrive::DropSecondEndpoint, None), "label-two").await;
    complete(&a);
    complete(&b);
    assert_ne!(a.input_sha256, b.input_sha256);
    assert_eq!(a.facts, b.facts);
    assert_eq!(a.identity_map, b.identity_map);
}

fn recorder_for(input: wire::MucInput) -> Recorder {
    let bytes = serde_json::to_vec(&case(input, "ordinary-r2-control")).unwrap();
    Arc::new(Mutex::new(wire::Recorder::new(
        &wire::decode(&bytes).unwrap(),
    )))
}
fn take_recorder(recorder: Recorder) -> wire::Recorder {
    match Arc::try_unwrap(recorder) {
        Ok(recorder) => recorder.into_inner().unwrap(),
        Err(_) => panic!("test owner retained recorder"),
    }
}
fn script(chunk: u32, fail: Option<u32>) -> wire::WriteScript {
    wire::WriteScript {
        chunk_limit: chunk,
        fail_after_accepted_bytes: nullable(fail),
        flush: wire::FlushReply::Ok,
    }
}
struct NativeResult {
    actual: std::result::Result<Poll<Result<()>>, wire::BudgetStop>,
    snapshot: native::Snapshot,
    accepted: usize,
    writes: u8,
    flushes: u8,
}
// Deliberately starts below adapter preflight to exercise the independent
// runtime backstop. This is an ordinary control, never a saved input route.
async fn native_backstop(
    item: OutboundItem,
    script: wire::WriteScript,
    recorder: Recorder,
) -> NativeResult {
    let site = wire::PollSite::new(wire::DriverOwner::Native, 0).unwrap();
    let observation = native::Observation::new(item.durable_source);
    let mut port = PlainPort {
        connection: fixed(2).0,
        recorder: recorder.clone(),
    };
    let mut writer = Writer {
        script,
        accepted: 0,
        materialized_len: item.stanza.len(),
        ordinal: 0,
        recorder: recorder.clone(),
        write_calls: 0,
        flush_calls: 0,
        stopped: false,
    };
    let child = async {
        let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
        let written = lease
            .write(|stanza| crate::xmpp::send(&mut writer, stanza))
            .await?;
        written.settle_with(&port).await;
        Ok::<_, anyhow::Error>(())
    };
    let mut runner = Box::pin(NativeWriteRunner::new(observation.clone(), child));
    let actual = std::future::poll_fn(|cx| {
        Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
    })
    .await;
    drop(runner);
    NativeResult {
        actual,
        snapshot: observation.snapshot(),
        accepted: writer.accepted,
        writes: writer.write_calls,
        flushes: writer.flush_calls,
    }
}
fn observed_fixture(
    i: &wire::MucInput,
    command: MucDiscussion,
    recorder: Recorder,
) -> (
    FrameExecution,
    SessionExecutions,
    Arc<Observers>,
    RoomApplication<RepositoryHandle>,
    PreparedMucDiscussion,
) {
    let (room, room_jid) = supplied_room(&command).unwrap();
    let repository = Arc::new(DiscussionRepository {
        supplied: i.repository.clone(),
        recorder: recorder.clone(),
        observation: Mutex::new(None),
    });
    let application = RoomApplication::new(
        RepositoryHandle(repository.clone()),
        i.configured_domain.as_str(),
    );
    let prepared = application.prepare_discussion(command.clone());
    let requested = prepared.requested_class();
    let prepared = PreparedMucDiscussion::new(prepared, &room, room_jid, command.stanza).unwrap();
    let frame = FrameExecution::for_saved_case(
        crate::xmpp::protocol::ClientTransport::Tcp,
        i.frame.input.as_str(),
        i.frame.frame_id.0,
    );
    let sessions = SessionExecutions::for_saved_frame(frame.clone());
    let muc = sessions
        .muc_discussion(&prepared.prepared)
        .unwrap()
        .unwrap();
    let observed = Arc::new(Observers {
        recorder,
        frame: frame.clone(),
        admission: frame.direct_operation(),
        muc,
        requested,
        repository_command: Mutex::new(None),
        begin_returned: AtomicBool::new(false),
        finalize_returned: AtomicBool::new(false),
        commit_pending_polled: AtomicBool::new(false),
        endpoint_pending_polled: AtomicBool::new(false),
    });
    *repository.observation.lock().unwrap() = Some(observed.clone());
    (frame, sessions, observed, application, prepared)
}
#[tokio::test]
async fn sticky_lost_recorder_does_not_change_any_finite_muc_owner_result() {
    for (i, expected, polls) in [
        (
            input(wire::MucDrive::Complete, None),
            wire::Execution::Complete,
            2,
        ),
        (
            input(wire::MucDrive::Complete, Some(fixed(65))),
            wire::Execution::Complete,
            1,
        ),
        (
            input(wire::MucDrive::DropSecondEndpoint, None),
            wire::Execution::Cancelled,
            1,
        ),
        (
            input(wire::MucDrive::DropCommit, None),
            wire::Execution::Cancelled,
            1,
        ),
    ] {
        let recorder = recorder_for(i.clone());
        driver::lost(&recorder);
        assert_eq!(run(i, recorder.clone()).await.unwrap(), expected);
        assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), polls);
        assert!(driver::resource_stop(&recorder).is_none());
        let e = take_recorder(recorder).finish(expected).unwrap();
        assert!(matches!(
            e.observation_status,
            wire::ObservationStatus::Lost(_)
        ));
        assert_eq!(e.execution.get(), Some(&expected));
        assert!(e.resource_stop.get().is_none());
    }
}
#[tokio::test]
async fn lost_recorder_preserves_actual_native_write_flush_and_retirement() {
    let recorder = recorder_for(input(wire::MucDrive::Complete, None));
    driver::lost(&recorder);
    let result = native_backstop(
        OutboundItem::plain("abcdef".into()),
        script(2, None),
        recorder.clone(),
    )
    .await;
    assert!(matches!(result.actual, Ok(Poll::Ready(Ok(())))));
    assert_eq!((result.accepted, result.writes, result.flushes), (6, 3, 1));
    assert_eq!(
        result.snapshot.writer_result,
        Some(native::WriterResult::FullWrite)
    );
    assert_eq!(
        result.snapshot.write_decision,
        Some(native::WriteDecision::Written)
    );
    assert_eq!(result.snapshot.terminal, Some(native::Terminal::Returned));
    assert!(driver::resource_stop(&recorder).is_none());
}
#[tokio::test]
async fn failed_muc_command_projection_does_not_turn_actual_commit_into_backend_failure() {
    let i = input(wire::MucDrive::Complete, None);
    let recorder = recorder_for(i.clone());
    let mut command = input_command(&i.command);
    command.stanza = command.stanza.replace(
        "<body>hi</body>",
        &format!("<body>{}</body>", "x".repeat(5000)),
    );
    let (frame, _sessions, observed, application, prepared) =
        observed_fixture(&i, command, recorder.clone());
    let child = async {
        let _drop = ChildDrop(observed.clone());
        let bound = prepared.bind(observed.muc.clone())?;
        let completion = application
            .admit_discussion_observed(&bound.request)
            .await
            .map_err(|e| match e {
                muc::AdmissionError::Observation(e) => anyhow::Error::from(e),
                muc::AdmissionError::Repository(e) => e,
            })?;
        let returned = completion.outcome();
        assert!(bound.finish(completion)?.is_some());
        Ok::<_, anyhow::Error>(returned)
    };
    let mut runner = Box::pin(frame.run(child));
    let site = wire::PollSite::new(wire::DriverOwner::Muc, 0).unwrap();
    let result = std::future::poll_fn(|cx| {
        Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
    })
    .await;
    drop(runner);
    assert!(
        matches!(result, Ok(Poll::Ready(Ok(MucDiscussionAdmission::Stored(x)))) if x == fixed(63).0)
    );
    assert!(matches!(
        observed.muc.snapshot().knowledge,
        muc::Knowledge::ReceiptKnown(_)
    ));
    assert_eq!(
        observed.muc.snapshot().terminal,
        Some(muc::TerminalReason::Completed)
    );
    assert_eq!(frame.observation_for_saved_case().outcome_raw, 1);
    assert!(driver::resource_stop(&recorder).is_none());
    drop(application);
    drop(observed);
    drop(_sessions);
    drop(frame);
    let e = take_recorder(recorder)
        .finish(wire::Execution::Complete)
        .unwrap();
    assert!(matches!(
        e.observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}
#[tokio::test]
async fn queue_projection_bound_is_loss_and_not_a_new_native_byte_limit() {
    let i = input(wire::MucDrive::Complete, None);
    let recorder = recorder_for(i.clone());
    let (frame, _sessions, observed, _application, _prepared) =
        observed_fixture(&i, input_command(&i.command), recorder.clone());
    let endpoint = Endpoint::supplied(0, &i.recipients.as_slice()[0]);
    let actual_bytes = "x".repeat(20_000);
    endpoint.sender.try_send(actual_bytes).unwrap();
    let spec = wire::PlainNative {
        connection_id: fixed(2),
        write: script(4096, None),
    };
    let mut runner = Box::pin(frame.run(native_item(&spec, &endpoint, &observed)));
    let site = wire::PollSite::new(wire::DriverOwner::Muc, 0).unwrap();
    let actual = std::future::poll_fn(|cx| {
        Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
    })
    .await;
    drop(runner);
    assert!(matches!(actual, Ok(Poll::Ready(Ok(())))));
    assert_eq!(frame.observation_for_saved_case().outcome_raw, 1);
    assert!(driver::resource_stop(&recorder).is_none());
    assert!(endpoint.receiver.lock().unwrap().try_recv().is_err());
    drop(_application);
    drop(_prepared);
    drop(observed);
    drop(_sessions);
    drop(frame);
    let e = take_recorder(recorder)
        .finish(wire::Execution::Complete)
        .unwrap();
    assert!(matches!(
        e.observation_status,
        wire::ObservationStatus::Lost(_)
    ));
    assert!(e.resource_stop.get().is_none());
}
#[test]
fn native_required_calls_count_the_scripted_failure_and_zero_length_exactly() {
    assert_eq!(required_write_calls(33, &script(1, Some(31))), Some(32));
    assert_eq!(required_write_calls(33, &script(1, Some(32))), Some(33));
    assert_eq!(required_write_calls(33, &script(1, Some(0))), Some(1));
    assert_eq!(required_write_calls(33, &script(2, Some(33))), Some(17));
    assert_eq!(required_write_calls(33, &script(2, Some(100))), Some(17));
    assert_eq!(required_write_calls(33, &script(2, None)), Some(17));
    assert_eq!(required_write_calls(0, &script(1, Some(0))), Some(0));
    assert_eq!(required_write_calls(0, &script(1, None)), Some(0));
    assert_eq!(required_write_calls(33, &script(0, None)), None);
}
#[tokio::test]
async fn thirty_second_scripted_failure_remains_genuine_error_and_thirty_third_is_stopped_before_poll(
) {
    let item = OutboundItem::plain("x".repeat(33));
    let recorder = recorder_for(input(wire::MucDrive::Complete, None));
    assert!(native_preflight(&item, &script(1, Some(31)), 0, &recorder).is_none());
    let result = native_backstop(item, script(1, Some(31)), recorder.clone()).await;
    assert!(matches!(result.actual, Ok(Poll::Ready(Err(_)))));
    assert_eq!(
        (result.accepted, result.writes, result.flushes),
        (31, 32, 0)
    );
    assert_eq!(
        result.snapshot.writer_result,
        Some(native::WriterResult::Failed)
    );
    assert_eq!(result.snapshot.terminal, Some(native::Terminal::Returned));
    assert!(driver::resource_stop(&recorder).is_none());
    let stop = native_preflight(
        &OutboundItem::plain("x".repeat(33)),
        &script(1, Some(32)),
        0,
        &recorder,
    )
    .unwrap();
    assert!(
        matches!(stop.resource_stop, wire::ResourceStop::NativeWrite(x) if x.admitted_calls == 0)
    );
}
#[tokio::test]
async fn actual_set_to_expansion_drives_preflight_and_keeps_actual_frame_cancelled() {
    let mut i = input(wire::MucDrive::Complete, None);
    let original_len = i.command.stanza.as_str().len();
    let chunk = original_len.div_ceil(32) as u32;
    let wire::Nullable::Value(native) = &mut i.native else {
        unreachable!()
    };
    native.write.chunk_limit = chunk;
    let mut recipients = i.recipients.as_slice().to_vec();
    recipients[0].full_jid = text(&format!("a@example.test/{}", "r".repeat(700)));
    let actual =
        crate::xmpp::xml_util::set_to(i.command.stanza.as_str(), recipients[0].full_jid.as_str());
    assert!(required_write_calls(original_len, &script(chunk, None)).unwrap() <= 32);
    assert!(required_write_calls(actual.len(), &script(chunk, None)).unwrap() > 32);
    i.recipients = list(recipients);
    let e = execute(i, "ordinary-rendered-call-budget").await;
    assert!(e.execution.get().is_none() && e.rejection.get().is_none());
    assert!(
        matches!(e.resource_stop.get(), Some(wire::ResourceStop::NativeWrite(x)) if x.admitted_calls == 0)
    );
    assert_eq!(
        frames(&e).last().unwrap().1.outcome.get(),
        Some(&wire::FrameOutcome::Cancelled)
    );
    assert!(matches!(
        mucs(&e).last().unwrap().1.snapshot.knowledge,
        wire::MucKnowledge::ReceiptKnown(_)
    ));
    assert!(!e
        .facts
        .as_slice()
        .iter()
        .any(|x| matches!(x.fact, wire::Fact::Native(wire::NativeFact::Write(_)))));
    assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
}
#[tokio::test]
async fn lost_observation_does_not_disable_independent_native_write_stop() {
    let recorder = recorder_for(input(wire::MucDrive::Complete, None));
    driver::lost(&recorder);
    let result = native_backstop(
        OutboundItem::plain("x".repeat(33)),
        script(1, None),
        recorder.clone(),
    )
    .await;
    assert!(
        matches!(result.actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::NativeWrite(x) })
        if x.admitted_calls == 32)
    );
    assert_eq!(
        (result.accepted, result.writes, result.flushes),
        (31, 32, 0)
    );
    assert!(result.snapshot.writer_result.is_none());
    assert_eq!(result.snapshot.terminal, Some(native::Terminal::Cancelled));
    let e = take_recorder(recorder).finish_resource_stopped().unwrap();
    assert!(e.execution.get().is_none() && e.rejection.get().is_none());
    assert!(matches!(
        e.observation_status,
        wire::ObservationStatus::Lost(_)
    ));
    assert!(e.resource_stop.get().is_some());
}
#[tokio::test]
async fn second_flush_is_resource_pending_without_a_scripted_io_error() {
    use tokio::io::AsyncWriteExt as _;
    let recorder = recorder_for(input(wire::MucDrive::Complete, None));
    let item = OutboundItem::plain("abc".into());
    let observation = native::Observation::new(None);
    let mut port = PlainPort {
        connection: fixed(2).0,
        recorder: recorder.clone(),
    };
    let mut writer = Writer {
        script: script(3, None),
        accepted: 0,
        materialized_len: 3,
        ordinal: 0,
        recorder: recorder.clone(),
        write_calls: 0,
        flush_calls: 0,
        stopped: false,
    };
    let child = async {
        let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
        let written = lease
            .write(|stanza| async {
                crate::xmpp::send(&mut writer, stanza).await?;
                writer.flush().await?;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        written.settle_with(&port).await;
        Ok::<_, anyhow::Error>(())
    };
    let mut runner = Box::pin(NativeWriteRunner::new(observation.clone(), child));
    let site = wire::PollSite::new(wire::DriverOwner::Native, 0).unwrap();
    let actual = std::future::poll_fn(|cx| {
        Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
    })
    .await;
    drop(runner);
    assert!(
        matches!(actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::NativeFlush(x) })
        if x.admitted_calls == 1)
    );
    assert_eq!(writer.flush_calls, 1);
    assert!(observation.snapshot().writer_result.is_none());
    assert_eq!(
        observation.snapshot().terminal,
        Some(native::Terminal::Cancelled)
    );
}
#[tokio::test]
async fn nested_native_backstop_drops_children_before_frame_without_backend_failure() {
    let i = input(wire::MucDrive::Complete, None);
    let recorder = recorder_for(i.clone());
    let (frame, sessions, observed, application, prepared) =
        observed_fixture(&i, input_command(&i.command), recorder.clone());
    let item = OutboundItem::plain("x".repeat(33));
    // Preflight originally fits; an ordinary-only stale-script fault below
    // demonstrates the runtime backstop without adding any saved selector.
    assert!(native_preflight(&item, &script(2, None), 0, &recorder).is_none());
    let observation = native::Observation::new(None);
    let snapshots = Arc::new(NativeCapture {
        recorder: recorder.clone(),
        frame: frame.operation_id(),
        connection: fixed(2).0,
        ordinal: 0,
        observation: observation.clone(),
    });
    let mut port = PlainPort {
        connection: fixed(2).0,
        recorder: recorder.clone(),
    };
    let mut writer = Writer {
        script: script(1, None),
        accepted: 0,
        materialized_len: 33,
        ordinal: 0,
        recorder: recorder.clone(),
        write_calls: 0,
        flush_calls: 0,
        stopped: false,
    };
    let frame_child = async {
        let _frame_child_drop = ChildDrop(observed.clone());
        let bound = prepared.bind(observed.muc.clone())?;
        let completion = application
            .admit_discussion_observed(&bound.request)
            .await
            .map_err(|e| match e {
                muc::AdmissionError::Observation(e) => anyhow::Error::from(e),
                muc::AdmissionError::Repository(e) => e,
            })?;
        let _accepted = bound.finish(completion)?.unwrap();
        let native_child = async {
            let _native_child_drop = NativeChildDrop(snapshots.clone());
            let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
            let written = lease
                .write(|stanza| crate::xmpp::send(&mut writer, stanza))
                .await?;
            written.settle_with(&port).await;
            Ok::<_, anyhow::Error>(())
        };
        let terminal = NativeAfterRunnerDrop(snapshots.clone());
        let mut native_runner = Box::pin(NativeWriteRunner::new(observation.clone(), native_child));
        let site = wire::PollSite::new(wire::DriverOwner::Native, 0).unwrap();
        let actual = std::future::poll_fn(|cx| {
            Poll::Ready(driver::poll_once(
                &recorder,
                site,
                native_runner.as_mut(),
                cx,
            ))
        })
        .await;
        let result = match actual {
            Err(_) => return std::future::pending::<Result<()>>().await,
            Ok(Poll::Ready(result)) => result,
            Ok(Poll::Pending) => return std::future::pending::<Result<()>>().await,
        };
        drop(native_runner);
        drop(terminal);
        result
    };
    let mut runner = Box::pin(frame.run(frame_child));
    let site = wire::PollSite::new(wire::DriverOwner::Muc, 0).unwrap();
    let actual = std::future::poll_fn(|cx| {
        Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
    })
    .await;
    assert!(
        matches!(actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::NativeWrite(x) })
        if x.admitted_calls == 32)
    );
    drop(runner);
    observed.both(wire::Cut::AfterRunnerDrop);
    assert_eq!((writer.accepted, writer.write_calls), (31, 32));
    assert_eq!(
        observation.snapshot().terminal,
        Some(native::Terminal::Cancelled)
    );
    assert!(observation.snapshot().writer_result.is_none());
    assert_eq!(frame.observation_for_saved_case().outcome_raw, 4);
    assert_eq!(
        observed.muc.snapshot().terminal,
        Some(muc::TerminalReason::Cancelled)
    );
    drop(writer);
    drop(port);
    drop(snapshots);
    drop(application);
    drop(observed);
    drop(sessions);
    drop(frame);
    let e = take_recorder(recorder).finish_resource_stopped().unwrap();
    assert!(e.execution.get().is_none() && e.rejection.get().is_none());
    assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
    let cuts: Vec<_> = e
        .facts
        .as_slice()
        .iter()
        .filter_map(|x| match &x.fact {
            wire::Fact::Native(wire::NativeFact::Snapshot(n)) => Some((x.seq, n)),
            _ => None,
        })
        .collect();
    let child = cuts
        .iter()
        .find(|(_, n)| n.cut == wire::Cut::ChildDrop)
        .unwrap();
    let terminal = cuts
        .iter()
        .find(|(_, n)| n.cut == wire::Cut::AfterRunnerDrop)
        .unwrap();
    assert!(child.0 < terminal.0);
    assert!(child.1.snapshot.get().unwrap().terminal.get().is_none());
    assert_eq!(
        terminal.1.snapshot.get().unwrap().terminal.get(),
        Some(&wire::CallTerminal::Cancelled)
    );
    let frame_terminal = frames(&e).last().unwrap().0;
    assert!(terminal.0 < frame_terminal);
}

#[tokio::test]
async fn thirty_second_terminal_write_still_succeeds_and_flushes_once() {
    let recorder = recorder_for(input(wire::MucDrive::Complete, None));
    let item = OutboundItem::plain("x".repeat(32));
    assert!(native_preflight(&item, &script(1, None), 0, &recorder).is_none());
    let result = native_backstop(item, script(1, None), recorder.clone()).await;
    assert!(matches!(result.actual, Ok(Poll::Ready(Ok(())))));
    assert_eq!(
        (result.accepted, result.writes, result.flushes),
        (32, 32, 1)
    );
    assert_eq!(
        result.snapshot.writer_result,
        Some(native::WriterResult::FullWrite)
    );
    assert!(driver::resource_stop(&recorder).is_none());
}
#[tokio::test]
async fn expanded_native_item_above_4096_within_call_budget_retains_real_success() {
    let mut i = input(wire::MucDrive::Complete, None);
    let old = i.command.stanza.as_str();
    let body_len = 4090 - (old.len() - 2);
    i.command.stanza = text(&old.replace(
        "<body>hi</body>",
        &format!("<body>{}</body>", "x".repeat(body_len)),
    ));
    assert_eq!(i.command.stanza.as_str().len(), 4090);
    let mut recipients = i.recipients.as_slice().to_vec();
    recipients[0].full_jid = text(&format!("a@example.test/{}", "r".repeat(700)));
    let materialized =
        crate::xmpp::xml_util::set_to(i.command.stanza.as_str(), recipients[0].full_jid.as_str());
    assert!(materialized.len() > 4096);
    assert!(required_write_calls(materialized.len(), &script(512, None)).unwrap() <= 32);
    i.recipients = list(recipients);
    let wire::Nullable::Value(native) = &mut i.native else {
        unreachable!()
    };
    native.write.chunk_limit = 512;
    let e = execute(i, "ordinary-large-transformed-item").await;
    complete(&e);
    assert_eq!(e.execution.get(), Some(&wire::Execution::Complete));
    assert!(e.resource_stop.get().is_none());
    let dequeued = e
        .facts
        .as_slice()
        .iter()
        .find_map(|x| match &x.fact {
            wire::Fact::Native(wire::NativeFact::Dequeue(d)) => Some(d),
            _ => None,
        })
        .unwrap();
    assert_eq!(dequeued.item.stanza.as_str(), materialized);
}

#[tokio::test]
async fn sixty_fifth_nested_owner_poll_never_runs_and_outer_frame_is_really_cancelled() {
    let i = input(wire::MucDrive::Complete, None);
    let recorder = recorder_for(i.clone());
    let site = wire::PollSite::new(wire::DriverOwner::Worker, 0).unwrap();
    // Ordinary-only budget priming. Each admitted ready future really is
    // polled; these are not synthesized Driver facts or a saved case input.
    for _ in 0..63 {
        let mut ready = Box::pin(std::future::ready(()));
        let result = std::future::poll_fn(|cx| {
            Poll::Ready(driver::poll_once(&recorder, site, ready.as_mut(), cx))
        })
        .await;
        assert!(matches!(result, Ok(Poll::Ready(()))));
    }
    let actual = run(i, recorder.clone()).await;
    assert!(
        matches!(actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::DriverPoll(x) })
        if x.owner == wire::DriverOwner::Native && x.admitted_calls == 64)
    );
    assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), 64);
    let e = take_recorder(recorder).finish_resource_stopped().unwrap();
    assert!(e.execution.get().is_none() && e.rejection.get().is_none());
    assert_eq!(
        e.facts
            .as_slice()
            .iter()
            .filter(|x| matches!(x.fact, wire::Fact::Driver(_)))
            .count(),
        64
    );
    assert!(!e.facts.as_slice().iter().any(|x| matches!(
        x.fact,
        wire::Fact::Native(wire::NativeFact::Write(_) | wire::NativeFact::Flush(_))
    )));
    assert_eq!(
        frames(&e).last().unwrap().1.outcome.get(),
        Some(&wire::FrameOutcome::Cancelled)
    );
    assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
    let terminal = e
        .facts
        .as_slice()
        .iter()
        .find_map(|x| match &x.fact {
            wire::Fact::Native(wire::NativeFact::Snapshot(n))
                if n.cut == wire::Cut::AfterRunnerDrop =>
            {
                n.snapshot.get()
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(terminal.preparation, wire::NativePreparation::NotStarted);
    assert_eq!(
        terminal.terminal.get(),
        Some(&wire::CallTerminal::Cancelled)
    );
}
