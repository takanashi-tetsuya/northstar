use super::*;

// Ordinary parser/identity controls only. These are not saved S13 bytes,
// owner-composition positives, an expected envelope, or evidence of a run.
const AUTH_REQUEST: &str = "<body xmlns='http://jabber.org/protocol/httpbind' rid='22' sid='00000000-0000-0000-0000-000000000003'/>";
fn reduced_bytes() -> Vec<u8> {
    r#"{"schema":"northstar-stage4-composition-case-v1","case_id":"bosh-bound-error","adapter_contract":"local-stage4-composition-controlled-v1","composition":{"kind":"BoshAuth","data":{"mix":null,"auth":{"bound":{"frame":{"frame_id":"00000000-0000-0000-0000-000000000001","connection_id":"00000000-0000-0000-0000-000000000002","transport":"Bosh","input":"<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>r</resource></bind></iq>"},"user_id":"00000000-0000-0000-0000-000000000004","auth_generation":1,"device_id":null,"ordinal":0,"credential_kind":"Binding","binding":{"resource":"r","lease_seconds":60,"full_jid":"u@example.test/r"},"preparation":{"generation_allowed":true,"binding_reserved":true,"stage_present":false,"stage_epoch":null,"commit":"Complete"},"control":{"kind":"Binding","data":{"iq_id":"b1","full_jid":"u@example.test/r","xml":"<iq xmlns='jabber:client' id='b1' type='result'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>u@example.test/r</jid></bind></iq>"}},"publication":{"kind":"BackendError","data":{}},"notification_expected":false},"session":{"connection_id":"00000000-0000-0000-0000-000000000002","session_id":"00000000-0000-0000-0000-000000000003","ttl_seconds":60,"max_response_bytes":16384,"max_output_bytes":65536,"governor":{"max_bytes":65536,"max_recovery_bytes":65536,"max_recovery_jobs":2,"max_snapshot_bytes":65536},"response":{"rid":22,"fingerprint":"FP","request_xml":"<body xmlns='http://jabber.org/protocol/httpbind' rid='22' sid='00000000-0000-0000-0000-000000000003'/>","content_type":"text/xml; charset=utf-8","responders":["Open"]},"bind":{"commit":"Complete","membership":{"c2s_message_ids":[],"mix_delivery_ids":[]}}},"drive":"Complete"}}}}"#.replace("\"FP\"", &format!("\"{}\"", sha256(AUTH_REQUEST.as_bytes()).0)).into_bytes()
}
const MIX_REQUEST: &str = "<body xmlns='http://jabber.org/protocol/httpbind' rid='11' sid='00000000-0000-0000-0000-000000000008'/>";
fn independent_mix() -> IndependentMixLane {
    let raw = r#"{"worker":{"origin":{"kind":"InitialDurableRow","data":{"source":{"delivery_id":"00000000-0000-0000-0000-00000000000c","lease_token":"00000000-0000-0000-0000-00000000000d"},"event_id":"00000000-0000-0000-0000-000000000009","channel_id":"00000000-0000-0000-0000-00000000000a","channel_jid":"c@mix.example.test","participant_id":"00000000-0000-0000-0000-00000000000b","recipient_jid":"u@example.test","recipient_nick":null,"stanza":"<message/>","authoritative_stanza_id":"00000000-0000-0000-0000-000000000009","archive":true,"encrypted":false,"attempt_count":0,"route_wake_generation":1}},"attempt":{"claim":{"limit":1,"max_bytes":4096,"lease_token":"00000000-0000-0000-0000-00000000000d","attempt_count":0,"route_wake_generation":1,"commit":"Complete"},"archive":{"reply":{"kind":"StoreCandidate","data":{}},"commit":"Complete"},"route":{"enabled_account_id":"00000000-0000-0000-0000-000000000004","privacy_blocked":false,"targets":[{"full_jid":"u@example.test/m","user_id":"00000000-0000-0000-0000-000000000004","connection_id":"00000000-0000-0000-0000-000000000007","auth_generation":1,"routable":true,"disconnected":false,"lifecycle":"Active","caps":{"connection_id":"00000000-0000-0000-0000-000000000007","generation":1,"verified_features":["MixCore"]},"provenance":{"kind":"InitiallyPublished","data":{}}}],"queue_capacity":1}}},"transport":{"session":{"connection_id":"00000000-0000-0000-0000-000000000007","session_id":"00000000-0000-0000-0000-000000000008","ttl_seconds":60,"max_response_bytes":16384,"max_output_bytes":65536,"governor":{"max_bytes":65536,"max_recovery_bytes":65536,"max_recovery_jobs":2,"max_snapshot_bytes":65536},"response":{"rid":11,"fingerprint":"FP","request_xml":"<body xmlns='http://jabber.org/protocol/httpbind' rid='11' sid='00000000-0000-0000-0000-000000000008'/>","content_type":"text/xml; charset=utf-8","responders":["Open"]},"bind":{"commit":"Complete","membership":{"c2s_message_ids":[],"mix_delivery_ids":["00000000-0000-0000-0000-00000000000c"]}}},"transfer":{"commit":"Complete","returned_source":{"delivery_id":"00000000-0000-0000-0000-00000000000c","lease_token":"00000000-0000-0000-0000-00000000000e"}},"ack":null}}"#.replace("\"FP\"", &format!("\"{}\"", sha256(MIX_REQUEST.as_bytes()).0));
    serde_json::from_str(&raw).unwrap()
}
pub(super) fn input_case() -> ValidatedCase {
    decode(&reduced_bytes()).unwrap()
}
fn id(n: u128) -> EvidenceId {
    EvidenceId::observed(Uuid::from_u128(n))
}
fn credential(attempt: u128, constructed: Option<u128>, returned: Option<u128>) -> Fact {
    let nullable = |n: Option<u128>| n.map_or(Nullable::Null(()), |n| Nullable::Value(id(n)));
    Fact::Credential(CredentialCapture {
        cut: Cut::Introduction,
        snapshot: CredentialSnapshot {
            attempt: id(attempt),
            frame: id(1),
            connection: id(2),
            ordinal: 0,
            kind: ObservedCredentialKind::Binding,
            service_started: false,
            repository_started: false,
            begin: CredentialCall::NotEntered,
            eligibility: Eligibility::NotEntered(Empty {}),
            transaction_returned: false,
            preparation: [PreparationResult::NotEntered; 5],
            stage_id: Nullable::Null(()),
            rollback: Nullable::Null(()),
            commit: CredentialCall::NotEntered,
            receipt_constructed: constructed.is_some(),
            returned: Nullable::Null(()),
            return_matches: false,
            transferred: false,
            handler: Nullable::Null(()),
            call_terminal: Nullable::Null(()),
            integrity_failure: false,
        },
        joins: Nullable::Value(CredentialJoins {
            owner: CredentialAttemptJoin {
                attempt: id(attempt),
                frame: id(1),
                connection: id(2),
                ordinal: 0,
                kind: ObservedCredentialKind::Binding,
            },
            constructed_receipt: nullable(constructed),
            returned_receipt: nullable(returned),
            transferred_receipt: Nullable::Null(()),
        }),
    })
}
fn recorded(attempt: u128, receipt: u128) -> Envelope {
    let c = input_case();
    let mut recorder = Recorder::new(&c);
    recorder
        .capture(credential(attempt, Some(receipt), None))
        .unwrap();
    recorder
        .capture(credential(attempt, Some(receipt), Some(receipt)))
        .unwrap();
    recorder.finish(Execution::Complete).unwrap()
}
fn control_holder(transferred_receipt: Option<u128>) -> Fact {
    let association = |receipt| ControlAssociation {
        control: id(100),
        connection: id(2),
        frame: Nullable::Value(id(1)),
        receipt: id(receipt),
        length: 4,
        digest: sha256(b"test"),
        publication: PublicationJoins {
            control: id(100),
            frame: Nullable::Value(id(1)),
            receipt: id(receipt),
            credential: Nullable::Value(CredentialAttemptJoin {
                attempt: id(300),
                frame: id(1),
                connection: id(2),
                ordinal: 0,
                kind: ObservedCredentialKind::Binding,
            }),
            begun_receipt: Nullable::Null(()),
            bound_effects: true,
            notification_expected: false,
        },
    };
    Fact::Control(ControlFact::Holder(ControlCapture {
        cut: Cut::Introduction,
        actual_xml: Nullable::Null(()),
        holder: Nullable::Value(ControlJoins {
            introduced: Nullable::Value(association(200)),
            transferred: transferred_receipt.map_or(Nullable::Null(()), |receipt| {
                Nullable::Value(association(receipt))
            }),
        }),
    }))
}
fn is_opaque(id: &EvidenceId, expected: u8) -> bool {
    matches!(id, EvidenceId::Encoded(IdentityLabel::Opaque(o)) if o.ordinal == expected)
}

fn fixed(n: u128) -> Id {
    Id(Uuid::from_u128(n))
}
fn text<const N: usize>(value: &str) -> Text<N> {
    Text::new(value).unwrap()
}
fn list<T, const N: usize>(values: Vec<T>) -> List<T, N> {
    List::new(values).unwrap()
}
fn write_ok() -> WriteScript {
    WriteScript {
        chunk_limit: 4096,
        fail_after_accepted_bytes: Nullable::Null(()),
        flush: FlushReply::Ok,
    }
}
fn auth_input(transport: TransportKind, publication: PublicationReply) -> AuthInput {
    let c = input_case();
    let Composition::BoshAuth(b) = c.case.composition else {
        unreachable!()
    };
    let mut auth = b.auth.bound;
    auth.frame.transport = transport;
    auth.publication = publication;
    auth
}
fn parser_case(composition: Composition) -> Case {
    Case {
        schema: text(CASE_SCHEMA),
        case_id: text("ordinary-parser-input"),
        adapter_contract: text(ADAPTER_CONTRACT),
        composition,
    }
}
fn auth_bosh_case(mix: bool, cancel: bool) -> Case {
    let mut c = input_case().case;
    let Composition::BoshAuth(b) = &mut c.composition else {
        unreachable!()
    };
    if mix {
        b.mix = Nullable::Value(independent_mix());
    }
    if cancel {
        b.auth.bound.publication = PublicationReply::CommitPending(EpochReply {
            epoch: Nullable::Null(()),
        });
        b.auth.drive = AuthDrive::DropPublicationCommit;
    }
    c
}
fn native_auth_case(cancel: bool) -> Case {
    let publication = if cancel {
        PublicationReply::CommitPending(EpochReply {
            epoch: Nullable::Null(()),
        })
    } else {
        PublicationReply::BackendError(Empty {})
    };
    parser_case(Composition::NativeAuth(NativeAuthInput {
        auth: auth_input(TransportKind::Tcp, publication),
        native: PlainNative {
            connection_id: fixed(2),
            write: write_ok(),
        },
        drive: if cancel {
            AuthDrive::DropPublicationCommit
        } else {
            AuthDrive::Complete
        },
    }))
}
fn muc_case(cut: MucDrive, replay: bool) -> Case {
    let stanza = text("<message xmlns='jabber:client' type='groupchat'><body>hi</body></message>");
    let mut recipients = vec![RecipientInput {
        user_id: fixed(4),
        full_jid: text("a@example.test/one"),
        connection_id: fixed(2),
        blocked: false,
        endpoint: EndpointCut::Return,
    }];
    if cut == MucDrive::DropSecondEndpoint {
        recipients.push(RecipientInput {
            user_id: fixed(6),
            full_jid: text("b@example.test/two"),
            connection_id: fixed(7),
            blocked: false,
            endpoint: EndpointCut::Pending,
        });
    }
    if replay || cut == MucDrive::DropCommit {
        recipients.clear();
    }
    parser_case(Composition::Muc(MucInput {
        frame: Frame {
            frame_id: fixed(1),
            connection_id: fixed(2),
            transport: TransportKind::Tcp,
            input: stanza.clone(),
        },
        configured_domain: text("example.test"),
        command: MucCommand {
            id: fixed(63),
            room_id: fixed(60),
            actor_scope: text("a@example.test"),
            origin_id: if cut == MucDrive::DropSecondEndpoint {
                Nullable::Null(())
            } else {
                Nullable::Value(text("origin"))
            },
            sender_jid: text("a@example.test/one"),
            nick: text("a"),
            stanza,
            encrypted: false,
            archive: cut != MucDrive::DropSecondEndpoint,
            retention_days: 7,
            authority: Authority {
                clustered: false,
                expected_room_epoch: fixed(61),
                principal: MucPrincipal::Local(LocalPrincipal {
                    user_id: fixed(4),
                    local_domain: text("example.test"),
                }),
                actor_scope: text("a@example.test"),
                full_jid: text("a@example.test/one"),
                nick: text("a"),
                occupant_incarnation: fixed(62),
                connection_uuid: fixed(2),
                expected_role: text("participant"),
                expected_affiliation: text("member"),
                cluster_target: Nullable::Null(()),
            },
        },
        admission: RatedAdmission {
            fence: AdmissionFenceInput {
                admission_key: Hex::of(&[0; 32]).unwrap(),
                payload_mac: Hex::of(&[1; 32]).unwrap(),
                lease_token: fixed(64),
                dedupe_digest: Hex::of(&[2; 32]).unwrap(),
            },
            requirement: AdmissionRequirement {
                action: text("message"),
                step: 0,
                work_factor: 1,
                max_work_factor: 1,
                hard_wait_seconds: 0,
                retry_after_seconds: 0,
                cooldown_seconds: 0,
                approximate_max_device_seconds: 0,
                notice: text("synthetic"),
            },
            begin_commit: CommitCut::Complete,
            finalize_commit: CommitCut::Complete,
        },
        repository: MucRepository {
            original_id: if replay {
                Nullable::Value(fixed(65))
            } else {
                Nullable::Null(())
            },
            commit: if cut == MucDrive::DropCommit {
                CommitCut::Pending
            } else {
                CommitCut::Complete
            },
        },
        recipients: list(recipients),
        native: if !replay && cut == MucDrive::Complete {
            Nullable::Value(PlainNative {
                connection_id: fixed(2),
                write: write_ok(),
            })
        } else {
            Nullable::Null(())
        },
        drive: cut,
    }))
}
fn fresh_mix_native_case() -> Case {
    let auth = auth_input(
        TransportKind::Tcp,
        PublicationReply::Committed(EpochReply {
            epoch: Nullable::Null(()),
        }),
    );
    let mut worker = independent_mix().worker;
    worker.origin = ClaimOrigin::FreshProjection(FreshProjectionOrigin {
        foreground_frame: fixed(66),
        recipient_ordinal: 0,
        declared_delivery_id: fixed(12),
    });
    let route = &mut worker.attempt.route.targets.0[0];
    route.full_jid = text("u@example.test/r");
    route.connection_id = fixed(2);
    route.caps.connection_id = fixed(2);
    route.routable = false;
    route.provenance = RouteProvenance::ActivatedByAuth(ActivatedRoute { frame_id: fixed(1) });
    parser_case(Composition::AuthThenMixNative(FreshMixNativeInput {
        auth,
        auth_native: PlainNative {
            connection_id: fixed(2),
            write: write_ok(),
        },
        foreground: FreshForeground {
            frame: Frame {
                frame_id: fixed(66),
                connection_id: fixed(7),
                transport: TransportKind::Tcp,
                input: text("<message><body>hi</body></message>"),
            },
            configured_domain: text("mix.example.test"),
            ingress: MixIngress {
                channel_id: fixed(10),
                channel_jid: text("c@mix.example.test"),
                actor_bare: text("b@example.test"),
                actor_full: text("b@example.test/two"),
                children: text("<body>hi</body>"),
                encrypted: false,
                identity: Nullable::Null(()),
            },
            command: MixStoreCommand {
                channel_id: fixed(10),
                actor: text("b@example.test"),
                item_id: fixed(9),
                payload: text("<item/>"),
                identity: Nullable::Null(()),
                delivery_payload: text("<body>hi</body>"),
                visible_jid: Nullable::Null(()),
                encrypted: false,
            },
            stored: Stored {
                authoritative_id: fixed(9),
                storage_id: fixed(70),
                channel_id: fixed(10),
                channel_jid: text("c@mix.example.test"),
                projection: Nullable::Value(DeliveryProjection {
                    event_id: fixed(9),
                    channel_id: fixed(10),
                    channel_jid: text("c@mix.example.test"),
                    stanza_template: text("<message/>"),
                    authoritative_stanza_id: Nullable::Value(fixed(9)),
                    archive: true,
                    encrypted: false,
                    recipients: list(vec![RecipientProjection {
                        participant: Participant {
                            participant_id: fixed(11),
                            jid: text("u@example.test"),
                            nick: Nullable::Null(()),
                        },
                        delivery_id: fixed(12),
                        sequence: 1,
                    }]),
                }),
            },
            commit: CommitCut::Complete,
        },
        worker,
        delivery_native: DurableNative {
            connection_id: fixed(2),
            write: write_ok(),
            returned_fence: MixSource {
                delivery_id: fixed(12),
                lease_token: fixed(14),
            },
            ack_commit: CommitCut::Complete,
        },
    }))
}
fn replay_queued_auth_case() -> Case {
    let c = input_case();
    let Composition::BoshAuth(a) = c.case.composition else {
        unreachable!()
    };
    let bound = a.auth.bound;
    let session = a.auth.session;
    let mut unbound = bound.clone();
    unbound.frame.frame_id = fixed(30);
    unbound.frame.input = text("<authenticate xmlns='urn:xmpp:sasl:2'/>");
    unbound.credential_kind = CredentialKind::UnboundFast;
    unbound.binding = Nullable::Null(());
    unbound.preparation.binding_reserved = false;
    unbound.control = ControlInput::UnboundFast(UnboundControlInput { authorization_identifier: text("u@example.test"), xml: text("<success xmlns='urn:xmpp:sasl:2'><authorization-identifier>u@example.test</authorization-identifier></success>") });
    unbound.publication = PublicationReply::NoSql(Empty {});
    let count =
        RESPONSE_BYTES as usize - 256 - auth_xml(&unbound).len() - P_OPEN.len() - P_CLOSE.len();
    let padding = FixedAuthPadding {
        presence_xml: Text::new(format!("{P_OPEN}{}{P_CLOSE}", "x".repeat(count))).unwrap(),
        features_xml: text(FIXED_FEATURES),
    };
    let mut mix = independent_mix();
    mix.worker.attempt.archive.reply = ArchiveReply::Replay(ArchiveReplayInput {
        original_archive_id: fixed(50),
    });
    let request_xml = "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' ack='11' sid='00000000-0000-0000-0000-000000000008'/>";
    mix.transport.ack = Nullable::Value(BoshAckInput {
        request: BoshRequest {
            rid: 12,
            fingerprint: sha256(request_xml.as_bytes()),
            request_xml: text(request_xml),
            content_type: text("text/xml; charset=utf-8"),
            responders: list(vec![Responder::Open]),
        },
        acknowledged_rid: 11,
        renewal: CommitCut::Complete,
        commit: CommitCut::Complete,
        deleted: mix.transport.transfer.returned_source.clone(),
    });
    parser_case(Composition::ReplayMixQueuedAuth(ReplayMixQueuedAuth {
        mix: ReplayMixBoshLane {
            foreground: ReplayForeground {
                frame: Frame {
                    frame_id: fixed(31),
                    connection_id: fixed(7),
                    transport: TransportKind::Bosh,
                    input: text("<message><body>hi</body></message>"),
                },
                configured_domain: text("mix.example.test"),
                ingress: MixIngress {
                    channel_id: fixed(10),
                    channel_jid: text("c@mix.example.test"),
                    actor_bare: text("u@example.test"),
                    actor_full: text("u@example.test/m"),
                    children: text("<body>hi</body>"),
                    encrypted: false,
                    identity: Nullable::Value(ReplayIdentityInput {
                        client_id: text("replay"),
                        canonical_semantics: Bytes::of(b"<body>hi</body>").unwrap(),
                    }),
                },
                existing: Existing {
                    authoritative_id: fixed(9),
                    semantic_key_id: text("synthetic-v1"),
                    semantic_mac: Bytes::of(&[0; 32]).unwrap(),
                    target_id: Nullable::Null(()),
                },
                original_id: fixed(9),
            },
            worker: mix.worker,
            transport: mix.transport,
        },
        auth: QueuedAuthLane {
            unbound,
            bound,
            session,
            padding,
        },
    }))
}
fn recovery_case() -> Case {
    let mut worker = independent_mix().worker;
    worker.attempt.archive.reply = ArchiveReply::Replay(ArchiveReplayInput {
        original_archive_id: fixed(50),
    });
    let mut replacement = worker.attempt.clone();
    replacement.claim.lease_token = fixed(15);
    replacement.claim.attempt_count = 1;
    replacement.route.targets.0[0].connection_id = fixed(2);
    replacement.route.targets.0[0].caps.connection_id = fixed(2);
    replacement.route.targets.0[0].full_jid = text("u@example.test/r");
    parser_case(Composition::MixRecoveryNative(RecoveryInput {
        worker,
        replacement,
        native: DurableNative {
            connection_id: fixed(2),
            write: write_ok(),
            returned_fence: MixSource {
                delivery_id: fixed(12),
                lease_token: fixed(14),
            },
            ack_commit: CommitCut::Complete,
        },
    }))
}
fn defer_case() -> Case {
    let mut worker = independent_mix().worker;
    worker.attempt.route.targets = list(vec![]);
    parser_case(Composition::MixDefer(DeferInput {
        worker,
        settlement_commit: CommitCut::Complete,
        updated: true,
    }))
}
fn decoded_positive(case: Case) {
    let bytes = serde_json::to_vec(&case).unwrap();
    let parsed = decode(&bytes).unwrap();
    assert_eq!(parsed.case, case);
}
fn live_anchor(
    control: u128,
    receipt: u128,
    attempt: u128,
    frame: u128,
    kind: ObservedCredentialKind,
) -> Fact {
    Fact::Control(ControlFact::LivePublication(LivePublication {
        cut: Cut::Introduction,
        snapshot: PublicationSnapshot {
            control: id(control),
            frame: Nullable::Value(id(frame)),
            handler: Nullable::Null(()),
            sealed: false,
            transport: AuthTransport::NotStarted(Empty {}),
            publication: PublicationKnowledge::NotStarted(Empty {}),
            service_started: false,
            repository_started: false,
            rollback: PublicationRollback::NotRequested,
            returned: Nullable::Null(()),
            return_matches: false,
            effects: PublicationEffects {
                unbound: false,
                epoch_applied: false,
                route_mapping: Nullable::Null(()),
                route_activation: Nullable::Null(()),
                caps_entered: false,
                caps_returned: false,
                notification_entered: false,
                notification_returned: Nullable::Null(()),
            },
            terminal: Nullable::Null(()),
        },
        joins: Nullable::Value(PublicationJoins {
            control: id(control),
            frame: Nullable::Value(id(frame)),
            receipt: id(receipt),
            credential: Nullable::Value(CredentialAttemptJoin {
                attempt: id(attempt),
                frame: id(frame),
                connection: id(2),
                ordinal: 0,
                kind,
            }),
            begun_receipt: Nullable::Null(()),
            bound_effects: false,
            notification_expected: false,
        }),
    }))
}
fn credential_at(
    attempt: u128,
    receipt: u128,
    returned: u128,
    frame: u128,
    kind: ObservedCredentialKind,
) -> Fact {
    let mut fact = credential(attempt, Some(receipt), Some(returned));
    let Fact::Credential(c) = &mut fact else {
        unreachable!()
    };
    c.snapshot.frame = id(frame);
    c.snapshot.kind = kind;
    let Nullable::Value(joins) = &mut c.joins else {
        unreachable!()
    };
    joins.owner.frame = id(frame);
    joins.owner.kind = kind;
    fact
}

#[test]
fn decode_s01_muc_stored_native() {
    decoded_positive(muc_case(MucDrive::Complete, false));
}
#[test]
fn decode_s02_muc_replay_without_fanout() {
    decoded_positive(muc_case(MucDrive::Complete, true));
}
#[test]
fn decode_s03_muc_volatile_second_endpoint_drop() {
    decoded_positive(muc_case(MucDrive::DropSecondEndpoint, false));
}
#[test]
fn decode_s04_muc_commit_pending_drop() {
    decoded_positive(muc_case(MucDrive::DropCommit, false));
}
#[test]
fn decode_s05_auth_fresh_mix_native() {
    decoded_positive(fresh_mix_native_case());
}
#[test]
fn decode_s06_independent_replay_and_queued_auth() {
    decoded_positive(replay_queued_auth_case());
}
#[test]
fn decode_s07_recovery_distinct_initially_published_connections() {
    decoded_positive(recovery_case());
}
#[test]
fn decode_s08_archive_pending_defer() {
    decoded_positive(defer_case());
}
#[test]
fn decode_s09_native_auth_backend_error() {
    decoded_positive(native_auth_case(false));
}
#[test]
fn decode_s10_native_auth_publication_pending_drop() {
    decoded_positive(native_auth_case(true));
}
#[test]
fn decode_s11_bosh_auth_error_with_independent_mix() {
    decoded_positive(auth_bosh_case(true, false));
}
#[test]
fn decode_s12_bosh_auth_pending_drop_with_independent_mix() {
    decoded_positive(auth_bosh_case(true, true));
}
#[test]
fn decode_s13_reduced_bosh_auth_error() {
    decoded_positive(auth_bosh_case(false, false));
}

#[test]
fn binding_stage_device_presence_matches_actual_preparation_contract() {
    let absent = auth_bosh_case(false, false);
    decoded_positive(absent.clone());
    let mut present = absent.clone();
    let Composition::BoshAuth(c) = &mut present.composition else {
        unreachable!()
    };
    c.auth.bound.device_id = Nullable::Value(fixed(80));
    c.auth.bound.preparation.stage_present = true;
    c.auth.bound.preparation.stage_epoch = Nullable::Value(73);
    decoded_positive(present.clone());
    for (mut case, stage_present) in [(absent, true), (present, false)] {
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        c.auth.bound.preparation.stage_present = stage_present;
        c.auth.bound.preparation.stage_epoch = if stage_present {
            Nullable::Value(73)
        } else {
            Nullable::Null(())
        };
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }
}

#[test]
fn committed_epoch_presence_must_agree_with_prepared_stage() {
    for stage_present in [false, true] {
        let mut case = fresh_mix_native_case();
        let Composition::AuthThenMixNative(c) = &mut case.composition else {
            unreachable!()
        };
        c.auth.preparation.stage_present = stage_present;
        c.auth.preparation.stage_epoch = if stage_present {
            Nullable::Value(73)
        } else {
            Nullable::Null(())
        };
        c.auth.device_id = if stage_present {
            Nullable::Value(fixed(80))
        } else {
            Nullable::Null(())
        };
        c.auth.publication = PublicationReply::Committed(EpochReply {
            epoch: if stage_present {
                Nullable::Null(())
            } else {
                Nullable::Value(41)
            },
        });
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }
    // Only presence is constrained, never an expected numeric epoch hint.
    for epoch in [i64::MIN, 0, i64::MAX] {
        let mut case = fresh_mix_native_case();
        let Composition::AuthThenMixNative(c) = &mut case.composition else {
            unreachable!()
        };
        c.auth.preparation.stage_present = true;
        c.auth.preparation.stage_epoch = Nullable::Value(73);
        c.auth.device_id = Nullable::Value(fixed(80));
        c.auth.publication = PublicationReply::Committed(EpochReply {
            epoch: Nullable::Value(epoch),
        });
        decoded_positive(case);
    }
}

#[test]
fn pending_commit_epoch_presence_must_agree_with_prepared_stage() {
    for stage_present in [false, true] {
        let mut case = auth_bosh_case(true, true);
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        c.auth.bound.preparation.stage_present = stage_present;
        c.auth.bound.preparation.stage_epoch = if stage_present {
            Nullable::Value(73)
        } else {
            Nullable::Null(())
        };
        c.auth.bound.device_id = if stage_present {
            Nullable::Value(fixed(80))
        } else {
            Nullable::Null(())
        };
        c.auth.bound.publication = PublicationReply::CommitPending(EpochReply {
            epoch: if stage_present {
                Nullable::Null(())
            } else {
                Nullable::Value(41)
            },
        });
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }
    for epoch in [i64::MIN, 0, i64::MAX] {
        let mut case = auth_bosh_case(true, true);
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        c.auth.bound.preparation.stage_present = true;
        c.auth.bound.preparation.stage_epoch = Nullable::Value(73);
        c.auth.bound.device_id = Nullable::Value(fixed(80));
        c.auth.bound.publication = PublicationReply::CommitPending(EpochReply {
            epoch: Nullable::Value(epoch),
        });
        decoded_positive(case);
    }
}

#[test]
fn explicit_stage_hint_and_later_publication_epoch_may_differ() {
    for pending in [false, true] {
        let mut case = if pending {
            auth_bosh_case(true, true)
        } else {
            fresh_mix_native_case()
        };
        let auth = match &mut case.composition {
            Composition::AuthThenMixNative(c) => &mut c.auth,
            Composition::BoshAuth(c) => &mut c.auth.bound,
            _ => unreachable!(),
        };
        auth.device_id = Nullable::Value(fixed(80));
        auth.preparation.stage_present = true;
        // Both are explicit supplied data. The publication's real returned
        // epoch is independent of the earlier stage hint, never repaired.
        auth.preparation.stage_epoch = Nullable::Value(73);
        auth.publication = if pending {
            PublicationReply::CommitPending(EpochReply {
                epoch: Nullable::Value(9001),
            })
        } else {
            PublicationReply::Committed(EpochReply {
                epoch: Nullable::Value(9001),
            })
        };
        let parsed = decode(&serde_json::to_vec(&case).unwrap()).unwrap();
        let auth = match &parsed.case.composition {
            Composition::AuthThenMixNative(c) => &c.auth,
            Composition::BoshAuth(c) => &c.auth.bound,
            _ => unreachable!(),
        };
        let reply = match &auth.publication {
            PublicationReply::Committed(r) | PublicationReply::CommitPending(r) => r,
            _ => unreachable!(),
        };
        assert_eq!(auth.preparation.stage_epoch.get(), Some(&73));
        assert_eq!(reply.epoch.get(), Some(&9001));
        assert_ne!(auth.preparation.stage_epoch, reply.epoch);
    }
}

#[test]
fn explicit_stage_epoch_presence_must_match_stage_present() {
    for stage_present in [false, true] {
        let mut case = auth_bosh_case(false, false);
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        c.auth.bound.device_id = if stage_present {
            Nullable::Value(fixed(80))
        } else {
            Nullable::Null(())
        };
        c.auth.bound.preparation.stage_present = stage_present;
        c.auth.bound.preparation.stage_epoch = if stage_present {
            Nullable::Null(())
        } else {
            Nullable::Value(73)
        };
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }
}

#[test]
fn stage_epoch_is_required_nullable_i64_and_accepts_no_operation_id_input() {
    let absent = r#"{"generation_allowed":true,"binding_reserved":true,"stage_present":false,"stage_epoch":null,"commit":"Complete"}"#;
    let parsed: CredentialPreparationInput = serde_json::from_str(absent).unwrap();
    assert!(parsed.stage_epoch.get().is_none());
    assert!(serde_json::from_str::<CredentialPreparationInput>(
        &absent.replace(",\"stage_epoch\":null", "")
    )
    .is_err());
    let extra = absent.replacen(
        '{',
        "{\"stage_operation_id\":\"00000000-0000-0000-0000-000000000001\",",
        1,
    );
    assert!(serde_json::from_str::<CredentialPreparationInput>(&extra).is_err());
    for valid in [i64::MIN, 0, i64::MAX] {
        let raw = absent
            .replace("\"stage_present\":false", "\"stage_present\":true")
            .replace("\"stage_epoch\":null", &format!("\"stage_epoch\":{valid}"));
        assert_eq!(
            serde_json::from_str::<CredentialPreparationInput>(&raw)
                .unwrap()
                .stage_epoch
                .get(),
            Some(&valid)
        );
    }
    for invalid in [
        "true",
        "\"73\"",
        "73.0",
        "9223372036854775808",
        "-9223372036854775809",
    ] {
        assert!(
            serde_json::from_str::<CredentialPreparationInput>(&absent.replace(
                "\"stage_epoch\":null",
                &format!("\"stage_epoch\":{invalid}")
            ))
            .is_err()
        );
    }
}

#[test]
fn notification_intent_is_unsupported_before_owners_and_matches_rejection_envelope() {
    let rejected = |case: Case| {
        let input = serde_json::to_vec(&case).unwrap();
        assert!(matches!(decode(&input), Err(Rejection::Unsupported)));
        let envelope = Envelope::rejected(&input, Rejection::Unsupported).unwrap();
        assert!(
            envelope.facts.is_empty()
                && envelope.identity_map.is_empty()
                && envelope.execution.get().is_none()
        );
        assert_eq!(envelope.input_sha256, sha256(&input));
        validate_envelope(&envelope, &input, None).unwrap();
    };
    for mut case in [
        fresh_mix_native_case(),
        native_auth_case(false),
        native_auth_case(true),
        auth_bosh_case(true, false),
        auth_bosh_case(true, true),
        auth_bosh_case(false, false),
    ] {
        let auth = match &mut case.composition {
            Composition::AuthThenMixNative(c) => &mut c.auth,
            Composition::NativeAuth(c) => &mut c.auth,
            Composition::BoshAuth(c) => &mut c.auth.bound,
            _ => unreachable!(),
        };
        auth.notification_expected = true;
        rejected(case);
    }
    for unbound in [false, true] {
        let mut case = replay_queued_auth_case();
        let Composition::ReplayMixQueuedAuth(c) = &mut case.composition else {
            unreachable!()
        };
        if unbound {
            c.auth.unbound.notification_expected = true;
        } else {
            c.auth.bound.notification_expected = true;
        }
        rejected(case);
    }
}

#[test]
fn false_notification_intent_preserves_all_thirteen_positive_meanings() {
    for case in [
        muc_case(MucDrive::Complete, false),
        muc_case(MucDrive::Complete, true),
        muc_case(MucDrive::DropSecondEndpoint, false),
        muc_case(MucDrive::DropCommit, false),
        fresh_mix_native_case(),
        replay_queued_auth_case(),
        recovery_case(),
        defer_case(),
        native_auth_case(false),
        native_auth_case(true),
        auth_bosh_case(true, false),
        auth_bosh_case(true, true),
        auth_bosh_case(false, false),
    ] {
        decoded_positive(case);
    }
}

#[test]
fn no_notification_intent_with_some_epoch_remains_a_valid_component_input() {
    let mut case = fresh_mix_native_case();
    let Composition::AuthThenMixNative(c) = &mut case.composition else {
        unreachable!()
    };
    assert!(!c.auth.notification_expected);
    c.auth.device_id = Nullable::Value(fixed(80));
    c.auth.preparation.stage_present = true;
    c.auth.preparation.stage_epoch = Nullable::Value(73);
    c.auth.publication = PublicationReply::Committed(EpochReply {
        epoch: Nullable::Value(9001),
    });
    let parsed = decode(&serde_json::to_vec(&case).unwrap()).unwrap();
    let Composition::AuthThenMixNative(c) = &parsed.case.composition else {
        unreachable!()
    };
    assert!(!c.auth.notification_expected);
    assert!(matches!(
        c.auth.publication,
        PublicationReply::Committed(EpochReply {
            epoch: Nullable::Value(9001)
        })
    ));
    // publish_owned needs both a captured intent and Some authenticated
    // epoch. This controlled None-intent component input is not evidence
    // of full ProtocolSession notification-intent capture correspondence.
}

#[test]
fn admitted_owner_reservations_survive_sticky_loss_without_recharge() {
    let mut r = Recorder::new(&input_case());
    let site = PollSite::new(DriverOwner::Worker, 1).unwrap();
    r.reserve_owner_poll(site).unwrap();
    r.polled(
        site.owner(),
        site.owner_ordinal(),
        &std::task::Poll::<()>::Pending,
    )
    .unwrap();
    assert_eq!(r.admitted_owner_polls(), 1);
    assert_eq!(r.sequence.polls, 1);
    r.missing_observation();
    for expected in 2..=64 {
        r.reserve_owner_poll(site).unwrap();
        assert_eq!(
            r.polled(
                site.owner(),
                site.owner_ordinal(),
                &std::task::Poll::<()>::Pending
            ),
            Err(Loss::MissingObservation)
        );
        assert_eq!(r.admitted_owner_polls(), expected);
    }
    assert_eq!(r.sequence.polls, 1);
    let stop = r.reserve_owner_poll(site).unwrap_err();
    assert_eq!(r.admitted_owner_polls(), 64);
    assert_eq!(
        stop.resource_stop,
        ResourceStop::DriverPoll(DriverResourceStop {
            owner: DriverOwner::Worker,
            owner_ordinal: 1,
            admitted_calls: 64
        })
    );
    assert_eq!(
        r.reserve_owner_poll(PollSite::new(DriverOwner::Muc, 0).unwrap()),
        Err(stop)
    );
    let e = r.finish_resource_stopped().unwrap();
    assert!(e.execution.get().is_none());
    assert!(e.resource_stop.get().is_some());
    assert_eq!(e.facts.len(), 1);
    assert!(matches!(
        e.observation_status,
        ObservationStatus::Lost(LostObservation {
            reason: Loss::MissingObservation,
            after_seq: 1
        })
    ));
}

#[test]
fn first_valid_resource_stop_is_immutable_and_invalid_metadata_is_internal() {
    let mut r = Recorder::new(&input_case());
    assert_eq!(
        r.latch_resource_stop(ResourceStop::DriverPoll(DriverResourceStop {
            owner: DriverOwner::Worker,
            owner_ordinal: 0,
            admitted_calls: 64
        })),
        Err(DriverConfigurationError::AdmittedCalls)
    );
    let invalid = ResourceStop::NativeWrite(NativeResourceStop {
        item_ordinal: 5,
        admitted_calls: 0,
    });
    assert_eq!(
        r.latch_resource_stop(invalid.clone()),
        Err(DriverConfigurationError::ItemOrdinal)
    );
    assert!(r.resource_stop().is_none());
    assert!(r.loss.is_none());
    let first = ResourceStop::NativeWrite(NativeResourceStop {
        item_ordinal: 4,
        admitted_calls: 0,
    });
    let stopped = r.latch_resource_stop(first.clone()).unwrap();
    assert_eq!(
        r.latch_resource_stop(ResourceStop::NativeFlush(NativeResourceStop {
            item_ordinal: 1,
            admitted_calls: 1
        }))
        .unwrap(),
        stopped
    );
    assert_eq!(r.latch_resource_stop(invalid).unwrap(), stopped);
    assert_eq!(r.resource_stop(), Some(&first));
    assert_eq!(r.admitted_owner_polls(), 0);
    assert_eq!(
        r.reserve_owner_poll(PollSite::new(DriverOwner::Native, 4).unwrap()),
        Err(stopped)
    );
    assert_eq!(r.admitted_owner_polls(), 0);
    let e = r.finish(Execution::Complete).unwrap();
    assert!(e.rejection.get().is_none());
    assert!(e.execution.get().is_none());
    assert_eq!(e.resource_stop.get(), Some(&first));
}

#[test]
fn original_lost_prefix_and_later_resource_stop_are_both_retained() {
    let input = reduced_bytes();
    let validated = decode(&input).unwrap();
    let mut r = Recorder::new(&validated);
    r.capture(credential(100, Some(200), None)).unwrap();
    let prefix = r.facts.clone();
    r.missing_observation();
    let stop = ResourceStop::NativeWrite(NativeResourceStop {
        item_ordinal: 0,
        admitted_calls: 32,
    });
    r.latch_resource_stop(stop.clone()).unwrap();
    assert_eq!(
        r.capture(credential(100, Some(200), Some(200))),
        Err(Loss::MissingObservation)
    );
    let e = r.finish_resource_stopped().unwrap();
    assert_eq!(e.facts.as_slice(), prefix.as_slice());
    assert_eq!(e.resource_stop.get(), Some(&stop));
    assert!(matches!(
        e.observation_status,
        ObservationStatus::Lost(LostObservation {
            reason: Loss::MissingObservation,
            after_seq: 1
        })
    ));
    validate_envelope(&e, &input, Some(&validated)).unwrap();
    let encoded = encode_frame(&e).unwrap();
    assert_eq!(decode_frame(&encoded).unwrap(), e);
}

#[test]
fn envelope_requires_exact_rejected_normal_and_resource_stopped_nullability() {
    let input = reduced_bytes();
    let validated = decode(&input).unwrap();
    let normal = Recorder::new(&validated)
        .finish(Execution::Complete)
        .unwrap();
    validate_envelope(&normal, &input, Some(&validated)).unwrap();
    let mut missing_execution = normal.clone();
    missing_execution.execution = Nullable::Null(());
    assert_eq!(
        validate_envelope(&missing_execution, &input, Some(&validated)),
        Err(Loss::EncodingFailure)
    );
    let mut r = Recorder::new(&validated);
    r.latch_resource_stop(ResourceStop::NativeFlush(NativeResourceStop {
        item_ordinal: 4,
        admitted_calls: 1,
    }))
    .unwrap();
    let stopped = r.finish_resource_stopped().unwrap();
    validate_envelope(&stopped, &input, Some(&validated)).unwrap();
    let mut false_execution = stopped.clone();
    false_execution.execution = Nullable::Value(Execution::Cancelled);
    assert_eq!(
        validate_envelope(&false_execution, &input, Some(&validated)),
        Err(Loss::EncodingFailure)
    );
    let bad_input = b"{}";
    let mut rejected = Envelope::rejected(bad_input, Rejection::Json).unwrap();
    validate_envelope(&rejected, bad_input, None).unwrap();
    rejected.resource_stop = stopped.resource_stop.clone();
    assert_eq!(
        validate_envelope(&rejected, bad_input, None),
        Err(Loss::EncodingFailure)
    );
    assert_eq!(
        Recorder::new(&validated)
            .finish_resource_stopped()
            .unwrap_err(),
        DriverConfigurationError::MissingResourceStop
    );
}

#[test]
fn resource_stop_field_is_required_nullable_and_discriminator_is_closed() {
    let e = Recorder::new(&input_case())
        .finish(Execution::Complete)
        .unwrap();
    let raw = serde_json::to_string(&e).unwrap();
    assert!(raw.contains("\"resource_stop\":null"));
    assert!(serde_json::from_str::<Envelope>(&raw.replace(",\"resource_stop\":null", "")).is_err());
    for raw in [
        r#"{"kind":"NativeBytes","data":{"item_ordinal":0,"admitted_calls":0}}"#,
        r#"{"kind":"NativeWrite","data":{"item_ordinal":0,"admitted_calls":0,"text":"extra"}}"#,
        r#"{"kind":"DriverPoll","data":{"owner":"Worker","owner_ordinal":0,"admitted_calls":64,"time":1}}"#,
    ] {
        assert!(serde_json::from_str::<ResourceStop>(raw).is_err());
    }
}

#[test]
fn resource_stop_and_poll_site_bounds_match_fixed_owner_scopes() {
    for (owner, maximum) in [
        (DriverOwner::Muc, 2),
        (DriverOwner::Foreground, 2),
        (DriverOwner::Claim, 1),
        (DriverOwner::Worker, 1),
        (DriverOwner::Credential, 1),
        (DriverOwner::Publication, 1),
        (DriverOwner::Native, 4),
        (DriverOwner::Bosh, 3),
    ] {
        PollSite::new(owner, maximum).unwrap();
        assert_eq!(
            PollSite::new(owner, maximum + 1),
            Err(DriverConfigurationError::OwnerOrdinal)
        );
        ResourceStop::DriverPoll(DriverResourceStop {
            owner,
            owner_ordinal: maximum,
            admitted_calls: 64,
        })
        .validate()
        .unwrap();
    }
    for count in [0, 63, 65] {
        assert_eq!(
            ResourceStop::DriverPoll(DriverResourceStop {
                owner: DriverOwner::Worker,
                owner_ordinal: 0,
                admitted_calls: count
            })
            .validate(),
            Err(DriverConfigurationError::AdmittedCalls)
        );
    }
    for count in [0, 17, 32] {
        ResourceStop::NativeWrite(NativeResourceStop {
            item_ordinal: 4,
            admitted_calls: count,
        })
        .validate()
        .unwrap();
    }
    for count in [0, 1] {
        ResourceStop::NativeFlush(NativeResourceStop {
            item_ordinal: 4,
            admitted_calls: count,
        })
        .validate()
        .unwrap();
    }
    assert_eq!(
        ResourceStop::NativeWrite(NativeResourceStop {
            item_ordinal: 4,
            admitted_calls: 33
        })
        .validate(),
        Err(DriverConfigurationError::AdmittedCalls)
    );
    assert_eq!(
        ResourceStop::NativeFlush(NativeResourceStop {
            item_ordinal: 4,
            admitted_calls: 2
        })
        .validate(),
        Err(DriverConfigurationError::AdmittedCalls)
    );
    assert_eq!(
        ResourceStop::NativeFlush(NativeResourceStop {
            item_ordinal: 5,
            admitted_calls: 0
        })
        .validate(),
        Err(DriverConfigurationError::ItemOrdinal)
    );
}

#[test]
fn envelope_validator_rejects_out_of_bound_resource_metadata() {
    let input = reduced_bytes();
    let validated = decode(&input).unwrap();
    for stop in [
        ResourceStop::DriverPoll(DriverResourceStop {
            owner: DriverOwner::Claim,
            owner_ordinal: 2,
            admitted_calls: 64,
        }),
        ResourceStop::DriverPoll(DriverResourceStop {
            owner: DriverOwner::Claim,
            owner_ordinal: 0,
            admitted_calls: 63,
        }),
        ResourceStop::NativeWrite(NativeResourceStop {
            item_ordinal: 0,
            admitted_calls: 33,
        }),
        ResourceStop::NativeFlush(NativeResourceStop {
            item_ordinal: 0,
            admitted_calls: 2,
        }),
    ] {
        let mut envelope = Recorder::new(&validated)
            .finish(Execution::Complete)
            .unwrap();
        envelope.execution = Nullable::Null(());
        envelope.resource_stop = Nullable::Value(stop);
        assert_eq!(
            validate_envelope(&envelope, &input, Some(&validated)),
            Err(Loss::EncodingFailure)
        );
    }
}

#[test]
fn binding_lease_duration_has_exact_bounds_and_unsigned_integer_type() {
    for lease in [1, MAX_BINDING_LEASE_SECONDS] {
        let mut case = auth_bosh_case(false, false);
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        let Nullable::Value(binding) = &mut c.auth.bound.binding else {
            unreachable!()
        };
        binding.lease_seconds = lease;
        decoded_positive(case);
    }
    for lease in [0, MAX_BINDING_LEASE_SECONDS + 1, u64::MAX] {
        let mut case = auth_bosh_case(false, false);
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        let Nullable::Value(binding) = &mut c.auth.bound.binding else {
            unreachable!()
        };
        binding.lease_seconds = lease;
        assert!(decode(&serde_json::to_vec(&case).unwrap()).is_err());
    }
    for lease in [
        "true",
        "-1",
        "60.0",
        "18446744073709551616",
        "\"00000000-0000-0000-0000-000000000005\"",
    ] {
        let raw = format!(
            "{{\"resource\":\"r\",\"lease_seconds\":{lease},\"full_jid\":\"u@example.test/r\"}}"
        );
        assert!(serde_json::from_str::<BindingInput>(&raw).is_err());
    }
}

#[test]
fn recovery_rejects_unpublished_same_connection_or_changed_archive_original() {
    for change in 0..7 {
        let mut case = recovery_case();
        let Composition::MixRecoveryNative(c) = &mut case.composition else {
            unreachable!()
        };
        match change {
            0 => c.worker.attempt.archive.reply = ArchiveReply::StoreCandidate(Empty {}),
            1 => c.replacement.archive.reply = ArchiveReply::StoreCandidate(Empty {}),
            2 => {
                c.replacement.archive.reply = ArchiveReply::Replay(ArchiveReplayInput {
                    original_archive_id: fixed(51),
                })
            }
            3 => {
                c.replacement.route.targets.0[0].connection_id = fixed(7);
                c.replacement.route.targets.0[0].caps.connection_id = fixed(7);
                c.native.connection_id = fixed(7);
            }
            4 => {
                c.worker.attempt.route.targets.0[0].provenance =
                    RouteProvenance::ActivatedByAuth(ActivatedRoute { frame_id: fixed(1) });
                c.worker.attempt.route.targets.0[0].routable = false;
            }
            5 => {
                c.replacement.route.targets.0[0].provenance =
                    RouteProvenance::ActivatedByAuth(ActivatedRoute { frame_id: fixed(1) });
                c.replacement.route.targets.0[0].routable = false;
            }
            _ => c.replacement.route.targets.0[0].routable = false,
        }
        assert!(decode(&serde_json::to_vec(&case).unwrap()).is_err());
    }
}

#[test]
fn defer_rejects_privacy_block_before_archive_path() {
    let mut case = defer_case();
    let Composition::MixDefer(c) = &mut case.composition else {
        unreachable!()
    };
    c.worker.attempt.route.privacy_blocked = true;
    assert!(matches!(
        decode(&serde_json::to_vec(&case).unwrap()),
        Err(Rejection::Relationship)
    ));
}

#[test]
fn fresh_mix_requires_visible_actor_and_nonempty_projection() {
    let mut visible = fresh_mix_native_case();
    let Composition::AuthThenMixNative(c) = &mut visible.composition else {
        unreachable!()
    };
    c.foreground.command.visible_jid = Nullable::Value(c.foreground.ingress.actor_bare.clone());
    decoded_positive(visible);
    for empty in [false, true] {
        let mut case = fresh_mix_native_case();
        let Composition::AuthThenMixNative(c) = &mut case.composition else {
            unreachable!()
        };
        if empty {
            let Nullable::Value(p) = &mut c.foreground.stored.projection else {
                unreachable!()
            };
            p.stanza_template = text("");
        } else {
            c.foreground.command.visible_jid = Nullable::Value(text("different@example.test"));
        }
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }
}

#[test]
fn finite_recipe_actor_budget_rejects_third_distinct_actor() {
    let mut case = muc_case(MucDrive::DropSecondEndpoint, false);
    let Composition::Muc(c) = &mut case.composition else {
        unreachable!()
    };
    c.command.actor_scope = text("third@example.test");
    c.command.sender_jid = text("third@example.test/one");
    c.command.authority.actor_scope = c.command.actor_scope.clone();
    c.command.authority.full_jid = c.command.sender_jid.clone();
    let MucPrincipal::Local(p) = &mut c.command.authority.principal else {
        unreachable!()
    };
    p.user_id = fixed(80);
    // All pre-existing recipe relationships remain meaningful; only the
    // extra canonical account actor exceeds the finite two-actor scope.
    case.validate().unwrap();
    assert!(matches!(
        decode(&serde_json::to_vec(&case).unwrap()),
        Err(Rejection::Relationship)
    ));
}

#[test]
fn bosh_governor_input_enforces_actual_constructor_constraints() {
    for change in 0..3 {
        let mut case = auth_bosh_case(false, false);
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        let g = &mut c.auth.session.governor;
        match change {
            0 => g.max_recovery_jobs = 0,
            1 => {
                g.max_snapshot_bytes = 65537;
                g.max_recovery_bytes = 65537;
            }
            _ => g.max_recovery_bytes = 65535,
        }
        assert!(matches!(
            decode(&serde_json::to_vec(&case).unwrap()),
            Err(Rejection::Relationship)
        ));
    }
}

#[test]
fn publication_callback_preserves_actual_boolean_and_absent_return() {
    for returned in ["true", "false", "null"] {
        let raw = format!("{{\"connection\":\"00000000-0000-0000-0000-000000000002\",\"session\":null,\"rid\":null,\"invoked_owners\":[],\"returned\":{returned}}}");
        assert!(serde_json::from_str::<PublicationCallback<Id>>(&raw).is_ok());
    }
    let raw = r#"{"connection":"00000000-0000-0000-0000-000000000002","session":null,"rid":null,"invoked_owners":[],"returned":"Completed"}"#;
    assert!(serde_json::from_str::<PublicationCallback<Id>>(raw).is_err());
}

#[test]
fn actual_preseal_publication_capture_uses_phase_neutral_control_identity() {
    use northstar_auth_application::authentication::{
        publication as actual, CredentialCommitReceipt,
    };
    let receipt = CredentialCommitReceipt::new(None, None, None);
    let observed = actual::Observation::returned_receipt(&receipt, Some(Uuid::from_u128(1)));
    let s = observed.snapshot();
    let j = observed.joins();
    // This ordinary control deliberately captures a genuine newly created
    // observation before any seal. Unexpected noninitial states stop the
    // test rather than being replaced by a fixture's expected state.
    let transport = match s.transport {
        actual::Transport::NotStarted => AuthTransport::NotStarted(Empty {}),
        _ => panic!("not a pre-seal constructor snapshot"),
    };
    let publication = match s.publication {
        actual::Knowledge::NotStarted => PublicationKnowledge::NotStarted(Empty {}),
        _ => panic!("not initial publication knowledge"),
    };
    let rollback = match s.rollback {
        actual::Rollback::NotRequested => PublicationRollback::NotRequested,
        _ => panic!("unexpected rollback"),
    };
    let nullable_bool = |v: Option<bool>| v.map_or(Nullable::Null(()), Nullable::Value);
    let nullable_id = |v: Option<Uuid>| {
        v.map_or(Nullable::Null(()), |v| {
            Nullable::Value(EvidenceId::observed(v))
        })
    };
    let fact = Fact::Control(ControlFact::LivePublication(LivePublication {
        cut: Cut::Introduction,
        snapshot: PublicationSnapshot {
            control: EvidenceId::observed(s.control),
            frame: nullable_id(s.frame),
            handler: s
                .handler
                .map_or(Nullable::Null(()), |_| panic!("unexpected handler return")),
            sealed: s.sealed,
            transport,
            publication,
            service_started: s.service_started,
            repository_started: s.repository_started,
            rollback,
            returned: s.returned.map_or(Nullable::Null(()), |_| {
                panic!("unexpected publication return")
            }),
            return_matches: s.return_matches,
            effects: PublicationEffects {
                unbound: s.effects.unbound,
                epoch_applied: s.effects.epoch_applied,
                route_mapping: nullable_bool(s.effects.route_mapping),
                route_activation: nullable_bool(s.effects.route_activation),
                caps_entered: s.effects.caps_entered,
                caps_returned: s.effects.caps_returned,
                notification_entered: s.effects.notification_entered,
                notification_returned: nullable_bool(s.effects.notification_returned),
            },
            terminal: s
                .terminal
                .map_or(Nullable::Null(()), |_| panic!("unexpected terminal")),
        },
        joins: Nullable::Value(PublicationJoins {
            control: EvidenceId::observed(j.control),
            frame: nullable_id(j.frame),
            receipt: EvidenceId::observed(j.receipt),
            credential: j.credential.map_or(Nullable::Null(()), |_| {
                panic!("unexpected credential attachment")
            }),
            begun_receipt: nullable_id(j.begun_receipt),
            bound_effects: j.bound_effects,
            notification_expected: j.notification_expected,
        }),
    }));
    assert!(!s.sealed);
    let mut recorder = Recorder::new(&input_case());
    recorder.capture(fact).unwrap();
    let e = recorder.finish(Execution::Complete).unwrap();
    let Fact::Control(ControlFact::LivePublication(capture)) = &e.facts.0[0].fact else {
        unreachable!()
    };
    assert!(!capture.snapshot.sealed);
    let EvidenceId::Encoded(control) = &capture.snapshot.control else {
        unreachable!()
    };
    assert_eq!(
        e.identity_map
            .0
            .iter()
            .find(|i| &i.label == control)
            .unwrap()
            .locus,
        Introduction::ControlIdentity
    );
}

#[test]
fn prior_completed_frame_outcome_does_not_complete_pending_publication() {
    let input = reduced_bytes();
    let parsed = decode(&input).unwrap();
    let mut r = Recorder::new(&parsed);
    r.capture(Fact::Frame(FrameCapture {
        frame: id(1),
        cut: Cut::AfterPoll,
        stage: Nullable::Value(FrameStage::AuthPublication),
        outcome: Nullable::Value(FrameOutcome::Completed),
        admission_begin: Nullable::Null(()),
        admission_finalize: Nullable::Null(()),
    }))
    .unwrap();
    let mut live = live_anchor(100, 200, 300, 1, ObservedCredentialKind::Binding);
    let Fact::Control(ControlFact::LivePublication(p)) = &mut live else {
        unreachable!()
    };
    p.cut = Cut::AfterPoll;
    p.snapshot.publication = PublicationKnowledge::CommitCallEntered(Empty {});
    r.capture(live).unwrap();
    let e = r.finish(Execution::Cancelled).unwrap();
    validate_envelope(&e, &input, Some(&parsed)).unwrap();
    let Fact::Frame(frame) = &e.facts.0[0].fact else {
        unreachable!()
    };
    assert_eq!(frame.outcome.get(), Some(&FrameOutcome::Completed));
    let Fact::Control(ControlFact::LivePublication(p)) = &e.facts.0[1].fact else {
        unreachable!()
    };
    assert!(matches!(
        p.snapshot.publication,
        PublicationKnowledge::CommitCallEntered(_)
    ));
    assert!(p.snapshot.terminal.get().is_none());
    // Structural preservation only. The separate actual accessor control
    // establishes this combination's runtime origin; it is not run here.
}

#[test]
fn existing_receipt_reassignment_preserves_original_live_publication_anchors() {
    let parsed = decode(&serde_json::to_vec(&replay_queued_auth_case()).unwrap()).unwrap();
    let build = |returned| {
        let mut r = Recorder::new(&parsed);
        r.capture(credential_at(
            300,
            200,
            200,
            1,
            ObservedCredentialKind::Binding,
        ))
        .unwrap();
        r.capture(credential_at(
            301,
            201,
            201,
            30,
            ObservedCredentialKind::UnboundFast,
        ))
        .unwrap();
        r.capture(live_anchor(
            100,
            200,
            300,
            1,
            ObservedCredentialKind::Binding,
        ))
        .unwrap();
        r.capture(live_anchor(
            101,
            201,
            301,
            30,
            ObservedCredentialKind::UnboundFast,
        ))
        .unwrap();
        r.capture(credential_at(
            300,
            200,
            returned,
            1,
            ObservedCredentialKind::Binding,
        ))
        .unwrap();
        r.finish(Execution::Complete).unwrap()
    };
    let original = build(200);
    let changed = build(201);
    assert_eq!(original.identity_map, changed.identity_map);
    assert_eq!(&original.facts.0[..4], &changed.facts.0[..4]);
    let Fact::Credential(c) = &changed.facts.0[4].fact else {
        unreachable!()
    };
    let joins = c.joins.get().unwrap();
    let Fact::Control(ControlFact::LivePublication(a)) = &changed.facts.0[2].fact else {
        unreachable!()
    };
    let Fact::Control(ControlFact::LivePublication(b)) = &changed.facts.0[3].fact else {
        unreachable!()
    };
    assert_eq!(
        joins.constructed_receipt.get(),
        Some(&a.joins.get().unwrap().receipt)
    );
    assert_eq!(
        joins.returned_receipt.get(),
        Some(&b.joins.get().unwrap().receipt)
    );
    assert_ne!(joins.constructed_receipt, joins.returned_receipt);
    assert_ne!(
        encode_frame(&original).unwrap(),
        encode_frame(&changed).unwrap()
    );
}

#[test]
fn existing_control_receipt_swap_preserves_original_live_publication_anchors() {
    let parsed = decode(&serde_json::to_vec(&replay_queued_auth_case()).unwrap()).unwrap();
    let build = |receipt| {
        let mut r = Recorder::new(&parsed);
        r.capture(live_anchor(
            100,
            200,
            300,
            1,
            ObservedCredentialKind::Binding,
        ))
        .unwrap();
        r.capture(live_anchor(
            101,
            201,
            301,
            30,
            ObservedCredentialKind::UnboundFast,
        ))
        .unwrap();
        r.capture(control_holder(None)).unwrap();
        r.capture(control_holder(Some(receipt))).unwrap();
        r.finish(Execution::Complete).unwrap()
    };
    let original = build(200);
    let changed = build(201);
    assert_eq!(original.identity_map, changed.identity_map);
    assert_eq!(&original.facts.0[..3], &changed.facts.0[..3]);
    let Fact::Control(ControlFact::Holder(last)) = &changed.facts.0[3].fact else {
        unreachable!()
    };
    let joins = last.holder.get().unwrap();
    let Fact::Control(ControlFact::LivePublication(a)) = &changed.facts.0[0].fact else {
        unreachable!()
    };
    let Fact::Control(ControlFact::LivePublication(b)) = &changed.facts.0[1].fact else {
        unreachable!()
    };
    assert_eq!(
        joins.introduced.get().unwrap().receipt,
        a.joins.get().unwrap().receipt
    );
    assert_eq!(
        joins.transferred.get().unwrap().receipt,
        b.joins.get().unwrap().receipt
    );
    assert_ne!(
        joins.introduced.get().unwrap().receipt,
        joins.transferred.get().unwrap().receipt
    );
    assert_ne!(
        encode_frame(&original).unwrap(),
        encode_frame(&changed).unwrap()
    );
}

#[test]
fn transferred_receipt_only_swap_retains_historical_publication_receipt() {
    let parsed = decode(&serde_json::to_vec(&replay_queued_auth_case()).unwrap()).unwrap();
    let mut r = Recorder::new(&parsed);
    r.capture(live_anchor(
        100,
        200,
        300,
        1,
        ObservedCredentialKind::Binding,
    ))
    .unwrap();
    r.capture(live_anchor(
        101,
        201,
        301,
        30,
        ObservedCredentialKind::UnboundFast,
    ))
    .unwrap();
    r.capture(control_holder(None)).unwrap();
    let mut second_holder = control_holder(None);
    let Fact::Control(ControlFact::Holder(second)) = &mut second_holder else {
        unreachable!()
    };
    let Nullable::Value(joins) = &mut second.holder else {
        unreachable!()
    };
    let Nullable::Value(introduction) = &mut joins.introduced else {
        unreachable!()
    };
    introduction.control = id(101);
    introduction.frame = Nullable::Value(id(30));
    introduction.receipt = id(201);
    introduction.publication.control = id(101);
    introduction.publication.frame = Nullable::Value(id(30));
    introduction.publication.receipt = id(201);
    introduction.publication.bound_effects = false;
    let Nullable::Value(owner) = &mut introduction.publication.credential else {
        unreachable!()
    };
    owner.attempt = id(301);
    owner.frame = id(30);
    owner.kind = ObservedCredentialKind::UnboundFast;
    r.capture(second_holder).unwrap();
    r.capture(control_holder(Some(200))).unwrap();
    let original = r.finish(Execution::Complete).unwrap();
    let mut changed = original.clone();
    // Receipt 201 already has its own unchanged live publication anchor.
    let Fact::Control(ControlFact::LivePublication(second)) = &original.facts.0[1].fact else {
        unreachable!()
    };
    let introduced_201 = second.joins.get().unwrap().receipt.clone();
    let Fact::Control(ControlFact::Holder(last)) = &mut changed.facts.0[4].fact else {
        unreachable!()
    };
    let Nullable::Value(holder) = &mut last.holder else {
        unreachable!()
    };
    let Nullable::Value(transferred) = &mut holder.transferred else {
        unreachable!()
    };
    let historical_200 = transferred.publication.receipt.clone();
    // The one and only negative edit models the private swap shape. Unlike
    // control_holder(Some(201)), this does not rewrite the nested historical
    // publication association to make the reassignment look consistent.
    transferred.receipt = introduced_201.clone();
    assert_eq!(transferred.publication.receipt, historical_200);
    assert_ne!(transferred.receipt, transferred.publication.receipt);
    assert_eq!(original.identity_map, changed.identity_map);
    assert_eq!(&original.facts.0[..4], &changed.facts.0[..4]);
    validate_envelope(
        &changed,
        &serde_json::to_vec(&replay_queued_auth_case()).unwrap(),
        Some(&parsed),
    )
    .unwrap();
    assert_ne!(
        encode_frame(&original).unwrap(),
        encode_frame(&changed).unwrap()
    );
    // Reverse exactly that field and recover the complete original facts.
    let Fact::Control(ControlFact::Holder(last)) = &mut changed.facts.0[4].fact else {
        unreachable!()
    };
    let Nullable::Value(holder) = &mut last.holder else {
        unreachable!()
    };
    let Nullable::Value(transferred) = &mut holder.transferred else {
        unreachable!()
    };
    transferred.receipt = historical_200;
    assert_eq!(changed, original);
}

#[test]
fn account_call_distinguishes_entry_found_absent_and_error() {
    let mut encodings = BTreeSet::new();
    for returned in [
        "null",
        r#"{"kind":"Found","data":{"id":"00000000-0000-0000-0000-000000000385","username":"actual-name"}}"#,
        r#"{"kind":"Absent","data":{}}"#,
        r#"{"kind":"Error","data":{}}"#,
    ] {
        let raw = format!(
            "{{\"attempt_ordinal\":0,\"username\":\"requested-name\",\"returned\":{returned}}}"
        );
        let call: AccountCall<Id> = serde_json::from_str(&raw).unwrap();
        let encoded = serde_json::to_vec(&call).unwrap();
        assert_eq!(
            serde_json::from_slice::<AccountCall<Id>>(&encoded).unwrap(),
            call
        );
        encodings.insert(encoded);
    }
    assert_eq!(encodings.len(), 4);
    assert!(serde_json::from_str::<AccountCall<Id>>(
        r#"{"attempt_ordinal":0,"username":"requested-name"}"#
    )
    .is_err());
    assert!(serde_json::from_str::<AccountReturned<Id>>(
        r#"{"kind":"Error","data":{"diagnostic":"backend text"}}"#
    )
    .is_err());
}

#[test]
fn privacy_call_distinguishes_entry_true_false_and_error() {
    let mut encodings = BTreeSet::new();
    for returned in [
        "null",
        r#"{"kind":"Outcome","data":{"value":true}}"#,
        r#"{"kind":"Outcome","data":{"value":false}}"#,
        r#"{"kind":"Error","data":{}}"#,
    ] {
        let raw = format!("{{\"attempt_ordinal\":0,\"owner_id\":\"00000000-0000-0000-0000-000000000385\",\"candidate\":\"c@mix.example.test\",\"returned\":{returned}}}");
        let call: PrivacyCall<Id> = serde_json::from_str(&raw).unwrap();
        let encoded = serde_json::to_vec(&call).unwrap();
        assert_eq!(
            serde_json::from_slice::<PrivacyCall<Id>>(&encoded).unwrap(),
            call
        );
        encodings.insert(encoded);
    }
    assert_eq!(encodings.len(), 4);
    assert!(
        serde_json::from_str::<PrivacyReturned>(r#"{"kind":"Outcome","data":{"value":0}}"#)
            .is_err()
    );
    assert!(serde_json::from_str::<PrivacyReturned>(
        r#"{"kind":"Error","data":{"diagnostic":"backend text"}}"#
    )
    .is_err());
}

#[test]
fn account_privacy_strings_are_bounded_to_1024_utf8_bytes() {
    let accepted = "x".repeat(1024);
    let rejected = "x".repeat(1025);
    for (value, valid) in [(&accepted, true), (&rejected, false)] {
        let account =
            format!("{{\"attempt_ordinal\":0,\"username\":\"{value}\",\"returned\":null}}");
        let identity =
            format!("{{\"id\":\"00000000-0000-0000-0000-000000000385\",\"username\":\"{value}\"}}");
        let privacy = format!("{{\"attempt_ordinal\":0,\"owner_id\":\"00000000-0000-0000-0000-000000000385\",\"candidate\":\"{value}\",\"returned\":null}}");
        assert_eq!(
            serde_json::from_str::<AccountCall<Id>>(&account).is_ok(),
            valid
        );
        assert_eq!(
            serde_json::from_str::<AccountIdentity<Id>>(&identity).is_ok(),
            valid
        );
        assert_eq!(
            serde_json::from_str::<PrivacyCall<Id>>(&privacy).is_ok(),
            valid
        );
    }
    assert!(Text::<1024>::new("é".repeat(512)).is_ok());
    assert!(Text::<1024>::new("é".repeat(513)).is_err());
}

#[test]
fn account_return_identity_is_captured_and_reused_as_actual_privacy_argument() {
    let input = serde_json::to_vec(&recovery_case()).unwrap();
    let parsed = decode(&input).unwrap();
    // Actual service-result data type, deliberately different from the
    // supplied account ID/name. This ordinary data control does not run
    // either service or infer a successful account lookup from the input.
    let actual = crate::services::mix::MixAccount {
        id: Uuid::from_u128(901),
        username: "actual-name".to_owned(),
    };
    let requested = "requested-name";
    let candidate = "c@mix.example.test";
    let mut r = Recorder::new(&parsed);
    r.capture(Fact::Worker(WorkerFact::Account(AccountCall {
        attempt_ordinal: 0,
        username: text(requested),
        returned: Nullable::Null(()),
    })))
    .unwrap();
    r.capture(Fact::Worker(WorkerFact::Account(AccountCall {
        attempt_ordinal: 0,
        username: text(requested),
        returned: Nullable::Value(AccountReturned::Found(AccountIdentity {
            id: EvidenceId::observed(actual.id),
            username: text(&actual.username),
        })),
    })))
    .unwrap();
    r.capture(Fact::Worker(WorkerFact::Privacy(PrivacyCall {
        attempt_ordinal: 0,
        owner_id: EvidenceId::observed(actual.id),
        candidate: text(candidate),
        returned: Nullable::Null(()),
    })))
    .unwrap();
    r.capture(Fact::Worker(WorkerFact::Privacy(PrivacyCall {
        attempt_ordinal: 0,
        owner_id: EvidenceId::observed(actual.id),
        candidate: text(candidate),
        returned: Nullable::Value(PrivacyReturned::Outcome(BoolValue { value: false })),
    })))
    .unwrap();
    let e = r.finish(Execution::Complete).unwrap();
    validate_envelope(&e, &input, Some(&parsed)).unwrap();
    let Fact::Worker(WorkerFact::Account(entry)) = &e.facts.0[0].fact else {
        unreachable!()
    };
    assert!(entry.returned.get().is_none());
    let Fact::Worker(WorkerFact::Account(returned)) = &e.facts.0[1].fact else {
        unreachable!()
    };
    let Some(AccountReturned::Found(found)) = returned.returned.get() else {
        unreachable!()
    };
    assert_eq!(returned.username.as_str(), requested);
    assert_eq!(found.username.as_str(), actual.username);
    assert!(is_opaque(&found.id, 1));
    let Fact::Worker(WorkerFact::Privacy(privacy_entry)) = &e.facts.0[2].fact else {
        unreachable!()
    };
    let Fact::Worker(WorkerFact::Privacy(privacy_return)) = &e.facts.0[3].fact else {
        unreachable!()
    };
    assert_eq!(found.id, privacy_entry.owner_id);
    assert_eq!(found.id, privacy_return.owner_id);
    assert!(privacy_entry.returned.get().is_none());
    assert!(matches!(
        privacy_return.returned.get(),
        Some(PrivacyReturned::Outcome(BoolValue { value: false }))
    ));
    assert_eq!(e.identity_map.len(), 1);
    assert_eq!(e.identity_map.0[0].first_seq, 2);
    assert_eq!(
        e.facts.0.iter().map(|f| f.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
}

#[test]
fn bytes_hex_accessor_round_trips_without_repairing_invalid_encoding() {
    let raw = [0, 1, 127, 128, 255];
    let value = Bytes::<5>::of(&raw).unwrap();
    assert_eq!(value.as_hex(), "00017f80ff");
    let decoded: Vec<u8> = value
        .as_hex()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(decoded, raw);
    let round_trip: Bytes<5> =
        serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(round_trip.as_hex(), value.as_hex());
    assert_eq!(Bytes::<0>::of(&[]).unwrap().as_hex(), "");
    for invalid in ["00017F80ff", "00017f80f", "00017g80ff", "00017f80ff00"] {
        assert!(Bytes::<5>::new(invalid.to_owned()).is_err());
    }
    assert!(Bytes::<4>::of(&raw).is_err());
}

#[test]
fn account_privacy_records_consume_the_existing_case_fact_budget() {
    let mut r = Recorder::new(&input_case());
    for index in 0..MAX_FACTS {
        let fact = if index % 2 == 0 {
            Fact::Worker(WorkerFact::Account(AccountCall {
                attempt_ordinal: 0,
                username: text("u"),
                returned: Nullable::Null(()),
            }))
        } else {
            Fact::Worker(WorkerFact::Privacy(PrivacyCall {
                attempt_ordinal: 0,
                owner_id: id(4),
                candidate: text("c@mix.example.test"),
                returned: Nullable::Null(()),
            }))
        };
        assert_eq!(r.capture(fact).unwrap(), index as u32 + 1);
    }
    let extra = Fact::Worker(WorkerFact::Account(AccountCall {
        attempt_ordinal: 0,
        username: text("u"),
        returned: Nullable::Value(AccountReturned::Error(Empty {})),
    }));
    assert_eq!(r.capture(extra), Err(Loss::FactOverflow));
    let e = r.finish(Execution::Failed).unwrap();
    assert_eq!(e.facts.len(), MAX_FACTS);
    assert!(matches!(
        e.observation_status,
        ObservationStatus::Lost(LostObservation {
            reason: Loss::FactOverflow,
            after_seq: 256
        })
    ));
}

#[test]
fn parser_accepts_closed_auth_input_without_owner_construction() {
    assert!(decode(&reduced_bytes()).is_ok());
}

#[test]
fn parser_rejects_duplicate_and_unknown_top_level_fields() {
    let input = String::from_utf8(reduced_bytes()).unwrap();
    let duplicate = input.replacen("\"case_id\":", "\"case_id\":\"duplicate\",\"case_id\":", 1);
    assert!(matches!(decode(duplicate.as_bytes()), Err(Rejection::Json)));
    let extra = input.replacen('{', "{\"artifact\":\"mutant\",", 1);
    assert!(matches!(decode(extra.as_bytes()), Err(Rejection::Json)));
}

#[test]
fn parser_rejects_duplicates_inside_required_nullable_objects() {
    assert!(serde_json::from_str::<Nullable<BindingInput>>(
        r#"{"resource":"r","resource":"s","lease_seconds":60,"full_jid":"u@example.test/r"}"#
    )
    .is_err());
}

#[test]
fn parser_requires_named_records_even_under_tagged_sums() {
    assert!(serde_json::from_str::<EpochValue>("[null]").is_err());
    assert!(
        serde_json::from_str::<PublicationReply>(r#"{"kind":"Committed","data":[null]}"#).is_err()
    );
    assert!(serde_json::from_str::<PublicationReply>(r#"["Committed",{"epoch":null}]"#).is_err());
    assert!(serde_json::from_str::<PublicationReply>(
        r#"{"kind":"BackendError","data":{"extra":true}}"#
    )
    .is_err());
}

#[test]
fn parser_rejects_duplicate_tag_and_missing_empty_payload() {
    assert!(serde_json::from_str::<PublicationReply>(
        r#"{"kind":"NoSql","kind":"BackendError","data":{}}"#
    )
    .is_err());
    assert!(serde_json::from_str::<PublicationReply>(r#"{"kind":"BackendError"}"#).is_err());
}

#[test]
fn parser_rejects_object_and_numeric_tags_at_every_depth_and_key_order() {
    for bad in [r#"{"NoSql":null}"#, "0", "true", "null"] {
        for input in [
            format!("{{\"kind\":{bad},\"data\":{{}}}}"),
            format!("{{\"data\":{{}},\"kind\":{bad}}}"),
        ] {
            assert!(serde_json::from_str::<PublicationReply>(&input).is_err());
        }
    }
    // Exercise the actual Content-buffered nested-sum path. Variant index
    // 3 would otherwise select the payload-free ClusterSocketFenced value.
    for data in [
        r#"{"kind":3,"data":{}}"#,
        r#"{"data":{},"kind":3}"#,
        r#"{"kind":{"ClusterSocketFenced":null},"data":{}}"#,
    ] {
        let input = format!("{{\"kind\":\"Transferred\",\"data\":{data}}}");
        assert!(serde_json::from_str::<LocalResult<Id>>(&input).is_err());
    }
    assert!(serde_json::from_str::<LocalResult<Id>>(
        r#"{"kind":"Transferred","data":{"kind":"ClusterSocketFenced","data":{}}}"#
    )
    .is_ok());
    assert!(serde_json::from_str::<ArchiveReturned<Id>>(r#"{"kind":"Outcome","data":{"kind":"Stored","data":{"id":"00000000-0000-0000-0000-000000000001"}}}"#).is_ok());
    assert!(serde_json::from_str::<ArchiveReturned<Id>>(r#"{"kind":"Outcome","data":{"kind":0,"data":{"id":"00000000-0000-0000-0000-000000000001"}}}"#).is_err());
}

#[test]
fn parser_accepts_reordered_sum_fields_without_erasing_duplicates() {
    assert!(
        serde_json::from_str::<PublicationReply>(r#"{"data":{},"kind":"BackendError"}"#).is_ok()
    );
    assert!(serde_json::from_str::<PublicationReply>(
        r#"{"data":{"epoch":1,"epoch":2},"kind":"Committed"}"#
    )
    .is_err());
}

#[test]
fn parser_requires_explicit_nullable_fields() {
    assert!(serde_json::from_str::<EpochValue>(r#"{"epoch":null}"#).is_ok());
    assert!(serde_json::from_str::<EpochValue>("{}").is_err());
}

#[test]
fn parser_accepts_only_string_enum_encoding() {
    assert!(serde_json::from_str::<CommitCut>(r#""Complete""#).is_ok());
    assert!(serde_json::from_str::<CommitCut>(r#"{"Complete":null}"#).is_err());
    assert!(serde_json::from_str::<CommitCut>(r#""Completed""#).is_err());
}

#[test]
fn parser_rejects_noncanonical_uuid_and_hex() {
    for value in [
        "0000000000000000000000000000000abc",
        "00000000-0000-0000-0000-000000000ABC",
        "{00000000-0000-0000-0000-000000000abc}",
    ] {
        assert!(serde_json::from_str::<Id>(&format!("\"{value}\"")).is_err());
    }
    assert!(serde_json::from_str::<Hex<1>>(r#""AF""#).is_err());
    assert!(serde_json::from_str::<Bytes<2>>(r#""abc""#).is_err());
    assert!(serde_json::from_str::<Bytes<2>>(r#""00ff00""#).is_err());
}

#[test]
fn parser_rejects_boolean_float_negative_and_overflow_integer() {
    for n in ["true", "1.0", "-1", "4294967296"] {
        assert!(serde_json::from_str::<CountValue>(&format!("{{\"count\":{n}}}")).is_err());
    }
}

#[test]
fn parser_enforces_string_array_and_input_caps() {
    assert!(serde_json::from_str::<Text<2>>(r#""abc""#).is_err());
    assert!(serde_json::from_str::<List<u8, 2>>("[1,2,3]").is_err());
    assert!(matches!(
        decode(&vec![b' '; MAX_INPUT + 1]),
        Err(Rejection::TooLarge)
    ));
    assert!(matches!(
        read_input(std::io::Cursor::new(vec![b' '; MAX_INPUT + 1])),
        Err(Rejection::TooLarge)
    ));
}

#[test]
fn parser_rejects_trailing_value_and_foreign_contract() {
    let mut bytes = reduced_bytes();
    bytes.extend_from_slice(b" {}");
    assert!(matches!(decode(&bytes), Err(Rejection::Json)));
    let input = String::from_utf8(reduced_bytes())
        .unwrap()
        .replace(CASE_SCHEMA, "northstar-direct-case-v1");
    assert!(matches!(decode(input.as_bytes()), Err(Rejection::Schema)));
}

#[test]
fn relationship_rejection_precedes_owner_work() {
    let mut case: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
    let Composition::BoshAuth(c) = &mut case.composition else {
        unreachable!()
    };
    c.auth.session.connection_id = Id(Uuid::from_u128(6));
    let bytes = serde_json::to_vec(&case).unwrap();
    assert!(matches!(decode(&bytes), Err(Rejection::Relationship)));
    let envelope = Envelope::rejected(&bytes, Rejection::Relationship).unwrap();
    assert!(
        envelope.facts.is_empty()
            && envelope.identity_map.is_empty()
            && envelope.execution.get().is_none()
    );
    validate_envelope(&envelope, &bytes, None).unwrap();
}

#[test]
fn auth_parser_rejects_wrong_namespace_nested_leaf_and_nonzero_frame_ordinal() {
    let parsed = input_case();
    let Composition::BoshAuth(c) = &parsed.case.composition else {
        unreachable!()
    };
    for replacement in [
        "<jid xmlns='wrong'>u@example.test/r</jid>",
        "<jid>u@example.test/r<z:token xmlns:z='secrets'>x</z:token></jid>",
    ] {
        let mut bound = c.auth.bound.clone();
        let ControlInput::Binding(control) = &mut bound.control else {
            unreachable!()
        };
        control.xml.0 = control
            .xml
            .0
            .replace("<jid>u@example.test/r</jid>", replacement);
        assert!(validate_auth(&bound, CredentialKind::Binding, TransportKind::Bosh).is_err());
    }
    let mut bound = c.auth.bound.clone();
    bound.ordinal = 1;
    assert!(validate_auth(&bound, CredentialKind::Binding, TransportKind::Bosh).is_err());
}

#[test]
fn worker_parser_rejects_declared_recipient_route_disagreement() {
    let mut mix = independent_mix();
    mix.worker.attempt.route.targets.0[0].full_jid =
        Text::new("someone-else@example.test/m").unwrap();
    assert!(validate_worker(&mix.worker).is_err());
}

#[test]
fn case_id_does_not_select_behavior_or_artifact() {
    let mut a: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
    let composition = a.composition.clone();
    a.case_id = Text::new("M3-is-only-descriptive").unwrap();
    let b = decode(&serde_json::to_vec(&a).unwrap()).unwrap();
    assert_eq!(b.case.composition, composition);
}

#[test]
fn full_to_reduced_deletes_only_independent_mix_subtree() {
    let mut full: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
    let Composition::BoshAuth(c) = &mut full.composition else {
        unreachable!()
    };
    let auth_bytes = serde_json::to_vec(&c.auth).unwrap();
    c.mix = Nullable::Value(independent_mix());
    let full_bytes = serde_json::to_vec(&full).unwrap();
    assert!(decode(&full_bytes).is_ok());
    let mut reduced = full.clone();
    let Composition::BoshAuth(c) = &mut reduced.composition else {
        unreachable!()
    };
    c.mix = Nullable::Null(());
    assert_eq!(serde_json::to_vec(&c.auth).unwrap(), auth_bytes);
    assert_eq!(full.case_id, reduced.case_id);
    let baseline = serde_json::to_vec(&reduced).unwrap();
    let m2 = baseline.clone();
    let m3 = baseline.clone();
    assert_eq!(baseline, m2);
    assert_eq!(m2, m3);
    assert_eq!(sha256(&baseline), sha256(&m3));
    assert!(decode(&baseline).is_ok());
}

#[test]
fn independent_lanes_reject_connection_session_and_canonical_key_collision() {
    for change in 0..3 {
        let mut case: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
        let Composition::BoshAuth(c) = &mut case.composition else {
            unreachable!()
        };
        let mut mix = independent_mix();
        match change {
            0 => mix.transport.session.connection_id = c.auth.session.connection_id,
            1 => mix.transport.session.session_id = c.auth.session.session_id,
            _ => {
                mix.worker.attempt.route.targets.0[0].full_jid =
                    c.auth.bound.binding.get().unwrap().full_jid.clone()
            }
        }
        c.mix = Nullable::Value(mix);
        assert!(decode(&serde_json::to_vec(&case).unwrap()).is_err());
    }
}

#[test]
fn fixed_padding_accepts_only_frozen_geometry() {
    let parsed = input_case();
    let Composition::BoshAuth(c) = &parsed.case.composition else {
        unreachable!()
    };
    let b = c.auth.bound.clone();
    let mut u = b.clone();
    u.control = ControlInput::UnboundFast(UnboundControlInput { authorization_identifier: Text::new("u@example.test").unwrap(), xml: Text::new("<success xmlns='urn:xmpp:sasl:2'><authorization-identifier>u@example.test</authorization-identifier></success>").unwrap() });
    let count = RESPONSE_BYTES as usize - 256 - auth_xml(&u).len() - P_OPEN.len() - P_CLOSE.len();
    let mut padding = FixedAuthPadding {
        presence_xml: Text::new(format!("{P_OPEN}{}{P_CLOSE}", "x".repeat(count))).unwrap(),
        features_xml: Text::new(FIXED_FEATURES).unwrap(),
    };
    validate_padding(&padding, &u, &b).unwrap();
    padding.presence_xml.0 = padding.presence_xml.0.replacen('x', "y", 1);
    assert!(validate_padding(&padding, &u, &b).is_err());
}

#[test]
fn identity_repeated_across_roles_has_one_label() {
    let mut r = Recorder::new(&input_case());
    r.capture(credential(100, Some(100), Some(100))).unwrap();
    let e = r.finish(Execution::Complete).unwrap();
    let Fact::Credential(c) = &e.facts.0[0].fact else {
        unreachable!()
    };
    let joins = c.joins.get().unwrap();
    assert_eq!(
        c.snapshot.attempt,
        joins.constructed_receipt.get().unwrap().clone()
    );
    assert_eq!(joins.constructed_receipt, joins.returned_receipt);
    assert_eq!(
        e.identity_map
            .0
            .iter()
            .filter(|i| matches!(i.label, IdentityLabel::Opaque(_)))
            .count(),
        1
    );
}

#[test]
fn identity_distinct_raw_values_do_not_collapse() {
    let e = recorded(100, 200);
    let Fact::Credential(c) = &e.facts.0[0].fact else {
        unreachable!()
    };
    assert!(is_opaque(&c.snapshot.attempt, 1));
    assert!(is_opaque(
        c.joins.get().unwrap().constructed_receipt.get().unwrap(),
        2
    ));
}

#[test]
fn identity_fixed_generated_collision_remains_actual_equality() {
    let e = recorded(1, 200);
    let Fact::Credential(c) = &e.facts.0[0].fact else {
        unreachable!()
    };
    assert_eq!(c.snapshot.attempt, c.snapshot.frame);
    assert!(matches!(
        c.snapshot.attempt,
        EvidenceId::Encoded(IdentityLabel::Fixed(_))
    ));
}

#[test]
fn identity_global_opaque_renaming_is_canonical_equivalence() {
    assert_eq!(
        encode_frame(&recorded(100, 200)).unwrap(),
        encode_frame(&recorded(101, 201)).unwrap()
    );
}

#[test]
fn deleting_independent_mix_can_shift_opaque_ordinals_but_retains_auth_anchors() {
    let mut full: Case = serde_json::from_slice(&reduced_bytes()).unwrap();
    let Composition::BoshAuth(c) = &mut full.composition else {
        unreachable!()
    };
    c.mix = Nullable::Value(independent_mix());
    let full = decode(&serde_json::to_vec(&full).unwrap()).unwrap();
    let mut recorder = Recorder::new(&full);
    recorder
        .capture(Fact::Worker(WorkerFact::Archive(ArchiveCall {
            attempt_ordinal: 0,
            command: ArchiveCommand {
                personal_archive_id: id(999),
                owner_id: id(4),
                channel_jid: Text::new("c@mix.example.test").unwrap(),
                authoritative_stanza_id: id(9),
                stanza: Text::new("<message/>").unwrap(),
                encrypted: false,
                client_stanza_id: Nullable::Null(()),
            },
            returned: Nullable::Null(()),
        })))
        .unwrap();
    recorder.capture(credential(100, Some(200), None)).unwrap();
    let full = recorder.finish(Execution::Complete).unwrap();
    let reduced = recorded(100, 200);
    let Fact::Credential(a) = &full.facts.0[1].fact else {
        unreachable!()
    };
    let Fact::Credential(b) = &reduced.facts.0[0].fact else {
        unreachable!()
    };
    assert_eq!(a.snapshot.frame, b.snapshot.frame);
    assert_eq!(a.snapshot.connection, b.snapshot.connection);
    assert!(is_opaque(&a.snapshot.attempt, 2));
    assert!(is_opaque(&b.snapshot.attempt, 1));
    assert_eq!(full.facts.0[1].seq, 2);
    assert_eq!(reduced.facts.0[0].seq, 1);
    // The independent shrink reader must compare anchored retained graphs,
    // never demand identical first-seen numbers across these different inputs.
}

#[test]
fn identity_post_introduction_receipt_reassignment_stays_visible() {
    let c = input_case();
    let mut r = Recorder::new(&c);
    r.capture(credential(100, Some(200), None)).unwrap();
    r.capture(credential(100, Some(200), Some(201))).unwrap();
    let changed = r.finish(Execution::Complete).unwrap();
    let Fact::Credential(last) = &changed.facts.0[1].fact else {
        unreachable!()
    };
    let joins = last.joins.get().unwrap();
    assert_ne!(joins.constructed_receipt, joins.returned_receipt);
    assert!(is_opaque(joins.returned_receipt.get().unwrap(), 3));
    assert_ne!(
        encode_frame(&changed).unwrap(),
        encode_frame(&recorded(100, 200)).unwrap()
    );
    // This slice preserves the violating graph. The separate independent
    // semantic oracle, not this encoder, must reject the actual bad join.
}

#[test]
fn identity_post_introduction_control_association_reassignment_stays_visible() {
    let mut original = Recorder::new(&input_case());
    original.capture(control_holder(None)).unwrap();
    original.capture(control_holder(Some(200))).unwrap();
    let mut changed = Recorder::new(&input_case());
    changed.capture(control_holder(None)).unwrap();
    changed.capture(control_holder(Some(201))).unwrap();
    let e = changed.finish(Execution::Complete).unwrap();
    let Fact::Control(ControlFact::Holder(last)) = &e.facts.0[1].fact else {
        unreachable!()
    };
    let holder = last.holder.get().unwrap();
    assert_ne!(
        holder.introduced.get().unwrap().receipt,
        holder.transferred.get().unwrap().receipt
    );
    assert_eq!(
        holder.introduced.get().unwrap().control,
        holder.transferred.get().unwrap().control
    );
    assert_ne!(
        encode_frame(&e).unwrap(),
        encode_frame(&original.finish(Execution::Complete).unwrap()).unwrap()
    );
}

#[test]
fn identity_missing_receipt_is_not_synthesized_or_reserved() {
    let mut r = Recorder::new(&input_case());
    r.capture(credential(100, None, None)).unwrap();
    let e = r.finish(Execution::Complete).unwrap();
    let Fact::Credential(c) = &e.facts.0[0].fact else {
        unreachable!()
    };
    assert!(c.joins.get().unwrap().constructed_receipt.get().is_none());
    assert_eq!(
        e.identity_map
            .0
            .iter()
            .filter(|i| matches!(i.label, IdentityLabel::Opaque(_)))
            .count(),
        1
    );
}

#[test]
fn identity_overflow_keeps_contiguous_prefix_and_explicit_loss() {
    let mut r = Recorder::new(&input_case());
    for n in 0..8 {
        r.capture(credential(100 + n, Some(200 + n), None)).unwrap();
    }
    assert_eq!(
        r.capture(credential(108, Some(208), None)),
        Err(Loss::OpaqueOverflow)
    );
    let e = r.finish(Execution::Failed).unwrap();
    assert_eq!(e.facts.len(), 8);
    assert!(matches!(
        e.observation_status,
        ObservationStatus::Lost(LostObservation {
            reason: Loss::OpaqueOverflow,
            after_seq: 8
        })
    ));
    assert_eq!(
        e.identity_map
            .0
            .iter()
            .filter(|i| matches!(i.label, IdentityLabel::Opaque(_)))
            .count(),
        MAX_OPAQUE
    );
}

#[test]
fn identity_total_cap_includes_unused_fixed_anchors() {
    let mut m = IdentityMap::default();
    for n in 1..=64 {
        m.anchor(Uuid::from_u128(n), Introduction::UnexpectedObservedIdentity)
            .unwrap();
    }
    assert_eq!(
        m.observe(Uuid::from_u128(65), 1, Introduction::CredentialAttempt),
        Err(Loss::IdentityOverflow)
    );
    assert!(matches!(
        m.observe(Uuid::from_u128(1), 1, Introduction::CredentialAttempt),
        Ok(IdentityLabel::Fixed(_))
    ));
}

#[test]
fn raw_generated_uuid_cannot_escape_without_capture() {
    assert!(serde_json::to_vec(&credential(100, Some(200), None)).is_err());
}

#[test]
fn sequence_fact_poll_and_snapshot_bounds_are_explicit() {
    let mut sequence = Sequence::default();
    for n in 1..=MAX_FACTS {
        assert_eq!(sequence.available(false).unwrap(), n as u32);
        sequence.committed(false);
    }
    assert_eq!(sequence.available(false), Err(Loss::FactOverflow));
    let mut r = Recorder::new(&input_case());
    for _ in 0..MAX_POLLS {
        r.polled(DriverOwner::Publication, 0, &std::task::Poll::<()>::Pending)
            .unwrap();
    }
    assert_eq!(
        r.polled(DriverOwner::Publication, 0, &std::task::Poll::Ready(())),
        Err(Loss::PollOverflow)
    );
    let mut r = Recorder::new(&input_case());
    for _ in 0..MAX_OWNER_SNAPSHOTS {
        r.capture(credential(100, Some(200), None)).unwrap();
    }
    assert_eq!(
        r.capture(credential(100, Some(200), None)),
        Err(Loss::OwnerSnapshotOverflow)
    );
}

#[test]
fn framing_round_trip_preserves_full_canonical_envelope() {
    let input = reduced_bytes();
    let c = decode(&input).unwrap();
    let e = recorded(100, 200);
    let bytes = encode_frame(&e).unwrap();
    let reread = decode_frame(&bytes).unwrap();
    validate_envelope(&reread, &input, Some(&c)).unwrap();
    assert_eq!(encode_frame(&reread).unwrap(), bytes);
}

#[test]
fn framing_rejects_foreign_tag_length_trailing_and_oversize() {
    let frame = encode_frame(&recorded(100, 200)).unwrap();
    let foreign = String::from_utf8(frame.clone())
        .unwrap()
        .replace(FRAME_TAG, "NORTHSTAR_DIRECT_CASE_V1");
    assert!(decode_frame(foreign.as_bytes()).is_err());
    let mut trailing = frame.clone();
    trailing.extend_from_slice(b"x");
    assert!(decode_frame(&trailing).is_err());
    let mut truncated = frame;
    truncated.pop();
    assert!(decode_frame(&truncated).is_err());
    assert!(matches!(
        decode_frame(&vec![0; MAX_FRAME + 1]),
        Err(Rejection::TooLarge)
    ));
}

#[test]
fn framing_rejects_noncanonical_json_even_with_correct_length() {
    let e = recorded(100, 200);
    let payload = String::from_utf8(serde_json::to_vec(&e).unwrap())
        .unwrap()
        .replacen("\"schema\":", "\"schema\" :", 1);
    let frame = format!("\x1e{FRAME_TAG} {}\n{payload}\n\x1eEND\n", payload.len());
    assert!(matches!(
        decode_frame(frame.as_bytes()),
        Err(Rejection::Encoding)
    ));
}

#[test]
fn graph_reader_rejects_duplicate_sequence_or_forged_first_seen_locus() {
    let c = input_case();
    let input = reduced_bytes();
    let mut e = recorded(100, 200);
    e.facts.0[1].seq = 1;
    assert_eq!(
        validate_envelope(&e, &input, Some(&c)),
        Err(Loss::NoncontiguousSequence)
    );
    let mut e = recorded(100, 200);
    e.identity_map.0[0].locus = Introduction::ArchiveCandidate;
    assert_eq!(
        validate_envelope(&e, &input, Some(&c)),
        Err(Loss::NoncanonicalIdentity)
    );
}

#[test]
fn graph_reader_mirrors_per_item_io_bounds() {
    let input = reduced_bytes();
    let c = decode(&input).unwrap();
    let mut r = Recorder::new(&c);
    r.capture(Fact::Native(NativeFact::Flush(FlushCall {
        item_ordinal: 0,
        result: IoResult::Ok,
    })))
    .unwrap();
    let mut e = r.finish(Execution::Complete).unwrap();
    let mut duplicate = e.facts.0[0].clone();
    duplicate.seq = 2;
    e.facts.0.push(duplicate);
    assert_eq!(
        validate_envelope(&e, &input, Some(&c)),
        Err(Loss::FactOverflow)
    );
    let mut r = Recorder::new(&c);
    for _ in 0..32 {
        r.capture(Fact::Native(NativeFact::Write(WriteCall {
            item_ordinal: 0,
            offered_len: 1,
            offered_sha256: sha256(b"x"),
            accepted_bytes_hex: Bytes::of(b"x").unwrap(),
            result: IoResult::Ok,
        })))
        .unwrap();
    }
    let mut e = r.finish(Execution::Complete).unwrap();
    let mut extra = e.facts.0[0].clone();
    extra.seq = 33;
    e.facts.0.push(extra);
    assert_eq!(
        validate_envelope(&e, &input, Some(&c)),
        Err(Loss::FactOverflow)
    );
}

#[test]
fn graph_reader_rejects_unanchored_fixed_and_noncanonical_opaque_labels() {
    let c = input_case();
    let input = reduced_bytes();
    for replacement in [
        IdentityLabel::Fixed(FixedIdentity {
            uuid: Id(Uuid::from_u128(999)),
        }),
        IdentityLabel::Opaque(OpaqueIdentity { ordinal: 9 }),
    ] {
        let mut e = recorded(100, 200);
        let Fact::Credential(first) = &mut e.facts.0[0].fact else {
            unreachable!()
        };
        first.snapshot.attempt = EvidenceId::Encoded(replacement);
        assert_eq!(
            validate_envelope(&e, &input, Some(&c)),
            Err(Loss::NoncanonicalIdentity)
        );
    }
}

#[test]
fn selected_complete_is_independent_of_missing_live_publication() {
    let selected: SelectionStatus =
        serde_json::from_str(r#"{"kind":"Complete","data":{}}"#).unwrap();
    let not_started: PublicationKnowledge =
        serde_json::from_str(r#"{"kind":"NotStarted","data":{}}"#).unwrap();
    assert!(matches!(selected, SelectionStatus::Complete(_)));
    assert!(matches!(not_started, PublicationKnowledge::NotStarted(_)));
    // They are deliberately different types. No conversion to a domain
    // completion decision exists, and missing joins remain representable.
    assert!(
        serde_json::from_str::<PublicationKnowledge>(r#"{"kind":"Complete","data":{}}"#).is_err()
    );
}

#[test]
fn frame_cap_includes_actual_encoded_observations_without_truncation() {
    let mut r = Recorder::new(&input_case());
    for n in 0..4 {
        r.capture(Fact::Bosh(BoshFact::Receiver(BoshResponseReceiver {
            session: id(3),
            connection: Nullable::Value(id(2)),
            owner_ordinal: 0,
            rid: 22,
            receiver_ordinal: n,
            result: ResponseResult::Received(BodyBytes {
                body_hex: Bytes::of(&vec![b'x'; 16384]).unwrap(),
            }),
        })))
        .unwrap();
    }
    let e = r.finish(Execution::Complete).unwrap();
    assert_eq!(encode_frame(&e), Err(Loss::FrameOverflow));
    assert_eq!(e.facts.len(), 4);
}

#[test]
fn replay_canonical_semantics_accepts_exact_nul_and_non_utf8_bytes() {
    let mut case = replay_queued_auth_case();
    let Composition::ReplayMixQueuedAuth(c) = &mut case.composition else {
        unreachable!()
    };
    let bytes = [
        0, 0, 0, 0, 0, 0, 0, 7, b'm', b'e', b's', b's', b'a', b'g', b'e', 0x80, 0xff,
    ];
    c.mix.foreground.ingress.identity = Nullable::Value(ReplayIdentityInput {
        client_id: text("binary-replay"),
        canonical_semantics: Bytes::of(&bytes).unwrap(),
    });
    let raw = serde_json::to_vec(&case).unwrap();
    let decoded = decode(&raw).unwrap();
    assert_eq!(decoded.case(), &case);
    let Composition::ReplayMixQueuedAuth(c) = &decoded.case().composition else {
        unreachable!()
    };
    assert_eq!(
        c.mix
            .foreground
            .ingress
            .identity
            .get()
            .unwrap()
            .canonical_semantics
            .as_hex(),
        "00000000000000076d65737361676580ff"
    );
    assert_eq!(
        Bytes::<4096>::of(&vec![0; 4096]).unwrap().as_hex().len(),
        8192
    );
}

#[test]
fn replay_canonical_semantics_rejects_malformed_hex_without_repair() {
    let baseline = serde_json::to_value(replay_queued_auth_case()).unwrap();
    let pointer = "/composition/data/mix/foreground/ingress/identity/canonical_semantics";
    assert!(baseline.pointer(pointer).unwrap().is_string());
    for invalid in [
        "0".to_owned(),
        "AF".to_owned(),
        "0g".to_owned(),
        "00 ".to_owned(),
        "\0".to_owned(),
        "00".repeat(4097),
    ] {
        let mut changed = baseline.clone();
        *changed.pointer_mut(pointer).unwrap() = serde_json::Value::String(invalid);
        assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    assert!(decode(&serde_json::to_vec(&baseline).unwrap()).is_ok());
}
