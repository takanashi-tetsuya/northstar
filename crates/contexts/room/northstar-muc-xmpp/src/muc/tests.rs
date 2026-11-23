use self::host::Host;
use super::*;
use dashmap::DashMap;
use northstar_room_application::muc_service::{discussion::MucDiscussionSlot, MucService};
use northstar_session_core::JoinedMucMembership;
use northstar_xml_builder::message_policy::encrypted_archive_stanza;
use std::future::Future;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll, Waker};
use uuid::Uuid;

mod host;
mod repository;

const ROOM_ID: Uuid = Uuid::from_u128(12);
const ROOM_EPOCH: Uuid = Uuid::from_u128(13);
const USER_ID: Uuid = Uuid::from_u128(14);
const OCCUPANT_EPOCH: Uuid = Uuid::from_u128(15);
const CONNECTION_ID: Uuid = Uuid::from_u128(16);
const MESSAGE_ID: Uuid = Uuid::from_u128(17);
const ROOM_JID: &str = "room@conference.local.test";
const SENDER: &str = "alice@local.test/phone";
const REMOTE_SENDER: &str = "alice@remote.test/phone";

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Stage(MucFrameStage),
    Principal,
    ProtocolPolicy,
    User,
    Validate,
    Room,
    Affiliation,
    Operation,
    Observed(MucDiscussion),
    Legacy(MucDiscussion),
    Cluster(String, String, Option<String>),
    Recipients,
    Privacy,
    PrivateRoute(northstar_room_core::occupancy::MucOccupantRoute, bool),
    Deliver(String, String),
    Subject(String),
    ClusterSubject(Uuid, String),
    MessageLookup,
    Retraction(String),
    Target,
    Renew,
    Wake(Uuid),
}

#[derive(Clone, Copy)]
enum Admission {
    Stored,
    Unarchived,
    Replay,
    Unauthorized,
    Stale,
}

struct State {
    admission: Admission,
    events: Mutex<Vec<Event>>,
    logging_enabled: AtomicBool,
    cluster_pending: AtomicBool,
    delivery_pending: AtomicBool,
    counters: [AtomicU64; 7],
}

impl State {
    fn record(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    fn outcome(&self, command: &MucDiscussion) -> MucDiscussionAdmission {
        match self.admission {
            Admission::Stored => MucDiscussionAdmission::Stored {
                id: command.id,
                archived: command.archive_eligible,
            },
            Admission::Unarchived => MucDiscussionAdmission::Stored {
                id: command.id,
                archived: false,
            },
            Admission::Replay => MucDiscussionAdmission::Replay(MESSAGE_ID),
            Admission::Unauthorized => MucDiscussionAdmission::Unauthorized,
            Admission::Stale => MucDiscussionAdmission::Stale,
        }
    }
}

struct Session {
    host: Host,
    rooms: DashMap<String, JoinedMucMembership>,
    authenticated: bool,
    active_frame: bool,
    slot: MucDiscussionSlot,
    observation: Mutex<Option<discussion_owner::Observation>>,
}

impl Session {
    fn new(admission: Admission, active_frame: bool) -> Self {
        let state = Arc::new(State {
            admission,
            events: Mutex::new(Vec::new()),
            logging_enabled: AtomicBool::new(true),
            cluster_pending: AtomicBool::new(false),
            delivery_pending: AtomicBool::new(false),
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
        });
        let service = MucService::new_with_time_sources(
            repository::Repository(Arc::clone(&state)),
            "local.test",
            time_sources::test_sources(),
        );
        let rooms = DashMap::new();
        rooms.insert(
            ROOM_JID.to_owned(),
            JoinedMucMembership::new("Alice".to_owned(), OCCUPANT_EPOCH),
        );
        Self {
            host: Host {
                state,
                service,
                clustered: false,
                federated: false,
            },
            rooms,
            authenticated: true,
            active_frame,
            slot: MucDiscussionSlot::default(),
            observation: Mutex::new(None),
        }
    }
}

impl MucSession for Session {
    type Host = Host;
    fn host(&self) -> &Host {
        &self.host
    }
    fn user(&self) -> Option<MucSessionUser<'_>> {
        self.host.state.record(Event::User);
        self.authenticated.then_some(MucSessionUser {
            id: USER_ID,
            username: "alice",
        })
    }
    fn full_jid(&self) -> Option<&str> {
        self.host.state.record(Event::Principal);
        self.authenticated.then_some(SENDER)
    }
    fn connection_id(&self) -> Uuid {
        CONNECTION_ID
    }
    fn sm_db_id(&self) -> Option<Uuid> {
        None
    }
    fn joined_rooms(&self) -> &DashMap<String, JoinedMucMembership> {
        &self.rooms
    }
    fn outbound(&self) -> &northstar_stream::outbound::OutboundSender {
        panic!("discussion must use the fanout host port")
    }
    fn enter_frame_stage(&self, stage: MucFrameStage) {
        self.host.state.record(Event::Stage(stage));
    }
    fn muc_discussion_operation(
        &self,
        prepared: &discussion_owner::PreparedDiscussion,
    ) -> Result<Option<discussion_owner::Observation>, discussion_owner::Rejected> {
        self.host.state.record(Event::Operation);
        if !self.active_frame {
            return Ok(None);
        }
        let observation = self.slot.register(prepared)?;
        *self.observation.lock().unwrap() = Some(observation.clone());
        Ok(Some(observation))
    }
}

fn room() -> MucRoom {
    MucRoom {
        id: ROOM_ID,
        room_epoch: ROOM_EPOCH,
        config_version: 1,
        localpart: "room".to_owned(),
        title: None,
        description: None,
        persistent: false,
        members_only: false,
        public: false,
        moderated: false,
        non_anonymous: false,
        max_occupants: 10,
        subject: None,
        subject_changed_at: None,
        allow_subject_change: true,
        allow_invites: false,
        allow_private_messages: false,
        logging_enabled: true,
        allow_registration: false,
        password_hash: None,
        occupant_id_secret: vec![7; 32],
        configuration_owner_jid: None,
        configuration_expires_at: None,
    }
}

fn occupant(nick: &str, full_jid: &str) -> Occupant<Host> {
    northstar_room_core::occupancy::MucOccupant {
        full_jid: full_jid.to_owned(),
        room_jid: ROOM_JID.to_owned(),
        nick: nick.to_owned(),
        endpoint: northstar_room_core::occupancy::MucOccupantEndpoint::Federated {
            authenticated_domain: "local.test".to_owned(),
            connection_id: CONNECTION_ID,
        },
        affiliation: "member".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: false,
        occupant_id: "occupant-alice".to_owned(),
        cluster_epoch: OCCUPANT_EPOCH,
        connection_id: CONNECTION_ID,
        sm_session_id: None,
        payload: String::new(),
    }
}

fn cluster_target() -> northstar_room_core::ClusterMucOccupancyTarget {
    northstar_room_core::ClusterMucOccupancyTarget {
        room_id: ROOM_ID,
        room_epoch: ROOM_EPOCH,
        occupant_incarnation: OCCUPANT_EPOCH,
        occupancy_epoch: 1,
        full_jid: SENDER.to_owned(),
        nick: "Alice".to_owned(),
        connection_uuid: CONNECTION_ID,
        connection_epoch: 2,
    }
}

fn input(encrypted: bool, archive: bool) -> (MucDiscussion, String) {
    let content = if encrypted {
        "<body>fallback must stay live</body><encrypted xmlns='eu.siacs.conversations.axolotl'><header sid='7'/><payload>ciphertext</payload></encrypted>"
    } else {
        "<body>hello</body>"
    };
    let live = format!(
        "<message xmlns='jabber:client' from='{ROOM_JID}/Alice' to='{ROOM_JID}' type='groupchat'>{content}<stanza-id xmlns='urn:xmpp:sid:0' by='{ROOM_JID}' id='{MESSAGE_ID}'/></message>"
    );
    let command = MucDiscussion {
        id: MESSAGE_ID,
        room_id: ROOM_ID,
        actor_scope: "alice@local.test".to_owned(),
        origin_id: Some("original-origin".to_owned()),
        sender_jid: SENDER.to_owned(),
        nick: "Alice".to_owned(),
        stanza: if encrypted && archive {
            encrypted_archive_stanza(&live)
        } else {
            live.clone()
        },
        encrypted,
        archive_eligible: archive,
        unarchived_stanza_bytes: (encrypted && archive).then_some(live.len()),
        retention_days: 7,
        authority: MucActorAuthority {
            clustered: false,
            expected_room_epoch: ROOM_EPOCH,
            principal: MucActorPrincipal::Local {
                user_id: USER_ID,
                local_domain: "local.test".to_owned(),
            },
            actor_scope: "alice@local.test".to_owned(),
            full_jid: SENDER.to_owned(),
            nick: "Alice".to_owned(),
            occupant_incarnation: OCCUPANT_EPOCH,
            connection_uuid: CONNECTION_ID,
            expected_role: "participant".to_owned(),
            expected_affiliation: "member".to_owned(),
            cluster_target: None,
        },
    };
    (command, live)
}

fn envelope(
    session: &Session,
    command: MucDiscussion,
    live: String,
) -> Result<PreparedMucDiscussion> {
    PreparedMucDiscussion::new(
        session.host.service.prepare_muc_discussion(command),
        &room(),
        ROOM_JID.to_owned(),
        live,
    )
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("fixture unexpectedly pending"),
    }
}

fn pending<F: Future>(future: std::pin::Pin<&mut F>) {
    assert!(future
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());
}

#[test]
fn discussion_envelope_preserves_live_and_archive_ownership() {
    for (label, encrypted, archive) in [
        ("plain archive", false, true),
        ("encrypted archive", true, true),
        ("encrypted without archive", true, false),
        ("plain without archive", false, false),
    ] {
        let session = Session::new(Admission::Stored, true);
        let (command, live) = input(encrypted, archive);
        let prepared = envelope(&session, command.clone(), live.clone()).unwrap();
        assert_eq!(
            prepared.prepared.command(),
            &command,
            "{label}: archive projection"
        );
        assert_eq!(prepared.live.stanza, live, "{label}: live projection");
        if encrypted && archive {
            assert!(
                !command.stanza.contains("fallback must stay live"),
                "{label}"
            );
        }
        let observation = discussion_owner::Observation::new(prepared.prepared.clone());
        let bound = prepared.bind(observation.clone()).unwrap();
        assert_eq!(bound.request.command(), &command, "{label}: bound request");
        let completion = ready(
            session
                .host
                .service
                .execute_muc_discussion_observed(&bound.request),
        )
        .unwrap();
        let accepted = bound
            .finish(completion)
            .unwrap()
            .expect("stored has a fanout permit");
        session
            .host
            .state
            .cluster_pending
            .store(true, Ordering::Relaxed);
        let mut fanout = Box::pin(accepted.fanout(&session));
        pending(fanout.as_mut());
        assert_eq!(
            observation.snapshot().fanout.stage,
            discussion_owner::FanoutStage::ClusterEntered,
            "{label}: permit consumed"
        );
        assert_eq!(
            session.host.state.events(),
            [
                Event::Observed(command.clone()),
                Event::Stage(MucFrameStage::ClusterFanout),
                Event::Cluster(ROOM_JID.to_owned(), live.clone(), Some(SENDER.to_owned())),
            ],
            "{label}: exact originating cluster envelope"
        );
        session
            .host
            .state
            .cluster_pending
            .store(false, Ordering::Relaxed);
        assert!(ready(fanout).unwrap(), "{label}");
        assert_eq!(
            &session.host.state.events()[3..],
            [
                Event::Stage(MucFrameStage::LocalFanout),
                Event::Recipients,
                Event::Privacy,
                Event::Deliver(
                    "bob@local.test/phone".to_owned(),
                    set_to(&live, "bob@local.test/phone")
                ),
            ],
            "{label}: exact originating local envelope"
        );
        assert_eq!(
            observation.snapshot().fanout.stage,
            discussion_owner::FanoutStage::Completed,
            "{label}"
        );
        assert_eq!(observation.snapshot().fanout.accepted, 1, "{label}");
    }

    for (label, change) in [
        ("room identity", 0),
        ("room epoch", 1),
        ("room localpart", 2),
        ("archive bytes", 3),
        ("live sender", 4),
        ("live destination", 5),
        ("live type", 6),
        ("stable identity", 7),
    ] {
        let session = Session::new(Admission::Stored, true);
        let (mut command, mut live) = input(false, true);
        match change {
            0 => command.room_id = Uuid::from_u128(99),
            1 => command.authority.expected_room_epoch = Uuid::from_u128(99),
            2 => {}
            3 => command.stanza.push(' '),
            4 => live = live.replace("/Alice'", "/Mallory'"),
            5 => {
                live = live.replace(
                    &format!("to='{ROOM_JID}'"),
                    "to='other@conference.local.test'",
                )
            }
            6 => live = live.replace("type='groupchat'", "type='chat'"),
            7 => live = live.replace(&MESSAGE_ID.to_string(), &Uuid::from_u128(99).to_string()),
            _ => unreachable!(),
        }
        if change >= 4 {
            command.stanza = live.clone();
        }
        let jid = if change == 2 {
            "other@conference.local.test"
        } else {
            ROOM_JID
        };
        let result = PreparedMucDiscussion::new(
            session.host.service.prepare_muc_discussion(command),
            &room(),
            jid.to_owned(),
            live,
        );
        let Err(error) = result else {
            panic!("{label}: altered envelope accepted");
        };
        let expected = if change <= 2 {
            "room projection mismatch"
        } else if change == 3 {
            "archive projection mismatch"
        } else {
            "live identity mismatch"
        };
        assert!(error.to_string().contains(expected), "{label}: {error}");
        assert!(
            session.host.state.events().is_empty(),
            "{label}: no route or repository call"
        );
    }

    let session = Session::new(Admission::Stored, true);
    let (command, live) = input(false, true);
    let mut altered = command.clone();
    altered.origin_id = Some("other invocation".to_owned());
    let other =
        discussion_owner::Observation::new(session.host.service.prepare_muc_discussion(altered));
    let Err(error) = envelope(&session, command.clone(), live.clone())
        .unwrap()
        .bind(other.clone())
    else {
        panic!("invocation binding: altered command accepted");
    };
    assert!(
        error.to_string().contains("invocation mismatch"),
        "invocation binding"
    );
    assert!(
        !other.snapshot().request_issued,
        "invocation binding: reject before issuing request"
    );
    assert!(
        session.host.state.events().is_empty(),
        "invocation binding: no I/O"
    );

    let first = envelope(&session, command.clone(), live.clone()).unwrap();
    let second = envelope(&session, command, live).unwrap();
    let first_observation = discussion_owner::Observation::new(first.prepared.clone());
    let second_observation = discussion_owner::Observation::new(second.prepared.clone());
    let first = first.bind(first_observation.clone()).unwrap();
    let second = second.bind(second_observation).unwrap();
    let completion = ready(
        session
            .host
            .service
            .execute_muc_discussion_observed(&second.request),
    )
    .unwrap();
    assert!(
        first.finish(completion).is_err(),
        "completion binding: identical IDs cannot substitute another invocation"
    );
    assert_eq!(
        first_observation.snapshot().fanout.stage,
        discussion_owner::FanoutStage::Unavailable,
        "completion binding"
    );
    assert!(
        !session
            .host
            .state
            .events()
            .iter()
            .any(|event| matches!(event, Event::Cluster(..) | Event::Deliver(..))),
        "completion binding: no effects"
    );
}

#[test]
fn discussion_reflection_uses_committed_archive_outcome() {
    for active_frame in [false, true] {
        for (logging_was_enabled, no_store, admission, has_stanza_id) in [
            (true, false, Admission::Unarchived, false),
            (false, false, Admission::Stored, true),
            (false, false, Admission::Unarchived, true),
            (true, true, Admission::Unarchived, true),
        ] {
            let session = Session::new(admission, active_frame);
            session
                .host
                .state
                .logging_enabled
                .store(logging_was_enabled, Ordering::Relaxed);
            let hint = if no_store {
                "<no-store xmlns='urn:xmpp:hints'/>"
            } else {
                ""
            };
            let raw = format!(
                "<message xmlns='jabber:client' to='{ROOM_JID}' type='groupchat'><body>hello</body><origin-id xmlns='urn:xmpp:sid:0' id='original'/>{hint}</message>"
            );
            let document = roxmltree::Document::parse(&raw).unwrap();
            let action = ready(groupchat::muc_message(
                &session,
                document.root_element(),
                &raw,
            ))
            .unwrap();
            assert!(matches!(action, MucAction::None));
            let events = session.host.state.events();
            let command = events
                .iter()
                .find_map(|event| match event {
                    Event::Observed(command) | Event::Legacy(command) => Some(command),
                    _ => None,
                })
                .unwrap();
            assert_eq!(command.archive_eligible, !no_store);
            let mut reflections = 0;
            for event in &events {
                let stanza = match event {
                    Event::Cluster(_, stanza, _) | Event::Deliver(_, stanza) => stanza,
                    _ => continue,
                };
                let document = roxmltree::Document::parse(stanza).unwrap();
                let root = document.root_element();
                assert_eq!(
                    root.children()
                        .any(|child| child.has_tag_name(("urn:xmpp:sid:0", "stanza-id"))),
                    has_stanza_id,
                );
                assert!(root
                    .children()
                    .any(|child| child.has_tag_name(("urn:xmpp:sid:0", "origin-id"))));
                assert!(root
                    .children()
                    .any(|child| child.has_tag_name(("jabber:client", "body"))));
                reflections += 1;
            }
            assert!(reflections > 1);
            if active_frame {
                let observation = session.observation.lock().unwrap();
                let discussion_owner::Knowledge::ReceiptKnown(fact) =
                    observation.as_ref().unwrap().snapshot().knowledge
                else {
                    panic!("expected acknowledged discussion commit");
                };
                let class = if matches!(admission, Admission::Stored) {
                    discussion_owner::AcceptanceClass::ArchiveAndIdentity
                } else {
                    discussion_owner::AcceptanceClass::IdentityOnly
                };
                assert_eq!(fact.fresh_class(), Some(class));
            }
        }
    }
}

#[test]
fn federated_discussion_reflection_uses_committed_archive_outcome() {
    let raw = format!(
        "<message xmlns='jabber:server' from='{REMOTE_SENDER}' to='{ROOM_JID}' type='groupchat'><body>hello</body></message>"
    );
    let document = roxmltree::Document::parse(&raw).unwrap();
    for (admission, archived) in [(Admission::Unarchived, false), (Admission::Stored, true)] {
        let mut session = Session::new(admission, false);
        session.host.federated = true;
        session
            .host
            .state
            .logging_enabled
            .store(!archived, Ordering::Relaxed);
        let reply = ready(crate::federated_muc::federated_muc_message(
            &session.host,
            "remote.test",
            CONNECTION_ID,
            document.root_element(),
            &raw,
        ))
        .unwrap();
        assert!(reply.is_none());
        let events = session.host.state.events();
        let command = events
            .iter()
            .find_map(|event| match event {
                Event::Legacy(command) => Some(command),
                _ => None,
            })
            .unwrap();
        assert!(command.archive_eligible);
        let id = command.id.to_string();
        let mut reflections = 0;
        for event in &events {
            let stanza = match event {
                Event::Cluster(_, stanza, _) | Event::Deliver(_, stanza) => stanza,
                _ => continue,
            };
            let document = roxmltree::Document::parse(stanza).unwrap();
            let has_room_id = document.root_element().children().any(|child| {
                child.has_tag_name(("urn:xmpp:sid:0", "stanza-id"))
                    && child.attribute("by") == Some(ROOM_JID)
                    && child.attribute("id") == Some(id.as_str())
            });
            assert_eq!(has_room_id, archived);
            reflections += 1;
        }
        assert!(reflections > 1);
    }
}

#[test]
fn message_stages_preserve_authority_through_fanout() {
    let raw = "<message xmlns='jabber:client' to='room@conference.local.test' type='groupchat' id='original'><body>hello</body><origin-id xmlns='urn:xmpp:sid:0' id='original-origin'/></message>";
    let document = roxmltree::Document::parse(raw).unwrap();
    let root = document.root_element();
    let mut anonymous = Session::new(Admission::Stored, true);
    anonymous.authenticated = false;
    let action = ready(groupchat::muc_message(&anonymous, root, raw)).unwrap();
    assert!(
        matches!(action, MucAction::Send(ref xml) if xml.contains("not-authorized")),
        "policy before principal"
    );
    assert_eq!(
        anonymous.host.state.events(),
        [Event::Stage(MucFrameStage::Policy), Event::Principal],
        "policy before principal"
    );

    for (label, admission, active_frame) in [
        ("observed stored", Admission::Stored, true),
        ("legacy stored", Admission::Stored, false),
        ("observed replay", Admission::Replay, true),
        ("legacy replay", Admission::Replay, false),
        ("observed unauthorized", Admission::Unauthorized, true),
        ("observed stale", Admission::Stale, true),
    ] {
        let session = Session::new(admission, active_frame);
        let held = ready(session.host.service.lock_local_room_mutation(ROOM_ID));
        let mut message = Box::pin(groupchat::muc_message(&session, root, raw));
        pending(message.as_mut());
        let before_authority = vec![
            Event::Stage(MucFrameStage::Policy),
            Event::Principal,
            Event::ProtocolPolicy,
            Event::Principal,
            Event::Validate,
            Event::User,
            Event::Room,
            Event::Affiliation,
            Event::Room,
            Event::Stage(MucFrameStage::GateWait),
        ];
        assert_eq!(
            session.host.state.events(),
            before_authority,
            "{label}: gate wait precedes authority and admission"
        );
        drop(held);
        session
            .host
            .state
            .cluster_pending
            .store(true, Ordering::Relaxed);
        let result = message
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        let events = session.host.state.events();
        assert_eq!(
            &events[before_authority.len()..before_authority.len() + 6],
            [
                Event::Stage(MucFrameStage::Authority),
                Event::Room,
                Event::Principal,
                Event::Validate,
                Event::Affiliation,
                Event::Operation,
            ],
            "{label}: authority precedes bound operation"
        );
        let admission_index = before_authority.len() + 6;
        assert_eq!(
            events[admission_index],
            Event::Stage(MucFrameStage::Admission),
            "{label}: stage immediately precedes admission"
        );
        let command = match &events[admission_index + 1] {
            Event::Observed(command) if active_frame => command,
            Event::Legacy(command) if !active_frame => command,
            event => panic!("{label}: wrong dispatch {event:?}"),
        };
        assert_eq!(command.room_id, ROOM_ID, "{label}: bound room");
        assert_eq!(
            command.origin_id.as_deref(),
            Some("original-origin"),
            "{label}: bound origin"
        );
        assert_eq!(command.sender_jid, SENDER, "{label}: bound actor");
        assert_eq!(
            command.authority.expected_room_epoch, ROOM_EPOCH,
            "{label}: bound authority"
        );
        assert_eq!(
            command.retention_days, 7,
            "{label}: original archive policy"
        );
        if matches!(admission, Admission::Stored) {
            assert!(result.is_pending(), "{label}: cluster await");
            if active_frame {
                let snapshot = session
                    .observation
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .snapshot();
                assert_eq!(
                    snapshot.fanout.stage,
                    discussion_owner::FanoutStage::ClusterEntered,
                    "{label}: typed fanout owns cluster wait"
                );
            }
            assert_eq!(
                &events[admission_index + 2..],
                [
                    Event::Stage(MucFrameStage::ClusterFanout),
                    Event::Cluster(
                        ROOM_JID.to_owned(),
                        command.stanza.clone(),
                        Some(SENDER.to_owned())
                    ),
                ],
                "{label}: original live projection reaches cluster"
            );
            let mut writer = Box::pin(session.host.service.lock_local_room_mutation(ROOM_ID));
            pending(writer.as_mut());
            session
                .host
                .state
                .delivery_pending
                .store(true, Ordering::Relaxed);
            session
                .host
                .state
                .cluster_pending
                .store(false, Ordering::Relaxed);
            pending(message.as_mut());
            pending(writer.as_mut());
            if active_frame {
                let snapshot = session
                    .observation
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .snapshot();
                assert_eq!(
                    snapshot.fanout.stage,
                    discussion_owner::FanoutStage::Delivering,
                    "{label}: typed fanout owns local wait"
                );
                assert!(
                    snapshot.fanout.endpoint_pending,
                    "{label}: actual delivery pending"
                );
                assert_eq!(
                    snapshot.fanout.accepted, 0,
                    "{label}: no premature acceptance"
                );
            }
            assert_eq!(
                session.host.state.counters[5].load(Ordering::Relaxed),
                0,
                "{label}: local delivery is still pending under authority"
            );
            session
                .host
                .state
                .delivery_pending
                .store(false, Ordering::Relaxed);
            assert!(
                matches!(ready(message).unwrap(), MucAction::None),
                "{label}: stored action"
            );
            drop(ready(writer));
            assert_eq!(
                &session.host.state.events()[events.len()..],
                [
                    Event::Stage(MucFrameStage::LocalFanout),
                    Event::Recipients,
                    Event::Privacy,
                    Event::Deliver(
                        "bob@local.test/phone".to_owned(),
                        set_to(&command.stanza, "bob@local.test/phone")
                    ),
                ],
                "{label}: fanout stages belong to originating session"
            );
            assert_eq!(
                session.host.state.counters[5].load(Ordering::Relaxed),
                1,
                "{label}: routed once after completion"
            );
            if active_frame {
                let snapshot = session
                    .observation
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .snapshot();
                assert_eq!(
                    snapshot.fanout.stage,
                    discussion_owner::FanoutStage::Completed,
                    "{label}: typed fanout completed"
                );
                assert_eq!(
                    snapshot.fanout.accepted, 1,
                    "{label}: one actual acceptance"
                );
            }
        } else {
            let Poll::Ready(result) = result else {
                panic!("{label}: refusal/replay must not await fanout");
            };
            let action = result.unwrap();
            match admission {
                Admission::Replay => assert!(matches!(action, MucAction::None), "{label}"),
                Admission::Unauthorized => assert!(
                    matches!(action, MucAction::Send(ref xml) if xml.contains("forbidden")),
                    "{label}"
                ),
                Admission::Stale => assert!(
                    matches!(action, MucAction::Send(ref xml) if xml.contains("conflict")),
                    "{label}"
                ),
                Admission::Stored | Admission::Unarchived => unreachable!(),
            }
            assert_eq!(
                events.len(),
                admission_index + 2,
                "{label}: no fanout decision effects"
            );
            assert_eq!(
                session.host.state.counters[5].load(Ordering::Relaxed),
                0,
                "{label}: no routed metric"
            );
            drop(ready(
                session.host.service.lock_local_room_mutation(ROOM_ID),
            ));
        }
    }

    for (label, retired) in [("retired frame", true), ("conflicting frame", false)] {
        let session = Session::new(Admission::Stored, true);
        if retired {
            session
                .slot
                .retire(discussion_owner::TerminalReason::Cancelled);
        } else {
            let (command, _) = input(false, true);
            session
                .slot
                .register(&session.host.service.prepare_muc_discussion(command))
                .unwrap();
        }
        assert!(
            ready(groupchat::muc_message(&session, root, raw)).is_err(),
            "{label}: registration error propagates"
        );
        let events = session.host.state.events();
        assert_eq!(
            events.last(),
            Some(&Event::Operation),
            "{label}: no legacy fallback or admission"
        );
        assert!(
            !events.iter().any(|event| matches!(
                event,
                Event::Legacy(_) | Event::Observed(_) | Event::Cluster(..)
            )),
            "{label}"
        );
        drop(ready(
            session.host.service.lock_local_room_mutation(ROOM_ID),
        ));
    }

    for (label, payload, clustered) in [
        (
            "subject admission",
            "<subject>new topic</subject>".to_owned(),
            false,
        ),
        (
            "cluster subject admission",
            "<subject>new topic</subject>".to_owned(),
            true,
        ),
        (
            "retraction admission",
            format!("<retract xmlns='urn:xmpp:message-retract:1' id='{MESSAGE_ID}'/>"),
            false,
        ),
    ] {
        let mut session = Session::new(Admission::Stored, true);
        session.host.clustered = clustered;
        let raw = format!("<message xmlns='jabber:client' to='{ROOM_JID}' type='groupchat' id='original'>{payload}</message>");
        let document = roxmltree::Document::parse(&raw).unwrap();
        let action = ready(groupchat::muc_message(
            &session,
            document.root_element(),
            &raw,
        ))
        .unwrap();
        assert!(matches!(action, MucAction::None), "{label}: admitted");
        let events = session.host.state.events();
        let index = events
            .iter()
            .position(|event| {
                matches!(
                    event,
                    Event::Subject(_) | Event::ClusterSubject(..) | Event::Retraction(_)
                )
            })
            .expect("mutation reached repository");
        assert_eq!(
            events[index - 1],
            Event::Stage(MucFrameStage::Admission),
            "{label}: admission stage immediately precedes mutation"
        );
        assert!(
            !events.contains(&Event::Operation),
            "{label}: no discussion branch"
        );
        if clustered {
            assert!(
                !events.contains(&Event::Stage(MucFrameStage::GateWait)),
                "{label}: PostgreSQL authority bypasses standalone gate"
            );
            let Event::ClusterSubject(operation, _) = &events[index] else {
                panic!("{label}: wrong mutation");
            };
            assert_eq!(
                events[index + 1..],
                [Event::Wake(*operation)],
                "{label}: exact committed operation wake"
            );
        } else {
            assert!(
                events.contains(&Event::Stage(MucFrameStage::GateWait)),
                "{label}: standalone authority"
            );
            assert_eq!(
                events[index + 1],
                Event::Stage(MucFrameStage::ClusterFanout),
                "{label}: fanout follows admission"
            );
            drop(ready(
                session.host.service.lock_local_room_mutation(ROOM_ID),
            ));
        }
    }

    let session = Session::new(Admission::Stored, true);
    session
        .host
        .state
        .cluster_pending
        .store(true, Ordering::Relaxed);
    let mut message = Box::pin(groupchat::muc_message(&session, root, raw));
    pending(message.as_mut());
    let before_cancel = session.host.state.events();
    let mut writer = Box::pin(session.host.service.lock_local_room_mutation(ROOM_ID));
    pending(writer.as_mut());
    drop(message);
    drop(ready(writer));
    assert_eq!(
        session.host.state.events(),
        before_cancel,
        "cancelled fanout releases authority without later local effects"
    );
}

#[cfg(test)]
mod addressed_delivery;
mod read_snapshots;
mod time_sources;
