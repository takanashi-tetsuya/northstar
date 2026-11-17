use super::actor_fixture::Harness;
use super::actor_host::{Event, ItemFacts, CONNECTION};
use northstar_auth_application::authentication::publication::{Knowledge, Transport};
use northstar_delivery_core::bosh_ownership::OperationKind;
use northstar_stream::auth_publication::fixture::fixture_control;
use northstar_stream::auth_publication::{AuthReplies, OutboundAuthPublication};
use northstar_stream::outbound::{OutboundItem, SmUnackedStanza};
use northstar_stream::resume::ResumePayload;
use northstar_stream::transport::Action;
use std::collections::VecDeque;
use uuid::Uuid;

const CONTROL: &str = "<success xmlns='urn:xmpp:sasl:2'/>";
const FEATURES: &str = "<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>";
const REPLAY: &str = "<message xmlns='jabber:client' id='resume-original'/>";

#[tokio::test(start_paused = true)]
async fn activation_validates_before_recording_and_queues_only_the_first_control_holder() {
    for label in [
        "valid activation",
        "foreign connection",
        "changed first control",
        "recording already started",
        "stanza record rejected",
    ] {
        let mut harness = Harness::new(0);
        harness.queue(OutboundItem::plain("<presence id='prefix'/>".to_owned()));
        let prefix = ItemFacts::new(&harness.actor.output[0]);
        let connection = if label == "foreign connection" {
            Uuid::from_u128(9201)
        } else {
            CONNECTION
        };
        let (holder, observation) = fixture_control(CONTROL, connection);
        let joins = holder.join_observation();
        let sealed = joins.snapshot().introduced;
        assert!(sealed.is_some(), "{label}");
        if label == "recording already started" {
            holder.recording().unwrap();
        }
        *harness.host.reject_stanza_record.lock().unwrap() = label == "stanza record rejected";
        let control = if label == "changed first control" {
            "<success xmlns='urn:xmpp:sasl:2' changed='true'/>"
        } else {
            CONTROL
        };
        harness.host.trace.clear();
        let operation = harness
            .actor
            .begin_ownership_operation(OperationKind::Request);
        let accepted = harness
            .actor
            .apply_action(
                Action::SendManyThenActivate(AuthReplies {
                    replies: vec![control.to_owned(), FEATURES.to_owned()],
                    holder,
                }),
                &operation,
            )
            .await;
        assert_eq!(accepted, label == "valid activation", "{label}");
        assert_eq!(ItemFacts::new(&harness.actor.output[0]), prefix, "{label}");
        let effects = harness.host.trace.effects();
        let expected = match label {
            "valid activation" => vec![
                Event::RecordStanza(CONTROL.to_owned()),
                Event::RecordStanza(FEATURES.to_owned()),
                Event::Session("post action"),
            ],
            "stanza record rejected" => vec![Event::RecordStanza(CONTROL.to_owned())],
            _ => vec![],
        };
        assert_eq!(effects, expected, "{label}");
        assert_eq!(
            observation.snapshot().publication,
            Knowledge::NotStarted,
            "{label}"
        );
        assert!(joins.snapshot().transferred.is_none(), "{label}");
        if accepted {
            assert_eq!(harness.actor.output.len(), 3, "{label}");
            assert_eq!(harness.actor.output[1].stanza, CONTROL, "{label}");
            assert_eq!(harness.actor.output[2].stanza, FEATURES, "{label}");
            assert_eq!(
                harness
                    .actor
                    .output
                    .iter()
                    .map(OutboundItem::is_bosh_auth_control)
                    .collect::<Vec<_>>(),
                [false, true, false],
                "{label}"
            );
            assert_eq!(
                harness.actor.output[1]
                    .auth_publication()
                    .unwrap()
                    .join_observation()
                    .snapshot()
                    .introduced,
                sealed,
                "{label}: the queued holder must be the sealed first control"
            );
            assert_eq!(
                observation.snapshot().transport,
                Transport::Recording,
                "{label}"
            );
            assert!(observation.snapshot().terminal.is_none(), "{label}");
        } else {
            assert_eq!(harness.actor.output.len(), 1, "{label}");
            let expected = if matches!(
                label,
                "recording already started" | "stanza record rejected"
            ) {
                Transport::Recording
            } else {
                Transport::NotStarted
            };
            assert_eq!(observation.snapshot().transport, expected, "{label}");
        }
        assert_eq!(
            harness.actor.output_bytes,
            harness
                .actor
                .output
                .iter()
                .map(|item| item.stanza.len())
                .sum::<usize>(),
            "{label}"
        );
        assert!(harness.actor.replay.is_empty(), "{label}");
        harness.finish().await;
    }
}

#[tokio::test(start_paused = true)]
async fn resume_validates_its_control_then_admits_the_complete_batch_with_the_same_holder() {
    for label in [
        "authenticated resume",
        "resume without activation",
        "foreign connection",
        "changed control",
        "recording already started",
        "activation without holder",
        "holder without activation",
        "stanza record rejected",
        "stanza capacity exhausted",
        "byte capacity exhausted",
    ] {
        let mut harness = Harness::new(0);
        harness.queue(OutboundItem::plain("<presence id='prefix'/>".to_owned()));
        let prefix = ItemFacts::new(&harness.actor.output[0]);
        let activate = !matches!(
            label,
            "resume without activation" | "holder without activation"
        );
        let (holder, observation) = fixture_control(
            CONTROL,
            if label == "foreign connection" {
                Uuid::from_u128(9202)
            } else {
                CONNECTION
            },
        );
        let joins = holder.join_observation();
        let sealed = joins.snapshot().introduced;
        assert!(sealed.is_some(), "{label}");
        if label == "recording already started" {
            holder.recording().unwrap();
        }
        let source = VecDeque::from([SmUnackedStanza::plain(REPLAY.to_owned())]);
        let mut payload = ResumePayload::from_sm_unacked(
            &harness.actor.sm_memory_governor,
            CONTROL.to_owned(),
            vec![FEATURES.to_owned()],
            &source,
            activate,
        )
        .unwrap();
        if !matches!(
            label,
            "activation without holder" | "resume without activation"
        ) {
            payload.auth_publication = Some(holder);
        }
        if label == "changed control" {
            payload.control.push(' ');
        }
        if label == "stanza capacity exhausted" {
            harness.actor.max_output_stanzas = 3;
        }
        if label == "byte capacity exhausted" {
            harness.actor.max_output_bytes =
                prefix.stanza.len() + CONTROL.len() + FEATURES.len() + REPLAY.len() - 1;
        }
        *harness.host.reject_stanza_record.lock().unwrap() = label == "stanza record rejected";
        harness.host.trace.clear();
        let operation = harness
            .actor
            .begin_ownership_operation(OperationKind::Request);
        let accepted = harness
            .actor
            .apply_action(Action::Resume(payload), &operation)
            .await;
        assert_eq!(
            accepted,
            matches!(label, "authenticated resume" | "resume without activation"),
            "{label}"
        );
        assert_eq!(ItemFacts::new(&harness.actor.output[0]), prefix, "{label}");
        let records = matches!(
            label,
            "authenticated resume"
                | "resume without activation"
                | "stanza record rejected"
                | "stanza capacity exhausted"
                | "byte capacity exhausted"
        );
        let mut expected = vec![];
        if records {
            expected.push(Event::RecordStanza(CONTROL.to_owned()));
            if label != "stanza record rejected" {
                expected.push(Event::RecordStanza(FEATURES.to_owned()));
            }
        }
        if accepted {
            expected.extend([Event::Session("replayed"), Event::Session("post action")]);
        }
        assert_eq!(harness.host.trace.effects(), expected, "{label}");
        assert_eq!(
            observation.snapshot().publication,
            Knowledge::NotStarted,
            "{label}"
        );
        assert!(joins.snapshot().transferred.is_none(), "{label}");
        if accepted {
            assert_eq!(
                harness
                    .actor
                    .output
                    .iter()
                    .map(|item| item.stanza.as_str())
                    .collect::<Vec<_>>(),
                [prefix.stanza.as_str(), CONTROL, FEATURES, REPLAY],
                "{label}"
            );
            assert_eq!(
                harness
                    .actor
                    .output
                    .iter()
                    .map(OutboundItem::is_bosh_auth_control)
                    .collect::<Vec<_>>(),
                [false, activate, false, false],
                "{label}"
            );
            if activate {
                assert_eq!(
                    harness.actor.output[1]
                        .auth_publication()
                        .unwrap()
                        .join_observation()
                        .snapshot()
                        .introduced,
                    sealed,
                    "{label}"
                );
                assert_eq!(
                    observation.snapshot().transport,
                    Transport::Recording,
                    "{label}"
                );
            }
            assert!(
                harness
                    .actor
                    .output
                    .iter()
                    .skip(1)
                    .all(|item| item.transient_sm_capacity.is_some()),
                "{label}"
            );
        } else {
            assert_eq!(
                harness.actor.output.len(),
                1,
                "{label}: batch admission must be atomic"
            );
            let recording = matches!(
                label,
                "recording already started"
                    | "stanza record rejected"
                    | "stanza capacity exhausted"
                    | "byte capacity exhausted"
            );
            assert_eq!(
                observation.snapshot().transport,
                if recording {
                    Transport::Recording
                } else {
                    Transport::NotStarted
                },
                "{label}"
            );
        }
        assert_eq!(
            harness.actor.output_bytes,
            harness
                .actor
                .output
                .iter()
                .map(|item| item.stanza.len())
                .sum::<usize>(),
            "{label}"
        );
        assert!(harness.actor.replay.is_empty(), "{label}");
        harness.finish().await;
    }
}
