//! Build eligible archive candidates without sampling account preferences.

use northstar_message_application::messaging::{ArchiveCandidate, ArchiveDirection, ArchiveWrite};

pub(crate) fn archive_candidate(
    projection: ArchiveWrite<'_>,
    direction: ArchiveDirection,
    eligible: bool,
) -> Option<ArchiveCandidate<'_>> {
    eligible.then_some(ArchiveCandidate {
        projection,
        direction,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federated_message::route_inbound_message;
    use crate::test_support::{Event, Host, Session, State, ACTOR, RECIPIENT, SENDER, TARGET};
    use northstar_stream::transport::Action;
    use roxmltree::Document;
    use std::sync::atomic::Ordering;

    async fn client_message(session: &Session, xml: &str) -> Action {
        let doc = Document::parse(xml).unwrap();
        crate::messaging::message(session, doc.root_element(), xml, xml)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn local_and_federated_delivery_pass_candidate_owner_direction_and_peer() {
        let session = Session::new(State::default(), false);
        let local = format!(
            "<message from='{SENDER}' to='{TARGET}' type='chat'><body>local</body></message>"
        );
        assert!(matches!(
            client_message(&session, &local).await,
            Action::None
        ));
        let local_commit = session
            .host
            .state
            .committed
            .lock()
            .unwrap()
            .clone()
            .unwrap();
        assert_eq!(
            local_commit.candidates,
            [
                (ArchiveDirection::Outbound, ACTOR, TARGET.to_owned()),
                (ArchiveDirection::Inbound, RECIPIENT, SENDER.to_owned()),
            ]
        );

        let remote = "carol@remote.test/Phone";
        // A policy denial affects the transaction result, while the stanza
        // still supplies the eligible sender or recipient candidate.
        let outbound_session = Session::new(
            State {
                archive: false,
                ..State::default()
            },
            false,
        );
        let outbound = format!(
            "<message from='{SENDER}' to='{remote}' type='chat'><body>outbound</body></message>"
        );
        assert!(matches!(
            client_message(&outbound_session, &outbound).await,
            Action::None
        ));
        let events = outbound_session.host.state.events();
        assert!(events.contains(&Event::OutboundCommit(vec![(
            ArchiveDirection::Outbound,
            ACTOR,
            remote.to_owned(),
        )])));
        assert!(events.contains(&Event::WakeOutbox));

        let host = Host::new(State {
            archive: false,
            ..State::default()
        });
        let inbound = format!(
            "<message from='{remote}' to='{TARGET}' type='chat'><body>inbound</body></message>"
        );
        let doc = Document::parse(&inbound).unwrap();
        assert!(route_inbound_message(
            &host,
            doc.root_element(),
            &inbound,
            remote,
            TARGET,
            "remote.test"
        )
        .await
        .unwrap()
        .is_none());
        let inbound_commit = host.state.committed.lock().unwrap().clone().unwrap();
        assert_eq!(
            inbound_commit.candidates,
            [(ArchiveDirection::Inbound, RECIPIENT, remote.to_owned())]
        );
        assert!(inbound_commit.archives.is_empty());
        assert!(!host
            .state
            .events()
            .iter()
            .any(|event| matches!(event, Event::History(_))));
    }

    #[tokio::test]
    async fn local_archive_candidates_respect_hints_and_encryption() {
        let signal = "<composing xmlns='http://jabber.org/protocol/chatstates'/>";
        for (payload, hint, requires_encryption, expects_delivery_row, expects_archives) in [
            (signal, "", false, false, false),
            (signal, "<store xmlns='urn:xmpp:hints'/>", false, true, true),
            (
                "<body>chat</body>",
                "<no-store xmlns='urn:xmpp:hints'/>",
                false,
                false,
                false,
            ),
            (
                "<body>chat</body>",
                "<no-permanent-store xmlns='urn:xmpp:hints'/>",
                false,
                true,
                false,
            ),
            ("<body>chat</body>", "", true, false, false),
            (
                "<encrypted xmlns='urn:xmpp:omemo:2'>ciphertext</encrypted>",
                "",
                true,
                true,
                true,
            ),
        ] {
            let session = Session::new(
                State {
                    archive_requires_encryption: requires_encryption,
                    ..State::default()
                },
                false,
            );
            let xml = format!(
                "<message from='{SENDER}' to='{TARGET}' type='chat'>{payload}{hint}</message>"
            );
            assert!(matches!(client_message(&session, &xml).await, Action::None));
            let committed = session.host.state.committed.lock().unwrap();
            assert_eq!(
                committed.is_some(),
                expects_delivery_row,
                "{payload} {hint}"
            );
            if let Some(committed) = committed.as_ref() {
                assert_eq!(
                    committed.candidates.len(),
                    if expects_archives { 2 } else { 0 },
                    "{payload} {hint}"
                );
            }
            assert!(!session
                .host
                .state
                .events()
                .iter()
                .any(|event| matches!(event, Event::History(_))));
        }
    }

    #[tokio::test]
    async fn volatile_local_delivery_routes_before_history_and_keeps_acceptance_on_failure() {
        let session = Session::new(
            State {
                history_error: true,
                ..State::default()
            },
            false,
        );
        let target = format!("{TARGET}/phone");
        let xml = format!(
            "<message from='{SENDER}' to='{target}' type='headline'><body>notice</body></message>"
        );
        assert!(matches!(client_message(&session, &xml).await, Action::None));
        let events = session.host.state.events();
        let acceptance = events
            .iter()
            .rposition(|event| *event == Event::LocalAccepted(false))
            .unwrap();
        let history = events
            .iter()
            .position(|event| {
                *event
                    == Event::History(vec![
                        (ArchiveDirection::Outbound, ACTOR, target.clone()),
                        (ArchiveDirection::Inbound, RECIPIENT, SENDER.to_owned()),
                    ])
            })
            .unwrap();
        assert!(acceptance < history);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::History(_)))
                .count(),
            1
        );
        assert!(!events
            .iter()
            .any(|event| matches!(event, Event::Commit(..))));
        assert_eq!(session.host.counters[3].load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn outbound_retraction_bypasses_ordinary_archive_admission() {
        let session = Session::new(
            State {
                archive: false,
                archive_requires_encryption: true,
                expect_retraction: true,
                ..State::default()
            },
            false,
        );
        let xml = format!("<message from='{SENDER}' to='carol@remote.test' type='chat' id='action'><retract xmlns='urn:xmpp:message-retract:1' id='original'/><no-permanent-store xmlns='urn:xmpp:hints'/></message>");
        assert!(matches!(client_message(&session, &xml).await, Action::None));
        let events = session.host.state.events();
        assert!(events.contains(&Event::Retraction(vec![ACTOR])));
        assert!(events.contains(&Event::WakeOutbox));
        assert!(!events
            .iter()
            .any(|event| matches!(event, Event::OutboundCommit(_) | Event::History(_))));
    }
}
