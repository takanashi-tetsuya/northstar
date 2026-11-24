use super::*;
use northstar_stream::transport::Action;
use northstar_time::{DateTime, Utc};
use roxmltree::Document;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

struct BoundSession(ExtDiscoService);

impl BoundSession {
    fn new() -> Self {
        Self(ExtDiscoService::new(
            "example.test".to_owned(),
            None,
            Some(("turn.example.test".to_owned(), 3478)),
            Some("fixed coturn test secret".to_owned()),
            3_600,
            4,
        ))
    }
}

impl ExtDiscoSession for BoundSession {
    type Action = Action;

    fn extdisco_service(&self) -> &ExtDiscoService {
        &self.0
    }

    fn authenticated_username(&self) -> Option<&str> {
        Some("alice")
    }

    fn full_jid(&self) -> Option<&str> {
        Some("alice@example.test/device")
    }

    fn peer_ip(&self) -> IpAddr {
        "192.0.2.10".parse().unwrap()
    }
}

#[derive(Default)]
struct FixedEvents(AtomicUsize);

impl MessageEventSource for FixedEvents {
    fn now(&self) -> DateTime<Utc> {
        self.0.fetch_add(1, Ordering::Relaxed);
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn new_stanza_id(&self) -> Uuid {
        panic!("extdisco does not allocate stanza IDs")
    }
}

fn sent_xml(response: Result<Action>) -> String {
    let Action::Send(xml) = response.unwrap() else {
        panic!("expected an IQ reply");
    };
    xml
}

#[test]
fn out_of_scope_targets_keep_their_exact_error_xml() {
    let session = BoundSession::new();
    let events = FixedEvents::default();
    let expected = concat!(
        "<iq xmlns='jabber:client' type='error' from='example.test' id='scope'>",
        "<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>",
        "</error></iq>"
    );
    let listing = Document::parse(concat!(
        "<iq type='get' id='scope' to='elsewhere.test'>",
        "<services xmlns='urn:xmpp:extdisco:2'/></iq>"
    ))
    .unwrap();
    let iq = listing.root_element();
    assert_eq!(
        sent_xml(external_services(
            &session,
            "scope",
            iq,
            iq.first_element_child().unwrap(),
        )),
        expected
    );

    let issuance = Document::parse(concat!(
        "<iq type='get' id='scope' to='alice@example.test/device'>",
        "<credentials xmlns='urn:xmpp:extdisco:2'/></iq>"
    ))
    .unwrap();
    let iq = issuance.root_element();
    assert_eq!(
        sent_xml(external_credentials(
            &session,
            "scope",
            iq,
            iq.first_element_child().unwrap(),
            &events,
        )),
        expected
    );
}

#[test]
fn unavailable_selection_keeps_its_exact_error_xml() {
    let session = BoundSession::new();
    let events = FixedEvents::default();
    let request = Document::parse(concat!(
        "<iq type='get' id='missing' to='example.test'><credentials xmlns='urn:xmpp:extdisco:2'>",
        "<service host='turn.example.test' type='turn' port='5349'/></credentials></iq>"
    ))
    .unwrap();
    let iq = request.root_element();
    assert_eq!(
        sent_xml(external_credentials(
            &session,
            "missing",
            iq,
            iq.first_element_child().unwrap(),
            &events,
        )),
        concat!(
            "<iq xmlns='jabber:client' type='error' from='example.test' id='missing'>",
            "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>",
            "</error></iq>"
        )
    );
}

#[test]
fn credential_reply_uses_one_sample_of_the_supplied_wall_clock() {
    let session = BoundSession::new();
    let events = FixedEvents::default();
    let request = Document::parse(concat!(
        "<iq type='get' id='turn'><credentials xmlns='urn:xmpp:extdisco:2'>",
        "<service host='turn.example.test' type='turn' transport='udp'/></credentials></iq>"
    ))
    .unwrap();
    let iq = request.root_element();
    let response = sent_xml(external_credentials(
        &session,
        "turn",
        iq,
        iq.first_element_child().unwrap(),
        &events,
    ));
    assert!(response.contains("expires='2023-11-14T23:13:20Z'"));
    assert_eq!(events.0.load(Ordering::Relaxed), 1);
}
