#![forbid(unsafe_code)]

use northstar_xep_0215::{
    build_credentials_result, build_services_push, build_services_result, parse_iq,
    plan_credential_matches, select_services, CredentialedService, ExtDiscoError, ExtDiscoRequest,
    ExtendedField, PublicService, SecretText, ServiceAction, ServiceCredentials, ServiceHost,
    ServiceIdentity, ServiceToken, ServicesRequest, DESCRIPTOR, MAX_CREDENTIAL_REQUESTS,
    MAX_RESULT_SERVICES, NAMESPACE, XEP_ID,
};
use northstar_xep_core::{StanzaKind, XepId};
use roxmltree::Document;
use std::num::NonZeroU16;

fn token(value: &str) -> ServiceToken {
    ServiceToken::parse_service_type(value).expect("valid test token")
}

fn identity(host: &str, kind: &str, port: u16, transport: &str) -> ServiceIdentity {
    ServiceIdentity {
        host: ServiceHost::parse(host).expect("valid test host"),
        service_type: token(kind),
        port: NonZeroU16::new(port),
        transport: Some(ServiceToken::parse_transport(transport).expect("valid transport")),
    }
}

fn service(host: &str, kind: &str, port: u16, transport: &str) -> PublicService {
    PublicService::new(identity(host, kind, port, transport))
}

fn parse(xml: &str) -> Result<ExtDiscoRequest, ExtDiscoError> {
    let document = Document::parse(xml).expect("valid fixture XML");
    parse_iq(document.root_element())
}

#[test]
fn parses_all_and_selected_service_queries() {
    assert_eq!(
        parse("<iq type='get'><services xmlns='urn:xmpp:extdisco:2'/></iq>").unwrap(),
        ExtDiscoRequest::Services(ServicesRequest { service_type: None })
    );
    assert_eq!(
        parse("<iq type='get'><services xmlns='urn:xmpp:extdisco:2' type='turn'/></iq>").unwrap(),
        ExtDiscoRequest::Services(ServicesRequest {
            service_type: Some(token("turn"))
        })
    );
}

#[test]
fn parses_canonical_bounded_credential_selectors() {
    let request = parse(
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='B\u{fc}CHER.example.' type='turn'/><service host='2001:0db8::1' type='turn' port='3478' transport='tcp'/></credentials></iq>",
    )
    .unwrap();
    let ExtDiscoRequest::Credentials(request) = request else {
        panic!("expected credentials request");
    };
    assert_eq!(request.services.len(), 2);
    assert_eq!(request.services[0].host.to_string(), "b\u{fc}cher.example");
    assert_eq!(request.services[1].host.to_string(), "2001:db8::1");
    assert_eq!(request.services[1].port, NonZeroU16::new(3478));
    assert_eq!(
        request.services[1]
            .transport
            .as_ref()
            .map(ServiceToken::as_str),
        Some("tcp")
    );
}

#[test]
fn canonical_duplicate_credential_selectors_are_collapsed() {
    let request = parse(
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='B\u{fc}CHER.example.' type='turn'/><service host='xn--bcher-kva.example' type='turn'/></credentials></iq>",
    )
    .unwrap();
    let ExtDiscoRequest::Credentials(request) = request else {
        panic!("expected credentials request");
    };
    assert_eq!(request.services.len(), 1);
}

#[test]
fn rejects_wrong_carrier_type_and_ambiguous_payloads() {
    let document =
        Document::parse("<message><services xmlns='urn:xmpp:extdisco:2'/></message>").unwrap();
    assert_eq!(
        parse_iq(document.root_element()).unwrap_err(),
        ExtDiscoError::NotIq
    );
    assert_eq!(
        parse("<iq type='set'><services xmlns='urn:xmpp:extdisco:2'/></iq>").unwrap_err(),
        ExtDiscoError::WrongIqType
    );
    assert_eq!(
        parse(
            "<iq type='get'><query xmlns='urn:test'/><services xmlns='urn:xmpp:extdisco:2'/></iq>"
        )
        .unwrap_err(),
        ExtDiscoError::AmbiguousIqPayload
    );
}

#[test]
fn rejects_invalid_services_query_shapes_and_types() {
    for xml in [
        "<iq type='get'><services xmlns='urn:xmpp:extdisco:2' extra='x'/></iq>",
        "<iq type='get'><services xmlns='urn:xmpp:extdisco:2'><service/></services></iq>",
        "<iq type='get'><services xmlns='urn:xmpp:extdisco:2' type='1turn'/></iq>",
        "<iq type='get'><services xmlns='urn:xmpp:extdisco:2' type='turn:udp'/></iq>",
    ] {
        assert!(parse(xml).is_err(), "accepted {xml}");
    }
}

#[test]
fn rejects_empty_excessive_or_privilege_smuggling_credential_requests() {
    assert!(parse("<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'/></iq>").is_err());
    for xml in [
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2' extra='x'><service host='turn.example' type='turn'/></credentials></iq>",
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'>text<service host='turn.example' type='turn'/></credentials></iq>",
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' username='attacker'/></credentials></iq>",
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' password='probe'/></credentials></iq>",
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn'><x/></service></credentials></iq>",
    ] {
        assert!(parse(xml).is_err(), "accepted {xml}");
    }

    let selectors = (0..=MAX_CREDENTIAL_REQUESTS)
        .map(|index| format!("<service host='turn{index}.example' type='turn'/>"))
        .collect::<String>();
    assert_eq!(
        parse(&format!(
            "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'>{selectors}</credentials></iq>"
        ))
        .unwrap_err(),
        ExtDiscoError::CredentialRequestCount {
            limit: MAX_CREDENTIAL_REQUESTS
        }
    );
}

#[test]
fn validates_hosts_ports_transports_and_unicode_ncname_tokens() {
    assert!(ServiceHost::parse("turn.example").is_ok());
    assert!(ServiceHost::parse("192.0.2.1").is_ok());
    assert!(ServiceHost::parse("2001:db8::1").is_ok());
    assert!(ServiceHost::parse("bad_domain.example").is_err());
    assert!(ServiceToken::parse_service_type("\u{3c3}\u{3c4}\u{3bf}\u{3c5}\u{3bd}").is_ok());
    assert!(ServiceToken::parse_transport("turn:udp").is_err());
    for xml in [
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' port='0'/></credentials></iq>",
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' port='65536'/></credentials></iq>",
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='bad_domain.example' type='turn'/></credentials></iq>",
    ] {
        assert!(parse(xml).is_err(), "accepted {xml}");
    }
}

#[test]
fn discovery_selection_is_type_specific_and_preserves_configuration_order() {
    let configured = vec![
        service("stun.example", "stun", 3478, "udp"),
        service("turn.example", "turn", 3478, "udp"),
        service("turn.example", "turn", 3478, "tcp"),
    ];
    let all = select_services(&ServicesRequest { service_type: None }, &configured);
    assert_eq!(all.len(), 3);
    let turn = select_services(
        &ServicesRequest {
            service_type: Some(token("turn")),
        },
        &configured,
    );
    assert_eq!(turn.len(), 2);
    assert_eq!(turn[0].identity.transport.as_ref().unwrap().as_str(), "udp");
}

#[test]
fn credential_match_plan_is_secret_free_exact_and_deduplicated() {
    let configured = vec![
        service("turn.example", "turn", 3478, "udp"),
        service("turn.example", "turn", 3478, "tcp"),
        service("turn.example", "turn", 5349, "tcp"),
    ];
    let request = parse(
        "<iq type='get'><credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' port='3478'/></credentials></iq>",
    )
    .unwrap();
    let ExtDiscoRequest::Credentials(request) = request else {
        panic!("expected credentials request");
    };
    let plan = plan_credential_matches(&request, &configured);
    assert_eq!(plan.len(), 2);
    assert!(plan
        .iter()
        .all(|identity| identity.port == NonZeroU16::new(3478)));
}

#[test]
fn public_results_cannot_contain_credentials_and_escape_dynamic_values() {
    let mut public = service("turn.example", "turn", 3478, "udp");
    public.name = Some("TURN ' < & > \" \u{65e5}\u{672c}\u{8a9e}".to_owned());
    public.restricted = true;
    let xml = build_services_result(Some(&token("turn")), &[public]).unwrap();
    let document = Document::parse(&xml).unwrap();
    let root = document.root_element();
    let entry = root.children().find(roxmltree::Node::is_element).unwrap();
    assert_eq!(root.attribute("type"), Some("turn"));
    assert_eq!(
        entry.attribute("name"),
        Some("TURN ' < & > \" \u{65e5}\u{672c}\u{8a9e}")
    );
    assert_eq!(entry.attribute("restricted"), Some("true"));
    assert!(entry.attribute("username").is_none());
    assert!(entry.attribute("password").is_none());
}

#[test]
fn credential_results_escape_secrets_while_debug_is_redacted() {
    let password = SecretText::new("secret'\"<&>\u{65e5}\u{672c}\u{8a9e}").unwrap();
    assert_eq!(format!("{password:?}"), "SecretText(<redacted>)");
    let credentials =
        ServiceCredentials::new("opaque-user'\"<&>", password, "2099-01-01T00:00:00Z").unwrap();
    let xml = build_credentials_result(&[CredentialedService {
        service: service("turn.example", "turn", 3478, "udp"),
        credentials,
    }])
    .unwrap();
    let document = Document::parse(&xml).unwrap();
    let entry = document
        .root_element()
        .children()
        .find(roxmltree::Node::is_element)
        .unwrap();
    assert_eq!(
        entry.attribute("password"),
        Some("secret'\"<&>\u{65e5}\u{672c}\u{8a9e}")
    );
    assert_eq!(entry.attribute("expires"), Some("2099-01-01T00:00:00Z"));
}

#[test]
fn credential_expiry_must_be_valid_and_explicitly_utc() {
    for invalid in [
        "2099-01-01T00:00:00+01:00",
        "2099-02-30T00:00:00Z",
        "2099-01-01 00:00:00Z",
    ] {
        assert_eq!(
            ServiceCredentials::new("user", SecretText::new("secret").unwrap(), invalid)
                .unwrap_err(),
            ExtDiscoError::InvalidExpiry
        );
    }
}

#[test]
fn push_actions_and_extended_data_forms_are_typed_and_safe() {
    let mut public = service("turn.example", "turn", 3478, "udp");
    public.action = Some(ServiceAction::Modify);
    public.extended = vec![ExtendedField::new(
        "FORM_TYPE",
        Some("label<&".to_owned()),
        vec!["urn:example:<&".to_owned(), "second".to_owned()],
    )
    .unwrap()];
    let xml = build_services_push(Some(&token("turn")), &[public]).unwrap();
    let document = Document::parse(&xml).unwrap();
    let service = document
        .root_element()
        .children()
        .find(roxmltree::Node::is_element)
        .unwrap();
    assert_eq!(service.attribute("action"), Some("modify"));
    let form = service
        .children()
        .find(roxmltree::Node::is_element)
        .unwrap();
    assert_eq!(form.tag_name().namespace(), Some("jabber:x:data"));
    let values = form
        .descendants()
        .filter(|node| node.has_tag_name(("jabber:x:data", "value")))
        .map(|node| node.text().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(values, vec!["urn:example:<&", "second"]);
}

#[test]
fn builders_enforce_result_cardinality() {
    let services = (0..=MAX_RESULT_SERVICES)
        .map(|index| service(&format!("turn{index}.example"), "turn", 3478, "udp"))
        .collect::<Vec<_>>();
    assert_eq!(
        build_services_result(None, &services).unwrap_err(),
        ExtDiscoError::ResultServiceLimit {
            limit: MAX_RESULT_SERVICES
        }
    );
}

#[test]
fn descriptor_declares_discovery_and_credentials_routes() {
    assert_eq!(DESCRIPTOR.id, XEP_ID);
    assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
    assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
    assert_eq!(DESCRIPTOR.routes.len(), 2);
    assert!(DESCRIPTOR
        .routes
        .iter()
        .all(|route| { route.stanza == StanzaKind::IqGet && route.namespace == NAMESPACE }));
}
