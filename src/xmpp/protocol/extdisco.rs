use super::{Action, ProtocolSession};
use crate::services::extdisco::{CredentialIssueError, TurnCredentials};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::{iq_error_from, iq_result_from};
use anyhow::Result;
use roxmltree::Node;
use std::{
    collections::HashSet,
    net::IpAddr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const EXTDISCO_NS: &str = "urn:xmpp:extdisco:2";
const MAX_CREDENTIAL_SERVICES: usize = 16;

#[derive(Debug, Eq, PartialEq)]
struct CredentialRequest {
    host: String,
    service_type: String,
    port: Option<u16>,
    transport: Option<&'static str>,
}

impl ProtocolSession {
    pub(crate) fn external_services(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        services: Node<'_, '_>,
    ) -> Result<Action> {
        if !self.extdisco_request_authorized(iq) {
            return Ok(self.extdisco_error(id, "not-authorized"));
        }
        if !server_target_allowed(iq.attribute("to"), &self.state.config.domain) {
            return Ok(self.extdisco_error(id, "service-unavailable"));
        }
        if services
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "type")
            || has_content(services)
        {
            return Ok(self.extdisco_error(id, "bad-request"));
        }
        let requested_type = services.attribute("type");
        if requested_type.is_some_and(|value| !valid_service_type(value)) {
            return Ok(self.extdisco_error(id, "bad-request"));
        }

        let mut payload =
            XmlElement::namespaced("services", EXTDISCO_NS).optional_attr("type", requested_type);
        if requested_type.is_none() || requested_type == Some("stun") {
            if let Some((host, port)) = &self.state.config.stun_service {
                payload.push_child(service_element(
                    host,
                    *port,
                    "stun",
                    "udp",
                    "STUN Service (RFC 5389)",
                    false,
                    None,
                ));
            }
        }
        if requested_type.is_none() || requested_type == Some("turn") {
            if let Some((host, port)) = &self.state.config.turn_service {
                let restricted = self.state.extdisco_service().turn_is_restricted();
                for transport in ["udp", "tcp"] {
                    payload.push_child(service_element(
                        host,
                        *port,
                        "turn",
                        transport,
                        "TURN Relay (RFC 5766)",
                        restricted,
                        None,
                    ));
                }
            }
        }
        Ok(Action::Send(iq_result_from(
            id,
            &self.state.config.domain,
            &payload.finish(),
        )))
    }

    pub(crate) fn external_credentials(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        credentials: Node<'_, '_>,
    ) -> Result<Action> {
        if !self.extdisco_request_authorized(iq) {
            return Ok(self.extdisco_error(id, "not-authorized"));
        }
        if !server_target_allowed(iq.attribute("to"), &self.state.config.domain) {
            return Ok(self.extdisco_error(id, "service-unavailable"));
        }
        let requests = match parse_credential_requests(credentials) {
            Ok(requests) => requests,
            Err(condition) => return Ok(self.extdisco_error(id, condition)),
        };
        let Some((turn_host, turn_port)) = &self.state.config.turn_service else {
            return Ok(self.extdisco_error(id, "item-not-found"));
        };
        if !self.state.extdisco_service().turn_is_restricted() {
            return Ok(self.extdisco_error(id, "item-not-found"));
        }

        let bare_jid = crate::jid::CanonicalJid::parse(
            self.full_jid
                .as_deref()
                .expect("authorization requires a bound JID"),
        )?
        .bare();
        let turn_credentials = match self.state.extdisco_service().issue_turn_credentials(
            &bare_jid,
            self.peer_ip,
            Instant::now(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        ) {
            Ok(credentials) => credentials,
            Err(CredentialIssueError::NotConfigured) => {
                return Ok(self.extdisco_error(id, "item-not-found"));
            }
            Err(CredentialIssueError::RateLimited) => {
                return Ok(self.extdisco_error(id, "resource-constraint"));
            }
            Err(CredentialIssueError::TimestampOverflow) => {
                return Ok(self.extdisco_error(id, "internal-server-error"));
            }
        };

        let mut matches = Vec::new();
        let mut emitted = HashSet::new();
        for request in requests {
            if request.service_type != "turn"
                || request.host != *turn_host
                || request.port.is_some_and(|port| port != *turn_port)
            {
                continue;
            }
            let transports: &[&str] = match request.transport {
                Some("udp") => &["udp"],
                Some("tcp") => &["tcp"],
                _ => &["udp", "tcp"],
            };
            for transport in transports {
                if emitted.insert(*transport) {
                    matches.push(service_element(
                        turn_host,
                        *turn_port,
                        "turn",
                        transport,
                        "TURN Relay (RFC 5766)",
                        true,
                        Some(&turn_credentials),
                    ));
                }
            }
        }
        if matches.is_empty() {
            return Ok(self.extdisco_error(id, "item-not-found"));
        }
        let mut payload = XmlElement::namespaced("credentials", EXTDISCO_NS);
        for service in matches {
            payload.push_child(service);
        }
        Ok(Action::Send(iq_result_from(
            id,
            &self.state.config.domain,
            &payload.finish(),
        )))
    }

    fn extdisco_request_authorized(&self, iq: Node<'_, '_>) -> bool {
        let (Some(user), Some(full_jid)) = (&self.authenticated, self.full_jid.as_deref()) else {
            return false;
        };
        crate::jid::CanonicalJid::parse(full_jid).is_ok_and(|jid| {
            jid.resourcepart().is_some()
                && jid.localpart() == Some(user.username.as_str())
                && jid.domainpart() == self.state.config.domain
                && iq.attribute("type") == Some("get")
        })
    }

    fn extdisco_error(&self, id: &str, condition: &str) -> Action {
        Action::Send(iq_error_from(id, &self.state.config.domain, condition))
    }
}

fn server_target_allowed(target: Option<&str>, domain: &str) -> bool {
    target.is_none_or(|target| {
        crate::jid::CanonicalJid::parse_bare(target).is_ok_and(|jid| {
            jid.localpart().is_none() && jid.resourcepart().is_none() && jid.domainpart() == domain
        })
    })
}

fn parse_credential_requests(
    credentials: Node<'_, '_>,
) -> std::result::Result<Vec<CredentialRequest>, &'static str> {
    if credentials.attributes().len() != 0 || has_non_whitespace_text(credentials) {
        return Err("bad-request");
    }
    let services = credentials
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if services.is_empty() || services.len() > MAX_CREDENTIAL_SERVICES {
        return Err("bad-request");
    }
    let mut requests = Vec::with_capacity(services.len());
    for service in services {
        if service.tag_name().name() != "service"
            || service.tag_name().namespace() != Some(EXTDISCO_NS)
            || has_content(service)
            || service.attributes().any(|attribute| {
                attribute.namespace().is_some()
                    || !matches!(attribute.name(), "host" | "type" | "port" | "transport")
            })
        {
            return Err("bad-request");
        }
        let host = canonical_service_host(service.attribute("host").ok_or("bad-request")?)?;
        let service_type = service.attribute("type").ok_or("bad-request")?;
        if !valid_service_type(service_type) {
            return Err("bad-request");
        }
        let port = match service.attribute("port") {
            Some(port) => Some(
                port.parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or("bad-request")?,
            ),
            None => None,
        };
        let transport = match service.attribute("transport") {
            Some("udp") => Some("udp"),
            Some("tcp") => Some("tcp"),
            Some(_) => return Err("bad-request"),
            None => None,
        };
        requests.push(CredentialRequest {
            host,
            service_type: service_type.to_owned(),
            port,
            transport,
        });
    }
    Ok(requests)
}

fn canonical_service_host(value: &str) -> std::result::Result<String, &'static str> {
    if value.is_empty()
        || value.len() > 1_023
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err("bad-request");
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    crate::jid::prepare_domainpart(value).map_err(|_| "bad-request")
}

fn has_content(node: Node<'_, '_>) -> bool {
    node.children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter_map(|child| child.text())
        .any(|text| !text.trim().is_empty())
}

fn service_element(
    host: &str,
    port: u16,
    service_type: &str,
    transport: &str,
    name: &str,
    restricted: bool,
    credentials: Option<&TurnCredentials>,
) -> XmlElement {
    let mut service = XmlElement::namespaced("service", EXTDISCO_NS)
        .attr("host", host)
        .attr("port", port)
        .attr("type", service_type)
        .attr("transport", transport)
        .attr("name", name)
        .attr("restricted", restricted);
    if let Some(credentials) = credentials {
        service = service
            .attr("username", &credentials.username)
            .attr("password", credentials.password.as_str())
            .attr("expires", &credentials.expires);
    }
    service
}

fn valid_service_type(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && value.len() <= 64
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse_requests(xml: &str) -> std::result::Result<Vec<CredentialRequest>, &'static str> {
        let document = Document::parse(xml).unwrap();
        parse_credential_requests(document.root_element())
    }

    #[test]
    fn service_queries_validate_targets_types_and_xml_shape() {
        assert!(server_target_allowed(None, "example.test"));
        assert!(server_target_allowed(Some("EXAMPLE.test"), "example.test"));
        assert!(!server_target_allowed(
            Some("alice@example.test"),
            "example.test"
        ));
        assert!(!server_target_allowed(
            Some("example.test/resource"),
            "example.test"
        ));
        assert!(valid_service_type("turns"));
        assert!(!valid_service_type("1turn"));
        assert!(!valid_service_type("turn:udp"));
    }

    #[test]
    fn credential_requests_are_strict_bounded_and_canonical() {
        let parsed = parse_requests(
            "<credentials xmlns='urn:xmpp:extdisco:2'><service host='BÜCHER.example.' type='turn'/><service host='2001:db8::1' type='turn' port='3478' transport='tcp'/></credentials>",
        )
        .unwrap();
        assert_eq!(parsed[0].host, "bücher.example");
        assert_eq!(parsed[1].host, "2001:db8::1");
        assert_eq!(parsed[1].transport, Some("tcp"));

        for invalid in [
            "<credentials xmlns='urn:xmpp:extdisco:2'/>",
            "<credentials xmlns='urn:xmpp:extdisco:2' extra='x'><service host='turn.example' type='turn'/></credentials>",
            "<credentials xmlns='urn:xmpp:extdisco:2'>text<service host='turn.example' type='turn'/></credentials>",
            "<credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' password='probe'/></credentials>",
            "<credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' port='0'/></credentials>",
            "<credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn' transport='tls'/></credentials>",
            "<credentials xmlns='urn:xmpp:extdisco:2'><service host='turn.example' type='turn'><x/></service></credentials>",
        ] {
            assert_eq!(parse_requests(invalid), Err("bad-request"), "{invalid}");
        }
    }

    #[test]
    fn service_xml_omits_secrets_until_credentials_are_requested() {
        let xml = service_element(
            "turn.example.test",
            3478,
            "turn",
            "udp",
            "TURN Relay (RFC 5766)",
            true,
            None,
        )
        .finish();
        assert!(xml.contains("restricted='true'"));
        assert!(!xml.contains("username="));
        assert!(!xml.contains("password="));
        assert!(xml.contains("name='TURN Relay (RFC 5766)'"));
    }

    #[test]
    fn service_xml_round_trips_all_dynamic_attributes_without_injection() {
        let host = "turn.例.example'\"<&>";
        let service_type = "turn'\"<&>🙂";
        let transport = "udp' /><evil/>";
        let name = "TURN 日本語 ' \" < & >";
        let credentials = TurnCredentials {
            username: "user'\"<&>🙂".to_owned(),
            password: zeroize::Zeroizing::new("secret'\"<&>日本語".to_owned()),
            expires: "2099-01-01T00:00:00Z' /><evil/>".to_owned(),
        };
        let xml = service_element(
            host,
            3478,
            service_type,
            transport,
            name,
            true,
            Some(&credentials),
        )
        .finish();
        let document = Document::parse(&xml).unwrap();
        let service = document.root_element();
        assert_eq!(service.tag_name().namespace(), Some(EXTDISCO_NS));
        assert_eq!(service.attribute("host"), Some(host));
        assert_eq!(service.attribute("type"), Some(service_type));
        assert_eq!(service.attribute("transport"), Some(transport));
        assert_eq!(service.attribute("name"), Some(name));
        assert_eq!(
            service.attribute("username"),
            Some(credentials.username.as_str())
        );
        assert_eq!(
            service.attribute("password"),
            Some(credentials.password.as_str())
        );
        assert_eq!(
            service.attribute("expires"),
            Some(credentials.expires.as_str())
        );
        assert_eq!(service.children().filter(Node::is_element).count(), 0);
    }
}
