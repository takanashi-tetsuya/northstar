use super::{Action, ProtocolSession};
use crate::services::extdisco::CredentialIssueError;
use crate::xmpp::xml_util::{iq_error_from, iq_result_from};
use anyhow::Result;
use northstar_xep_0215::{
    CredentialedService, ExtDiscoRequest, PublicService, SecretText, ServiceCredentials,
    ServiceHost, ServiceIdentity, ServiceToken,
};
use roxmltree::Node;
use std::{
    num::NonZeroU16,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

impl ProtocolSession {
    pub(crate) fn external_services(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        _services: Node<'_, '_>,
    ) -> Result<Action> {
        if !self.extdisco_request_authorized(iq) {
            return Ok(self.extdisco_error(id, "not-authorized"));
        }
        if !server_target_allowed(iq.attribute("to"), &self.state.config.domain) {
            return Ok(self.extdisco_error(id, "service-unavailable"));
        }
        let request = match northstar_xep_0215::parse_iq(iq) {
            Ok(ExtDiscoRequest::Services(request)) => request,
            _ => return Ok(self.extdisco_error(id, "bad-request")),
        };
        let configured = self.configured_external_services()?;
        let selected = northstar_xep_0215::select_services(&request, &configured)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let payload =
            northstar_xep_0215::build_services_result(request.service_type.as_ref(), &selected)?;
        Ok(Action::Send(iq_result_from(
            id,
            &self.state.config.domain,
            &payload,
        )))
    }

    pub(crate) fn external_credentials(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        _credentials: Node<'_, '_>,
    ) -> Result<Action> {
        if !self.extdisco_request_authorized(iq) {
            return Ok(self.extdisco_error(id, "not-authorized"));
        }
        if !server_target_allowed(iq.attribute("to"), &self.state.config.domain) {
            return Ok(self.extdisco_error(id, "service-unavailable"));
        }
        let request = match northstar_xep_0215::parse_iq(iq) {
            Ok(ExtDiscoRequest::Credentials(request)) => request,
            _ => return Ok(self.extdisco_error(id, "bad-request")),
        };
        if !self.state.extdisco_service().turn_is_restricted() {
            return Ok(self.extdisco_error(id, "item-not-found"));
        }
        let configured = self.configured_external_services()?;
        let matches = northstar_xep_0215::plan_credential_matches(&request, &configured);
        if matches.is_empty() {
            return Ok(self.extdisco_error(id, "item-not-found"));
        }

        // Authorization and selector matching deliberately happen before the
        // stateful issuance/rate-limit capability is invoked.
        let bare_jid = crate::jid::CanonicalJid::parse(
            self.full_jid
                .as_deref()
                .expect("authorization requires a bound JID"),
        )?
        .bare();
        let issued = match self.state.extdisco_service().issue_turn_credentials(
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

        let mut services = Vec::with_capacity(matches.len());
        for identity in matches {
            let Some(service) = configured
                .iter()
                .find(|service| service.identity == identity)
                .cloned()
            else {
                continue;
            };
            let credentials = ServiceCredentials::new(
                issued.username.clone(),
                SecretText::new(issued.password.as_str())?,
                issued.expires.clone(),
            )?;
            services.push(CredentialedService {
                service,
                credentials,
            });
        }
        if services.is_empty() {
            return Ok(self.extdisco_error(id, "item-not-found"));
        }
        let payload = northstar_xep_0215::build_credentials_result(&services)?;
        Ok(Action::Send(iq_result_from(
            id,
            &self.state.config.domain,
            &payload,
        )))
    }

    fn configured_external_services(&self) -> Result<Vec<PublicService>> {
        let mut services = Vec::with_capacity(3);
        if let Some((host, port)) = &self.state.config.stun_service {
            services.push(public_service(
                host,
                *port,
                "stun",
                "udp",
                "STUN Service (RFC 5389)",
                false,
            )?);
        }
        if let Some((host, port)) = &self.state.config.turn_service {
            let restricted = self.state.extdisco_service().turn_is_restricted();
            for transport in ["udp", "tcp"] {
                services.push(public_service(
                    host,
                    *port,
                    "turn",
                    transport,
                    "TURN Relay (RFC 5766)",
                    restricted,
                )?);
            }
        }
        Ok(services)
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

fn public_service(
    host: &str,
    port: u16,
    service_type: &str,
    transport: &str,
    name: &str,
    restricted: bool,
) -> Result<PublicService> {
    let mut service = PublicService::new(ServiceIdentity {
        host: ServiceHost::parse(host)?,
        service_type: ServiceToken::parse_service_type(service_type)?,
        port: NonZeroU16::new(port),
        transport: Some(ServiceToken::parse_transport(transport)?),
    });
    service.name = Some(name.to_owned());
    service.restricted = restricted;
    service.validate()?;
    Ok(service)
}

fn server_target_allowed(target: Option<&str>, domain: &str) -> bool {
    target.is_none_or(|target| {
        crate::jid::CanonicalJid::parse_bare(target).is_ok_and(|jid| {
            jid.localpart().is_none() && jid.resourcepart().is_none() && jid.domainpart() == domain
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_targets_remain_implicit_or_domain_only() {
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
    }

    #[test]
    fn configured_service_conversion_is_strict_and_secret_free() {
        let service = public_service(
            "TURN.Example.test.",
            3478,
            "turn",
            "udp",
            "TURN Relay",
            true,
        )
        .unwrap();
        let xml = northstar_xep_0215::build_services_result(None, &[service]).unwrap();
        assert!(xml.contains("host='turn.example.test'"));
        assert!(xml.contains("restricted='true'"));
        assert!(!xml.contains("username="));
        assert!(!xml.contains("password="));
    }
}
