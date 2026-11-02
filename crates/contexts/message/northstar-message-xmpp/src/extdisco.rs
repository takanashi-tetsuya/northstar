//! XEP-0215 external service discovery requests.

use crate::ports::MessageOutcome;
use anyhow::Result;
use northstar_message_application::extdisco::{CredentialIssueError, ExtDiscoService};
use northstar_xep_0215::{CredentialedService, ExtDiscoRequest, SecretText, ServiceCredentials};
use northstar_xml_builder::stanza::{iq_error_from, iq_result_from};
use roxmltree::Node;
use std::net::IpAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// What the external service discovery handlers read from the session that took the request.
pub trait ExtDiscoSession {
    type Action: MessageOutcome;

    fn extdisco_service(&self) -> &ExtDiscoService;
    fn authenticated_username(&self) -> Option<&str>;
    fn full_jid(&self) -> Option<&str>;
    fn peer_ip(&self) -> IpAddr;
}

pub fn external_services<S: ExtDiscoSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    _services: Node<'_, '_>,
) -> Result<S::Action> {
    if !extdisco_request_authorized(session, iq) {
        return Ok(extdisco_error(session, id, "not-authorized"));
    }
    if !session
        .extdisco_service()
        .target_allowed(iq.attribute("to"))
    {
        return Ok(extdisco_error(session, id, "service-unavailable"));
    }
    let request = match northstar_xep_0215::parse_iq(iq) {
        Ok(ExtDiscoRequest::Services(request)) => request,
        _ => return Ok(extdisco_error(session, id, "bad-request")),
    };
    let configured = session.extdisco_service().public_services()?;
    let selected = northstar_xep_0215::select_services(&request, &configured)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let payload =
        northstar_xep_0215::build_services_result(request.service_type.as_ref(), &selected)?;
    Ok(S::Action::send(iq_result_from(
        id,
        session.extdisco_service().domain(),
        &payload,
    )))
}

pub fn external_credentials<S: ExtDiscoSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    _credentials: Node<'_, '_>,
) -> Result<S::Action> {
    if !extdisco_request_authorized(session, iq) {
        return Ok(extdisco_error(session, id, "not-authorized"));
    }
    if !session
        .extdisco_service()
        .target_allowed(iq.attribute("to"))
    {
        return Ok(extdisco_error(session, id, "service-unavailable"));
    }
    let request = match northstar_xep_0215::parse_iq(iq) {
        Ok(ExtDiscoRequest::Credentials(request)) => request,
        _ => return Ok(extdisco_error(session, id, "bad-request")),
    };
    if !session.extdisco_service().turn_is_restricted() {
        return Ok(extdisco_error(session, id, "item-not-found"));
    }
    let configured = session.extdisco_service().public_services()?;
    let matches = northstar_xep_0215::plan_credential_matches(&request, &configured);
    if matches.is_empty() {
        return Ok(extdisco_error(session, id, "item-not-found"));
    }

    // Authorization and selector matching deliberately happen before the
    // stateful issuance/rate-limit capability is invoked.
    let bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse(
        session
            .full_jid()
            .expect("authorization requires a bound JID"),
    )?
    .bare();
    let issued = match session.extdisco_service().issue_turn_credentials(
        &bare_jid,
        session.peer_ip(),
        Instant::now(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    ) {
        Ok(credentials) => credentials,
        Err(CredentialIssueError::NotConfigured) => {
            return Ok(extdisco_error(session, id, "item-not-found"));
        }
        Err(CredentialIssueError::RateLimited) => {
            return Ok(extdisco_error(session, id, "resource-constraint"));
        }
        Err(CredentialIssueError::TimestampOverflow) => {
            return Ok(extdisco_error(session, id, "internal-server-error"));
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
        return Ok(extdisco_error(session, id, "item-not-found"));
    }
    let payload = northstar_xep_0215::build_credentials_result(&services)?;
    Ok(S::Action::send(iq_result_from(
        id,
        session.extdisco_service().domain(),
        &payload,
    )))
}

fn extdisco_request_authorized<S: ExtDiscoSession>(session: &S, iq: Node<'_, '_>) -> bool {
    session.extdisco_service().request_authorized(
        session.authenticated_username(),
        session.full_jid(),
        iq.attribute("type"),
    )
}

fn extdisco_error<S: ExtDiscoSession>(session: &S, id: &str, condition: &str) -> S::Action {
    S::Action::send(iq_error_from(
        id,
        session.extdisco_service().domain(),
        condition,
    ))
}
