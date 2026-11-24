//! XEP-0215 external service discovery requests.

use crate::ports::{MessageHost, MessageOutcome};
use anyhow::Result;
use northstar_message_application::extdisco::{
    ExtDiscoCommand, ExtDiscoIssuance, ExtDiscoQuery, ExtDiscoRejection, ExtDiscoRequestScope,
    ExtDiscoService, ExtDiscoServices, IssuanceTime,
};
use northstar_message_core::MessageEventSource;
use northstar_xep_0215::ExtDiscoRequest;
use northstar_xml_builder::stanza::{iq_error_from, iq_result_from};
use roxmltree::Node;
use std::net::IpAddr;
use std::time::Instant;

/// What the node provides to the external service discovery handlers. The composition root implements it.
pub trait ExtDiscoHost: MessageHost {
    /// The external service discovery service.
    fn extdisco_service(&self) -> &ExtDiscoService;
}

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
    let request = match northstar_xep_0215::parse_iq(iq) {
        Ok(ExtDiscoRequest::Services(request)) => Some(request),
        _ => None,
    };
    let service = session.extdisco_service();
    let result = service.list_services(ExtDiscoQuery {
        scope: request_scope(session, iq),
        request,
    })?;
    let payload = match result {
        ExtDiscoServices::Listed {
            service_type,
            services,
        } => northstar_xep_0215::build_services_result(service_type.as_ref(), &services)?,
        ExtDiscoServices::Rejected(rejection) => return Ok(extdisco_error(session, id, rejection)),
    };
    Ok(S::Action::send(iq_result_from(
        id,
        service.domain(),
        &payload,
    )))
}

pub fn external_credentials<S: ExtDiscoSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    _credentials: Node<'_, '_>,
    message_events: &dyn MessageEventSource,
) -> Result<S::Action> {
    let request = match northstar_xep_0215::parse_iq(iq) {
        Ok(ExtDiscoRequest::Credentials(request)) => Some(request),
        _ => None,
    };
    let command = ExtDiscoCommand {
        scope: request_scope(session, iq),
        request,
        peer_ip: session.peer_ip(),
    };
    let time = IssuanceTime {
        monotonic: Instant::now(),
        unix_seconds: message_events.now().timestamp(),
    };
    let service = session.extdisco_service();
    let payload = match service.issue_credentials(command, time)? {
        ExtDiscoIssuance::Issued(services) => {
            northstar_xep_0215::build_credentials_result(&services)?
        }
        ExtDiscoIssuance::Rejected(rejection) => return Ok(extdisco_error(session, id, rejection)),
    };
    Ok(S::Action::send(iq_result_from(
        id,
        service.domain(),
        &payload,
    )))
}

fn request_scope<'a, S: ExtDiscoSession>(
    session: &'a S,
    iq: Node<'a, '_>,
) -> ExtDiscoRequestScope<'a> {
    ExtDiscoRequestScope {
        username: session.authenticated_username(),
        full_jid: session.full_jid(),
        iq_type: iq.attribute("type"),
        target: iq.attribute("to"),
    }
}

fn extdisco_error<S: ExtDiscoSession>(
    session: &S,
    id: &str,
    rejection: ExtDiscoRejection,
) -> S::Action {
    let condition = match rejection {
        ExtDiscoRejection::NotAuthorized => "not-authorized",
        ExtDiscoRejection::OutOfScope => "service-unavailable",
        ExtDiscoRejection::MalformedRequest => "bad-request",
        ExtDiscoRejection::Unavailable => "item-not-found",
        ExtDiscoRejection::RateLimited => "resource-constraint",
        ExtDiscoRejection::TimestampOverflow => "internal-server-error",
    };
    S::Action::send(iq_error_from(
        id,
        session.extdisco_service().domain(),
        condition,
    ))
}

#[cfg(test)]
mod wire_tests;
