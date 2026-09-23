use super::{Action, ProtocolSession};
use crate::services::extdisco::CredentialIssueError;
use crate::xmpp::xml_util::{iq_error_from, iq_result_from};
use anyhow::Result;
use northstar_xep_0215::{CredentialedService, ExtDiscoRequest, SecretText, ServiceCredentials};
use roxmltree::Node;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
        if !self
            .state
            .extdisco_service()
            .target_allowed(iq.attribute("to"))
        {
            return Ok(self.extdisco_error(id, "service-unavailable"));
        }
        let request = match northstar_xep_0215::parse_iq(iq) {
            Ok(ExtDiscoRequest::Services(request)) => request,
            _ => return Ok(self.extdisco_error(id, "bad-request")),
        };
        let configured = self.state.extdisco_service().public_services()?;
        let selected = northstar_xep_0215::select_services(&request, &configured)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let payload =
            northstar_xep_0215::build_services_result(request.service_type.as_ref(), &selected)?;
        Ok(Action::Send(iq_result_from(
            id,
            self.state.extdisco_service().domain(),
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
        if !self
            .state
            .extdisco_service()
            .target_allowed(iq.attribute("to"))
        {
            return Ok(self.extdisco_error(id, "service-unavailable"));
        }
        let request = match northstar_xep_0215::parse_iq(iq) {
            Ok(ExtDiscoRequest::Credentials(request)) => request,
            _ => return Ok(self.extdisco_error(id, "bad-request")),
        };
        if !self.state.extdisco_service().turn_is_restricted() {
            return Ok(self.extdisco_error(id, "item-not-found"));
        }
        let configured = self.state.extdisco_service().public_services()?;
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
            self.state.extdisco_service().domain(),
            &payload,
        )))
    }

    fn extdisco_request_authorized(&self, iq: Node<'_, '_>) -> bool {
        self.state.extdisco_service().request_authorized(
            self.authenticated
                .as_ref()
                .map(|user| user.username.as_str()),
            self.full_jid.as_deref(),
            iq.attribute("type"),
        )
    }

    fn extdisco_error(&self, id: &str, condition: &str) -> Action {
        Action::Send(iq_error_from(
            id,
            self.state.extdisco_service().domain(),
            condition,
        ))
    }
}
