//! Pure service selection and credential-match planning.

use crate::model::{CredentialsRequest, PublicService, ServiceIdentity, ServicesRequest};
use std::collections::BTreeSet;

pub fn select_services<'a>(
    request: &ServicesRequest,
    configured: &'a [PublicService],
) -> Vec<&'a PublicService> {
    configured
        .iter()
        .filter(|service| {
            request
                .service_type
                .as_ref()
                .is_none_or(|requested| requested == &service.identity.service_type)
        })
        .collect()
}

/// Select configured identities for which a credential provider may be asked.
///
/// This plan contains no credentials. The application service must authorize
/// the account, rate-limit issuance, acquire the current time and call the
/// provider only after a configured identity matches.
pub fn plan_credential_matches(
    request: &CredentialsRequest,
    configured: &[PublicService],
) -> Vec<ServiceIdentity> {
    let mut matches = BTreeSet::new();
    for selector in &request.services {
        for service in configured {
            let identity = &service.identity;
            if identity.host == selector.host
                && identity.service_type == selector.service_type
                && selector.port.is_none_or(|port| identity.port == Some(port))
                && selector
                    .transport
                    .as_ref()
                    .is_none_or(|transport| identity.transport.as_ref() == Some(transport))
            {
                matches.insert(identity.clone());
            }
        }
    }
    matches.into_iter().collect()
}
