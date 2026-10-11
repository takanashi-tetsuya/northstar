//! Federation and external route domain policy and domain pattern lists.

use super::*;

/// The immutable domains allowed by the configured component and federation
/// transports. Runtime federation rules are applied separately by AppState.
#[derive(Clone)]
pub(crate) struct ExternalRouteDomainPolicy {
    pub(super) local_domain: String,
    pub(super) federation_enabled: bool,
    pub(super) federation_allowlist: Vec<String>,
    pub(super) federation_denylist: Vec<String>,
    pub(super) component_domains: Vec<String>,
}

impl ExternalRouteDomainPolicy {
    pub(crate) fn federation_domain_allowed(&self, domain: &str) -> bool {
        federation_domain_allowed_in(
            domain,
            &self.local_domain,
            self.federation_enabled,
            &self.federation_allowlist,
            &self.federation_denylist,
        )
    }

    pub(crate) fn external_route_domain_allowed(&self, domain: &str) -> bool {
        crate::jid::prepare_domainpart(domain)
            .is_ok_and(|domain| self.component_domains.iter().any(|entry| entry == &domain))
            || self.federation_domain_allowed(domain)
    }
}

pub(super) fn federation_domain_allowed_in(
    domain: &str,
    local_domain: &str,
    enabled: bool,
    allowlist: &[String],
    denylist: &[String],
) -> bool {
    if !enabled {
        return false;
    }
    let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
        return false;
    };
    if domain == local_domain
        || domain == format!("conference.{local_domain}")
        || domain == format!("upload.{local_domain}")
        || domain == format!("pubsub.{local_domain}")
        || domain == format!("mix.{local_domain}")
    {
        return false;
    }
    if denylist
        .iter()
        .any(|pattern| domain_pattern_matches(pattern, &domain))
    {
        return false;
    }
    allowlist.is_empty()
        || allowlist
            .iter()
            .any(|pattern| domain_pattern_matches(pattern, &domain))
}

pub(super) fn domain_list(value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|pattern| {
            let (wildcard, domain) = pattern
                .strip_prefix("*.")
                .map_or((false, pattern), |domain| (true, domain));
            let domain = crate::jid::prepare_domainpart(domain)?;
            Ok(if wildcard {
                format!("*.{domain}")
            } else {
                domain
            })
        })
        .collect()
}

pub(super) fn domain_pattern_matches(pattern: &str, domain: &str) -> bool {
    pattern == domain
        || pattern
            .strip_prefix("*.")
            .is_some_and(|suffix| domain != suffix && domain.ends_with(&format!(".{suffix}")))
}
