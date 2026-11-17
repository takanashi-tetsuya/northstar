//! The HTTP context's discovery policy, shared body admission and protected credentials.

use northstar_http::contexts::{http_body_admission, PublicDiscoveryContext};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(in crate::node) struct HttpModule {
    public_discovery_context: PublicDiscoveryContext,
    body_admission: Arc<http_body_admission::HttpBodyAdmission>,
    /// Optional credential for the dedicated observability listener. Callers
    /// can ask for an authorization decision but cannot read the token.
    metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
    /// Reverse-proxy credential for the isolated administration origin. The
    /// API can ask for a constant-time decision but cannot read key bytes.
    web_admin_gateway_token: Option<Arc<Zeroizing<String>>>,
}

impl HttpModule {
    pub(in crate::node) fn new(
        public_discovery_context: PublicDiscoveryContext,
        body_admission: Arc<http_body_admission::HttpBodyAdmission>,
        metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
        web_admin_gateway_token: Option<Arc<Zeroizing<String>>>,
    ) -> Self {
        Self {
            public_discovery_context,
            body_admission,
            metrics_bearer_token,
            web_admin_gateway_token,
        }
    }

    pub(in crate::node) fn discovery(&self) -> &PublicDiscoveryContext {
        &self.public_discovery_context
    }

    pub(in crate::node) fn body_admission(&self) -> &Arc<http_body_admission::HttpBodyAdmission> {
        &self.body_admission
    }

    pub(in crate::node) fn metrics_bearer_token(&self) -> Option<&Arc<Zeroizing<String>>> {
        self.metrics_bearer_token.as_ref()
    }

    pub(in crate::node) fn web_admin_gateway_token(&self) -> Option<&Arc<Zeroizing<String>>> {
        self.web_admin_gateway_token.as_ref()
    }
}
