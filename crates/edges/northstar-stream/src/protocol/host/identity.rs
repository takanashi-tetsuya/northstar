use std::time::Duration;

/// Local identity, protocol switches, and connection policy.
pub trait SessionIdentityHost: Send + Sync + 'static {
    /// See `ServerNode::c2s_resource_bind_timeout_seconds`.
    fn c2s_resource_bind_timeout_seconds(&self) -> u64;
    /// See `ServerNode::capacity_session_lease_seconds`.
    fn capacity_session_lease_seconds(&self) -> u64;
    /// Validated local identity for protocol routing without exposing Config.
    fn local_domain(&self) -> &str;
    /// See `ServerNode::tls_context`.
    fn tls_context(&self) -> &northstar_security::tls::TlsContext;
    /// See `ServerNode::unauthenticated_timeout`.
    fn unauthenticated_timeout(&self) -> Duration;
    /// See `ServerNode::xmpp_extension_enabled`.
    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool;
    /// See `ServerNode::c2s_scram_sha1_enabled`.
    fn c2s_scram_sha1_enabled(&self) -> bool;
    /// The MUC service domain (`conference.<local domain>`).
    fn muc_domain(&self) -> String;
    /// The MIX service domain.
    fn mix_domain(&self) -> String;
    /// The PubSub service domain.
    fn pubsub_domain(&self) -> String;
    /// The HTTP upload service domain (`upload.<local domain>`).
    fn upload_domain(&self) -> String;
    /// Whether the XEP-0363 HTTP upload service is enabled.
    fn http_upload_enabled(&self) -> bool;
    /// See `ServerNode::xmpp_external_route_domain_allowed`.
    fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool;
    /// See `ServerNode::xmpp_route_enabled`.
    fn xmpp_route_enabled(
        &self,
        stanza: northstar_xep_core::StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool;
}
