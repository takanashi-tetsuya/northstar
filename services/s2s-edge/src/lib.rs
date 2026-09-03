//! S2S Edge Transport Gateway microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 5.1, 6, 19.6).

use northstar_federation_core::{
    compute_dialback_key, is_valid_dialback_key, matches_dialback_key,
};
use std::collections::HashSet;
use std::sync::RwLock;

pub struct S2sEdgeGateway {
    dialback_secret: String,
    authenticated_peers: RwLock<HashSet<String>>, // remote_domain
}

impl S2sEdgeGateway {
    pub fn new(dialback_secret: impl Into<String>) -> Self {
        Self {
            dialback_secret: dialback_secret.into(),
            authenticated_peers: RwLock::new(HashSet::new()),
        }
    }

    /// Computes authoritative Dialback key (XEP-0185) for an outgoing S2S stream.
    pub fn generate_outbound_dialback_key(
        &self,
        receiving_server: &str,
        originating_server: &str,
        stream_id: &str,
    ) -> String {
        compute_dialback_key(
            self.dialback_secret.as_bytes(),
            receiving_server,
            originating_server,
            stream_id,
        )
    }

    /// Validates an incoming Dialback key (XEP-0220 / XEP-0185) from a remote peer in constant time.
    pub fn verify_inbound_dialback_key(
        &self,
        receiving_server: &str,
        originating_server: &str,
        stream_id: &str,
        key: &str,
    ) -> bool {
        if !is_valid_dialback_key(key) {
            return false;
        }

        let expected = compute_dialback_key(
            self.dialback_secret.as_bytes(),
            receiving_server,
            originating_server,
            stream_id,
        );
        let valid = matches_dialback_key(&expected, key);
        if valid {
            self.authenticated_peers
                .write()
                .unwrap()
                .insert(originating_server.to_string());
        }
        valid
    }

    /// Checks if a remote peer domain is currently authenticated for S2S exchange.
    pub fn is_peer_authenticated(&self, remote_domain: &str) -> bool {
        self.authenticated_peers
            .read()
            .unwrap()
            .contains(remote_domain)
    }

    pub fn disconnect_peer(&self, remote_domain: &str) {
        self.authenticated_peers
            .write()
            .unwrap()
            .remove(remote_domain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s2s_edge_dialback_handshake_flow() {
        let gateway = S2sEdgeGateway::new("s2s_shared_secret_123");
        let recv = "local.example.com";
        let orig = "remote.example.org";
        let stream = "stream-789";

        // Generate authoritative key
        let key = gateway.generate_outbound_dialback_key(recv, orig, stream);
        assert!(!key.is_empty());

        // Verify incoming key
        assert!(gateway.verify_inbound_dialback_key(recv, orig, stream, &key));
        assert!(gateway.is_peer_authenticated(orig));

        // Tampered key fails
        assert!(!gateway.verify_inbound_dialback_key(
            recv,
            orig,
            stream,
            "bad_key_000000000000000000000000000000000000000000000000000000000000"
        ));

        gateway.disconnect_peer(orig);
        assert!(!gateway.is_peer_authenticated(orig));
    }
}
