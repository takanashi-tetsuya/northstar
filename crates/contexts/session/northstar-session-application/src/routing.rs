//! Routing ports that protocol handlers use to reach other servers without naming a transport.

use std::future::Future;

/// Sends stanzas to other servers without naming the transport that carries them.
pub trait RemoteRoutePort: Sync {
    /// Writes `stanza` on a route from `source_domain` to `target_domain` that is already authenticated and
    /// writable. It never opens a connection, stores the stanza or retries; the result says whether the write
    /// completed.
    fn send_volatile(
        &self,
        source_domain: &str,
        target_domain: &str,
        stanza: String,
    ) -> impl Future<Output = bool> + Send;
}
