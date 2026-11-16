//! Client connection admission guard.

use crate::node::*;

pub struct ClientConnectionGuard {
    pub(in crate::node) state: Arc<ServerNode>,
    pub(in crate::node) ip: std::net::IpAddr,
    pub(in crate::node) _permit: OwnedSemaphorePermit,
}

impl Drop for ClientConnectionGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.state.client_connections_by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.state
                .client_connections_by_ip
                .remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

impl ServerNode {
    pub fn acquire_client_connection(
        self: &Arc<Self>,
        ip: std::net::IpAddr,
    ) -> Option<ClientConnectionGuard> {
        let permit = Arc::clone(&self.client_connections)
            .try_acquire_owned()
            .ok()?;
        {
            let mut count = self.client_connections_by_ip.entry(ip).or_insert(0);
            if *count >= self.config.max_connections_per_ip {
                let remove_zero = *count == 0;
                drop(count);
                if remove_zero {
                    self.client_connections_by_ip.remove(&ip);
                }
                return None;
            }
            *count += 1;
        }
        Some(ClientConnectionGuard {
            state: Arc::clone(self),
            ip,
            _permit: permit,
        })
    }
}

impl ServerNode {
    pub(crate) fn connection_actors(
        &self,
    ) -> &northstar_runtime::connection_actors::ConnectionActorRegistry {
        &self.connection_actors
    }
}
