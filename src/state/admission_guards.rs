//! Client connection and upload request guards.

use super::*;

pub struct ClientConnectionGuard {
    pub(super) state: Arc<AppState>,
    pub(super) ip: std::net::IpAddr,
    pub(super) _permit: OwnedSemaphorePermit,
}

pub struct UploadRequestGuard {
    pub(super) counts: Arc<DashMap<std::net::IpAddr, usize>>,
    pub(super) ip: std::net::IpAddr,
    pub(super) _permit: OwnedSemaphorePermit,
}

pub struct UploadDownloadGuard {
    pub(super) counts: Arc<DashMap<std::net::IpAddr, usize>>,
    pub(super) ip: std::net::IpAddr,
    pub(super) _permit: OwnedSemaphorePermit,
}

impl Drop for UploadDownloadGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.counts.remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

impl Drop for UploadRequestGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.counts.remove_if(&self.ip, |_, count| *count == 0);
        }
    }
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

impl AppState {
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
