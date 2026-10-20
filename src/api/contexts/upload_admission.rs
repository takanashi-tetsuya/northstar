//! Upload request and download admission: shared global and per-IP limits and their drop guards.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub(crate) struct UploadAdmission {
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) by_ip: Arc<DashMap<std::net::IpAddr, usize>>,
    pub(crate) max_per_ip: usize,
}

impl UploadAdmission {
    pub(crate) fn try_acquire_download(&self, ip: std::net::IpAddr) -> Option<UploadDownloadGuard> {
        let permit = Arc::clone(&self.semaphore).try_acquire_owned().ok()?;
        let mut count = self.by_ip.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            let remove_zero = *count == 0;
            drop(count);
            if remove_zero {
                self.by_ip.remove(&ip);
            }
            return None;
        }
        *count += 1;
        drop(count);
        Some(UploadDownloadGuard {
            counts: Arc::clone(&self.by_ip),
            ip,
            _permit: permit,
        })
    }
}

pub struct UploadRequestGuard {
    pub(crate) counts: Arc<DashMap<std::net::IpAddr, usize>>,
    pub(crate) ip: std::net::IpAddr,
    pub(crate) _permit: OwnedSemaphorePermit,
}

pub struct UploadDownloadGuard {
    pub(crate) counts: Arc<DashMap<std::net::IpAddr, usize>>,
    pub(crate) ip: std::net::IpAddr,
    pub(crate) _permit: OwnedSemaphorePermit,
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
