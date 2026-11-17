//! Upload request and download admission: shared global and per-IP limits and their drop guards.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct UploadAdmission {
    pub semaphore: Arc<Semaphore>,
    pub by_ip: Arc<DashMap<std::net::IpAddr, usize>>,
    pub max_per_ip: usize,
}

pub enum UploadRuntime {
    Enabled {
        requests: UploadAdmission,
        downloads: UploadAdmission,
    },
    DrainReadOnly {
        downloads: UploadAdmission,
    },
    Disabled,
}

impl UploadRuntime {
    pub fn from_config(config: &northstar_config::Config) -> Self {
        Self::from_parts(
            config.upload_mode,
            config.upload_download_max_concurrent,
            config.upload_download_max_per_ip,
        )
    }

    fn from_parts(
        upload_mode: northstar_config::UploadMode,
        upload_download_max_concurrent: usize,
        upload_download_max_per_ip: usize,
    ) -> Self {
        let downloads = || UploadAdmission {
            semaphore: Arc::new(Semaphore::new(upload_download_max_concurrent)),
            by_ip: Arc::new(DashMap::new()),
            max_per_ip: upload_download_max_per_ip,
        };
        match upload_mode {
            northstar_config::UploadMode::Enabled => Self::Enabled {
                requests: UploadAdmission {
                    semaphore: Arc::new(Semaphore::new(32)),
                    by_ip: Arc::new(DashMap::new()),
                    max_per_ip: 4,
                },
                downloads: downloads(),
            },
            northstar_config::UploadMode::DrainReadOnly => Self::DrainReadOnly {
                downloads: downloads(),
            },
            northstar_config::UploadMode::Disabled => Self::Disabled,
        }
    }

    pub fn request_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { requests, .. } => Some(requests),
            Self::DrainReadOnly { .. } | Self::Disabled => None,
        }
    }

    pub fn download_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { downloads, .. } | Self::DrainReadOnly { downloads } => Some(downloads),
            Self::Disabled => None,
        }
    }
}

impl UploadAdmission {
    pub fn try_acquire_download(&self, ip: std::net::IpAddr) -> Option<UploadDownloadGuard> {
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
    pub counts: Arc<DashMap<std::net::IpAddr, usize>>,
    pub ip: std::net::IpAddr,
    pub _permit: OwnedSemaphorePermit,
}

pub struct UploadDownloadGuard {
    pub counts: Arc<DashMap<std::net::IpAddr, usize>>,
    pub ip: std::net::IpAddr,
    pub _permit: OwnedSemaphorePermit,
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

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_config::UploadMode;

    #[test]
    fn upload_runtime_matches_the_upload_mode() {
        let enabled = UploadRuntime::from_parts(UploadMode::Enabled, 17, 3);
        let requests = enabled.request_admission().unwrap();
        assert_eq!(requests.semaphore.available_permits(), 32);
        assert_eq!(requests.max_per_ip, 4);
        assert!(requests.by_ip.is_empty());
        let downloads = enabled.download_admission().unwrap();
        assert_eq!(downloads.semaphore.available_permits(), 17);
        assert_eq!(downloads.max_per_ip, 3);
        assert!(downloads.by_ip.is_empty());

        let draining = UploadRuntime::from_parts(UploadMode::DrainReadOnly, 19, 5);
        assert!(draining.request_admission().is_none());
        let downloads = draining.download_admission().unwrap();
        assert_eq!(downloads.semaphore.available_permits(), 19);
        assert_eq!(downloads.max_per_ip, 5);
        assert!(downloads.by_ip.is_empty());

        let disabled = UploadRuntime::from_parts(UploadMode::Disabled, 0, 0);
        assert!(disabled.request_admission().is_none());
        assert!(disabled.download_admission().is_none());
    }
}
