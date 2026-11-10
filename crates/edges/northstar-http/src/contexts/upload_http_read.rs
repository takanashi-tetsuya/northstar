//! Public upload reads receive only download admission, a guarded object read,
//! the public-file projection, immutable transport policy, and one timer.

use super::upload_admission::{UploadAdmission, UploadDownloadGuard};
use super::UploadService;
use crate::repositories::HttpRepositories;
use northstar_telemetry::metrics::DurationHistogram;
use northstar_telemetry::metrics::DurationTimer;
use northstar_upload_application::service::UploadSlot;
use northstar_upload_application::store::{StoredUploadReader, UploadStore};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct UploadHttpReadContext<R: HttpRepositories> {
    pub service: Option<UploadService<R>>,
    pub guarded_store: Option<Arc<dyn UploadStore>>,
    pub admission: Option<UploadAdmission>,
    pub trusted_proxies: Arc<[IpAddr]>,
    pub operation_duration: Arc<DurationHistogram>,
    pub read_timeout: Duration,
    pub max_duration: Duration,
}

impl<R: HttpRepositories> UploadHttpReadContext<R> {
    pub fn operation_timer(&self) -> DurationTimer<'_> {
        self.operation_duration.start_timer()
    }

    pub fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub fn acquire_download(&self, ip: IpAddr) -> Option<UploadDownloadGuard> {
        self.admission.as_ref()?.try_acquire_download(ip)
    }

    pub async fn public_file(&self, id: Uuid) -> anyhow::Result<Option<UploadSlot>> {
        self.service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
            .public_file(id)
            .await
    }

    pub fn backend(&self) -> &'static str {
        self.guarded_store
            .as_ref()
            .expect("upload routes and workers require an enabled or draining runtime")
            .backend()
    }

    pub async fn get(
        &self,
        object_key: &str,
        object_version: Option<&str>,
    ) -> anyhow::Result<Option<StoredUploadReader>> {
        self.guarded_store
            .as_ref()
            .expect("upload routes and workers require an enabled or draining runtime")
            .get(object_key, object_version)
            .await
    }

    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    pub fn max_duration(&self) -> Duration {
        self.max_duration
    }
}

/// Exact, guarded object reads used to verify a claimed upload replay.
/// The caller already holds write admission; this capability has no public
/// file lookup or independent download admission.
#[derive(Clone)]
pub struct UploadHttpReplayReadContext {
    pub guarded_store: Option<Arc<dyn UploadStore>>,
    pub read_timeout: Duration,
    pub max_duration: Duration,
}

impl UploadHttpReplayReadContext {
    pub fn backend(&self) -> &'static str {
        self.guarded_store
            .as_ref()
            .expect("upload routes and workers require an enabled or draining runtime")
            .backend()
    }

    pub async fn get(
        &self,
        object_key: &str,
        object_version: Option<&str>,
    ) -> anyhow::Result<Option<StoredUploadReader>> {
        self.guarded_store
            .as_ref()
            .expect("upload routes and workers require an enabled or draining runtime")
            .get(object_key, object_version)
            .await
    }

    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    pub fn max_duration(&self) -> Duration {
        self.max_duration
    }
}

#[cfg(test)]
mod tests {
    use super::UploadAdmission;
    use dashmap::DashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[test]
    fn cloned_download_admission_shares_global_and_per_ip_limits_until_guard_drop() {
        let admission = UploadAdmission {
            semaphore: Arc::new(Semaphore::new(2)),
            by_ip: Arc::new(DashMap::new()),
            max_per_ip: 1,
        };
        let cloned = admission.clone();
        let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let third_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));

        let first = admission.try_acquire_download(first_ip).unwrap();
        assert!(cloned.try_acquire_download(first_ip).is_none());
        let second = cloned.try_acquire_download(second_ip).unwrap();
        assert!(admission.try_acquire_download(third_ip).is_none());

        drop(first);
        let replacement = cloned.try_acquire_download(first_ip).unwrap();
        assert!(admission.try_acquire_download(third_ip).is_none());
        drop(replacement);
        drop(second);
        assert!(admission.try_acquire_download(third_ip).is_some());
    }
}
