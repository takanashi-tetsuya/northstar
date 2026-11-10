//! PUT upload authority: request admission, lifecycle service, guarded object
//! writes, and the immutable transport and retention settings it needs.

use super::upload_admission::{UploadAdmission, UploadRequestGuard};
use super::UploadService;
use crate::repositories::HttpRepositories;
use northstar_telemetry::metrics::DurationHistogram;
use northstar_telemetry::metrics::DurationTimer;
use northstar_upload_application::safety::{UploadIoPermit, UploadSafetyError, UploadSafetyGate};
use northstar_upload_application::store::UploadStore;
use northstar_upload_application::UploadIoClass;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone)]
pub struct UploadHttpWriteContext<R: HttpRepositories> {
    pub service: Option<UploadService<R>>,
    pub guarded_store: Option<Arc<dyn UploadStore>>,
    pub admission: Option<UploadAdmission>,
    pub safety_gate: Arc<UploadSafetyGate>,
    pub trusted_proxies: Arc<[IpAddr]>,
    pub operation_duration: Arc<DurationHistogram>,
    pub retention_seconds: u64,
}

impl<R: HttpRepositories> UploadHttpWriteContext<R> {
    pub fn operation_timer(&self) -> DurationTimer<'_> {
        self.operation_duration.start_timer()
    }

    pub fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub fn acquire_request(&self, ip: IpAddr) -> Option<UploadRequestGuard> {
        let admission = self.admission.as_ref()?;
        let permit = Arc::clone(&admission.semaphore).try_acquire_owned().ok()?;
        {
            let mut count = admission.by_ip.entry(ip).or_insert(0);
            if *count >= admission.max_per_ip {
                let remove_zero = *count == 0;
                drop(count);
                if remove_zero {
                    admission.by_ip.remove(&ip);
                }
                return None;
            }
            *count += 1;
        }
        Some(UploadRequestGuard {
            counts: Arc::clone(&admission.by_ip),
            ip,
            _permit: permit,
        })
    }

    pub fn permit_new_write(&self) -> Result<UploadIoPermit, UploadSafetyError> {
        self.safety_gate.permit(UploadIoClass::NewWrite)
    }

    pub fn service(&self) -> &UploadService<R> {
        self.service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
    }

    pub fn store(&self) -> &dyn UploadStore {
        self.guarded_store
            .as_deref()
            .expect("upload routes and workers require an enabled or draining runtime")
    }

    pub fn retention_seconds(&self) -> u64 {
        self.retention_seconds
    }
}
