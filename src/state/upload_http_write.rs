//! PUT upload authority: request admission, lifecycle service, guarded object
//! writes, and the immutable transport and retention settings it needs.

use super::{AppState, UploadAdmission, UploadRequestGuard, UploadService};
use crate::metrics::{DurationHistogram, DurationTimer};
use crate::services::upload_safety::{
    UploadIoClass, UploadIoPermit, UploadSafetyError, UploadSafetyGate,
};
use crate::storage::UploadStore;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct UploadHttpWriteContext {
    service: Option<UploadService>,
    guarded_store: Option<Arc<dyn UploadStore>>,
    admission: Option<UploadAdmission>,
    safety_gate: Arc<UploadSafetyGate>,
    trusted_proxies: Arc<[IpAddr]>,
    operation_duration: Arc<DurationHistogram>,
    retention_seconds: u64,
}

impl axum::extract::FromRef<Arc<AppState>> for UploadHttpWriteContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self {
            service: state.upload_service.clone(),
            // AppState stores only GuardedUploadStore implementations here.
            guarded_store: state.upload_store.as_ref().map(Arc::clone),
            admission: state.upload_runtime.request_admission().cloned(),
            safety_gate: Arc::clone(&state.upload_safety_gate),
            trusted_proxies: state.config.trusted_proxy_ips.clone().into(),
            operation_duration: Arc::clone(&state.metrics.upload_operation_duration_seconds),
            retention_seconds: state.config.upload_retention_seconds,
        }
    }
}

impl UploadHttpWriteContext {
    pub(crate) fn operation_timer(&self) -> DurationTimer<'_> {
        self.operation_duration.start_timer()
    }

    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) fn acquire_request(&self, ip: IpAddr) -> Option<UploadRequestGuard> {
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

    pub(crate) fn permit_new_write(&self) -> Result<UploadIoPermit, UploadSafetyError> {
        self.safety_gate.permit(UploadIoClass::NewWrite)
    }

    pub(crate) fn service(&self) -> &UploadService {
        self.service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
    }

    pub(crate) fn store(&self) -> &dyn UploadStore {
        self.guarded_store
            .as_deref()
            .expect("upload routes and workers require an enabled or draining runtime")
    }

    pub(crate) fn retention_seconds(&self) -> u64 {
        self.retention_seconds
    }
}
