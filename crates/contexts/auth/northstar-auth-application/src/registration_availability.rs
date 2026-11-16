//! Shared registration availability for account administration and public admission.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone)]
pub struct RegistrationAvailability {
    closed: Arc<AtomicBool>,
    dependency_locked: bool,
}

impl RegistrationAvailability {
    pub fn new(dependency_locked: bool, closed: Arc<AtomicBool>) -> Self {
        Self {
            dependency_locked,
            closed,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.dependency_locked || self.closed.load(Ordering::Acquire)
    }

    pub fn shared_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.closed)
    }

    pub fn http_availability(
        &self,
        invitation_only: bool,
    ) -> crate::account::HttpRegistrationAvailability {
        crate::account::HttpRegistrationAvailability::new(
            Arc::clone(&self.closed),
            self.dependency_locked,
            invitation_only,
        )
    }
}

impl crate::account_admin::RegistrationCache for RegistrationAvailability {
    fn dependency_locked(&self) -> bool {
        self.dependency_locked
    }
    fn apply_current_closed(&self, closed: bool) {
        self.closed
            .store(closed || self.dependency_locked, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_admin::RegistrationCache;

    #[test]
    fn registration_cache_updates_the_original_flag_and_preserves_dependency_lock() {
        let shared = Arc::new(AtomicBool::new(true));
        let cache = RegistrationAvailability::new(false, Arc::clone(&shared));
        cache.apply_current_closed(false);
        assert!(!shared.load(Ordering::Acquire));
        cache.apply_current_closed(true);
        assert!(shared.load(Ordering::Acquire));
        let locked = RegistrationAvailability::new(true, Arc::clone(&shared));
        locked.apply_current_closed(false);
        assert!(shared.load(Ordering::Acquire));
    }

    #[test]
    fn availability_reads_the_shared_flag_and_dependency_lock() {
        let shared = Arc::new(AtomicBool::new(false));
        let availability = RegistrationAvailability::new(false, Arc::clone(&shared));
        let flag = availability.shared_flag();
        assert!(Arc::ptr_eq(&shared, &flag));
        assert!(!availability.is_closed());
        flag.store(true, Ordering::Release);
        assert!(availability.is_closed());
        flag.store(false, Ordering::Release);
        assert!(!availability.is_closed());

        let locked = RegistrationAvailability::new(true, Arc::clone(&shared));
        let locked_flag = locked.shared_flag();
        assert!(locked.is_closed());
        locked_flag.store(true, Ordering::Release);
        assert!(locked.is_closed());
        locked_flag.store(false, Ordering::Release);
        assert!(locked.is_closed());
    }

    #[test]
    fn http_availability_shares_the_original_flag() {
        let shared = Arc::new(AtomicBool::new(false));
        let availability = RegistrationAvailability::new(false, Arc::clone(&shared));
        let http = availability.http_availability(true);
        assert!(!http.is_closed());
        availability.apply_current_closed(true);
        assert!(shared.load(Ordering::Acquire));
        assert!(http.is_closed());
        availability.apply_current_closed(false);
        assert!(!shared.load(Ordering::Acquire));
        assert!(!http.is_closed());
    }
}
