//! Client connection admission guard.

use dashmap::DashMap;
use std::{net::IpAddr, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Process-wide client connection admission: a global permit, then a per-IP count.
pub struct ClientAdmission {
    connections: Arc<Semaphore>,
    by_ip: DashMap<IpAddr, usize>,
    max_per_ip: usize,
}

impl ClientAdmission {
    pub fn new(connections: Arc<Semaphore>, max_per_ip: usize) -> Self {
        Self {
            connections,
            by_ip: DashMap::new(),
            max_per_ip,
        }
    }

    pub fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ClientConnectionGuard> {
        let permit = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        {
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
        }
        Some(ClientConnectionGuard {
            admission: Arc::clone(self),
            ip,
            _permit: permit,
        })
    }
}

/// One admitted client connection; dropping it releases the permit and the per-IP count.
pub struct ClientConnectionGuard {
    admission: Arc<ClientAdmission>,
    ip: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ClientConnectionGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.admission.by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.admission
                .by_ip
                .remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_counts_per_ip_and_releases_on_drop() {
        let connections = Arc::new(Semaphore::new(3));
        let admission = Arc::new(ClientAdmission::new(Arc::clone(&connections), 2));
        let ip = IpAddr::from([192, 0, 2, 1]);
        let other_ip = IpAddr::from([192, 0, 2, 2]);

        let first = admission.acquire(ip).unwrap();
        let second = admission.acquire(ip).unwrap();
        let other = admission.acquire(other_ip).unwrap();
        assert_eq!(*admission.by_ip.get(&ip).unwrap(), 2);
        assert_eq!(*admission.by_ip.get(&other_ip).unwrap(), 1);
        assert_eq!(connections.available_permits(), 0);

        drop(first);
        assert_eq!(*admission.by_ip.get(&ip).unwrap(), 1);
        assert_eq!(connections.available_permits(), 1);
        drop(second);
        assert!(!admission.by_ip.contains_key(&ip));
        assert_eq!(*admission.by_ip.get(&other_ip).unwrap(), 1);
        drop(other);
        assert!(admission.by_ip.is_empty());
        assert_eq!(connections.available_permits(), 3);

        let guard = admission.acquire(ip).unwrap();
        assert_eq!(*admission.by_ip.get(&ip).unwrap(), 1);
        drop(guard);
        assert!(admission.by_ip.is_empty());
        assert_eq!(connections.available_permits(), 3);
    }

    #[test]
    fn admission_rejects_at_the_per_ip_limit_without_leaking_an_entry() {
        let connections = Arc::new(Semaphore::new(2));
        let admission = Arc::new(ClientAdmission::new(Arc::clone(&connections), 1));
        let ip = IpAddr::from([192, 0, 2, 1]);

        let guard = admission.acquire(ip).unwrap();
        assert!(admission.acquire(ip).is_none());
        assert_eq!(*admission.by_ip.get(&ip).unwrap(), 1);
        assert_eq!(admission.by_ip.len(), 1);
        assert_eq!(connections.available_permits(), 1);
        drop(guard);
        assert!(admission.by_ip.is_empty());
        assert_eq!(connections.available_permits(), 2);

        let admission = Arc::new(ClientAdmission::new(Arc::clone(&connections), 0));
        assert!(admission.acquire(ip).is_none());
        assert!(admission.by_ip.is_empty());
        assert_eq!(connections.available_permits(), 2);
    }

    #[test]
    fn admission_rejects_when_the_global_permits_are_exhausted() {
        let connections = Arc::new(Semaphore::new(1));
        let admission = Arc::new(ClientAdmission::new(Arc::clone(&connections), 2));
        let ip = IpAddr::from([192, 0, 2, 1]);
        let other_ip = IpAddr::from([192, 0, 2, 2]);

        let guard = admission.acquire(ip).unwrap();
        assert!(admission.acquire(ip).is_none());
        assert!(admission.acquire(other_ip).is_none());
        assert_eq!(*admission.by_ip.get(&ip).unwrap(), 1);
        assert!(!admission.by_ip.contains_key(&other_ip));
        assert_eq!(admission.by_ip.len(), 1);
        drop(guard);
        assert!(admission.by_ip.is_empty());
        assert_eq!(connections.available_permits(), 1);

        let admission = Arc::new(ClientAdmission::new(Arc::new(Semaphore::new(0)), 2));
        assert!(admission.acquire(ip).is_none());
        assert!(admission.by_ip.is_empty());
    }
}
