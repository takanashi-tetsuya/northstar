//! Bounded, process-local admission for REST bodies before authentication.
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(crate) struct HttpBodyAdmission {
    reads: Mutex<Reads>,
    global_limit: usize,
    per_ip_limit: usize,
    pub(crate) timeout: Duration,
}

#[derive(Default)]
struct Reads {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
}

impl Default for HttpBodyAdmission {
    fn default() -> Self {
        Self::new(128, 8, Duration::from_secs(15))
    }
}

impl HttpBodyAdmission {
    pub(crate) fn new(global_limit: usize, per_ip_limit: usize, timeout: Duration) -> Self {
        assert!(global_limit > 0 && per_ip_limit > 0 && !timeout.is_zero());
        Self {
            reads: Mutex::new(Reads::default()),
            global_limit,
            per_ip_limit,
            timeout,
        }
    }

    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<BodyReadPermit> {
        let ip = ip.to_canonical();
        let mut reads = self.reads.lock().unwrap_or_else(|error| error.into_inner());
        if reads.total >= self.global_limit
            || reads.by_ip.get(&ip).copied().unwrap_or_default() >= self.per_ip_limit
        {
            return None;
        }
        // No waiting queue or permanent per-source entries: the map has at
        // most global_limit entries, even when every request uses a new IP.
        reads.total += 1;
        *reads.by_ip.entry(ip).or_default() += 1;
        Some(BodyReadPermit {
            admission: Arc::clone(self),
            ip,
        })
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> (usize, usize) {
        let reads = self.reads.lock().unwrap();
        (reads.total, reads.by_ip.len())
    }
}

pub(crate) struct BodyReadPermit {
    admission: Arc<HttpBodyAdmission>,
    ip: IpAddr,
}

impl Drop for BodyReadPermit {
    fn drop(&mut self) {
        let mut reads = self
            .admission
            .reads
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        reads.total -= 1;
        let count = reads.by_ip.get_mut(&self.ip).expect("owned REST body read");
        *count -= 1;
        if *count == 0 {
            reads.by_ip.remove(&self.ip);
        }
    }
}
