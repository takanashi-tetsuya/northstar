//! OMEMO recovery polling: concurrency and per-IP admission windows, the recovery service and the poll context.

use super::*;

pub(super) const OMEMO_POLL_CONCURRENCY: usize = 4;
pub(super) const OMEMO_POLL_IP_REQUESTS_PER_MINUTE: usize = 30;
pub(super) const OMEMO_POLL_MAX_ACTIVE_IPS: usize = 65_536;

pub(super) fn admit_omemo_poll_ip_window(window: &mut VecDeque<Instant>, now: Instant) -> bool {
    let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
    while window.front().is_some_and(|seen| *seen <= cutoff) {
        window.pop_front();
    }
    if window.len() >= OMEMO_POLL_IP_REQUESTS_PER_MINUTE {
        return false;
    }
    window.push_back(now);
    true
}

pub(super) fn admit_bounded_omemo_poll_ip(
    windows: &DashMap<std::net::IpAddr, VecDeque<Instant>>,
    admission: &std::sync::Mutex<()>,
    ip: std::net::IpAddr,
    now: Instant,
    sweep: bool,
    max_active_ips: usize,
) -> bool {
    let _admission = admission
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if sweep {
        let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        windows.retain(|_, window| {
            while window.front().is_some_and(|seen| *seen <= cutoff) {
                window.pop_front();
            }
            !window.is_empty()
        });
    }
    if !windows.contains_key(&ip) && windows.len() >= max_active_ips {
        return false;
    }
    let mut window = windows.entry(ip).or_default();
    admit_omemo_poll_ip_window(&mut window, now)
}

impl AppState {
    pub(crate) fn omemo_recovery_service(
        &self,
    ) -> &crate::services::omemo_recovery::OmemoRecoveryService<
        db::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    > {
        &self.omemo_recovery_service
    }
    pub(crate) fn omemo_recovery_poll_context(&self) -> OmemoRecoveryPollContext {
        self.omemo_recovery_poll_context.clone()
    }
}
