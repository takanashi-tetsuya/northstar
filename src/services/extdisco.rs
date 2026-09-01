use base64::Engine;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const CREDENTIAL_RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_WINDOW_SWEEP_INTERVAL: u64 = 256;
const MAX_ACTIVE_RATE_KEYS: usize = 65_536;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TurnCredentials {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) expires: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialIssueError {
    NotConfigured,
    RateLimited,
    TimestampOverflow,
}

#[derive(Clone)]
pub(crate) struct ExtDiscoService {
    inner: Arc<ExtDiscoInner>,
}

struct ExtDiscoInner {
    turn_shared_secret: Option<Zeroizing<Vec<u8>>>,
    credential_ttl_seconds: u64,
    requests_per_minute: usize,
    rate_windows: DashMap<String, VecDeque<Instant>>,
    /// Serializes only first insertion of a rate key. Existing keys remain
    /// independently sharded by DashMap, while the global key ceiling cannot
    /// be crossed by concurrent check-then-insert races.
    rate_key_insertion: Mutex<()>,
    max_active_rate_keys: usize,
    rate_window_checks: AtomicU64,
}

impl ExtDiscoService {
    pub(crate) fn new(
        mut turn_shared_secret: Option<String>,
        credential_ttl_seconds: u64,
        requests_per_minute: usize,
    ) -> Self {
        Self::new_with_rate_key_limit(
            turn_shared_secret.take(),
            credential_ttl_seconds,
            requests_per_minute,
            MAX_ACTIVE_RATE_KEYS,
        )
    }

    fn new_with_rate_key_limit(
        mut turn_shared_secret: Option<String>,
        credential_ttl_seconds: u64,
        requests_per_minute: usize,
        max_active_rate_keys: usize,
    ) -> Self {
        let protected_secret = turn_shared_secret.as_mut().map(|secret| {
            let protected = Zeroizing::new(secret.as_bytes().to_vec());
            secret.zeroize();
            protected
        });
        Self {
            inner: Arc::new(ExtDiscoInner {
                turn_shared_secret: protected_secret,
                credential_ttl_seconds,
                requests_per_minute,
                rate_windows: DashMap::new(),
                rate_key_insertion: Mutex::new(()),
                max_active_rate_keys,
                rate_window_checks: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn turn_is_restricted(&self) -> bool {
        self.inner.turn_shared_secret.is_some()
    }

    pub(crate) fn issue_turn_credentials(
        &self,
        bare_jid: &str,
        peer_ip: IpAddr,
        now: Instant,
        now_seconds: u64,
    ) -> Result<TurnCredentials, CredentialIssueError> {
        let secret = self
            .inner
            .turn_shared_secret
            .as_deref()
            .ok_or(CredentialIssueError::NotConfigured)?;
        let limit = self.inner.requests_per_minute;
        if !self.rate_window_allows(&format!("account:{bare_jid}"), limit, now)
            || !self.rate_window_allows(&format!("ip:{peer_ip}"), limit, now)
        {
            return Err(CredentialIssueError::RateLimited);
        }
        derive_turn_credentials(
            secret,
            bare_jid,
            self.inner.credential_ttl_seconds,
            now_seconds,
        )
        .ok_or(CredentialIssueError::TimestampOverflow)
    }

    fn rate_window_allows(&self, key: &str, limit: usize, now: Instant) -> bool {
        if self
            .inner
            .rate_window_checks
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(RATE_WINDOW_SWEEP_INTERVAL)
        {
            self.inner.rate_windows.retain(|_, events| {
                events.back().is_some_and(|event| {
                    now.saturating_duration_since(*event) < CREDENTIAL_RATE_WINDOW
                })
            });
        }

        if let Some(mut events) = self.inner.rate_windows.get_mut(key) {
            return rate_events_allow(&mut events, limit, now);
        }

        // The first lookup deliberately stays outside the global insertion
        // gate. Only a new actor pays this lock; established actors continue
        // to use independent DashMap shard locks.
        let _insertion = self
            .inner
            .rate_key_insertion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut events) = self.inner.rate_windows.get_mut(key) {
            return rate_events_allow(&mut events, limit, now);
        }
        if self.inner.rate_windows.len() >= self.inner.max_active_rate_keys {
            return false;
        }
        let mut events = VecDeque::new();
        let allowed = rate_events_allow(&mut events, limit, now);
        if allowed {
            self.inner.rate_windows.insert(key.to_owned(), events);
        }
        allowed
    }
}

fn rate_events_allow(events: &mut VecDeque<Instant>, limit: usize, now: Instant) -> bool {
    while events
        .front()
        .is_some_and(|event| now.saturating_duration_since(*event) >= CREDENTIAL_RATE_WINDOW)
    {
        events.pop_front();
    }
    if events.len() >= limit {
        return false;
    }
    events.push_back(now);
    true
}

fn derive_turn_credentials(
    secret: &[u8],
    bare_jid: &str,
    ttl_seconds: u64,
    now_seconds: u64,
) -> Option<TurnCredentials> {
    let expires_at = now_seconds.checked_add(ttl_seconds)?;
    let mut identity_hmac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
    identity_hmac.update(expires_at.to_string().as_bytes());
    identity_hmac.update(b":");
    identity_hmac.update(bare_jid.as_bytes());
    let opaque_identity = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(identity_hmac.finalize().into_bytes());
    let username = format!("{expires_at}:{opaque_identity}");
    let mut hmac = Hmac::<Sha1>::new_from_slice(secret).ok()?;
    hmac.update(username.as_bytes());
    let password = Zeroizing::new(
        base64::engine::general_purpose::STANDARD.encode(hmac.finalize().into_bytes()),
    );
    let expires = chrono::DateTime::<chrono::Utc>::from_timestamp(expires_at as i64, 0)?
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    Some(TurnCredentials {
        username,
        password,
        expires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_opaque_short_lived_and_verifiable() {
        let secret = "0123456789abcdef0123456789abcdef";
        let service = ExtDiscoService::new(Some(secret.to_owned()), 3_600, 4);
        let credentials = service
            .issue_turn_credentials(
                "alice@example.test",
                "192.0.2.10".parse().unwrap(),
                Instant::now(),
                1_700_000_000,
            )
            .unwrap();
        assert!(credentials.username.starts_with("1700003600:"));
        assert!(!credentials.username.contains("alice"));
        assert_eq!(credentials.expires, "2023-11-14T23:13:20Z");

        let mut hmac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).unwrap();
        hmac.update(credentials.username.as_bytes());
        assert_eq!(
            credentials.password.as_str(),
            base64::engine::general_purpose::STANDARD.encode(hmac.finalize().into_bytes())
        );
    }

    #[test]
    fn missing_secret_and_timestamp_overflow_fail_closed() {
        let ip = "192.0.2.10".parse().unwrap();
        let now = Instant::now();
        assert_eq!(
            ExtDiscoService::new(None, 3_600, 4).issue_turn_credentials(
                "alice@example.test",
                ip,
                now,
                1
            ),
            Err(CredentialIssueError::NotConfigured)
        );
        assert_eq!(
            ExtDiscoService::new(Some("a sufficiently long secret".to_owned()), 1, 4)
                .issue_turn_credentials("alice@example.test", ip, now, u64::MAX),
            Err(CredentialIssueError::TimestampOverflow)
        );
    }

    #[test]
    fn account_and_ip_rate_windows_are_bounded_and_recover() {
        let service = ExtDiscoService::new(Some("a sufficiently long secret".to_owned()), 60, 2);
        let start = Instant::now();
        let ip = "192.0.2.10".parse().unwrap();
        assert!(service
            .issue_turn_credentials("alice@example.test", ip, start, 1)
            .is_ok());
        assert!(service
            .issue_turn_credentials("alice@example.test", ip, start + Duration::from_secs(1), 2)
            .is_ok());
        assert_eq!(
            service.issue_turn_credentials(
                "alice@example.test",
                ip,
                start + Duration::from_secs(59),
                3
            ),
            Err(CredentialIssueError::RateLimited)
        );
        assert!(service
            .issue_turn_credentials(
                "alice@example.test",
                ip,
                start + Duration::from_secs(60),
                61
            )
            .is_ok());
    }

    #[test]
    fn concurrent_new_rate_keys_cannot_cross_the_hard_capacity() {
        const KEY_CAPACITY: usize = 8;
        const CONTENDERS: usize = 64;
        let service = ExtDiscoService::new_with_rate_key_limit(None, 60, 1, KEY_CAPACITY);
        let barrier = Arc::new(std::sync::Barrier::new(CONTENDERS));
        let now = Instant::now();
        let threads = (0..CONTENDERS)
            .map(|index| {
                let service = service.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    service.rate_window_allows(&format!("actor:{index}"), 1, now)
                })
            })
            .collect::<Vec<_>>();
        let admitted = threads
            .into_iter()
            .map(|thread| thread.join().expect("rate-key contender panicked"))
            .filter(|admitted| *admitted)
            .count();

        assert_eq!(admitted, KEY_CAPACITY);
        assert_eq!(service.inner.rate_windows.len(), KEY_CAPACITY);
    }
}
