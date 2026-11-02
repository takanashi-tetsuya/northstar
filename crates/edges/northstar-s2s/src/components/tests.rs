use super::*;
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context as TaskContext, Poll},
};

struct RenewalGatedWriter {
    writable: Arc<AtomicBool>,
    bytes: Vec<u8>,
}

impl AsyncWrite for RenewalGatedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.writable.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        self.bytes.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn unconfigured_component_task_stays_alive_until_cancelled() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let task_cancel = cancel.clone();
    let mut task = tokio::spawn(async move {
        wait_for_component_shutdown(&task_cancel).await;
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut task)
            .await
            .is_err(),
        "an unconfigured component task must not terminate main"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("component shutdown wait timed out")
        .expect("component shutdown task panicked");
}

#[tokio::test]
async fn connect_supervisor_failures_and_panics_are_never_silent() {
    let mut failed = JoinSet::new();
    failed
        .spawn(async { Err::<(), anyhow::Error>(anyhow::anyhow!("injected supervisor failure")) });
    let error = component_supervisor_completion(failed.join_next().await, false)
        .expect_err("supervisor error must terminate the component service");
    assert!(format!("{error:#}").contains("injected supervisor failure"));

    let joined: std::result::Result<Result<()>, tokio::task::JoinError> =
        tokio::spawn(async { panic!("injected supervisor panic") })
            .await
            .map(|()| Ok(()));
    let error = component_supervisor_completion(Some(joined), false)
        .expect_err("supervisor panic must terminate the component service");
    assert!(format!("{error:#}").contains("panicked or was cancelled"));

    assert!(component_supervisor_completion(Some(Ok(Ok(()))), true).is_ok());
    assert!(component_supervisor_completion(Some(Ok(Ok(()))), false).is_err());
}

#[tokio::test]
async fn component_socket_write_is_fenced_by_lease_renewal() {
    let writable = Arc::new(AtomicBool::new(false));
    let renewals = Arc::new(AtomicUsize::new(0));
    let mut writer = RenewalGatedWriter {
        writable: Arc::clone(&writable),
        bytes: Vec::new(),
    };
    let writable_after_renewal = Arc::clone(&writable);
    let renewal_count = Arc::clone(&renewals);
    let cancel = tokio_util::sync::CancellationToken::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        write_component_outbox_with_renewal(
            &mut writer,
            "<message/>".to_owned(),
            Duration::from_millis(1),
            Duration::from_millis(100),
            cancel.clone(),
            move || {
                writable_after_renewal.store(true, Ordering::Release);
                renewal_count.fetch_add(1, Ordering::Relaxed);
                std::future::ready(Ok(true))
            },
        ),
    )
    .await
    .expect("lease-fenced component write timed out")
    .expect("renewed component write failed");
    assert_eq!(renewals.load(Ordering::Relaxed), 1);
    assert_eq!(writer.bytes, b"<message/>");

    let mut blocked = RenewalGatedWriter {
        writable: Arc::new(AtomicBool::new(false)),
        bytes: Vec::new(),
    };
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        write_component_outbox_with_renewal(
            &mut blocked,
            "<message/>".to_owned(),
            Duration::from_millis(1),
            Duration::from_millis(100),
            cancel,
            || std::future::ready(Ok(false)),
        ),
    )
    .await
    .expect("lease-loss component write timed out");
    assert!(matches!(result, Err(ComponentOutboxWriteError::Lease(_))));
    assert!(blocked.bytes.is_empty());
}

#[test]
fn component_outbox_claims_are_just_in_time_and_bounded() {
    assert_eq!(COMPONENT_OUTBOX_CLAIM_BATCH, 1);
    const { assert!(COMPONENT_OUTBOX_DRAIN_LIMIT <= 32) };
    assert_eq!(component_lease_renewal_period(30), Duration::from_secs(10));
    assert_eq!(component_lease_renewal_period(1), Duration::from_secs(1));
}

#[test]
fn connect_endpoint_ssrf_policy_requires_explicit_public_opt_in() {
    for private in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "::1",
        "fd00::1",
    ] {
        assert!(component_connect_address_allowed(
            private.parse().unwrap(),
            false
        ));
    }
    for forbidden in ["0.0.0.0", "224.0.0.1", "::", "ff02::1", "169.254.169.254"] {
        assert!(!component_connect_address_allowed(
            forbidden.parse().unwrap(),
            false
        ));
    }
    assert!(component_connect_address_allowed(
        "203.0.113.1".parse().unwrap(),
        true
    ));
    for forbidden_even_when_public in ["0.0.0.0", "255.255.255.255", "169.254.169.254", "fe80::1"] {
        assert!(!component_connect_address_allowed(
            forbidden_even_when_public.parse().unwrap(),
            true
        ));
    }
}
