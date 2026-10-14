use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

struct FaultPort {
    calls: Mutex<Vec<&'static str>>,
    joins: AtomicUsize,
    refreshes: AtomicUsize,
    reconciliations: AtomicUsize,
}

impl MucSoftStateProjectionPort for &FaultPort {
    async fn join_room(&self, room_jid: &str) -> Result<()> {
        assert_eq!(room_jid, "room@conference.local.test");
        self.calls.lock().unwrap().push("join");
        if self.joins.fetch_add(1, Ordering::SeqCst) == 0 {
            anyhow::bail!("injected Redis join outage");
        }
        Ok(())
    }

    async fn refresh_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        exact_occupant_json: &str,
    ) -> Result<bool> {
        assert_eq!(room_jid, "room@conference.local.test");
        assert_eq!(nick, "Alice");
        assert_eq!(exact_occupant_json, "exact-PG-fenced-occupant");
        self.calls.lock().unwrap().push("refresh");
        match self.refreshes.fetch_add(1, Ordering::SeqCst) {
            0 => Ok(false),
            1 => anyhow::bail!("injected Redis refresh outage"),
            _ => Ok(true),
        }
    }

    async fn reconcile_room(&self, room_jid: &str) -> Result<()> {
        assert_eq!(room_jid, "room@conference.local.test");
        self.calls.lock().unwrap().push("reconcile");
        if self.reconciliations.fetch_add(1, Ordering::SeqCst) == 0 {
            anyhow::bail!("injected Redis reconciliation outage");
        }
        Ok(())
    }
}

#[tokio::test]
async fn projection_failure_does_not_claim_success_and_recovery_retries_in_order() {
    let port = FaultPort {
        calls: Mutex::new(Vec::new()),
        joins: AtomicUsize::new(0),
        refreshes: AtomicUsize::new(0),
        reconciliations: AtomicUsize::new(0),
    };
    let service = MucSoftStateProjectionService::new(&port);
    let refresh = || {
        service.refresh(
            "room@conference.local.test",
            "Alice",
            "exact-PG-fenced-occupant",
        )
    };
    assert!(matches!(
        refresh().await,
        Err(MucSoftStateDegradation::Join(_))
    ));
    assert!(matches!(
        refresh().await,
        Err(MucSoftStateDegradation::IdentityRejected)
    ));
    assert!(matches!(
        refresh().await,
        Err(MucSoftStateDegradation::Refresh(_))
    ));
    refresh().await.unwrap();
    assert!(matches!(
        service.reconcile_room("room@conference.local.test").await,
        Err(MucSoftStateDegradation::Reconcile(_))
    ));
    service
        .reconcile_room("room@conference.local.test")
        .await
        .unwrap();
    assert_eq!(
        *port.calls.lock().unwrap(),
        [
            "join",
            "join",
            "refresh",
            "join",
            "refresh",
            "join",
            "refresh",
            "reconcile",
            "reconcile"
        ]
    );
}
