use super::*;
use tokio::sync::Notify;

impl RosterPushRoutes for PushPorts {
    fn with_local_roster_session<T>(
        &self,
        full_jid: &str,
        handoff: impl FnOnce(&OnlineSession) -> T,
    ) -> Option<T> {
        let replacement = self.replacement.lock().unwrap();
        replacement
            .iter()
            .chain(&self.sessions)
            .find(|(jid, _)| jid == full_jid)
            .map(|(_, session)| handoff(session))
    }

    async fn capture_remote_roster_routes(
        &self,
        account: &str,
        (account_id, auth_generation): (Uuid, i64),
    ) -> Result<Vec<ExactPresenceRoute>> {
        assert_eq!(account, "alice@example.test");
        if let Some((captured, release)) = &self.capture_pause {
            captured.notify_one();
            release.notified().await;
        }
        if self.lookup_error {
            anyhow::bail!("lookup failed");
        }
        Ok(self
            .nodes
            .iter()
            .map(|node| ExactPresenceRoute {
                account_id,
                auth_generation,
                connection_id: Uuid::from_u128(19),
                full_jid: format!("{account}/{node}"),
                node_id: Some(node.clone()),
            })
            .collect())
    }
}

#[tokio::test]
async fn replacing_the_captured_roster_session_does_not_redirect_the_push() {
    let owner = Uuid::from_u128(1);
    let original = Uuid::from_u128(2);
    let target = "alice@example.test/Phone";
    for (generation, connection) in [(8, original), (7, Uuid::from_u128(3))] {
        let (session, mut output) = test_online_session(owner, 7, original, "Phone", 1);
        roster_ready(&session, false);
        let (replacement, mut replacement_output) =
            test_online_session(owner, generation, connection, "Phone", 1);
        roster_ready(&replacement, false);
        let captured = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let current = Arc::new(Mutex::new(None));
        let failures = Arc::new(AtomicU64::new(0));
        let delivery = RosterPushDelivery::new(
            PushPorts {
                sessions: vec![(target.into(), session)],
                capture_pause: Some((Arc::clone(&captured), Arc::clone(&release))),
                replacement: Arc::clone(&current),
                ..PushPorts::default()
            },
            Arc::clone(&failures),
            "example.test".into(),
        );
        let send = tokio::spawn(async move {
            deliver_committed_roster_change(
                &delivery,
                owner,
                "alice",
                &change(),
                None,
                &northstar_roster_application::SystemRosterEvents,
            )
            .await
            .unwrap();
        });
        captured.notified().await;
        *current.lock().unwrap() = Some((target.into(), replacement));
        release.notify_one();
        send.await.unwrap();
        assert!(output.try_recv().is_err());
        assert!(replacement_output.try_recv().is_err());
        assert_eq!(failures.load(Ordering::Relaxed), 0);
    }
}
