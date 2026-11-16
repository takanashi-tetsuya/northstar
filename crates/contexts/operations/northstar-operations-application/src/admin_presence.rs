use anyhow::Result;
use std::collections::BTreeSet;
use std::future::Future;
use std::time::Duration;

/// Online and activity sources for administrative presence queries.
pub trait AdminPresenceSources: Send + Sync {
    fn local_online_bare_jids(&self) -> BTreeSet<String>;
    fn local_activity_bare_jids(&self, idle: Duration) -> (BTreeSet<String>, BTreeSet<String>);
    fn cluster_online_bare_jids(&self) -> impl Future<Output = Result<BTreeSet<String>>> + Send;
    fn cluster_activity_bare_jids(
        &self,
        idle_seconds: u64,
        active: bool,
    ) -> impl Future<Output = Result<BTreeSet<String>>> + Send;
}

/// The remote nodes an announcement can reach.
pub trait AnnouncementRoutes: Send + Sync {
    fn local_node_id(&self) -> &str;
    fn account_nodes(&self, account: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
    fn send_to_node_available(
        &self,
        node_id: &str,
        account: &str,
        stanza: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

pub async fn online_bare_jids(sources: &impl AdminPresenceSources) -> Result<BTreeSet<String>> {
    let mut users = sources.local_online_bare_jids();
    users.extend(sources.cluster_online_bare_jids().await?);
    Ok(users)
}

pub async fn activity_bare_jids(
    sources: &impl AdminPresenceSources,
    idle_seconds: u64,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let (mut online, mut active) =
        sources.local_activity_bare_jids(Duration::from_secs(idle_seconds));
    active.extend(
        sources
            .cluster_activity_bare_jids(idle_seconds, true)
            .await?,
    );
    online.extend(active.iter().cloned());
    online.extend(
        sources
            .cluster_activity_bare_jids(idle_seconds, false)
            .await?,
    );
    let idle = online.difference(&active).cloned().collect();
    Ok((active, idle))
}

/// A headline announcement reaches every remote node with an eligible
/// resource; count the account only if one node accepted it.
pub async fn send_remote_announcement(
    routes: &impl AnnouncementRoutes,
    account: &str,
    stanza: &str,
) -> Result<bool> {
    let mut delivered = false;
    for node_id in routes.account_nodes(account).await? {
        if node_id != routes.local_node_id()
            && routes
                .send_to_node_available(&node_id, account, stanza)
                .await?
        {
            delivered = true;
        }
    }
    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn jids(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[derive(Default)]
    struct Presence {
        calls: Mutex<Vec<(u64, bool)>>,
        local_idle: Mutex<Option<Duration>>,
    }

    impl AdminPresenceSources for Presence {
        fn local_online_bare_jids(&self) -> BTreeSet<String> {
            jids(&["local", "shared"])
        }

        fn local_activity_bare_jids(&self, idle: Duration) -> (BTreeSet<String>, BTreeSet<String>) {
            *self.local_idle.lock().unwrap() = Some(idle);
            (
                jids(&["local-idle", "shared"]),
                jids(&["local-active", "shared"]),
            )
        }

        async fn cluster_online_bare_jids(&self) -> Result<BTreeSet<String>> {
            Ok(jids(&["remote", "shared"]))
        }

        async fn cluster_activity_bare_jids(
            &self,
            idle_seconds: u64,
            active: bool,
        ) -> Result<BTreeSet<String>> {
            self.calls.lock().unwrap().push((idle_seconds, active));
            Ok(if active {
                jids(&["remote-active", "shared"])
            } else {
                jids(&["remote-idle", "local-active", "remote-active"])
            })
        }
    }

    #[tokio::test]
    async fn online_set_is_union() {
        assert_eq!(
            online_bare_jids(&Presence::default()).await.unwrap(),
            jids(&["local", "remote", "shared"])
        );
    }

    #[tokio::test]
    async fn activity_sets_and_cluster_call_order() {
        let sources = Presence::default();
        assert_eq!(
            activity_bare_jids(&sources, 42).await.unwrap(),
            (
                jids(&["local-active", "remote-active", "shared"]),
                jids(&["local-idle", "remote-idle"]),
            )
        );
        assert_eq!(
            *sources.local_idle.lock().unwrap(),
            Some(Duration::from_secs(42))
        );
        assert_eq!(
            *sources.calls.lock().unwrap(),
            vec![(42, true), (42, false)]
        );
    }

    #[derive(Default)]
    struct Routes {
        nodes: Vec<String>,
        accepted: BTreeSet<String>,
        lookup_error: bool,
        send_error: Option<String>,
        sent: Mutex<Vec<String>>,
    }

    impl AnnouncementRoutes for Routes {
        fn local_node_id(&self) -> &str {
            "local"
        }

        async fn account_nodes(&self, account: &str) -> Result<Vec<String>> {
            assert_eq!(account, "account");
            anyhow::ensure!(!self.lookup_error, "lookup failed");
            Ok(self.nodes.clone())
        }

        async fn send_to_node_available(
            &self,
            node_id: &str,
            account: &str,
            stanza: &str,
        ) -> Result<bool> {
            assert_eq!(account, "account");
            assert_eq!(stanza, "<message/>");
            self.sent.lock().unwrap().push(node_id.to_owned());
            anyhow::ensure!(self.send_error.as_deref() != Some(node_id), "send failed");
            Ok(self.accepted.contains(node_id))
        }
    }

    fn routes() -> Routes {
        Routes {
            nodes: ["local", "first", "second", "third"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ..Routes::default()
        }
    }

    #[tokio::test]
    async fn announcement_skips_local_and_visits_every_remote() {
        let routes = Routes {
            accepted: jids(&["first"]),
            ..routes()
        };
        assert!(send_remote_announcement(&routes, "account", "<message/>")
            .await
            .unwrap());
        assert_eq!(
            *routes.sent.lock().unwrap(),
            vec!["first", "second", "third"]
        );
    }

    #[tokio::test]
    async fn announcement_returns_false_when_none_accept() {
        let routes = routes();
        assert!(!send_remote_announcement(&routes, "account", "<message/>")
            .await
            .unwrap());
        assert_eq!(
            *routes.sent.lock().unwrap(),
            vec!["first", "second", "third"]
        );
        assert!(
            !send_remote_announcement(&Routes::default(), "account", "<message/>")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn announcement_send_error_stops_later_nodes() {
        let routes = Routes {
            accepted: jids(&["first"]),
            send_error: Some("second".to_owned()),
            ..routes()
        };
        let error = send_remote_announcement(&routes, "account", "<message/>")
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "send failed");
        assert_eq!(*routes.sent.lock().unwrap(), vec!["first", "second"]);
    }

    #[tokio::test]
    async fn announcement_lookup_error_is_returned() {
        let routes = Routes {
            lookup_error: true,
            ..routes()
        };
        let error = send_remote_announcement(&routes, "account", "<message/>")
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "lookup failed");
        assert!(routes.sent.lock().unwrap().is_empty());
    }
}
