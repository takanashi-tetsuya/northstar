use super::RemoteRouteFailure;
use crate::listener_blocking::wire::{SnapshotEntry, SnapshotRequest, SNAPSHOT_PAGE};
use crate::ClusterManager;
use anyhow::Result;
use northstar_roster_application::{blocking_mutation::BlockingPresenceTarget, RosterActor};

impl ClusterManager {
    pub(crate) async fn capture_remote_blocking_routes(
        &self,
        actor: &RosterActor,
        patterns: Option<Vec<String>>,
    ) -> (Vec<SnapshotEntry>, Vec<RemoteRouteFailure>) {
        let Some(security) = self.security.as_ref().filter(|_| self.is_enabled()) else {
            return (Vec::new(), Vec::new());
        };
        let mut nodes = security.peer_node_ids();
        nodes.sort_unstable();
        let mut captured = Vec::new();
        let mut failures = Vec::new();
        // Capture pages one node at a time. A failed node cannot discard the
        // routes already sampled on the other nodes.
        for node in nodes.into_iter().filter(|node| *node != self.node_id) {
            let mut request = SnapshotRequest {
                patterns: patterns.clone(),
                after: None,
            };
            if let Err(error) = self
                .capture_blocking_node(&node, actor, &mut request, &mut captured)
                .await
            {
                failures.push(RemoteRouteFailure {
                    node_id: node,
                    error,
                });
            }
        }
        (captured, failures)
    }

    async fn capture_blocking_node(
        &self,
        node: &str,
        actor: &RosterActor,
        request: &mut SnapshotRequest,
        captured: &mut Vec<SnapshotEntry>,
    ) -> Result<()> {
        loop {
            let entries = self.request_blocking_snapshot(node, actor, request).await?;
            let mut previous = request
                .after
                .as_ref()
                .map(|(full, directed)| (full.as_str(), directed.as_deref()));
            anyhow::ensure!(
                entries.len() <= SNAPSHOT_PAGE,
                "oversized blocking snapshot page"
            );
            for entry in &entries {
                anyhow::ensure!(
                    entry.route.node_id.as_deref() == Some(node)
                        && previous.is_none_or(|key| entry.key() > key),
                    "invalid blocking snapshot order or route owner"
                );
                previous = Some(entry.key());
            }
            let done = entries.len() < SNAPSHOT_PAGE;
            request.after =
                previous.map(|(full, directed)| (full.to_owned(), directed.map(str::to_owned)));
            captured.extend(entries);
            if done {
                return Ok(());
            }
        }
    }

    pub(crate) async fn route_remote_blocking_presence_change(
        &self,
        targets: &[BlockingPresenceTarget],
        available: bool,
    ) -> Vec<RemoteRouteFailure> {
        let Some(node) = targets
            .first()
            .and_then(|target| target.source.node_id.as_deref())
        else {
            return Vec::new();
        };
        send_blocking_pages(node, targets, |page| {
            self.send_blocking_presence_change(node, page, available)
        })
        .await
    }
}

pub(crate) async fn send_blocking_pages<'a, F>(
    node: &str,
    group: &'a [BlockingPresenceTarget],
    mut send: impl FnMut(&'a [BlockingPresenceTarget]) -> F,
) -> Vec<RemoteRouteFailure>
where
    F: std::future::Future<Output = Result<()>>,
{
    let mut failures = Vec::new();
    // Bound bytes even for maximum-length source, destination and grant JIDs.
    for page in group.chunks(64) {
        if let Err(error) = send(page).await {
            failures.push(RemoteRouteFailure {
                node_id: node.to_owned(),
                error,
            });
        }
    }
    failures
}
