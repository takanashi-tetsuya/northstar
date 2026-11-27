use crate::listener_blocking::wire::{
    checked_control, control, payload, SnapshotEntry, SnapshotRequest, WireTarget,
};
use crate::{supports_exact_control, ClusterControlOutcome, ClusterManager};
use anyhow::Result;
use northstar_roster_application::{
    blocking_mutation::BlockingPresenceTarget, ExactPresenceRoute, RosterActor,
};
use redis::AsyncCommands;

impl ClusterManager {
    pub(crate) async fn request_blocking_snapshot(
        &self,
        node: &str,
        actor: &RosterActor,
        request: &SnapshotRequest,
    ) -> Result<Vec<SnapshotEntry>> {
        let route = ExactPresenceRoute {
            account_id: actor.account_id,
            auth_generation: actor.auth_generation,
            connection_id: actor.connection_id,
            full_jid: actor.full_jid.clone(),
            node_id: Some(self.node_id.clone()),
        };
        let mut envelope = payload(&control(&route, &route), &route);
        envelope["blocking_snapshot"] = serde_json::to_value(request)?;
        let ack = self
            .correlated_control_sender()
            .send_control_to_node_ack(node, &route.full_jid, envelope)
            .await?;
        match ack.control_outcome {
            Some(ClusterControlOutcome::BlockingSnapshot(entries))
                if ack.control_processed == Some(true) =>
            {
                Ok(entries)
            }
            _ => anyhow::bail!("cluster peer rejected the v15 blocking snapshot"),
        }
    }

    pub(crate) async fn send_blocking_presence_change(
        &self,
        node: &str,
        targets: &[BlockingPresenceTarget],
        available: bool,
    ) -> Result<()> {
        let source = &targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("empty blocking presence slice"))?
            .source;
        anyhow::ensure!(
            targets.len() <= northstar_xep_0191::MAX_ITEMS
                && targets.iter().all(|target| target.source == *source),
            "invalid blocking presence slice"
        );
        let mut envelope = payload(&control(source, source), source);
        envelope["available"] = available.into();
        let wire_targets = targets
            .iter()
            .map(|target| {
                let mut target = target.clone();
                if let Some(route) = target
                    .recipient
                    .as_mut()
                    .filter(|route| route.node_id.is_none())
                {
                    route.node_id = Some(self.node_id.clone());
                }
                WireTarget(target)
            })
            .collect::<Vec<_>>();
        envelope["blocking_targets"] = serde_json::to_value(wire_targets)?;
        let ack = self
            .correlated_control_sender()
            .send_control_to_node_ack(node, &source.full_jid, envelope)
            .await?;
        match ack.control_outcome {
            Some(ClusterControlOutcome::BlockingPresence { failed: 0 })
                if ack.control_processed == Some(true) =>
            {
                Ok(())
            }
            Some(ClusterControlOutcome::BlockingPresence { failed }) => {
                anyhow::bail!("cluster peer reported {failed} failed blocking presence handoffs")
            }
            _ => anyhow::bail!("cluster peer rejected the v15 blocking presence slice"),
        }
    }

    pub(crate) async fn send_blocking_presence_recipient(
        &self,
        node: &str,
        target: &BlockingPresenceTarget,
        stanza: &str,
        available: bool,
    ) -> Result<()> {
        let recipient = target
            .recipient
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing blocking recipient"))?;
        let from_listener = target.source.node_id.is_some();
        let mut envelope = payload(&control(&target.source, recipient), recipient);
        let mut target = target.clone();
        target.source.node_id = Some(self.node_id.clone());
        envelope["blocking_recipient"] = serde_json::to_value(WireTarget(target))?;
        envelope["available"] = available.into();
        envelope["stanza"] = stanza.into();
        checked_control(&envelope, &recipient.full_jid, Some(stanza))?;
        if !from_listener {
            return self
                .correlated_control_sender()
                .send_control_to_node(node, &recipient.full_jid, envelope)
                .await;
        }
        // A sequential source listener cannot await a second listener's
        // receipt. Report publish failures here and queue failures there.
        let pool = self
            .pool
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("cluster transport is unavailable"))?;
        let mut connection = pool.get().await?;
        let peer: Option<String> = connection
            .get(self.key(format!("node:{node}:alive")))
            .await?;
        anyhow::ensure!(
            supports_exact_control(peer.as_deref()),
            "cluster peer cannot accept v15 blocking presence"
        );
        let channel = self.key(format!("node:{node}"));
        let subscribers = self
            .signed_publisher()
            .publish_signed(&mut connection, node, &channel, envelope)
            .await?;
        anyhow::ensure!(subscribers > 0, "v15 blocking presence had no subscriber");
        Ok(())
    }

    pub(crate) async fn blocking_route_owner_is_current(
        &self,
        route: &ExactPresenceRoute,
    ) -> Result<bool> {
        let Some(node) = &route.node_id else {
            return Ok(false);
        };
        let store = self
            .session_store
            .get()
            .ok_or_else(|| anyhow::anyhow!("cluster session authority pool is unavailable"))?;
        Ok(store
            .session_route_authority(&self.namespace, &route.full_jid)
            .await?
            .is_some_and(|current| {
                current.owner_node_id == *node && current.connection_uuid == route.connection_id
            }))
    }
}
