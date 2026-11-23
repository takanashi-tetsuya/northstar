use super::*;
use northstar_room_application::muc_service::LiveAudience;
use northstar_room_core::occupancy::{
    MucOccupantRoute, MUC_EXACT_ROUTE_ENVELOPE_VERSION, MUC_ROUTE_ENVELOPE_LIMIT,
};
use std::collections::BTreeMap;

const SIGNED_ENVELOPE_HEADROOM: usize = 16_384;

impl ClusterManager {
    pub async fn send_to_muc_audience(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: Option<&str>,
        audience: &LiveAudience,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let real_sender = real_sender
            .map(northstar_xmpp_types::jid::canonicalize)
            .transpose()?;
        let room_jid = northstar_xmpp_types::jid::canonicalize_bare(room_jid)?;
        let mut nodes = BTreeMap::<&str, Vec<&MucOccupantRoute>>::new();
        for (node, route) in audience.routes() {
            if node != &self.node_id {
                nodes.entry(node.as_str()).or_default().push(route);
            }
        }
        if nodes.is_empty() {
            return Ok(());
        }
        let mut conn = pool.get().await?;
        let mut first_error = None;
        for (node, routes) in nodes {
            let channel = self.key(format!("node:{node}"));
            for payload in
                exact_broadcast_payloads(&room_jid, stanza, real_sender.as_deref(), &routes)
            {
                if let Err(error) = self
                    .publish_signed(&mut conn, node, &channel, payload)
                    .await
                {
                    first_error.get_or_insert_with(|| {
                        error.context(format!("MUC volatile fan-out to node {node} failed"))
                    });
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn exact_broadcast_payload(
    room_jid: &str,
    stanza: &str,
    real_sender: Option<&str>,
    routes: &[&MucOccupantRoute],
) -> serde_json::Value {
    serde_json::json!({
        "target": room_jid,
        "stanza": stanza,
        "muc_broadcast": true,
        "real_sender": real_sender,
        "envelope_version": MUC_EXACT_ROUTE_ENVELOPE_VERSION,
        "audience": routes,
    })
}

fn exact_broadcast_payloads<'a>(
    room_jid: &'a str,
    stanza: &'a str,
    real_sender: Option<&'a str>,
    routes: &'a [&'a MucOccupantRoute],
) -> impl Iterator<Item = serde_json::Value> + 'a {
    let mut pending: Vec<_> = routes.chunks(MUC_ROUTE_ENVELOPE_LIMIT).rev().collect();
    std::iter::from_fn(move || {
        while let Some(chunk) = pending.pop() {
            let payload = exact_broadcast_payload(room_jid, stanza, real_sender, chunk);
            if chunk.len() > 1
                && payload.to_string().len() > MAX_CLUSTER_PAYLOAD_BYTES - SIGNED_ENVELOPE_HEADROOM
            {
                let (left, right) = chunk.split_at(chunk.len() / 2);
                pending.extend([right, left]);
            } else {
                return Some(payload);
            }
        }
        None
    })
}

#[cfg(test)]
mod tests;
