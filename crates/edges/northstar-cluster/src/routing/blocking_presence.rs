use crate::ClusterManager;
use anyhow::Result;

impl ClusterManager {
    /// Ask another node that owns resources of `owner` to emit those exact
    /// resources' polite-blocking presence transition.
    pub async fn send_blocking_presence_change(
        &self,
        node_id: &str,
        owner: &str,
        targets: &[String],
        patterns: &[String],
        available: bool,
    ) -> Result<()> {
        let (Some(pool), _) = (&self.pool, &self.client) else {
            return Ok(());
        };
        let owner = northstar_xmpp_types::jid::canonicalize_bare(owner)?;
        if targets.len() > northstar_xep_0191::MAX_ITEMS
            || patterns.len() > northstar_xep_0191::MAX_ITEMS
        {
            anyhow::bail!("too many blocking presence targets");
        }
        let targets = targets
            .iter()
            .map(|target| northstar_xmpp_types::jid::canonicalize(target))
            .collect::<Result<Vec<_>>>()?;
        let patterns = patterns
            .iter()
            .map(|pattern| northstar_xmpp_types::jid::canonicalize(pattern))
            .collect::<Result<Vec<_>>>()?;
        let payload = serde_json::json!({
            "target": owner,
            "blocking_presence_change": true,
            "blocking_targets": targets,
            "blocking_patterns": patterns,
            "available": available,
        });
        let mut conn = pool.get().await?;
        let channel = self.key(format!("node:{node_id}"));
        let _ = self
            .publish_signed(&mut conn, node_id, &channel, payload)
            .await?;
        Ok(())
    }
}
