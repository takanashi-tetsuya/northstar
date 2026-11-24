use crate::delivery_contract::NodeDeliveryOptions;
use crate::routing::primary_message_options;
use crate::ClusterManager;
use anyhow::Result;
use northstar_message_application::messaging::{ExactMessageRoute, OnlineRouteResult};
use northstar_message_application::telemetry::PersonalMessageTelemetry;
use northstar_stream::outbound::DurableDelivery;
use northstar_xmpp_types::jid::CanonicalJid;
use redis::AsyncCommands;
use std::collections::BTreeMap;
use uuid::Uuid;

mod presence;

impl ClusterManager {
    pub async fn capture_remote_message_routes(
        &self,
        jid: &str,
        account_id: Uuid,
        auth_generation: i64,
    ) -> Result<Vec<ExactMessageRoute>> {
        let Some(pool) = &self.pool else {
            return Ok(Vec::new());
        };
        let target = CanonicalJid::parse(jid)?;
        let bare = target.bare();
        let store = self
            .session_store
            .get()
            .ok_or_else(|| anyhow::anyhow!("cluster session authority pool is unavailable"))?;
        let full_jids: Vec<String> = if target.resourcepart().is_some() {
            vec![target.to_string()]
        } else {
            let mut conn = pool.get().await?;
            conn.smembers(self.key(format!("user_sessions:{bare}")))
                .await?
        };
        let mut routes = Vec::new();
        for full_jid in full_jids {
            let Ok(candidate) = CanonicalJid::parse(&full_jid) else {
                continue;
            };
            if candidate.resourcepart().is_none()
                || candidate.bare() != bare
                || candidate.to_string() != full_jid
            {
                continue;
            }
            let Some(owner) = store
                .session_route_authority(&self.namespace, &full_jid)
                .await?
            else {
                continue;
            };
            if owner.owner_node_id != self.node_id {
                routes.push(ExactMessageRoute {
                    full_jid,
                    account_id,
                    auth_generation,
                    connection_id: owner.connection_uuid,
                    node_id: Some(owner.owner_node_id),
                    priority: None,
                    available: None,
                });
            }
        }
        if let Err(error) = self.read_remote_route_presence(pool, &mut routes).await {
            tracing::warn!(?error, "could not sample remote message route presence");
        }
        Ok(routes)
    }

    pub async fn route_exact_remote_message(
        &self,
        jid: &str,
        routes: &[ExactMessageRoute],
        stanza: &str,
        delivery: Option<DurableDelivery>,
        deliver_all: bool,
        telemetry: &PersonalMessageTelemetry<'_>,
    ) -> OnlineRouteResult {
        let mut groups = BTreeMap::<_, Vec<_>>::new();
        for route in routes {
            if let Some(node) = route
                .node_id
                .as_deref()
                .filter(|node| *node != self.node_id.as_str())
            {
                groups
                    .entry((node, route.account_id, route.auth_generation))
                    .or_default()
                    .push(route);
            }
        }
        let mut result = OnlineRouteResult::default();
        for ((node, account_id, auth_generation), routes) in groups {
            let connections = routes
                .into_iter()
                .map(|route| (route.full_jid.clone(), route.connection_id))
                .collect();
            let mode = exact_route_mode(jid, deliver_all);
            let options = NodeDeliveryOptions {
                expected_user_id: Some(account_id),
                expected_auth_generation: Some(auth_generation),
                exact_message_routes: Some(&connections),
                durable_delivery: delivery,
                ..mode
            };
            let receipt = self
                .send_to_node_receipt(node, jid, stanza, options)
                .await
                .unwrap_or_default();
            if crate::s2s_routing::accepted_cluster_message_delivery(telemetry, node, jid, &receipt)
            {
                result.delivered = true;
                if result.accepted_full_jid.is_none() {
                    result.accepted_full_jid = receipt.accepted_full_jid;
                }
                if !deliver_all {
                    break;
                }
            }
        }
        result
    }
}

/// RFC 6121 headline fanout reaches available resources with a non-negative
/// priority only, as before exact routes; other bare messages use the primary
/// options.
pub(crate) fn exact_route_mode<'a>(jid: &str, deliver_all: bool) -> NodeDeliveryOptions<'a> {
    if deliver_all {
        NodeDeliveryOptions {
            available_nonnegative_only: true,
            ..NodeDeliveryOptions::default()
        }
    } else {
        primary_message_options(jid)
    }
}
