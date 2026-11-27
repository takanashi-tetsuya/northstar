use super::ServerNode;
use anyhow::Result;
use northstar_cluster::{presence_routing::PresenceProbeTelemetry, ExactControlKind};
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_roster_application::probe_decision::{PresenceRoute, ProbeQuery, ProbeStatus};
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount, RosterActor};
use northstar_roster_xmpp::exact_presence::{ExactPresenceHost, PresenceEffect};
use northstar_roster_xmpp::presence_delivery::{answer_local_probe, replay_to_captured_routes};
use northstar_stream::outbound::PresenceDelivery;
use std::sync::atomic::Ordering;

impl ExactPresenceHost for ServerNode {
    async fn capture_presence_routes(
        &self,
        target: &str,
        account: &PresenceAccount,
        available_only: bool,
    ) -> Result<Vec<PresenceRoute>> {
        let table = self.session.live().sessions();
        let mut routes: Vec<_> = table
            .session_entries_for(target)
            .into_iter()
            .filter(|(_, session)| {
                session.user_id == account.id
                    && session.auth_generation == account.auth_generation
                    && (!available_only || session.available.load(Ordering::Acquire))
            })
            .map(|(full_jid, session)| PresenceRoute {
                exact: ExactPresenceRoute {
                    account_id: session.user_id,
                    auth_generation: session.auth_generation,
                    connection_id: session.connection_id,
                    full_jid,
                    node_id: None,
                },
                active_list: session.privacy_active_snapshot(),
            })
            .collect();
        let remote = self
            .cluster
            .capture_remote_message_routes(target, account.id, account.auth_generation)
            .await?
            .into_iter()
            .filter(|route| !available_only || route.available == Some(true))
            .filter(|route| {
                routes
                    .iter()
                    .all(|local| local.exact.full_jid != route.full_jid)
            })
            .map(|route| PresenceRoute {
                exact: ExactPresenceRoute {
                    account_id: route.account_id,
                    auth_generation: route.auth_generation,
                    connection_id: route.connection_id,
                    full_jid: route.full_jid,
                    node_id: route.node_id,
                },
                active_list: None,
            })
            .collect::<Vec<_>>();
        routes.extend(remote);
        Ok(routes)
    }

    async fn send_presence_route(
        &self,
        source: &RosterActor,
        recipient: &PresenceRoute,
        stanza: &str,
        effect: PresenceEffect,
        available_only: bool,
    ) -> Result<bool> {
        let table = self.session.live().sessions();
        let source_route = ExactMessageRoute {
            full_jid: source.full_jid.clone(),
            account_id: source.account_id,
            auth_generation: source.auth_generation,
            connection_id: source.connection_id,
            node_id: None,
            priority: None,
            available: None,
        };
        if table
            .with_exact_message_route(&source_route, |_| ())
            .is_none()
        {
            return Ok(false);
        }
        let route = &recipient.exact;
        let (scope, sequence) = match effect {
            PresenceEffect::Broadcast { source_epoch } => {
                (PresenceDelivery::Status { source_epoch }, source_epoch)
            }
            PresenceEffect::CurrentReplay | PresenceEffect::ProbeResponse => {
                (PresenceDelivery::ProbeReply, None)
            }
        };
        if route.node_id.is_some() {
            let kind = match effect {
                PresenceEffect::Broadcast { .. } => {
                    if roxmltree::Document::parse(stanza)?
                        .root_element()
                        .attribute("type")
                        == Some("unavailable")
                    {
                        ExactControlKind::UnavailablePresence
                    } else {
                        ExactControlKind::AvailablePresence
                    }
                }
                PresenceEffect::CurrentReplay => ExactControlKind::CurrentPresenceReplay,
                PresenceEffect::ProbeResponse => ExactControlKind::ProbeResponse,
            };
            return self
                .cluster
                .send_exact_presence(source, route, stanza, kind, available_only, sequence)
                .await;
        }
        let route = ExactMessageRoute {
            full_jid: route.full_jid.clone(),
            account_id: route.account_id,
            auth_generation: route.auth_generation,
            connection_id: route.connection_id,
            node_id: None,
            priority: None,
            available: None,
        };
        Ok(table.with_exact_message_route(&route, |current| {
            (!available_only || current.available.load(Ordering::Acquire))
                && (matches!(effect, PresenceEffect::Broadcast { .. })
                    && source.account_id == route.account_id
                    || current.privacy_active_snapshot() == recipient.active_list)
                && current
                    .sender
                    .try_send_presence(stanza.to_owned(), scope)
                    .is_ok()
        }) == Some(true))
    }

    async fn answer_presence_probe(
        &self,
        owner: &PresenceAccount,
        target: &str,
        requester: &RosterActor,
        active_list: Option<String>,
        id: Option<&str>,
    ) -> Result<()> {
        answer_local_probe(self, owner, target, requester, active_list, id).await
    }

    async fn replay_presence_to_routes(
        &self,
        owner: &PresenceAccount,
        target: &str,
        recipient: &str,
        routes: &[PresenceRoute],
    ) -> Result<()> {
        replay_to_captured_routes(self, owner, target, recipient, routes).await
    }

    async fn request_captured_presence(
        &self,
        query: ProbeQuery<'_>,
        owners: &[PresenceRoute],
    ) -> Result<Option<ProbeStatus>> {
        if query.explicit {
            self.cluster
                .delegate_authorized_full_presence_probe_remote(query, owners)
                .await
        } else {
            self.cluster
                .replay_current_presence_from_remote_owners(
                    query,
                    owners,
                    &PresenceProbeTelemetry::new(
                        &self.metrics.cluster_presence_probe_failures_total,
                    ),
                )
                .await
        }
    }
}
