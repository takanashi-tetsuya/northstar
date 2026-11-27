use crate::node::ServerNode;
use anyhow::Result;
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader,
};
use northstar_roster_postgres::privacy::PostgresPrivacyRepository;
use northstar_stream::protocol::iq_visibility::{IqVisibilityHost, LocalIqAdmission};
use northstar_xmpp_types::jid::CanonicalJid;

impl CommunicationPolicyReader for ServerNode {
    async fn read_communication_policies(
        &self,
        queries: &[CommunicationPolicyQuery],
    ) -> Result<Vec<CommunicationDecision>> {
        PostgresPrivacyRepository::new(self.pool.clone())
            .read_communication_policies(queries)
            .await
    }
}

impl IqVisibilityHost for ServerNode {
    async fn authorize_iq_resource(&self, admission: &LocalIqAdmission<'_>) -> Result<bool> {
        self.message
            .message_service()
            .allows_resource_stanza(admission.policy(), admission.requires_subscription())
            .await
    }

    fn local_iq_handoff(&self, admission: &LocalIqAdmission<'_>, stanza: Option<&str>) -> bool {
        admission.handoff(self.session.live().sessions(), stanza)
    }

    async fn capture_remote_iq_route(&self, full_jid: &str) -> Result<Option<ExactMessageRoute>> {
        if !self.cluster.is_enabled() {
            return Ok(None);
        }
        let target = CanonicalJid::parse(full_jid)?;
        let Some(username) = target.localpart().filter(|_| {
            target.resourcepart().is_some() && target.domainpart() == self.config.domain
        }) else {
            return Ok(None);
        };
        let Some(account) = self
            .roster
            .presence_service()
            .find_enabled_user(username)
            .await?
        else {
            return Ok(None);
        };
        Ok(self
            .cluster
            .capture_remote_message_routes(full_jid, account.id, account.auth_generation)
            .await?
            .into_iter()
            .next())
    }

    async fn remote_iq_handoff(
        &self,
        route: &ExactMessageRoute,
        stanza: &str,
        admission_only: bool,
    ) -> bool {
        self.cluster
            .handoff_exact_iq(route, stanza, admission_only)
            .await
    }

    async fn remote_iq_route_current(&self, route: &ExactMessageRoute) -> Result<bool> {
        Ok(self
            .capture_remote_iq_route(&route.full_jid)
            .await?
            .is_some_and(|current| {
                current.account_id == route.account_id
                    && current.auth_generation == route.auth_generation
                    && current.connection_id == route.connection_id
                    && current.node_id == route.node_id
            }))
    }
}
