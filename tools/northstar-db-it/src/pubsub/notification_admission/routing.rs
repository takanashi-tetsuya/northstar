use super::{DOMAIN, READER};
use northstar_auth_postgres::users::User;
use northstar_pubsub_xmpp::{
    notification_delivery::PubSubNotificationPorts,
    pep_last_items::{PepLastItemsContext, PepLastItemsPorts},
};
use northstar_roster_application::notification_admission::{
    NotificationAdmission, NotificationHandoff, NotificationRecipient, NotificationSource,
};
use northstar_session_application::LocalCapsEpoch;
use northstar_stream::{
    local_routes::{session::test_online_session, session_table::LocalSessionTable},
    outbound::OutboundItem,
};
use northstar_workflows::pubsub_repository::{test_pubsub_service, PostgresPubSubRepository};
use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

pub(super) struct Ports(PostgresPubSubRepository);

impl NotificationAdmission for Ports {
    async fn authorize_notification(
        &self,
        recipient: NotificationRecipient<'_>,
        source: NotificationSource<'_>,
    ) -> anyhow::Result<bool> {
        self.0.authorize_notification(recipient, source).await
    }
}

impl PubSubNotificationPorts for Ports {
    async fn remote_nodes(&self, _: &str) -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
    }

    async fn send_pubsub_notification(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<Uuid>,
    ) -> anyhow::Result<NotificationHandoff> {
        unreachable!("this fixture has no remote nodes")
    }

    fn federation_domain_allowed(&self, _: &str) -> bool {
        false
    }

    async fn send_federated(&self, _: &str, _: String, _: Option<String>) -> bool {
        unreachable!("this fixture delivers to the local domain")
    }
}

impl PepLastItemsPorts for Ports {
    type CapsSnapshot = ();

    fn caps_snapshot(&self, _: &str) -> Option<Self::CapsSnapshot> {
        None
    }

    fn caps_snapshot_local_epoch(&self, _: &Self::CapsSnapshot) -> Option<LocalCapsEpoch> {
        unreachable!("this fixture has no CAPS observations")
    }

    fn caps_snapshot_notify_nodes(&self, _: Self::CapsSnapshot) -> Vec<String> {
        unreachable!("this fixture has no CAPS observations")
    }

    fn remove_local_caps_epoch(&self, _: &str, _: LocalCapsEpoch) {
        unreachable!("this fixture has no CAPS observations")
    }
}

pub(super) fn context(
    pool: &PgPool,
    reader: &User,
    connection_id: Uuid,
    active_list: Option<&str>,
) -> (
    PepLastItemsContext<PostgresPubSubRepository, Ports>,
    mpsc::Receiver<OutboundItem>,
) {
    let sessions = LocalSessionTable::default();
    let (session, output) =
        test_online_session(reader.id, reader.auth_generation, connection_id, "phone", 4);
    *session.privacy_active.write().unwrap() = active_list.map(str::to_owned);
    sessions.insert(READER.to_owned(), session);
    (
        PepLastItemsContext::new(
            test_pubsub_service(pool.clone(), DOMAIN),
            sessions,
            DOMAIN.to_owned(),
            Ports(PostgresPubSubRepository::new(pool.clone(), DOMAIN)),
        ),
        output,
    )
}
