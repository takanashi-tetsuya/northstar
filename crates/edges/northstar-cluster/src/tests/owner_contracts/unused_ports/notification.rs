use super::UnusedPorts;
use northstar_roster_application::notification_admission::{
    NotificationAdmission, NotificationRecipient, NotificationSource,
};

impl NotificationAdmission for UnusedPorts {
    async fn authorize_notification(
        &self,
        _: NotificationRecipient<'_>,
        _: NotificationSource<'_>,
    ) -> anyhow::Result<bool> {
        unreachable!("this fixture does not send PubSub notifications")
    }
}
