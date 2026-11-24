use crate::messaging::{LocalRecipientDecision, MessageRepository, MessageService};
use anyhow::Result;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use uuid::Uuid;

impl<R: MessageRepository> MessageService<R> {
    pub async fn allows_carbon(
        &self,
        account: &str,
        account_id: Uuid,
        connection_id: Uuid,
        active_list: Option<&str>,
        peer: &str,
    ) -> Result<bool> {
        let account = CanonicalJid::parse_bare(account)?;
        let Some(username) = account.localpart() else {
            return Ok(false);
        };
        if !matches!(
            self.resolve_local_recipient(username, account.domainpart(), peer).await?,
            LocalRecipientDecision::Deliver(recipient) if recipient.id == account_id
        ) {
            return Ok(false);
        }
        self.privacy_allows_session(
            account_id,
            connection_id,
            active_list,
            peer,
            PrivacyStanzaKind::Message,
        )
        .await
    }
}
