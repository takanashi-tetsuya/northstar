use super::{Action, ProtocolSession};
use anyhow::Result;
use northstar_roster_application::privacy::{PrivacyRepository, PrivacyService};
use roxmltree::Node;
use std::sync::atomic::Ordering;

impl ProtocolSession {
    pub(crate) async fn privacy_get(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        northstar_roster_xmpp::privacy::privacy_get(self, id, root, query)
            .await
            .map(Action::Send)
    }

    pub(crate) async fn privacy_set(
        &self,
        id: &str,
        root: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let (response, current_push) =
            northstar_roster_xmpp::privacy::privacy_set(self, id, root, query).await?;
        Ok(match current_push {
            Some(push) => Action::SendMany(vec![response, push]),
            None => Action::Send(response),
        })
    }
}

impl northstar_roster_xmpp::privacy::PrivacySession for ProtocolSession {
    fn privacy_full_jid(&self) -> Option<&str> {
        self.full_jid.as_deref()
    }

    fn privacy_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    fn privacy_service(&self) -> &PrivacyService<impl PrivacyRepository> {
        self.state.privacy_service()
    }

    fn privacy_mark_requested(&self) {
        self.privacy_requested.store(true, Ordering::Release);
    }

    fn privacy_active_list(&self) -> Option<String> {
        self.privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn privacy_set_active_list(&self, name: Option<String>) {
        *self
            .privacy_active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = name;
    }

    fn privacy_local_resources(&self, account: &str) -> usize {
        self.state.sessions_for(account).len()
    }

    async fn privacy_has_remote_resources(&self, account: &str) -> Result<bool> {
        self.state.account_has_remote_resources(account).await
    }

    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.state.sessions_for(account).iter().any(|session| {
            session
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_deref()
                == Some(name)
        })
    }

    async fn privacy_push_change(&self, account: &str, name: &str, base: &str) -> Option<String> {
        let mut current_push = None;
        for (jid, session) in self.state.session_entries_for(account) {
            if !session.privacy_requested.load(Ordering::Acquire) {
                continue;
            }
            let push = crate::services::xml_util::set_to(base, &jid);
            if session.connection_id == self.connection_id {
                current_push = Some(push);
            } else if let Err(error) = session.sender.try_send(push) {
                // The mutation has already committed.  Keeping this resource
                // alive after dropping its ordered IQ push would let the
                // client continue with a stale privacy-list view.  Force a
                // reconnect so its next query observes the authoritative
                // state instead of allowing later pushes to cross this gap.
                session.sender.disconnect_backpressured_transport();
                session.disconnect.cancel();
                self.state.post_accept_failure_telemetry().record_failure();
                tracing::warn!(
                    %jid,
                    list = %name,
                    ?error,
                    "XEP-0016 privacy-list push queue was unavailable; disconnecting stale resource"
                );
            }
        }
        match self.state.route_remote_privacy_push(account, base).await {
            Ok(failures) => {
                for failure in failures {
                    tracing::warn!(
                        error = ?failure.error,
                        node_id = %failure.node_id,
                        list = %name,
                        "clustered XEP-0016 push failed"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(?error, list = %name, "could not enumerate nodes for XEP-0016 push")
            }
        }
        current_push
    }
}
