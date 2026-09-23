//! Presence audience and policy checks for durable SM teardown.

use anyhow::{bail, Result};
use std::future::Future;
use uuid::Uuid;

pub(crate) struct RosterPresenceContact {
    pub(crate) jid: String,
    pub(crate) subscription: String,
}

pub(crate) struct UnavailablePolicy<'a> {
    pub(crate) owner_id: Uuid,
    pub(crate) owner_bare_jid: &'a str,
    pub(crate) active_privacy_list: Option<&'a str>,
    pub(crate) from: &'a str,
    pub(crate) target: &'a str,
    pub(crate) local_domain: &'a str,
}

pub(crate) trait SmTeardownPresenceRepository: Send + Sync {
    fn roster_contacts(
        &self,
        owner_id: Uuid,
    ) -> impl Future<Output = Result<Vec<RosterPresenceContact>>> + Send;

    fn is_blocked(
        &self,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn outbound_privacy_denies(
        &self,
        owner_id: Uuid,
        active_list: Option<&str>,
        candidate: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn enabled_user_id(&self, username: &str) -> impl Future<Output = Result<Option<Uuid>>> + Send;
}

#[derive(Clone)]
pub(crate) struct SmTeardownPresenceService<R> {
    repository: R,
}

impl<R: SmTeardownPresenceRepository> SmTeardownPresenceService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn roster_subscribers(&self, owner_id: Uuid) -> Result<Vec<String>> {
        Ok(self
            .repository
            .roster_contacts(owner_id)
            .await?
            .into_iter()
            .filter(|contact| matches!(contact.subscription.as_str(), "from" | "both"))
            .map(|contact| contact.jid)
            .collect())
    }

    pub(crate) async fn allows_unavailable(&self, policy: UnavailablePolicy<'_>) -> Result<bool> {
        if self
            .repository
            .is_blocked(policy.owner_id, policy.owner_bare_jid, policy.target)
            .await?
        {
            return Ok(false);
        }
        if self
            .repository
            .outbound_privacy_denies(policy.owner_id, policy.active_privacy_list, policy.target)
            .await?
        {
            return Ok(false);
        }
        let Ok(target_jid) = crate::jid::CanonicalJid::parse(policy.target) else {
            bail!("invalid SM teardown presence target");
        };
        if target_jid.domainpart() == policy.local_domain {
            if let Some(username) = target_jid.localpart() {
                let Some(recipient_id) = self.repository.enabled_user_id(username).await? else {
                    return Ok(false);
                };
                if self
                    .repository
                    .is_blocked(recipient_id, &target_jid.bare(), policy.from)
                    .await?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeRepository {
        calls: Arc<Mutex<Vec<&'static str>>>,
        contacts: Vec<(String, String)>,
        outbound_blocked: bool,
        privacy_denied: bool,
        local_user: Option<Uuid>,
        inbound_blocked: bool,
    }

    impl SmTeardownPresenceRepository for FakeRepository {
        async fn roster_contacts(&self, _owner_id: Uuid) -> Result<Vec<RosterPresenceContact>> {
            self.calls.lock().unwrap().push("roster");
            Ok(self
                .contacts
                .iter()
                .map(|(jid, subscription)| RosterPresenceContact {
                    jid: jid.clone(),
                    subscription: subscription.clone(),
                })
                .collect())
        }

        async fn is_blocked(
            &self,
            _owner_id: Uuid,
            _owner_bare_jid: &str,
            candidate: &str,
        ) -> Result<bool> {
            let mut calls = self.calls.lock().unwrap();
            if candidate == "alice@example.test/old" {
                calls.push("inbound_block");
                Ok(self.inbound_blocked)
            } else {
                calls.push("outbound_block");
                Ok(self.outbound_blocked)
            }
        }

        async fn outbound_privacy_denies(
            &self,
            _owner_id: Uuid,
            _active_list: Option<&str>,
            _candidate: &str,
        ) -> Result<bool> {
            self.calls.lock().unwrap().push("privacy");
            Ok(self.privacy_denied)
        }

        async fn enabled_user_id(&self, _username: &str) -> Result<Option<Uuid>> {
            self.calls.lock().unwrap().push("enabled_user");
            Ok(self.local_user)
        }
    }

    fn fixture() -> FakeRepository {
        FakeRepository {
            calls: Arc::default(),
            contacts: Vec::new(),
            outbound_blocked: false,
            privacy_denied: false,
            local_user: None,
            inbound_blocked: false,
        }
    }

    fn policy<'a>(owner_id: Uuid, target: &'a str) -> UnavailablePolicy<'a> {
        UnavailablePolicy {
            owner_id,
            owner_bare_jid: "alice@example.test",
            active_privacy_list: None,
            from: "alice@example.test/old",
            target,
            local_domain: "example.test",
        }
    }

    #[tokio::test]
    async fn roster_audience_includes_only_presence_subscribers_in_order() {
        let mut repository = fixture();
        repository.contacts = vec![
            ("a@example.test".into(), "from".into()),
            ("b@example.test".into(), "to".into()),
            ("c@example.test".into(), "both".into()),
            ("d@example.test".into(), "none".into()),
        ];
        let service = SmTeardownPresenceService::new(repository);
        assert_eq!(
            service.roster_subscribers(Uuid::new_v4()).await.unwrap(),
            vec!["a@example.test".to_owned(), "c@example.test".to_owned()]
        );
    }

    #[tokio::test]
    async fn blocking_and_privacy_short_circuit_before_local_lookup() {
        let owner = Uuid::new_v4();
        let mut repository = fixture();
        repository.outbound_blocked = true;
        let calls = Arc::clone(&repository.calls);
        let service = SmTeardownPresenceService::new(repository);
        assert!(!service
            .allows_unavailable(policy(owner, "bob@example.test"))
            .await
            .unwrap());
        assert_eq!(*calls.lock().unwrap(), ["outbound_block"]);

        let mut repository = fixture();
        repository.privacy_denied = true;
        let calls = Arc::clone(&repository.calls);
        let service = SmTeardownPresenceService::new(repository);
        assert!(!service
            .allows_unavailable(policy(owner, "bob@example.test"))
            .await
            .unwrap());
        assert_eq!(*calls.lock().unwrap(), ["outbound_block", "privacy"]);
    }

    #[tokio::test]
    async fn disabled_or_blocking_local_recipient_is_denied() {
        let owner = Uuid::new_v4();
        let repository = fixture();
        let service = SmTeardownPresenceService::new(repository);
        assert!(!service
            .allows_unavailable(policy(owner, "bob@example.test"))
            .await
            .unwrap());

        let mut repository = fixture();
        repository.local_user = Some(Uuid::new_v4());
        repository.inbound_blocked = true;
        let calls = Arc::clone(&repository.calls);
        let service = SmTeardownPresenceService::new(repository);
        assert!(!service
            .allows_unavailable(policy(owner, "bob@example.test"))
            .await
            .unwrap());
        assert_eq!(
            *calls.lock().unwrap(),
            ["outbound_block", "privacy", "enabled_user", "inbound_block"]
        );
    }

    #[tokio::test]
    async fn allowed_local_and_remote_recipients_follow_distinct_checks() {
        let owner = Uuid::new_v4();
        let mut repository = fixture();
        repository.local_user = Some(Uuid::new_v4());
        let calls = Arc::clone(&repository.calls);
        let service = SmTeardownPresenceService::new(repository);
        assert!(service
            .allows_unavailable(policy(owner, "bob@example.test"))
            .await
            .unwrap());
        assert_eq!(
            *calls.lock().unwrap(),
            ["outbound_block", "privacy", "enabled_user", "inbound_block"]
        );

        let repository = fixture();
        let calls = Arc::clone(&repository.calls);
        let service = SmTeardownPresenceService::new(repository);
        assert!(service
            .allows_unavailable(policy(owner, "bob@remote.test"))
            .await
            .unwrap());
        assert_eq!(*calls.lock().unwrap(), ["outbound_block", "privacy"]);
    }
}
