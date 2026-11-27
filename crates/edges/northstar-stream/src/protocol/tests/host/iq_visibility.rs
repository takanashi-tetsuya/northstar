use super::TestHost;
use crate::local_routes::{session::test_online_session, session_table::LocalSessionTable};
use crate::protocol::iq_visibility::{ExactMessageRoute, IqVisibilityHost, LocalIqAdmission};
use crate::protocol::Action;
use anyhow::Result;
use northstar_auth_application::authentication::AuthenticatedAccount;
use northstar_protocol_runtime::caps::{CapsKey, VerifiedCapsSummary};
use northstar_roster_application::{
    CommunicationDecision, CommunicationPolicyQuery, CommunicationPolicyReader,
};
use northstar_session_core::LocalCapsEpoch;
use roxmltree::Document;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

const TARGET: &str = "bob@example.test/Phone";
const PEER: &str = "alice@example.test/Desktop";
const CAPS: &str = "<iq to='bob@example.test/Phone' type='get' id='caps'><query xmlns='http://jabber.org/protocol/disco#info' node='client#hash'/></iq>";

impl CommunicationPolicyReader for TestHost {
    async fn read_communication_policies(
        &self,
        queries: &[CommunicationPolicyQuery],
    ) -> Result<Vec<CommunicationDecision>> {
        assert!(queries.iter().all(|query| query.peer != "example.test"));
        Ok(vec![CommunicationDecision::Allow; queries.len()])
    }
}

impl IqVisibilityHost for TestHost {
    async fn authorize_iq_resource(&self, admission: &LocalIqAdmission<'_>) -> Result<bool> {
        let policy = admission.policy();
        if policy.peer == "race@example.test/Desktop" {
            let (replacement, _) =
                test_online_session(policy.account_id, 2, Uuid::new_v4(), "Phone", 4);
            self.routes.insert(TARGET.to_owned(), replacement);
        }
        Ok(!policy.expects_active && !admission.requires_subscription())
    }

    fn local_iq_handoff(&self, admission: &LocalIqAdmission<'_>, stanza: Option<&str>) -> bool {
        admission.handoff(&LocalSessionTable::new(Arc::clone(&self.routes)), stanza)
    }

    async fn capture_remote_iq_route(&self, _: &str) -> Result<Option<ExactMessageRoute>> {
        Ok(None)
    }

    async fn remote_iq_handoff(&self, _: &ExactMessageRoute, _: &str, _: bool) -> bool {
        panic!("unexpected remote IQ handoff")
    }

    async fn remote_iq_route_current(&self, _: &ExactMessageRoute) -> Result<bool> {
        panic!("unexpected remote IQ route check")
    }
}

#[tokio::test]
async fn cached_caps_require_the_resource_policy_even_with_a_directed_grant() {
    let host = TestHost::new();
    let mut requester = host.session();
    requester.full_jid = Some(PEER.to_owned());
    let (target, mut output) = test_online_session(Uuid::new_v4(), 2, Uuid::new_v4(), "Phone", 4);
    target.directed_presence.insert(PEER.to_owned());
    let key = CapsKey {
        algorithm: "sha-1".to_owned(),
        node: "client".to_owned(),
        version: "hash".to_owned(),
    };
    let summary = Arc::new(VerifiedCapsSummary::new(
        false,
        false,
        String::new(),
        Vec::new(),
    ));
    let now = Instant::now();
    host.caps_cache.insert(
        key.clone(),
        "<query xmlns='http://jabber.org/protocol/disco#info'/>".to_owned(),
        Arc::clone(&summary),
        now,
    );
    host.caps.observe_local(
        TARGET.to_owned(),
        LocalCapsEpoch::new(target.connection_id, 0),
        Some(key),
        Some(summary),
        now,
    );
    host.routes.insert(TARGET.to_owned(), target.clone());
    let document = Document::parse(CAPS).unwrap();
    *target.privacy_active.write().unwrap() = Some("deny".to_owned());
    assert!(matches!(
        requester.iq(document.root_element(), CAPS).await.unwrap(),
        Action::Send(xml) if xml.contains("service-unavailable")
    ));
    *target.privacy_active.write().unwrap() = None;
    assert!(matches!(
        requester.iq(document.root_element(), CAPS).await.unwrap(),
        Action::Send(xml) if xml.contains("type='result'") || xml.contains("type=\"result\"")
    ));
    assert!(output.try_recv().is_err());
}

#[tokio::test]
async fn route_replacement_during_policy_read_cannot_receive_the_iq() {
    let host = TestHost::new();
    let mut requester = host.session();
    requester.full_jid = Some("race@example.test/Desktop".to_owned());
    let (target, mut output) = test_online_session(Uuid::new_v4(), 2, Uuid::new_v4(), "Phone", 4);
    target
        .directed_presence
        .insert("race@example.test".to_owned());
    host.routes.insert(TARGET.to_owned(), target);
    let document = Document::parse(CAPS).unwrap();
    assert!(matches!(
        requester.iq(document.root_element(), CAPS).await.unwrap(),
        Action::Send(xml) if xml.contains("service-unavailable")
    ));
    assert!(output.try_recv().is_err());
}

#[tokio::test]
async fn explicitly_addressed_server_request_skips_user_policy() {
    let host = TestHost::new();
    let mut requester = host.session();
    requester.full_jid = Some(PEER.to_owned());
    requester.authenticated = Some(AuthenticatedAccount {
        id: Uuid::new_v4(),
        auth_generation: 0,
        username: "alice".to_owned(),
    });
    let raw = "<iq to='example.test' type='get' id='server'><query xmlns='test:unknown'/></iq>";
    let document = Document::parse(raw).unwrap();
    assert!(matches!(
        requester.iq(document.root_element(), raw).await.unwrap(),
        Action::Send(xml) if xml.contains("feature-not-implemented")
    ));
}
