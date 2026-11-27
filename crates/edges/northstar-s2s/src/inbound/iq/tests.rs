use super::*;
use northstar_pubsub_application::profile::PublicVCard;
use northstar_roster_core::PresenceAccount;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::protocol::iq_visibility::{ExactMessageRoute, IqVisibilityHost};
use roxmltree::Node;
use std::sync::Mutex;
use uuid::Uuid;

const FROM: &str = "alice@remote.test/Phone";
const TO: &str = "bob@example.test/Desktop";
const DISCO: &str = "<iq type='get' id='caps'><query xmlns='http://jabber.org/protocol/disco#info' node='client#hash'/></iq>";

struct Host {
    allows: bool,
    current: bool,
    calls: Mutex<Vec<&'static str>>,
}

impl Host {
    fn new(allows: bool, current: bool) -> Self {
        Self {
            allows,
            current,
            calls: Mutex::default(),
        }
    }

    fn record(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }

    async fn route(&self, raw: &str, to: &str) -> Option<String> {
        let doc = Document::parse(raw).unwrap();
        route_inbound_iq(self, doc.root_element(), raw, FROM, to)
            .await
            .unwrap()
    }
}

impl IqVisibilityHost for Host {
    async fn authorize_iq_resource(&self, _: &LocalIqAdmission<'_>) -> Result<bool> {
        panic!("unexpected local admission")
    }

    fn local_iq_handoff(&self, _: &LocalIqAdmission<'_>, _: Option<&str>) -> bool {
        panic!("unexpected local handoff")
    }

    async fn capture_remote_iq_route(&self, _: &str) -> Result<Option<ExactMessageRoute>> {
        Ok(Some(ExactMessageRoute {
            full_jid: TO.to_owned(),
            account_id: Uuid::from_u128(1),
            auth_generation: 1,
            connection_id: Uuid::from_u128(2),
            node_id: Some("owner-node".to_owned()),
            priority: None,
            available: None,
        }))
    }

    async fn remote_iq_handoff(
        &self,
        route: &ExactMessageRoute,
        _: &str,
        check_only: bool,
    ) -> bool {
        assert_eq!(route.connection_id, Uuid::from_u128(2));
        self.record(if check_only { "admit" } else { "forward" });
        self.allows
    }

    async fn remote_iq_route_current(&self, route: &ExactMessageRoute) -> Result<bool> {
        assert_eq!(route.connection_id, Uuid::from_u128(2));
        self.record("revalidate");
        Ok(self.current)
    }
}

impl InboundHost for Host {
    fn local_domain(&self) -> &str {
        "example.test"
    }
    fn island_mode_enabled(&self) -> bool {
        false
    }
    fn federation_entity_allowed(&self, _: &str) -> bool {
        true
    }
    fn s2s_component_domain_configured(&self, _: &str) -> bool {
        false
    }
    fn s2s_ping_route_enabled(&self) -> bool {
        true
    }
    fn s2s_ping_feature_enabled(&self) -> bool {
        true
    }
    async fn send_to_component(&self, _: &str, _: String) -> bool {
        unreachable!()
    }
    async fn federated_mix_iq(self: Arc<Self>, _: &str, _: String) -> Result<bool> {
        unreachable!()
    }
    async fn federated_mix_message(self: Arc<Self>, _: &str, _: String) -> Result<bool> {
        unreachable!()
    }
    async fn federated_mix_presence(self: Arc<Self>, _: &str, _: String) -> Result<bool> {
        unreachable!()
    }
    async fn federated_muc_presence(
        &self,
        _: &str,
        _: Uuid,
        _: Node<'_, '_>,
        _: &str,
    ) -> Result<Option<String>> {
        unreachable!()
    }
    async fn federated_muc_message(
        &self,
        _: &str,
        _: Uuid,
        _: Node<'_, '_>,
        _: &str,
    ) -> Result<Option<String>> {
        unreachable!()
    }
    async fn federated_muc_iq(
        &self,
        _: &str,
        _: Uuid,
        _: Node<'_, '_>,
        _: &str,
    ) -> Result<Option<String>> {
        unreachable!()
    }
    async fn handle_pubsub_authorization_response(&self, _: &str, _: Node<'_, '_>) -> Result<()> {
        unreachable!()
    }
    async fn route_inbound_message(
        &self,
        _: Node<'_, '_>,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<Option<String>> {
        unreachable!()
    }
    async fn route_inbound_presence(
        &self,
        _: Node<'_, '_>,
        _: &str,
        _: &str,
        _: &str,
        _: Uuid,
    ) -> Result<Option<String>> {
        unreachable!()
    }
    async fn find_enabled_presence_user(&self, _: &str) -> Result<Option<PresenceAccount>> {
        unreachable!()
    }
    async fn is_blocked_for_account(&self, _: Uuid, _: &str, _: &str) -> Result<bool> {
        unreachable!()
    }
    async fn allows_presence(&self, _: Uuid, _: &str) -> Result<bool> {
        unreachable!()
    }
    async fn handle_federated_caps_response(
        &self,
        id: &str,
        _: &str,
        _: Node<'_, '_>,
        _: &str,
    ) -> bool {
        id == "correlated"
    }
    async fn handle_push_delivery_response(&self, _: &str, _: &str, _: &str) -> Result<bool> {
        Ok(false)
    }
    fn cached_disco_result(&self, _: &str, _: &str, _: Option<&str>) -> Option<String> {
        self.record("cache");
        Some("<iq type='result' id='caps'><query/></iq>".to_owned())
    }
    fn sessions_for(&self, _: &str) -> Vec<OnlineSession> {
        unreachable!()
    }
    fn session_entries_for(&self, _: &str) -> Vec<(String, OnlineSession)> {
        Vec::new()
    }
    async fn privacy_allows_iq(&self, _: &OnlineSession, _: &str) -> Result<bool> {
        unreachable!()
    }
    async fn route_s2s_iq_response_to_remote_resource(&self, _: &str, _: &str) {
        unreachable!()
    }
    async fn s2s_remote_recipient_route_exists(&self, _: &str) -> bool {
        unreachable!()
    }
    async fn route_s2s_iq_request_remote(&self, _: &str, _: &str, _: bool) -> bool {
        unreachable!()
    }
    async fn public_vcard(&self, _: &str) -> Result<PublicVCard> {
        unreachable!()
    }
    async fn handle_pubsub_request(
        &self,
        _: &str,
        _: &str,
        _: Node<'_, '_>,
    ) -> Result<PubSubReply> {
        unreachable!()
    }
    async fn pubsub_disco_info(&self, _: &str, _: Option<&str>) -> Result<PubSubReply> {
        unreachable!()
    }
    async fn pubsub_disco_items(&self, _: &str, _: Node<'_, '_>) -> Result<PubSubReply> {
        unreachable!()
    }
    async fn federated_pep_items(&self, _: InboundPepRequest<'_, '_>) -> Result<String> {
        unreachable!()
    }
    async fn federated_pep_subscription(&self, _: InboundPepRequest<'_, '_>) -> Result<String> {
        unreachable!()
    }
    async fn pep_disco_info(&self, _: &str, _: &str, _: Option<&str>) -> Result<Option<String>> {
        unreachable!()
    }
    async fn pep_disco_items(&self, _: &str, _: &str, _: Option<&str>) -> Result<Option<String>> {
        unreachable!()
    }
}

#[tokio::test]
async fn denied_remote_resource_never_reads_the_caps_cache() {
    let host = Host::new(false, true);
    assert!(host
        .route(DISCO, TO)
        .await
        .unwrap()
        .contains("service-unavailable"));
    assert_eq!(*host.calls.lock().unwrap(), ["admit"]);
}

#[tokio::test]
async fn remote_cache_answer_is_discarded_if_the_route_was_replaced() {
    let host = Host::new(true, false);
    assert!(host
        .route(DISCO, TO)
        .await
        .unwrap()
        .contains("service-unavailable"));
    assert_eq!(
        *host.calls.lock().unwrap(),
        ["admit", "cache", "revalidate"]
    );
}

#[tokio::test]
async fn remote_forwarding_checks_once_at_the_owning_node() {
    let host = Host::new(true, true);
    assert!(host
        .route(
            "<iq type='get' id='forward'><query xmlns='test:forward'/></iq>",
            TO
        )
        .await
        .is_none());
    assert_eq!(*host.calls.lock().unwrap(), ["forward"]);
}

#[tokio::test]
async fn server_ping_and_correlated_control_skip_the_resource_gate() {
    let host = Host::new(false, false);
    let result = host
        .route(
            "<iq type='get' id='ping'><ping xmlns='urn:xmpp:ping'/></iq>",
            "example.test",
        )
        .await
        .unwrap();
    assert_eq!(
        Document::parse(&result)
            .unwrap()
            .root_element()
            .attribute("type"),
        Some("result")
    );
    assert!(host
        .route("<iq type='result' id='correlated'/>", TO)
        .await
        .is_none());
    assert!(host.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn denied_uncorrelated_responses_do_not_emit_errors() {
    let host = Host::new(false, true);
    for kind in ["error", "result"] {
        let raw = format!("<iq type='{kind}' id='ordinary'/>");
        assert!(host.route(&raw, TO).await.is_none());
    }
    assert_eq!(*host.calls.lock().unwrap(), ["forward", "forward"]);
}
