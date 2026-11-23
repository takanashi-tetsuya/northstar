use super::*;
use crate::tests::{
    fixture::{Call, Context, LocalSession},
    reflection_host,
};
use northstar_stream::outbound::{OutboundItem, OutboundSender};
use std::sync::atomic::Ordering;
use tokio::sync::mpsc::{self, Receiver};
use tokio_util::sync::CancellationToken;

const CHANNEL: &str = "room@mix.remote.test";
const DOMAIN: &str = "mix.remote.test";
const RECIPIENT: &str = "bob@local.test";
const PHONE: &str = "bob@local.test/phone";
const DESK: &str = "bob@local.test/desk";
const ACCOUNT: Uuid = Uuid::from_u128(81);

fn subscribe(context: &Context, node: &str, user_id: Uuid) {
    *context.state.reflection_membership.lock().unwrap() = Some(PamMembership {
        id: Uuid::new_v4(),
        user_id,
        channel_jid: CHANNEL.into(),
        participant_id: Some("receiver".into()),
        state: "joined".into(),
        request_id: None,
        client_request_id: None,
        requester_full_jid: None,
        subscriptions: vec![node.into()],
    });
}

fn add_route(context: &Context, full_jid: &str) -> Receiver<OutboundItem> {
    let (tx, rx) = mpsc::channel(4);
    context.state.sessions.lock().unwrap().push((
        full_jid.into(),
        LocalSession {
            sender: OutboundSender::new(tx),
            disconnect: CancellationToken::new(),
        },
    ));
    rx
}

fn presence_error(to: &str) -> String {
    format!("<presence type='error' from='{CHANNEL}' to='{to}'><error type='auth'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>")
}

#[test]
fn only_error_presence_takes_the_error_path() {
    assert_eq!(
        ReflectedPresence::classify("error"),
        ReflectedPresence::Error
    );
    for kind in ["available", "unavailable", "probe"] {
        assert_eq!(
            ReflectedPresence::classify(kind),
            ReflectedPresence::Reflection
        );
    }
}

#[tokio::test]
async fn reflected_presence_error_checks_node_auth_account_caps_and_exact_resource() {
    let context = Context::new(1);
    let host = reflection_host(context.clone());
    let mut phone = add_route(&context, PHONE);
    let mut desk = add_route(&context, DESK);
    let raw = presence_error(PHONE);

    subscribe(&context, NODE_MESSAGES, ACCOUNT);
    assert!(federated_mix_presence(host.clone(), DOMAIN, raw.clone())
        .await
        .unwrap());
    subscribe(&context, NODE_PRESENCE, ACCOUNT);
    assert!(
        federated_mix_presence(host.clone(), "forged.test", raw.clone())
            .await
            .is_err()
    );
    let unbound = raw.replace(CHANNEL, DOMAIN);
    assert!(federated_mix_presence(host.clone(), DOMAIN, unbound)
        .await
        .unwrap());
    context
        .state
        .reflection_blocked
        .store(true, Ordering::SeqCst);
    assert!(federated_mix_presence(host.clone(), DOMAIN, raw.clone())
        .await
        .unwrap());
    context
        .state
        .reflection_blocked
        .store(false, Ordering::SeqCst);
    assert!(context.state.calls().is_empty());

    subscribe(&context, NODE_PRESENCE, Uuid::new_v4());
    assert!(federated_mix_presence(host.clone(), DOMAIN, raw.clone())
        .await
        .unwrap());
    subscribe(&context, NODE_PRESENCE, ACCOUNT);
    *context.state.capability.lock().unwrap() = MixSessionCapability::Unknown;
    assert!(federated_mix_presence(host.clone(), DOMAIN, raw.clone())
        .await
        .unwrap());
    assert!(phone.try_recv().is_err());
    assert!(desk.try_recv().is_err());

    *context.state.capability.lock().unwrap() = MixSessionCapability::Supported;
    assert!(federated_mix_presence(host, DOMAIN, raw.clone())
        .await
        .unwrap());
    assert_eq!(phone.try_recv().unwrap().stanza, raw);
    assert!(desk.try_recv().is_err());
    assert!(!context
        .state
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Archive(..) | Call::Federation(..))));
}

#[tokio::test]
async fn denied_or_replayed_original_never_routes_and_store_binds_the_account() {
    let context = Context::new(1);
    let host = reflection_host(context.clone());
    let mut phone = add_route(&context, PHONE);
    let id = Uuid::new_v4();
    let raw = format!("<message from='{CHANNEL}/sender' to='{RECIPIENT}' id='{id}' type='groupchat'><body>original</body><mix xmlns='{CORE_NS}'/><stanza-id xmlns='urn:xmpp:sid:0' by='{CHANNEL}' id='{id}'/></message>");
    subscribe(&context, NODE_PRESENCE, ACCOUNT);
    assert!(federated_mix_message(host.clone(), DOMAIN, raw.clone())
        .await
        .unwrap());
    assert!(context.state.calls().is_empty());
    subscribe(&context, NODE_MESSAGES, Uuid::new_v4());
    assert!(federated_mix_message(host.clone(), DOMAIN, raw.clone())
        .await
        .unwrap());
    assert!(phone.try_recv().is_err());

    subscribe(&context, NODE_MESSAGES, ACCOUNT);
    context.state.archive_replay.store(true, Ordering::SeqCst);
    assert!(federated_mix_message(host.clone(), DOMAIN, raw.clone())
        .await
        .unwrap());
    assert!(phone.try_recv().is_err());
    context.state.archive_replay.store(false, Ordering::SeqCst);
    assert!(federated_mix_message(host, DOMAIN, raw.clone())
        .await
        .unwrap());
    assert_eq!(phone.try_recv().unwrap().stanza, raw);
}
