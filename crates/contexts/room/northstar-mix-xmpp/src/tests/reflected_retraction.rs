use super::*;

const CHANNEL: &str = "room@mix.remote.test";
const DOMAIN: &str = "mix.remote.test";
const TARGET: Uuid = Uuid::from_u128(0xaaaaaaaa_0000_4000_8000_000000000001);
const ACTION: Uuid = Uuid::from_u128(0xbbbbbbbb_0000_4000_8000_000000000002);
const RECIPIENT: Uuid = Uuid::from_u128(81);

fn reflected_action() -> String {
    format!("<message xmlns='jabber:client' from='{CHANNEL}/actor' to='bob@local.test' id='{ACTION}' type='groupchat'><retract xmlns='{MISC_NS}' id='{TARGET}'/><mix xmlns='{CORE_NS}'><nick>Moderator</nick></mix><stanza-id xmlns='urn:xmpp:sid:0' id='{ACTION}' by='{CHANNEL}'/></message>")
}

fn subscribe(context: &Context) {
    *context.state.reflection_membership.lock().unwrap() = Some(PamMembership {
        id: Uuid::new_v4(),
        user_id: RECIPIENT,
        channel_jid: CHANNEL.into(),
        participant_id: Some("recipient".into()),
        state: "joined".into(),
        request_id: None,
        client_request_id: None,
        requester_full_jid: None,
        subscriptions: vec![NODE_MESSAGES.into()],
    });
}

fn admitted_call() -> Call {
    Call::ReflectedRetraction(RECIPIENT, CHANNEL.into(), TARGET, ACTION, "actor".into())
}

#[tokio::test]
async fn verified_remote_retraction_reaches_source_port_once() {
    let context = Context::new(1);
    subscribe(&context);
    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    context.state.sessions.lock().unwrap().push((
        "bob@local.test/phone".into(),
        LocalSession {
            sender: northstar_stream::outbound::OutboundSender::new(tx),
            disconnect: CancellationToken::new(),
        },
    ));
    let host = reflection_host(context.clone());
    let action = reflected_action();
    assert!(federated_mix_message(host.clone(), DOMAIN, action.clone())
        .await
        .unwrap());
    assert!(rx.try_recv().is_ok());
    let calls = context.state.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| **call == admitted_call())
            .count(),
        1
    );
    assert!(calls.contains(&Call::Sessions("bob@local.test".into())));
    context.state.calls.lock().unwrap().clear();
    context.state.archive_replay.store(true, Ordering::SeqCst);
    assert!(federated_mix_message(host, DOMAIN, action).await.unwrap());
    assert!(rx.try_recv().is_err());
    assert_no_delivery(&context, true);
}

fn assert_no_delivery(context: &Context, typed_call: bool) {
    let calls = context.state.calls();
    let mut admissions = calls
        .iter()
        .filter(|call| matches!(call, Call::ReflectedRetraction(..)));
    assert_eq!(admissions.next(), typed_call.then(admitted_call).as_ref());
    assert!(admissions.next().is_none());
    assert!(!calls.iter().any(|call| matches!(
        call,
        Call::Archive(..) | Call::Sessions(_) | Call::Capability(_) | Call::Federation(..)
    )));
    assert_eq!(context.state.outbox_wakes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn misbound_reflected_retraction_has_no_effects() {
    let valid = reflected_action();
    let target = TARGET.to_string();
    let action = ACTION.to_string();
    let retract = format!("<retract xmlns='{MISC_NS}' id='{TARGET}'/>");
    let sid = format!("<stanza-id xmlns='urn:xmpp:sid:0' id='{ACTION}' by='{CHANNEL}'/>");
    for (domain, stanza) in [
        ("other.test", valid.clone()),
        (
            "remote.test",
            valid.replace("@mix.remote.test", "@remote.test"),
        ),
        (
            "mix.local.test",
            valid.replace("@mix.remote.test", "@mix.local.test"),
        ),
        (
            DOMAIN,
            valid.replace(&format!("by='{CHANNEL}'"), "by='other@mix.remote.test'"),
        ),
        (DOMAIN, valid.replace(&target, &target.to_ascii_uppercase())),
        (DOMAIN, valid.replace(&action, &action.to_ascii_uppercase())),
        (DOMAIN, valid.replacen(&action, &target, 1)),
        (
            DOMAIN,
            valid.replace(&retract, &format!("{retract}{retract}")),
        ),
        (DOMAIN, valid.replace(&sid, &format!("{sid}{sid}"))),
        (DOMAIN, valid.replace(&target, &action)),
        (DOMAIN, valid.replace("/actor", "")),
        (
            DOMAIN,
            valid.replace("bob@local.test", "bob@local.test/phone"),
        ),
        (
            DOMAIN,
            valid.replace("</message>", "<body>hidden</body></message>"),
        ),
        (
            DOMAIN,
            valid.replace(
                "</message>",
                "<encrypted xmlns='urn:xmpp:omemo:2'/></message>",
            ),
        ),
        (DOMAIN, valid.replace("</nick>", "<extra/></nick>")),
    ] {
        let context = Context::new(1);
        subscribe(&context);
        assert!(
            federated_mix_message(reflection_host(context.clone()), domain, stanza)
                .await
                .unwrap()
        );
        assert!(context.state.calls().is_empty());
        assert_no_delivery(&context, false);
    }
    for policy in ["unsubscribed", "blocked", "conflict"] {
        let context = Context::new(1);
        if policy != "unsubscribed" {
            subscribe(&context);
        }
        context
            .state
            .reflection_blocked
            .store(policy == "blocked", Ordering::SeqCst);
        context
            .state
            .reflection_conflict
            .store(policy == "conflict", Ordering::SeqCst);
        assert!(
            federated_mix_message(reflection_host(context.clone()), DOMAIN, valid.clone())
                .await
                .unwrap()
        );
        assert_no_delivery(&context, policy == "conflict");
    }
}
