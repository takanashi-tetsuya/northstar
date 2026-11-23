use super::*;
use northstar_room_application::mix_service::{
    HostedMixRefusal, PamJoinResult, RemotePamJoinOptions,
};

const CHANNEL: &str = "room@mix.example.test";

#[test]
fn remote_join_round_trips_invitation_and_anon_options() {
    let incoming = "<join xmlns='urn:xmpp:mix:anon:0'>
        <subscribe node='urn:xmpp:mix:nodes:messages'/><nick>Nick</nick>
        <invitation xmlns='urn:xmpp:mix:misc:0'><inviter>owner@example.test</inviter>
        <invitee>guest@example.test</invitee><channel>room@mix.example.test</channel>
        <token>a&amp;b</token></invitation>
        <x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mix:anon:0</value></field>
        <field var='JID Visibility'><value>never</value></field><field var='Presence'><value>not share</value></field>
        </x></join>";
    let document = Document::parse(incoming).unwrap();
    let join = parse_join(document.root_element()).unwrap();
    let options =
        RemotePamJoinOptions::new(join.anonymous_profile, join.preference.as_ref()).unwrap();
    let request_id = options.request_id(Uuid::new_v4());
    let channel = MixChannelAddress::parse(CHANNEL).unwrap();
    let outbound = crate::iq_parse::remote_pam_join_stanza(
        &MixRealJid::parse("guest@example.test").unwrap(),
        &channel,
        &request_id,
        &join,
        &options,
    );
    let IqOperation::Join(forwarded) = parse_iq(&outbound).unwrap().unwrap().operation else {
        panic!("expected forwarded Core join");
    };
    assert!(forwarded.anonymous_profile);
    assert_eq!(forwarded.invitation, join.invitation);
    assert_eq!(forwarded.nodes, join.nodes);
    assert_eq!(forwarded.nick, join.nick);
    assert_eq!(forwarded.preference, join.preference);
    let form = crate::forms::preference_result_form(forwarded.preference.as_ref().unwrap());
    let result =
        format!("<iq type='result'><join xmlns='{ANON_NS}' id='opaque'>{form}</join></iq>");
    let parsed = join_evidence::parse_join_evidence(&result, &channel)
        .unwrap()
        .unwrap();
    let evidence = parsed.evidence();
    assert_eq!(evidence.participant.as_str(), "opaque");
    assert_eq!(evidence.preference, join.preference.as_ref());
    RemotePamJoinOptions::new(evidence.anonymous_profile, evidence.preference)
        .unwrap()
        .verify_result(&request_id)
        .unwrap();
    let recipient = MixRealJid::parse("guest@example.test").unwrap();
    let addressed = RemotePamResponse {
        authenticated_domain: "mix.example.test",
        channel: &channel,
        recipient: &recipient,
        request_id: &request_id,
        digest: &[0; 32],
    };
    let pam = evidence
        .render_anon_result(
            &addressed,
            PamJoinResult {
                client_request_id: "client-join",
                actor_bare: recipient.as_str(),
                requester_full_jid: "guest@example.test/phone",
                channel_jid: channel.as_str(),
                participant_id: evidence.participant.as_str(),
                subscriptions: evidence.subscriptions,
                nick: evidence.nick.map(|nick| nick.as_str()),
            },
        )
        .unwrap();
    let pam_document = Document::parse(&pam).unwrap();
    let nested_join = pam_document
        .descendants()
        .find(|node| node.has_tag_name((ANON_NS, "join")))
        .unwrap();
    assert_eq!(
        nested_join.attribute("jid"),
        Some("opaque#room@mix.example.test")
    );
    assert_eq!(parse_join(nested_join).unwrap().preference, join.preference);
}

#[test]
fn remote_join_refuses_an_omitted_default_valued_field() {
    let requested = MixParticipantPreference::default();
    let request_id = RemotePamJoinOptions::new(true, Some(&requested))
        .unwrap()
        .request_id(Uuid::new_v4());
    let channel = MixChannelAddress::parse(CHANNEL).unwrap();
    let result = "<iq type='result'><join xmlns='urn:xmpp:mix:anon:0' id='opaque'>
        <x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE'><value>urn:xmpp:mix:anon:0</value></field>
        <field var='JID Visibility'><value>default</value></field>
        <field var='Private Messages'><value>allow</value></field>
        <field var='Presence'><value>share</value></field></x></join></iq>";
    let parsed = join_evidence::parse_join_evidence(result, &channel)
        .unwrap()
        .unwrap();
    let evidence = parsed.evidence();
    assert_eq!(
        RemotePamJoinOptions::new(evidence.anonymous_profile, evidence.preference)
            .unwrap()
            .verify_result(&request_id),
        Err(HostedMixRefusal::RemoteJoinOptionsNotHonoured),
    );
}
