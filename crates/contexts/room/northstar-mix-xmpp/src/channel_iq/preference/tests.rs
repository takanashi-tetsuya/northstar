use super::*;
use crate::tests::{
    fixture::{channel, Call, Context},
    reflection_host,
};
use northstar_room_application::mix_service::{
    CommittedMixRosterDelta, CommittedPreference, MixAccount, PreferencePatch,
};
use northstar_room_core::mix::{MixLocalParticipantId, MixParticipantId};
use northstar_roster_core::RosterChange;

#[tokio::test]
async fn preference_reply_and_push_use_committed_facts_without_account_lookup() {
    let context = Context::new(1);
    let host = reflection_host(context.clone());
    let channel = channel();
    let channel_jid = channel.jid();
    let participant = MixLocalParticipantId::new(Uuid::from_u128(94));
    let owner = Uuid::from_u128(81);
    let preference = MixParticipantPreference {
        private_messages: "block".into(),
        share_presence: false,
        ..MixParticipantPreference::default()
    };
    let delta = CommittedMixRosterDelta {
        auth_generation: Some(3),
        ..CommittedMixRosterDelta::new(
            MixAccount {
                id: owner,
                username: "bob".into(),
            },
            RosterChange {
                version: 7,
                contact_jid: channel_jid.clone(),
                display_name: None,
                subscription: Some("none".into()),
                ask: None,
                groups: Vec::new(),
                approved: false,
                removed: false,
                owner_authority: None,
            },
            Some(MixParticipantId::Local(participant.clone())),
        )
    };
    *context.state.preference_commit.lock().unwrap() = Some(CommittedPreference {
        participant_id: participant.clone(),
        preference: preference.clone(),
        roster_changes: vec![delta],
    });
    let fields = BTreeMap::from([
        ("FORM_TYPE".into(), vec![ANON_NS.into()]),
        ("Presence".into(), vec!["not share".into()]),
    ]);
    let reply_to = "bob@local.test/laptop";
    let request = OwnedIq {
        id: "preference".into(),
        kind: "set".into(),
        from: Some(reply_to.into()),
        to: Some(channel_jid.clone()),
        operation: IqOperation::UserPreferenceSet(fields.clone()),
    };
    let reply = set_user_preference(
        &host,
        &request,
        &channel,
        "bob@local.test",
        reply_to,
        &fields,
        None,
    )
    .await
    .unwrap();
    let expected_payload = XmlElement::namespaced("user-preference", ANON_NS)
        .validated_fragment(&preference_result_form(&preference))
        .unwrap()
        .finish();
    assert_eq!(
        reply,
        iq_result_to("preference", &channel_jid, reply_to, &expected_payload)
    );
    assert_eq!(
        context.state.calls(),
        [
            Call::PreferenceWrite(
                channel.id,
                "bob@local.test".into(),
                PreferencePatch {
                    share_presence: Some(false),
                    ..PreferencePatch::default()
                },
            ),
            Call::RosterChange(owner, "bob".into(), 7, Some(participant.to_string())),
        ]
    );
}
