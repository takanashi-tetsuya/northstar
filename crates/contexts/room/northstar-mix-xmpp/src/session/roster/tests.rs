use super::*;
use northstar_room_application::mix_service::MixAccount;
use northstar_room_core::mix::MixParticipantId;
use northstar_roster_core::{
    RosterChange, RosterFlushBatch, RosterPushDisposition, RosterSyncGate,
};
use std::sync::atomic::AtomicBool;

#[test]
fn exact_roster_transitions_keep_annotation_with_their_own_version() {
    let account = MixAccount {
        id: Uuid::new_v4(),
        username: "member".to_owned(),
    };
    let change = |version: i64, removed: bool| RosterChange {
        version,
        contact_jid: "room@mix.example.test".to_owned(),
        display_name: None,
        subscription: (!removed).then(|| "to".to_owned()),
        ask: None,
        groups: Vec::new(),
        approved: false,
        removed,
        owner_authority: None,
    };
    let first = CommittedMixRosterDelta::new(
        account.clone(),
        change(8, false),
        Some(MixParticipantId::parse_remote("first").unwrap()),
    );
    let removed = CommittedMixRosterDelta::new(
        account.clone(),
        change(9, true),
        first.participant_annotation.clone(),
    );
    let rejoined = CommittedMixRosterDelta::new(
        account,
        change(10, false),
        Some(MixParticipantId::parse_remote("next").unwrap()),
    );
    for (delta, version, participant) in [
        (first, 8, Some("first")),
        (removed, 9, None),
        (rejoined, 10, Some("next")),
    ] {
        assert_eq!(delta.version, version);
        assert_eq!(delta.change.version, version);
        assert_eq!(committed_annotation(&delta).as_deref(), participant);
        for wants_annotations in [false, true] {
            let gate = RosterSyncGate::default();
            let requested = AtomicBool::new(true);
            let annotated = AtomicBool::new(wants_annotations);
            let permit = gate
                .begin(&requested, &annotated, wants_annotations)
                .unwrap();
            assert_eq!(
                gate.start_flush(permit, version - 1),
                RosterFlushBatch::Complete
            );
            let plain = format!("version={version}");
            let annotated_push =
                committed_annotation(&delta).map(|id| format!("{plain};participant={id}"));
            let expected = if wants_annotations {
                annotated_push.clone().unwrap_or_else(|| plain.clone())
            } else {
                plain.clone()
            };
            assert_eq!(
                gate.route(
                    &requested,
                    &annotated,
                    delta.version,
                    plain,
                    annotated_push,
                    |stanza| {
                        assert_eq!(stanza, expected);
                        true
                    }
                ),
                RosterPushDisposition::Delivered
            );
        }
    }
}
