//! Applies personal XEP-0424 retractions through the service that owns their transaction.

use crate::ports::MessageHost;
use anyhow::Result;
use northstar_message_application::retractions::{
    ArchiveWrite, DeliveryProjection, OutboundProjection, OwnerProjection, RetractionCommand,
    RetractionOutcome,
};
use northstar_message_core::retraction::personal_retraction_command;
use roxmltree::Node;
use uuid::Uuid;

#[expect(
    clippy::too_many_arguments,
    reason = "the XEP-0424 admission keeps both owner projections and the exact durable delivery projection explicit at the protocol boundary"
)]
pub(crate) async fn apply_personal_retraction<H: MessageHost>(
    state: &H,
    sender_id: Uuid,
    sender_jid: &str,
    recipient_id: Option<Uuid>,
    recipient_jid: &str,
    root: Node<'_, '_>,
    action_writes: &[ArchiveWrite<'_>],
    delivery: &DeliveryProjection<'_>,
) -> Result<RetractionOutcome> {
    let Some(command) = personal_retraction_command(root).ok().flatten() else {
        anyhow::bail!("personal retraction admission requires a valid command");
    };
    let mut owners = vec![OwnerProjection {
        owner_id: sender_id,
        peer_jid: recipient_jid,
    }];
    if let Some(recipient_id) = recipient_id.filter(|id| *id != sender_id) {
        owners.push(OwnerProjection {
            owner_id: recipient_id,
            peer_jid: sender_jid,
        });
    }
    state
        .retraction_service()
        .apply_with_delivery(
            &owners,
            sender_jid,
            &RetractionCommand {
                target_id: &command.target_id,
                action_id: &command.action_id,
                semantic_payload: &command.semantic_payload,
            },
            action_writes,
            Some(delivery),
            None,
        )
        .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the XEP-0424 federation admission keeps archive and outbox authority explicit at the protocol boundary"
)]
pub(crate) async fn apply_outbound_personal_retraction<H: MessageHost>(
    state: &H,
    sender_id: Uuid,
    sender_jid: &str,
    recipient_jid: &str,
    root: Node<'_, '_>,
    action_writes: &[ArchiveWrite<'_>],
    target_domain: &str,
    stanza: &str,
) -> Result<RetractionOutcome> {
    let Some(command) = personal_retraction_command(root).ok().flatten() else {
        anyhow::bail!("outbound retraction admission requires a valid retraction command");
    };
    let outbox = OutboundProjection {
        target_domain,
        stanza,
        bounce_to: Some(sender_jid),
        policy: state.federation_outbox_policy().into(),
    };
    state
        .retraction_service()
        .apply(
            &[OwnerProjection {
                owner_id: sender_id,
                peer_jid: recipient_jid,
            }],
            sender_jid,
            &RetractionCommand {
                target_id: &command.target_id,
                action_id: &command.action_id,
                semantic_payload: &command.semantic_payload,
            },
            action_writes,
            Some(&outbox),
        )
        .await
}

#[cfg(test)]
mod tests {
    use northstar_message_application::retractions::{retractable_message, tombstone_message};
    use northstar_message_core::retraction::{personal_retraction_command, retraction_target};
    use northstar_xml_builder::message_policy::encrypted_retraction_archive_stanza;
    use roxmltree::Document;

    #[test]
    fn validates_retraction_shape() {
        let document = Document::parse(
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='original'/></message>",
        )
        .unwrap();
        assert_eq!(
            retraction_target(document.root_element()).unwrap(),
            Some("original".to_owned())
        );
        for xml in [
            "<message><retract xmlns='urn:xmpp:message-retract:1'/></message>",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='a'/></message>",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='a'/><retract xmlns='urn:xmpp:message-retract:1' id='b'/></message>",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='a'><extra/></retract></message>",
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='a'>not-empty</retract></message>",
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='a'/><reactions xmlns='urn:xmpp:reactions:0' id='b'/></message>",
            "<message id='action'><body>ambiguous</body><retract xmlns='urn:xmpp:message-retract:1' id='a'/><replace xmlns='urn:xmpp:message-correct:0' id='b'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(retraction_target(document.root_element()).is_err());
        }

        let longest = "x".repeat(1_024);
        let xml = format!(
            "<message id='{longest}'><retract xmlns='urn:xmpp:message-retract:1' id='{longest}'/></message>"
        );
        let document = Document::parse(&xml).unwrap();
        assert_eq!(
            personal_retraction_command(document.root_element())
                .unwrap()
                .unwrap()
                .target_id
                .len(),
            1_024
        );
        let too_long = "x".repeat(1_025);
        let xml = format!(
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='{too_long}'/></message>"
        );
        let document = Document::parse(&xml).unwrap();
        assert!(personal_retraction_command(document.root_element()).is_err());
    }

    #[test]
    fn tombstone_drops_original_content_and_escapes_attributes() {
        let document = Document::parse(
            "<message from='a@example.test/device' to='b@example.test' id='m1'><body>secret</body></message>",
        )
        .unwrap();
        let tombstone = tombstone_message(document.root_element(), "retract-1");
        assert!(!tombstone.contains("secret"));
        assert!(tombstone.contains("<retracted xmlns='urn:xmpp:message-retract:1'"));
        assert!(tombstone.contains("id='retract-1'"));
    }

    #[test]
    fn only_user_visible_messages_are_retractable() {
        for xml in [
            "<message from='a@example.test/device'><body>visible</body></message>",
            "<message from='a@example.test/device'><encrypted xmlns='urn:xmpp:omemo:2'/></message>",
            "<message from='a@example.test/device'><file-sharing xmlns='urn:xmpp:sfs:0'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(retractable_message(document.root_element()), "{xml}");
        }
        for xml in [
            "<message from='a@example.test/device'><received xmlns='urn:xmpp:receipts' id='m1'/></message>",
            "<message from='a@example.test/device'><body>call fallback</body><propose xmlns='urn:xmpp:jingle-message:0' id='call'/></message>",
            "<message from='a@example.test/device'><body>retraction fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='m1'/></message>",
            "<message from='a@example.test/device' type='error'><body>reflected</body></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!retractable_message(document.root_element()), "{xml}");
        }
    }

    #[test]
    fn encrypted_retraction_archive_keeps_only_safe_payload_and_target() {
        let archive = encrypted_retraction_archive_stanza(
            "<message from='alice@example.test/Phone' id='action'><body>private fallback</body><encrypted xmlns='urn:xmpp:omemo:2'><header sid='1'/><payload>ciphertext</payload></encrypted><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
            "target",
        );
        assert!(!archive.contains("private fallback"), "{archive}");
        assert!(archive.contains("urn:xmpp:omemo:2"), "{archive}");
        assert!(archive.contains("urn:xmpp:message-retract:1"), "{archive}");
        assert!(archive.contains("id='target'"), "{archive}");
    }

    #[test]
    fn personal_retraction_command_parses_valid_xml_and_extracts_fields() {
        let xml = "<message from='alice@example.com' to='bob@example.com' id='act-99'><body>deleted</body><retract xmlns='urn:xmpp:message-retract:1' id='tgt-123'/></message>";
        let doc = Document::parse(xml).unwrap();
        let cmd = personal_retraction_command(doc.root_element())
            .unwrap()
            .unwrap();
        assert_eq!(cmd.target_id, "tgt-123");
        assert_eq!(cmd.action_id, "act-99");
        assert_eq!(cmd.semantic_payload, xml);
    }

    #[test]
    fn personal_retraction_command_rejects_malformed_xml_and_conflicts() {
        // No retract element
        let xml_none = "<message id='act-1'><body>plain message</body></message>";
        let doc_none = Document::parse(xml_none).unwrap();
        assert_eq!(
            personal_retraction_command(doc_none.root_element()).unwrap(),
            None
        );

        // Conflicting replace element
        let xml_replace = "<message id='act-1'><retract xmlns='urn:xmpp:message-retract:1' id='tgt-1'/><replace xmlns='urn:xmpp:message-correct:0' id='tgt-1'/></message>";
        let doc_replace = Document::parse(xml_replace).unwrap();
        assert!(personal_retraction_command(doc_replace.root_element()).is_err());

        // Conflicting reactions element
        let xml_react = "<message id='act-1'><retract xmlns='urn:xmpp:message-retract:1' id='tgt-1'/><reactions xmlns='urn:xmpp:reactions:0' id='tgt-1'/></message>";
        let doc_react = Document::parse(xml_react).unwrap();
        assert!(personal_retraction_command(doc_react.root_element()).is_err());

        // A direct MUC invitation can grant a durable affiliation. It must
        // never share an operation boundary with a personal retraction.
        let xml_invite = "<message id='act-1'><retract xmlns='urn:xmpp:message-retract:1' id='tgt-1'/><x xmlns='jabber:x:conference' jid='room@conference.example.com'/></message>";
        let doc_invite = Document::parse(xml_invite).unwrap();
        assert!(personal_retraction_command(doc_invite.root_element()).is_err());
    }

    #[test]
    fn protocol_retractions_has_zero_db_dto_dependencies() {
        let source = include_str!("retractions.rs");
        let target_archive_dto = format!("db::Personal{}Write", "Archive");
        let target_outbox_dto = format!("db::Personal{}OutboxAdmission", "S2s");
        let db_import = format!("use crate::{};", "db");
        assert!(
            !source.contains(&target_archive_dto),
            "protocol/retractions.rs must not reference db archive DTO"
        );
        assert!(
            !source.contains(&target_outbox_dto),
            "protocol/retractions.rs must not reference db outbox DTO"
        );
        assert!(
            !source.contains(&db_import),
            "protocol/retractions.rs must not import crate db"
        );
    }
}
