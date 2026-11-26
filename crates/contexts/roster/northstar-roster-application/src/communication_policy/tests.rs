use super::*;
use CommunicationDecision::*;

#[test]
fn communication_decision_precedence() {
    let descending = [StaleAccount, OwnerBlocks, PeerBlocks, PrivacyDenies, Allow];
    for (index, expected) in descending.iter().copied().enumerate() {
        assert_eq!(
            descending[index..].iter().rev().copied().max(),
            Some(expected)
        );
    }
}

#[test]
fn only_allow_allows_communication() {
    assert!(Allow.allows());
    for decision in [StaleAccount, OwnerBlocks, PeerBlocks, PrivacyDenies] {
        assert!(!decision.allows());
    }
}

#[tokio::test]
async fn single_read_uses_the_batch_reader_and_records_the_query() {
    let reader = InMemoryCommunicationPolicyReader::new(|query| {
        Ok(if query.check_owner_block {
            OwnerBlocks
        } else {
            Allow
        })
    });
    let query = CommunicationPolicyQuery {
        account_id: Uuid::new_v4(),
        expected_auth_generation: Some(1),
        subject: PolicySubject::AccountDefault,
        peer: "peer@example.test/Phone".to_owned(),
        kind: PrivacyStanzaKind::Iq,
        direction: PolicyDirection::Outbound,
        check_owner_block: true,
        check_peer_block: false,
    };
    assert_eq!(
        reader.read_communication_policy(&query).await.unwrap(),
        OwnerBlocks
    );
    assert_eq!(reader.batches(), vec![vec![query]]);
}
