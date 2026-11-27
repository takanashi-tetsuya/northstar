use super::*;
use northstar_roster_application::{
    blocking_mutation::BlockingContactTransition, ExactPresenceRoute,
};
use uuid::Uuid;

pub(crate) fn contact(
    jid: &str,
    node: Option<&str>,
    before: bool,
    after: bool,
    allows: bool,
) -> BlockingContactTransition {
    BlockingContactTransition {
        route: BlockingPresenceTarget {
            source: ExactPresenceRoute {
                account_id: Uuid::from_u128(1),
                auth_generation: 2,
                connection_id: Uuid::from_u128(3),
                full_jid: "alice@example.test/source".into(),
                node_id: None,
            },
            recipient: Some(ExactPresenceRoute {
                account_id: Uuid::from_u128(4),
                auth_generation: 2,
                connection_id: Uuid::new_v4(),
                full_jid: jid.into(),
                node_id: node.map(str::to_owned),
            }),
            source_expects_active: false,
            recipient_expects_active: false,
            address: jid.into(),
            directed: None,
        },
        covered_before: before,
        covered_after: after,
        other_policy_allows: allows,
    }
}

pub(crate) fn change(contacts: Vec<BlockingContactTransition>) -> CommittedBlockingChange {
    CommittedBlockingChange {
        delta: vec!["example.test".into()],
        contacts,
    }
}

#[tokio::test]
async fn ordered_1024_and_1025_item_plans_visit_the_directed_grant_once() {
    for count in [1024, 1025] {
        let mut contacts = (0..count)
            .map(|index| {
                contact(
                    &format!("bob{index}@example.test/Phone"),
                    Some("node"),
                    false,
                    true,
                    true,
                )
            })
            .collect::<Vec<_>>();
        contacts[0].route.directed = Some(contacts[0].route.address.clone());
        let mut sent = Vec::new();
        let mut sizes = Vec::new();
        deliver_blocking_presence_change(change(contacts.clone()), |page, available| {
            assert!(!available);
            sizes.push(page.len());
            sent.extend(page);
            std::future::ready(())
        })
        .await;
        assert_eq!(
            sizes,
            if count == 1024 {
                vec![1024]
            } else {
                vec![1024, 1]
            }
        );
        assert_eq!(
            sent,
            contacts
                .into_iter()
                .map(|contact| contact.route)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            sent.iter()
                .filter(|target| target.directed.is_some())
                .count(),
            1
        );
    }
}
