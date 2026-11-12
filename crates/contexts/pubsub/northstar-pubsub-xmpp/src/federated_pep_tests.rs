#[test]
fn federated_pep_subscription_branch_has_no_split_authority_reads() {
    let source = include_str!("federated_pep.rs");
    let branch = source
        .split_once("pub async fn federated_pep_subscription<")
        .expect("federated PEP subscription handler must remain identifiable")
        .1
        .split_once("\n}\n")
        .expect("federated PEP subscription handler must end")
        .0;
    for forbidden in [
        "db::pep_node(",
        "pep_access_allowed(",
        "subscribe_pep_node_with_outbox(",
        "db::unsubscribe_pep_node(",
    ] {
        assert!(
            !branch.contains(forbidden),
            "federated PEP policy escaped the service transaction: {forbidden}"
        );
    }
    assert!(branch.contains(".subscribe_pep_node("));
    assert!(branch.contains(".unsubscribe_pep_node("));
    assert!(branch.contains("PepSubscriptionActor"));
}
