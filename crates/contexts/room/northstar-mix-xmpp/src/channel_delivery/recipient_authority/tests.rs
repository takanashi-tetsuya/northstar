use super::*;

#[test]
fn route_account_must_match_the_bound_recipient() {
    let account = Uuid::from_u128(81);
    let authority = MixDeliveryRecipientAuthority::Local {
        address: MixRealJid::parse("bob@local.test").unwrap(),
        account_id: account,
    };
    assert!(check_route_account(Some(&authority), account).is_ok());
    let error = check_route_account(Some(&authority), Uuid::from_u128(82)).unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<PermanentMixDeliveryError>()
            .unwrap()
            .reason,
        "account-unavailable"
    );
}
