use super::*;

struct CloneProbe<T>(std::marker::PhantomData<T>);
trait NotClone {
    fn is_clone(&self) -> bool {
        false
    }
}
impl<T> NotClone for CloneProbe<T> {}
impl<T: Clone> CloneProbe<T> {
    fn is_clone(&self) -> bool {
        true
    }
}

struct CopyProbe<T>(std::marker::PhantomData<T>);
trait NotCopy {
    fn is_copy(&self) -> bool {
        false
    }
}
impl<T> NotCopy for CopyProbe<T> {}
impl<T: Copy> CopyProbe<T> {
    fn is_copy(&self) -> bool {
        true
    }
}

#[test]
fn equal_receipt_payloads_have_distinct_authority_and_redact_bearers() {
    let stage = StagedLoginEpoch {
        operation_id: Uuid::from_u128(1),
        connection_id: Uuid::from_u128(2),
        user_id: Uuid::from_u128(3),
        device_id: Uuid::from_u128(4),
        auth_generation: 17,
        epoch: 29,
    };
    let binding = BindingPublication {
        connection_id: stage.connection_id,
        user_id: stage.user_id,
        full_jid: "alice@example.test/device".to_owned(),
        lease_seconds: 61,
    };
    let secret = "sentinel-fast-bearer-must-stay-secret";
    let expires_at = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let mut first = CredentialCommitReceipt::new(
        Some(IssuedFastToken {
            token: Zeroizing::new(secret.to_owned()),
            expires_at,
        }),
        Some(stage),
        Some(binding.clone()),
    );
    let second = CredentialCommitReceipt::new(
        Some(IssuedFastToken {
            token: Zeroizing::new(secret.to_owned()),
            expires_at,
        }),
        Some(stage),
        Some(binding.clone()),
    );
    let identity = first.publication_identity();
    assert_ne!(
        identity,
        second.publication_identity(),
        "fresh receipt authority"
    );
    assert_ne!(identity, Uuid::nil(), "fresh receipt authority");
    for receipt in [&first, &second] {
        assert_eq!(
            receipt.publication_identity().get_version(),
            Some(uuid::Version::Random),
            "random receipt authority"
        );
        assert_eq!(
            receipt.staged_login_epoch(),
            Some(stage),
            "staged identity preserved"
        );
        assert_eq!(
            receipt.binding_publication(),
            Some(&binding),
            "binding preserved"
        );
        let debug = format!("{receipt:?}");
        assert!(debug.contains("[REDACTED]"), "bearer redaction");
        assert!(!debug.contains(secret), "bearer redaction");
    }
    let issued = first.take_issued_fast().expect("original issued bearer");
    assert_eq!(issued.token.as_str(), secret, "bearer preserved");
    assert_eq!(issued.expires_at, expires_at, "expiry preserved");
    let debug = format!("{issued:?}");
    assert!(debug.contains("[REDACTED]"), "issued bearer redaction");
    assert!(!debug.contains(secret), "issued bearer redaction");
    assert!(first.take_issued_fast().is_none(), "bearer consumed once");
    assert_eq!(
        first.publication_identity(),
        identity,
        "stable receipt authority"
    );
    assert_eq!(first.staged_login_epoch(), Some(stage));
    assert_eq!(first.binding_publication(), Some(&binding));
}

#[test]
fn credential_receipts_cannot_be_cloned_or_copied() {
    assert!(!CloneProbe::<CredentialCommitReceipt>(std::marker::PhantomData).is_clone());
    assert!(CloneProbe::<String>(std::marker::PhantomData).is_clone());
    assert!(!CopyProbe::<CredentialCommitReceipt>(std::marker::PhantomData).is_copy());
    assert!(CopyProbe::<u64>(std::marker::PhantomData).is_copy());
}
