use super::*;

#[test]
fn login_pow_identity_is_bound_to_ip_and_normalized_account() {
    let ip: IpAddr = "203.0.113.9".parse().unwrap();
    let alice = login_abuse_identity(ip, "Alice").unwrap();
    let alice_case_variant = login_abuse_identity(ip, "alice").unwrap();
    let bob = login_abuse_identity(ip, "bob").unwrap();
    assert_eq!(alice, alice_case_variant);
    assert_ne!(alice.0, bob.0);
    assert_ne!(alice.1, bob.1);
    assert!(login_abuse_identity(ip, "").is_none());
}
