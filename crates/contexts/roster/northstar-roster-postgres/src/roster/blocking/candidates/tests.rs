use super::*;
use northstar_xmpp_types::jid::CanonicalJid;

#[test]
fn indexed_keys_have_scalar_scope_for_all_jid_shapes() {
    let jids = [
        "example.test",
        "example.test/Desk",
        "example.test/Phone",
        "bob@example.test",
        "bob@example.test/Desk",
        "bob@example.test/Phone",
        "alice@example.test",
        "alice@example.test/Desk",
        "other.test/Desk",
    ];
    for jid in jids {
        let keys = blocking_match_candidates(&CanonicalJid::parse(jid).unwrap());
        for pattern in jids {
            assert_eq!(
                keys.iter().any(|key| key == pattern),
                blocked_jid_matches(pattern, jid),
                "{pattern} -> {jid}",
            );
        }
    }
}
