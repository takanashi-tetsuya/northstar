use super::*;

#[test]
fn prepared_token_keeps_wire_shape_lifetime_and_redacts_debug() {
    let mut entropy = [1, 2, 3].into_iter().map(Uuid::from_u128);
    let token = PreparedMixInvitationToken::prepare(|| entropy.next().unwrap());
    assert_eq!(token.id(), Uuid::from_u128(1));
    assert_eq!(
        token.secret(),
        "0000000000000000000000000000000200000000000000000000000000000003"
    );
    assert_eq!(token.lifetime().num_seconds(), 3_600);
    assert_eq!(
        token.hash(),
        [
            0xa1, 0x5c, 0x81, 0xae, 0x1a, 0x15, 0xad, 0x61, 0xd5, 0xb8, 0x9b, 0xd5, 0xdc, 0xfd,
            0x18, 0x59, 0xb3, 0x64, 0xcc, 0x50, 0x6a, 0x1b, 0x78, 0x80, 0x20, 0x5d, 0xa8, 0x4a,
            0xe0, 0x44, 0x66, 0x6c,
        ]
    );
    assert_eq!(
        format!("{token:?}"),
        "PreparedMixInvitationToken([redacted])"
    );
}
