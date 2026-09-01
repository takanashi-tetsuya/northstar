#![no_main]

use base64::{engine::general_purpose::STANDARD, Engine};
use libfuzzer_sys::fuzz_target;

#[path = "../../src/jid.rs"]
mod jid;
#[path = "../../src/auth.rs"]
mod auth;
#[path = "../../src/xmpp/sm_counter.rs"]
mod sm_counter;

use auth::{
    ChannelBindings, ExternalMechanism, PlainMechanism, SaslMechanism, SaslStep,
    ScramSha256Mechanism,
};

fn observe(step: SaslStep) -> bool {
    match step {
        SaslStep::Success(username, data) => !username.is_empty() || data.is_some(),
        SaslStep::Challenge(challenge) => challenge.len() <= 16 * 1024,
        SaslStep::NeedsCredentials(username) => !username.is_empty(),
        SaslStep::Failure(failure) => {
            let condition = failure.condition();
            !condition.is_empty()
                && condition
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        }
    }
}

fn exercise_sasl(data: &[u8]) {
    let selector = data.first().copied().unwrap_or_default();
    let split = data.len().min(8 * 1024) / 2;
    let first = String::from_utf8_lossy(&data[..split]);
    let second = String::from_utf8_lossy(&data[split..data.len().min(8 * 1024)]);
    match selector % 4 {
        0 => {
            let mut mechanism = PlainMechanism::new("example.test".into());
            let payload = if selector & 0x80 == 0 {
                first.into_owned()
            } else {
                STANDARD.encode(first.as_bytes())
            };
            let _ = observe(mechanism.initial_response(&payload));
            let _ = observe(mechanism.response(&second));
        }
        1 => {
            let mut mechanism = ExternalMechanism::new(vec!["alice@example.test".into()]);
            let payload = if selector & 0x80 == 0 {
                first.into_owned()
            } else {
                STANDARD.encode(first.as_bytes())
            };
            let _ = observe(mechanism.initial_response(&payload));
            let _ = observe(mechanism.response(&second));
        }
        2 => {
            let mut mechanism = ScramSha256Mechanism::new_with_channel_binding_support(
                "example.test".into(),
            );
            let first = STANDARD.encode(first.as_bytes());
            let needs_credentials = matches!(
                mechanism.initial_response(&first),
                SaslStep::NeedsCredentials(_)
            );
            if needs_credentials {
                let key_len = if selector & 0x40 == 0 { 32 } else { 31 };
                let _ = observe(mechanism.provide_credentials(
                    vec![selector; 16],
                    u32::from(selector).max(1),
                    vec![selector; key_len],
                    vec![selector ^ 0x5a; key_len],
                ));
                let _ = observe(mechanism.response(&STANDARD.encode(second.as_bytes())));
            }
        }
        _ => {
            let Ok(bindings) = ChannelBindings::new(vec![1; 32], Some(vec![2; 32])) else {
                return;
            };
            let mut mechanism = ScramSha256Mechanism::new_plus("example.test".into(), bindings);
            let _ = observe(mechanism.initial_response(&STANDARD.encode(first.as_bytes())));
            let _ = observe(mechanism.response(&STANDARD.encode(second.as_bytes())));
        }
    }
}

fn exercise_sm(data: &[u8]) {
    let mut acknowledged = 0_u32;
    let mut outstanding = 0usize;
    for chunk in data.chunks(5).take(16_384) {
        let mut bytes = [0_u8; 4];
        bytes[..chunk.len().min(4)].copy_from_slice(&chunk[..chunk.len().min(4)]);
        let received = u32::from_le_bytes(bytes);
        if chunk.get(4).copied().unwrap_or_default() & 1 == 0 {
            outstanding = outstanding.saturating_add(1).min(65_536);
        }
        if let Some(delta) =
            sm_counter::acknowledgement_delta(acknowledged, received, outstanding)
        {
            assert!(delta <= outstanding);
            outstanding -= delta;
            acknowledged = received;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    exercise_sasl(data);
    exercise_sm(data);
});
