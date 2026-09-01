#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/xmpp/framing.rs"]
mod framing;

const MAX_INPUT: usize = 1_048_576;

fuzz_target!(|data: &[u8]| {
    // Match the production transport ceiling before allocating a UTF-8 copy
    // or a vector containing every character boundary.
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(entity) = std::str::from_utf8(data) else {
        return;
    };

    // Exercise a network-fragment boundary selected by the input itself.  A
    // partial frame may wait or reject, but it must never panic.  If it waits,
    // appending the remaining bytes must retain the same safety properties.
    let selector = data.first().copied().unwrap_or_default() as usize;
    let char_boundaries = entity
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(entity.len()))
        .collect::<Vec<_>>();
    let split = char_boundaries[selector % char_boundaries.len()];
    let mut buffer = entity[..split].to_owned();
    // Match the transport implementation: XML declaration and stream QName
    // state belong to one XML entity and must survive network fragmentation
    // and extraction of multiple stanzas.
    let mut framer = framing::XmlEntityFramer::default();
    let first = framer.take_frame(&mut buffer);
    if !matches!(first, Ok(None)) {
        return;
    }
    buffer.push_str(&entity[split..]);

    // Multiple stanzas can arrive in one transport frame.  Every successful
    // extraction must make progress; cap the loop so one fuzz input cannot
    // monopolize a worker with millions of tiny self-closing elements.
    for _ in 0..256 {
        let before = buffer.len();
        match framer.take_frame(&mut buffer) {
            Ok(Some(frame)) => {
                assert!(!frame.is_empty());
                assert!(buffer.len() < before);
            }
            Ok(None) => break,
            Err(error) => {
                assert!(matches!(
                    framing::stream_error_condition(&error),
                    "restricted-xml"
                        | "unsupported-encoding"
                        | "policy-violation"
                        | "not-well-formed"
                ));
                break;
            }
        }
    }
});
