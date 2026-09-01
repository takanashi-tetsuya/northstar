#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../src/xmpp/framing.rs"]
pub mod framing;

mod xmpp {
    pub use crate::framing;
}

#[path = "../../src/transport_parsing.rs"]
mod transport_parsing;

const HTTP_BIND_NS: &str = "http://jabber.org/protocol/httpbind";
const MAX_INPUT: usize = 1_048_576;

fn exercise_websocket_stream(input: &str, selector: usize) {
    let mut complete_framer = framing::XmlEntityFramer::default();
    if let Ok(frame) = transport_parsing::take_websocket_frame(input, &mut complete_framer, MAX_INPUT)
    {
        let _ = transport_parsing::websocket_has_invalid_stream_header_namespace(&frame);
        let _ = transport_parsing::websocket_close_has_content(&frame);
    }

    let boundaries = input
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(input.len()))
        .collect::<Vec<_>>();
    let split = boundaries[selector % boundaries.len()];
    // RFC 7395 forbids a fragment across WebSocket text messages. Exercise
    // both halves independently through the same production entry point; this
    // catches accidental acceptance of an incomplete first message without
    // giving the fuzz target a shadow XML scanner.
    let mut framer = framing::XmlEntityFramer::default();
    let _ = transport_parsing::take_websocket_frame(&input[..split], &mut framer, MAX_INPUT);
    let _ = transport_parsing::take_websocket_frame(&input[split..], &mut framer, MAX_INPUT);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    // Every valid XML transport unit begins with '<' (an even byte), so use
    // the next byte to avoid permanently starving the WebSocket branch.
    let selector = data.get(1).copied().unwrap_or_default() as usize;
    if selector & 1 == 0 {
        let _ = transport_parsing::parse_bosh_frame(input, 100, MAX_INPUT, HTTP_BIND_NS);
    } else {
        exercise_websocket_stream(input, selector);
    }
});
