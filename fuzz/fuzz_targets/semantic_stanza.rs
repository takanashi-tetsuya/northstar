#![no_main]

use libfuzzer_sys::fuzz_target;
use roxmltree::Document;

#[path = "../../src/xmpp/framing.rs"]
mod framing;
#[path = "../../src/jid.rs"]
mod jid;
#[path = "../../src/xmpp/stanza_validation.rs"]
mod stanza_validation;

const MAX_INPUT: usize = 1_048_576;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let mut buffer = input.to_owned();
    let mut framer = framing::XmlEntityFramer::default();
    for _ in 0..256 {
        let before = buffer.len();
        match framer.take_frame(&mut buffer) {
            Ok(Some(frame)) => {
                assert!(!frame.is_empty());
                assert!(buffer.len() < before);
                if !frame.trim_start().starts_with("<stream:")
                    && !frame.trim_start().starts_with("</stream:")
                {
                    if let Ok(document) = Document::parse(&frame) {
                        let _ = stanza_validation::validate_client_stanza(document.root_element());
                    }
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
});
