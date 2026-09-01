#![no_main]

use libfuzzer_sys::fuzz_target;
use roxmltree::{Document, Node};

#[path = "../../src/mam_pubsub_parsing.rs"]
mod mam_pubsub_parsing;

const MAX_INPUT: usize = 4 * 1_048_576;

fn exercise_production_parsers(node: Node<'_, '_>) {
    // The protocol layer supplies RFC 7622 and RFC 3339 conversions at these
    // two dependency-injection points. Identity conversion here keeps this
    // harness focused on the exact shared XML grammar rather than maintaining
    // a second, inevitably divergent semantic parser.
    let _ = mam_pubsub_parsing::parse_mam_query(
        node,
        |jid| Ok(jid.to_owned()),
        |timestamp| Ok(timestamp.to_owned()),
    );

    for kind in ["get", "set"] {
        if let Ok(envelope) = mam_pubsub_parsing::parse_pubsub_envelope(node, kind) {
            for operation in envelope.operations {
                if operation.tag_name().name() == "set"
                    && operation.tag_name().namespace() == Some(mam_pubsub_parsing::RSM_NS)
                {
                    let _ = mam_pubsub_parsing::parse_pubsub_rsm(operation);
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(document) = Document::parse(xml) else {
        return;
    };
    let root = document.root_element();
    exercise_production_parsers(root);
    for child in root.children().filter(Node::is_element) {
        exercise_production_parsers(child);
    }
});
