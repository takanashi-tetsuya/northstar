#![no_main]

use libfuzzer_sys::fuzz_target;
use roxmltree::{Document, Node};

const MAX_INPUT: usize = 4 * 1_048_576;

fn exercise_production_parsers(node: Node<'_, '_>) {
    // The production crate owns XML grammar, RFC 7622 identity conversion,
    // and RFC 3339 timestamps. Exercise the complete parser used by MAM.
    let _ = northstar_xep_0313::parse_mam_query(node);

    for kind in ["get", "set"] {
        if let Ok(envelope) = northstar_xep_0060::parse_pubsub_envelope(node, kind) {
            for operation in envelope.operations {
                if operation.tag_name().name() == "set"
                    && operation.tag_name().namespace() == Some(northstar_xep_0060::NS_RSM)
                {
                    let _ = northstar_xep_0060::parse_rsm_element(operation);
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
