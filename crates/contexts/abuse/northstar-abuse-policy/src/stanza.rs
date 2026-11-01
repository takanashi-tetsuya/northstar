//! The proof-of-work stanza extension: the error that asks for work and the removal of the client's
//! proof before a stanza is stored or forwarded.

use crate::WorkRequirement;
use northstar_xml_builder::stanza::{reflected_stanza_error, stanza_condition_element};
use northstar_xml_builder::XmlElement;
use roxmltree::{Document, Node};

pub fn abuse_stanza_error(root: Node<'_, '_>, requirement: &WorkRequirement) -> String {
    let error = XmlElement::namespaced("error", "jabber:client")
        .attr("type", "wait")
        .child(stanza_condition_element("resource-constraint"))
        .child(
            XmlElement::namespaced("pow-required", "urn:northstar:pow:1")
                .attr("step", requirement.step)
                .attr("work-factor", requirement.work_factor)
                .attr("max-work-factor", requirement.max_work_factor)
                .attr(
                    "retry-after",
                    requirement
                        .hard_wait_seconds
                        .max(requirement.retry_after_seconds),
                )
                .attr("cooldown", requirement.cooldown_seconds)
                .attr(
                    "max-device-seconds",
                    requirement.approximate_max_device_seconds,
                ),
        )
        .finish();
    reflected_stanza_error(root, &error)
}

pub fn strip_pow_element(raw: &str) -> String {
    let Ok(document) = Document::parse(raw) else {
        return raw.to_owned();
    };
    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "pow"
                && node.tag_name().namespace() == Some("urn:northstar:pow:1")
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();
    if ranges.is_empty() {
        return raw.to_owned();
    }
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut cleaned = raw.to_owned();
    for range in ranges {
        cleaned.replace_range(range, "");
    }
    cleaned
}
