use northstar_roster_core::SubscriptionReply;
use northstar_xml_builder::rewrite::{set_client_namespace, set_from, set_to};
use northstar_xml_builder::XmlElement;

pub(super) fn presence_probe_status_response(
    from: &str,
    to: &str,
    kind: &str,
    id: Option<&str>,
) -> String {
    let kind = match kind {
        "unavailable" => "unavailable",
        "unsubscribed" => "unsubscribed",
        _ => "error",
    };
    XmlElement::new("presence")
        .attr("xmlns", "jabber:server")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .optional_attr("id", id)
        .finish()
}

pub(super) fn canonical_subscription_stanza(raw: &str, from: &str, to: &str) -> String {
    set_client_namespace(&set_to(&set_from(raw, from), to))
}

pub(super) fn subscription_reply(
    from: &str,
    to: &str,
    kind: SubscriptionReply,
    id: Option<&str>,
) -> String {
    XmlElement::new("presence")
        .attr("xmlns", "jabber:server")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind.as_str())
        .optional_attr("id", id)
        .finish()
}

#[cfg(test)]
mod tests;
