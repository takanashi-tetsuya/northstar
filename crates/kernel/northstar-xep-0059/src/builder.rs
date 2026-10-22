//! Safe XML builders and serializers for XEP-0059 Result Set Management payloads.

use crate::constants::NAMESPACE;
use crate::models::{BeforeCursor, RsmFin, RsmRequest, RsmResponse};
use crate::xml::XmlElement;

/// Build an <set xmlns='http://jabber.org/protocol/rsm'> XML element for an RSM response.
pub fn build_rsm_set_element(response: &RsmResponse) -> XmlElement {
    let mut set = XmlElement::namespaced("set", NAMESPACE);

    if let Some(ref first) = response.first {
        let mut el = XmlElement::new("first");
        if let Some(index) = first.index {
            el = el.attr("index", index);
        }
        el = el.text(&first.value);
        set.push_child(el);
    }

    if let Some(ref last) = response.last {
        set.push_child(XmlElement::new("last").text(last));
    }

    if let Some(count) = response.count {
        set.push_child(XmlElement::new("count").text(count.to_string()));
    }

    if let Some(index) = response.index {
        set.push_child(XmlElement::new("index").text(index.to_string()));
    }

    set
}

/// Render an <set xmlns='http://jabber.org/protocol/rsm'> XML string for an RSM response.
pub fn build_rsm_set(response: &RsmResponse) -> String {
    build_rsm_set_element(response).finish()
}

/// Build an <set xmlns='http://jabber.org/protocol/rsm'> response from raw components.
pub fn build_rsm_set_raw(
    first: Option<(Option<u64>, &str)>,
    last: Option<&str>,
    count: Option<u64>,
) -> String {
    let mut resp = RsmResponse::default();
    if let Some((idx, val)) = first {
        resp.first = Some(if let Some(i) = idx {
            crate::models::RsmFirstItem::with_index(val, i)
        } else {
            crate::models::RsmFirstItem::new(val)
        });
    }
    if let Some(l) = last {
        resp.last = Some(l.to_owned());
    }
    resp.count = count;
    build_rsm_set(&resp)
}

/// Build an <set xmlns='http://jabber.org/protocol/rsm'> XML element for an RSM request.
pub fn build_rsm_request_element(request: &RsmRequest) -> XmlElement {
    let mut set = XmlElement::namespaced("set", NAMESPACE);

    if let Some(max) = request.max {
        set.push_child(XmlElement::new("max").text(max.to_string()));
    }

    if let Some(ref after) = request.after {
        set.push_child(XmlElement::new("after").text(after));
    }

    if let Some(ref before) = request.before {
        match before {
            BeforeCursor::LastPage => {
                set.push_child(XmlElement::new("before"));
            }
            BeforeCursor::Item(id) => {
                set.push_child(XmlElement::new("before").text(id));
            }
        }
    }

    if let Some(index) = request.index {
        set.push_child(XmlElement::new("index").text(index.to_string()));
    }

    set
}

/// Render an <set xmlns='http://jabber.org/protocol/rsm'> XML string for an RSM request.
pub fn build_rsm_request(request: &RsmRequest) -> String {
    build_rsm_request_element(request).finish()
}

/// Build a <fin ...> MAM element enclosing an RSM set.
pub fn build_mam_fin_element(fin: &RsmFin, mam_ns: &str) -> XmlElement {
    let mut el = XmlElement::namespaced("fin", mam_ns)
        .attr("complete", if fin.complete { "true" } else { "false" })
        .attr("stable", if fin.stable { "true" } else { "false" });

    if let Some(ref rsm) = fin.rsm {
        el.push_child(build_rsm_set_element(rsm));
    }

    el
}

/// Render a <fin ...> MAM XML string enclosing an RSM set.
pub fn build_mam_fin(fin: &RsmFin, mam_ns: &str) -> String {
    build_mam_fin_element(fin, mam_ns).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_fin_without_rsm() {
        let fin = RsmFin::new(false, true);
        let xml = build_mam_fin(&fin, "urn:xmpp:mam:2");
        assert_eq!(
            xml,
            "<fin xmlns='urn:xmpp:mam:2' complete='false' stable='true'/>"
        );
    }
}
