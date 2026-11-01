//! Submitted XEP-0004 data forms as strict input.

use crate::XmlElement;
use roxmltree::Node;
use std::collections::HashMap;

/// A form that is not a strict submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidForm;

pub fn strict_xdata_submit(
    form: Node<'_, '_>,
    expected_form_type: &str,
    allowed_fields: &[&str],
) -> Result<HashMap<String, String>, InvalidForm> {
    if form.tag_name().name() != "x"
        || form.tag_name().namespace() != Some("jabber:x:data")
        || form.attribute("type") != Some("submit")
        || form
            .attributes()
            .any(|attribute| attribute.name() != "type")
        || form.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(InvalidForm);
    }
    let mut values = HashMap::new();
    for field in form.children().filter(|child| child.is_element()) {
        if field.tag_name().name() != "field"
            || field.tag_name().namespace() != Some("jabber:x:data")
        {
            return Err(InvalidForm);
        }
        let variable = field.attribute("var").ok_or(InvalidForm)?;
        if variable.is_empty()
            || variable.len() > 256
            || field
                .attributes()
                .any(|attribute| !matches!(attribute.name(), "var" | "type" | "label"))
            || field.children().any(|child| {
                !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return Err(InvalidForm);
        }
        let children = field
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if children.len() != 1
            || children[0].tag_name().name() != "value"
            || children[0].tag_name().namespace() != Some("jabber:x:data")
            || children[0].attributes().len() != 0
            || children[0].children().any(|child| child.is_element())
        {
            return Err(InvalidForm);
        }
        let value = children[0]
            .children()
            .filter_map(|child| child.text())
            .collect::<String>();
        if value.len() > 4_096 {
            return Err(InvalidForm);
        }
        // XEP-0004 ignores unknown fields; validate their shape and size first
        // so they remain subject to the same input limits.
        if variable != "FORM_TYPE" && !allowed_fields.contains(&variable) {
            continue;
        }
        if values.insert(variable.to_owned(), value).is_some() {
            return Err(InvalidForm);
        }
    }
    if values.get("FORM_TYPE").map(String::as_str) != Some(expected_form_type)
        || form
            .children()
            .find(|child| {
                child.is_element()
                    && child.tag_name().name() == "field"
                    && child.attribute("var") == Some("FORM_TYPE")
            })
            .and_then(|field| field.attribute("type"))
            != Some("hidden")
    {
        return Err(InvalidForm);
    }
    Ok(values)
}

pub fn xdata_field<'a, 'input>(form: Node<'a, 'input>, name: &str) -> Option<&'a str> {
    form.children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some("jabber:x:data")
                && node.attribute("var") == Some(name)
        })
        .and_then(|node| crate::stanza::child_text(node, "value"))
}

/// An XEP-0004 boolean field holds neither `0`, `1`, `false` nor `true`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidXdataBool;

pub fn xdata_bool(
    form: Node<'_, '_>,
    name: &str,
) -> std::result::Result<Option<bool>, InvalidXdataBool> {
    match xdata_field(form, name) {
        None => Ok(None),
        Some("1" | "true") => Ok(Some(true)),
        Some("0" | "false") => Ok(Some(false)),
        Some(_) => Err(InvalidXdataBool),
    }
}

pub fn xdata_value_field(
    variable: &'static str,
    kind: &'static str,
    value: impl ToString,
) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .attr("type", kind)
        .child(XmlElement::new("value").text(value.to_string()))
}

pub fn bool_value(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

#[cfg(test)]
mod tests;
