use super::{field_first, validate_form_fields, ANON_NS};
use crate::services::mix::MixParticipantPreference;
use crate::xmpp::xml_builder::XmlElement;
use anyhow::{Context, Result};
use roxmltree::Node;
use std::collections::BTreeMap;

pub(super) fn is_xdata(node: Node<'_, '_>) -> bool {
    node.is_element()
        && node.tag_name().name() == "x"
        && node.tag_name().namespace() == Some("jabber:x:data")
}

pub(super) fn parse_fields(form: Node<'_, '_>) -> Result<BTreeMap<String, Vec<String>>> {
    anyhow::ensure!(
        matches!(form.attribute("type"), Some("submit" | "result")),
        "invalid MIX data form"
    );
    let mut fields = BTreeMap::new();
    for field in form.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "field"
            && node.tag_name().namespace() == Some("jabber:x:data")
    }) {
        let var = field
            .attribute("var")
            .context("MIX form field missing var")?;
        let values = field
            .children()
            .filter(|node| node.is_element() && node.tag_name().name() == "value")
            .map(|node| node.text().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        anyhow::ensure!(
            fields.insert(var.to_owned(), values).is_none(),
            "duplicate MIX form field"
        );
    }
    Ok(fields)
}

fn mix_xdata_value_field(
    variable: &'static str,
    kind: Option<&'static str>,
    value: impl ToString,
) -> XmlElement {
    XmlElement::new("field")
        .attr("var", variable)
        .optional_attr("type", kind)
        .child(XmlElement::new("value").text(value.to_string()))
}

fn mix_xdata_option(value: &'static str) -> XmlElement {
    XmlElement::new("option").child(XmlElement::new("value").text(value))
}

pub(super) fn preference_result_form(preference: &MixParticipantPreference) -> String {
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "result")
        .child(mix_xdata_value_field("FORM_TYPE", Some("hidden"), ANON_NS))
        .child(mix_xdata_value_field(
            "JID Visibility",
            None,
            &preference.jid_visibility,
        ))
        .child(mix_xdata_value_field(
            "Private Messages",
            None,
            &preference.private_messages,
        ))
        .child(mix_xdata_value_field("vCard", None, &preference.vcard))
        .child(mix_xdata_value_field(
            "Presence",
            None,
            if preference.share_presence {
                "share"
            } else {
                "not share"
            },
        ))
        .finish()
}

pub(super) fn preference_template_form() -> String {
    let mut visibility = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "JID Visibility");
    for value in ["default", "never", "always", "prefer not"] {
        visibility.push_child(mix_xdata_option(value));
    }
    let mut private_messages = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "Private Messages");
    for value in ["allow", "block"] {
        private_messages.push_child(mix_xdata_option(value));
    }
    let mut vcard = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "vCard");
    for value in ["allow", "block"] {
        vcard.push_child(mix_xdata_option(value));
    }
    let mut presence = XmlElement::new("field")
        .attr("type", "list-single")
        .attr("var", "Presence");
    for value in ["share", "not share"] {
        presence.push_child(mix_xdata_option(value));
    }
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "form")
        .child(mix_xdata_value_field("FORM_TYPE", Some("hidden"), ANON_NS))
        .child(visibility)
        .child(private_messages)
        .child(vcard)
        .child(presence)
        .finish()
}

pub(super) fn parse_preference_submission(
    fields: &BTreeMap<String, Vec<String>>,
    current: Option<&MixParticipantPreference>,
) -> Result<MixParticipantPreference> {
    validate_form_fields(
        fields,
        &[
            "FORM_TYPE",
            "JID Visibility",
            "Private Messages",
            "vCard",
            "Presence",
        ],
        &[],
    )?;
    anyhow::ensure!(
        field_first(fields, "FORM_TYPE") == Some(ANON_NS),
        "invalid MIX-ANON preference form"
    );
    let default = MixParticipantPreference::default();
    let current = current.unwrap_or(&default);
    let preference = MixParticipantPreference {
        jid_visibility: field_first(fields, "JID Visibility")
            .unwrap_or(&current.jid_visibility)
            .to_owned(),
        private_messages: field_first(fields, "Private Messages")
            .unwrap_or(&current.private_messages)
            .to_owned(),
        vcard: field_first(fields, "vCard")
            .unwrap_or(&current.vcard)
            .to_owned(),
        share_presence: match field_first(fields, "Presence") {
            None => current.share_presence,
            Some("share") => true,
            Some("not share") => false,
            Some(_) => anyhow::bail!("invalid MIX presence preference"),
        },
    };
    anyhow::ensure!(
        matches!(
            preference.jid_visibility.as_str(),
            "default" | "never" | "always" | "prefer not"
        ) && matches!(preference.private_messages.as_str(), "allow" | "block")
            && matches!(preference.vcard.as_str(), "allow" | "block"),
        "invalid MIX participant preference"
    );
    Ok(preference)
}
