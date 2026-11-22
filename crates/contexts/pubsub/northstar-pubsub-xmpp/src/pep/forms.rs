//! Decode PEP node configuration forms into core patches.

use super::{child_text, parse_form_bool, xdata_field, NS_XDATA};
use northstar_pubsub_core::{PepConfigPatch, PepMaxItems};
use roxmltree::Node;
use std::collections::HashSet;

pub(in crate::pep) fn is_pep_config_form(form: Node<'_, '_>) -> bool {
    form.is_element()
        && form.tag_name().namespace() == Some(NS_XDATA)
        && form.tag_name().name() == "x"
}

pub(in crate::pep) fn decode_pep_config_form(
    form: Node<'_, '_>,
    expected_form_type: &str,
) -> Result<PepConfigPatch, ()> {
    if form.attribute("type") != Some("submit")
        || xdata_field(form, "FORM_TYPE") != Some(expected_form_type)
    {
        return Err(());
    }
    let mut patch = PepConfigPatch::default();
    let mut seen = HashSet::new();
    for field in form.children().filter(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(NS_XDATA)
            && child.tag_name().name() == "field"
    }) {
        let variable = field.attribute("var").ok_or(())?;
        if !seen.insert(variable) {
            return Err(());
        }
        let value = || child_text(field, "value").ok_or(());
        match variable {
            "FORM_TYPE" => {}
            "pubsub#access_model" => patch.access_model = Some(value()?.to_owned()),
            "pubsub#max_items" => {
                patch.max_items = Some(match value()? {
                    "max" => PepMaxItems::Max,
                    count => PepMaxItems::Count(count.parse().map_err(|_| ())?),
                });
            }
            "pubsub#persist_items" => patch.persist_items = Some(parse_form_bool(value()?)?),
            "pubsub#send_last_published_item" => {
                patch.send_last_published_item = Some(value()?.to_owned());
            }
            "pubsub#deliver_notifications" => {
                patch.deliver_notifications = Some(parse_form_bool(value()?)?);
            }
            "pubsub#roster_groups_allowed" => {
                patch.roster_groups_allowed = Some(
                    field
                        .children()
                        .filter(|child| {
                            child.is_element()
                                && child.tag_name().namespace() == Some(NS_XDATA)
                                && child.tag_name().name() == "value"
                        })
                        .map(|child| child.text().unwrap_or_default().to_owned())
                        .collect(),
                );
            }
            _ => return Err(()),
        }
    }
    Ok(patch)
}
