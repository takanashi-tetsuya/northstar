use super::*;
use northstar_room_application::mix_service::valid_stable_participant_id;
use roxmltree::Node;

const SID_NS: &str = "urn:xmpp:sid:0";

pub(super) fn claims_retraction(root: Node<'_, '_>) -> bool {
    root.children().any(is_retract)
}

fn is_retract(node: Node<'_, '_>) -> bool {
    node.is_element() && node.has_tag_name((MISC_NS, "retract"))
}

pub(super) fn verified_target(
    root: Node<'_, '_>,
    action: Uuid,
    local_mix: &str,
    authenticated_domain: &str,
) -> Option<Uuid> {
    let from = root.attribute("from")?;
    let source = CanonicalJid::parse(from).ok()?;
    let channel = source.bare();
    let to = root.attribute("to")?;
    let recipient = CanonicalJid::parse_bare(to).ok()?;
    if source.to_string() != from
        || source.localpart().is_none()
        || !source
            .resourcepart()
            .is_some_and(valid_stable_participant_id)
        || !source.domainpart().starts_with("mix.")
        || same_jid_domain(source.domainpart(), local_mix)
        || !authenticated_mix_service(source.domainpart(), authenticated_domain)
        || recipient.localpart().is_none()
        || recipient.to_string() != to
        || root.attribute("type") != Some("groupchat")
        || root.attribute("id")? != action.to_string()
        || root.attributes().any(|attr| {
            attr.namespace().is_some() || !matches!(attr.name(), "from" | "to" | "id" | "type")
        })
    {
        return None;
    }
    let mut target = None;
    for child in root.children() {
        if is_retract(child) {
            let claimed = child.attribute("id")?;
            let id = Uuid::parse_str(claimed).ok()?;
            if target.replace(id).is_some()
                || id == action
                || id.to_string() != claimed
                || child.attributes().len() != 1
                || child.first_child().is_some()
            {
                return None;
            }
        } else if child.is_element() && child.has_tag_name((SID_NS, "stanza-id")) {
            if child.attribute("by") != Some(channel.as_str())
                || child.attributes().len() != 2
                || child.first_child().is_some()
            {
                return None;
            }
        } else if child.is_element() && child.has_tag_name((CORE_NS, "mix")) {
            if child.attributes().next().is_some()
                || !child.children().all(|element| {
                    whitespace(element)
                        || (element.is_element()
                            && element.attributes().next().is_none()
                            && element.children().all(|text| text.is_text()))
                })
            {
                return None;
            }
        } else if !whitespace(child) {
            return None;
        }
    }
    target
}

fn whitespace(node: Node<'_, '_>) -> bool {
    node.is_text() && node.text().is_some_and(|text| text.trim().is_empty())
}
