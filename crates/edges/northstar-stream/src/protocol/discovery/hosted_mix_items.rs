use super::{disco_item, iq_error_from, iq_result_from, XmlElement};
use northstar_room_application::mix_service::{
    HostedDiscoView, CORE_NODES, NODE_ALLOWED, NODE_AVATAR_DATA, NODE_AVATAR_METADATA, NODE_BANNED,
    NODE_CONFIG, NODE_JIDMAP,
};

pub(super) fn reply(
    view: Option<&HostedDiscoView>,
    requested_node: Option<&str>,
    id: &str,
    from: &str,
    mut query: XmlElement,
) -> String {
    let Some(view) = view.filter(|view| view.visible_to_actor) else {
        return iq_error_from(id, from, "item-not-found");
    };
    match requested_node {
        None => {}
        Some("mix") => {
            for node in CORE_NODES {
                query.push_child(disco_item(from, Some(node), None));
            }
            if view.actor_role.is_some() {
                for node in [NODE_CONFIG, NODE_ALLOWED, NODE_BANNED, NODE_JIDMAP] {
                    query.push_child(disco_item(from, Some(node), None));
                }
            }
            for node in [NODE_AVATAR_DATA, NODE_AVATAR_METADATA] {
                query.push_child(disco_item(from, Some(node), None));
            }
        }
        Some(_) => return iq_error_from(id, from, "item-not-found"),
    }
    iq_result_from(id, from, &query.finish())
}

#[cfg(test)]
mod tests;
