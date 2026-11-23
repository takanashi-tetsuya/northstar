use super::{disco_item, disco_rsm_result_element, XmlElement};
use northstar_xml_builder::disco::DiscoItemsRequest;

pub(super) fn append_room_items(
    query: &mut XmlElement,
    room_jid: &str,
    nicks: &[String],
    request: &DiscoItemsRequest,
) -> bool {
    let after = request.after.as_deref();
    let before = request.before.as_ref().and_then(|value| value.as_deref());
    if after
        .or(before)
        .is_some_and(|cursor| !nicks.iter().any(|nick| nick == cursor))
    {
        return false;
    }
    let start = nicks.partition_point(|nick| after.is_some_and(|cursor| nick.as_str() <= cursor));
    let end = nicks.partition_point(|nick| before.is_none_or(|cursor| nick.as_str() < cursor));
    let limit = request.max.clamp(0, 100) as usize;
    let shown_end = if request.before.is_some() {
        end
    } else {
        end.min(start + limit)
    };
    let shown_start = start.max(shown_end.saturating_sub(limit));
    let page = nicks.get(shown_start..shown_end).unwrap_or_default();
    for nick in page {
        query.push_child(disco_item(&format!("{room_jid}/{nick}"), None, None));
    }
    query.push_child(disco_rsm_result_element(
        page.first().map(String::as_str),
        page.last().map(String::as_str),
        shown_start as i64,
        nicks.len() as i64,
    ));
    true
}

#[cfg(test)]
mod tests;
