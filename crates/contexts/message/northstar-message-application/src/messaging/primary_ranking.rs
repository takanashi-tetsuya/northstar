use super::ExactMessageRoute;
use std::cmp::Reverse;

pub enum PrimaryRouteCandidate<'a, S> {
    Local(&'a (String, S)),
    Remote(&'a ExactMessageRoute),
}

pub fn rank_primary_routes<'a, S: 'a>(
    local: impl IntoIterator<Item = (&'a (String, S), Option<i16>)>,
    remote: &'a [ExactMessageRoute],
) -> Vec<PrimaryRouteCandidate<'a, S>> {
    let mut ranked = Vec::new();
    for (target, priority) in local {
        if let Some(priority) = priority.filter(|priority| *priority >= 0) {
            ranked.push((
                (false, Reverse(priority), None, target.0.as_str()),
                PrimaryRouteCandidate::Local(target),
            ));
        }
    }
    for route in remote {
        let Some(node) = route.node_id.as_deref() else {
            continue;
        };
        if route.available == Some(false) || route.priority.is_some_and(|priority| priority < 0) {
            continue;
        }
        let priority = route.priority.filter(|_| route.available == Some(true));
        ranked.push((
            (
                priority.is_none(),
                Reverse(priority.unwrap_or_default()),
                Some(node),
                route.full_jid.as_str(),
            ),
            PrimaryRouteCandidate::Remote(route),
        ));
    }
    ranked.sort_unstable_by_key(|(key, _)| *key);
    ranked.into_iter().map(|(_, candidate)| candidate).collect()
}

#[cfg(test)]
mod tests;
