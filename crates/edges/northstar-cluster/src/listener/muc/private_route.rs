use crate::muc_delivery_endpoints::ClusterMucDeliveryEndpoints;
use northstar_room_core::occupancy::{MucOccupantRoute, MUC_EXACT_ROUTE_ENVELOPE_VERSION};
use northstar_stream::local_routes::{muc::MucOccupant, muc_table::with_local_muc_occupant_exact};

pub(super) enum PrivateRoute<'a> {
    Legacy(&'a str),
    Exact {
        route: MucOccupantRoute,
        require_moderator: bool,
    },
}

pub(super) fn decode(json: &serde_json::Value) -> Option<PrivateRoute<'_>> {
    let nick = json.get("target_nick")?.as_str()?;
    let Some(version) = json.get("envelope_version") else {
        return Some(PrivateRoute::Legacy(nick));
    };
    if version.as_u64()? != MUC_EXACT_ROUTE_ENVELOPE_VERSION {
        return None;
    }
    let route: MucOccupantRoute = serde_json::from_value(json.get("target_route")?.clone()).ok()?;
    if route.nick != nick || !route.is_exact() {
        return None;
    }
    let require_moderator = match json.get("require_role") {
        None => false,
        Some(role) if role.as_str() == Some("moderator") => true,
        _ => return None,
    };
    Some(PrivateRoute::Exact {
        route,
        require_moderator,
    })
}

impl PrivateRoute<'_> {
    pub(super) fn required_moderator(&self) -> Option<&MucOccupantRoute> {
        match self {
            Self::Exact {
                route,
                require_moderator: true,
            } => Some(route),
            _ => None,
        }
    }

    pub(super) fn role_allows(&self, moderators: &[MucOccupantRoute]) -> bool {
        self.required_moderator()
            .is_none_or(|route| moderators.contains(route))
    }

    pub(super) fn recipient(
        &self,
        endpoints: &ClusterMucDeliveryEndpoints,
        room: &str,
    ) -> Option<MucOccupant> {
        match self {
            Self::Legacy(nick) => endpoints.cached_recipient(room, nick),
            Self::Exact { route, .. } => with_local_muc_occupant_exact(
                &endpoints.occupants,
                route.identity(room),
                |current| current.clone(),
            ),
        }
    }
}

#[cfg(test)]
mod tests;
