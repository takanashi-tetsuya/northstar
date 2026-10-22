#![forbid(unsafe_code)]

//! Transport-neutral metadata and deterministic activation for XMPP extension
//! modules.
//!
//! This crate deliberately has no runtime, database, HTTP, or server-state
//! dependency. An extension can describe its wire routing and relationships
//! here without gaining access to Northstar's application capabilities.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Stable numeric identity of an XMPP Extension Protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct XepId(u16);

impl XepId {
    pub const fn new(number: u16) -> Self {
        Self(number)
    }

    pub const fn number(self) -> u16 {
        self.0
    }
}

impl fmt::Display for XepId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "XEP-{:04}", self.0)
    }
}

/// Top-level XMPP entity to which a route applies.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StanzaKind {
    Message,
    Presence,
    IqGet,
    IqSet,
    Stream,
}

/// A wire-level dispatch key owned by an extension.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StanzaRoute {
    pub stanza: StanzaKind,
    pub namespace: &'static str,
    pub local_name: &'static str,
}

/// Static, capability-free declaration of one extension module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionDescriptor {
    pub id: XepId,
    pub name: &'static str,
    pub default_enabled: bool,
    pub dependencies: &'static [XepId],
    pub conflicts: &'static [XepId],
    pub disco_features: &'static [&'static str],
    pub routes: &'static [StanzaRoute],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureOverride {
    Enable,
    Disable,
}

/// Operator selection before dependency and conflict resolution.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeatureSelection {
    overrides: BTreeMap<XepId, FeatureOverride>,
}

impl FeatureSelection {
    pub fn set(&mut self, id: XepId, value: FeatureOverride) {
        self.overrides.insert(id, value);
    }

    pub fn enable(&mut self, id: XepId) {
        self.set(id, FeatureOverride::Enable);
    }

    pub fn disable(&mut self, id: XepId) {
        self.set(id, FeatureOverride::Disable);
    }

    pub fn get(&self, id: XepId) -> Option<FeatureOverride> {
        self.overrides.get(&id).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (XepId, FeatureOverride)> + '_ {
        self.overrides.iter().map(|(id, value)| (*id, *value))
    }
}

/// Why an extension was initially requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedState {
    DefaultEnabled,
    DefaultDisabled,
    ExplicitlyEnabled,
    ExplicitlyDisabled,
}

/// Auditable, fail-closed activation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveState {
    Enabled,
    DisabledByDefault,
    DisabledExplicitly,
    DisabledMissingDependency(XepId),
    DisabledDependency(XepId),
    DisabledConflict(XepId),
    DisabledRouteConflict { route: StanzaRoute, with: XepId },
    InvalidDuplicateDescriptor,
}

impl EffectiveState {
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedExtension {
    pub id: XepId,
    pub name: &'static str,
    pub requested: RequestedState,
    pub effective: EffectiveState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionIssue {
    DuplicateDescriptor(XepId),
    UnknownOverride(XepId),
    MissingDependency {
        extension: XepId,
        dependency: XepId,
    },
    DisabledDependency {
        extension: XepId,
        dependency: XepId,
    },
    Conflict {
        first: XepId,
        second: XepId,
    },
    RouteConflict {
        route: StanzaRoute,
        first: XepId,
        second: XepId,
    },
}

/// Complete deterministic result suitable for logging or an admin status API.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeatureResolution {
    pub extensions: Vec<ResolvedExtension>,
    pub issues: Vec<ResolutionIssue>,
    pub disco_features: Vec<&'static str>,
    pub routes: Vec<(XepId, StanzaRoute)>,
}

impl FeatureResolution {
    pub fn state(&self, id: XepId) -> Option<EffectiveState> {
        self.extensions
            .iter()
            .find(|extension| extension.id == id)
            .map(|extension| extension.effective)
    }

    pub fn is_enabled(&self, id: XepId) -> bool {
        self.state(id).is_some_and(EffectiveState::is_enabled)
    }
}

/// Resolve a catalog without depending on input order.
///
/// Explicit disablement always wins. Missing or disabled dependencies disable
/// their dependants. A declared conflict disables both requested extensions;
/// the resolver never chooses a winner implicitly.
pub fn resolve_features(
    catalog: &[&'static ExtensionDescriptor],
    selection: &FeatureSelection,
) -> FeatureResolution {
    let mut descriptors = BTreeMap::<XepId, &'static ExtensionDescriptor>::new();
    let mut duplicates = BTreeSet::new();
    for descriptor in catalog {
        if descriptors.insert(descriptor.id, descriptor).is_some() {
            duplicates.insert(descriptor.id);
        }
    }

    let mut issues = BTreeSet::<IssueKey>::new();
    for duplicate in &duplicates {
        issues.insert(IssueKey::DuplicateDescriptor(*duplicate));
    }
    for (id, _) in selection.iter() {
        if !descriptors.contains_key(&id) {
            issues.insert(IssueKey::UnknownOverride(id));
        }
    }

    let mut extensions = BTreeMap::<XepId, ResolvedExtension>::new();
    for (id, descriptor) in &descriptors {
        let requested = if duplicates.contains(id) {
            match selection.get(*id) {
                Some(FeatureOverride::Enable) => RequestedState::ExplicitlyEnabled,
                Some(FeatureOverride::Disable) => RequestedState::ExplicitlyDisabled,
                None => RequestedState::DefaultDisabled,
            }
        } else {
            match selection.get(*id) {
                Some(FeatureOverride::Enable) => RequestedState::ExplicitlyEnabled,
                Some(FeatureOverride::Disable) => RequestedState::ExplicitlyDisabled,
                None if descriptor.default_enabled => RequestedState::DefaultEnabled,
                None => RequestedState::DefaultDisabled,
            }
        };
        let effective = if duplicates.contains(id) {
            EffectiveState::InvalidDuplicateDescriptor
        } else {
            match requested {
                RequestedState::ExplicitlyDisabled => EffectiveState::DisabledExplicitly,
                RequestedState::DefaultDisabled => EffectiveState::DisabledByDefault,
                RequestedState::DefaultEnabled | RequestedState::ExplicitlyEnabled => {
                    EffectiveState::Enabled
                }
            }
        };
        extensions.insert(
            *id,
            ResolvedExtension {
                id: *id,
                name: if duplicates.contains(id) {
                    "<duplicate descriptor>"
                } else {
                    descriptor.name
                },
                requested,
                effective,
            },
        );
    }

    // Conflicts are evaluated over requested features, before dependency
    // propagation, so catalog order can never select a winner.
    for (id, descriptor) in &descriptors {
        if !extensions
            .get(id)
            .is_some_and(|extension| extension.effective.is_enabled())
        {
            continue;
        }
        for conflict in descriptor.conflicts {
            if *conflict == *id
                || !extensions
                    .get(conflict)
                    .is_some_and(|extension| extension.effective.is_enabled())
            {
                continue;
            }
            let (first, second) = if id < conflict {
                (*id, *conflict)
            } else {
                (*conflict, *id)
            };
            issues.insert(IssueKey::Conflict(first, second));
        }
    }
    let conflicts = issues
        .iter()
        .filter_map(|issue| match issue {
            IssueKey::Conflict(first, second) => Some((*first, *second)),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (first, second) in conflicts {
        if let Some(extension) = extensions.get_mut(&first) {
            extension.effective = EffectiveState::DisabledConflict(second);
        }
        if let Some(extension) = extensions.get_mut(&second) {
            extension.effective = EffectiveState::DisabledConflict(first);
        }
    }

    propagate_dependency_failures(&descriptors, &mut extensions, &mut issues);

    // One wire route has one owner. Ambiguous dispatch is disabled rather than
    // being resolved by catalog registration order.
    let mut route_owners = BTreeMap::<StanzaRoute, Vec<XepId>>::new();
    for (id, descriptor) in &descriptors {
        if extensions
            .get(id)
            .is_some_and(|extension| extension.effective.is_enabled())
        {
            for route in descriptor.routes {
                route_owners.entry(*route).or_default().push(*id);
            }
        }
    }
    for (route, owners) in route_owners {
        if owners.len() < 2 {
            continue;
        }
        for (offset, first) in owners.iter().enumerate() {
            for second in owners.iter().skip(offset + 1) {
                issues.insert(IssueKey::RouteConflict(route, *first, *second));
            }
            let with = owners
                .iter()
                .copied()
                .find(|owner| owner != first)
                .expect("a conflicting route has another owner");
            extensions
                .get_mut(first)
                .expect("route owner is a catalog entry")
                .effective = EffectiveState::DisabledRouteConflict { route, with };
        }
    }
    // Route conflict disablement can invalidate downstream dependants.
    propagate_dependency_failures(&descriptors, &mut extensions, &mut issues);

    let mut disco_features = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for (id, descriptor) in &descriptors {
        if extensions
            .get(id)
            .is_some_and(|extension| extension.effective.is_enabled())
        {
            disco_features.extend(descriptor.disco_features.iter().copied());
            routes.extend(descriptor.routes.iter().copied().map(|route| (*id, route)));
        }
    }

    FeatureResolution {
        extensions: extensions.into_values().collect(),
        issues: issues.into_iter().map(ResolutionIssue::from).collect(),
        disco_features: disco_features.into_iter().collect(),
        routes: routes.into_iter().collect(),
    }
}

fn propagate_dependency_failures(
    descriptors: &BTreeMap<XepId, &'static ExtensionDescriptor>,
    extensions: &mut BTreeMap<XepId, ResolvedExtension>,
    issues: &mut BTreeSet<IssueKey>,
) {
    loop {
        let previous = extensions
            .iter()
            .map(|(id, extension)| (*id, extension.effective))
            .collect::<BTreeMap<_, _>>();
        let mut changed = false;
        for (id, descriptor) in descriptors {
            if !previous.get(id).is_some_and(|state| state.is_enabled()) {
                continue;
            }
            let failure = descriptor.dependencies.iter().find_map(|dependency| {
                if !descriptors.contains_key(dependency) {
                    Some((true, *dependency))
                } else if !previous
                    .get(dependency)
                    .is_some_and(|state| state.is_enabled())
                {
                    Some((false, *dependency))
                } else {
                    None
                }
            });
            if let Some((missing, dependency)) = failure {
                let effective = if missing {
                    issues.insert(IssueKey::MissingDependency(*id, dependency));
                    EffectiveState::DisabledMissingDependency(dependency)
                } else {
                    issues.insert(IssueKey::DisabledDependency(*id, dependency));
                    EffectiveState::DisabledDependency(dependency)
                };
                extensions
                    .get_mut(id)
                    .expect("catalog entry exists")
                    .effective = effective;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IssueKey {
    DuplicateDescriptor(XepId),
    UnknownOverride(XepId),
    MissingDependency(XepId, XepId),
    DisabledDependency(XepId, XepId),
    Conflict(XepId, XepId),
    RouteConflict(StanzaRoute, XepId, XepId),
}

impl From<IssueKey> for ResolutionIssue {
    fn from(issue: IssueKey) -> Self {
        match issue {
            IssueKey::DuplicateDescriptor(id) => Self::DuplicateDescriptor(id),
            IssueKey::UnknownOverride(id) => Self::UnknownOverride(id),
            IssueKey::MissingDependency(extension, dependency) => Self::MissingDependency {
                extension,
                dependency,
            },
            IssueKey::DisabledDependency(extension, dependency) => Self::DisabledDependency {
                extension,
                dependency,
            },
            IssueKey::Conflict(first, second) => Self::Conflict { first, second },
            IssueKey::RouteConflict(route, first, second) => Self::RouteConflict {
                route,
                first,
                second,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XEP_30: XepId = XepId::new(30);
    const XEP_184: XepId = XepId::new(184);
    const XEP_999: XepId = XepId::new(999);
    const XEP_1000: XepId = XepId::new(1000);

    static DISCO: ExtensionDescriptor = ExtensionDescriptor {
        id: XEP_30,
        name: "Service Discovery",
        default_enabled: true,
        dependencies: &[],
        conflicts: &[],
        disco_features: &["http://jabber.org/protocol/disco#info"],
        routes: &[],
    };
    static RECEIPTS: ExtensionDescriptor = ExtensionDescriptor {
        id: XEP_184,
        name: "Message Delivery Receipts",
        default_enabled: true,
        dependencies: &[XEP_30],
        conflicts: &[],
        disco_features: &["urn:xmpp:receipts"],
        routes: &[StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: "urn:xmpp:receipts",
            local_name: "request",
        }],
    };

    #[test]
    fn resolution_is_order_independent_and_aggregates_metadata() {
        let forward = resolve_features(&[&DISCO, &RECEIPTS], &FeatureSelection::default());
        let reverse = resolve_features(&[&RECEIPTS, &DISCO], &FeatureSelection::default());
        assert_eq!(forward, reverse);
        assert!(forward.is_enabled(XEP_184));
        assert_eq!(
            forward.disco_features,
            vec!["http://jabber.org/protocol/disco#info", "urn:xmpp:receipts",]
        );
        assert_eq!(forward.routes.len(), 1);
    }

    #[test]
    fn explicit_disable_propagates_fail_closed() {
        let mut selection = FeatureSelection::default();
        selection.disable(XEP_30);
        let resolution = resolve_features(&[&DISCO, &RECEIPTS], &selection);
        assert_eq!(
            resolution.state(XEP_30),
            Some(EffectiveState::DisabledExplicitly)
        );
        assert_eq!(
            resolution.state(XEP_184),
            Some(EffectiveState::DisabledDependency(XEP_30))
        );
        assert!(resolution.disco_features.is_empty());
        assert!(resolution.routes.is_empty());
    }

    #[test]
    fn missing_dependencies_and_unknown_overrides_are_auditable() {
        let mut selection = FeatureSelection::default();
        selection.enable(XEP_999);
        let resolution = resolve_features(&[&RECEIPTS], &selection);
        assert_eq!(
            resolution.state(XEP_184),
            Some(EffectiveState::DisabledMissingDependency(XEP_30))
        );
        assert!(resolution
            .issues
            .contains(&ResolutionIssue::UnknownOverride(XEP_999)));
        assert!(resolution
            .issues
            .contains(&ResolutionIssue::MissingDependency {
                extension: XEP_184,
                dependency: XEP_30,
            }));
    }

    #[test]
    fn conflicts_disable_both_sides_without_choosing_a_winner() {
        static FIRST: ExtensionDescriptor = ExtensionDescriptor {
            id: XEP_999,
            name: "First",
            default_enabled: true,
            dependencies: &[],
            conflicts: &[XEP_1000],
            disco_features: &["urn:first"],
            routes: &[],
        };
        static SECOND: ExtensionDescriptor = ExtensionDescriptor {
            id: XEP_1000,
            name: "Second",
            default_enabled: true,
            dependencies: &[],
            conflicts: &[],
            disco_features: &["urn:second"],
            routes: &[],
        };
        let resolution = resolve_features(&[&SECOND, &FIRST], &FeatureSelection::default());
        assert_eq!(
            resolution.state(XEP_999),
            Some(EffectiveState::DisabledConflict(XEP_1000))
        );
        assert_eq!(
            resolution.state(XEP_1000),
            Some(EffectiveState::DisabledConflict(XEP_999))
        );
        assert!(resolution.disco_features.is_empty());
    }

    #[test]
    fn duplicate_descriptors_are_never_activated() {
        let resolution = resolve_features(&[&DISCO, &DISCO], &FeatureSelection::default());
        assert_eq!(
            resolution.state(XEP_30),
            Some(EffectiveState::InvalidDuplicateDescriptor)
        );
        assert!(resolution
            .issues
            .contains(&ResolutionIssue::DuplicateDescriptor(XEP_30)));
    }

    #[test]
    fn duplicate_route_owners_are_both_disabled() {
        static FIRST: ExtensionDescriptor = ExtensionDescriptor {
            id: XEP_999,
            name: "First",
            default_enabled: true,
            dependencies: &[],
            conflicts: &[],
            disco_features: &["urn:first"],
            routes: &[StanzaRoute {
                stanza: StanzaKind::IqSet,
                namespace: "urn:shared",
                local_name: "command",
            }],
        };
        static SECOND: ExtensionDescriptor = ExtensionDescriptor {
            id: XEP_1000,
            name: "Second",
            default_enabled: true,
            dependencies: &[],
            conflicts: &[],
            disco_features: &["urn:second"],
            routes: FIRST.routes,
        };
        let resolution = resolve_features(&[&SECOND, &FIRST], &FeatureSelection::default());
        assert!(matches!(
            resolution.state(XEP_999),
            Some(EffectiveState::DisabledRouteConflict { with, .. }) if with == XEP_1000
        ));
        assert!(matches!(
            resolution.state(XEP_1000),
            Some(EffectiveState::DisabledRouteConflict { with, .. }) if with == XEP_999
        ));
        assert!(resolution.routes.is_empty());
        assert!(resolution.issues.iter().any(|issue| matches!(
            issue,
            ResolutionIssue::RouteConflict { first, second, .. }
                if *first == XEP_999 && *second == XEP_1000
        )));
    }
}
