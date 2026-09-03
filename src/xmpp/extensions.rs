//! Runtime activation boundary for capability-free XEP crates.
//!
//! The registry is the only place where built-in protocol foundations and
//! independently compiled extensions are assembled. Transport handlers query
//! the resolved result; they do not reinterpret environment switches.

use northstar_xep_core::{
    resolve_features, ExtensionDescriptor, FeatureResolution, FeatureSelection, StanzaKind, XepId,
};

pub(crate) const XEP_0030: XepId = XepId::new(30);

/// XEP-0030 is a built-in protocol foundation rather than an optional crate.
/// Its descriptor is backed by `protocol::discovery` and makes dependencies
/// explicit without pretending they are enabled outside the resolver.
static SERVICE_DISCOVERY: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_0030,
    name: "Service Discovery",
    default_enabled: true,
    dependencies: &[],
    conflicts: &[],
    disco_features: &[
        "http://jabber.org/protocol/disco#info",
        "http://jabber.org/protocol/disco#items",
    ],
    routes: &[],
};

static CATALOG: &[&ExtensionDescriptor] = &[
    &SERVICE_DISCOVERY,
    &northstar_xep_0016::DESCRIPTOR,
    &northstar_xep_0045::DESCRIPTOR,
    &northstar_xep_0059::DESCRIPTOR,
    &northstar_xep_0060::DESCRIPTOR,
    &northstar_xep_0313::DESCRIPTOR,
    &northstar_xep_0352::DESCRIPTOR,
    &northstar_xep_0357::DESCRIPTOR,
    &northstar_xep_0085::DESCRIPTOR,
    &northstar_xep_0184::DESCRIPTOR,
    &northstar_xep_0092::DESCRIPTOR,
    &northstar_xep_0115::DESCRIPTOR,
    &northstar_xep_0191::DESCRIPTOR,
    &northstar_xep_0198::DESCRIPTOR,
    &northstar_xep_0199::DESCRIPTOR,
    &northstar_xep_0202::DESCRIPTOR,
    &northstar_xep_0215::DESCRIPTOR,
    &northstar_xep_0280::DESCRIPTOR,
    &northstar_xep_0308::DESCRIPTOR,
    &northstar_xep_0333::DESCRIPTOR,
    &northstar_xep_0359::DESCRIPTOR,
    &northstar_xep_0363::DESCRIPTOR,
    &northstar_xep_0380::DESCRIPTOR,
    &northstar_xep_0444::DESCRIPTOR,
    &northstar_xep_0461::DESCRIPTOR,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExtensionSwitches {
    pub xep_0016: bool,
    pub xep_0045: bool,
    pub xep_0059: bool,
    pub xep_0060: bool,
    pub xep_0085: bool,
    pub xep_0092: bool,
    pub xep_0115: bool,
    pub xep_0184: bool,
    pub xep_0191: bool,
    pub xep_0198: bool,
    pub xep_0199: bool,
    pub xep_0202: bool,
    pub xep_0215: bool,
    pub xep_0280: bool,
    pub xep_0313: bool,
    pub xep_0352: bool,
    pub xep_0357: bool,
    pub xep_0359: bool,
    pub xep_0363: bool,
    pub xep_0308: bool,
    pub xep_0333: bool,
    pub xep_0380: bool,
    pub xep_0444: bool,
    pub xep_0461: bool,
}

impl Default for ExtensionSwitches {
    fn default() -> Self {
        Self {
            xep_0016: true,
            xep_0045: true,
            xep_0059: true,
            xep_0060: true,
            xep_0085: true,
            xep_0092: true,
            xep_0115: true,
            xep_0184: true,
            xep_0191: true,
            xep_0198: true,
            xep_0199: true,
            xep_0202: true,
            xep_0215: true,
            xep_0280: true,
            xep_0313: true,
            xep_0352: true,
            xep_0357: true,
            xep_0359: true,
            xep_0363: true,
            xep_0308: true,
            xep_0333: true,
            xep_0380: true,
            xep_0444: true,
            xep_0461: true,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ExtensionRuntime {
    resolution: FeatureResolution,
}

impl ExtensionRuntime {
    pub(crate) fn resolve(switches: ExtensionSwitches) -> Self {
        let mut selection = FeatureSelection::default();
        for (id, enabled) in [
            (northstar_xep_0016::XEP_ID, switches.xep_0016),
            (northstar_xep_0045::XEP_ID, switches.xep_0045),
            (northstar_xep_0059::XEP_ID, switches.xep_0059),
            (northstar_xep_0060::XEP_ID, switches.xep_0060),
            (northstar_xep_0085::XEP_ID, switches.xep_0085),
            (northstar_xep_0092::XEP_ID, switches.xep_0092),
            (northstar_xep_0115::XEP_ID, switches.xep_0115),
            (northstar_xep_0184::XEP_ID, switches.xep_0184),
            (northstar_xep_0191::XEP_ID, switches.xep_0191),
            (northstar_xep_0198::XEP_ID, switches.xep_0198),
            (northstar_xep_0199::XEP_ID, switches.xep_0199),
            (northstar_xep_0202::XEP_ID, switches.xep_0202),
            (northstar_xep_0215::XEP_ID, switches.xep_0215),
            (northstar_xep_0280::XEP_ID, switches.xep_0280),
            (northstar_xep_0313::XEP_ID, switches.xep_0313),
            (northstar_xep_0352::XEP_ID, switches.xep_0352),
            (northstar_xep_0357::XEP_ID, switches.xep_0357),
            (northstar_xep_0359::XEP_ID, switches.xep_0359),
            (northstar_xep_0363::XEP_ID, switches.xep_0363),
            (northstar_xep_0308::XEP_ID, switches.xep_0308),
            (northstar_xep_0333::XEP_ID, switches.xep_0333),
            (northstar_xep_0380::XEP_ID, switches.xep_0380),
            (northstar_xep_0444::XEP_ID, switches.xep_0444),
            (northstar_xep_0461::XEP_ID, switches.xep_0461),
        ] {
            if enabled {
                selection.enable(id);
            } else {
                selection.disable(id);
            }
        }
        Self {
            resolution: resolve_features(CATALOG, &selection),
        }
    }

    pub(crate) fn enabled(&self, id: XepId) -> bool {
        self.resolution.is_enabled(id)
    }

    pub(crate) fn route_enabled(
        &self,
        stanza: StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool {
        self.resolution.routes.iter().any(|(_, route)| {
            route.stanza == stanza && route.namespace == namespace && route.local_name == local_name
        })
    }

    pub(crate) fn server_disco_features(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.resolution
            .disco_features
            .iter()
            .copied()
            .filter(|feature| {
                !matches!(
                    *feature,
                    "http://jabber.org/protocol/disco#info"
                        | "http://jabber.org/protocol/disco#items"
                        | northstar_xep_0059::NAMESPACE
                        | northstar_xep_0184::NAMESPACE
                        | northstar_xep_0359::NAMESPACE
                ) && !feature.starts_with("http://jabber.org/protocol/pubsub")
                    && !feature.starts_with("http://jabber.org/protocol/muc")
                    && !feature.starts_with("muc_")
            })
    }

    #[cfg(test)]
    pub(crate) fn resolution(&self) -> &FeatureResolution {
        &self.resolution
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_xep_core::{EffectiveState, StanzaKind};

    #[test]
    fn built_in_disco_satisfies_real_plugin_dependencies() {
        let runtime = ExtensionRuntime::resolve(ExtensionSwitches::default());
        assert_eq!(
            runtime.resolution().state(XEP_0030),
            Some(EffectiveState::Enabled)
        );
        for id in [
            northstar_xep_0016::XEP_ID,
            northstar_xep_0045::XEP_ID,
            northstar_xep_0060::XEP_ID,
            northstar_xep_0085::XEP_ID,
            northstar_xep_0184::XEP_ID,
            northstar_xep_0092::XEP_ID,
            northstar_xep_0115::XEP_ID,
            northstar_xep_0191::XEP_ID,
            northstar_xep_0198::XEP_ID,
            northstar_xep_0199::XEP_ID,
            northstar_xep_0202::XEP_ID,
            northstar_xep_0215::XEP_ID,
            northstar_xep_0280::XEP_ID,
            northstar_xep_0059::XEP_ID,
            northstar_xep_0313::XEP_ID,
            northstar_xep_0352::XEP_ID,
            northstar_xep_0357::XEP_ID,
            northstar_xep_0308::XEP_ID,
            northstar_xep_0333::XEP_ID,
            northstar_xep_0359::XEP_ID,
            northstar_xep_0363::XEP_ID,
            northstar_xep_0380::XEP_ID,
            northstar_xep_0444::XEP_ID,
            northstar_xep_0461::XEP_ID,
        ] {
            assert_eq!(
                runtime.resolution().state(id),
                Some(EffectiveState::Enabled)
            );
        }
        assert!(runtime.resolution().issues.is_empty());
    }

    #[test]
    fn disabled_extension_loses_both_route_and_disco_feature() {
        let runtime = ExtensionRuntime::resolve(ExtensionSwitches {
            xep_0016: false,
            xep_0045: false,
            xep_0059: false,
            xep_0060: false,
            xep_0085: false,
            xep_0092: false,
            xep_0115: false,
            xep_0184: false,
            xep_0191: false,
            xep_0198: false,
            xep_0199: false,
            xep_0202: false,
            xep_0215: false,
            xep_0280: false,
            xep_0313: false,
            xep_0352: false,
            xep_0357: false,
            xep_0359: false,
            xep_0363: false,
            xep_0308: false,
            xep_0333: false,
            xep_0380: false,
            xep_0444: false,
            xep_0461: false,
        });
        for (id, stanza, namespace, local_name) in [
            (
                northstar_xep_0016::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0016::NAMESPACE,
                "query",
            ),
            (
                northstar_xep_0045::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0045::XMLNS_MUC_ADMIN,
                "query",
            ),
            (
                northstar_xep_0060::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0060::NS_PUBSUB,
                "pubsub",
            ),
            (
                northstar_xep_0085::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0085::NAMESPACE,
                "active",
            ),
            (
                northstar_xep_0092::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0092::NAMESPACE,
                "query",
            ),
            (
                northstar_xep_0115::XEP_ID,
                StanzaKind::Presence,
                northstar_xep_0115::CAPS_NS,
                "c",
            ),
            (
                northstar_xep_0184::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0184::NAMESPACE,
                "request",
            ),
            (
                northstar_xep_0191::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0191::NAMESPACE,
                "blocklist",
            ),
            (
                northstar_xep_0198::XEP_ID,
                StanzaKind::Stream,
                northstar_xep_0198::NAMESPACE,
                "enable",
            ),
            (
                northstar_xep_0199::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0199::NAMESPACE,
                "ping",
            ),
            (
                northstar_xep_0202::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0202::NAMESPACE,
                "time",
            ),
            (
                northstar_xep_0215::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0215::NAMESPACE,
                "services",
            ),
            (
                northstar_xep_0280::XEP_ID,
                StanzaKind::IqSet,
                northstar_xep_0280::NAMESPACE,
                "enable",
            ),
            (
                northstar_xep_0313::XEP_ID,
                StanzaKind::IqSet,
                northstar_xep_0313::XMLNS_MAM,
                "query",
            ),
            (
                northstar_xep_0352::XEP_ID,
                StanzaKind::Stream,
                northstar_xep_0352::NAMESPACE,
                "active",
            ),
            (
                northstar_xep_0357::XEP_ID,
                StanzaKind::IqSet,
                northstar_xep_0357::XMLNS_PUSH,
                "enable",
            ),
            (
                northstar_xep_0359::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0359::NAMESPACE,
                "origin-id",
            ),
            (
                northstar_xep_0363::XEP_ID,
                StanzaKind::IqGet,
                northstar_xep_0363::NAMESPACE,
                "request",
            ),
            (
                northstar_xep_0308::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0308::NAMESPACE,
                "replace",
            ),
            (
                northstar_xep_0333::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0333::NAMESPACE,
                "displayed",
            ),
            (
                northstar_xep_0380::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0380::NAMESPACE,
                "encryption",
            ),
            (
                northstar_xep_0444::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0444::NAMESPACE,
                "reactions",
            ),
            (
                northstar_xep_0461::XEP_ID,
                StanzaKind::Message,
                northstar_xep_0461::NAMESPACE,
                "reply",
            ),
        ] {
            assert_eq!(
                runtime.resolution().state(id),
                Some(EffectiveState::DisabledExplicitly)
            );
            assert!(!runtime.route_enabled(stanza, namespace, local_name));
            assert!(!runtime
                .server_disco_features()
                .any(|feature| feature == namespace));
        }
        assert_eq!(
            runtime.resolution().state(northstar_xep_0059::XEP_ID),
            Some(EffectiveState::DisabledExplicitly)
        );
    }

    #[test]
    fn disabling_rsm_disables_every_extension_that_requires_its_paging_contract() {
        let runtime = ExtensionRuntime::resolve(ExtensionSwitches {
            xep_0059: false,
            ..ExtensionSwitches::default()
        });
        assert_eq!(
            runtime.resolution().state(northstar_xep_0059::XEP_ID),
            Some(EffectiveState::DisabledExplicitly)
        );
        for id in [northstar_xep_0060::XEP_ID, northstar_xep_0313::XEP_ID] {
            assert_eq!(
                runtime.resolution().state(id),
                Some(EffectiveState::DisabledDependency(
                    northstar_xep_0059::XEP_ID,
                ))
            );
        }
    }
}
