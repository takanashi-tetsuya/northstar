//! IQ request routing table and route types.
//!
//! Provides [`IqRouter`] for dispatching incoming IQ requests based on payload
//! element name, namespace, and IQ kind (`get` or `set`).

use std::fmt;

/// The kind of an IQ request stanza.
///
/// Only requests (`get` and `set`) are routed; `result` and `error` responses
/// are handled before routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum IqKind {
    /// An IQ `get` request.
    Get,
    /// An IQ `set` request.
    Set,
}

impl IqKind {
    /// Parses an IQ request kind from its XML attribute string value.
    ///
    /// Returns `Some(IqKind::Get)` for `"get"` and `Some(IqKind::Set)` for `"set"`.
    /// Any other string returns `None`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "get" => Some(Self::Get),
            "set" => Some(Self::Set),
            _ => None,
        }
    }

    /// Returns the static string representation (`"get"` or `"set"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Set => "set",
        }
    }
}

/// A routing key identifying an IQ request payload by element name, namespace, and kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct IqRoute {
    /// The root XML element name of the payload.
    pub element: &'static str,
    /// The XML namespace URI of the payload.
    pub namespace: &'static str,
    /// The IQ request kind (`get` or `set`).
    pub kind: IqKind,
}

impl IqRoute {
    /// Creates a new IQ route key.
    pub const fn new(element: &'static str, namespace: &'static str, kind: IqKind) -> Self {
        Self {
            element,
            namespace,
            kind,
        }
    }
}

impl fmt::Display for IqRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.element,
            self.namespace,
            self.kind.as_str()
        )
    }
}

/// Error returned when attempting to register an IQ route that is already registered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateIqRoute(pub IqRoute);

impl fmt::Display for DuplicateIqRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IQ route {} is registered twice", self.0)
    }
}

impl std::error::Error for DuplicateIqRoute {}

/// An inbound IQ request routed to a handler.
#[derive(Clone, Copy, Debug)]
pub struct IqRequest<'a> {
    /// The stanza ID attribute value.
    pub id: &'a str,
    /// The IQ request kind (`get` or `set`).
    pub kind: IqKind,
    /// The root `<iq/>` stanza element node.
    pub stanza: roxmltree::Node<'a, 'a>,
    /// The child payload element node that selected this route.
    pub payload: roxmltree::Node<'a, 'a>,
    /// The raw stanza XML text as received from the wire.
    pub raw: &'a str,
}

/// A routing table mapping IQ routes to their handlers.
pub struct IqRouter<H> {
    routes: Vec<(IqRoute, H)>,
}

impl<H> IqRouter<H> {
    /// Creates an empty IQ router.
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Registers a handler for the given IQ route.
    ///
    /// Inserts the route at the sorted position found by binary search.
    /// If an equal route is already present, returns [`DuplicateIqRoute`]
    /// and leaves the table unchanged.
    pub fn register(&mut self, route: IqRoute, handler: H) -> Result<(), DuplicateIqRoute> {
        let key = (route.element, route.namespace, route.kind);
        match self
            .routes
            .binary_search_by(|(r, _)| (r.element, r.namespace, r.kind).cmp(&key))
        {
            Ok(_) => Err(DuplicateIqRoute(route)),
            Err(pos) => {
                self.routes.insert(pos, (route, handler));
                Ok(())
            }
        }
    }

    /// Looks up a handler by payload element name, namespace, and IQ kind.
    ///
    /// Uses binary search comparing `(route.element, route.namespace, route.kind)`
    /// against `(element, namespace, kind)`.
    pub fn route(&self, element: &str, namespace: &str, kind: IqKind) -> Option<&H> {
        let key = (element, namespace, kind);
        self.routes
            .binary_search_by(|(r, _)| (r.element, r.namespace, r.kind).cmp(&key))
            .ok()
            .map(|idx| &self.routes[idx].1)
    }

    /// Returns an iterator over all registered routes in sorted order.
    pub fn routes(&self) -> impl Iterator<Item = &IqRoute> + '_ {
        self.routes.iter().map(|(route, _)| route)
    }

    /// Returns the number of registered routes in the router.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Returns `true` if no routes are registered.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl<H> Default for IqRouter<H> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iq_kind() {
        assert_eq!(IqKind::parse("get"), Some(IqKind::Get));
        assert_eq!(IqKind::parse("set"), Some(IqKind::Set));
        assert_eq!(IqKind::parse("result"), None);
        assert_eq!(IqKind::parse("error"), None);
        assert_eq!(IqKind::parse("GET"), None);
        assert_eq!(IqKind::parse(""), None);

        assert_eq!(IqKind::Get.as_str(), "get");
        assert_eq!(IqKind::Set.as_str(), "set");
    }

    #[test]
    fn display_route() {
        let route = IqRoute::new("query", "jabber:iq:roster", IqKind::Get);
        assert_eq!(route.to_string(), "query jabber:iq:roster get");

        let dup = DuplicateIqRoute(route);
        assert_eq!(
            dup.to_string(),
            "IQ route query jabber:iq:roster get is registered twice"
        );
    }

    #[test]
    fn register_and_route() {
        let mut router = IqRouter::new();
        assert!(router.is_empty());
        assert_eq!(router.len(), 0);

        let r1 = IqRoute::new("query", "jabber:iq:roster", IqKind::Get);
        let r2 = IqRoute::new("ping", "urn:xmpp:ping", IqKind::Get);

        router.register(r1, "roster_handler").unwrap();
        router.register(r2, "ping_handler").unwrap();

        assert_eq!(router.len(), 2);
        assert!(!router.is_empty());

        assert_eq!(
            router.route("query", "jabber:iq:roster", IqKind::Get),
            Some(&"roster_handler")
        );
        assert_eq!(
            router.route("ping", "urn:xmpp:ping", IqKind::Get),
            Some(&"ping_handler")
        );

        // A miss on a different kind
        assert_eq!(router.route("query", "jabber:iq:roster", IqKind::Set), None);
        // A miss on a different namespace
        assert_eq!(
            router.route("query", "jabber:iq:version", IqKind::Get),
            None
        );
        // A miss on a different element
        assert_eq!(router.route("item", "jabber:iq:roster", IqKind::Get), None);

        // Duplicate registration returns DuplicateIqRoute and leaves len() unchanged
        let err = router.register(r1, "duplicate_handler").unwrap_err();
        assert_eq!(err, DuplicateIqRoute(r1));
        assert_eq!(router.len(), 2);
    }

    #[test]
    fn routes_yields_in_sorted_order() {
        let mut router = IqRouter::new();

        let r_set = IqRoute::new("query", "jabber:iq:roster", IqKind::Set);
        let r_get = IqRoute::new("query", "jabber:iq:roster", IqKind::Get);
        let r_ping = IqRoute::new("ping", "urn:xmpp:ping", IqKind::Get);
        let r_bind = IqRoute::new("bind", "urn:ietf:params:xml:ns:xmpp-bind", IqKind::Set);

        // Register in arbitrary/unsorted order
        router.register(r_set, 1).unwrap();
        router.register(r_get, 2).unwrap();
        router.register(r_ping, 3).unwrap();
        router.register(r_bind, 4).unwrap();

        let routes: Vec<&IqRoute> = router.routes().collect();
        assert_eq!(routes, vec![&r_bind, &r_ping, &r_get, &r_set]);
    }

    #[test]
    fn lookup_with_borrowed_document_strings() {
        let mut router = IqRouter::new();
        let route = IqRoute::new("query", "jabber:iq:roster", IqKind::Get);
        router.register(route, "roster").unwrap();

        let xml = r#"<iq id="roster-1" type="get"><query xmlns="jabber:iq:roster"/></iq>"#;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let stanza = doc.root_element();
        let payload = stanza.first_element_child().unwrap();

        let element: &str = payload.tag_name().name();
        let namespace: &str = payload.tag_name().namespace().unwrap();
        let kind = IqKind::parse(stanza.attribute("type").unwrap()).unwrap();

        assert_eq!(router.route(element, namespace, kind), Some(&"roster"));
    }
}
