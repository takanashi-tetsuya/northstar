//! Selection of configured external-component authentication records.

use northstar_config::ComponentCredential;
use std::sync::Arc;

#[derive(Clone)]
pub struct ComponentCredentials(Arc<[ComponentCredential]>);

impl ComponentCredentials {
    pub fn new(credentials: Arc<[ComponentCredential]>) -> Self {
        Self(credentials)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn connect_credentials(&self) -> Vec<ComponentCredential> {
        self.0
            .iter()
            .filter(|credential| {
                credential.connection == northstar_config::ComponentConnectionMode::Connect
            })
            .cloned()
            .collect()
    }

    pub fn accepts_connections(&self) -> bool {
        self.0.iter().any(|credential| {
            credential.connection == northstar_config::ComponentConnectionMode::Accept
        })
    }

    pub fn authentication_credential(&self, domain: &str) -> Option<ComponentCredential> {
        let domain = northstar_xmpp_types::jid::prepare_domainpart(domain).ok()?;
        self.0
            .iter()
            .find(|credential| {
                credential
                    .allowed_domains
                    .iter()
                    .any(|allowed| allowed == &domain)
            })
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_config::ComponentConnectionMode;

    fn credential(domain: &str, connection: ComponentConnectionMode) -> ComponentCredential {
        ComponentCredential {
            primary_domain: domain.to_owned(),
            allowed_domains: vec![domain.to_owned()],
            secret_value: None,
            secret_file: None,
            secret_sha256: [0; 32],
            legacy_0114: true,
            modern_0225: true,
            connection,
            connect_endpoint: None,
            allow_public_connect: false,
        }
    }

    #[test]
    fn connect_and_accept_selection_follows_connection_mode() {
        let empty = ComponentCredentials::new(Arc::from([]));
        assert!(empty.is_empty());
        assert!(empty.connect_credentials().is_empty());
        assert!(!empty.accepts_connections());

        let connect = credential("connect.example", ComponentConnectionMode::Connect);
        let connect_only = ComponentCredentials::new(Arc::from([connect.clone()]));
        assert!(!connect_only.is_empty());
        assert!(!connect_only.accepts_connections());
        assert_eq!(connect_only.connect_credentials().len(), 1);

        let accept = credential("accept.example", ComponentConnectionMode::Accept);
        let accept_only = ComponentCredentials::new(Arc::from([accept.clone()]));
        assert!(accept_only.accepts_connections());
        assert!(accept_only.connect_credentials().is_empty());

        let second_connect = credential("second.example", ComponentConnectionMode::Connect);
        let mixed = ComponentCredentials::new(Arc::from([
            connect.clone(),
            accept,
            second_connect,
            connect,
        ]));
        assert!(mixed.accepts_connections());
        let domains: Vec<_> = mixed
            .connect_credentials()
            .into_iter()
            .map(|credential| credential.primary_domain)
            .collect();
        assert_eq!(
            domains,
            vec!["connect.example", "second.example", "connect.example"]
        );
    }

    #[test]
    fn authentication_selects_the_first_credential_for_a_prepared_domain() {
        let mut first = credential("first.example", ComponentConnectionMode::Connect);
        first.allowed_domains.push("gateway.example".to_owned());
        let mut second = credential("second.example", ComponentConnectionMode::Accept);
        second.allowed_domains.push("gateway.example".to_owned());
        let credentials = ComponentCredentials::new(Arc::from([first, second]));

        assert_eq!(
            credentials
                .authentication_credential("Gateway.Example")
                .unwrap()
                .primary_domain,
            "first.example"
        );
        assert_eq!(
            credentials
                .authentication_credential("SECOND.EXAMPLE")
                .unwrap()
                .primary_domain,
            "second.example"
        );
        assert!(credentials
            .authentication_credential("unknown.example")
            .is_none());
        assert!(credentials.authentication_credential("bad jid").is_none());
        assert!(credentials
            .authentication_credential("example..test")
            .is_none());
    }
}
