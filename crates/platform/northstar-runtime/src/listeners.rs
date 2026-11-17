//! Inventory the addresses of listeners already bound by the process.

use anyhow::{Context, Result};
use std::{collections::BTreeMap, net::SocketAddr};

pub struct RuntimeListeners<'a> {
    pub xmpp: &'a tokio::net::TcpListener,
    pub xmpps: &'a tokio::net::TcpListener,
    pub http: &'a tokio::net::TcpListener,
    pub metrics: &'a tokio::net::TcpListener,
    pub admin: Option<&'a tokio::net::TcpListener>,
    pub s2s: Option<&'a tokio::net::TcpListener>,
    pub s2s_tls: Option<&'a tokio::net::TcpListener>,
    pub component: Option<&'a tokio::net::TcpListener>,
}

pub fn runtime_listener_addresses(
    listeners: RuntimeListeners<'_>,
) -> Result<BTreeMap<String, SocketAddr>> {
    let mut addresses = BTreeMap::new();
    for (purpose, listener) in [
        ("xmpp", listeners.xmpp),
        ("xmpps", listeners.xmpps),
        ("http", listeners.http),
        ("metrics", listeners.metrics),
    ] {
        addresses.insert(
            purpose.to_owned(),
            listener
                .local_addr()
                .with_context(|| format!("could not inspect {purpose} listener"))?,
        );
    }
    for (purpose, listener) in [
        ("web-admin", listeners.admin),
        ("s2s", listeners.s2s),
        ("s2s-tls", listeners.s2s_tls),
        ("component", listeners.component),
    ] {
        if let Some(listener) = listener {
            addresses.insert(
                purpose.to_owned(),
                listener
                    .local_addr()
                    .with_context(|| format!("could not inspect {purpose} listener"))?,
            );
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn runtime_listener_inventory_uses_bound_ephemeral_addresses() {
        let xmpp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let xmpps = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let metrics = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addresses = super::runtime_listener_addresses(super::RuntimeListeners {
            xmpp: &xmpp,
            xmpps: &xmpps,
            http: &http,
            metrics: &metrics,
            admin: None,
            s2s: None,
            s2s_tls: None,
            component: None,
        })
        .unwrap();
        assert_eq!(addresses.len(), 4);
        for (purpose, address) in addresses {
            assert!(address.ip().is_loopback(), "{purpose} must remain loopback");
            assert_ne!(
                address.port(),
                0,
                "{purpose} must be resolved before readiness"
            );
        }
    }
}
