//! External component credentials, connection modes, credential files and component transport and capacity checks.

use super::*;

#[derive(Clone)]
pub struct ComponentCredential {
    pub primary_domain: String,
    pub allowed_domains: Vec<String>,
    /// The validated secret is loaded exactly once during startup and retained
    /// in zeroizing memory. `secret_file` is optional provenance only; runtime
    /// authentication never performs a blocking filesystem read.
    pub secret_value: Option<Arc<Zeroizing<String>>>,
    pub secret_file: Option<PathBuf>,
    pub secret_sha256: [u8; 32],
    pub legacy_0114: bool,
    pub modern_0225: bool,
    pub connection: ComponentConnectionMode,
    pub connect_endpoint: Option<ComponentConnectEndpoint>,
    pub allow_public_connect: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ComponentConnectionMode {
    Accept,
    Connect,
}

pub(super) fn default_component_connection_mode() -> ComponentConnectionMode {
    ComponentConnectionMode::Accept
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentConnectEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ComponentCredentialFile {
    pub(super) jid: String,
    pub(super) secret: Option<String>,
    pub(super) secret_file: Option<PathBuf>,
    #[serde(default)]
    pub(super) aliases: Vec<String>,
    #[serde(default = "default_true")]
    pub(super) legacy_0114: bool,
    #[serde(default = "default_true")]
    pub(super) modern_0225: bool,
    #[serde(default = "default_component_connection_mode")]
    pub(super) connection: ComponentConnectionMode,
    pub(super) connect_endpoint: Option<String>,
    #[serde(default)]
    pub(super) allow_public_connect: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum ComponentConfigDocument {
    List(Vec<ComponentCredentialFile>),
    Object {
        components: Vec<ComponentCredentialFile>,
    },
}

pub(super) fn load_component_credentials(
    path: &std::path::Path,
    server_domain: &str,
) -> Result<Vec<ComponentCredential>> {
    let mut encoded = read_protected_utf8_file(path, "COMPONENTS_CONFIG_FILE", 1024 * 1024, false)?;
    let parsed = serde_json::from_str(&encoded);
    encoded.zeroize();
    let document: ComponentConfigDocument = parsed.context("component config is not valid JSON")?;
    let entries = match document {
        ComponentConfigDocument::List(entries)
        | ComponentConfigDocument::Object {
            components: entries,
        } => entries,
    };
    if entries.len() > 1024 {
        anyhow::bail!("component config contains more than 1024 components");
    }

    let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let reserved = [
        server_domain.to_owned(),
        format!("conference.{server_domain}"),
        format!("upload.{server_domain}"),
        format!("pubsub.{server_domain}"),
        format!("mix.{server_domain}"),
    ];
    let mut claimed_domains = HashSet::new();
    let mut credentials = Vec::with_capacity(entries.len());
    for entry in entries {
        let ComponentCredentialFile {
            jid,
            secret,
            secret_file,
            aliases,
            legacy_0114,
            modern_0225,
            connection,
            connect_endpoint,
            allow_public_connect,
        } = entry;
        if secret.is_some() == secret_file.is_some() {
            anyhow::bail!("set exactly one of component secret or secret_file");
        }
        if aliases.len() > 64 {
            anyhow::bail!("a component cannot configure more than 64 aliases");
        }
        let primary_domain = northstar_xmpp_types::jid::prepare_domainpart(jid.trim())
            .context("component JID must be a domain identifier")?;
        let mut allowed_domains = Vec::with_capacity(aliases.len() + 1);
        allowed_domains.push(primary_domain.clone());
        for alias in aliases {
            let alias = northstar_xmpp_types::jid::prepare_domainpart(alias.trim())
                .context("component alias must be a domain identifier")?;
            if !allowed_domains.contains(&alias) {
                allowed_domains.push(alias);
            }
        }
        for component_domain in &allowed_domains {
            if reserved.iter().any(|domain| domain == component_domain) {
                anyhow::bail!("component domain conflicts with a built-in hosted domain");
            }
            if !claimed_domains.insert(component_domain.clone()) {
                anyhow::bail!("component domains and aliases must be globally unique");
            }
        }
        if !legacy_0114 && !modern_0225 {
            anyhow::bail!("each component must enable XEP-0114 or XEP-0225");
        }
        let connect_endpoint = match (connection, connect_endpoint.as_deref()) {
            (ComponentConnectionMode::Accept, None) => None,
            (ComponentConnectionMode::Accept, Some(_)) => {
                anyhow::bail!("accept-mode components cannot configure connect_endpoint")
            }
            (ComponentConnectionMode::Connect, None) => {
                anyhow::bail!("connect-mode components require connect_endpoint")
            }
            (ComponentConnectionMode::Connect, Some(endpoint)) => {
                let (host, port) = parse_external_service(endpoint)
                    .context("component connect_endpoint must use exact host:port syntax")?;
                Some(ComponentConnectEndpoint { host, port })
            }
        };
        if connection == ComponentConnectionMode::Connect && (!legacy_0114 || modern_0225) {
            anyhow::bail!(
                "connect-mode is the legacy XEP-0114 profile and requires legacy_0114=true, modern_0225=false"
            );
        }
        if connection == ComponentConnectionMode::Accept && allow_public_connect {
            anyhow::bail!("allow_public_connect is valid only for connect-mode components");
        }

        let secret_file = secret_file.map(|path| {
            if path.is_absolute() {
                path
            } else {
                base.join(path)
            }
        });
        let mut secret = match (secret, &secret_file) {
            (Some(secret), None) => Zeroizing::new(secret),
            (None, Some(path)) => Zeroizing::new(read_secret_file(path, "component secret_file")?),
            _ => unreachable!("component secret source was validated above"),
        };
        if secret.len() < 32 || secret.len() > 4096 || secret.contains('\0') {
            secret.zeroize();
            anyhow::bail!("component secrets must contain 32 to 4096 bytes without NUL");
        }
        let secret_sha256: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        credentials.push(ComponentCredential {
            primary_domain,
            allowed_domains,
            secret_value: Some(Arc::new(secret)),
            secret_file,
            secret_sha256,
            legacy_0114,
            modern_0225,
            connection,
            connect_endpoint,
            allow_public_connect,
        });
    }
    Ok(credentials)
}

pub(super) fn validate_component_transport(
    bind: SocketAddr,
    components: &[ComponentCredential],
) -> Result<()> {
    if !bind.ip().is_loopback()
        && components.iter().any(|credential| {
            credential.connection == ComponentConnectionMode::Accept && credential.legacy_0114
        })
    {
        anyhow::bail!(
            "plaintext XEP-0114 components require a loopback COMPONENT_BIND; use XEP-0225 for a public listener"
        );
    }
    Ok(())
}

pub(super) fn validate_component_capacity(
    max_connections: usize,
    components: &[ComponentCredential],
) -> Result<()> {
    let outbound_domains = components
        .iter()
        .filter(|credential| credential.connection == ComponentConnectionMode::Connect)
        .map(|credential| credential.allowed_domains.len())
        .sum::<usize>();
    let accept_reserve = usize::from(
        components
            .iter()
            .any(|credential| credential.connection == ComponentConnectionMode::Accept),
    );
    if outbound_domains.saturating_add(accept_reserve) > max_connections {
        anyhow::bail!(
            "MAX_COMPONENT_CONNECTIONS must cover every connect-mode domain and one accept-mode reserve"
        );
    }
    Ok(())
}
