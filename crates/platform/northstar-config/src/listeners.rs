//! Registration mode, web capability plan, listener plan, test listener activation and the public URL.

use super::*;

pub(super) fn requested_registration_mode(raw: &RawConfig) -> RegistrationMode {
    match (raw.open_registration, raw.invitation_required) {
        (false, _) => RegistrationMode::Closed,
        (true, true) => RegistrationMode::InvitationOnly,
        (true, false) => RegistrationMode::Open,
    }
}

pub(super) fn resolve_web_capability_plan(raw: &RawConfig) -> Result<ResolvedWebCapabilities> {
    let max_concurrent = u32::try_from(raw.upload_download_max_concurrent).ok();
    let upload_ceiling = DownloadCeiling {
        max_bytes: raw.upload_download_max_bytes,
        max_concurrent_streams: max_concurrent,
    };
    RequestedWebCapabilities::default()
        .with_user_rest(raw.rest_api_enabled)
        .with_websocket(raw.websocket_enabled)
        .with_bosh(raw.bosh_enabled)
        .with_web_client(raw.web_client_enabled)
        .with_web_admin(raw.web_admin_enabled)
        .with_upload_mode(raw.upload_mode)
        .with_upload_protocol(raw.xep_0363_enabled)
        // Durable facts are obtained only after the database authority is
        // available.  Disabled plans therefore remain explicitly pending
        // runtime proof and AppState refuses construction unless all facts
        // are empty.
        .with_upload_facts(UploadRuntimeFacts::unknown())
        .with_upload_ceiling(upload_ceiling)
        .with_registration(requested_registration_mode(raw))
        .with_observability(true)
        .with_listeners(
            ListenerConfiguration::new(raw.http_bind, raw.web_admin_bind)
                .with_observability_addr(Some(raw.metrics_bind)),
        )
        .resolve()
        .map_err(anyhow::Error::new)
}

pub(super) fn validate_web_admin_exposure(enabled: bool, bind: SocketAddr) -> Result<()> {
    if !enabled || bind.ip().is_loopback() {
        return Ok(());
    }
    anyhow::bail!(
        "WEB_ADMIN_BIND must be loopback-only in this release; use a local reverse proxy, SSH tunnel, or future mTLS/Unix-socket transport"
    )
}

pub(super) fn listener_addresses_overlap(left: SocketAddr, right: SocketAddr) -> bool {
    if left.port() == 0 || right.port() == 0 {
        return false;
    }
    if left.port() != right.port() {
        return false;
    }
    if left.ip() == right.ip() {
        return true;
    }
    if !(left.ip().is_unspecified() || right.ip().is_unspecified()) {
        return false;
    }
    match (left.ip(), right.ip()) {
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
            (left.ip().is_ipv6() && left.ip().is_unspecified())
                || (right.ip().is_ipv6() && right.ip().is_unspecified())
        }
        _ => true,
    }
}

pub(super) fn validate_listener_plan(raw: &RawConfig, public_http_active: bool) -> Result<()> {
    let mut listeners = vec![
        ("XMPP_BIND", raw.xmpp_bind),
        ("XMPPS_BIND", raw.xmpps_bind),
        ("METRICS_BIND", raw.metrics_bind),
    ];
    if public_http_active {
        listeners.push(("HTTP_BIND", raw.http_bind));
    }
    if raw.web_admin_enabled {
        listeners.push(("WEB_ADMIN_BIND", raw.web_admin_bind));
    }
    if raw.federation_enabled {
        listeners.push(("S2S_BIND", raw.s2s_bind));
        listeners.push(("S2S_TLS_BIND", raw.s2s_tls_bind));
    }
    if raw.components_enabled {
        listeners.push(("COMPONENT_BIND", raw.component_bind));
    }
    for (index, (left_name, left)) in listeners.iter().enumerate() {
        for (right_name, right) in listeners.iter().skip(index + 1) {
            if listener_addresses_overlap(*left, *right) {
                anyhow::bail!(
                    "active listener conflict: {left_name}={left} overlaps {right_name}={right}"
                );
            }
        }
    }
    Ok(())
}

pub(super) fn validate_test_listener_activation(
    raw: &RawConfig,
    listeners_are_loopback: bool,
    reserved_development_domain: bool,
) -> Result<()> {
    let configured = raw.test_readiness_file.is_some() || raw.test_readiness_nonce.is_some();
    if !raw.test_listener_activation {
        anyhow::ensure!(
            !configured,
            "TEST_READINESS_FILE and TEST_READINESS_NONCE require TEST_LISTENER_ACTIVATION=true"
        );
        return Ok(());
    }
    anyhow::ensure!(
        listeners_are_loopback && reserved_development_domain,
        "TEST_LISTENER_ACTIVATION is restricted to loopback listeners on a reserved development domain"
    );
    let path = raw
        .test_readiness_file
        .as_ref()
        .context("TEST_LISTENER_ACTIVATION requires TEST_READINESS_FILE")?;
    anyhow::ensure!(
        path.is_absolute(),
        "TEST_READINESS_FILE must be an absolute path"
    );
    let nonce = raw
        .test_readiness_nonce
        .as_deref()
        .context("TEST_LISTENER_ACTIVATION requires TEST_READINESS_NONCE")?;
    anyhow::ensure!(
        (16..=128).contains(&nonce.len())
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "TEST_READINESS_NONCE must be 16-128 lowercase hexadecimal characters"
    );
    Ok(())
}

/// Whether each listener was deliberately selected by the caller rather than
/// filled by its production default. `envy` applies serde defaults before the
/// configuration validator can observe this distinction.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TestListenerBindExplicitness {
    pub(super) xmpp: bool,
    pub(super) xmpps: bool,
    pub(super) http: bool,
    pub(super) web_admin: bool,
    pub(super) metrics: bool,
    pub(super) s2s: bool,
    pub(super) s2s_tls: bool,
    pub(super) component: bool,
}

impl TestListenerBindExplicitness {
    pub(super) fn from_environment() -> Self {
        let supplied = |name: &str| std::env::var_os(name).is_some();
        Self {
            xmpp: supplied("XMPP_BIND"),
            xmpps: supplied("XMPPS_BIND"),
            http: supplied("HTTP_BIND"),
            web_admin: supplied("WEB_ADMIN_BIND"),
            metrics: supplied("METRICS_BIND"),
            s2s: supplied("S2S_BIND"),
            s2s_tls: supplied("S2S_TLS_BIND"),
            component: supplied("COMPONENT_BIND"),
        }
    }
}

pub(super) fn ephemeral_test_listener_bind() -> SocketAddr {
    "127.0.0.1:0"
        .parse()
        .expect("the fixed loopback test listener bind is valid")
}

/// Test activation is an opt-in, loopback-only listener regime. Any listener
/// a fixture did not explicitly choose becomes a child-owned ephemeral
/// loopback listener. This makes readiness records the only authority for a
/// dynamically selected endpoint, rather than allowing an inherited
/// production port (such as the administration listener on 8081) to collide
/// with another fixture. Explicit fixture endpoints—including privileged
/// handoff fixtures—remain authoritative; ordinary deployments are unchanged.
pub(super) fn apply_test_listener_defaults(
    raw: &mut RawConfig,
    explicit: TestListenerBindExplicitness,
) {
    if !raw.test_listener_activation {
        return;
    }

    let ephemeral = ephemeral_test_listener_bind();
    if !explicit.xmpp {
        raw.xmpp_bind = ephemeral;
    }
    if !explicit.xmpps {
        raw.xmpps_bind = ephemeral;
    }
    if !explicit.http {
        raw.http_bind = ephemeral;
    }
    if !explicit.web_admin {
        raw.web_admin_bind = ephemeral;
    }
    if !explicit.metrics {
        raw.metrics_bind = ephemeral;
    }
    if !explicit.s2s {
        raw.s2s_bind = ephemeral;
    }
    if !explicit.s2s_tls {
        raw.s2s_tls_bind = ephemeral;
    }
    if !explicit.component {
        raw.component_bind = ephemeral;
    }
}

/// Resolve the public HTTP authority without ever advertising a listener's
/// kernel-selected test port.  Test activation deliberately replaces inherited
/// listener binds with port zero; unlike a readiness record, a public URL is a
/// stable externally-consumed authority and therefore must be supplied by the
/// fixture when it inherits `HTTP_BIND`.
pub(super) fn resolve_public_url(
    raw: &RawConfig,
    domain: &str,
    inherited_http_bind: bool,
) -> Result<String> {
    anyhow::ensure!(
        !(raw.test_listener_activation && inherited_http_bind && raw.public_url.is_none()),
        "TEST_LISTENER_ACTIVATION with an inherited HTTP_BIND requires PUBLIC_URL; refusing to advertise the ephemeral port"
    );
    let default_public_url = if domain == "localhost" {
        format!("http://localhost:{}", raw.http_bind.port())
    } else {
        format!("https://{domain}")
    };
    let public_url = raw
        .public_url
        .clone()
        .unwrap_or(default_public_url)
        .trim_end_matches('/')
        .to_owned();
    if !(public_url.starts_with("http://") || public_url.starts_with("https://"))
        || public_url.chars().any(char::is_whitespace)
    {
        anyhow::bail!("PUBLIC_URL must be an absolute HTTP(S) URL without whitespace");
    }
    Ok(public_url)
}
