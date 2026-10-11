//! Parsing of external services, PoW compatibility dates, XEP-0487 addresses, paths and bearer secrets.

use super::*;

pub(super) fn parse_external_service(value: &str) -> Result<(String, u16)> {
    let value = value.trim();
    let bracketed = value.starts_with('[');
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .context("bracketed IPv6 endpoint must end with ]:port")?;
        (host, port)
    } else {
        value
            .rsplit_once(':')
            .context("endpoint must use host:port syntax")?
    };
    if host.is_empty()
        || (!bracketed && host.contains(':'))
        || host.chars().any(char::is_whitespace)
        || host.chars().any(char::is_control)
    {
        anyhow::bail!("service host is empty or contains whitespace");
    }
    let port = port.parse::<u16>().context("service port is invalid")?;
    if port == 0 {
        anyhow::bail!("service port must be non-zero");
    }
    let host = if let Ok(address) = host.parse::<IpAddr>() {
        address.to_string()
    } else {
        crate::jid::prepare_domainpart(host)
            .context("service host is not a valid IP or IDNA domain")?
    };
    Ok((host, port))
}

pub(super) fn parse_pow_v1_compatibility_until(
    value: Option<&str>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    value
        .map(|value| {
            let parsed = chrono::DateTime::parse_from_rfc3339(value)
                .context("POW_V1_COMPATIBILITY_UNTIL must be an RFC 3339 timestamp")?;
            anyhow::ensure!(
                parsed.offset().local_minus_utc() == 0 && value.ends_with('Z'),
                "POW_V1_COMPATIBILITY_UNTIL must use the canonical UTC Z form"
            );
            Ok(parsed.with_timezone(&chrono::Utc))
        })
        .transpose()
}

pub(super) fn parse_xep_0487_ips(value: &str) -> Result<Vec<IpAddr>> {
    let addresses = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<IpAddr>, _>>()
        .context("XEP_0487_IPS must contain comma-separated literal IP addresses")?;
    if addresses.len() > 32 {
        anyhow::bail!("XEP_0487_IPS may contain at most 32 addresses");
    }
    if addresses
        .iter()
        .any(|address| !crate::s2s::dns::is_public_ip(*address))
    {
        anyhow::bail!("XEP_0487_IPS must contain only public, globally routable addresses");
    }
    Ok(addresses)
}

pub(super) fn non_empty_path(path: Option<PathBuf>) -> Option<PathBuf> {
    path.filter(|path| !path.as_os_str().is_empty())
}

pub(super) fn valid_http_bearer_secret(value: &str) -> bool {
    (32..=4096).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}
