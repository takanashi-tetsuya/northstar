//! Federation endpoints and the pure parts of finding them: XEP-0487 documents,
//! their HTTP framing, RFC 2782 ordering and the host-meta cache admission.

use anyhow::{Context, Result};
use northstar_security::address_scope::is_public_ip;
use northstar_security::dane::DaneSrvBinding;
use rand::{seq::SliceRandom, Rng};
use serde::de::{
    Deserialize, Deserializer, Error as DeserializeError, MapAccess, SeqAccess, Visitor,
};
use serde_json::Value;
use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::Instant,
};

pub const HOST_META_PATH: &str = "/.well-known/host-meta.json";
pub const HOST_META_MAX_HEADER_BYTES: usize = 32 * 1024;
pub const HOST_META_MAX_BODY_BYTES: usize = 256 * 1024;
pub const HOST_META_MAX_LINKS: usize = 64;
pub const HOST_META_MAX_IPS_PER_LINK: usize = 32;
pub const HOST_META_MAX_ENDPOINTS: usize = 128;
pub const HOST_META_MAX_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const HOST_META_MAX_CACHE_DOMAINS: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationEndpoint {
    pub address: SocketAddr,
    pub direct_tls: bool,
    /// TLS SNI selected by the discovery mechanism. RFC 6120/XEP-0368 use
    /// the XMPP service domain; an authenticated XEP-0487 document may
    /// explicitly delegate a different name.
    pub tls_server_name: String,
    pub delegated_identity: bool,
    pub public_key_pins: Vec<[u8; 32]>,
    /// Consecutive endpoints in the same discovery group may be raced using
    /// Happy Eyeballs. Lower-priority groups remain strictly ordered.
    pub selection_group: u64,
    /// Exact SRV relationship that selected this DNS endpoint. It is re-read
    /// through the local DNSSEC validator before any socket is opened.
    pub dane_srv_binding: Option<DaneSrvBinding>,
}

#[derive(Default)]
pub struct BoundedCacheAdmission {
    pub next_expiry: Option<Instant>,
    #[cfg(test)]
    pub sweeps: usize,
}

pub fn bounded_cache_insert<V, ExpiresAt>(
    cache: &dashmap::DashMap<String, V>,
    admission: &Mutex<BoundedCacheAdmission>,
    domain: String,
    value: V,
    now: Instant,
    expires_at: ExpiresAt,
) where
    ExpiresAt: Fn(&V) -> Instant,
{
    let _ = bounded_cache_insert_with_limit(
        cache,
        admission,
        domain,
        value,
        HOST_META_MAX_CACHE_DOMAINS,
        now,
        expires_at,
    );
}

pub fn bounded_cache_insert_with_limit<V, ExpiresAt>(
    cache: &dashmap::DashMap<String, V>,
    admission: &Mutex<BoundedCacheAdmission>,
    domain: String,
    value: V,
    limit: usize,
    now: Instant,
    expires_at: ExpiresAt,
) -> bool
where
    ExpiresAt: Fn(&V) -> Instant,
{
    let value_expiry = expires_at(&value);
    let mut admission = admission
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache.len() >= limit
        && admission
            .next_expiry
            .is_some_and(|next_expiry| now >= next_expiry)
    {
        // Sweep only when the earliest known TTL can actually have expired.
        // A full cache fed with new domains otherwise turns every rejection
        // into an O(limit) scan under the global admission lock.
        #[cfg(test)]
        {
            admission.sweeps += 1;
        }
        let mut next_expiry = None;
        cache.retain(|_, cached| {
            let cached_expiry = expires_at(cached);
            let retained = cached_expiry > now;
            if retained {
                next_expiry = Some(
                    next_expiry.map_or(cached_expiry, |next: Instant| next.min(cached_expiry)),
                );
            }
            retained
        });
        admission.next_expiry = next_expiry;
    }
    if cache.contains_key(&domain) || cache.len() < limit {
        cache.insert(domain, value);
        admission.next_expiry = Some(
            admission
                .next_expiry
                .map_or(value_expiry, |next| next.min(value_expiry)),
        );
        true
    } else {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostMetaDiscovery {
    Legacy,
    Authoritative {
        ttl_seconds: u64,
        endpoints: Vec<FederationEndpoint>,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("authoritative XEP-0487 document is invalid: {0:#}")]
pub struct AuthoritativeHostMetaError(anyhow::Error);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HttpsLocation {
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// RFC 8259 says object member names SHOULD be unique, while common JSON
/// libraries disagree about whether the first or last duplicate wins. Host
/// metadata controls TLS delegation and IP selection, so accepting ambiguous
/// duplicates would create an avoidable policy-smuggling boundary.
pub struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

pub struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unambiguous JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: DeserializeError,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object member {key:?}"
                )));
            }
            let UniqueJsonValue(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

pub fn parse_https_redirect(current: &HttpsLocation, value: &str) -> Result<HttpsLocation> {
    if value.len() > 4_096 || value.bytes().any(|byte| byte.is_ascii_control()) {
        anyhow::bail!("XEP-0487 redirect Location is invalid or too long");
    }
    if value.starts_with('/') {
        return Ok(HttpsLocation {
            host: current.host.clone(),
            port: current.port,
            path_and_query: value.to_owned(),
        });
    }
    let remainder = value
        .strip_prefix("https://")
        .context("XEP-0487 redirects must retain HTTPS")?;
    let (authority, path_and_query) =
        remainder
            .split_once('/')
            .map_or((remainder, "/"), |(authority, path)| {
                (
                    authority,
                    value.get(value.len() - path.len() - 1..).unwrap_or("/"),
                )
            });
    if authority.is_empty() || authority.contains(['@', '[', ']']) {
        anyhow::bail!("XEP-0487 redirect authority is invalid");
    }
    let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .context("XEP-0487 redirect port is invalid")?;
        (host, port)
    } else {
        (authority, 443)
    };
    let host = northstar_xmpp_types::jid::domain_to_ascii(host)
        .context("XEP-0487 redirect host is not a valid domain")?;
    if host.parse::<IpAddr>().is_ok() || path_and_query.len() > 4_096 {
        anyhow::bail!("XEP-0487 redirect host or path is not policy-compliant");
    }
    Ok(HttpsLocation {
        host,
        port,
        path_and_query: path_and_query.to_owned(),
    })
}

pub fn parse_http_response(response: &[u8]) -> Result<HttpResponse> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .context("XEP-0487 HTTPS response has no complete header block")?;
    if header_end > HOST_META_MAX_HEADER_BYTES {
        anyhow::bail!("XEP-0487 HTTPS response headers exceed their size limit");
    }
    let header = std::str::from_utf8(&response[..header_end])
        .context("XEP-0487 HTTPS response headers are not UTF-8")?;
    if header
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\r' | '\n' | '\t'))
    {
        anyhow::bail!("XEP-0487 HTTPS response headers contain control characters");
    }
    let mut lines = header[..header.len() - 4].split("\r\n");
    let status_line = lines.next().context("XEP-0487 HTTP status is absent")?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    let status = status_parts
        .next()
        .and_then(|status| status.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status))
        .context("XEP-0487 HTTP status is malformed")?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        anyhow::bail!("XEP-0487 endpoint did not return HTTP/1.x");
    }

    let mut content_type = None;
    let mut location = None;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.starts_with([' ', '\t']) {
            anyhow::bail!("XEP-0487 HTTP response uses obsolete folded headers");
        }
        let (name, value) = line
            .split_once(':')
            .context("XEP-0487 HTTP response contains a malformed header")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            anyhow::bail!("XEP-0487 HTTP response contains an invalid header name");
        }
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "content-type" => set_unique_header(&mut content_type, value, "Content-Type")?,
            "location" => set_unique_header(&mut location, value, "Location")?,
            "content-length" => {
                let parsed = value
                    .parse::<usize>()
                    .ok()
                    .filter(|length| *length <= HOST_META_MAX_BODY_BYTES)
                    .context("XEP-0487 Content-Length is invalid or too large")?;
                if content_length
                    .replace(parsed)
                    .is_some_and(|old| old != parsed)
                {
                    anyhow::bail!("XEP-0487 response has conflicting Content-Length headers");
                }
            }
            "transfer-encoding" => {
                if !value.eq_ignore_ascii_case("chunked") || chunked {
                    anyhow::bail!("XEP-0487 response uses an unsupported Transfer-Encoding");
                }
                chunked = true;
            }
            _ => {}
        }
    }
    if chunked && content_length.is_some() {
        anyhow::bail!("XEP-0487 response ambiguously combines framing headers");
    }
    let encoded_body = &response[header_end..];
    let body = if chunked {
        decode_chunked_body(encoded_body)?
    } else if let Some(content_length) = content_length {
        if encoded_body.len() != content_length {
            anyhow::bail!("XEP-0487 response body length does not match Content-Length");
        }
        encoded_body.to_vec()
    } else {
        if encoded_body.len() > HOST_META_MAX_BODY_BYTES {
            anyhow::bail!("XEP-0487 response body exceeds its size limit");
        }
        encoded_body.to_vec()
    };
    Ok(HttpResponse {
        status,
        content_type,
        location,
        body,
    })
}

pub fn set_unique_header(target: &mut Option<String>, value: &str, name: &str) -> Result<()> {
    if target.replace(value.to_owned()).is_some() {
        anyhow::bail!("XEP-0487 response has duplicate {name} headers");
    }
    Ok(())
}

pub fn decode_chunked_body(mut encoded: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .context("XEP-0487 chunk size line is incomplete")?;
        if line_end > 128 {
            anyhow::bail!("XEP-0487 chunk size line is too long");
        }
        let size_text = std::str::from_utf8(&encoded[..line_end])
            .context("XEP-0487 chunk size is not ASCII")?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .context("XEP-0487 chunk size is invalid")?;
        encoded = &encoded[line_end + 2..];
        if size == 0 {
            // A zero chunk is followed by an optional bounded trailer block.
            if encoded == b"\r\n"
                || (encoded.ends_with(b"\r\n\r\n") && encoded.len() <= HOST_META_MAX_HEADER_BYTES)
            {
                return Ok(decoded);
            }
            anyhow::bail!("XEP-0487 chunk trailers are malformed or too large");
        }
        if size > HOST_META_MAX_BODY_BYTES.saturating_sub(decoded.len())
            || encoded.len() < size + 2
            || &encoded[size..size + 2] != b"\r\n"
        {
            anyhow::bail!("XEP-0487 chunk data is truncated or too large");
        }
        decoded.extend_from_slice(&encoded[..size]);
        encoded = &encoded[size + 2..];
    }
}

pub fn parse_xep_0487_document(
    federation_allow_private_ips: bool,
    body: &[u8],
) -> Result<HostMetaDiscovery> {
    let declares_xmpp = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|document| document.as_object().map(|root| root.contains_key("xmpp")))
        .unwrap_or(false);
    let UniqueJsonValue(document) = serde_json::from_slice(body)
        .context("XEP-0487 document is invalid or ambiguous JSON")
        .map_err(|error| -> anyhow::Error {
            if declares_xmpp {
                AuthoritativeHostMetaError(error).into()
            } else {
                error
            }
        })?;
    let root = document
        .as_object()
        .context("XEP-0487 document root must be an object")?;
    let Some(xmpp) = root.get("xmpp") else {
        return Ok(HostMetaDiscovery::Legacy);
    };
    parse_authoritative_xep_0487(federation_allow_private_ips, root, xmpp)
        .map_err(|error| AuthoritativeHostMetaError(error).into())
}

pub fn parse_authoritative_xep_0487(
    federation_allow_private_ips: bool,
    root: &serde_json::Map<String, Value>,
    xmpp: &Value,
) -> Result<HostMetaDiscovery> {
    let xmpp = xmpp
        .as_object()
        .context("XEP-0487 xmpp member must be an object")?;
    let ttl_seconds = xmpp
        .get("ttl")
        .and_then(Value::as_u64)
        .filter(|ttl| (1..=HOST_META_MAX_TTL_SECONDS).contains(ttl))
        .context("XEP-0487 ttl is absent, zero, or exceeds the cache-policy limit")?;
    let public_key_pins = parse_public_key_pins(xmpp.get("public-key-pins-sha-256"))?;
    let links = root
        .get("links")
        .and_then(Value::as_array)
        .context("XEP-0487 links member must be an array")?;
    if links.len() > HOST_META_MAX_LINKS {
        anyhow::bail!("XEP-0487 document contains too many links");
    }

    let mut candidates = Vec::new();
    for link in links {
        let link = link
            .as_object()
            .context("XEP-0487 link must be an object")?;
        if link.get("rel").and_then(Value::as_str) != Some("urn:xmpp:alt-connections:s2s-tls") {
            continue;
        }
        let port = link
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .context("XEP-0487 S2S TLS link has an invalid port")?;
        let priority = link
            .get("priority")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .context("XEP-0487 S2S TLS link has an invalid priority")?;
        let weight = link
            .get("weight")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .context("XEP-0487 S2S TLS link has an invalid weight")?;
        let sni = link
            .get("sni")
            .and_then(Value::as_str)
            .and_then(|sni| northstar_xmpp_types::jid::domain_to_ascii(sni).ok())
            .filter(|sni| sni.parse::<IpAddr>().is_err())
            .context("XEP-0487 S2S TLS link has an invalid SNI domain")?;
        let ips = link
            .get("ips")
            .and_then(Value::as_array)
            .context("XEP-0487 S2S TLS link has no IP list")?;
        if ips.is_empty() || ips.len() > HOST_META_MAX_IPS_PER_LINK {
            anyhow::bail!("XEP-0487 S2S TLS link has an invalid number of IPs");
        }
        for ip in ips {
            let ip = ip
                .as_str()
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .context("XEP-0487 S2S TLS link contains a non-literal IP")?;
            let address = SocketAddr::new(ip, port);
            validate_address_policy(federation_allow_private_ips, address)?;
            candidates.push(HostMetaEndpoint {
                priority,
                weight,
                endpoint: FederationEndpoint {
                    address,
                    direct_tls: true,
                    tls_server_name: sni.clone(),
                    delegated_identity: true,
                    public_key_pins: public_key_pins.clone(),
                    selection_group: u64::from(priority),
                    dane_srv_binding: None,
                },
            });
            if candidates.len() > HOST_META_MAX_ENDPOINTS {
                anyhow::bail!("XEP-0487 document expands to too many endpoints");
            }
        }
    }
    let mut endpoints = weighted_host_meta_order(candidates);
    deduplicate_endpoints(&mut endpoints);
    Ok(HostMetaDiscovery::Authoritative {
        ttl_seconds,
        endpoints,
    })
}

pub fn parse_public_key_pins(value: Option<&Value>) -> Result<Vec<[u8; 32]>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let pins = value
        .as_array()
        .context("XEP-0487 public-key pins must be an array")?;
    if pins.len() > 16 {
        anyhow::bail!("XEP-0487 document contains too many public-key pins");
    }
    let mut parsed = Vec::new();
    for pin in pins {
        let pin = pin
            .as_str()
            .context("XEP-0487 public-key pin must be a string")?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pin)
            .context("XEP-0487 public-key pin is not valid base64")?;
        let pin: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("XEP-0487 public-key pin is not a SHA-256 digest"))?;
        if !parsed.contains(&pin) {
            parsed.push(pin);
        }
    }
    Ok(parsed)
}

#[derive(Clone, Debug)]
pub struct HostMetaEndpoint {
    pub priority: u16,
    pub weight: u16,
    pub endpoint: FederationEndpoint,
}

pub fn weighted_host_meta_order(mut records: Vec<HostMetaEndpoint>) -> Vec<FederationEndpoint> {
    let mut ordered = Vec::with_capacity(records.len());
    let mut rng = rand::thread_rng();
    while !records.is_empty() {
        let priority = records
            .iter()
            .map(|record| record.priority)
            .min()
            .unwrap_or_default();
        let (mut group, remaining): (Vec<_>, Vec<_>) = records
            .into_iter()
            .partition(|record| record.priority == priority);
        while !group.is_empty() {
            group.shuffle(&mut rng);
            group.sort_by_key(|record| record.weight != 0);
            let total_weight: u32 = group.iter().map(|record| u32::from(record.weight)).sum();
            let ticket = rng.gen_range(0..=total_weight);
            let mut running_weight = 0_u32;
            let mut index = group.len() - 1;
            for (candidate, record) in group.iter().enumerate() {
                running_weight += u32::from(record.weight);
                if running_weight >= ticket {
                    index = candidate;
                    break;
                }
            }
            ordered.push(group.swap_remove(index).endpoint);
        }
        records = remaining;
    }
    ordered
}

pub fn deduplicate_endpoints(endpoints: &mut Vec<FederationEndpoint>) {
    let mut seen = HashSet::new();
    endpoints.retain(|endpoint| {
        seen.insert((
            endpoint.address,
            endpoint.direct_tls,
            endpoint.tls_server_name.clone(),
        ))
    });
}

pub fn interleave_ip_families(addresses: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut first_is_v6 = None;
    for address in addresses {
        first_is_v6.get_or_insert(address.is_ipv6());
        if address.is_ipv6() {
            v6.push(address);
        } else {
            v4.push(address);
        }
    }
    let mut ordered = Vec::with_capacity(v4.len() + v6.len());
    let mut v4 = v4.into_iter();
    let mut v6 = v6.into_iter();
    let prefer_v6 = first_is_v6.unwrap_or(true);
    loop {
        let (first, second) = if prefer_v6 {
            (v6.next(), v4.next())
        } else {
            (v4.next(), v6.next())
        };
        if first.is_none() && second.is_none() {
            break;
        }
        ordered.extend(first);
        ordered.extend(second);
    }
    ordered
}

pub fn weighted_srv_order(mut records: Vec<SrvRecord>) -> Vec<SrvRecord> {
    let mut ordered = Vec::with_capacity(records.len());
    let mut rng = rand::thread_rng();
    while !records.is_empty() {
        let priority = records
            .iter()
            .map(|record| record.priority)
            .min()
            .unwrap_or_default();
        let (mut group, remaining): (Vec<_>, Vec<_>) = records
            .into_iter()
            .partition(|record| record.priority == priority);
        while !group.is_empty() {
            group.shuffle(&mut rng);
            // RFC 2782 places zero-weight records first so they retain the
            // deliberately small chance represented by a ticket of zero.
            group.sort_by_key(|record| record.weight != 0);
            let total_weight: u32 = group.iter().map(|record| u32::from(record.weight)).sum();
            let ticket = rng.gen_range(0..=total_weight);
            let mut running_weight = 0_u32;
            let mut index = group.len() - 1;
            for (candidate, record) in group.iter().enumerate() {
                running_weight += u32::from(record.weight);
                if running_weight >= ticket {
                    index = candidate;
                    break;
                }
            }
            ordered.push(group.swap_remove(index));
        }
        records = remaining;
    }
    ordered
}

pub fn validate_address_policy(
    federation_allow_private_ips: bool,
    address: SocketAddr,
) -> Result<()> {
    if !federation_allow_private_ips && !is_public_ip(address.ip()) {
        anyhow::bail!("federation endpoint resolves to a private or special-use IP address");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
