use crate::{
    s2s::dane::{DaneMode, DaneSrvBinding},
    state::AppState,
};
use anyhow::{Context, Result};
use hickory_resolver::{
    net::{DnsError, NetError},
    proto::{op::ResponseCode, rr::RData},
    TokioResolver,
};
use rand::{seq::SliceRandom, Rng};
use serde::de::{
    Deserialize, Deserializer, Error as DeserializeError, MapAccess, SeqAccess, Visitor,
};
use serde_json::Value;
use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

const HOST_META_PATH: &str = "/.well-known/host-meta.json";
const HOST_META_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HOST_META_IO_TIMEOUT: Duration = Duration::from_secs(12);
const HOST_META_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(45);
const HOST_META_MAX_HEADER_BYTES: usize = 32 * 1024;
const HOST_META_MAX_BODY_BYTES: usize = 256 * 1024;
const HOST_META_MAX_RESPONSE_BYTES: usize = HOST_META_MAX_HEADER_BYTES + HOST_META_MAX_BODY_BYTES;
const HOST_META_MAX_REDIRECTS: usize = 3;
const HOST_META_MAX_LINKS: usize = 64;
const HOST_META_MAX_IPS_PER_LINK: usize = 32;
const HOST_META_MAX_ENDPOINTS: usize = 128;
const HOST_META_MAX_HTTPS_ADDRESSES: usize = 16;
const HOST_META_MAX_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const HOST_META_MAX_CACHE_DOMAINS: usize = 10_000;
const HOST_META_LEGACY_CACHE_SECONDS: u64 = 300;
const HOST_META_FAILURE_CACHE_SECONDS: u64 = 60;
const DNS_MAX_SRV_RECORDS: usize = 128;
const DNS_MAX_IPS_PER_SRV_TARGET: usize = 32;
const DNS_MAX_ENDPOINTS: usize = 256;
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FederationEndpoint {
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

#[derive(Clone, Debug)]
struct CachedHostMeta {
    expires_at: Instant,
    endpoints: Vec<FederationEndpoint>,
}

static HOST_META_CACHE: OnceLock<dashmap::DashMap<String, CachedHostMeta>> = OnceLock::new();
static HOST_META_NEGATIVE_CACHE: OnceLock<dashmap::DashMap<String, Instant>> = OnceLock::new();
static HOST_META_CACHE_ADMISSION: OnceLock<Mutex<BoundedCacheAdmission>> = OnceLock::new();
static HOST_META_NEGATIVE_CACHE_ADMISSION: OnceLock<Mutex<BoundedCacheAdmission>> = OnceLock::new();

#[derive(Default)]
struct BoundedCacheAdmission {
    next_expiry: Option<Instant>,
    #[cfg(test)]
    sweeps: usize,
}

fn host_meta_cache() -> &'static dashmap::DashMap<String, CachedHostMeta> {
    HOST_META_CACHE.get_or_init(dashmap::DashMap::new)
}

fn host_meta_negative_cache() -> &'static dashmap::DashMap<String, Instant> {
    HOST_META_NEGATIVE_CACHE.get_or_init(dashmap::DashMap::new)
}

fn bounded_cache_insert<V, ExpiresAt>(
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

fn bounded_cache_insert_with_limit<V, ExpiresAt>(
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
struct SrvRecord {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

/// Resolve every usable endpoint in RFC 2782 order. Hickory owns the positive
/// and negative caches, honors record TTLs, follows CNAMEs, tries all system
/// name servers, and falls back to TCP for truncated/failed UDP responses.
pub(crate) async fn resolve_federation_endpoints(
    state: &AppState,
    domain: &str,
) -> Result<Vec<FederationEndpoint>> {
    let domain = crate::jid::prepare_domainpart(domain)
        .context("federation target is not a valid RFC 7622 domain")?;
    let dns_domain = crate::jid::domain_to_ascii(&domain)
        .context("federation target cannot be represented as a DNS name")?;
    if state.config.federation_dane_mode == DaneMode::Required {
        return resolve_dns_endpoints(state, &domain).await;
    }
    if let Some((_, address, direct_tls)) =
        state
            .config
            .federation_dns_overrides
            .iter()
            .find(|(candidate, _, _)| {
                crate::jid::prepare_domainpart(candidate).is_ok_and(|candidate| candidate == domain)
            })
    {
        validate_endpoint(state, *address)?;
        return Ok(vec![FederationEndpoint {
            address: *address,
            direct_tls: *direct_tls,
            tls_server_name: dns_domain,
            delegated_identity: false,
            public_key_pins: Vec::new(),
            selection_group: 0,
            dane_srv_binding: None,
        }]);
    }

    let cached = host_meta_cache().get(&domain).map(|entry| entry.clone());
    if cached
        .as_ref()
        .is_some_and(|cached| cached.expires_at > Instant::now())
    {
        return cached
            .map(|cached| cached.endpoints)
            .context("fresh XEP-0487 cache entry disappeared");
    }
    if let Some(expires_at) = host_meta_negative_cache().get(&domain).map(|entry| *entry) {
        if expires_at > Instant::now() {
            if let Some(cached) = cached {
                return stale_host_meta_with_dns(state, &domain, cached.endpoints).await;
            }
            return resolve_dns_endpoints(state, &domain).await;
        }
        host_meta_negative_cache().remove(&domain);
    }
    let host_meta =
        tokio::time::timeout(HOST_META_DISCOVERY_TIMEOUT, fetch_xep_0487(state, &domain))
            .await
            .context("XEP-0487 discovery exceeded its total time limit")
            .and_then(|result| result);
    match host_meta {
        Ok(HostMetaDiscovery::Authoritative {
            ttl_seconds,
            endpoints,
        }) => {
            bounded_cache_insert(
                host_meta_cache(),
                HOST_META_CACHE_ADMISSION
                    .get_or_init(|| Mutex::new(BoundedCacheAdmission::default())),
                domain.clone(),
                CachedHostMeta {
                    expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
                    endpoints: endpoints.clone(),
                },
                Instant::now(),
                |cached: &CachedHostMeta| cached.expires_at,
            );
            host_meta_negative_cache().remove(&domain);
            if endpoints.is_empty() {
                anyhow::bail!(
                    "remote XEP-0487 metadata publishes no policy-compliant S2S endpoint"
                );
            }
            return Ok(endpoints);
        }
        Ok(HostMetaDiscovery::Legacy) => {
            host_meta_cache().remove(&domain);
            bounded_cache_insert(
                host_meta_negative_cache(),
                HOST_META_NEGATIVE_CACHE_ADMISSION
                    .get_or_init(|| Mutex::new(BoundedCacheAdmission::default())),
                domain.clone(),
                Instant::now() + Duration::from_secs(HOST_META_LEGACY_CACHE_SECONDS),
                Instant::now(),
                |expires_at: &Instant| *expires_at,
            );
        }
        Err(error) if error.downcast_ref::<AuthoritativeHostMetaError>().is_some() => {
            // An authenticated host-meta document containing the top-level
            // `xmpp` marker explicitly supersedes legacy discovery. Falling
            // back to DNS here would turn malformed authoritative policy into
            // a transport/security downgrade.
            return Err(error);
        }
        Err(error) => {
            tracing::debug!(%domain, ?error, "XEP-0487 discovery unavailable; trying cached and DNS connection methods");
            bounded_cache_insert(
                host_meta_negative_cache(),
                HOST_META_NEGATIVE_CACHE_ADMISSION
                    .get_or_init(|| Mutex::new(BoundedCacheAdmission::default())),
                domain.clone(),
                Instant::now() + Duration::from_secs(HOST_META_FAILURE_CACHE_SECONDS),
                Instant::now(),
                |expires_at: &Instant| *expires_at,
            );
            if let Some(cached) = cached {
                // XEP-0487 explicitly requires expired metadata to remain a
                // fallback when refresh fails. DNS candidates are appended
                // below, so every available method can still be attempted.
                return stale_host_meta_with_dns(state, &domain, cached.endpoints).await;
            }
        }
    }

    resolve_dns_endpoints(state, &domain).await
}

async fn stale_host_meta_with_dns(
    state: &AppState,
    domain: &str,
    mut endpoints: Vec<FederationEndpoint>,
) -> Result<Vec<FederationEndpoint>> {
    match resolve_dns_endpoints(state, domain).await {
        Ok(dns) => endpoints.extend(dns),
        Err(error) => {
            tracing::debug!(%domain, ?error, "DNS fallback after stale XEP-0487 metadata failed")
        }
    }
    deduplicate_endpoints(&mut endpoints);
    if endpoints.is_empty() {
        anyhow::bail!("neither stale XEP-0487 metadata nor DNS provided an endpoint");
    }
    Ok(endpoints)
}

async fn resolve_dns_endpoints(state: &AppState, domain: &str) -> Result<Vec<FederationEndpoint>> {
    let dns_domain = crate::jid::domain_to_ascii(domain)
        .context("federation target cannot be represented as a DNS name")?;
    // XEP-0368 defines Direct TLS and STARTTLS as two connection methods for
    // one service.  Query both concurrently and retain a usable method when
    // only its sibling lookup fails; a transient DNS error must not prevent a
    // successfully published SRV method from being attempted.
    let (direct_result, starttls_result) = tokio::join!(
        lookup_srv(state.s2s_dns_resolver(), &dns_domain, "_xmpps-server"),
        lookup_srv(state.s2s_dns_resolver(), &dns_domain, "_xmpp-server")
    );
    let srv_lookup_failed = direct_result.is_err() || starttls_result.is_err();
    if let Err(error) = &direct_result {
        tracing::debug!(%domain, ?error, "Direct-TLS federation SRV lookup failed");
    }
    if let Err(error) = &starttls_result {
        tracing::debug!(%domain, ?error, "STARTTLS federation SRV lookup failed");
    }
    if direct_result.is_err() && starttls_result.is_err() {
        anyhow::bail!("both federation SRV connection-method lookups failed");
    }
    let direct_records = direct_result.unwrap_or_default();
    let starttls_records = starttls_result.unwrap_or_default();
    let srv_was_published = !direct_records.is_empty() || !starttls_records.is_empty();

    // XEP-0368 permits an implementation to prefer one transport.  Northstar
    // prefers Direct TLS, but STARTTLS records remain connection candidates if
    // every preferred endpoint fails.  Both transports perform identical
    // PKIX/XMPP identity checks, so this is not an authentication downgrade.
    let mut endpoints = Vec::new();
    if direct_records.iter().any(|record| record.target != ".") {
        endpoints.extend(
            resolve_srv_records(state, direct_records, "_xmpps-server", domain)
                .await?
                .into_iter()
                .map(
                    |(address, selection_group, dane_srv_binding)| FederationEndpoint {
                        address,
                        direct_tls: true,
                        tls_server_name: dns_domain.clone(),
                        delegated_identity: false,
                        public_key_pins: Vec::new(),
                        selection_group,
                        dane_srv_binding: Some(dane_srv_binding),
                    },
                ),
        );
    }
    if starttls_records.iter().any(|record| record.target != ".") {
        endpoints.extend(
            resolve_srv_records(state, starttls_records, "_xmpp-server", domain)
                .await?
                .into_iter()
                .map(
                    |(address, selection_group, dane_srv_binding)| FederationEndpoint {
                        address,
                        direct_tls: false,
                        tls_server_name: dns_domain.clone(),
                        delegated_identity: false,
                        public_key_pins: Vec::new(),
                        selection_group,
                        dane_srv_binding: Some(dane_srv_binding),
                    },
                ),
        );
    }
    if !endpoints.is_empty() {
        return Ok(endpoints);
    }
    if srv_was_published || srv_lookup_failed {
        // RFC 6120 / XEP-0368 prohibit A/AAAA fallback once the owner has
        // published SRV intent, including the explicit no-service target '.'.
        // A transient failure of either lookup is also not proof that no SRV
        // intent exists, so fail this attempt instead of silently downgrading
        // to the implicit port-5269 route.
        anyhow::bail!(
            "remote domain published no usable federation endpoint or SRV discovery was incomplete"
        );
    }
    if state.config.federation_dane_mode == DaneMode::Required {
        anyhow::bail!("DANE is required but no XMPP SRV relationship was published");
    }

    let lookup = tokio::time::timeout(
        DNS_LOOKUP_TIMEOUT,
        state.s2s_dns_resolver().lookup_ip(&dns_domain),
    )
    .await
    .context("federation address lookup timed out")?
    .context("federation address lookup failed")?;
    let addresses = interleave_ip_families(lookup.iter())
        .into_iter()
        .take(DNS_MAX_ENDPOINTS)
        .map(|ip| SocketAddr::new(ip, 5269))
        .filter(|address| validate_endpoint(state, *address).is_ok())
        .map(|address| FederationEndpoint {
            address,
            direct_tls: false,
            tls_server_name: dns_domain.clone(),
            delegated_identity: false,
            public_key_pins: Vec::new(),
            selection_group: 0,
            dane_srv_binding: None,
        })
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        anyhow::bail!("no policy-compliant federation endpoint was found");
    }
    Ok(addresses)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HostMetaDiscovery {
    Legacy,
    Authoritative {
        ttl_seconds: u64,
        endpoints: Vec<FederationEndpoint>,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("authoritative XEP-0487 document is invalid: {0:#}")]
struct AuthoritativeHostMetaError(anyhow::Error);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct HttpsLocation {
    host: String,
    port: u16,
    path_and_query: String,
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    content_type: Option<String>,
    location: Option<String>,
    body: Vec<u8>,
}

/// RFC 8259 says object member names SHOULD be unique, while common JSON
/// libraries disagree about whether the first or last duplicate wins. Host
/// metadata controls TLS delegation and IP selection, so accepting ambiguous
/// duplicates would create an avoidable policy-smuggling boundary.
struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

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

async fn fetch_xep_0487(state: &AppState, domain: &str) -> Result<HostMetaDiscovery> {
    let mut location = HttpsLocation {
        host: crate::jid::domain_to_ascii(domain)?,
        port: 443,
        path_and_query: HOST_META_PATH.to_owned(),
    };
    let mut visited = HashSet::new();

    for redirect_count in 0..=HOST_META_MAX_REDIRECTS {
        if !visited.insert(location.clone()) {
            anyhow::bail!("XEP-0487 host-meta redirect loop detected");
        }
        let response = fetch_https_location(state, &location).await?;
        match response.status {
            200 => {
                let content_type = response
                    .content_type
                    .as_deref()
                    .and_then(|value| value.split(';').next())
                    .map(str::trim)
                    .unwrap_or_default();
                if !matches!(content_type, "application/json" | "application/jrd+json") {
                    anyhow::bail!("XEP-0487 host-meta response has an unsupported media type");
                }
                return parse_xep_0487_document(
                    state.config.federation_allow_private_ips,
                    &response.body,
                );
            }
            301 | 302 | 307 | 308 => {
                if redirect_count == HOST_META_MAX_REDIRECTS {
                    anyhow::bail!("XEP-0487 host-meta exceeded its redirect limit");
                }
                let redirect = response
                    .location
                    .as_deref()
                    .context("XEP-0487 redirect omitted Location")?;
                location = parse_https_redirect(&location, redirect)?;
            }
            404 | 410 => return Ok(HostMetaDiscovery::Legacy),
            status => anyhow::bail!("XEP-0487 host-meta returned HTTP status {status}"),
        }
    }
    anyhow::bail!("XEP-0487 host-meta exceeded its redirect limit")
}

fn parse_https_redirect(current: &HttpsLocation, value: &str) -> Result<HttpsLocation> {
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
    let host = crate::jid::domain_to_ascii(host)
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

async fn fetch_https_location(state: &AppState, location: &HttpsLocation) -> Result<HttpResponse> {
    let lookup = tokio::time::timeout(
        DNS_LOOKUP_TIMEOUT,
        state.s2s_dns_resolver().lookup_ip(&location.host),
    )
    .await
    .context("XEP-0487 HTTPS host address lookup timed out")?
    .context("XEP-0487 HTTPS host address lookup failed")?;
    let addresses = interleave_ip_families(lookup.iter())
        .into_iter()
        .take(HOST_META_MAX_HTTPS_ADDRESSES)
        .map(|ip| SocketAddr::new(ip, location.port))
        .filter(|address| validate_endpoint(state, *address).is_ok())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        anyhow::bail!("XEP-0487 HTTPS host has no policy-compliant address");
    }

    let mut last_error = None;
    for address in addresses {
        match fetch_https_address(state, location, address).await {
            Ok(response) => return Ok(response),
            Err(error) => {
                tracing::debug!(host = %location.host, %address, ?error, "XEP-0487 HTTPS endpoint failed");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("XEP-0487 HTTPS endpoint list is empty")))
}

async fn fetch_https_address(
    state: &AppState,
    location: &HttpsLocation,
    address: SocketAddr,
) -> Result<HttpResponse> {
    let stream = tokio::time::timeout(
        HOST_META_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(address),
    )
    .await
    .context("XEP-0487 HTTPS TCP connection timed out")??;
    stream.set_nodelay(true)?;
    let server_name =
        ServerName::try_from(location.host.clone()).context("XEP-0487 HTTPS SNI is invalid")?;
    let connector = TlsConnector::from(crate::s2s::tls::host_meta_https_client_config(state)?);
    let mut secure =
        tokio::time::timeout(HOST_META_IO_TIMEOUT, connector.connect(server_name, stream))
            .await
            .context("XEP-0487 HTTPS TLS handshake timed out")??;

    let host_header = if location.port == 443 {
        location.host.clone()
    } else {
        format!("{}:{}", location.host, location.port)
    };
    const USER_AGENT: &str = concat!("Northstar-XMPP/", env!("CARGO_PKG_VERSION"));
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/jrd+json, application/json\r\nUser-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n",
        location.path_and_query, host_header
    );
    tokio::time::timeout(HOST_META_IO_TIMEOUT, secure.write_all(request.as_bytes()))
        .await
        .context("XEP-0487 HTTPS request write timed out")??;
    tokio::time::timeout(HOST_META_IO_TIMEOUT, secure.flush())
        .await
        .context("XEP-0487 HTTPS request flush timed out")??;

    let mut response = Vec::new();
    tokio::time::timeout(
        HOST_META_IO_TIMEOUT,
        secure
            .take((HOST_META_MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut response),
    )
    .await
    .context("XEP-0487 HTTPS response read timed out")??;
    if response.len() > HOST_META_MAX_RESPONSE_BYTES {
        anyhow::bail!("XEP-0487 HTTPS response exceeds its size limit");
    }
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<HttpResponse> {
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

fn set_unique_header(target: &mut Option<String>, value: &str, name: &str) -> Result<()> {
    if target.replace(value.to_owned()).is_some() {
        anyhow::bail!("XEP-0487 response has duplicate {name} headers");
    }
    Ok(())
}

fn decode_chunked_body(mut encoded: &[u8]) -> Result<Vec<u8>> {
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

fn parse_xep_0487_document(
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

fn parse_authoritative_xep_0487(
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
            .and_then(|sni| crate::jid::domain_to_ascii(sni).ok())
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

fn parse_public_key_pins(value: Option<&Value>) -> Result<Vec<[u8; 32]>> {
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
struct HostMetaEndpoint {
    priority: u16,
    weight: u16,
    endpoint: FederationEndpoint,
}

fn weighted_host_meta_order(mut records: Vec<HostMetaEndpoint>) -> Vec<FederationEndpoint> {
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

fn deduplicate_endpoints(endpoints: &mut Vec<FederationEndpoint>) {
    let mut seen = HashSet::new();
    endpoints.retain(|endpoint| {
        seen.insert((
            endpoint.address,
            endpoint.direct_tls,
            endpoint.tls_server_name.clone(),
        ))
    });
}

async fn resolve_srv_records(
    state: &AppState,
    records: Vec<SrvRecord>,
    service: &str,
    xmpp_domain: &str,
) -> Result<Vec<(SocketAddr, u64, DaneSrvBinding)>> {
    let mut addresses = Vec::new();
    for (selection_group, record) in weighted_srv_order(records).into_iter().enumerate() {
        if record.target == "." {
            continue;
        }
        let target = record.target.trim_end_matches('.');
        let dane_srv_binding = DaneSrvBinding::new(service, xmpp_domain, target, record.port)?;
        let lookup = match tokio::time::timeout(
            DNS_LOOKUP_TIMEOUT,
            state.s2s_dns_resolver().lookup_ip(target),
        )
        .await
        {
            Err(_) => {
                tracing::debug!(%target, "federation SRV target address lookup timed out");
                continue;
            }
            Ok(lookup) => match lookup {
                Ok(lookup) => lookup,
                Err(error) if no_records(&error) => continue,
                Err(error) => {
                    tracing::debug!(%target, ?error, "federation SRV target address lookup failed");
                    continue;
                }
            },
        };
        for ip in interleave_ip_families(lookup.iter())
            .into_iter()
            .take(DNS_MAX_IPS_PER_SRV_TARGET)
        {
            let address = SocketAddr::new(ip, record.port);
            if validate_endpoint(state, address).is_ok()
                && !addresses
                    .iter()
                    .any(|(candidate, _, _)| *candidate == address)
            {
                addresses.push((address, selection_group as u64, dane_srv_binding.clone()));
                if addresses.len() >= DNS_MAX_ENDPOINTS {
                    return Ok(addresses);
                }
            }
        }
    }
    Ok(addresses)
}

fn interleave_ip_families(addresses: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
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

fn weighted_srv_order(mut records: Vec<SrvRecord>) -> Vec<SrvRecord> {
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

async fn lookup_srv(
    resolver: &TokioResolver,
    domain: &str,
    service: &str,
) -> Result<Vec<SrvRecord>> {
    let name = format!("{service}._tcp.{}.", domain.trim_end_matches('.'));
    let lookup = match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, resolver.srv_lookup(name.clone()))
        .await
        .with_context(|| format!("DNS SRV lookup timed out for {name}"))?
    {
        Ok(lookup) => lookup,
        Err(error) if no_records(&error) => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("DNS SRV lookup failed for {name}"));
        }
    };
    Ok(lookup
        .answers()
        .iter()
        .take(DNS_MAX_SRV_RECORDS)
        .filter_map(|record| match &record.data {
            RData::SRV(record) => Some(SrvRecord {
                priority: record.priority,
                weight: record.weight,
                port: record.port,
                target: if record.target.to_utf8() == "." {
                    ".".to_owned()
                } else {
                    crate::jid::domain_to_ascii(&record.target.to_utf8()).ok()?
                },
            }),
            _ => None,
        })
        .collect())
}

fn no_records(error: &NetError) -> bool {
    matches!(
        error,
        NetError::Dns(DnsError::NoRecordsFound(no_records)) if matches!(
            no_records.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        )
    )
}

pub(crate) fn validate_endpoint(state: &AppState, address: SocketAddr) -> Result<()> {
    validate_address_policy(state.config.federation_allow_private_ips, address)
}

fn validate_address_policy(federation_allow_private_ips: bool, address: SocketAddr) -> Result<()> {
    if !federation_allow_private_ips && !is_public_ip(address.ip()) {
        anyhow::bail!("federation endpoint resolves to a private or special-use IP address");
    }
    Ok(())
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // Deprecated IPv4-compatible addresses and translation/transition
        // prefixes can otherwise tunnel a syntactically public IPv6 literal
        // to an IPv4 loopback or private destination.
        || segments[..6] == [0, 0, 0, 0, 0, 0]
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || segments[0] == 0x2002
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x0100 && segments[1] == 0)
        || (segments[0] == 0x2001 && segments[1] == 0x0002)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] & 0xfff0) == 0x3ff0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(priority: u16, weight: u16, target: &str) -> SrvRecord {
        SrvRecord {
            priority,
            weight,
            port: 5269,
            target: target.to_owned(),
        }
    }

    #[test]
    fn host_meta_cache_capacity_admission_is_linearizable() {
        let cache = dashmap::DashMap::new();
        let admission = Mutex::new(BoundedCacheAdmission::default());
        let workers = 64;
        let limit = 16;
        let now = Instant::now();
        let expiry = now + Duration::from_secs(60);
        let barrier = std::sync::Barrier::new(workers);
        let accepted = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for index in 0..workers {
                let cache = &cache;
                let admission = &admission;
                let barrier = &barrier;
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    bounded_cache_insert_with_limit(
                        cache,
                        admission,
                        format!("peer-{index}.example"),
                        (index, expiry),
                        limit,
                        now,
                        |entry| entry.1,
                    )
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("cache admission worker"))
                .filter(|accepted| *accepted)
                .count()
        });

        assert_eq!(accepted, limit);
        assert_eq!(cache.len(), limit);
    }

    #[test]
    fn expired_host_meta_entries_release_capacity() {
        let cache = dashmap::DashMap::new();
        let admission = Mutex::new(BoundedCacheAdmission::default());
        let now = Instant::now();
        let expired_at = now + Duration::from_millis(1);
        assert!(bounded_cache_insert_with_limit(
            &cache,
            &admission,
            "expired.example".to_owned(),
            (1_u8, expired_at),
            1,
            now,
            |entry| entry.1,
        ));
        assert!(bounded_cache_insert_with_limit(
            &cache,
            &admission,
            "fresh.example".to_owned(),
            (2_u8, expired_at + Duration::from_secs(60)),
            1,
            expired_at + Duration::from_millis(1),
            |entry| entry.1,
        ));
        assert!(!cache.contains_key("expired.example"));
        assert_eq!(cache.get("fresh.example").map(|entry| entry.0), Some(2));
    }

    #[test]
    fn full_host_meta_cache_does_not_rescan_before_the_earliest_ttl() {
        let cache = dashmap::DashMap::new();
        let admission = Mutex::new(BoundedCacheAdmission::default());
        let now = Instant::now();
        let resident_expiry = now + Duration::from_secs(60);
        assert!(bounded_cache_insert_with_limit(
            &cache,
            &admission,
            "resident.example".to_owned(),
            resident_expiry,
            1,
            now,
            |expiry| *expiry,
        ));
        for index in 0..128 {
            assert!(!bounded_cache_insert_with_limit(
                &cache,
                &admission,
                format!("rejected-{index}.example"),
                resident_expiry + Duration::from_secs(60),
                1,
                now,
                |expiry| *expiry,
            ));
        }
        assert_eq!(
            admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sweeps,
            0
        );
        assert!(bounded_cache_insert_with_limit(
            &cache,
            &admission,
            "replacement.example".to_owned(),
            resident_expiry + Duration::from_secs(60),
            1,
            resident_expiry + Duration::from_millis(1),
            |expiry| *expiry,
        ));
        assert_eq!(
            admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sweeps,
            1
        );
    }

    #[test]
    fn srv_order_never_crosses_priority_groups() {
        for _ in 0..100 {
            let ordered = weighted_srv_order(vec![
                record(20, 100, "late.example."),
                record(10, 0, "first-a.example."),
                record(10, 50, "first-b.example."),
            ]);
            assert_eq!(ordered[0].priority, 10);
            assert_eq!(ordered[1].priority, 10);
            assert_eq!(ordered[2].priority, 20);
        }
    }

    #[test]
    fn zero_weight_group_still_returns_every_record() {
        let ordered = weighted_srv_order(vec![
            record(10, 0, "a.example."),
            record(10, 0, "b.example."),
            record(10, 0, "c.example."),
        ]);
        assert_eq!(ordered.len(), 3);
    }

    #[test]
    fn dual_stack_candidates_are_interleaved_without_dropping_either_family() {
        let ordered = interleave_ip_families([
            "2001:4860:4860::8888".parse().unwrap(),
            "2001:4860:4860::8844".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "8.8.4.4".parse().unwrap(),
        ]);
        assert_eq!(ordered.len(), 4);
        assert!(ordered[0].is_ipv6());
        assert!(ordered[1].is_ipv4());
        assert!(ordered[2].is_ipv6());
        assert!(ordered[3].is_ipv4());

        let ipv4_first = interleave_ip_families([
            "8.8.8.8".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ]);
        assert!(ipv4_first[0].is_ipv4());
        assert!(ipv4_first[1].is_ipv6());
    }

    #[test]
    fn ssrf_filter_rejects_private_special_and_mapped_addresses() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fec0::1",
            "fe80::1",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::",
            "2001:db8::1",
            "3fff::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public_ip(ip.parse().unwrap()), "accepted {ip}");
        }
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn xep_0487_document_is_authoritative_bounded_and_delegates_exactly() {
        let document = br#"{
            "xmpp":{"ttl":300,"public-key-pins-sha-256":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]},
            "links":[
                {"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,
                 "ips":["8.8.8.8"],"priority":10,"weight":50,"sni":"Xmpp.Example."},
                {"rel":"urn:xmpp:alt-connections:websocket","href":"wss://ignored.example/ws"}
            ]
        }"#;
        let parsed = parse_xep_0487_document(false, document).unwrap();
        let HostMetaDiscovery::Authoritative {
            ttl_seconds,
            endpoints,
        } = parsed
        else {
            panic!("XEP-0487 marker was not authoritative");
        };
        assert_eq!(ttl_seconds, 300);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].address, "8.8.8.8:5270".parse().unwrap());
        assert_eq!(endpoints[0].tls_server_name, "xmpp.example");
        assert!(endpoints[0].direct_tls);
        assert!(endpoints[0].delegated_identity);
        assert_eq!(endpoints[0].public_key_pins, vec![[0; 32]]);
        assert_eq!(endpoints[0].selection_group, 10);

        assert_eq!(
            parse_xep_0487_document(false, br#"{"links":[]}"#).unwrap(),
            HostMetaDiscovery::Legacy
        );
        let no_s2s =
            parse_xep_0487_document(false, br#"{"xmpp":{"ttl":30},"links":[{"rel":"ignored"}]}"#)
                .unwrap();
        assert!(matches!(
            no_s2s,
            HostMetaDiscovery::Authoritative { endpoints, .. } if endpoints.is_empty()
        ));
    }

    #[test]
    fn xep_0487_rejects_unsafe_or_ambiguous_connection_metadata() {
        for invalid in [
            br#"{"xmpp":{},"links":[]}"#.as_slice(),
            br#"{"xmpp":{"ttl":0},"links":[]}"#.as_slice(),
            br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":[],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
            br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":["not-an-ip"],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
            br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":["127.0.0.1"],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
            br#"{"xmpp":{"ttl":30,"public-key-pins-sha-256":["AA=="]},"links":[]}"#.as_slice(),
            br#"{"xmpp":{"ttl":30},"xmpp":{"ttl":60},"links":[]}"#.as_slice(),
            br#"{"xmpp":{"ttl":30,"ttl":60},"links":[]}"#.as_slice(),
            br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","rel":"ignored","port":5270,"ips":["8.8.8.8"],"priority":0,"weight":0,"sni":"example.org"}]}"#.as_slice(),
        ] {
            assert!(
                parse_xep_0487_document(false, invalid).is_err(),
                "accepted {}",
                String::from_utf8_lossy(invalid)
            );
        }
        let authoritative_error =
            parse_xep_0487_document(false, br#"{"xmpp":{"ttl":30,"ttl":60},"links":[]}"#)
                .unwrap_err();
        assert!(
            authoritative_error
                .downcast_ref::<AuthoritativeHostMetaError>()
                .is_some(),
            "an explicit xmpp marker must not downgrade to legacy DNS discovery"
        );
        let private_test = br#"{"xmpp":{"ttl":30},"links":[{"rel":"urn:xmpp:alt-connections:s2s-tls","port":5270,"ips":["127.0.0.1"],"priority":0,"weight":0,"sni":"localhost"}]}"#;
        assert!(parse_xep_0487_document(true, private_test).is_ok());
    }

    #[test]
    fn host_meta_http_parser_enforces_framing_and_decodes_chunks() {
        let response = parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/jrd+json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"test");
        assert_eq!(
            response.content_type.as_deref(),
            Some("application/jrd+json")
        );

        for invalid in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nbody".as_slice(),
            b"HTTP/1.1 200 OK\r\n folded: value\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\ntoo-long".as_slice(),
        ] {
            assert!(parse_http_response(invalid).is_err());
        }
    }

    #[test]
    fn host_meta_redirects_remain_https_bounded_and_loop_trackable() {
        let current = HttpsLocation {
            host: "example.org".to_owned(),
            port: 443,
            path_and_query: HOST_META_PATH.to_owned(),
        };
        assert_eq!(
            parse_https_redirect(&current, "/metadata.json").unwrap(),
            HttpsLocation {
                host: "example.org".to_owned(),
                port: 443,
                path_and_query: "/metadata.json".to_owned(),
            }
        );
        assert_eq!(
            parse_https_redirect(&current, "https://Meta.Example:8443/host.json?q=1").unwrap(),
            HttpsLocation {
                host: "meta.example".to_owned(),
                port: 8443,
                path_and_query: "/host.json?q=1".to_owned(),
            }
        );
        for invalid in [
            "http://example.org/metadata",
            "https://user@example.org/metadata",
            "https://127.0.0.1/metadata",
            "https://example.org:0/metadata",
        ] {
            assert!(parse_https_redirect(&current, invalid).is_err());
        }
    }
}
