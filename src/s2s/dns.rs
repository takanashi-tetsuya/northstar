use anyhow::{Context, Result};
use hickory_resolver::{
    net::{DnsError, NetError},
    proto::{op::ResponseCode, rr::RData},
    TokioResolver,
};
use northstar_federation_application::endpoint::*;
use northstar_security::dane::DaneSrvBinding;
use northstar_security::tls::TlsContext;
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

/// What federation endpoint discovery reads from the composition root: the
/// S2S resolver, the configured DNS overrides, the DANE and private-address
/// policies and the federation TLS material for XEP-0487 HTTPS lookups.
#[derive(Clone, Copy)]
pub(crate) struct FederationDnsContext<'a> {
    pub(crate) resolver: &'a TokioResolver,
    pub(crate) overrides: &'a [(String, SocketAddr, bool)],
    pub(crate) dane_required: bool,
    pub(crate) private_addresses_allowed: bool,
    pub(crate) tls: &'a TlsContext,
}

impl FederationDnsContext<'_> {
    fn dns_override(&self, domain: &str) -> Option<(SocketAddr, bool)> {
        self.overrides
            .iter()
            .find(|(candidate, _, _)| {
                northstar_xmpp_types::jid::prepare_domainpart(candidate)
                    .is_ok_and(|candidate| candidate == domain)
            })
            .map(|(_, address, direct_tls)| (*address, *direct_tls))
    }
}

const HOST_META_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HOST_META_IO_TIMEOUT: Duration = Duration::from_secs(12);
const HOST_META_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(45);
const HOST_META_MAX_RESPONSE_BYTES: usize = HOST_META_MAX_HEADER_BYTES + HOST_META_MAX_BODY_BYTES;
const HOST_META_MAX_REDIRECTS: usize = 3;
const HOST_META_MAX_HTTPS_ADDRESSES: usize = 16;
const HOST_META_LEGACY_CACHE_SECONDS: u64 = 300;
const HOST_META_FAILURE_CACHE_SECONDS: u64 = 60;
const DNS_MAX_SRV_RECORDS: usize = 128;
const DNS_MAX_IPS_PER_SRV_TARGET: usize = 32;
const DNS_MAX_ENDPOINTS: usize = 256;
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Debug)]
struct CachedHostMeta {
    expires_at: Instant,
    endpoints: Vec<FederationEndpoint>,
}

static HOST_META_CACHE: OnceLock<dashmap::DashMap<String, CachedHostMeta>> = OnceLock::new();
static HOST_META_NEGATIVE_CACHE: OnceLock<dashmap::DashMap<String, Instant>> = OnceLock::new();
static HOST_META_CACHE_ADMISSION: OnceLock<Mutex<BoundedCacheAdmission>> = OnceLock::new();
static HOST_META_NEGATIVE_CACHE_ADMISSION: OnceLock<Mutex<BoundedCacheAdmission>> = OnceLock::new();

fn host_meta_cache() -> &'static dashmap::DashMap<String, CachedHostMeta> {
    HOST_META_CACHE.get_or_init(dashmap::DashMap::new)
}

fn host_meta_negative_cache() -> &'static dashmap::DashMap<String, Instant> {
    HOST_META_NEGATIVE_CACHE.get_or_init(dashmap::DashMap::new)
}

/// Resolve every usable endpoint in RFC 2782 order. Hickory owns the positive
/// and negative caches, honors record TTLs, follows CNAMEs, tries all system
/// name servers, and falls back to TCP for truncated/failed UDP responses.
pub(crate) async fn resolve_federation_endpoints(
    dns: FederationDnsContext<'_>,
    domain: &str,
) -> Result<Vec<FederationEndpoint>> {
    let domain = northstar_xmpp_types::jid::prepare_domainpart(domain)
        .context("federation target is not a valid RFC 7622 domain")?;
    let dns_domain = northstar_xmpp_types::jid::domain_to_ascii(&domain)
        .context("federation target cannot be represented as a DNS name")?;
    if dns.dane_required {
        return resolve_dns_endpoints(dns, &domain).await;
    }
    if let Some((address, direct_tls)) = dns.dns_override(&domain) {
        validate_endpoint(dns, address)?;
        return Ok(vec![FederationEndpoint {
            address,
            direct_tls,
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
                return stale_host_meta_with_dns(dns, &domain, cached.endpoints).await;
            }
            return resolve_dns_endpoints(dns, &domain).await;
        }
        host_meta_negative_cache().remove(&domain);
    }
    let host_meta = tokio::time::timeout(HOST_META_DISCOVERY_TIMEOUT, fetch_xep_0487(dns, &domain))
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
                return stale_host_meta_with_dns(dns, &domain, cached.endpoints).await;
            }
        }
    }

    resolve_dns_endpoints(dns, &domain).await
}

async fn stale_host_meta_with_dns(
    dns: FederationDnsContext<'_>,
    domain: &str,
    mut endpoints: Vec<FederationEndpoint>,
) -> Result<Vec<FederationEndpoint>> {
    match resolve_dns_endpoints(dns, domain).await {
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

async fn resolve_dns_endpoints(
    dns: FederationDnsContext<'_>,
    domain: &str,
) -> Result<Vec<FederationEndpoint>> {
    let dns_domain = northstar_xmpp_types::jid::domain_to_ascii(domain)
        .context("federation target cannot be represented as a DNS name")?;
    // XEP-0368 defines Direct TLS and STARTTLS as two connection methods for
    // one service.  Query both concurrently and retain a usable method when
    // only its sibling lookup fails; a transient DNS error must not prevent a
    // successfully published SRV method from being attempted.
    let (direct_result, starttls_result) = tokio::join!(
        lookup_srv(dns.resolver, &dns_domain, "_xmpps-server"),
        lookup_srv(dns.resolver, &dns_domain, "_xmpp-server")
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
            resolve_srv_records(dns, direct_records, "_xmpps-server", domain)
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
            resolve_srv_records(dns, starttls_records, "_xmpp-server", domain)
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
    if dns.dane_required {
        anyhow::bail!("DANE is required but no XMPP SRV relationship was published");
    }

    let lookup = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, dns.resolver.lookup_ip(&dns_domain))
        .await
        .context("federation address lookup timed out")?
        .context("federation address lookup failed")?;
    let addresses = interleave_ip_families(lookup.iter())
        .into_iter()
        .take(DNS_MAX_ENDPOINTS)
        .map(|ip| SocketAddr::new(ip, 5269))
        .filter(|address| validate_endpoint(dns, *address).is_ok())
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

async fn fetch_xep_0487(dns: FederationDnsContext<'_>, domain: &str) -> Result<HostMetaDiscovery> {
    let mut location = HttpsLocation {
        host: northstar_xmpp_types::jid::domain_to_ascii(domain)?,
        port: 443,
        path_and_query: HOST_META_PATH.to_owned(),
    };
    let mut visited = HashSet::new();

    for redirect_count in 0..=HOST_META_MAX_REDIRECTS {
        if !visited.insert(location.clone()) {
            anyhow::bail!("XEP-0487 host-meta redirect loop detected");
        }
        let response = fetch_https_location(dns, &location).await?;
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
                return parse_xep_0487_document(dns.private_addresses_allowed, &response.body);
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

async fn fetch_https_location(
    dns: FederationDnsContext<'_>,
    location: &HttpsLocation,
) -> Result<HttpResponse> {
    let lookup = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, dns.resolver.lookup_ip(&location.host))
        .await
        .context("XEP-0487 HTTPS host address lookup timed out")?
        .context("XEP-0487 HTTPS host address lookup failed")?;
    let addresses = interleave_ip_families(lookup.iter())
        .into_iter()
        .take(HOST_META_MAX_HTTPS_ADDRESSES)
        .map(|ip| SocketAddr::new(ip, location.port))
        .filter(|address| validate_endpoint(dns, *address).is_ok())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        anyhow::bail!("XEP-0487 HTTPS host has no policy-compliant address");
    }

    let mut last_error = None;
    for address in addresses {
        match fetch_https_address(dns, location, address).await {
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
    dns: FederationDnsContext<'_>,
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
    let connector = TlsConnector::from(crate::s2s::tls::host_meta_https_client_config(dns.tls)?);
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

async fn resolve_srv_records(
    dns: FederationDnsContext<'_>,
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
        let lookup = match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, dns.resolver.lookup_ip(target))
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
            if validate_endpoint(dns, address).is_ok()
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
                    northstar_xmpp_types::jid::domain_to_ascii(&record.target.to_utf8()).ok()?
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

pub(crate) fn validate_endpoint(dns: FederationDnsContext<'_>, address: SocketAddr) -> Result<()> {
    validate_address_policy(dns.private_addresses_allowed, address)
}
