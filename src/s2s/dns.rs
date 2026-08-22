use crate::state::AppState;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::{net::IpAddr, time::Duration};
use tokio::net::lookup_host;
use tokio::net::UdpSocket;

pub(crate) async fn resolve_federation_endpoint(
    state: &AppState,
    domain: &str,
) -> Result<SocketAddr> {
    if let Some((_, address)) = state
        .config
        .federation_dns_overrides
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(domain))
    {
        validate_endpoint(state, *address)?;
        return Ok(*address);
    }

    if let Some(cached) = state.s2s_dns_cache.get(domain) {
        if cached.value().1.elapsed() < Duration::from_secs(3600) {
            return Ok(cached.value().0);
        }
    }

    let records = lookup_srv(domain).await.unwrap_or_default();
    for (_, _, port, target) in records {
        if target == "." {
            anyhow::bail!("remote domain explicitly disables XMPP federation");
        }
        for address in lookup_host((target.trim_end_matches('.'), port)).await? {
            if validate_endpoint(state, address).is_ok() {
                state
                    .s2s_dns_cache
                    .insert(domain.to_string(), (address, std::time::Instant::now()));
                return Ok(address);
            }
        }
    }
    for address in lookup_host((domain, 5269)).await? {
        if validate_endpoint(state, address).is_ok() {
            state
                .s2s_dns_cache
                .insert(domain.to_string(), (address, std::time::Instant::now()));
            return Ok(address);
        }
    }
    anyhow::bail!("no policy-compliant federation endpoint was found")
}

pub(crate) fn validate_endpoint(state: &AppState, address: SocketAddr) -> Result<()> {
    if !state.config.federation_allow_private_ips && !is_public_ip(address.ip()) {
        anyhow::bail!("federation endpoint resolves to a private or special-use IP address");
    }
    Ok(())
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || ip.is_unspecified())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8))
        }
    }
}

pub(crate) async fn lookup_srv(domain: &str) -> Result<Vec<(u16, u16, u16, String)>> {
    let resolv = tokio::fs::read_to_string("/etc/resolv.conf").await?;
    let nameserver = resolv
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next())
                .flatten()
        })
        .context("no DNS nameserver is configured")?;
    let nameserver: IpAddr = nameserver.parse().context("invalid DNS nameserver")?;
    let socket = if nameserver.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0").await?
    } else {
        UdpSocket::bind("[::]:0").await?
    };
    let id = rand::random::<u16>();
    let mut query = Vec::with_capacity(512);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    encode_dns_name(&format!("_xmpp-server._tcp.{domain}"), &mut query)?;
    query.extend_from_slice(&33u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    socket.connect(SocketAddr::new(nameserver, 53)).await?;
    socket.send(&query).await?;
    let mut response = [0u8; 4096];
    let length = tokio::time::timeout(Duration::from_secs(3), socket.recv(&mut response))
        .await
        .context("DNS SRV query timed out")??;
    parse_srv_response(&response[..length], id)
}

pub(crate) fn encode_dns_name(name: &str, output: &mut Vec<u8>) -> Result<()> {
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("invalid DNS name");
        }
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

pub(crate) fn parse_srv_response(
    response: &[u8],
    expected_id: u16,
) -> Result<Vec<(u16, u16, u16, String)>> {
    if response.len() < 12 || u16_at(response, 0)? != expected_id || response[3] & 0x0f != 0 {
        anyhow::bail!("invalid DNS response");
    }
    let questions = u16_at(response, 4)? as usize;
    let answers = u16_at(response, 6)? as usize;
    let mut position = 12;
    for _ in 0..questions {
        position = skip_dns_name(response, position)?;
        position = position.checked_add(4).context("truncated DNS question")?;
        if position > response.len() {
            anyhow::bail!("truncated DNS question");
        }
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        position = skip_dns_name(response, position)?;
        let record_type = u16_at(response, position)?;
        let class = u16_at(response, position + 2)?;
        let length = u16_at(response, position + 8)? as usize;
        let data = position + 10;
        let end = data.checked_add(length).context("DNS record overflow")?;
        if end > response.len() {
            anyhow::bail!("truncated DNS record");
        }
        if record_type == 33 && class == 1 && length >= 7 {
            records.push((
                u16_at(response, data)?,
                u16_at(response, data + 2)?,
                u16_at(response, data + 4)?,
                read_dns_name(response, data + 6)?.0,
            ));
        }
        position = end;
    }
    records.sort_by_key(|(priority, weight, _, _)| (*priority, std::cmp::Reverse(*weight)));
    Ok(records)
}

pub(crate) fn u16_at(data: &[u8], position: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(position..position + 2)
        .context("truncated DNS integer")?
        .try_into()?;
    Ok(u16::from_be_bytes(bytes))
}

pub(crate) fn skip_dns_name(data: &[u8], mut position: usize) -> Result<usize> {
    loop {
        let length = *data.get(position).context("truncated DNS name")?;
        if length & 0xc0 == 0xc0 {
            return position.checked_add(2).context("DNS name overflow");
        }
        position += 1;
        if length == 0 {
            return Ok(position);
        }
        if length & 0xc0 != 0 {
            anyhow::bail!("invalid DNS label");
        }
        position = position
            .checked_add(length as usize)
            .context("DNS name overflow")?;
        if position > data.len() {
            anyhow::bail!("truncated DNS label");
        }
    }
}

pub(crate) fn read_dns_name(data: &[u8], position: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = position;
    let mut consumed = None;
    for _ in 0..128 {
        let length = *data.get(cursor).context("truncated DNS name")?;
        if length & 0xc0 == 0xc0 {
            let next = *data.get(cursor + 1).context("truncated DNS pointer")? as usize;
            let pointer = (((length & 0x3f) as usize) << 8) | next;
            consumed.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        cursor += 1;
        if length == 0 {
            let end = consumed.unwrap_or(cursor);
            return Ok((format!("{}.", labels.join(".")), end));
        }
        if length & 0xc0 != 0 || length > 63 {
            anyhow::bail!("invalid DNS label");
        }
        let label = data
            .get(cursor..cursor + length as usize)
            .context("truncated DNS label")?;
        labels.push(std::str::from_utf8(label)?.to_ascii_lowercase());
        cursor += length as usize;
    }
    anyhow::bail!("DNS compression pointer loop")
}
