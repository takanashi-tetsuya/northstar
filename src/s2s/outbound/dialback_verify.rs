//! Asks the authoritative server to verify a peer's dialback key (XEP-0220 section 2.3).

use super::*;

pub(crate) async fn verify_remote(
    state: Arc<AppState>,
    originating_domain: &str,
    receiving_domain: &str,
    stream_id: &str,
    supplied_key: &str,
) -> Result<DialbackOutcome> {
    if !valid_key(supplied_key) {
        return Ok(DialbackOutcome::Invalid);
    }
    let originating_domain =
        prepare_domainpart(originating_domain).context("invalid dialback originating domain")?;
    let receiving_domain =
        prepare_domainpart(receiving_domain).context("invalid dialback receiving domain")?;
    let permit = state
        .try_acquire_dialback_verification()
        .context("too many concurrent dialback verification requests")?;
    let _connection_permit = state
        .try_acquire_s2s_connection()
        .context("S2S connection capacity is exhausted during dialback verification")?;
    let (mut stream, opening, _features, mut input, _peer_certificates, _tls_generation) =
        crate::s2s::outbound::connect_secure_stream_from(
            &state,
            &receiving_domain,
            &originating_domain,
        )
        .await?;
    if stream_attribute(&opening, "from")
        .is_none_or(|domain| !same_dialback_domain(&domain, &originating_domain))
        || stream_attribute(&opening, "to")
            .is_none_or(|domain| !same_dialback_domain(&domain, &receiving_domain))
    {
        anyhow::bail!("authoritative dialback endpoint returned an invalid stream identity");
    }
    write_xml(
        &mut stream,
        &verify_request(
            &receiving_domain,
            &originating_domain,
            stream_id,
            supplied_key,
        ),
    )
    .await?;
    let response = timed_read_frame(&mut stream, &mut input).await?;
    drop(permit);
    parse_verify_response(&response, &originating_domain, &receiving_domain, stream_id)
}
