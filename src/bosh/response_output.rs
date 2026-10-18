//! Own bounded response buffers, resume output, cached replay and XML response rendering.

use super::*;

pub(super) fn superseded_bosh_message_id(error: &anyhow::Error) -> Option<uuid::Uuid> {
    error
        .downcast_ref::<crate::xmpp::outbound::DurableDeliverySuperseded>()
        .map(|superseded| superseded.message_id)
}

pub(super) struct BoshCapacityBody {
    pub(super) body: String,
    pub(super) _holds: Vec<Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>>,
}

impl AsRef<[u8]> for BoshCapacityBody {
    fn as_ref(&self) -> &[u8] {
        self.body.as_bytes()
    }
}

pub(super) fn bosh_response_bytes(
    body: String,
    holds: Vec<Arc<Vec<crate::services::sm_capacity::SmCapacityLease>>>,
) -> Bytes {
    if holds.is_empty() {
        Bytes::from(body)
    } else {
        // `Bytes::from_owner` binds the leases to the exact ref-counted body
        // allocation. Cache clones, duplicate waiters and Hyper retain them
        // until their last byte owner is consumed or dropped on failure.
        Bytes::from_owner(BoshCapacityBody {
            body,
            _holds: holds,
        })
    }
}

pub(super) fn queue_bosh_resume_payload(
    output: &mut VecDeque<crate::xmpp::outbound::OutboundItem>,
    output_bytes: &mut usize,
    max_output_stanzas: usize,
    max_output_bytes: usize,
    payload: ResumeTransportParts,
) -> bool {
    let ResumeTransportParts {
        control,
        post_control,
        replay,
        activate_route,
        auth_publication,
        transient_capacity,
    } = payload;
    let Some(batch_count) = 1usize
        .checked_add(post_control.len())
        .and_then(|count| count.checked_add(replay.len()))
    else {
        return false;
    };
    let Some(batch_bytes) = post_control
        .iter()
        .chain(&replay)
        .try_fold(control.len(), |bytes, stanza| {
            bytes.checked_add(stanza.len())
        })
    else {
        return false;
    };
    if output
        .len()
        .checked_add(batch_count)
        .is_none_or(|count| count > max_output_stanzas)
        || output_bytes
            .checked_add(batch_bytes)
            .is_none_or(|bytes| bytes > max_output_bytes)
    {
        return false;
    }

    let hold = Arc::new(transient_capacity);
    let control = crate::xmpp::outbound::OutboundItem::resume_fragment(control, Arc::clone(&hold));
    let control = if activate_route {
        let Some(holder) = auth_publication else {
            return false;
        };
        match control.with_auth_publication(holder) {
            Ok(control) => control,
            Err(_) => return false,
        }
    } else {
        if auth_publication.is_some() {
            return false;
        }
        control
    };
    output.push_back(control);
    for stanza in post_control.into_iter().chain(replay) {
        output.push_back(crate::xmpp::outbound::OutboundItem::resume_fragment(
            stanza,
            Arc::clone(&hold),
        ));
    }
    *output_bytes += batch_bytes;
    true
}

/// Put a failed response attempt back ahead of later actor output. An exact
/// superseded C2S item is the only one discarded; every other stanza and its
/// receipt keep their original relative order for response reconstruction.
pub(super) fn restore_response_items(
    output: &mut VecDeque<crate::xmpp::outbound::OutboundItem>,
    output_bytes: &mut usize,
    selected: VecDeque<crate::xmpp::outbound::OutboundItem>,
    superseded: Option<uuid::Uuid>,
) -> bool {
    restore_response_items_observed(output, output_bytes, selected, superseded, |_| {})
}

pub(super) fn restore_response_items_observed(
    output: &mut VecDeque<crate::xmpp::outbound::OutboundItem>,
    output_bytes: &mut usize,
    selected: VecDeque<crate::xmpp::outbound::OutboundItem>,
    superseded: Option<uuid::Uuid>,
    mut on_removed: impl FnMut(usize),
) -> bool {
    let mut removed = false;
    for (index, item) in selected.into_iter().enumerate().rev() {
        if superseded.is_some_and(|id| {
            item.c2s_delivery()
                .is_some_and(|source| source.message_id == id)
        }) {
            on_removed(index);
            removed = true;
            continue;
        }
        *output_bytes = output_bytes
            .checked_add(item.stanza.len())
            .expect("restoring previously bounded BOSH output bytes");
        output.push_front(item);
    }
    removed
}

pub(super) fn take_response_payload(
    output: &mut VecDeque<crate::xmpp::outbound::OutboundItem>,
    output_bytes: &mut usize,
    max_response_bytes: usize,
    governor: &Arc<crate::services::sm_capacity::SmMemoryGovernor>,
) -> anyhow::Result<BoshResponsePayload> {
    const WRAPPER_RESERVE: usize = 256;
    let mut selected = 0usize;
    let mut selected_bytes = 0usize;
    for stanza in output.iter() {
        if selected > 0
            && selected_bytes
                .saturating_add(stanza.stanza.len())
                .saturating_add(WRAPPER_RESERVE)
                > max_response_bytes
        {
            break;
        }
        if selected == 0 && stanza.stanza.len().saturating_add(WRAPPER_RESERVE) > max_response_bytes
        {
            anyhow::bail!("one BOSH output stanza exceeds the response byte limit");
        }
        selected_bytes = selected_bytes
            .checked_add(stanza.stanza.len())
            .context("BOSH response payload byte count overflow")?;
        selected += 1;
    }

    let mut transient_sm_capacity = Vec::new();
    let mut seen_capacity = std::collections::HashSet::new();
    for item in output.iter().take(selected) {
        if let Some(capacity) = &item.transient_sm_capacity {
            let identity = Arc::as_ptr(capacity) as usize;
            if seen_capacity.insert(identity) {
                transient_sm_capacity.push(Arc::clone(capacity));
            }
        }
    }
    if !transient_sm_capacity.is_empty() {
        // XmlElement's validated-fragment boundary temporarily owns `payload`,
        // its parser wrapper/copy and the final response. The original action
        // lease accounts for one copy; reserve the other two before allocating
        // any response buffer. The final String is moved into `Bytes`, so RID
        // cache, duplicate waiters and Hyper all share that one allocation.
        let construction_bytes = selected_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(WRAPPER_RESERVE * 4))
            .context("BOSH resume response construction capacity overflow")?;
        let extra = governor
            .try_reserve_transient(construction_bytes)
            .context("BOSH resume response memory capacity reached")?;
        transient_sm_capacity.push(Arc::new(extra));
    }

    let mut payload = String::with_capacity(selected_bytes);
    let mut sources = Vec::new();
    let mut transport_receipts = Vec::new();
    let mut selected_items = VecDeque::with_capacity(selected);
    for _ in 0..selected {
        let stanza = output.pop_front().expect("front was present");
        *output_bytes = output_bytes
            .checked_sub(stanza.stanza.len())
            .context("BOSH output byte accounting underflow")?;
        payload.push_str(&stanza.stanza);
        if let Some(receipt) = &stanza.transport_receipt {
            transport_receipts.push(receipt.clone());
        }
        if let Some(receipt) = &stanza.transport_write_receipt {
            transport_receipts.push(receipt.clone());
        }
        if let Some(source) = stanza.durable_source {
            sources.push(source);
        }
        selected_items.push_back(stanza);
    }
    Ok((
        payload,
        sources,
        transport_receipts,
        transient_sm_capacity,
        selected_items,
    ))
}

pub(super) fn replay_response(
    replay: &mut VecDeque<CachedResponse>,
    request: &BoshRequest,
) -> Option<(
    BoshHttpResponse,
    bool,
    Arc<crate::xmpp::outbound::BoshResponseOwnership>,
)> {
    let cached = replay.iter_mut().find(|cached| cached.rid == request.rid)?;
    if cached.fingerprint != request.fingerprint {
        return Some((
            terminal_response("bad-request"),
            true,
            Arc::new(crate::xmpp::outbound::BoshResponseOwnership::default()),
        ));
    }
    if cached.replays >= MAX_RESPONSE_REPLAYS {
        return Some((
            terminal_response("policy-violation"),
            true,
            Arc::new(crate::xmpp::outbound::BoshResponseOwnership::default()),
        ));
    }
    cached.replays += 1;
    Some((
        cached.response.clone(),
        false,
        cached.durable_ownership.clone(),
    ))
}

pub(super) fn bosh_unacknowledged_limit_exceeded(
    replay: &VecDeque<CachedResponse>,
    next_response_bytes: usize,
    now: Instant,
) -> bool {
    replay.len() >= RESPONSE_CACHE_SIZE
        || replay
            .iter()
            .map(|cached| cached.response_bytes)
            .sum::<usize>()
            .saturating_add(next_response_bytes)
            > MAX_UNACKNOWLEDGED_RESPONSE_BYTES
        || replay
            .front()
            .is_some_and(|cached| now.duration_since(cached.owned_at) >= MAX_RESPONSE_ACK_AGE)
}

pub(super) fn bosh_body_element(
    condition: Option<&str>,
    terminate: bool,
    highest_contiguous_received: Option<u64>,
) -> XmlElement {
    let mut body = XmlElement::new("body").attr("xmlns", HTTP_BIND_NS);
    if terminate {
        body = body.attr("type", "terminate");
        if let Some(condition) = condition.filter(|condition| *condition != "terminate") {
            body = body.attr("condition", condition);
            if condition == "remote-stream-error" {
                body = body.attr("xmlns:stream", "http://etherx.jabber.org/streams");
            }
        }
    } else if let Some(highest_contiguous_received) = highest_contiguous_received {
        body = body.attr("ack", highest_contiguous_received);
    }
    body
}

pub(super) fn terminal_response(condition: &str) -> BoshHttpResponse {
    terminal_response_with_content(condition, "text/xml; charset=utf-8")
}

pub(super) fn terminal_response_with_content(
    condition: &str,
    content_type: &str,
) -> BoshHttpResponse {
    BoshHttpResponse {
        body: Bytes::from(bosh_body_element(Some(condition), true, None).finish()),
        content_type: content_type.to_owned(),
    }
}
