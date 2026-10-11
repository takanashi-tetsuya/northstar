//! MAM queries against MIX channel archives.

use super::*;

pub(super) async fn handle_mix_mam_iq(
    state: &Arc<AppState>,
    request: &OwnedIq,
    actor: &str,
    addressed: &str,
    reply_to: &str,
) -> Result<Vec<String>> {
    if !state.xmpp_extension_enabled(northstar_xep_0313::XEP_ID) {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "feature-not-implemented",
        )]);
    }
    let target = match CanonicalJid::parse_bare(addressed) {
        Ok(target) => target,
        Err(_) => {
            return Ok(vec![iq_error_to(
                &request.id,
                addressed,
                reply_to,
                "modify",
                "jid-malformed",
            )]);
        }
    };
    let mix_domain = local_mix_domain(state);
    let Some(localpart) = target.localpart() else {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "service-unavailable",
        )]);
    };
    let viewer_id = match CanonicalJid::parse_bare(actor) {
        Ok(viewer) if same_jid_domain(viewer.domainpart(), state.local_domain()) => {
            match viewer.localpart() {
                Some(username) => state
                    .mix_service()
                    .find_enabled_user(username)
                    .await?
                    .map(|user| user.id),
                None => None,
            }
        }
        _ => None,
    };
    if target.domainpart() != mix_domain {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "item-not-found",
        )]);
    }
    let Some(channel) = state
        .mix_service()
        .mix_channel(target.domainpart(), localpart)
        .await?
    else {
        return Ok(vec![iq_error_to(
            &request.id,
            addressed,
            reply_to,
            "cancel",
            "item-not-found",
        )]);
    };
    if let IqOperation::MamError(condition) = &request.operation {
        return Ok(vec![iq_error_to(
            &request.id,
            &channel.jid(),
            reply_to,
            stanza_error_type(condition),
            condition,
        )]);
    }
    match &request.operation {
        IqOperation::MamForm => {
            if !matches!(
                state
                    .mix_service()
                    .authorized_mix_mam_boundaries(channel.id, actor, viewer_id)
                    .await?,
                MixReadOutcome::Found(_)
            ) {
                return Ok(vec![iq_error_to(
                    &request.id,
                    &channel.jid(),
                    reply_to,
                    "auth",
                    "forbidden",
                )]);
            }
            return Ok(vec![iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                mam_extended_form(),
            )]);
        }
        IqOperation::MamMetadata => {
            let (first, last) = match state
                .mix_service()
                .authorized_mix_mam_boundaries(channel.id, actor, viewer_id)
                .await?
            {
                MixReadOutcome::Found(boundaries) => boundaries,
                MixReadOutcome::Unauthorized | MixReadOutcome::NotFound => {
                    return Ok(vec![iq_error_to(
                        &request.id,
                        &channel.jid(),
                        reply_to,
                        "auth",
                        "forbidden",
                    )]);
                }
            };
            let boundary = |name: &str, value: Option<ArchiveBoundary>| -> Result<_> {
                value
                    .map(|value| {
                        Ok(XmlElement::dynamic(name)?.attr("id", value.id).attr(
                            "timestamp",
                            value
                                .created_at
                                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        ))
                    })
                    .transpose()
            };
            let mut metadata = XmlElement::namespaced("metadata", MAM_NS);
            if let Some(start) = boundary("start", first)? {
                metadata.push_child(start);
            }
            if let Some(end) = boundary("end", last)? {
                metadata.push_child(end);
            }
            return Ok(vec![iq_result_to(
                &request.id,
                &channel.jid(),
                reply_to,
                &metadata.finish(),
            )]);
        }
        IqOperation::Mam(_) => {}
        _ => unreachable!("MIX MAM dispatcher received a non-MAM operation"),
    }

    let IqOperation::Mam(parsed) = &request.operation else {
        unreachable!();
    };
    // The MAM protocol parser produces the service-owned query; translate it
    // once so both paging variants share the identical authorized snapshot.
    let query = MamArchiveQuery::from(parsed.query.clone());
    // The repository checks peer-filter visibility with channel authorization
    // in the same snapshot that selects the page.
    let page = match state
        .mix_service()
        .authorized_mix_mam_page(channel.id, actor, viewer_id, &query)
        .await?
    {
        MixReadOutcome::Found(page) => page,
        MixReadOutcome::Unauthorized => {
            return Ok(vec![iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "auth",
                "forbidden",
            )]);
        }
        MixReadOutcome::NotFound => {
            return Ok(vec![iq_error_to(
                &request.id,
                &channel.jid(),
                reply_to,
                "cancel",
                "item-not-found",
            )]);
        }
    };
    let mut replies = Vec::with_capacity(page.events.len() + 1);
    let events: Box<dyn Iterator<Item = &MixEvent>> = if parsed.flip_page {
        Box::new(page.events.iter().rev())
    } else {
        Box::new(page.events.iter())
    };
    for event in events {
        let mut forwarded = XmlElement::namespaced("forwarded", "urn:xmpp:forward:0").child(
            XmlElement::namespaced("delay", "urn:xmpp:delay").attr(
                "stamp",
                event
                    .created_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ),
        );
        forwarded.push_validated_fragment(&event.payload)?;
        let result = XmlElement::namespaced("result", MAM_NS)
            .attr("id", event.id)
            .optional_attr("queryid", parsed.query_id.as_deref())
            .child(forwarded);
        replies.push(
            XmlElement::namespaced("message", "jabber:client")
                .attr("from", channel.jid())
                .attr("to", reply_to)
                .attr("id", Uuid::new_v4())
                .child(result)
                .finish(),
        );
    }
    let mut rsm_page = XmlElement::namespaced("set", "http://jabber.org/protocol/rsm");
    if let (Some(first), Some(last)) = (page.events.first(), page.events.last()) {
        rsm_page.push_child(
            XmlElement::new("first")
                .attr("index", page.first_index)
                .text(first.id.to_string()),
        );
        rsm_page.push_child(XmlElement::new("last").text(last.id.to_string()));
    }
    rsm_page.push_child(XmlElement::new("count").text(page.total.to_string()));
    let fin = XmlElement::namespaced("fin", MAM_NS)
        .attr("complete", page.complete)
        .attr("stable", "true")
        .child(rsm_page);
    replies.push(iq_result_to(
        &request.id,
        &channel.jid(),
        reply_to,
        &fin.finish(),
    ));
    Ok(replies)
}
