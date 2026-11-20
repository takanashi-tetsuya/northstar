//! MAM queries against MIX channel archives.

use super::*;
use northstar_room_application::mix_service::{
    ArchiveBoundary, MamArchiveQuery, MixEvent, MixMamPage, MixMamReadActor, MixMamReadCommand,
    MixMamReadOperation, MixMamReadOutcome, MixMamReadResult, MixMamReadTarget,
};

pub(super) fn is_mix_mam_request(request: &OwnedIq) -> bool {
    matches!(
        request.operation,
        IqOperation::Mam(_)
            | IqOperation::MamForm
            | IqOperation::MamMetadata
            | IqOperation::MamError(_)
    )
}

pub(super) struct MixMamReply<'a> {
    pub(super) request: &'a OwnedIq,
    pub(super) addressed: &'a str,
    pub(super) reply_to: &'a str,
}

impl MixMamReply<'_> {
    pub(super) fn command(
        &self,
        host: &impl MixHost,
        actor: MixMamReadActor,
    ) -> std::result::Result<MixMamReadCommand, String> {
        if !host.xmpp_extension_enabled(northstar_xep_0313::XEP_ID) {
            return Err(self.error(self.addressed, "cancel", "feature-not-implemented"));
        }
        let target = CanonicalJid::parse_bare(self.addressed)
            .map_err(|_| self.error(self.addressed, "modify", "jid-malformed"))?;
        let Some(localpart) = target.localpart() else {
            return Err(self.error(self.addressed, "cancel", "service-unavailable"));
        };
        if target.domainpart() != local_mix_domain(host.local_domain()) {
            return Err(self.error(self.addressed, "cancel", "item-not-found"));
        }
        let operation = match &self.request.operation {
            IqOperation::Mam(parsed) => {
                MixMamReadOperation::Query(MamArchiveQuery::from(parsed.query.clone()))
            }
            IqOperation::MamMetadata => MixMamReadOperation::Metadata,
            IqOperation::MamForm | IqOperation::MamError(_) => MixMamReadOperation::Form,
            _ => unreachable!("MIX MAM dispatcher received a non-MAM operation"),
        };
        Ok(MixMamReadCommand {
            target: MixMamReadTarget {
                service_domain: target.domainpart().to_owned(),
                localpart: localpart.to_owned(),
            },
            actor,
            operation,
        })
    }

    pub(super) fn render(&self, outcome: MixMamReadOutcome) -> Result<Vec<String>> {
        let (channel_jid, result) = match outcome {
            MixMamReadOutcome::MissingChannel => {
                return Ok(vec![self.error(self.addressed, "cancel", "item-not-found")]);
            }
            MixMamReadOutcome::NotAuthorized { channel_jid } => {
                return Ok(vec![self.error(&channel_jid, "auth", "forbidden")]);
            }
            MixMamReadOutcome::StaleAccount => {
                return Ok(vec![self.error(self.addressed, "auth", "not-authorized")]);
            }
            MixMamReadOutcome::Authorized {
                channel_jid,
                result,
            } => (channel_jid, result),
        };
        if let IqOperation::MamError(condition) = &self.request.operation {
            return Ok(vec![self.error(
                &channel_jid,
                stanza_error_type(condition),
                condition,
            )]);
        }
        let response = match result {
            MixMamReadResult::Form => self.result(&channel_jid, mam_extended_form()),
            MixMamReadResult::Boundaries(first, last) => {
                self.result(&channel_jid, &render_metadata(first, last)?)
            }
            MixMamReadResult::Page(page) => {
                return render_page(self.request, &channel_jid, self.reply_to, &page);
            }
            MixMamReadResult::MissingReference => {
                self.error(&channel_jid, "cancel", "item-not-found")
            }
        };
        Ok(vec![response])
    }

    fn error(&self, from: &str, error_type: &str, condition: &str) -> String {
        iq_error_to(&self.request.id, from, self.reply_to, error_type, condition)
    }

    fn result(&self, from: &str, payload: &str) -> String {
        iq_result_to(&self.request.id, from, self.reply_to, payload)
    }
}

fn render_metadata(
    first: Option<ArchiveBoundary>,
    last: Option<ArchiveBoundary>,
) -> Result<String> {
    let mut metadata = XmlElement::namespaced("metadata", MAM_NS);
    for (name, boundary) in [("start", first), ("end", last)] {
        if let Some(boundary) = boundary {
            metadata.push_child(
                XmlElement::dynamic(name)?.attr("id", boundary.id).attr(
                    "timestamp",
                    boundary
                        .created_at
                        .to_rfc3339_opts(northstar_time::SecondsFormat::Millis, true),
                ),
            );
        }
    }
    Ok(metadata.finish())
}

fn render_page(
    request: &OwnedIq,
    channel_jid: &str,
    reply_to: &str,
    page: &MixMamPage,
) -> Result<Vec<String>> {
    let IqOperation::Mam(parsed) = &request.operation else {
        unreachable!("MIX MAM page requires a parsed query");
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
                    .to_rfc3339_opts(northstar_time::SecondsFormat::Millis, true),
            ),
        );
        forwarded.push_validated_fragment(&event.payload)?;
        let result = XmlElement::namespaced("result", MAM_NS)
            .attr("id", event.id)
            .optional_attr("queryid", parsed.query_id.as_deref())
            .child(forwarded);
        replies.push(
            XmlElement::namespaced("message", "jabber:client")
                .attr("from", channel_jid)
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
        channel_jid,
        reply_to,
        &fin.finish(),
    ));
    Ok(replies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_query_form_and_metadata_are_masked_by_authority() {
        let addressed = "channel@mix.local.test";
        let reply_to = "alice@example.test/device";
        for (kind, element, malformed, success) in [
            (
                "set",
                "query",
                "<query xmlns='urn:xmpp:mam:2' extra='bad'/>",
                "fin",
            ),
            (
                "get",
                "query",
                "<query xmlns='urn:xmpp:mam:2' queryid='bad'/>",
                "query",
            ),
            (
                "get",
                "metadata",
                "<metadata xmlns='urn:xmpp:mam:2'><unexpected/></metadata>",
                "metadata",
            ),
            ("set", "query", "<metadata xmlns='urn:xmpp:mam:2'/>", "fin"),
        ] {
            for (payload, valid) in [
                (format!("<{element} xmlns='{MAM_NS}'/>"), true),
                (malformed.to_owned(), false),
            ] {
                let raw = format!("<iq id='r' type='{kind}' to='{addressed}'>{payload}</iq>");
                let request = parse_iq(&raw).unwrap().unwrap();
                assert!(is_mix_mam_request(&request));
                assert_eq!(
                    matches!(request.operation, IqOperation::MamError("bad-request")),
                    !valid
                );
                let reply = MixMamReply {
                    request: &request,
                    addressed,
                    reply_to,
                };
                for (outcome, error_type, condition) in [
                    (
                        MixMamReadOutcome::MissingChannel,
                        "cancel",
                        "item-not-found",
                    ),
                    (
                        MixMamReadOutcome::NotAuthorized {
                            channel_jid: addressed.into(),
                        },
                        "auth",
                        "forbidden",
                    ),
                    (MixMamReadOutcome::StaleAccount, "auth", "not-authorized"),
                ] {
                    assert_eq!(
                        reply.render(outcome).unwrap(),
                        vec![iq_error_to("r", addressed, reply_to, error_type, condition)]
                    );
                }
                let result = match &request.operation {
                    IqOperation::Mam(_) => MixMamReadResult::Page(MixMamPage {
                        events: vec![],
                        total: 0,
                        first_index: 0,
                        complete: true,
                    }),
                    IqOperation::MamMetadata => MixMamReadResult::Boundaries(None, None),
                    _ => MixMamReadResult::Form,
                };
                let responses = reply
                    .render(MixMamReadOutcome::Authorized {
                        channel_jid: addressed.into(),
                        result,
                    })
                    .unwrap();
                if valid {
                    let document = Document::parse(&responses[0]).unwrap();
                    let iq = document.root_element();
                    assert_eq!(iq.attribute("type"), Some("result"));
                    assert_eq!(iq.first_element_child().unwrap().tag_name().name(), success);
                } else {
                    assert_eq!(
                        responses,
                        vec![iq_error_to(
                            "r",
                            addressed,
                            reply_to,
                            "modify",
                            "bad-request"
                        )]
                    );
                }
            }
        }
    }
}
