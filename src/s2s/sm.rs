use std::{collections::VecDeque, sync::Arc, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use roxmltree::Document;
use tokio::{
    io::AsyncWrite,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

use crate::{
    db, services::s2s_sm_outbox::SmOutboxClaim, state::AppState, xmpp::xml_builder::XmlElement,
};

use super::{outbound::fail_envelope, write_xml, FederationEnvelope};

pub(crate) const NS: &str = "urn:xmpp:sm:3";
const ACK_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PENDING: usize = 256;

pub(crate) fn feature() -> String {
    XmlElement::new("sm").attr("xmlns", NS).finish()
}

struct Pending {
    durable: Option<db::S2sOutboxItem>,
    deadline: Instant,
    replay: Option<String>,
    _bytes: Option<OwnedSemaphorePermit>,
}

/// Counters and replay bytes belong to the logical stream, across transports.
#[derive(Default)]
pub(crate) struct StreamManagement {
    enabled: bool,
    received: u32,
    acknowledged: u32,
    pending: VecDeque<Pending>,
    budget: Option<Arc<Semaphore>>,
    bytes: usize,
}

impl StreamManagement {
    #[cfg(test)]
    pub(crate) fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    pub(crate) fn with_budget(budget: Arc<Semaphore>) -> Self {
        Self {
            budget: Some(budget),
            ..Self::default()
        }
    }

    pub(crate) fn enable(&mut self) {
        self.enabled = true;
    }
    pub(crate) fn received(&self) -> u32 {
        self.received
    }

    pub(crate) fn owns(&self, envelope: &FederationEnvelope) -> bool {
        self.pending.iter().any(|pending| {
            pending.durable.as_ref().is_some_and(|item| {
                item.id == envelope.outbox_id && item.lock_token == envelope.lock_token
            })
        })
    }

    #[cfg(test)]
    fn can_resume(&self) -> bool {
        self.pending.iter().all(|item| item.replay.is_some())
    }

    pub(crate) fn validate_resume(&self, h: u32, max_bytes: Option<usize>) -> Result<()> {
        let count = self.ack_count(h)?;
        ensure!(
            self.pending.iter().skip(count).all(|item| item
                .replay
                .as_ref()
                .is_some_and(|xml| max_bytes.is_none_or(|limit| xml.len() <= limit))),
            "S2S replay is unavailable or exceeds peer limit"
        );
        Ok(())
    }

    pub(crate) async fn renew(&self, state: &AppState) -> Result<()> {
        // Never revive an expired claim: a different process may already own it.
        let claims: Vec<_> = self
            .pending
            .iter()
            .filter_map(|pending| pending.durable.as_ref())
            .map(|item| SmOutboxClaim {
                id: item.id,
                lock_token: item.lock_token,
            })
            .collect();
        tokio::time::timeout(
            Duration::from_secs(5),
            state
                .s2s_sm_outbox_service()
                .renew_pending(&claims, super::resume::WINDOW.as_secs() + 30),
        )
        .await
        .context("S2S replay lease renewal timed out")?
    }

    pub(crate) async fn acknowledge(&mut self, state: &AppState, h: u32) -> Result<()> {
        let count = self.ack_count(h)?;
        tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..count {
                if let Some(item) = &self.pending.front().expect("validated ack count").durable {
                    state
                        .s2s_sm_outbox_service()
                        .complete_acknowledged(SmOutboxClaim {
                            id: item.id,
                            lock_token: item.lock_token,
                        })
                        .await?;
                }
                let item = self.pending.pop_front().expect("validated ack count");
                self.bytes -= item
                    ._bytes
                    .as_ref()
                    .map_or(0, |permit| permit.num_permits());
                self.acknowledged = self.acknowledged.wrapping_add(1);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("S2S acknowledgement database deadline elapsed")?
    }

    pub(crate) async fn replay<S: AsyncWrite + Unpin>(
        &mut self,
        state: &AppState,
        stream: &mut S,
    ) -> Result<()> {
        self.renew(state).await?;
        tokio::time::timeout(ACK_TIMEOUT, async {
            let _permit = state
                .federation_delivery_permit()
                .await
                .context("federation delivery is disabled by island mode")?;
            for item in &mut self.pending {
                write_xml(
                    stream,
                    item.replay
                        .as_deref()
                        .context("S2S stanza cannot be replayed")?,
                )
                .await?;
                item.deadline = Instant::now() + ACK_TIMEOUT;
            }
            self.request(stream).await
        })
        .await
        .context("S2S replay write deadline elapsed")?
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.pending.front().map_or_else(
            || Instant::now() + Duration::from_secs(86400),
            |item| item.deadline,
        )
    }

    pub(crate) fn track(&mut self, envelope: Option<&FederationEnvelope>, xml: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        ensure!(
            self.pending.len() < MAX_PENDING,
            "S2S acknowledgement window is full"
        );
        ensure!(
            self.deadline() > Instant::now(),
            "S2S acknowledgement timed out"
        );
        // Volatile/no-store stanzas contribute to h but retain no payload.
        let durable = envelope
            .filter(|item| item.is_durable())
            .map(|item| db::S2sOutboxItem {
                id: item.outbox_id,
                lock_token: item.lock_token,
                target_domain: item.target_domain.clone(),
                bounce_to: item.bounce_to.clone(),
                stanza: item.stanza.clone(),
                attempt_count: item.attempt_count,
            });
        let replayable = envelope.is_none_or(|item| item.is_durable())
            && !Document::parse(xml).is_ok_and(|doc| {
                doc.root_element()
                    .children()
                    .any(|node| node.has_tag_name(("urn:xmpp:hints", "no-store")))
            });
        let bytes = if replayable {
            xml.len() + durable.as_ref().map_or(0, |item| item.stanza.len())
        } else {
            0
        };
        let permit = if let Some(budget) = &self.budget {
            ensure!(
                self.bytes + bytes <= 4 * 1024 * 1024,
                "S2S stream replay buffer is full"
            );
            Some(
                budget
                    .clone()
                    .try_acquire_many_owned(bytes.try_into()?)
                    .context("S2S replay memory budget exhausted")?,
            )
        } else {
            None
        };
        self.bytes += permit.as_ref().map_or(0, |permit| permit.num_permits());
        self.pending.push_back(Pending {
            durable,
            deadline: Instant::now() + ACK_TIMEOUT,
            replay: (replayable && self.budget.is_some()).then(|| xml.to_owned()),
            _bytes: permit,
        });
        Ok(())
    }

    pub(crate) async fn request<S: AsyncWrite + Unpin>(&self, stream: &mut S) -> Result<()> {
        if self.enabled {
            write_xml(stream, &XmlElement::new("r").attr("xmlns", NS).finish()).await?;
        }
        Ok(())
    }

    pub(crate) fn handled(&mut self, frame: &str) {
        if self.enabled && is_stanza(frame) {
            self.received = self.received.wrapping_add(1);
        }
    }

    fn ack_count(&self, h: u32) -> Result<usize> {
        let count = h.wrapping_sub(self.acknowledged) as usize;
        ensure!(
            count <= self.pending.len(),
            "S2S peer acknowledged unsent stanzas"
        );
        Ok(count)
    }

    pub(crate) async fn control<S: AsyncWrite + Unpin>(
        &mut self,
        state: &AppState,
        stream: &mut S,
        frame: &str,
        allow_enable: bool,
    ) -> Result<bool> {
        let Some(control) = parse_control(frame)? else {
            return Ok(false);
        };
        match control {
            Control::Enable { .. } if allow_enable && !self.enabled => {
                self.enabled = true;
                write_xml(
                    stream,
                    &XmlElement::new("enabled").attr("xmlns", NS).finish(),
                )
                .await?;
            }
            Control::Resume { .. } if !self.enabled => {
                write_xml(
                    stream,
                    &XmlElement::new("failed")
                        .attr("xmlns", NS)
                        .child(
                            XmlElement::new("item-not-found")
                                .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"),
                        )
                        .finish(),
                )
                .await?;
            }
            Control::Request if self.enabled => {
                write_xml(
                    stream,
                    &XmlElement::new("a")
                        .attr("xmlns", NS)
                        .attr("h", self.received.to_string())
                        .finish(),
                )
                .await?;
            }
            Control::Ack(h) if self.enabled => {
                let count = match self.ack_count(h) {
                    Ok(count) => count,
                    Err(error) => {
                        let sent = self.acknowledged.wrapping_add(self.pending.len() as u32);
                        let error_xml = XmlElement::new("stream:error")
                            .child(
                                XmlElement::new("undefined-condition")
                                    .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-streams"),
                            )
                            .child(
                                XmlElement::new("handled-count-too-high")
                                    .attr("xmlns", NS)
                                    .attr("h", h.to_string())
                                    .attr("send-count", sent.to_string()),
                            )
                            .finish();
                        write_xml(stream, &error_xml).await?;
                        write_xml(stream, &XmlElement::new("stream:stream").close()).await?;
                        return Err(error);
                    }
                };
                ensure!(
                    count == 0 || self.deadline() > Instant::now(),
                    "late S2S acknowledgement"
                );
                self.acknowledge(state, h).await?;
            }
            _ => {
                super::send_stream_error(stream, "unexpected-request").await?;
                bail!("unexpected S2S stream management command");
            }
        }
        Ok(true)
    }

    pub(crate) async fn retry_unacknowledged(&mut self, state: &AppState) {
        let error = anyhow::anyhow!("S2S stream closed before acknowledgement");
        self.bytes = 0;
        while let Some(item) = self.pending.pop_front() {
            if let Some(item) = item.durable {
                fail_envelope(state, &FederationEnvelope::from(item), &error, false).await;
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Control {
    Enable { resume: bool, max: Option<u32> },
    Resume { id: String, h: u32 },
    Request,
    Ack(u32),
    Other,
}

pub(crate) fn parse_control(frame: &str) -> Result<Option<Control>> {
    let Ok(document) = Document::parse(frame) else {
        return Ok(None);
    };
    let root = document.root_element();
    if root.tag_name().namespace() != Some(NS) {
        return Ok(None);
    }
    ensure!(
        !root.children().any(|node| node.is_element()
            || node.is_text() && !node.text().unwrap_or_default().trim().is_empty()),
        "S2S SM command contains content"
    );
    Ok(Some(match root.tag_name().name() {
        "enable" => {
            ensure!(
                root.attributes()
                    .all(|attr| attr.namespace().is_none()
                        && matches!(attr.name(), "resume" | "max")),
                "invalid SM enable attributes"
            );
            let resume = match root.attribute("resume") {
                None | Some("false" | "0") => false,
                Some("true" | "1") => true,
                _ => bail!("invalid SM resume boolean"),
            };
            let max = root.attribute("max").map(counter).transpose()?;
            Control::Enable { resume, max }
        }
        "resume" => {
            ensure!(root.attributes().len() == 2, "invalid SM resume attributes");
            let id = root.attribute("previd").context("missing SM resume id")?;
            ensure!(!id.is_empty() && id.len() <= 4000, "invalid SM resume id");
            Control::Resume {
                id: id.to_owned(),
                h: counter(root.attribute("h").context("missing SM resume counter")?)?,
            }
        }
        "r" if root.attributes().len() == 0 => Control::Request,
        "a" if root.attributes().len() == 1 => {
            let h = root
                .attribute("h")
                .context("S2S acknowledgement is missing h")?;
            ensure!(
                !h.is_empty() && h.bytes().all(|byte| byte.is_ascii_digit()),
                "invalid S2S acknowledgement counter"
            );
            Control::Ack(
                h.parse()
                    .context("S2S acknowledgement counter exceeds u32")?,
            )
        }
        _ => Control::Other,
    }))
}

fn counter(value: &str) -> Result<u32> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid SM counter"
    );
    value.parse().context("SM counter exceeds u32")
}

pub(crate) fn enabled_resume(frame: &str) -> Result<Option<(String, Duration)>> {
    let doc = Document::parse(frame)?;
    let root = doc.root_element();
    ensure!(root.has_tag_name((NS, "enabled")), "expected SM enabled");
    match root.attribute("resume") {
        None | Some("false" | "0") => Ok(None),
        Some("true" | "1") => {
            let id = root.attribute("id").context("resumable SM is missing id")?;
            ensure!(!id.is_empty() && id.len() <= 4000, "invalid SM resume id");
            let max = root
                .attribute("max")
                .map(counter)
                .transpose()?
                .unwrap_or(60)
                .min(60);
            ensure!(max > 0, "SM resume window is zero");
            Ok(Some((id.to_owned(), Duration::from_secs(u64::from(max)))))
        }
        _ => bail!("invalid SM resume boolean"),
    }
}

pub(crate) fn resumed(frame: &str, id: &str) -> Result<u32> {
    let doc = Document::parse(frame)?;
    let root = doc.root_element();
    ensure!(
        root.has_tag_name((NS, "resumed"))
            && root.attribute("previd") == Some(id)
            && root.attributes().len() == 2
            && !root.children().any(|node| node.is_element()
                || node.is_text() && !node.text().unwrap_or_default().trim().is_empty()),
        "S2S resumption rejected or invalid"
    );
    counter(root.attribute("h").context("missing resumed counter")?)
}

pub(crate) async fn failed<S: AsyncWrite + Unpin>(
    stream: &mut S,
    condition: &'static str,
) -> Result<()> {
    write_xml(
        stream,
        &XmlElement::new("failed")
            .attr("xmlns", NS)
            .child(XmlElement::new(condition).attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas"))
            .finish(),
    )
    .await
}

pub(crate) fn is_stanza(frame: &str) -> bool {
    Document::parse(frame).is_ok_and(|document| {
        let root = document.root_element();
        matches!(root.tag_name().name(), "message" | "presence" | "iq")
            && matches!(root.tag_name().namespace(), None | Some("jabber:server"))
    })
}

pub(crate) fn advertised(features: &str) -> bool {
    let opening = XmlElement::new("root")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .open();
    let closing = XmlElement::new("root").close();
    let wrapped = format!("{opening}{features}{closing}");
    Document::parse(&wrapped).is_ok_and(|document| {
        document
            .root_element()
            .first_element_child()
            .is_some_and(|features| {
                features
                    .children()
                    .any(|node| node.has_tag_name((NS, "sm")))
            })
    })
}

pub(crate) fn accepted(frame: &str) -> bool {
    Document::parse(frame).is_ok_and(|document| {
        let root = document.root_element();
        root.has_tag_name((NS, "enabled"))
            && !root.children().any(|node| {
                node.is_element()
                    || node.is_text() && !node.text().unwrap_or_default().trim().is_empty()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_is_bounded_and_does_not_retain_volatile_payloads() {
        let budget = Arc::new(Semaphore::new(32));
        let mut sm = StreamManagement::with_budget(budget.clone());
        sm.enable();
        sm.track(None, "<iq id='one'/>").unwrap();
        assert!(sm.can_resume());
        assert!(sm.validate_resume(0, Some(2)).is_err());
        assert!(sm.validate_resume(1, Some(2)).is_ok());
        assert!(sm.track(None, &"x".repeat(32)).is_err());
        assert_eq!(sm.pending.len(), 1);
        let (volatile, _receipt) = FederationEnvelope::volatile(
            "remote.example".into(),
            "<presence/>".into(),
            Instant::now() + Duration::from_secs(5),
        );
        sm.track(Some(&volatile), "<presence/>").unwrap();
        assert!(!sm.can_resume());
        assert!(sm.pending.back().unwrap().replay.is_none());
        assert!(sm.validate_resume(1, None).is_err());
        assert!(sm.validate_resume(2, None).is_ok());
        drop(sm);
        assert_eq!(budget.available_permits(), 32);
    }

    #[test]
    fn resume_negotiation_rejects_malformed_identity_and_counters() {
        for frame in [
            "<resume xmlns='urn:xmpp:sm:3' previd='' h='0'/>",
            "<resume xmlns='urn:xmpp:sm:3' previd='id' h='-1'/>",
            "<resume xmlns='urn:xmpp:sm:3' previd='id' h='4294967296'/>",
            "<enable xmlns='urn:xmpp:sm:3' resume='yes'/>",
            "<enable xmlns='urn:xmpp:sm:3' resume='true' max='-1'/>",
        ] {
            assert!(parse_control(frame).is_err(), "{frame}");
        }
        assert!(enabled_resume("<enabled xmlns='urn:xmpp:sm:3' resume='true'/>").is_err());
        assert!(
            enabled_resume("<enabled xmlns='urn:xmpp:sm:3' resume='true' id='id' max='0'/>")
                .is_err()
        );
        assert_eq!(
            enabled_resume("<enabled xmlns='urn:xmpp:sm:3' resume='1' id='id' max='900'/>")
                .unwrap(),
            Some(("id".into(), Duration::from_secs(60)))
        );
        assert!(resumed(
            "<resumed xmlns='urn:xmpp:sm:3' previd='other' h='0'/>",
            "id"
        )
        .is_err());
        assert!(resumed(
            "<resumed xmlns='urn:xmpp:sm:3' previd='id' h='0'><r/></resumed>",
            "id"
        )
        .is_err());
    }

    #[test]
    fn counters_wrap_and_never_ack_unsent_stanzas() {
        let mut sm = StreamManagement::enabled();
        sm.acknowledged = u32::MAX - 1;
        sm.track(None, "<iq/>").unwrap();
        sm.track(None, "<iq/>").unwrap();
        assert_eq!(sm.ack_count(0).unwrap(), 2);
        assert!(sm.ack_count(1).is_err());
        assert!(sm.ack_count(u32::MAX - 2).is_err());
        sm.received = u32::MAX;
        sm.handled("<message xmlns='jabber:server'/>");
        assert_eq!(sm.received, 0);
        sm.handled("<r xmlns='urn:xmpp:sm:3'/>");
        sm.handled("<message xmlns='urn:untrusted'/>");
        assert_eq!(sm.received, 0);
    }

    #[test]
    fn ack_syntax_and_capacity_are_bounded() {
        for frame in [
            "<a xmlns='urn:xmpp:sm:3'/>",
            "<a xmlns='urn:xmpp:sm:3' h='-1'/>",
            "<a xmlns='urn:xmpp:sm:3' h='4294967296'/>",
            "<a xmlns='urn:xmpp:sm:3' h='1'><message/></a>",
        ] {
            assert!(
                parse_control(frame).is_err()
                    || matches!(parse_control(frame), Ok(Some(Control::Other)))
            );
        }
        assert_eq!(parse_control("<a xmlns='urn:other' h='2'/>").unwrap(), None);
        let mut sm = StreamManagement::enabled();
        for _ in 0..MAX_PENDING {
            sm.track(None, "<iq/>").unwrap();
        }
        assert!(sm.track(None, "<iq/>").is_err());
        assert!(sm.pending.iter().all(|item| item.durable.is_none()));
        sm.pending.front_mut().unwrap().deadline = Instant::now();
        assert!(sm.deadline() <= Instant::now());
        assert!(advertised(
            "<stream:features><sm xmlns='urn:xmpp:sm:3'/></stream:features>"
        ));
        assert!(!advertised(
            "<stream:features><sm xmlns='urn:other'/></stream:features>"
        ));
    }
}
