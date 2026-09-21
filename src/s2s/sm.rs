use std::{collections::VecDeque, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use roxmltree::Document;
use tokio::{io::AsyncWrite, time::Instant};

use crate::{db, state::AppState, xmpp::xml_builder::XmlElement};

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
}

/// S2S acknowledgements are connection-scoped. Until resumable federation
/// state has its own durable ownership fence, we never grant a resume ID.
#[derive(Default)]
pub(crate) struct StreamManagement {
    enabled: bool,
    received: u32,
    acknowledged: u32,
    pending: VecDeque<Pending>,
}

impl StreamManagement {
    pub(crate) fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
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

    pub(crate) fn track(&mut self, envelope: Option<&FederationEnvelope>) -> Result<()> {
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
        self.pending.push_back(Pending {
            durable,
            deadline: Instant::now() + ACK_TIMEOUT,
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
            Control::Enable if allow_enable && !self.enabled => {
                self.enabled = true;
                write_xml(
                    stream,
                    &XmlElement::new("enabled").attr("xmlns", NS).finish(),
                )
                .await?;
            }
            Control::Resume if !self.enabled => {
                write_xml(
                    stream,
                    &XmlElement::new("failed")
                        .attr("xmlns", NS)
                        .child(
                            XmlElement::new("feature-not-implemented")
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
                for _ in 0..count {
                    if let Some(item) = &self.pending.front().expect("validated ack count").durable
                    {
                        let completed = tokio::time::timeout(
                            Duration::from_secs(5),
                            db::complete_s2s_outbox(&state.pool, item.id, item.lock_token),
                        )
                        .await
                        .context("S2S acknowledgement database deadline elapsed")??;
                        ensure!(
                            completed,
                            "S2S outbox lease was lost before acknowledgement"
                        );
                    }
                    self.pending.pop_front();
                    self.acknowledged = self.acknowledged.wrapping_add(1);
                }
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
        while let Some(item) = self.pending.pop_front() {
            if let Some(item) = item.durable {
                fail_envelope(state, &FederationEnvelope::from(item), &error, false).await;
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Control {
    Enable,
    Resume,
    Request,
    Ack(u32),
    Other,
}

fn parse_control(frame: &str) -> Result<Option<Control>> {
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
        "enable" => Control::Enable,
        "resume" => Control::Resume,
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
        root.has_tag_name((NS, "enabled")) && !root.children().any(|node| node.is_element())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_wrap_and_never_ack_unsent_stanzas() {
        let mut sm = StreamManagement::enabled();
        sm.acknowledged = u32::MAX - 1;
        sm.track(None).unwrap();
        sm.track(None).unwrap();
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
            sm.track(None).unwrap();
        }
        assert!(sm.track(None).is_err());
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
