//! XEP-0198 wire forms of a server-to-server stream.

use anyhow::{bail, ensure, Context, Result};
use northstar_xml_builder::XmlElement;
use roxmltree::Document;
use std::time::Duration;

pub const NS: &str = "urn:xmpp:sm:3";

pub fn feature() -> String {
    XmlElement::new("sm").attr("xmlns", NS).finish()
}

#[derive(Debug, Eq, PartialEq)]
pub enum Control {
    Enable { resume: bool, max: Option<u32> },
    Resume { id: String, h: u32 },
    Request,
    Ack(u32),
    Other,
}

pub fn parse_control(frame: &str) -> Result<Option<Control>> {
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

pub fn enabled_resume(frame: &str) -> Result<Option<(String, Duration)>> {
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

pub fn resumed(frame: &str, id: &str) -> Result<u32> {
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

pub fn is_stanza(frame: &str) -> bool {
    Document::parse(frame).is_ok_and(|document| {
        let root = document.root_element();
        matches!(root.tag_name().name(), "message" | "presence" | "iq")
            && matches!(root.tag_name().namespace(), None | Some("jabber:server"))
    })
}

pub fn advertised(features: &str) -> bool {
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

pub fn accepted(frame: &str) -> bool {
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
}
