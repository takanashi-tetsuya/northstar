use anyhow::{bail, Result};

const MAX_XML_DEPTH: usize = 256;

/// Removes and returns one complete top-level XML element from an XMPP stream.
///
/// XMPP is an XML stream rather than a sequence of complete XML documents. The
/// opening `stream:stream` tag therefore has to be emitted on its own, while
/// normal stanzas are delimited by balanced XML elements. This scanner tracks
/// element depth and quoted markup instead of looking for the first textual
/// closing tag, which is unsafe for forwarded, carbon-copied and MAM stanzas
/// that can contain another `<message>` element.
pub fn take_frame(buffer: &mut String) -> Result<Option<String>> {
    loop {
        let trimmed = buffer.trim_start();
        if trimmed.len() != buffer.len() {
            buffer.drain(..buffer.len() - trimmed.len());
        }
        if buffer.is_empty() {
            return Ok(None);
        }
        if buffer.starts_with("<?xml") {
            let Some(end) = buffer.find("?>") else {
                return Ok(None);
            };
            buffer.drain(..end + 2);
            continue;
        }
        break;
    }

    if !buffer.starts_with('<') {
        bail!("unexpected non-XML data before XMPP frame");
    }

    if starts_with_element_name(buffer, 1, "stream:stream") {
        let Some(end) = find_tag_end(buffer, 0)? else {
            return Ok(None);
        };
        if is_self_closing(buffer, end) {
            bail!("XMPP stream opening tag must not be self-closing");
        }
        return Ok(Some(buffer.drain(..=end).collect()));
    }
    if buffer.starts_with("</") && starts_with_element_name(buffer, 2, "stream:stream") {
        let Some(end) = find_tag_end(buffer, 0)? else {
            return Ok(None);
        };
        let trailing = &buffer[2 + "stream:stream".len()..end];
        if !trailing.trim().is_empty() {
            bail!("XMPP stream closing tag must not contain attributes");
        }
        return Ok(Some(buffer.drain(..=end).collect()));
    }

    let mut cursor = 0;
    let mut elements = Vec::<String>::new();
    let mut root_started = false;

    while cursor < buffer.len() {
        let Some(relative) = buffer.as_bytes()[cursor..]
            .iter()
            .position(|byte| *byte == b'<')
        else {
            return Ok(None);
        };
        let start = cursor + relative;
        if !root_started && !buffer[cursor..start].trim().is_empty() {
            bail!("unexpected text before XMPP stanza");
        }

        if buffer[start..].starts_with("<!--") {
            let Some(relative_end) = buffer[start + 4..].find("-->") else {
                return Ok(None);
            };
            cursor = start + 4 + relative_end + 3;
            continue;
        }
        if buffer[start..].starts_with("<![CDATA[") {
            if !root_started {
                bail!("CDATA is not allowed outside an XMPP stanza");
            }
            let Some(relative_end) = buffer[start + 9..].find("]]>") else {
                return Ok(None);
            };
            cursor = start + 9 + relative_end + 3;
            continue;
        }
        if buffer[start..].starts_with("<?") {
            let Some(relative_end) = buffer[start + 2..].find("?>") else {
                return Ok(None);
            };
            cursor = start + 2 + relative_end + 2;
            continue;
        }
        if buffer[start..].starts_with("<!") {
            let remainder = &buffer[start..];
            if "<!--".starts_with(remainder) || "<![CDATA[".starts_with(remainder) {
                return Ok(None);
            }
            bail!("XML declarations and DTDs are not allowed in XMPP streams");
        }

        let Some(end) = find_tag_end(buffer, start)? else {
            return Ok(None);
        };
        if buffer[start..].starts_with("</") {
            if elements.is_empty() {
                bail!("unexpected XML closing tag");
            }
            let name = element_name(buffer, start + 2, end)?;
            let expected = elements.pop().expect("element stack was checked");
            if name != expected {
                bail!("mismatched XML closing tag: expected </{expected}>, found </{name}>");
            }
            cursor = end + 1;
            if elements.is_empty() {
                return Ok(Some(buffer.drain(..cursor).collect()));
            }
            continue;
        }

        let name = element_name(buffer, start + 1, end)?.to_owned();
        root_started = true;
        cursor = end + 1;
        if is_self_closing(buffer, end) {
            if elements.is_empty() {
                return Ok(Some(buffer.drain(..cursor).collect()));
            }
        } else {
            elements.push(name);
            if elements.len() > MAX_XML_DEPTH {
                bail!("XMPP XML nesting exceeds {MAX_XML_DEPTH} elements");
            }
        }
    }

    Ok(None)
}

fn starts_with_element_name(xml: &str, name_start: usize, expected: &str) -> bool {
    let Some(remainder) = xml.get(name_start..) else {
        return false;
    };
    let Some(after) = remainder.strip_prefix(expected) else {
        return false;
    };
    after
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'>'))
}

fn find_tag_end(xml: &str, start: usize) -> Result<Option<usize>> {
    let mut quote = None;
    for (offset, byte) in xml.as_bytes()[start + 1..].iter().copied().enumerate() {
        let index = start + 1 + offset;
        match quote {
            Some(delimiter) if byte == delimiter => quote = None,
            Some(_) => {}
            None if matches!(byte, b'\'' | b'"') => quote = Some(byte),
            None if byte == b'>' => return Ok(Some(index)),
            None if byte == b'<' => bail!("unexpected '<' inside XML tag"),
            None => {}
        }
    }
    Ok(None)
}

fn element_name(xml: &str, start: usize, tag_end: usize) -> Result<&str> {
    let end = xml.as_bytes()[start..tag_end]
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'>'))
        .map(|offset| start + offset)
        .unwrap_or(tag_end);
    if start == end {
        bail!("XML element name is empty");
    }
    Ok(&xml[start..end])
}

fn is_self_closing(xml: &str, tag_end: usize) -> bool {
    xml.as_bytes()[..tag_end]
        .iter()
        .rev()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_stream_and_stanzas() {
        let mut data =
            "<stream:stream to='localhost'><message to='a@localhost'><body>hi</body></message>"
                .to_owned();
        assert!(take_frame(&mut data)
            .unwrap()
            .unwrap()
            .starts_with("<stream:stream"));
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<message to='a@localhost'><body>hi</body></message>"
        );
    }

    #[test]
    fn keeps_nested_stanzas_in_the_outer_frame() {
        let outer = "<message id='outer'><result xmlns='urn:xmpp:mam:2'><forwarded xmlns='urn:xmpp:forward:0'><message id='inner'><body>stored</body></message></forwarded></result></message>";
        let mut data = format!("{outer}<presence/>");
        assert_eq!(take_frame(&mut data).unwrap().unwrap(), outer);
        assert_eq!(take_frame(&mut data).unwrap().unwrap(), "<presence/>");
    }

    #[test]
    fn ignores_markup_in_attributes_comments_and_cdata() {
        let stanza = "<message data='</message> and >'><!-- </message> --><body><![CDATA[</message>]]></body></message>";
        let mut data = stanza.to_owned();
        assert_eq!(take_frame(&mut data).unwrap().unwrap(), stanza);
    }

    #[test]
    fn waits_for_fragmented_tags_and_utf8_text() {
        let mut data = "<message><body>消".to_owned();
        assert!(take_frame(&mut data).unwrap().is_none());
        data.push_str("息</body></message>");
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<message><body>消息</body></message>"
        );
    }

    #[test]
    fn tag_end_respects_quoted_greater_than_characters() {
        let mut data = "<stream:stream to='a>b'><iq id=\"one>two\"/>".to_owned();
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<stream:stream to='a>b'>"
        );
        assert_eq!(
            take_frame(&mut data).unwrap().unwrap(),
            "<iq id=\"one>two\"/>"
        );
    }

    #[test]
    fn rejects_dtds_and_mismatched_elements() {
        let mut dtd = "<!DOCTYPE message><message/>".to_owned();
        assert!(take_frame(&mut dtd)
            .unwrap_err()
            .to_string()
            .contains("DTDs"));

        let mut mismatched = "<message><body></message></body>".to_owned();
        assert!(take_frame(&mut mismatched)
            .unwrap_err()
            .to_string()
            .contains("mismatched"));
    }

    #[test]
    fn rejects_excessive_nesting_and_malformed_stream_close() {
        let mut nested = "<x>".repeat(MAX_XML_DEPTH + 1);
        nested.push_str(&"</x>".repeat(MAX_XML_DEPTH + 1));
        assert!(take_frame(&mut nested)
            .unwrap_err()
            .to_string()
            .contains("nesting"));

        let mut close = "</stream:stream bogus='true'>".to_owned();
        assert!(take_frame(&mut close)
            .unwrap_err()
            .to_string()
            .contains("must not contain attributes"));
    }

    #[test]
    fn compatibility_corpus_survives_every_utf8_fragment_boundary() {
        let corpus = [
            "<message xmlns='jabber:client' id='carbon'><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client' id='inner'><body>carbon</body></message></forwarded></sent></message>",
            "<message xmlns='jabber:client' id='mam'><result xmlns='urn:xmpp:mam:2'><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' stamp='2026-08-22T00:00:00Z'/><message xmlns='jabber:client'><encrypted xmlns='urn:xmpp:omemo:2'><payload>密文</payload></encrypted></message></forwarded></result></message>",
            "<iq xmlns='jabber:client' type='set' id='pep'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:bundles'><item id='42'><bundle xmlns='urn:xmpp:omemo:2'><prekeys><pk id='1'>AA==</pk></prekeys></bundle></item></publish></pubsub></iq>",
            "<presence xmlns='jabber:client' data='a>b'><x xmlns='http://jabber.org/protocol/muc#user'><!-- occupant --><item jid='用户@example.test/device'/></x></presence>",
        ];
        for stanza in corpus {
            for split in stanza
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(stanza.len()))
            {
                let mut buffer = stanza[..split].to_owned();
                let first = take_frame(&mut buffer).unwrap();
                if split == stanza.len() {
                    assert_eq!(first.as_deref(), Some(stanza));
                    continue;
                }
                assert!(
                    first.is_none(),
                    "frame completed before split {split}: {stanza}"
                );
                buffer.push_str(&stanza[split..]);
                assert_eq!(take_frame(&mut buffer).unwrap().as_deref(), Some(stanza));
                assert!(buffer.is_empty());
            }
        }
    }
}
