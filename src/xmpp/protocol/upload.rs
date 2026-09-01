use super::{Action, ProtocolSession};
use crate::services::upload::{UploadSlotAdmission, UploadSlotRequest};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
use roxmltree::Node;

struct UploadRequest<'a> {
    filename: &'a str,
    content_type: &'a str,
    size: u64,
}

fn parse_upload_request<'input>(
    request: Node<'input, 'input>,
) -> std::result::Result<UploadRequest<'input>, &'static str> {
    if request.attributes().any(|attribute| {
        attribute.namespace().is_some()
            || !matches!(attribute.name(), "filename" | "size" | "content-type")
    }) || request
        .children()
        .any(|child| child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("bad-request");
    }
    // Upload purposes have retention semantics of their own. Northstar does
    // not advertise those optional profiles, so accepting and ignoring one
    // would make a false promise to the client.
    if request.children().any(|child| child.is_element()) {
        return Err("feature-not-implemented");
    }
    let filename = request.attribute("filename").unwrap_or_default();
    let content_type = request
        .attribute("content-type")
        .unwrap_or("application/octet-stream");
    let Some(size) = request
        .attribute("size")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|size| *size > 0)
    else {
        return Err("bad-request");
    };
    if !valid_upload_filename(filename) || !valid_content_type(content_type) {
        return Err("not-acceptable");
    }
    Ok(UploadRequest {
        filename,
        content_type,
        size,
    })
}

fn file_too_large(id: &str, from: &str, maximum: u64) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .attr("from", from)
        .child(
            XmlElement::new("error")
                .attr("type", "modify")
                .child(XmlElement::namespaced(
                    "not-acceptable",
                    "urn:ietf:params:xml:ns:xmpp-stanzas",
                ))
                .child(
                    XmlElement::namespaced("file-too-large", "urn:xmpp:http:upload:0")
                        .child(XmlElement::new("max-file-size").text(maximum.to_string())),
                ),
        )
        .finish()
}

fn upload_slot(put_url: &str, token: &str, get_url: &str) -> String {
    XmlElement::namespaced("slot", "urn:xmpp:http:upload:0")
        .child(
            XmlElement::new("put").attr("url", put_url).child(
                XmlElement::new("header")
                    .attr("name", "Authorization")
                    .text(format!("Bearer {token}")),
            ),
        )
        .child(XmlElement::new("get").attr("url", get_url))
        .finish()
}

impl ProtocolSession {
    pub(crate) fn upload_domain(&self) -> String {
        crate::jid::prepare_domainpart(&format!("upload.{}", self.state.config.domain))
            .expect("configured XMPP domain must form a valid upload service domain")
    }

    pub(crate) async fn http_upload_slot(
        &self,
        id: &str,
        to: Option<&str>,
        request: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let upload_domain = self.upload_domain();
        if !to.is_some_and(|value| {
            crate::jid::CanonicalJid::parse_bare(value).is_ok_and(|target| {
                target.localpart().is_none() && target.domainpart() == upload_domain
            })
        }) {
            return Ok(Action::Send(iq_error(id, "service-unavailable")));
        }
        let upload = match parse_upload_request(request) {
            Ok(upload) => upload,
            Err(condition) => {
                return Ok(Action::Send(iq_error_from(id, &upload_domain, condition)));
            }
        };
        if upload.size > self.state.config.upload_max_bytes {
            return Ok(Action::Send(file_too_large(
                id,
                &upload_domain,
                self.state.config.upload_max_bytes,
            )));
        }
        let (slot_id, token) = match self
            .state
            .upload_service()
            .reserve_slot(UploadSlotRequest {
                user_id: user.id,
                filename: upload.filename,
                content_type: upload.content_type,
                size: upload.size,
                max_files_per_user: self.state.config.upload_max_files_per_user,
                max_bytes_per_user: self.state.config.upload_max_bytes_per_user,
                storage_backend: self.state.upload_store().backend(),
                max_retained_files: self.state.config.upload_storage_max_retained_files,
                max_retained_bytes: self.state.config.upload_storage_max_retained_bytes,
                max_pending_jobs: self.state.config.upload_storage_max_pending_jobs,
            })
            .await?
        {
            UploadSlotAdmission::Reserved { id, bearer_token } => (id, bearer_token),
            UploadSlotAdmission::CapacityExceeded => {
                return Ok(Action::Send(iq_error_from(
                    id,
                    &upload_domain,
                    "resource-constraint",
                )));
            }
        };
        let put_url = format!("{}/api/v1/upload/{}", self.state.config.public_url, slot_id);
        let get_url = format!("{}/uploads/{}", self.state.config.public_url, slot_id);
        let slot = upload_slot(&put_url, &token, &get_url);
        Ok(Action::Send(iq_result_from(id, &upload_domain, &slot)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse(xml: &str) -> std::result::Result<(String, String, u64), &'static str> {
        let document = Document::parse(xml).unwrap();
        parse_upload_request(document.root_element()).map(|request| {
            (
                request.filename.to_owned(),
                request.content_type.to_owned(),
                request.size,
            )
        })
    }

    #[test]
    fn upload_request_is_strict_and_size_is_positive() {
        assert_eq!(
            parse("<request xmlns='urn:xmpp:http:upload:0' filename='cipher.bin' size='12'/>"),
            Ok((
                "cipher.bin".to_owned(),
                "application/octet-stream".to_owned(),
                12,
            ))
        );
        for xml in [
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='0'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='-1'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='1' unknown='x'/>",
            "<request xmlns='urn:xmpp:http:upload:0' xmlns:x='urn:example' filename='a' size='1' x:content-type='text/plain'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='1'>text</request>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a/b' size='1'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='1' content-type=' text/plain'/>",
        ] {
            assert!(parse(xml).is_err(), "{xml}");
        }
        assert_eq!(
            parse(
                "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='1'><profile xmlns='urn:xmpp:http:upload:purpose:0'/></request>"
            ),
            Err("feature-not-implemented")
        );
    }

    #[test]
    fn oversized_error_exposes_the_advertised_limit() {
        let xml = file_too_large("slot-1", "upload.example.test", 25_000_000);
        assert!(xml.contains("<file-too-large xmlns='urn:xmpp:http:upload:0'>"));
        assert!(xml.contains("<max-file-size>25000000</max-file-size>"));
        assert!(xml.contains("from='upload.example.test'"));
    }

    #[test]
    fn upload_slot_escapes_urls_and_authorization_text_structurally() {
        let put = "https://example.test/put?a='&b=<evil>";
        let token = "token<&already-&amp;";
        let get = "https://example.test/get?'&x=1";
        let xml = upload_slot(put, token, get);
        let document = Document::parse(&xml).unwrap();
        let slot = document.root_element();
        let put_element = slot
            .children()
            .find(|child| child.has_tag_name("put"))
            .unwrap();
        let header = put_element
            .children()
            .find(|child| child.has_tag_name("header"))
            .unwrap();
        let get_element = slot
            .children()
            .find(|child| child.has_tag_name("get"))
            .unwrap();
        let expected_authorization = format!("Bearer {token}");
        assert_eq!(put_element.attribute("url"), Some(put));
        assert_eq!(header.text(), Some(expected_authorization.as_str()));
        assert_eq!(get_element.attribute("url"), Some(get));
        assert_eq!(
            slot.descendants()
                .filter(|node| node.has_tag_name("evil"))
                .count(),
            0
        );
    }
}
