use super::{Action, ProtocolSession};
use crate::services::upload::{UploadSlotAdmission, UploadSlotRequestCommand};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::*;
use anyhow::Result;
use roxmltree::Node;

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
                    XmlElement::namespaced("file-too-large", northstar_xep_0363::NAMESPACE)
                        .child(XmlElement::new("max-file-size").text(maximum.to_string())),
                ),
        )
        .finish()
}

impl ProtocolSession {
    pub(crate) fn http_upload_enabled(&self) -> bool {
        self.state.config.upload_mode.admits_new_uploads()
            && self
                .state
                .config
                .xmpp_extensions
                .enabled(northstar_xep_0363::XEP_ID)
    }

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
        let upload = match northstar_xep_0363::parse_request(request) {
            Ok(upload) => upload,
            Err(error) => {
                let condition = match error {
                    northstar_xep_0363::ValidationError::UnsupportedChild => {
                        "feature-not-implemented"
                    }
                    northstar_xep_0363::ValidationError::InvalidMetadata => "not-acceptable",
                    northstar_xep_0363::ValidationError::UnexpectedElement
                    | northstar_xep_0363::ValidationError::MalformedRequest
                    | northstar_xep_0363::ValidationError::InvalidResponseValue => "bad-request",
                };
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
            .execute_upload_slot_reservation(UploadSlotRequestCommand {
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
        let slot = match northstar_xep_0363::build_slot(&put_url, &token, &get_url) {
            Ok(slot) => slot,
            Err(error) => {
                tracing::error!(?error, "refused to build an invalid XEP-0363 upload slot");
                return Ok(Action::Send(iq_error_from(
                    id,
                    &upload_domain,
                    "internal-server-error",
                )));
            }
        };
        Ok(Action::Send(iq_result_from(id, &upload_domain, &slot)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse(xml: &str) -> std::result::Result<(String, String, u64), &'static str> {
        let document = Document::parse(xml).unwrap();
        northstar_xep_0363::parse_request(document.root_element())
            .map_err(|error| match error {
                northstar_xep_0363::ValidationError::UnsupportedChild => "feature-not-implemented",
                northstar_xep_0363::ValidationError::InvalidMetadata => "not-acceptable",
                _ => "bad-request",
            })
            .map(|request| {
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
        let xml = northstar_xep_0363::build_slot(put, token, get).unwrap();
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
