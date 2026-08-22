use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    auth, db,
    state::{attr_escape, bare_jid, xml_escape},
};
use anyhow::Result;
use roxmltree::Node;

impl ProtocolSession {
    pub(crate) fn upload_domain(&self) -> String {
        format!("upload.{}", self.state.config.domain).to_ascii_lowercase()
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
        if !to.is_some_and(|value| bare_jid(value).eq_ignore_ascii_case(&upload_domain)) {
            return Ok(Action::Send(iq_error(id, "service-unavailable")));
        }
        let filename = request.attribute("filename").unwrap_or_default().trim();
        let content_type = request
            .attribute("content-type")
            .unwrap_or("application/octet-stream")
            .trim();
        let Some(size) = request
            .attribute("size")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return Ok(Action::Send(iq_error_from(
                id,
                &upload_domain,
                "bad-request",
            )));
        };
        if !valid_upload_filename(filename)
            || !valid_content_type(content_type)
            || size > self.state.config.upload_max_bytes
        {
            return Ok(Action::Send(iq_error_from(
                id,
                &upload_domain,
                "not-acceptable",
            )));
        }
        let token = auth::new_session_token();
        let slot_id = db::create_upload_slot(
            &self.state.pool,
            user.id,
            filename,
            content_type,
            size as i64,
            &auth::token_hash(&token),
        )
        .await?;
        let put_url = format!("{}/api/v1/upload/{}", self.state.config.public_url, slot_id);
        let get_url = format!("{}/uploads/{}", self.state.config.public_url, slot_id);
        let slot = format!(
                "<slot xmlns='urn:xmpp:http:upload:0'><put url='{}'><header name='Authorization'>Bearer {}</header></put><get url='{}'/></slot>",
                attr_escape(&put_url),
                xml_escape(&token),
                attr_escape(&get_url)
            );
        Ok(Action::Send(iq_result_from(id, &upload_domain, &slot)))
    }
}
