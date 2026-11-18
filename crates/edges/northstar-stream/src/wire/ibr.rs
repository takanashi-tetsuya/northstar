//! XEP-0389 registration flows: their submissions and wire forms.

use northstar_auth_application::account::PowProof;
use northstar_xml_builder::{
    xdata::{strict_xdata_submit, InvalidForm},
    XmlElement,
};
use roxmltree::Node;
use zeroize::Zeroize;

pub const IBR2_NS: &str = "urn:xmpp:register:0";
pub const FLOW_ID: &str = "northstar";
pub const POW_FLOW_ID: &str = "northstar-pow-v2";
pub const POW_NS: &str = "urn:northstar:pow:2";
pub const INVITATION_TOKEN_MAX_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IbrFlowTransport {
    Stream,
    Iq,
}

pub struct RegistrationSubmission {
    pub username: String,
    pub password: String,
    pub invitation_token: Option<String>,
    pub proof: Option<PowProof>,
}

impl Drop for RegistrationSubmission {
    fn drop(&mut self) {
        self.password.zeroize();
        if let Some(invitation_token) = self.invitation_token.as_mut() {
            invitation_token.zeroize();
        }
    }
}

pub fn ibr_stream_feature() -> String {
    XmlElement::namespaced("register", IBR2_NS)
        .child(
            XmlElement::new("flow")
                .attr("id", "northstar")
                .child(
                    XmlElement::new("name")
                        .attr("xml:lang", "en")
                        .text("Account registration"),
                )
                .child(XmlElement::new("challenge").attr("type", "jabber:x:data")),
        )
        .child(
            XmlElement::new("flow")
                .attr("id", POW_FLOW_ID)
                .child(
                    XmlElement::new("name")
                        .attr("xml:lang", "en")
                        .text("Registration with proof of work"),
                )
                .child(XmlElement::new("challenge").attr("type", "jabber:x:data"))
                .child(XmlElement::new("challenge").attr("type", POW_NS)),
        )
        .finish()
}

pub fn ibr_flow_list() -> String {
    ibr_stream_feature()
}

pub fn ibr_empty_flow_list() -> String {
    XmlElement::namespaced("register", IBR2_NS).finish()
}

pub fn parse_response(node: Node<'_, '_>) -> Result<RegistrationSubmission, InvalidForm> {
    if node.tag_name().name() != "response"
        || node.tag_name().namespace() != Some(IBR2_NS)
        || node.attributes().len() != 0
        || node.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err(InvalidForm);
    }
    let children = node
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if children.len() != 1 {
        return Err(InvalidForm);
    }
    let fields = strict_xdata_submit(
        children[0],
        IBR2_NS,
        &[
            "username",
            "password",
            "urn:northstar:invite:token",
            "urn:northstar:pow:challenge-id",
            "urn:northstar:pow:version",
            "urn:northstar:pow:prefix",
            "urn:northstar:pow:work-factor",
            "urn:northstar:pow:max-work-factor",
            "urn:northstar:pow:hard-wait-seconds",
            "urn:northstar:pow:max-device-seconds",
            "urn:northstar:pow:intent-body-sha256",
            "urn:northstar:pow:nonce",
        ],
    )?;
    let username = fields.get("username").cloned().ok_or(InvalidForm)?;
    let password = fields.get("password").cloned().ok_or(InvalidForm)?;
    let invitation_token = fields
        .get("urn:northstar:invite:token")
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned());
    if invitation_token
        .as_ref()
        .is_some_and(|value| value.len() > INVITATION_TOKEN_MAX_BYTES)
    {
        return Err(InvalidForm);
    }
    let challenge_id = fields
        .get("urn:northstar:pow:challenge-id")
        .map(|value| value.parse::<uuid::Uuid>())
        .transpose()
        .map_err(|_| InvalidForm)?;
    let proof = match (challenge_id, fields.get("urn:northstar:pow:nonce")) {
        (Some(challenge_id), Some(nonce)) if !nonce.is_empty() => {
            if nonce.len() > 64 || !nonce.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(InvalidForm);
            }
            Some(PowProof {
                challenge_id,
                nonce: nonce.to_owned(),
            })
        }
        (Some(_), Some(_)) | (Some(_), None) | (None, None) => None,
        (None, Some(_)) => return Err(InvalidForm),
    };
    Ok(RegistrationSubmission {
        username,
        password,
        invitation_token,
        proof,
    })
}

pub fn valid_flow_selection(node: Node<'_, '_>) -> bool {
    if node.tag_name().name() != "register"
        || node.tag_name().namespace() != Some(IBR2_NS)
        || node.attributes().len() != 0
        || node.children().any(|child| {
            !child.is_element() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    let children = node
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    let [flow] = children.as_slice() else {
        return false;
    };
    flow.tag_name().name() == "flow"
        && flow.tag_name().namespace() == Some(IBR2_NS)
        && matches!(flow.attribute("id"), Some(FLOW_ID | POW_FLOW_ID))
        && flow.attributes().all(|attribute| attribute.name() == "id")
        && !flow.children().any(|child| child.is_element())
        && flow.text().is_none_or(|text| text.trim().is_empty())
}

pub fn pow_flow_selected(node: Node<'_, '_>) -> bool {
    node.children()
        .find(|child| child.is_element())
        .is_some_and(|flow| flow.attribute("id") == Some(POW_FLOW_ID))
}

pub fn valid_empty_element(node: Node<'_, '_>, name: &str, namespace: &str) -> bool {
    node.tag_name().name() == name
        && node.tag_name().namespace() == Some(namespace)
        && node.attributes().len() == 0
        && !node.children().any(|child| child.is_element())
        && node.text().is_none_or(|text| text.trim().is_empty())
}

pub fn invalid_flow_stream_error() -> String {
    XmlElement::new("stream:error")
        .attr("xmlns:stream", "http://etherx.jabber.org/streams")
        .child(XmlElement::namespaced(
            "undefined-condition",
            "urn:ietf:params:xml:ns:xmpp-streams",
        ))
        .child(XmlElement::namespaced("invalid-flow", IBR2_NS))
        .finish()
}

pub fn ibr_success(username: &str, domain: &str) -> String {
    XmlElement::namespaced("success", IBR2_NS)
        .child(XmlElement::new("jid").text(format!("{username}@{domain}")))
        .child(XmlElement::new("username").text(username))
        .finish()
}

pub fn ibr_cancel() -> String {
    XmlElement::namespaced("cancel", IBR2_NS).finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn flow_selection_is_exact() {
        let pow = Document::parse(
            "<register xmlns='urn:xmpp:register:0'><flow id='northstar-pow-v2'/></register>",
        )
        .unwrap();
        assert!(valid_flow_selection(pow.root_element()));
        assert!(pow_flow_selected(pow.root_element()));
        let valid = Document::parse(
            "<register xmlns='urn:xmpp:register:0'><flow id='northstar'/></register>",
        )
        .unwrap();
        assert!(valid_flow_selection(valid.root_element()));
        assert!(!pow_flow_selected(valid.root_element()));
        for xml in [
            "<register xmlns='urn:xmpp:register:0'/>",
            "<register xmlns='urn:xmpp:register:0'><flow id='other'/></register>",
            "<register xmlns='urn:xmpp:register:0'><flow id='northstar'/><flow id='northstar'/></register>",
            "<register xmlns='urn:xmpp:register:0'><flow id='northstar'><name>x</name></flow></register>",
        ] {
            let doc = Document::parse(xml).unwrap();
            assert!(!valid_flow_selection(doc.root_element()), "{xml}");
        }
    }

    #[test]
    fn response_rejects_ambiguous_values() {
        let valid = "<response xmlns='urn:xmpp:register:0'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:register:0</value></field><field var='username'><value>alice</value></field><field var='password'><value>correct-horse-battery</value></field></x></response>";
        let doc = Document::parse(valid).unwrap();
        assert!(parse_response(doc.root_element()).is_ok());

        let duplicate = valid.replace(
            "<field var='username'><value>alice</value></field>",
            "<field var='username'><value>alice</value></field><field var='username'><value>mallory</value></field>",
        );
        let doc = Document::parse(&duplicate).unwrap();
        assert!(parse_response(doc.root_element()).is_err());

        let nested = valid.replace("<value>alice</value>", "<value><b>alice</b></value>");
        let doc = Document::parse(&nested).unwrap();
        assert!(parse_response(doc.root_element()).is_err());

        let orphan_nonce = valid.replace(
            "</x>",
            "<field var='urn:northstar:pow:nonce'><value>123</value></field></x>",
        );
        let doc = Document::parse(&orphan_nonce).unwrap();
        assert!(parse_response(doc.root_element()).is_err());

        let challenge_without_work = valid.replace(
            "</x>",
            "<field var='urn:northstar:pow:challenge-id'><value>de305d54-75b4-431b-adb2-eb6b9e546013</value></field><field var='urn:northstar:pow:nonce'><value></value></field></x>",
        );
        let doc = Document::parse(&challenge_without_work).unwrap();
        assert!(parse_response(doc.root_element()).is_ok());
    }

    #[test]
    fn success_contains_required_escaped_identity() {
        assert_eq!(
            ibr_success("alice", "example.test"),
            "<success xmlns='urn:xmpp:register:0'><jid>alice@example.test</jid><username>alice</username></success>"
        );
    }

    #[test]
    fn unavailable_iq_flow_list_is_a_successful_empty_register_element() {
        let flow = ibr_empty_flow_list();
        let document = Document::parse(&flow).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().name(), "register");
        assert_eq!(root.tag_name().namespace(), Some(IBR2_NS));
        assert!(!root.children().any(|child| child.is_element()));
    }
}
