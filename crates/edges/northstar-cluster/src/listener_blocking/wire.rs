use crate::{
    validate_exact_control, ExactControl, ExactControlKind, ExactControlSource,
    EXACT_CONTROL_DELIVERY_VERSION,
};
use anyhow::Result;
use northstar_roster_application::{blocking_mutation::BlockingPresenceTarget, ExactPresenceRoute};
use northstar_xml_builder::XmlElement;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const SNAPSHOT_PAGE: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotEntry {
    pub route: ExactPresenceRoute,
    pub available: bool,
    pub expects_active: bool,
    pub directed: Option<String>,
}

impl SnapshotEntry {
    pub fn key(&self) -> (&str, Option<&str>) {
        (&self.route.full_jid, self.directed.as_deref())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotRequest {
    pub patterns: Option<Vec<String>>,
    pub after: Option<(String, Option<String>)>,
}

#[derive(Deserialize, Serialize)]
#[serde(remote = "BlockingPresenceTarget", deny_unknown_fields)]
struct TargetFields {
    source: ExactPresenceRoute,
    source_expects_active: bool,
    recipient: Option<ExactPresenceRoute>,
    recipient_expects_active: bool,
    address: String,
    directed: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct WireTarget(#[serde(with = "TargetFields")] pub BlockingPresenceTarget);

pub(crate) fn control(source: &ExactPresenceRoute, recipient: &ExactPresenceRoute) -> ExactControl {
    ExactControl {
        kind: ExactControlKind::BlockingPresence,
        account_id: recipient.account_id,
        auth_generation: recipient.auth_generation,
        expected_connections: [(recipient.full_jid.clone(), recipient.connection_id)].into(),
        roster_version: None,
        blocklist_revision: None,
        remote_peer: None,
        source: Some(ExactControlSource {
            account_id: source.account_id,
            auth_generation: source.auth_generation,
            connection_id: source.connection_id,
            full_jid: source.full_jid.clone(),
        }),
        sequence: None,
    }
}

pub(crate) fn payload(control: &ExactControl, route: &ExactPresenceRoute) -> Value {
    serde_json::json!({
        "protocol_version": EXACT_CONTROL_DELIVERY_VERSION,
        "target": route.full_jid,
        "blocking_presence_change": true,
        "exact_control": control,
    })
}

pub(crate) fn checked_control(
    json: &Value,
    target: &str,
    stanza: Option<&str>,
) -> Result<ExactControl> {
    anyhow::ensure!(
        json["blocking_presence_change"].as_bool() == Some(true)
            && json["protocol_version"].as_str() == Some(EXACT_CONTROL_DELIVERY_VERSION),
        "blocking presence requires v15"
    );
    let control = ExactControl::deserialize(&json["exact_control"])?;
    anyhow::ensure!(
        control.kind == ExactControlKind::BlockingPresence
            && control.expected_connections.len() == 1
            && control.expected_connections.contains_key(target),
        "blocking presence requires one exact route"
    );
    let source = control
        .source
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing blocking source"))?;
    let synthetic;
    let stanza = match stanza {
        Some(stanza) => stanza,
        None => {
            synthetic = XmlElement::namespaced("presence", "jabber:client")
                .attr("from", &source.full_jid)
                .finish();
            &synthetic
        }
    };
    validate_exact_control(&control, target, &roxmltree::Document::parse(stanza)?)?;
    Ok(control)
}
