use northstar_archive_core::{FederatedMamStreamPage, FederatedMamStreamRow, MamRoomAccess};
use northstar_room_core::stanza::{
    project_muc_mam_message, MucMamProjectionError, MucMamStoredRow,
};
use northstar_time::SecondsFormat;
use northstar_xep_0313::{XMLNS_MAM, XMLNS_RSM};
use northstar_xml_builder::{stanza::iq_result_to, XmlElement};
use uuid::Uuid;

pub fn render_federated_mam_stream(
    page: &FederatedMamStreamPage,
    room_jid: &str,
    recipient: &str,
    iq_id: &str,
    query_id: Option<&str>,
    flip_page: bool,
    result_id_seed: Uuid,
) -> anyhow::Result<Vec<String>> {
    let access = page.access();
    let rows: Box<dyn Iterator<Item = &FederatedMamStreamRow>> = if flip_page {
        Box::new(page.rows().iter().rev())
    } else {
        Box::new(page.rows().iter())
    };
    let mut responses = Vec::with_capacity(page.rows().len() + 1);
    for (item, offset) in rows.zip(0_u128..) {
        let archived = project_federated_mam_row(room_jid, access, item).inspect_err(|error| {
            tracing::warn!(archive_id = %item.id(), %error, "MUC MAM projection failed");
        })?;
        let forwarded = XmlElement::namespaced("forwarded", "urn:xmpp:forward:0")
            .child(
                XmlElement::namespaced("delay", "urn:xmpp:delay").attr(
                    "stamp",
                    item.created_at()
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                ),
            )
            .validated_fragment(&archived)?;
        let result = XmlElement::namespaced("result", XMLNS_MAM)
            .attr("id", item.id())
            .optional_attr("queryid", query_id)
            .child(forwarded);
        let result_id = Uuid::from_u128(result_id_seed.as_u128() ^ offset);
        responses.push(
            XmlElement::namespaced("message", "jabber:client")
                .attr("from", room_jid)
                .attr("to", recipient)
                .attr("id", result_id)
                .child(result)
                .finish(),
        );
    }

    let mut rsm = XmlElement::namespaced("set", XMLNS_RSM);
    if let (Some(first), Some(last)) = (page.rows().first(), page.rows().last()) {
        rsm.push_child(
            XmlElement::new("first")
                .attr("index", page.first_index())
                .text(first.id().to_string()),
        );
        rsm.push_child(XmlElement::new("last").text(last.id().to_string()));
    }
    rsm.push_child(XmlElement::new("count").text(page.total().to_string()));
    let fin = XmlElement::namespaced("fin", XMLNS_MAM)
        .attr("complete", page.complete())
        .attr("stable", "true")
        .child(rsm)
        .finish();
    responses.push(iq_result_to(iq_id, room_jid, recipient, &fin));
    Ok(responses)
}

fn project_federated_mam_row(
    room_jid: &str,
    access: &MamRoomAccess,
    row: &FederatedMamStreamRow,
) -> Result<String, MucMamProjectionError> {
    let muc = row.muc().ok_or(MucMamProjectionError::Identity)?;
    project_muc_mam_message(
        room_jid,
        access.occupant_id_secret(),
        access.reveal_real_jid(),
        MucMamStoredRow {
            id: row.id(),
            stanza: row.stanza(),
            sender_jid: row.peer_jid(),
            nick: &muc.nick,
            message_kind: &muc.message_kind,
            encrypted: row.encrypted(),
            retracted: muc.retracted,
        },
    )
}

#[cfg(test)]
mod tests;
