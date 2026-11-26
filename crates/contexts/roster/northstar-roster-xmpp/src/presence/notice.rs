use super::PresenceSession;
use anyhow::Result;
use northstar_xml_builder::XmlElement;

/// Delivers MOTD or welcome service messages to a newly available resource.
pub async fn deliver_service_messages<S: PresenceSession>(session: &S, from: &str) -> Result<()> {
    let user = session.session_account().expect("authenticated session");
    for claim in session
        .presence_service()
        .claim_service_messages(user.id)
        .await?
    {
        let subject = if claim.kind() == "motd" {
            "Message of the Day"
        } else {
            "Welcome"
        };
        let notice = XmlElement::namespaced("message", "jabber:client")
            .attr("from", session.session_local_domain())
            .attr("to", from)
            .attr("type", "headline")
            .attr("id", uuid::Uuid::new_v4())
            .child(XmlElement::new("subject").text(subject))
            .child(XmlElement::new("body").text(claim.body()))
            .finish();
        session.presence_send(notice).await?;
        if !session
            .presence_service()
            .complete_service_message_claim(user.id, &claim)
            .await?
        {
            tracing::warn!(
                kind = %claim.kind(),
                user_id = %user.id,
                "service-message delivery lease changed after queue acceptance"
            );
        }
    }
    Ok(())
}
