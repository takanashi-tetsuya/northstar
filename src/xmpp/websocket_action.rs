//! Execute XMPP protocol actions over RFC 7395 WebSocket framing.

use super::{
    websocket_fatal_error, websocket_orderly_close, websocket_record_and_send_item,
    websocket_send_live, websocket_send_many_and_close, WebSocketSendCancellation,
    WebSocketTerminalSequence,
};
use crate::xmpp::protocol::{Action, ProtocolSession};
use anyhow::Result;
use axum::extract::ws::{Message, WebSocket};

pub(super) async fn apply(
    socket: &mut WebSocket,
    session: &mut ProtocolSession,
    action: Result<Action>,
    opening: bool,
    terminal_sequence: &mut WebSocketTerminalSequence,
    send_cancellation: &WebSocketSendCancellation<'_>,
) -> bool {
    match action {
        Ok(Action::Send(reply)) => {
            if session.record_outbound(&reply).await.is_err() {
                session.forbid_sm_resume();
                let domain = session.local_domain().to_owned();
                websocket_fatal_error(
                    socket,
                    &domain,
                    opening,
                    crate::xmpp::xml_util::stream_error("internal-server-error"),
                    terminal_sequence,
                )
                .await;
                return false;
            }
            if !websocket_send_live(socket, Message::Text(reply.into()), send_cancellation).await {
                // A broken transport remains eligible for XEP-0198 resume.
                return false;
            }
        }
        Ok(Action::SendMany(replies)) => {
            for reply in replies {
                if session.record_outbound(&reply).await.is_err() {
                    session.forbid_sm_resume();
                    let domain = session.local_domain().to_owned();
                    websocket_fatal_error(
                        socket,
                        &domain,
                        opening,
                        crate::xmpp::xml_util::stream_error("internal-server-error"),
                        terminal_sequence,
                    )
                    .await;
                    return false;
                }
                if !websocket_send_live(socket, Message::Text(reply.into()), send_cancellation)
                    .await
                {
                    return false;
                }
            }
        }
        Ok(Action::SendManyItems(items)) => {
            for item in items {
                if !websocket_record_and_send_item(
                    socket,
                    session,
                    &item,
                    opening,
                    terminal_sequence,
                    send_cancellation,
                )
                .await
                {
                    return false;
                }
            }
        }
        Ok(Action::SendManyThenActivate(replies)) => {
            let (replies, holder) = replies.into_parts();
            let mut holder = Some(holder);
            for reply in replies {
                if let Some(holder) = &holder {
                    if holder
                        .validate_connection(session.connection_id)
                        .and_then(|_| holder.validate_control(&reply))
                        .is_err()
                    {
                        session.forbid_sm_resume();
                        return false;
                    }
                    if holder.recording().is_err() {
                        session.forbid_sm_resume();
                        return false;
                    }
                }
                if session.record_outbound(&reply).await.is_err() {
                    session.forbid_sm_resume();
                    return false;
                }
                if let Some(holder) = holder.take() {
                    let Some(owner) =
                        write_auth_control(socket, reply, holder, send_cancellation).await
                    else {
                        return false;
                    };
                    if !session
                        .publish_committed_authentication_and_route(owner)
                        .await
                    {
                        return false;
                    }
                } else if !websocket_send_live(
                    socket,
                    Message::Text(reply.into()),
                    send_cancellation,
                )
                .await
                {
                    return false;
                }
            }
        }
        Ok(Action::SendManyAndClose(replies)) => {
            session.forbid_sm_resume();
            websocket_send_many_and_close(socket, replies, true, terminal_sequence).await;
            return false;
        }
        Ok(Action::Resume(payload)) => {
            let crate::xmpp::protocol::ResumeTransportParts {
                control,
                post_control,
                replay,
                activate_route,
                auth_publication,
                transient_capacity: _resume_transport_capacity,
            } = payload.into_transport_parts();
            if activate_route != auth_publication.is_some() {
                session.forbid_sm_resume();
                return false;
            }
            if activate_route {
                let Some(holder) = &auth_publication else {
                    session.forbid_sm_resume();
                    return false;
                };
                if holder
                    .validate_connection(session.connection_id)
                    .and_then(|_| holder.validate_control(&control))
                    .is_err()
                {
                    session.forbid_sm_resume();
                    return false;
                }
                if holder.recording().is_err() {
                    session.forbid_sm_resume();
                    return false;
                }
            }
            if session.record_outbound(&control).await.is_err() {
                session.forbid_sm_resume();
                let domain = session.local_domain().to_owned();
                websocket_fatal_error(
                    socket,
                    &domain,
                    opening,
                    crate::xmpp::xml_util::stream_error("internal-server-error"),
                    terminal_sequence,
                )
                .await;
                return false;
            }
            if activate_route {
                let holder = auth_publication.expect("validated activating resume owner");
                let Some(owner) =
                    write_auth_control(socket, control, holder, send_cancellation).await
                else {
                    return false;
                };
                if !session
                    .publish_committed_authentication_and_route(owner)
                    .await
                {
                    return false;
                }
            } else if !websocket_send_live(socket, Message::Text(control.into()), send_cancellation)
                .await
            {
                return false;
            }
            for nonza in post_control {
                if session.record_outbound(&nonza).await.is_err() {
                    session.forbid_sm_resume();
                    return false;
                }
                if !websocket_send_live(socket, Message::Text(nonza.into()), send_cancellation)
                    .await
                {
                    return false;
                }
            }
            for stanza in replay {
                if !websocket_send_live(socket, Message::Text(stanza.into()), send_cancellation)
                    .await
                {
                    return false;
                }
                session.record_replayed();
            }
        }
        Ok(Action::Close) => {
            session.forbid_sm_resume();
            websocket_orderly_close(socket, true, terminal_sequence).await;
            return false;
        }
        Ok(Action::CloseWith(reply)) => {
            session.forbid_sm_resume();
            let domain = session.local_domain().to_owned();
            websocket_fatal_error(socket, &domain, opening, reply, terminal_sequence).await;
            return false;
        }
        Ok(Action::None) => {}
        Ok(Action::StartTls) => {
            if !websocket_send_live(
                socket,
                Message::Text("<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'><unexpected-request/></failure>".into()),
                    send_cancellation,
            ).await {
                return false;
            }
        }
        Err(error) => {
            tracing::debug!(?error, "invalid WebSocket XMPP stanza");
            session.forbid_sm_resume();
            let domain = session.local_domain().to_owned();
            websocket_fatal_error(
                socket,
                &domain,
                opening,
                crate::xmpp::xml_util::stream_error("internal-server-error"),
                terminal_sequence,
            )
            .await;
            return false;
        }
    }
    true
}

async fn write_auth_control(
    socket: &mut WebSocket,
    control: String,
    holder: super::auth_publication::AuthControlHolder,
    cancellation: &WebSocketSendCancellation<'_>,
) -> Option<super::auth_publication::OwnedPublication> {
    holder
        .write(control, |control| async move {
            if websocket_send_live(socket, Message::Text(control.into()), cancellation).await {
                Ok(())
            } else {
                anyhow::bail!("authentication control WebSocket write did not complete")
            }
        })
        .await
        .ok()
}
