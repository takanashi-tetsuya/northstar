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
                session.sm_resume_allowed = false;
                let domain = session.state.local_domain().to_owned();
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
                    session.sm_resume_allowed = false;
                    let domain = session.state.local_domain().to_owned();
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
                    item,
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
            for (index, reply) in replies.into_iter().enumerate() {
                if session.record_outbound(&reply).await.is_err() {
                    session.sm_resume_allowed = false;
                    return false;
                }
                if !websocket_send_live(socket, Message::Text(reply.into()), send_cancellation)
                    .await
                {
                    return false;
                }
                if index == 0 && !session.publish_committed_authentication_and_route().await {
                    return false;
                }
            }
        }
        Ok(Action::SendManyAndClose(replies)) => {
            session.sm_resume_allowed = false;
            websocket_send_many_and_close(socket, replies, true, terminal_sequence).await;
            return false;
        }
        Ok(Action::Resume(payload)) => {
            let crate::xmpp::protocol::ResumeTransportParts {
                control,
                post_control,
                replay,
                activate_route,
                transient_capacity: _resume_transport_capacity,
            } = payload.into_transport_parts();
            if session.record_outbound(&control).await.is_err() {
                session.sm_resume_allowed = false;
                let domain = session.state.local_domain().to_owned();
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
            if !websocket_send_live(socket, Message::Text(control.into()), send_cancellation).await
            {
                return false;
            }
            if activate_route && !session.publish_committed_authentication_and_route().await {
                return false;
            }
            for nonza in post_control {
                if session.record_outbound(&nonza).await.is_err() {
                    session.sm_resume_allowed = false;
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
            session.sm_resume_allowed = false;
            websocket_orderly_close(socket, true, terminal_sequence).await;
            return false;
        }
        Ok(Action::CloseWith(reply)) => {
            session.sm_resume_allowed = false;
            let domain = session.state.local_domain().to_owned();
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
            session.sm_resume_allowed = false;
            let domain = session.state.local_domain().to_owned();
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
