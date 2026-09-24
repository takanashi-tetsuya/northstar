//! Execute protocol actions on the ordered TCP stream shared by plain and TLS C2S.

use super::{send, tcp_fatal_error, tcp_record_and_send, tcp_record_and_send_item};
use crate::xmpp::protocol::{Action, ProtocolSession, ResumeTransportParts};
use anyhow::Result;
use tokio::io::AsyncWrite;

pub(super) enum TcpActionDisposition {
    Continue,
    Close,
    Upgrade,
}

pub(super) async fn apply<S: AsyncWrite + Unpin>(
    io: &mut S,
    session: &mut ProtocolSession,
    action: Action,
    opening: bool,
) -> Result<TcpActionDisposition> {
    match action {
        Action::Send(reply) => {
            if !tcp_record_and_send(io, session, &reply, opening).await? {
                return Ok(TcpActionDisposition::Close);
            }
        }
        Action::SendMany(replies) => {
            for reply in replies {
                if !tcp_record_and_send(io, session, &reply, opening).await? {
                    return Ok(TcpActionDisposition::Close);
                }
            }
        }
        Action::SendManyItems(items) => {
            for item in items {
                if !tcp_record_and_send_item(io, session, &item, opening).await? {
                    return Ok(TcpActionDisposition::Close);
                }
            }
        }
        Action::SendManyThenActivate(replies) => {
            for (index, reply) in replies.into_iter().enumerate() {
                if !tcp_record_and_send(io, session, &reply, opening).await? {
                    return Ok(TcpActionDisposition::Close);
                }
                if index == 0 && !session.publish_committed_authentication_and_route().await {
                    return Ok(TcpActionDisposition::Close);
                }
            }
        }
        Action::SendManyAndClose(replies) => {
            session.sm_resume_allowed = false;
            for reply in replies {
                send(io, &reply).await?;
            }
            send(io, "</stream:stream>").await?;
            return Ok(TcpActionDisposition::Close);
        }
        Action::Resume(payload) => {
            let ResumeTransportParts {
                control,
                post_control,
                replay,
                activate_route,
                transient_capacity: _resume_transport_capacity,
            } = payload.into_transport_parts();
            if !tcp_record_and_send(io, session, &control, opening).await? {
                return Ok(TcpActionDisposition::Close);
            }
            if activate_route && !session.publish_committed_authentication_and_route().await {
                return Ok(TcpActionDisposition::Close);
            }
            for nonza in post_control {
                if !tcp_record_and_send(io, session, &nonza, opening).await? {
                    return Ok(TcpActionDisposition::Close);
                }
            }
            for stanza in replay {
                send(io, &stanza).await?;
                session.record_replayed();
            }
        }
        Action::StartTls => return Ok(TcpActionDisposition::Upgrade),
        Action::CloseWith(reply) => {
            session.sm_resume_allowed = false;
            tcp_fatal_error(io, session.state.local_domain(), opening, &reply).await?;
            return Ok(TcpActionDisposition::Close);
        }
        Action::Close => {
            send(io, "</stream:stream>").await?;
            return Ok(TcpActionDisposition::Close);
        }
        Action::None => {}
    }
    Ok(TcpActionDisposition::Continue)
}
