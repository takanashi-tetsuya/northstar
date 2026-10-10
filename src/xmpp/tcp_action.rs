//! Execute protocol actions on the ordered TCP stream shared by plain and TLS C2S.

use super::{
    send, tcp_fatal_error, tcp_record_and_send, tcp_record_and_send_auth, tcp_record_and_send_item,
};
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
            let (replies, holder) = replies.into_parts();
            let mut holder = Some(holder);
            for reply in replies {
                if let Some(holder) = holder.take() {
                    let Some(owner) =
                        tcp_record_and_send_auth(io, session, reply, holder, opening).await?
                    else {
                        return Ok(TcpActionDisposition::Close);
                    };
                    if !session
                        .publish_committed_authentication_and_route(owner)
                        .await
                    {
                        return Ok(TcpActionDisposition::Close);
                    }
                } else if !tcp_record_and_send(io, session, &reply, opening).await? {
                    return Ok(TcpActionDisposition::Close);
                }
            }
        }
        Action::SendManyAndClose(replies) => {
            session.forbid_sm_resume();
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
                auth_publication,
                transient_capacity: _resume_transport_capacity,
            } = payload.into_transport_parts();
            anyhow::ensure!(
                activate_route == auth_publication.is_some(),
                "resume activation and auth owner disagree"
            );
            if activate_route {
                let holder = auth_publication.ok_or_else(|| {
                    anyhow::anyhow!("activating resume has no sealed auth control")
                })?;
                let Some(owner) =
                    tcp_record_and_send_auth(io, session, control, holder, opening).await?
                else {
                    return Ok(TcpActionDisposition::Close);
                };
                if !session
                    .publish_committed_authentication_and_route(owner)
                    .await
                {
                    return Ok(TcpActionDisposition::Close);
                }
            } else if !tcp_record_and_send(io, session, &control, opening).await? {
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
            session.forbid_sm_resume();
            tcp_fatal_error(io, session.local_domain(), opening, &reply).await?;
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
