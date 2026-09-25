//! Apply protocol actions to the bounded BOSH response FIFO.

use super::{queue_bosh_resume_payload, BoshActor};
use crate::xmpp::protocol::{Action, ResumeTransportParts};

impl BoshActor {
    pub(super) async fn apply_action(&mut self, action: Action) -> bool {
        match action {
            Action::Send(reply) => {
                let accepted = self.record_and_push(reply).await;
                if accepted {
                    self.protocol.start_post_action_tasks();
                }
                accepted
            }
            Action::SendMany(replies) => {
                for reply in replies {
                    if !self.record_and_push(reply).await {
                        return false;
                    }
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::SendManyItems(items) => {
                for item in items {
                    if !self.record_and_push_item(item).await {
                        return false;
                    }
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::SendManyThenActivate(replies) => {
                for (index, reply) in replies.into_iter().enumerate() {
                    if !self.record_and_push(reply).await {
                        return false;
                    }
                    if index == 0 {
                        self.auth_publication_pending = true;
                    }
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::SendManyAndClose(replies) => {
                self.protocol.forbid_sm_resume();
                for reply in replies {
                    if !self.push_output(reply) {
                        return false;
                    }
                }
                false
            }
            Action::Resume(payload) => {
                let ResumeTransportParts {
                    control,
                    post_control,
                    replay,
                    activate_route,
                    transient_capacity,
                } = payload.into_transport_parts();
                if self.protocol.record_outbound(&control).await.is_err() {
                    return false;
                }
                if activate_route {
                    self.auth_publication_pending = true;
                }
                for nonza in &post_control {
                    if self.protocol.record_outbound(nonza).await.is_err() {
                        return false;
                    }
                }
                let replay_count = replay.len();
                if !queue_bosh_resume_payload(
                    &mut self.output,
                    &mut self.output_bytes,
                    self.max_output_stanzas,
                    self.max_output_bytes,
                    ResumeTransportParts {
                        control,
                        post_control,
                        replay,
                        activate_route,
                        transient_capacity,
                    },
                ) {
                    return false;
                }
                // Replay counters advance only after the whole ordered batch
                // has been admitted atomically to the bounded BOSH FIFO.
                for _ in 0..replay_count {
                    self.protocol.record_replayed();
                }
                self.protocol.start_post_action_tasks();
                true
            }
            Action::StartTls => self.push_output(
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'><unexpected-request/></failure>"
                    .to_owned(),
            ),
            Action::CloseWith(reply) => {
                self.protocol.forbid_sm_resume();
                if !self.push_output(reply.clone()) {
                    // A stream error is the authoritative final payload. If
                    // ordinary queued stanzas consumed the bounded output
                    // budget, discard those stanzas rather than silently
                    // losing the error that explains why the stream closed.
                    self.output.clear();
                    self.output_bytes = 0;
                    let _ = self.push_output(reply);
                }
                false
            }
            Action::Close => {
                self.protocol.forbid_sm_resume();
                false
            }
            Action::None => {
                self.protocol.start_post_action_tasks();
                true
            }
        }
    }
}
