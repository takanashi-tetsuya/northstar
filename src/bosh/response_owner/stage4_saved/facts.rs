//! Exact bounded projections of actual BOSH owner and selected-holder reads.
use super::*;
use crate::xmpp::auth_publication::stage4_saved::facts::{
    association, control_joins, count, id, mix, nullable, source,
};
use northstar_delivery_core::bosh_ownership as actual;
use northstar_delivery_core::bosh_ownership::response;
type Id = wire::EvidenceId;
pub(super) fn membership(m: &BoshResponseOwnership) -> Result<wire::Membership<Id>> {
    Ok(wire::Membership {
        c2s_message_ids: wire::List::new(m.c2s_message_ids.iter().copied().map(id).collect())?,
        mix_delivery_ids: wire::List::new(m.mix_delivery_ids.iter().copied().map(id).collect())?,
    })
}
pub(super) fn selection(s: SelectionSnapshot, cut: wire::Cut) -> Result<wire::Fact> {
    let status = match s.status {
        SelectionReadStatus::Complete => wire::SelectionStatus::Complete(wire::Empty {}),
        SelectionReadStatus::Incomplete {
            omitted_items,
            missing_auth_associations,
            connection_changed,
        } => wire::SelectionStatus::Incomplete(wire::IncompleteSelection {
            omitted_items: count(omitted_items)?,
            missing_auth_associations: count(missing_auth_associations)?,
            connection_changed,
        }),
    };
    let convert = |s: SelectedItemSnapshot| -> Result<_> {
        Ok(wire::SelectedItem {
            ordinal: count(s.ordinal)?,
            source: nullable(s.source.map(source)),
            utf8_length: count(s.utf8_length)?,
            sha256: wire::Hex::of(&s.sha256)?,
            auth_marker: s.auth_marker,
            sealed_association: nullable(s.sealed_association.map(association).transpose()?),
            holder_joins: nullable(s.holder_joins.map(control_joins).transpose()?),
        })
    };
    let [a, b, c, d] = s.items;
    Ok(wire::Fact::Bosh(wire::BoshFact::Selection(
        wire::SelectionCapture {
            cut,
            selection: wire::SelectionSnapshot {
                session: id(s.session),
                rid: s.rid,
                fingerprint: wire::Hex::of(&s.fingerprint)?,
                first_validated_connection: nullable(s.first_validated_connection.map(id)),
                validated_connection: nullable(s.validated_connection.map(id)),
                selected_count: count(s.selected_count)?,
                status,
                items: [
                    nullable(a.map(convert).transpose()?),
                    nullable(b.map(convert).transpose()?),
                    nullable(c.map(convert).transpose()?),
                    nullable(d.map(convert).transpose()?),
                ],
            },
        },
    )))
}
fn knowledge(k: response::Knowledge) -> wire::TransactionKnowledge {
    match k {
        response::Knowledge::NoCommitRequested => wire::TransactionKnowledge::NoCommitRequested,
        response::Knowledge::CommitCallEntered => wire::TransactionKnowledge::CommitCallEntered,
        response::Knowledge::ReceiptKnown => wire::TransactionKnowledge::ReceiptKnown,
    }
}
pub(super) fn expected(
    e: Option<(u64, &BoshResponseOwnership)>,
) -> Result<wire::Nullable<wire::BoshExpected<Id>>> {
    Ok(nullable(
        e.map(|(rid, m)| -> Result<_> {
            Ok(wire::BoshExpected {
                rid,
                membership: membership(m)?,
            })
        })
        .transpose()?,
    ))
}
fn bind_attempt(s: &response::BindAttemptSnapshot) -> Result<wire::BoshBindAttempt<Id>> {
    Ok(wire::BoshBindAttempt {
        selected_end: nullable(s.selected_end.map(count).transpose()?),
        selected_len: count(s.selected_len)?,
        sources: nullable(
            s.sources
                .as_ref()
                .map(|v| wire::List::new(v.iter().copied().map(source).collect()))
                .transpose()?,
        ),
        knowledge: match &s.knowledge {
            response::BindKnowledge::NotRequired => {
                wire::BoshBindKnowledge::NotRequired(wire::Empty {})
            }
            response::BindKnowledge::NoCommitRequested => {
                wire::BoshBindKnowledge::NoCommitRequested(wire::Empty {})
            }
            response::BindKnowledge::CommitCallEntered(m) => {
                wire::BoshBindKnowledge::CommitCallEntered(membership(m)?)
            }
            response::BindKnowledge::ReceiptKnown(m) => {
                wire::BoshBindKnowledge::ReceiptKnown(membership(m)?)
            }
        },
        returned: nullable(s.returned.as_ref().map(|m| membership(m)).transpose()?),
        return_matches: s.return_matches,
        superseded_message: nullable(s.superseded_message.map(id)),
        restored: s.restored,
        restore_matches: s.restore_matches,
        removed_indices: wire::List::new(
            s.removed_indices
                .iter()
                .copied()
                .map(count)
                .collect::<Result<_>>()?,
        )?,
    })
}
fn response(s: &response::ResponseSnapshot) -> Result<wire::BoshResponseSnapshot<Id>> {
    Ok(wire::BoshResponseSnapshot {
        rid: s.rid,
        kind: match s.kind {
            response::ResponseKind::Payload => wire::BoshResponseKind::Payload,
            response::ResponseKind::TerminalControl => wire::BoshResponseKind::TerminalControl,
            response::ResponseKind::EmptyControl => wire::BoshResponseKind::EmptyControl,
        },
        lineage: wire::List::new(s.lineage.iter().map(|v| nullable(v.map(source))).collect())?,
        removed: wire::List::new(s.removed.clone())?,
        attempts: wire::List::new(s.attempts.iter().map(bind_attempt).collect::<Result<_>>()?)?,
        construction_restored: count(s.construction_restored)?,
        exposure_entered: s.exposure_entered,
        responder_calls: count(s.responder_calls)?,
        accepted_responders: count(s.accepted_responders)?,
        refused_responders: count(s.refused_responders)?,
        control_calls: count(s.control_calls)?,
        control_accepted: count(s.control_accepted)?,
        control_refused: count(s.control_refused)?,
        empty_cache_evictions: count(s.empty_cache_evictions)?,
        bookkeeping: s.bookkeeping,
        cached: s.cached,
    })
}
pub(super) fn snapshot(s: actual::Snapshot) -> Result<wire::BoshSnapshot<Id>> {
    Ok(wire::BoshSnapshot {
        scope: wire::BoshScope {
            session_id: id(s.scope.session_id),
            ttl_seconds: s.scope.ttl_seconds,
            kind: match s.scope.kind {
                actual::OperationKind::Request => wire::BoshOperationKind::Request,
                actual::OperationKind::Outbound => wire::BoshOperationKind::Outbound,
                actual::OperationKind::HeldResponse => wire::BoshOperationKind::HeldResponse,
            },
        },
        transfers: wire::List::new(
            s.transfers
                .iter()
                .map(|v| wire::BoshTransferSnapshot {
                    source: mix(v.source),
                    knowledge: match v.knowledge {
                        actual::TransferKnowledge::NoCommitRequested => {
                            wire::BoshTransferKnowledge::NoCommitRequested(wire::Empty {})
                        }
                        actual::TransferKnowledge::CommitCallEntered(m) => {
                            wire::BoshTransferKnowledge::CommitCallEntered(mix(m))
                        }
                        actual::TransferKnowledge::ReceiptKnown(m) => {
                            wire::BoshTransferKnowledge::ReceiptKnown(mix(m))
                        }
                    },
                    returned_source: nullable(v.returned_source.map(mix)),
                    return_matches_receipt: v.return_matches_receipt,
                    local_entered: v.local_entered,
                    source_applied: v.source_applied,
                    notification_attempted: v.notification_attempted,
                    queue_accepted: nullable(v.queue_accepted),
                })
                .collect(),
        )?,
        responses: wire::List::new(s.responses.iter().map(response).collect::<Result<_>>()?)?,
        renewals: wire::List::new(
            s.renewals
                .iter()
                .map(|r| -> Result<_> {
                    Ok(wire::BoshRenewSnapshot {
                        expected: expected(r.expected.as_ref().map(|(rid, m)| (*rid, m.as_ref())))?,
                        knowledge: knowledge(r.knowledge),
                        returned: r.returned,
                        return_matches: r.return_matches,
                        ack_issued: r.ack_issued,
                        replay_calls: count(r.replay_calls)?,
                        replay_accepted: count(r.replay_accepted)?,
                        replay_refused: count(r.replay_refused)?,
                        replay_bookkeeping: r.replay_bookkeeping,
                    })
                })
                .collect::<Result<_>>()?,
        )?,
        acknowledgements: wire::List::new(
            s.acknowledgements
                .iter()
                .map(|a| -> Result<_> {
                    Ok(wire::BoshAckSnapshot {
                        rid: a.rid,
                        knowledge: knowledge(a.knowledge),
                        deleted: nullable(
                            a.deleted
                                .as_ref()
                                .map(|ds| {
                                    wire::List::new(
                                        ds.iter()
                                            .map(|d| match *d {
                                                response::DeletedSource::Mix(m) => {
                                                    wire::DeletedSource::Mix(mix(m))
                                                }
                                                response::DeletedSource::C2s {
                                                    recipient_id,
                                                    message_id,
                                                } => wire::DeletedSource::C2s(wire::DeletedC2s {
                                                    recipient_id: id(recipient_id),
                                                    message_id: id(message_id),
                                                }),
                                            })
                                            .collect(),
                                    )
                                })
                                .transpose()?,
                        ),
                        returned: a.returned,
                        return_matches: a.return_matches,
                        cache_evictions: count(a.cache_evictions)?,
                        receipt_calls: count(a.receipt_calls)?,
                        receipts_sent: count(a.receipts_sent)?,
                        receipts_refused: count(a.receipts_refused)?,
                    })
                })
                .collect::<Result<_>>()?,
        )?,
        terminal: nullable(s.terminal.map(|t| match t {
            actual::Terminal::Returned => wire::CallTerminal::Returned,
            actual::Terminal::TimedOut => wire::CallTerminal::TimedOut,
            actual::Terminal::Cancelled => wire::CallTerminal::Cancelled,
            actual::Terminal::Panicked => wire::CallTerminal::Panicked,
        })),
        keep_running: nullable(s.keep_running),
    })
}
