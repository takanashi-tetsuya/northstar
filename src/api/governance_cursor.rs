//! Signed endpoint-specific governance continuations.
use crate::{
    api::cursor::{
        CanonicalScope, CursorBinding, CursorDirection, CursorKeyring, CursorPosition, CursorValue,
    },
    services::governance::*,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

const LEGAL_HOLD_EXPORT_ENDPOINT: &str = "admin/legal-holds/export-v2";
const LEGAL_HOLD_EXPORT_SORT: &str = "resource.created_at.id.asc";
const AUDIT_EXPORT_ENDPOINT: &str = "admin/audit/export-v2";
const AUDIT_EXPORT_SORT: &str = "id.asc.snapshot";

fn legal_hold_export_filter(hold_id: Uuid) -> Result<CanonicalScope, GovernanceFailure> {
    CanonicalScope::new()
        .field("hold_id", Some(hold_id.as_bytes()))
        .map_err(GovernanceFailure::internal)
}

fn audit_export_filter(
    start: Option<chrono::DateTime<chrono::Utc>>,
    end: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<CanonicalScope, GovernanceFailure> {
    let start = start.map(|value| value.timestamp_micros().to_string());
    let end = end.map(|value| value.timestamp_micros().to_string());
    CanonicalScope::new()
        .field("end", end.as_deref().map(str::as_bytes))
        .and_then(|scope| scope.field("start", start.as_deref().map(str::as_bytes)))
        .map_err(GovernanceFailure::internal)
}

fn governance_binding<'a>(
    endpoint: &'a str,
    sort: &'a str,
    actor_id: &'a Uuid,
    filter: &'a CanonicalScope,
) -> CursorBinding<'a> {
    CursorBinding {
        endpoint,
        principal_scope: actor_id.as_bytes(),
        filter_scope: filter.as_bytes(),
        sort,
        direction: CursorDirection::Forward,
        // Governance snapshots live in PostgreSQL and are portable across
        // nodes/restarts as long as the cursor HMAC key remains deployed.
        node_incarnation: Uuid::nil(),
    }
}

fn decode_legal_hold_cursor(
    position: CursorPosition,
) -> Result<LegalHoldExportCursor, GovernanceFailure> {
    match position.last.as_slice() {
        [CursorValue::Uuid(export_id), CursorValue::U64(resource_order), CursorValue::TimestampMicros(created_at), CursorValue::Uuid(record_id), CursorValue::TimestampMicros(snapshot_at), CursorValue::Digest32(chain_root)]
            if !export_id.is_nil() && !record_id.is_nil() && (1..=4).contains(resource_order) =>
        {
            Ok(LegalHoldExportCursor {
                export_id: *export_id,
                after_resource_order: i64::try_from(*resource_order)
                    .map_err(|_| invalid_cursor())?,
                after_created_at: chrono::DateTime::from_timestamp_micros(*created_at)
                    .ok_or(invalid_cursor())?,
                after_record_id: *record_id,
                snapshot_at: chrono::DateTime::from_timestamp_micros(*snapshot_at)
                    .ok_or(invalid_cursor())?,
                chain_root: *chain_root,
            })
        }
        _ => Err(invalid_cursor()),
    }
}

fn decode_audit_cursor(position: CursorPosition) -> Result<AuditExportCursor, GovernanceFailure> {
    match position.last.as_slice() {
        [CursorValue::Uuid(export_id), CursorValue::I64(after_id), CursorValue::I64(snapshot_max_id), CursorValue::TimestampMicros(snapshot_at), CursorValue::Digest32(chain_root)]
            if !export_id.is_nil() && *after_id >= 0 && *snapshot_max_id >= *after_id =>
        {
            Ok(AuditExportCursor {
                export_id: *export_id,
                after_id: *after_id,
                snapshot_max_id: *snapshot_max_id,
                snapshot_at: chrono::DateTime::from_timestamp_micros(*snapshot_at)
                    .ok_or(invalid_cursor())?,
                chain_root: *chain_root,
            })
        }
        _ => Err(invalid_cursor()),
    }
}

fn export_cursor_ttl_seconds(
    exported_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<i64, GovernanceFailure> {
    let remaining = expires_at
        .timestamp()
        .saturating_sub(exported_at.timestamp());
    if !(30..=GOVERNANCE_EXPORT_LEASE_SECONDS).contains(&remaining) {
        return Err(invalid_cursor());
    }
    Ok(remaining)
}

fn issue_legal_hold_cursor(
    keyring: &CursorKeyring,
    binding: &CursorBinding<'_>,
    export: &LegalHoldExport,
) -> Result<Option<String>, GovernanceFailure> {
    let Some(next) = export.next.as_ref() else {
        return Ok(None);
    };
    let expires_at = export.lease_expires_at.ok_or_else(|| {
        GovernanceFailure::internal(anyhow::anyhow!(
            "legal-hold continuation has no export lease"
        ))
    })?;
    let ttl = export_cursor_ttl_seconds(export.exported_at, expires_at)?;
    keyring
        .issue(
            binding,
            &CursorPosition {
                last: vec![
                    CursorValue::Uuid(next.export_id),
                    CursorValue::U64(
                        u64::try_from(next.after_resource_order).map_err(|_| invalid_cursor())?,
                    ),
                    CursorValue::TimestampMicros(next.after_created_at.timestamp_micros()),
                    CursorValue::Uuid(next.after_record_id),
                    CursorValue::TimestampMicros(next.snapshot_at.timestamp_micros()),
                    CursorValue::Digest32(next.chain_root),
                ],
            },
            export.exported_at.timestamp(),
            ttl,
        )
        .map(Some)
        .map_err(GovernanceFailure::internal)
}

fn issue_audit_cursor(
    keyring: &CursorKeyring,
    binding: &CursorBinding<'_>,
    export: &AuditExport,
) -> Result<Option<String>, GovernanceFailure> {
    let Some(next) = export.next.as_ref() else {
        return Ok(None);
    };
    let ttl = export_cursor_ttl_seconds(export.exported_at, export.lease_expires_at)?;
    keyring
        .issue(
            binding,
            &CursorPosition {
                last: vec![
                    CursorValue::Uuid(next.export_id),
                    CursorValue::I64(next.after_id),
                    CursorValue::I64(next.snapshot_max_id),
                    CursorValue::TimestampMicros(next.snapshot_at.timestamp_micros()),
                    CursorValue::Digest32(next.chain_root),
                ],
            },
            export.exported_at.timestamp(),
            ttl,
        )
        .map(Some)
        .map_err(GovernanceFailure::internal)
}

fn invalid_cursor() -> GovernanceFailure {
    GovernanceFailure::quiet(GovernanceError::InvalidCursor)
}

#[derive(Clone)]
pub(crate) struct SignedGovernanceCursors {
    keyring: Arc<CursorKeyring>,
}
impl SignedGovernanceCursors {
    pub(crate) fn new(keyring: Arc<CursorKeyring>) -> Self {
        Self { keyring }
    }
    fn verify(
        &self,
        token: &str,
        binding: &CursorBinding<'_>,
        now: DateTime<Utc>,
    ) -> Result<CursorPosition, GovernanceFailure> {
        self.keyring
            .verify(token, binding, now.timestamp())
            .map_err(|_| GovernanceFailure::rejected_cursor())
    }
}
impl GovernanceCursorCodec for SignedGovernanceCursors {
    fn decode_hold(
        &self,
        actor: Uuid,
        hold: Uuid,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<LegalHoldExportCursor, GovernanceFailure> {
        let filter = legal_hold_export_filter(hold)?;
        let binding = governance_binding(
            LEGAL_HOLD_EXPORT_ENDPOINT,
            LEGAL_HOLD_EXPORT_SORT,
            &actor,
            &filter,
        );
        decode_legal_hold_cursor(self.verify(token, &binding, now)?)
    }
    fn decode_audit(
        &self,
        actor: Uuid,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<AuditExportCursor, GovernanceFailure> {
        let filter = audit_export_filter(start, end)?;
        let binding = governance_binding(AUDIT_EXPORT_ENDPOINT, AUDIT_EXPORT_SORT, &actor, &filter);
        decode_audit_cursor(self.verify(token, &binding, now)?)
    }
    fn encode_hold(
        &self,
        actor: Uuid,
        export: &LegalHoldExport,
    ) -> Result<Option<String>, GovernanceFailure> {
        let filter = legal_hold_export_filter(export.hold.id)?;
        let binding = governance_binding(
            LEGAL_HOLD_EXPORT_ENDPOINT,
            LEGAL_HOLD_EXPORT_SORT,
            &actor,
            &filter,
        );
        issue_legal_hold_cursor(&self.keyring, &binding, export)
    }
    fn encode_audit(
        &self,
        actor: Uuid,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        export: &AuditExport,
    ) -> Result<Option<String>, GovernanceFailure> {
        let filter = audit_export_filter(start, end)?;
        let binding = governance_binding(AUDIT_EXPORT_ENDPOINT, AUDIT_EXPORT_SORT, &actor, &filter);
        issue_audit_cursor(&self.keyring, &binding, export)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn governance_cursor_positions_are_endpoint_specific_and_bounded() {
        let snapshot = 1_700_000_000_123_456_i64;
        let legal = CursorPosition {
            last: vec![
                CursorValue::Uuid(Uuid::from_u128(1)),
                CursorValue::U64(2),
                CursorValue::TimestampMicros(snapshot - 1),
                CursorValue::Uuid(Uuid::from_u128(2)),
                CursorValue::TimestampMicros(snapshot),
                CursorValue::Digest32([7; 32]),
            ],
        };
        let decoded = decode_legal_hold_cursor(legal.clone()).unwrap();
        assert_eq!(decoded.after_resource_order, 2);
        assert_eq!(decoded.chain_root, [7; 32]);
        assert!(decode_audit_cursor(legal).is_err());

        let audit = CursorPosition {
            last: vec![
                CursorValue::Uuid(Uuid::from_u128(3)),
                CursorValue::I64(10),
                CursorValue::I64(20),
                CursorValue::TimestampMicros(snapshot),
                CursorValue::Digest32([9; 32]),
            ],
        };
        assert_eq!(decode_audit_cursor(audit.clone()).unwrap().after_id, 10);
        assert!(decode_legal_hold_cursor(audit).is_err());
        assert!(decode_audit_cursor(CursorPosition {
            last: vec![
                CursorValue::Uuid(Uuid::from_u128(3)),
                CursorValue::I64(21),
                CursorValue::I64(20),
                CursorValue::TimestampMicros(snapshot),
                CursorValue::Digest32([9; 32]),
            ],
        })
        .is_err());
    }

    #[test]
    fn governance_cursor_scope_and_lease_lifetime_fail_closed() {
        let hold_a = legal_hold_export_filter(Uuid::from_u128(1)).unwrap();
        let hold_b = legal_hold_export_filter(Uuid::from_u128(2)).unwrap();
        assert_ne!(hold_a.as_bytes(), hold_b.as_bytes());
        let start = chrono::DateTime::from_timestamp_micros(1_700_000_000_000_000);
        let end = chrono::DateTime::from_timestamp_micros(1_700_000_100_000_000);
        assert_ne!(
            audit_export_filter(start, end).unwrap().as_bytes(),
            audit_export_filter(start, None).unwrap().as_bytes()
        );
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        assert_eq!(
            export_cursor_ttl_seconds(now, now + chrono::Duration::seconds(900)).unwrap(),
            900
        );
        assert!(export_cursor_ttl_seconds(now, now + chrono::Duration::seconds(29)).is_err());
        assert!(export_cursor_ttl_seconds(now, now + chrono::Duration::seconds(901)).is_err());
    }
}
