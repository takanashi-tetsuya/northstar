use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const DURATION_BUCKETS_MICROS: [u64; 14] = [
    500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000,
    2_500_000, 5_000_000, 10_000_000,
];

/// A fixed-cardinality Prometheus duration histogram.
///
/// Bounds and metric names are compile-time constants, and observations have
/// no labels. JIDs, account names, nodes, domains and request IDs therefore
/// cannot accidentally become metric labels or grow process memory.
pub struct DurationHistogram {
    buckets: [AtomicU64; DURATION_BUCKETS_MICROS.len()],
    count: AtomicU64,
    sum_nanos: AtomicU64,
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_nanos: AtomicU64::new(0),
        }
    }
}

impl DurationHistogram {
    pub fn observe(&self, duration: Duration) {
        let micros = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        for (upper_bound, bucket) in DURATION_BUCKETS_MICROS.iter().zip(&self.buckets) {
            if micros <= *upper_bound {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        let nanos = duration.as_nanos().min(u128::from(u64::MAX)) as u64;
        let _ = self
            .sum_nanos
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |sum| {
                Some(sum.saturating_add(nanos))
            });
    }

    pub fn start_timer(&self) -> DurationTimer<'_> {
        DurationTimer {
            histogram: self,
            started: Instant::now(),
        }
    }

    fn render_into(&self, output: &mut String, name: &str, help: &str) {
        debug_assert!(name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':')));
        let _ = writeln!(output, "# HELP {name} {help}");
        let _ = writeln!(output, "# TYPE {name} histogram");
        for (upper_bound, bucket) in DURATION_BUCKETS_MICROS.iter().zip(&self.buckets) {
            let seconds = *upper_bound as f64 / 1_000_000.0;
            let _ = writeln!(
                output,
                "{name}_bucket{{le=\"{seconds}\"}} {}",
                bucket.load(Ordering::Relaxed)
            );
        }
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(output, "{name}_bucket{{le=\"+Inf\"}} {count}");
        let _ = writeln!(
            output,
            "{name}_sum {:.9}",
            self.sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
        );
        let _ = writeln!(output, "{name}_count {count}");
    }
}

pub struct DurationTimer<'a> {
    histogram: &'a DurationHistogram,
    started: Instant,
}

impl Drop for DurationTimer<'_> {
    fn drop(&mut self) {
        self.histogram.observe(self.started.elapsed());
    }
}

#[derive(Default)]
pub struct Metrics {
    pub authentication_duration_seconds: DurationHistogram,
    pub database_operation_duration_seconds: DurationHistogram,
    pub routing_duration_seconds: DurationHistogram,
    pub outbox_delivery_duration_seconds: DurationHistogram,
    pub redis_operation_duration_seconds: DurationHistogram,
    pub upload_operation_duration_seconds: DurationHistogram,
    pub upload_storage_reconciliation_failures_total: AtomicU64,
    pub upload_storage_capacity_ledger_mismatches: AtomicU64,
    pub upload_storage_capacity_authority_violations: AtomicU64,
    /// 0=healthy, 1=recovery-draining, 2=unproven, 3=namespace-unsafe,
    /// 4=capacity-authority-unsafe, 5=ledger-mismatch.
    pub upload_storage_safety_gate_state: AtomicU64,
    pub upload_storage_promotion_success_total: AtomicU64,
    pub upload_storage_promotion_failures_total: AtomicU64,
    pub upload_storage_stage_deletion_success_total: AtomicU64,
    pub upload_storage_stage_deletion_failures_total: AtomicU64,
    pub upload_storage_object_deletion_success_total: AtomicU64,
    pub upload_storage_object_deletion_failures_total: AtomicU64,
    pub upload_storage_cleanup_success_total: AtomicU64,
    pub upload_storage_cleanup_failures_total: AtomicU64,
    pub upload_storage_integrity_failures_total: AtomicU64,
    pub upload_storage_credential_refresh_failures_total: AtomicU64,
    pub upload_storage_scrub_success_total: AtomicU64,
    pub upload_storage_scrub_failures_total: AtomicU64,
    pub upload_storage_jobs_pending: AtomicU64,
    pub upload_storage_cleanup_pending: AtomicU64,
    pub upload_storage_cleanup_obligation_debt: AtomicU64,
    pub upload_storage_configured_pending_limit: AtomicU64,
    pub upload_storage_legacy_overcommit_draining: AtomicU64,
    pub upload_storage_recovery_retained_files: AtomicU64,
    pub upload_storage_recovery_retained_bytes: AtomicU64,
    pub upload_storage_recovery_overcommit_draining: AtomicU64,
    pub upload_storage_oldest_pending_age_seconds: AtomicU64,
    pub upload_storage_dead_letter_jobs: AtomicU64,
    pub upload_storage_scrub_failures: AtomicU64,
    pub upload_storage_scrub_due_capped: AtomicU64,
    pub upload_storage_scrub_oldest_overdue_seconds: AtomicU64,
    pub upload_storage_cleanup_obligations_due_capped: AtomicU64,
    pub upload_storage_cleanup_oldest_overdue_seconds: AtomicU64,
    pub tcp_connections_total: AtomicU64,
    pub websocket_connections_total: AtomicU64,
    pub http_insecure_requests_rejected_total: AtomicU64,
    pub bosh_sessions_total: AtomicU64,
    pub bosh_sessions_active: AtomicU64,
    pub active_sessions: AtomicU64,
    pub capacity_reservations_rejected_total: AtomicU64,
    pub capacity_session_lease_losses_total: AtomicU64,
    pub stanzas_in_total: AtomicU64,
    pub stanzas_out_total: AtomicU64,
    pub registrations_total: AtomicU64,
    pub authentication_failures_total: AtomicU64,
    pub authentication_backend_failures_total: AtomicU64,
    /// FAST rows existed but could not be reproduced with the configured
    /// derivation key (operator key mismatch or durable corruption).
    pub fast_credential_integrity_failures_total: AtomicU64,
    pub messages_routed_total: AtomicU64,
    /// Message stanzas admitted without a database-backed transport fence.
    /// These are intentionally limited to best-effort protocol fan-out such
    /// as headlines, Carbons and post-commit notifications.
    pub online_queue_volatile_acceptances_total: AtomicU64,
    /// Message stanzas admitted with a database row which survives the
    /// in-memory queue and is removed only after the owning transport crosses
    /// its recoverable write boundary.
    pub online_queue_durable_acceptances_total: AtomicU64,
    /// Connections deliberately terminated after an ordered durable delivery
    /// or committed state push could not enter the bounded outbound queue.
    /// Recoverable database rows remain available for replay; state pushes
    /// are refreshed by the client after reconnect.
    pub c2s_backpressure_disconnects_total: AtomicU64,
    /// C2S actors which reached the explicit, awaited cleanup boundary.
    pub session_finalizations_total: AtomicU64,
    /// Individually failed or timed-out cleanup steps. Exact leases/epochs or
    /// soft-state reconciliation remain responsible for eventual recovery.
    pub session_finalization_failures_total: AtomicU64,
    /// ProtocolSession values dropped without their explicit finalizer. The
    /// synchronous fallback only quiesces process-local routes.
    pub session_drop_fallbacks_total: AtomicU64,
    pub post_action_tasks_started_total: AtomicU64,
    pub post_action_tasks_completed_total: AtomicU64,
    pub post_action_tasks_panicked_total: AtomicU64,
    pub post_action_tasks_aborted_total: AtomicU64,
    pub post_action_capacity_rejections_total: AtomicU64,
    pub cluster_legacy_delivery_acceptances_total: AtomicU64,
    pub cluster_presence_probe_failures_total: AtomicU64,
    pub post_accept_side_effect_failures_total: AtomicU64,
    /// XEP-0280 Carbon copies that could not be admitted after the primary
    /// message was already accepted.  This is deliberately separate from
    /// primary delivery failures: a Carbon is a best-effort post-accept copy
    /// and must never turn a successful send into a retryable stanza error.
    pub carbon_post_accept_delivery_failures_total: AtomicU64,
    /// Local Carbon resource attempts which exhausted their independent
    /// per-target deadline. This separates slow-resource isolation from other
    /// post-accept failures such as closed queues or invalid payloads.
    pub carbon_fanout_target_timeouts_total: AtomicU64,
    pub pubsub_post_commit_delivery_failures_total: AtomicU64,
    pub pep_post_commit_delivery_failures_total: AtomicU64,
    pub pubsub_event_outbox_pending_rows: AtomicU64,
    pub pubsub_event_outbox_pending_bytes: AtomicU64,
    pub pubsub_event_outbox_dead_letter_rows: AtomicU64,
    pub muc_post_commit_delivery_failures_total: AtomicU64,
    pub cluster_muc_outbox_deliveries_total: AtomicU64,
    pub cluster_muc_outbox_retries_total: AtomicU64,
    pub cluster_muc_outbox_dead_letters: AtomicU64,
    pub cluster_muc_outbox_queued: AtomicU64,
    pub cluster_muc_outbox_oldest_age_seconds: AtomicU64,
    pub cluster_muc_pg_reconciliations_total: AtomicU64,
    pub cluster_muc_authority_rejections_total: AtomicU64,
    pub mix_post_commit_delivery_failures_total: AtomicU64,
    pub federation_inbound_connections_total: AtomicU64,
    pub federation_outbound_deliveries_total: AtomicU64,
    pub federation_failures_total: AtomicU64,
    pub s2s_outbox_retries_total: AtomicU64,
    pub s2s_outbox_expired_total: AtomicU64,
    pub s2s_outbox_permanent_failures_total: AtomicU64,
    pub s2s_outbox_lease_lost_total: AtomicU64,
    pub component_connections_active: AtomicU64,
    pub component_deliveries_total: AtomicU64,
    pub component_failures_total: AtomicU64,
    pub anti_abuse_challenges_total: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub omemo_recovery_poll_requests_total: AtomicU64,
    pub omemo_recovery_poll_rate_limited_total: AtomicU64,
    pub omemo_recovery_poll_concurrency_rejected_total: AtomicU64,
    pub omemo_recovery_poll_not_found_total: AtomicU64,
    pub anti_abuse_backend_failures_total: AtomicU64,
    pub reports_total: AtomicU64,
    pub appeals_total: AtomicU64,
    pub pep_items_published_total: AtomicU64,
    pub pep_items_retracted_total: AtomicU64,
    pub pep_retrievals_total: AtomicU64,
    /// New full-JID effects rejected after the process-wide XEP-0115
    /// side-effect queue reached its fixed cardinality ceiling.
    pub caps_effect_queue_saturated_total: AtomicU64,
    /// Repeated presence/capability observations folded into an existing
    /// per-full-JID job rather than allocating another task or waiter.
    pub caps_effect_coalesced_total: AtomicU64,
    /// Individual PEP/MIX effects which failed inside the supervised worker.
    pub caps_effect_failures_total: AtomicU64,
    /// Queue admission through completion, including bounded queue wait.
    pub caps_effect_latency_seconds: DurationHistogram,
    pub federation_inbound_active: AtomicU64,
    pub background_maintenance_failures_total: AtomicU64,
    pub retention_personal_mam_deleted_total: AtomicU64,
    pub retention_muc_mam_deleted_total: AtomicU64,
    pub retention_offline_messages_deleted_total: AtomicU64,
    pub retention_personal_delivery_admissions_deleted_total: AtomicU64,
    pub retention_moderation_cases_deleted_total: AtomicU64,
    pub retention_legal_hold_snapshots_deleted_total: AtomicU64,
    pub retention_audit_log_deleted_total: AtomicU64,
    pub retention_governance_export_leases_deleted_total: AtomicU64,
    pub retention_omemo_recovery_transfers_deleted_total: AtomicU64,
    pub governance_export_cursor_rejections_total: AtomicU64,
    pub legal_hold_operations_total: AtomicU64,
    pub legal_hold_operation_failures_total: AtomicU64,
    pub audit_export_operations_total: AtomicU64,
    pub audit_export_operation_failures_total: AtomicU64,
    pub retention_cleanup_failures_total: AtomicU64,
    pub tls_reload_failures_total: AtomicU64,
    pub tls_revocation_rechecks_total: AtomicU64,
    pub tls_revocation_recheck_inconclusive_total: AtomicU64,
    pub tls_revoked_sessions_drained_total: AtomicU64,
    pub tls_revoked_c2s_external_sessions_drained_total: AtomicU64,
    pub tls_revoked_inbound_s2s_external_sessions_drained_total: AtomicU64,
    pub tls_revoked_outbound_s2s_external_sessions_drained_total: AtomicU64,
    pub push_notifications_attempted_total: AtomicU64,
    pub push_notifications_routed_total: AtomicU64,
    pub push_notifications_failed_total: AtomicU64,
    pub push_subscriptions_rate_limited_total: AtomicU64,
    pub account_deletion_recovery_success_total: AtomicU64,
    pub account_deletion_recovery_failures_total: AtomicU64,
    pub account_deletion_recovery_lease_losses_total: AtomicU64,
}

impl Metrics {
    pub fn render(&self) -> String {
        let read = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let mut rendered = format!(
            concat!(
                "# TYPE xmpp_tcp_connections_total counter\n",
                "xmpp_tcp_connections_total {}\n",
                "# TYPE xmpp_websocket_connections_total counter\n",
                "xmpp_websocket_connections_total {}\n",
                "# TYPE xmpp_http_insecure_requests_rejected_total counter\n",
                "xmpp_http_insecure_requests_rejected_total {}\n",
                "# TYPE xmpp_bosh_sessions_total counter\n",
                "xmpp_bosh_sessions_total {}\n",
                "# TYPE xmpp_bosh_sessions_active gauge\n",
                "xmpp_bosh_sessions_active {}\n",
                "# TYPE xmpp_active_sessions gauge\n",
                "xmpp_active_sessions {}\n",
                "# TYPE xmpp_capacity_reservations_rejected_total counter\n",
                "xmpp_capacity_reservations_rejected_total {}\n",
                "# TYPE xmpp_capacity_session_lease_losses_total counter\n",
                "xmpp_capacity_session_lease_losses_total {}\n",
                "# TYPE xmpp_stanzas_in_total counter\n",
                "xmpp_stanzas_in_total {}\n",
                "# TYPE xmpp_stanzas_out_total counter\n",
                "xmpp_stanzas_out_total {}\n",
                "# TYPE xmpp_registrations_total counter\n",
                "xmpp_registrations_total {}\n",
                "# TYPE xmpp_authentication_failures_total counter\n",
                "xmpp_authentication_failures_total {}\n",
                "# TYPE xmpp_authentication_backend_failures_total counter\n",
                "xmpp_authentication_backend_failures_total {}\n",
                "# TYPE xmpp_fast_credential_integrity_failures_total counter\n",
                "xmpp_fast_credential_integrity_failures_total {}\n",
                "# TYPE xmpp_messages_routed_total counter\n",
                "xmpp_messages_routed_total {}\n",
                "# TYPE xmpp_online_queue_volatile_acceptances_total counter\n",
                "xmpp_online_queue_volatile_acceptances_total {}\n",
                "# TYPE xmpp_online_queue_durable_acceptances_total counter\n",
                "xmpp_online_queue_durable_acceptances_total {}\n",
                "# TYPE xmpp_c2s_backpressure_disconnects_total counter\n",
                "xmpp_c2s_backpressure_disconnects_total {}\n",
                "# TYPE xmpp_cluster_legacy_delivery_acceptances_total counter\n",
                "xmpp_cluster_legacy_delivery_acceptances_total {}\n",
                "# TYPE xmpp_cluster_presence_probe_failures_total counter\n",
                "xmpp_cluster_presence_probe_failures_total {}\n",
                "# TYPE xmpp_post_accept_side_effect_failures_total counter\n",
                "xmpp_post_accept_side_effect_failures_total {}\n",
                "# TYPE xmpp_carbon_post_accept_delivery_failures_total counter\n",
                "xmpp_carbon_post_accept_delivery_failures_total {}\n",
                "# TYPE xmpp_carbon_fanout_target_timeouts_total counter\n",
                "xmpp_carbon_fanout_target_timeouts_total {}\n",
                "# TYPE xmpp_pubsub_post_commit_delivery_failures_total counter\n",
                "xmpp_pubsub_post_commit_delivery_failures_total {}\n",
                "# TYPE xmpp_pubsub_mutation_admission_rejections_total counter\n",
                "xmpp_pubsub_mutation_admission_rejections_total {}\n",
                "# TYPE xmpp_pubsub_mutation_admission_waiters gauge\n",
                "xmpp_pubsub_mutation_admission_waiters {}\n",
                "# TYPE xmpp_pubsub_mutation_admission_active gauge\n",
                "xmpp_pubsub_mutation_admission_active {}\n",
                "# TYPE xmpp_pep_post_commit_delivery_failures_total counter\n",
                "xmpp_pep_post_commit_delivery_failures_total {}\n",
                "# TYPE xmpp_pubsub_event_outbox_pending_rows gauge\n",
                "xmpp_pubsub_event_outbox_pending_rows {}\n",
                "# TYPE xmpp_pubsub_event_outbox_pending_bytes gauge\n",
                "xmpp_pubsub_event_outbox_pending_bytes {}\n",
                "# TYPE xmpp_pubsub_event_outbox_dead_letter_rows gauge\n",
                "xmpp_pubsub_event_outbox_dead_letter_rows {}\n",
                "# TYPE xmpp_pubsub_event_outbox_retries_total counter\n",
                "xmpp_pubsub_event_outbox_retries_total {}\n",
                "# TYPE xmpp_pubsub_event_outbox_dead_letters_total counter\n",
                "xmpp_pubsub_event_outbox_dead_letters_total {}\n",
                "# TYPE xmpp_pubsub_event_outbox_lease_lost_total counter\n",
                "xmpp_pubsub_event_outbox_lease_lost_total {}\n",
                "# TYPE xmpp_pubsub_event_outbox_capacity_rejections_total counter\n",
                "xmpp_pubsub_event_outbox_capacity_rejections_total {}\n",
                "# TYPE xmpp_pubsub_event_outbox_unverifiable_pep_drops_total counter\n",
                "xmpp_pubsub_event_outbox_unverifiable_pep_drops_total {}\n",
                "# TYPE xmpp_muc_post_commit_delivery_failures_total counter\n",
                "xmpp_muc_post_commit_delivery_failures_total {}\n",
                "# TYPE xmpp_mix_post_commit_delivery_failures_total counter\n",
                "xmpp_mix_post_commit_delivery_failures_total {}\n",
                "# TYPE xmpp_mix_delivery_capacity_rejections_total counter\n",
                "xmpp_mix_delivery_capacity_rejections_total {}\n",
                "# TYPE xmpp_mix_delivery_lease_lost_total counter\n",
                "xmpp_mix_delivery_lease_lost_total {}\n",
                "# TYPE xmpp_mix_delivery_retries_total counter\n",
                "xmpp_mix_delivery_retries_total {}\n",
                "# TYPE xmpp_mix_delivery_dead_letters_total counter\n",
                "xmpp_mix_delivery_dead_letters_total {}\n",
                "# TYPE xmpp_federation_inbound_connections_total counter\n",
                "xmpp_federation_inbound_connections_total {}\n",
                "# TYPE xmpp_federation_outbound_deliveries_total counter\n",
                "xmpp_federation_outbound_deliveries_total {}\n",
                "# TYPE xmpp_federation_failures_total counter\n",
                "xmpp_federation_failures_total {}\n",
                "# TYPE xmpp_s2s_outbox_retries_total counter\n",
                "xmpp_s2s_outbox_retries_total {}\n",
                "# TYPE xmpp_s2s_outbox_expired_total counter\n",
                "xmpp_s2s_outbox_expired_total {}\n",
                "# TYPE xmpp_s2s_outbox_permanent_failures_total counter\n",
                "xmpp_s2s_outbox_permanent_failures_total {}\n",
                "# TYPE xmpp_s2s_outbox_lease_lost_total counter\n",
                "xmpp_s2s_outbox_lease_lost_total {}\n",
                "# TYPE xmpp_s2s_outbox_capacity_rejections_total counter\n",
                "xmpp_s2s_outbox_capacity_rejections_total {}\n",
                "# TYPE xmpp_component_connections_active gauge\n",
                "xmpp_component_connections_active {}\n",
                "# TYPE xmpp_component_deliveries_total counter\n",
                "xmpp_component_deliveries_total {}\n",
                "# TYPE xmpp_component_failures_total counter\n",
                "xmpp_component_failures_total {}\n",
                "# TYPE xmpp_anti_abuse_challenges_total counter\n",
                "xmpp_anti_abuse_challenges_total {}\n",
                "# TYPE xmpp_rate_limited_total counter\n",
                "xmpp_rate_limited_total {}\n",
                "# TYPE xmpp_omemo_recovery_poll_requests_total counter\n",
                "xmpp_omemo_recovery_poll_requests_total {}\n",
                "# TYPE xmpp_omemo_recovery_poll_rate_limited_total counter\n",
                "xmpp_omemo_recovery_poll_rate_limited_total {}\n",
                "# TYPE xmpp_omemo_recovery_poll_concurrency_rejected_total counter\n",
                "xmpp_omemo_recovery_poll_concurrency_rejected_total {}\n",
                "# TYPE xmpp_omemo_recovery_poll_not_found_total counter\n",
                "xmpp_omemo_recovery_poll_not_found_total {}\n",
                "# TYPE xmpp_anti_abuse_backend_failures_total counter\n",
                "xmpp_anti_abuse_backend_failures_total {}\n",
                "# TYPE xmpp_reports_total counter\n",
                "xmpp_reports_total {}\n",
                "# TYPE xmpp_appeals_total counter\n",
                "xmpp_appeals_total {}\n",
                "# TYPE xmpp_pep_items_published_total counter\n",
                "xmpp_pep_items_published_total {}\n",
                "# TYPE xmpp_pep_items_retracted_total counter\n",
                "xmpp_pep_items_retracted_total {}\n",
                "# TYPE xmpp_pep_retrievals_total counter\n",
                "xmpp_pep_retrievals_total {}\n",
                "# TYPE xmpp_federation_inbound_active gauge\n",
                "xmpp_federation_inbound_active {}\n",
                "# TYPE xmpp_background_maintenance_failures_total counter\n",
                "xmpp_background_maintenance_failures_total {}\n",
                "# TYPE xmpp_retention_personal_mam_deleted_total counter\n",
                "xmpp_retention_personal_mam_deleted_total {}\n",
                "# TYPE xmpp_retention_muc_mam_deleted_total counter\n",
                "xmpp_retention_muc_mam_deleted_total {}\n",
                "# TYPE xmpp_retention_offline_messages_deleted_total counter\n",
                "xmpp_retention_offline_messages_deleted_total {}\n",
                "# TYPE xmpp_retention_personal_delivery_admissions_deleted_total counter\n",
                "xmpp_retention_personal_delivery_admissions_deleted_total {}\n",
                "# TYPE xmpp_retention_moderation_cases_deleted_total counter\n",
                "xmpp_retention_moderation_cases_deleted_total {}\n",
                "# TYPE xmpp_retention_legal_hold_snapshots_deleted_total counter\n",
                "xmpp_retention_legal_hold_snapshots_deleted_total {}\n",
                "# TYPE xmpp_retention_audit_log_deleted_total counter\n",
                "xmpp_retention_audit_log_deleted_total {}\n",
                "# TYPE xmpp_retention_governance_export_leases_deleted_total counter\n",
                "xmpp_retention_governance_export_leases_deleted_total {}\n",
                "# TYPE xmpp_retention_omemo_recovery_transfers_deleted_total counter\n",
                "xmpp_retention_omemo_recovery_transfers_deleted_total {}\n",
                "# TYPE xmpp_governance_export_cursor_rejections_total counter\n",
                "xmpp_governance_export_cursor_rejections_total {}\n",
                "# TYPE xmpp_legal_hold_operations_total counter\n",
                "xmpp_legal_hold_operations_total {}\n",
                "# TYPE xmpp_legal_hold_operation_failures_total counter\n",
                "xmpp_legal_hold_operation_failures_total {}\n",
                "# TYPE xmpp_audit_export_operations_total counter\n",
                "xmpp_audit_export_operations_total {}\n",
                "# TYPE xmpp_audit_export_operation_failures_total counter\n",
                "xmpp_audit_export_operation_failures_total {}\n",
                "# TYPE xmpp_retention_cleanup_failures_total counter\n",
                "xmpp_retention_cleanup_failures_total {}\n",
                "# TYPE xmpp_tls_reload_failures_total counter\n",
                "xmpp_tls_reload_failures_total {}\n",
                "# TYPE xmpp_tls_revocation_rechecks_total counter\n",
                "xmpp_tls_revocation_rechecks_total {}\n",
                "# TYPE xmpp_tls_revocation_recheck_inconclusive_total counter\n",
                "xmpp_tls_revocation_recheck_inconclusive_total {}\n",
                "# TYPE xmpp_tls_revoked_sessions_drained_total counter\n",
                "xmpp_tls_revoked_sessions_drained_total {}\n",
                "# TYPE xmpp_tls_revoked_c2s_external_sessions_drained_total counter\n",
                "xmpp_tls_revoked_c2s_external_sessions_drained_total {}\n",
                "# TYPE xmpp_tls_revoked_inbound_s2s_external_sessions_drained_total counter\n",
                "xmpp_tls_revoked_inbound_s2s_external_sessions_drained_total {}\n",
                "# TYPE xmpp_tls_revoked_outbound_s2s_external_sessions_drained_total counter\n",
                "xmpp_tls_revoked_outbound_s2s_external_sessions_drained_total {}\n",
                "# TYPE xmpp_push_notifications_attempted_total counter\n",
                "xmpp_push_notifications_attempted_total {}\n",
                "# TYPE xmpp_push_notifications_routed_total counter\n",
                "xmpp_push_notifications_routed_total {}\n",
                "# TYPE xmpp_push_notifications_failed_total counter\n",
                "xmpp_push_notifications_failed_total {}\n",
                "# TYPE xmpp_push_subscriptions_rate_limited_total counter\n",
                "xmpp_push_subscriptions_rate_limited_total {}\n",
                "# TYPE xmpp_account_deletion_recovery_success_total counter\n",
                "xmpp_account_deletion_recovery_success_total {}\n",
                "# TYPE xmpp_account_deletion_recovery_failures_total counter\n",
                "xmpp_account_deletion_recovery_failures_total {}\n",
                "# TYPE xmpp_account_deletion_recovery_lease_losses_total counter\n",
                "xmpp_account_deletion_recovery_lease_losses_total {}\n"
            ),
            read(&self.tcp_connections_total),
            read(&self.websocket_connections_total),
            read(&self.http_insecure_requests_rejected_total),
            read(&self.bosh_sessions_total),
            read(&self.bosh_sessions_active),
            read(&self.active_sessions),
            read(&self.capacity_reservations_rejected_total),
            read(&self.capacity_session_lease_losses_total),
            read(&self.stanzas_in_total),
            read(&self.stanzas_out_total),
            read(&self.registrations_total),
            read(&self.authentication_failures_total),
            read(&self.authentication_backend_failures_total),
            read(&self.fast_credential_integrity_failures_total),
            read(&self.messages_routed_total),
            read(&self.online_queue_volatile_acceptances_total),
            read(&self.online_queue_durable_acceptances_total),
            read(&self.c2s_backpressure_disconnects_total),
            read(&self.cluster_legacy_delivery_acceptances_total),
            read(&self.cluster_presence_probe_failures_total),
            read(&self.post_accept_side_effect_failures_total),
            read(&self.carbon_post_accept_delivery_failures_total),
            read(&self.carbon_fanout_target_timeouts_total),
            read(&self.pubsub_post_commit_delivery_failures_total),
            crate::services::pubsub::pubsub_mutation_admission_rejections_total(),
            crate::services::pubsub::pubsub_mutation_admission_waiters(),
            crate::services::pubsub::pubsub_mutation_admission_active(),
            read(&self.pep_post_commit_delivery_failures_total),
            read(&self.pubsub_event_outbox_pending_rows),
            read(&self.pubsub_event_outbox_pending_bytes),
            read(&self.pubsub_event_outbox_dead_letter_rows),
            crate::db::pubsub_outbox_retries_total(),
            crate::db::pubsub_outbox_dead_letters_total(),
            crate::db::pubsub_outbox_lease_lost_total(),
            crate::db::pubsub_outbox_capacity_rejections_total(),
            crate::db::pubsub_outbox_unverifiable_pep_drops_total(),
            read(&self.muc_post_commit_delivery_failures_total),
            read(&self.mix_post_commit_delivery_failures_total),
            crate::db::mix_delivery_capacity_rejections_total(),
            crate::db::mix_delivery_lease_lost_total(),
            crate::db::mix_delivery_retries_total(),
            crate::db::mix_delivery_dead_letters_total(),
            read(&self.federation_inbound_connections_total),
            read(&self.federation_outbound_deliveries_total),
            read(&self.federation_failures_total),
            read(&self.s2s_outbox_retries_total),
            read(&self.s2s_outbox_expired_total),
            read(&self.s2s_outbox_permanent_failures_total),
            read(&self.s2s_outbox_lease_lost_total),
            crate::db::s2s_outbox_capacity_rejections_total(),
            read(&self.component_connections_active),
            read(&self.component_deliveries_total),
            read(&self.component_failures_total),
            read(&self.anti_abuse_challenges_total),
            read(&self.rate_limited_total),
            read(&self.omemo_recovery_poll_requests_total),
            read(&self.omemo_recovery_poll_rate_limited_total),
            read(&self.omemo_recovery_poll_concurrency_rejected_total),
            read(&self.omemo_recovery_poll_not_found_total),
            read(&self.anti_abuse_backend_failures_total),
            read(&self.reports_total),
            read(&self.appeals_total),
            read(&self.pep_items_published_total),
            read(&self.pep_items_retracted_total),
            read(&self.pep_retrievals_total),
            read(&self.federation_inbound_active),
            read(&self.background_maintenance_failures_total),
            read(&self.retention_personal_mam_deleted_total),
            read(&self.retention_muc_mam_deleted_total),
            read(&self.retention_offline_messages_deleted_total),
            read(&self.retention_personal_delivery_admissions_deleted_total),
            read(&self.retention_moderation_cases_deleted_total),
            read(&self.retention_legal_hold_snapshots_deleted_total),
            read(&self.retention_audit_log_deleted_total),
            read(&self.retention_governance_export_leases_deleted_total),
            read(&self.retention_omemo_recovery_transfers_deleted_total),
            read(&self.governance_export_cursor_rejections_total),
            read(&self.legal_hold_operations_total),
            read(&self.legal_hold_operation_failures_total),
            read(&self.audit_export_operations_total),
            read(&self.audit_export_operation_failures_total),
            read(&self.retention_cleanup_failures_total),
            read(&self.tls_reload_failures_total),
            read(&self.tls_revocation_rechecks_total),
            read(&self.tls_revocation_recheck_inconclusive_total),
            read(&self.tls_revoked_sessions_drained_total),
            read(&self.tls_revoked_c2s_external_sessions_drained_total),
            read(&self.tls_revoked_inbound_s2s_external_sessions_drained_total),
            read(&self.tls_revoked_outbound_s2s_external_sessions_drained_total),
            read(&self.push_notifications_attempted_total),
            read(&self.push_notifications_routed_total),
            read(&self.push_notifications_failed_total),
            read(&self.push_subscriptions_rate_limited_total),
            read(&self.account_deletion_recovery_success_total),
            read(&self.account_deletion_recovery_failures_total),
            read(&self.account_deletion_recovery_lease_losses_total),
        );
        rendered.push_str(&format!(
            concat!(
                "# TYPE xmpp_cluster_muc_outbox_deliveries_total counter\n",
                "xmpp_cluster_muc_outbox_deliveries_total {}\n",
                "# TYPE xmpp_cluster_muc_outbox_retries_total counter\n",
                "xmpp_cluster_muc_outbox_retries_total {}\n",
                "# TYPE xmpp_cluster_muc_outbox_dead_letters gauge\n",
                "xmpp_cluster_muc_outbox_dead_letters {}\n",
                "# TYPE xmpp_cluster_muc_outbox_queued gauge\n",
                "xmpp_cluster_muc_outbox_queued {}\n",
                "# TYPE xmpp_cluster_muc_outbox_oldest_age_seconds gauge\n",
                "xmpp_cluster_muc_outbox_oldest_age_seconds {}\n",
                "# TYPE xmpp_cluster_muc_pg_reconciliations_total counter\n",
                "xmpp_cluster_muc_pg_reconciliations_total {}\n",
                "# TYPE xmpp_cluster_muc_authority_rejections_total counter\n",
                "xmpp_cluster_muc_authority_rejections_total {}\n"
            ),
            read(&self.cluster_muc_outbox_deliveries_total),
            read(&self.cluster_muc_outbox_retries_total),
            read(&self.cluster_muc_outbox_dead_letters),
            read(&self.cluster_muc_outbox_queued),
            read(&self.cluster_muc_outbox_oldest_age_seconds),
            read(&self.cluster_muc_pg_reconciliations_total),
            read(&self.cluster_muc_authority_rejections_total),
        ));
        let _ = write!(
            rendered,
            concat!(
                "# TYPE xmpp_upload_storage_reconciliation_failures_total counter\n",
                "xmpp_upload_storage_reconciliation_failures_total {}\n",
                "# TYPE xmpp_upload_storage_capacity_ledger_mismatches gauge\n",
                "xmpp_upload_storage_capacity_ledger_mismatches {}\n",
                "# TYPE xmpp_upload_storage_capacity_authority_violations gauge\n",
                "xmpp_upload_storage_capacity_authority_violations {}\n",
                "# TYPE xmpp_upload_storage_safety_gate_state gauge\n",
                "xmpp_upload_storage_safety_gate_state {}\n",
                "# TYPE xmpp_upload_storage_promotion_success_total counter\n",
                "xmpp_upload_storage_promotion_success_total {}\n",
                "# TYPE xmpp_upload_storage_promotion_failures_total counter\n",
                "xmpp_upload_storage_promotion_failures_total {}\n",
                "# TYPE xmpp_upload_storage_stage_deletion_success_total counter\n",
                "xmpp_upload_storage_stage_deletion_success_total {}\n",
                "# TYPE xmpp_upload_storage_stage_deletion_failures_total counter\n",
                "xmpp_upload_storage_stage_deletion_failures_total {}\n",
                "# TYPE xmpp_upload_storage_object_deletion_success_total counter\n",
                "xmpp_upload_storage_object_deletion_success_total {}\n",
                "# TYPE xmpp_upload_storage_object_deletion_failures_total counter\n",
                "xmpp_upload_storage_object_deletion_failures_total {}\n",
                "# TYPE xmpp_upload_storage_cleanup_success_total counter\n",
                "xmpp_upload_storage_cleanup_success_total {}\n",
                "# TYPE xmpp_upload_storage_cleanup_failures_total counter\n",
                "xmpp_upload_storage_cleanup_failures_total {}\n",
                "# TYPE xmpp_upload_storage_integrity_failures_total counter\n",
                "xmpp_upload_storage_integrity_failures_total {}\n",
                "# TYPE xmpp_upload_storage_credential_refresh_failures_total counter\n",
                "xmpp_upload_storage_credential_refresh_failures_total {}\n",
                "# TYPE xmpp_upload_storage_scrub_success_total counter\n",
                "xmpp_upload_storage_scrub_success_total {}\n",
                "# TYPE xmpp_upload_storage_scrub_failures_total counter\n",
                "xmpp_upload_storage_scrub_failures_total {}\n",
                "# TYPE xmpp_upload_storage_jobs_pending gauge\n",
                "xmpp_upload_storage_jobs_pending {}\n",
                "# TYPE xmpp_upload_storage_cleanup_pending gauge\n",
                "xmpp_upload_storage_cleanup_pending {}\n",
                "# TYPE xmpp_upload_storage_cleanup_obligation_debt gauge\n",
                "xmpp_upload_storage_cleanup_obligation_debt {}\n",
                "# TYPE xmpp_upload_storage_configured_pending_limit gauge\n",
                "xmpp_upload_storage_configured_pending_limit {}\n",
                "# TYPE xmpp_upload_storage_legacy_overcommit_draining gauge\n",
                "xmpp_upload_storage_legacy_overcommit_draining {}\n",
                "# TYPE xmpp_upload_storage_recovery_retained_files gauge\n",
                "xmpp_upload_storage_recovery_retained_files {}\n",
                "# TYPE xmpp_upload_storage_recovery_retained_bytes gauge\n",
                "xmpp_upload_storage_recovery_retained_bytes {}\n",
                "# TYPE xmpp_upload_storage_recovery_overcommit_draining gauge\n",
                "xmpp_upload_storage_recovery_overcommit_draining {}\n",
                "# TYPE xmpp_upload_storage_oldest_pending_age_seconds gauge\n",
                "xmpp_upload_storage_oldest_pending_age_seconds {}\n",
                "# HELP xmpp_upload_storage_dead_letter_jobs Saturating health count; 1001 means at least 1001 dead letters.\n",
                "# TYPE xmpp_upload_storage_dead_letter_jobs gauge\n",
                "xmpp_upload_storage_dead_letter_jobs {}\n",
                "# HELP xmpp_upload_storage_scrub_failures Saturating health count; 1001 means at least 1001 persistent scrub failures.\n",
                "# TYPE xmpp_upload_storage_scrub_failures gauge\n",
                "xmpp_upload_storage_scrub_failures {}\n",
                "# TYPE xmpp_upload_storage_scrub_due_capped gauge\n",
                "xmpp_upload_storage_scrub_due_capped {}\n",
                "# TYPE xmpp_upload_storage_scrub_oldest_overdue_seconds gauge\n",
                "xmpp_upload_storage_scrub_oldest_overdue_seconds {}\n",
                "# TYPE xmpp_upload_storage_cleanup_obligations_due_capped gauge\n",
                "xmpp_upload_storage_cleanup_obligations_due_capped {}\n",
                "# TYPE xmpp_upload_storage_cleanup_oldest_overdue_seconds gauge\n",
                "xmpp_upload_storage_cleanup_oldest_overdue_seconds {}\n"
            ),
            read(&self.upload_storage_reconciliation_failures_total),
            read(&self.upload_storage_capacity_ledger_mismatches),
            read(&self.upload_storage_capacity_authority_violations),
            read(&self.upload_storage_safety_gate_state),
            read(&self.upload_storage_promotion_success_total),
            read(&self.upload_storage_promotion_failures_total),
            read(&self.upload_storage_stage_deletion_success_total),
            read(&self.upload_storage_stage_deletion_failures_total),
            read(&self.upload_storage_object_deletion_success_total),
            read(&self.upload_storage_object_deletion_failures_total),
            read(&self.upload_storage_cleanup_success_total),
            read(&self.upload_storage_cleanup_failures_total),
            read(&self.upload_storage_integrity_failures_total),
            read(&self.upload_storage_credential_refresh_failures_total),
            read(&self.upload_storage_scrub_success_total),
            read(&self.upload_storage_scrub_failures_total),
            read(&self.upload_storage_jobs_pending),
            read(&self.upload_storage_cleanup_pending),
            read(&self.upload_storage_cleanup_obligation_debt),
            read(&self.upload_storage_configured_pending_limit),
            read(&self.upload_storage_legacy_overcommit_draining),
            read(&self.upload_storage_recovery_retained_files),
            read(&self.upload_storage_recovery_retained_bytes),
            read(&self.upload_storage_recovery_overcommit_draining),
            read(&self.upload_storage_oldest_pending_age_seconds),
            read(&self.upload_storage_dead_letter_jobs),
            read(&self.upload_storage_scrub_failures),
            read(&self.upload_storage_scrub_due_capped),
            read(&self.upload_storage_scrub_oldest_overdue_seconds),
            read(&self.upload_storage_cleanup_obligations_due_capped),
            read(&self.upload_storage_cleanup_oldest_overdue_seconds),
        );
        let _ = write!(
            rendered,
            concat!(
                "# TYPE xmpp_session_finalizations_total counter\n",
                "xmpp_session_finalizations_total {}\n",
                "# TYPE xmpp_session_finalization_failures_total counter\n",
                "xmpp_session_finalization_failures_total {}\n",
                "# TYPE xmpp_session_drop_fallbacks_total counter\n",
                "xmpp_session_drop_fallbacks_total {}\n",
                "# TYPE xmpp_post_action_tasks_started_total counter\n",
                "xmpp_post_action_tasks_started_total {}\n",
                "# TYPE xmpp_post_action_tasks_completed_total counter\n",
                "xmpp_post_action_tasks_completed_total {}\n",
                "# TYPE xmpp_post_action_tasks_panicked_total counter\n",
                "xmpp_post_action_tasks_panicked_total {}\n",
                "# TYPE xmpp_post_action_tasks_aborted_total counter\n",
                "xmpp_post_action_tasks_aborted_total {}\n",
                "# TYPE xmpp_post_action_capacity_rejections_total counter\n",
                "xmpp_post_action_capacity_rejections_total {}\n"
            ),
            read(&self.session_finalizations_total),
            read(&self.session_finalization_failures_total),
            read(&self.session_drop_fallbacks_total),
            read(&self.post_action_tasks_started_total),
            read(&self.post_action_tasks_completed_total),
            read(&self.post_action_tasks_panicked_total),
            read(&self.post_action_tasks_aborted_total),
            read(&self.post_action_capacity_rejections_total),
        );
        let _ = write!(
            rendered,
            concat!(
                "# TYPE xmpp_caps_effect_queue_saturated_total counter\n",
                "xmpp_caps_effect_queue_saturated_total {}\n",
                "# TYPE xmpp_caps_effect_coalesced_total counter\n",
                "xmpp_caps_effect_coalesced_total {}\n",
                "# TYPE xmpp_caps_effect_failures_total counter\n",
                "xmpp_caps_effect_failures_total {}\n"
            ),
            read(&self.caps_effect_queue_saturated_total),
            read(&self.caps_effect_coalesced_total),
            read(&self.caps_effect_failures_total),
        );
        self.authentication_duration_seconds.render_into(
            &mut rendered,
            "xmpp_authentication_duration_seconds",
            "Authentication exchange processing duration.",
        );
        self.database_operation_duration_seconds.render_into(
            &mut rendered,
            "xmpp_database_operation_duration_seconds",
            "Database operation duration at instrumented service boundaries.",
        );
        self.routing_duration_seconds.render_into(
            &mut rendered,
            "xmpp_routing_duration_seconds",
            "Message routing admission duration.",
        );
        self.outbox_delivery_duration_seconds.render_into(
            &mut rendered,
            "xmpp_outbox_delivery_duration_seconds",
            "Durable outbox delivery attempt duration.",
        );
        self.redis_operation_duration_seconds.render_into(
            &mut rendered,
            "xmpp_redis_operation_duration_seconds",
            "Redis control-plane operation duration.",
        );
        self.upload_operation_duration_seconds.render_into(
            &mut rendered,
            "xmpp_upload_operation_duration_seconds",
            "HTTP Upload operation duration.",
        );
        self.caps_effect_latency_seconds.render_into(
            &mut rendered,
            "xmpp_caps_effect_latency_seconds",
            "XEP-0115 side-effect queue admission through completion latency.",
        );
        rendered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omemo_poll_metrics_are_fixed_cardinality() {
        let metrics = Metrics::default();
        metrics
            .omemo_recovery_poll_requests_total
            .store(4, Ordering::Relaxed);
        metrics
            .omemo_recovery_poll_rate_limited_total
            .store(2, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_omemo_recovery_poll_requests_total 4\n"));
        assert!(rendered.contains("xmpp_omemo_recovery_poll_rate_limited_total 2\n"));
        assert!(!rendered.contains("client_ip="));
    }

    #[test]
    fn post_commit_protocol_failures_are_exported_separately() {
        let metrics = Metrics::default();
        metrics
            .pubsub_post_commit_delivery_failures_total
            .store(2, Ordering::Relaxed);
        metrics
            .pep_post_commit_delivery_failures_total
            .store(3, Ordering::Relaxed);
        metrics
            .muc_post_commit_delivery_failures_total
            .store(4, Ordering::Relaxed);
        metrics
            .mix_post_commit_delivery_failures_total
            .store(5, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_pubsub_post_commit_delivery_failures_total 2\n"));
        assert!(rendered.contains("xmpp_pep_post_commit_delivery_failures_total 3\n"));
        assert!(rendered.contains("xmpp_muc_post_commit_delivery_failures_total 4\n"));
        assert!(rendered.contains("xmpp_mix_post_commit_delivery_failures_total 5\n"));
    }

    #[test]
    fn carbon_post_accept_failures_have_a_dedicated_metric() {
        let metrics = Metrics::default();
        metrics
            .carbon_post_accept_delivery_failures_total
            .store(7, Ordering::Relaxed);
        metrics
            .carbon_fanout_target_timeouts_total
            .store(3, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_carbon_post_accept_delivery_failures_total 7\n"));
        assert!(rendered.contains("xmpp_carbon_fanout_target_timeouts_total 3\n"));
    }

    #[test]
    fn account_deletion_recovery_is_observable_without_identity_labels() {
        let metrics = Metrics::default();
        metrics
            .account_deletion_recovery_success_total
            .store(2, Ordering::Relaxed);
        metrics
            .account_deletion_recovery_failures_total
            .store(3, Ordering::Relaxed);
        metrics
            .account_deletion_recovery_lease_losses_total
            .store(5, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_account_deletion_recovery_success_total 2\n"));
        assert!(rendered.contains("xmpp_account_deletion_recovery_failures_total 3\n"));
        assert!(rendered.contains("xmpp_account_deletion_recovery_lease_losses_total 5\n"));
        assert!(!rendered.contains("user_id="));
    }

    #[test]
    fn upload_storage_metrics_are_fixed_cardinality_and_exported() {
        let metrics = Metrics::default();
        metrics
            .upload_storage_promotion_success_total
            .store(2, Ordering::Relaxed);
        metrics
            .upload_storage_capacity_ledger_mismatches
            .store(1, Ordering::Relaxed);
        metrics
            .upload_storage_capacity_authority_violations
            .store(2, Ordering::Relaxed);
        metrics
            .upload_storage_safety_gate_state
            .store(4, Ordering::Relaxed);
        metrics
            .upload_storage_integrity_failures_total
            .store(3, Ordering::Relaxed);
        metrics
            .upload_storage_jobs_pending
            .store(5, Ordering::Relaxed);
        metrics
            .upload_storage_oldest_pending_age_seconds
            .store(7, Ordering::Relaxed);
        metrics
            .upload_storage_scrub_success_total
            .store(11, Ordering::Relaxed);
        metrics
            .upload_storage_scrub_failures_total
            .store(13, Ordering::Relaxed);
        metrics
            .upload_storage_dead_letter_jobs
            .store(17, Ordering::Relaxed);
        metrics
            .upload_storage_scrub_failures
            .store(19, Ordering::Relaxed);
        metrics
            .upload_storage_scrub_due_capped
            .store(23, Ordering::Relaxed);
        metrics
            .upload_storage_scrub_oldest_overdue_seconds
            .store(29, Ordering::Relaxed);
        metrics
            .upload_storage_cleanup_obligations_due_capped
            .store(31, Ordering::Relaxed);
        metrics
            .upload_storage_cleanup_oldest_overdue_seconds
            .store(37, Ordering::Relaxed);
        metrics
            .upload_storage_cleanup_obligation_debt
            .store(41, Ordering::Relaxed);
        metrics
            .upload_storage_configured_pending_limit
            .store(43, Ordering::Relaxed);
        metrics
            .upload_storage_legacy_overcommit_draining
            .store(1, Ordering::Relaxed);
        metrics
            .upload_storage_recovery_retained_files
            .store(47, Ordering::Relaxed);
        metrics
            .upload_storage_recovery_retained_bytes
            .store(53, Ordering::Relaxed);
        metrics
            .upload_storage_recovery_overcommit_draining
            .store(1, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_upload_storage_promotion_success_total 2\n"));
        assert!(rendered.contains("xmpp_upload_storage_capacity_ledger_mismatches 1\n"));
        assert!(rendered.contains("xmpp_upload_storage_capacity_authority_violations 2\n"));
        assert!(rendered.contains("xmpp_upload_storage_safety_gate_state 4\n"));
        assert!(rendered.contains("xmpp_upload_storage_integrity_failures_total 3\n"));
        assert!(rendered.contains("xmpp_upload_storage_jobs_pending 5\n"));
        assert!(rendered.contains("xmpp_upload_storage_oldest_pending_age_seconds 7\n"));
        assert!(rendered.contains("xmpp_upload_storage_scrub_success_total 11\n"));
        assert!(rendered.contains("xmpp_upload_storage_scrub_failures_total 13\n"));
        assert!(rendered.contains(
            "# HELP xmpp_upload_storage_dead_letter_jobs Saturating health count; 1001 means at least 1001 dead letters.\n"
        ));
        assert!(rendered.contains("xmpp_upload_storage_dead_letter_jobs 17\n"));
        assert!(rendered.contains(
            "# HELP xmpp_upload_storage_scrub_failures Saturating health count; 1001 means at least 1001 persistent scrub failures.\n"
        ));
        assert!(rendered.contains("xmpp_upload_storage_scrub_failures 19\n"));
        assert!(rendered.contains("xmpp_upload_storage_scrub_due_capped 23\n"));
        assert!(rendered.contains("xmpp_upload_storage_scrub_oldest_overdue_seconds 29\n"));
        assert!(rendered.contains("xmpp_upload_storage_cleanup_obligations_due_capped 31\n"));
        assert!(rendered.contains("xmpp_upload_storage_cleanup_oldest_overdue_seconds 37\n"));
        assert!(rendered.contains("xmpp_upload_storage_cleanup_obligation_debt 41\n"));
        assert!(rendered.contains("xmpp_upload_storage_configured_pending_limit 43\n"));
        assert!(rendered.contains("xmpp_upload_storage_legacy_overcommit_draining 1\n"));
        assert!(rendered.contains("xmpp_upload_storage_recovery_retained_files 47\n"));
        assert!(rendered.contains("xmpp_upload_storage_recovery_retained_bytes 53\n"));
        assert!(rendered.contains("xmpp_upload_storage_recovery_overcommit_draining 1\n"));
        assert!(!rendered.contains("upload_id="));
    }

    #[test]
    fn online_delivery_boundaries_have_separate_metrics() {
        let metrics = Metrics::default();
        metrics
            .online_queue_volatile_acceptances_total
            .store(11, Ordering::Relaxed);
        metrics
            .online_queue_durable_acceptances_total
            .store(13, Ordering::Relaxed);
        metrics
            .c2s_backpressure_disconnects_total
            .store(17, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_online_queue_volatile_acceptances_total 11\n"));
        assert!(rendered.contains("xmpp_online_queue_durable_acceptances_total 13\n"));
        assert!(rendered.contains("xmpp_c2s_backpressure_disconnects_total 17\n"));
    }

    #[test]
    fn deployment_capacity_failures_are_exported() {
        let metrics = Metrics::default();
        metrics
            .capacity_reservations_rejected_total
            .store(19, Ordering::Relaxed);
        metrics
            .capacity_session_lease_losses_total
            .store(23, Ordering::Relaxed);
        let rendered = metrics.render();
        assert!(rendered.contains("xmpp_capacity_reservations_rejected_total 19\n"));
        assert!(rendered.contains("xmpp_capacity_session_lease_losses_total 23\n"));
    }

    #[test]
    fn certificate_revocation_rechecks_and_exact_drains_are_exported() {
        let metrics = Metrics::default();
        metrics
            .tls_revocation_rechecks_total
            .store(29, Ordering::Relaxed);
        metrics
            .tls_revocation_recheck_inconclusive_total
            .store(3, Ordering::Relaxed);
        metrics
            .tls_revoked_sessions_drained_total
            .store(5, Ordering::Relaxed);
        metrics
            .tls_revoked_c2s_external_sessions_drained_total
            .store(1, Ordering::Relaxed);
        metrics
            .tls_revoked_inbound_s2s_external_sessions_drained_total
            .store(2, Ordering::Relaxed);
        metrics
            .tls_revoked_outbound_s2s_external_sessions_drained_total
            .store(2, Ordering::Relaxed);

        let rendered = metrics.render();
        for expected in [
            "xmpp_tls_revocation_rechecks_total 29\n",
            "xmpp_tls_revocation_recheck_inconclusive_total 3\n",
            "xmpp_tls_revoked_sessions_drained_total 5\n",
            "xmpp_tls_revoked_c2s_external_sessions_drained_total 1\n",
            "xmpp_tls_revoked_inbound_s2s_external_sessions_drained_total 2\n",
            "xmpp_tls_revoked_outbound_s2s_external_sessions_drained_total 2\n",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn outbox_and_component_metrics_have_independent_names() {
        let metrics = Metrics::default();
        metrics.s2s_outbox_retries_total.store(2, Ordering::Relaxed);
        metrics.s2s_outbox_expired_total.store(3, Ordering::Relaxed);
        metrics
            .s2s_outbox_permanent_failures_total
            .store(4, Ordering::Relaxed);
        metrics
            .s2s_outbox_lease_lost_total
            .store(5, Ordering::Relaxed);
        metrics
            .component_connections_active
            .store(6, Ordering::Relaxed);
        metrics
            .component_deliveries_total
            .store(7, Ordering::Relaxed);
        metrics.component_failures_total.store(8, Ordering::Relaxed);
        metrics
            .federation_outbound_deliveries_total
            .store(9, Ordering::Relaxed);

        let rendered = metrics.render();
        for expected in [
            "xmpp_s2s_outbox_retries_total 2\n",
            "xmpp_s2s_outbox_expired_total 3\n",
            "xmpp_s2s_outbox_permanent_failures_total 4\n",
            "xmpp_s2s_outbox_lease_lost_total 5\n",
            "xmpp_component_connections_active 6\n",
            "xmpp_component_deliveries_total 7\n",
            "xmpp_component_failures_total 8\n",
            "xmpp_federation_outbound_deliveries_total 9\n",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn duration_histograms_are_cumulative_bounded_and_label_free() {
        let metrics = Metrics::default();
        metrics
            .routing_duration_seconds
            .observe(Duration::from_micros(750));
        metrics
            .routing_duration_seconds
            .observe(Duration::from_secs(20));
        let rendered = metrics.render();
        assert!(rendered.contains("# TYPE xmpp_routing_duration_seconds histogram\n"));
        assert!(rendered.contains("xmpp_routing_duration_seconds_bucket{le=\"0.0005\"} 0\n"));
        assert!(rendered.contains("xmpp_routing_duration_seconds_bucket{le=\"0.001\"} 1\n"));
        assert!(rendered.contains("xmpp_routing_duration_seconds_bucket{le=\"10\"} 1\n"));
        assert!(rendered.contains("xmpp_routing_duration_seconds_bucket{le=\"+Inf\"} 2\n"));
        assert!(rendered.contains("xmpp_routing_duration_seconds_count 2\n"));
        for forbidden in ["jid=", "username=", "domain=", "request_id="] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn caps_effect_capacity_failure_and_latency_metrics_are_exported() {
        let metrics = Metrics::default();
        metrics
            .caps_effect_queue_saturated_total
            .store(2, Ordering::Relaxed);
        metrics
            .caps_effect_coalesced_total
            .store(3, Ordering::Relaxed);
        metrics
            .caps_effect_failures_total
            .store(4, Ordering::Relaxed);
        metrics
            .caps_effect_latency_seconds
            .observe(Duration::from_millis(5));
        let rendered = metrics.render();
        for expected in [
            "xmpp_caps_effect_queue_saturated_total 2\n",
            "xmpp_caps_effect_coalesced_total 3\n",
            "xmpp_caps_effect_failures_total 4\n",
            "xmpp_caps_effect_latency_seconds_count 1\n",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn duration_timer_records_on_every_return_path() {
        let histogram = DurationHistogram::default();
        {
            let _timer = histogram.start_timer();
        }
        let mut rendered = String::new();
        histogram.render_into(&mut rendered, "test_duration_seconds", "test");
        assert!(rendered.contains("test_duration_seconds_count 1\n"));
    }
}
