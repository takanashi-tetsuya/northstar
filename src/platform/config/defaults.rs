//! Default values of the raw configuration fields.

use super::*;

// Defaults
pub(super) fn default_domain() -> String {
    "localhost".to_string()
}
pub(super) fn default_server_name() -> String {
    "Northstar".to_string()
}
pub(super) fn default_db_max_connections() -> u32 {
    32
}

pub(super) fn default_cluster_signing_key_epoch() -> i64 {
    1
}
pub(super) fn default_cluster_failure_policy() -> String {
    "fail_closed".to_owned()
}
pub(super) fn default_cluster_safety_lease_seconds() -> u64 {
    120
}
pub(super) fn default_db_min_connections() -> u32 {
    2
}
pub(super) fn default_scram_iterations() -> u32 {
    northstar_auth_core::DEFAULT_SCRAM_ITERATIONS
}
pub(super) fn default_fast_token_ttl() -> i64 {
    30
}
pub(super) fn default_fast_token_rotation() -> i64 {
    7
}
pub(super) fn default_fast_strong_reauth() -> i64 {
    90
}
pub(super) fn default_sm_resume_timeout() -> u64 {
    300
}
pub(super) fn default_sm_live_lease() -> u64 {
    // Redis cluster node ownership expires after 90 seconds. A crash-recovery
    // claim must not race a still-alive node, so the durable lease is longer.
    120
}
pub(super) fn default_sm_claim_lease() -> u64 {
    30
}
pub(super) fn default_sm_max_unacked_stanzas() -> usize {
    512
}
pub(super) fn default_sm_max_unacked_bytes() -> usize {
    4 * 1024 * 1024
}
pub(super) fn default_sm_max_snapshot_bytes() -> usize {
    4 * 1024 * 1024
}
pub(super) fn default_sm_memory_budget_bytes() -> usize {
    1024 * 1024 * 1024
}
pub(super) fn default_sm_recovery_max_bytes() -> usize {
    256 * 1024 * 1024
}
pub(super) fn default_sm_recovery_max_jobs() -> usize {
    1024
}
pub(super) fn default_sm_max_resumable_sessions() -> usize {
    4096
}
pub(super) fn default_sm_ip_binding() -> String {
    "subnet".to_owned()
}
pub(super) fn default_turn_credentials_ttl() -> u64 {
    3600
}
pub(super) fn default_turn_credential_requests_per_minute() -> usize {
    12
}
pub(super) fn default_offline_message_ttl() -> i64 {
    30
}
pub(super) fn default_mam_retention_days() -> i64 {
    365
}
pub(super) fn default_muc_mam_retention_days() -> i64 {
    365
}
pub(super) fn default_retention_cleanup_batch_size() -> i64 {
    1_000
}
pub(super) fn default_retention_cleanup_interval() -> u64 {
    60
}

pub(super) fn default_moderation_retention_days() -> i64 {
    365
}
pub(super) fn default_audit_log_retention_days() -> i64 {
    730
}
pub(super) fn default_offline_max_messages() -> i64 {
    1_000
}
pub(super) fn default_offline_max_bytes() -> i64 {
    100 * 1024 * 1024
}
pub(super) fn default_xmpp_bind() -> SocketAddr {
    "0.0.0.0:5222".parse().unwrap()
}
pub(super) fn default_xmpps_bind() -> SocketAddr {
    "0.0.0.0:5223".parse().unwrap()
}
pub(super) fn default_http_bind() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}
pub(super) fn default_web_admin_bind() -> SocketAddr {
    "127.0.0.1:8081".parse().unwrap()
}
pub(super) fn default_metrics_bind() -> SocketAddr {
    "127.0.0.1:9091".parse().unwrap()
}
pub(super) fn default_bosh_max_sessions() -> usize {
    2_048
}
pub(super) fn default_bosh_max_body_reads() -> usize {
    128
}
pub(super) fn default_bosh_body_read_timeout() -> u64 {
    15
}
pub(super) fn default_bosh_max_wait() -> u64 {
    60
}
pub(super) fn default_bosh_inactivity() -> u64 {
    30
}
pub(super) fn default_bosh_polling() -> u64 {
    5
}
pub(super) fn default_bosh_max_pause() -> u64 {
    120
}
pub(super) fn default_bosh_max_request_bytes() -> usize {
    1024 * 1024
}
pub(super) fn default_bosh_max_response_bytes() -> usize {
    1024 * 1024
}
pub(super) fn default_bosh_max_stanzas() -> usize {
    64
}
pub(super) fn default_bosh_output_stanzas() -> usize {
    128
}
pub(super) fn default_bosh_output_bytes() -> usize {
    4 * 1024 * 1024
}
pub(super) fn default_tls_cert_path() -> PathBuf {
    PathBuf::from("certs/server.crt")
}
pub(super) fn default_tls_key_path() -> PathBuf {
    PathBuf::from("certs/server.key")
}
pub(super) fn default_true() -> bool {
    true
}
pub(super) fn default_false() -> bool {
    false
}
pub(super) fn default_federation_dane_mode() -> String {
    "off".to_owned()
}
pub(super) fn default_registration_rate() -> u32 {
    20
}
pub(super) fn default_pow_base() -> u64 {
    1024
}
pub(super) fn default_pow_max() -> u64 {
    524288
}
pub(super) fn default_message_free_burst() -> usize {
    60
}
pub(super) fn default_pow_max_device_seconds() -> u64 {
    8
}
pub(super) fn default_abuse_window() -> u64 {
    60
}
pub(super) fn default_abuse_cooldown() -> u64 {
    60
}
pub(super) fn default_abuse_wait() -> u64 {
    900
}
pub(super) fn default_abuse_state_hmac_key_epoch() -> i64 {
    1
}
pub(super) fn default_trusted_ips() -> String {
    "127.0.0.1,::1".to_string()
}
pub(super) fn default_session_ttl() -> i64 {
    168
}
pub(super) fn default_max_client_connections() -> usize {
    4096
}
pub(super) fn default_max_connections_per_ip() -> usize {
    512
}
pub(super) fn default_max_sessions_per_account() -> usize {
    64
}
pub(super) fn default_deployment_capacity_epoch() -> i64 {
    1
}
pub(super) fn default_max_accounts_total() -> i64 {
    100_000
}
pub(super) fn default_max_muc_rooms_total() -> i64 {
    10_000
}
pub(super) fn default_max_muc_rooms_per_owner() -> i64 {
    100
}
pub(super) fn default_max_live_sessions_total() -> i64 {
    4_096
}
pub(super) fn default_capacity_session_lease() -> u64 {
    120
}
pub(super) fn default_capacity_session_heartbeat() -> u64 {
    30
}
pub(super) fn default_unauthenticated_timeout() -> u64 {
    30
}
pub(super) fn default_resource_bind_timeout() -> u64 {
    30
}
pub(super) fn default_pubsub_max_nodes_per_owner() -> i64 {
    100
}
pub(super) fn default_pep_max_nodes_per_account() -> i64 {
    100
}
pub(super) fn default_pubsub_max_storage_per_owner() -> i64 {
    100 * 1024 * 1024
}
pub(super) fn default_pep_max_storage_per_account() -> i64 {
    100 * 1024 * 1024
}
pub(super) fn default_upload_dir() -> PathBuf {
    PathBuf::from("data/uploads")
}
pub(super) fn default_upload_storage_backend() -> String {
    "local".to_owned()
}
pub(super) fn default_upload_s3_region() -> String {
    "us-east-1".to_owned()
}
pub(super) fn default_upload_s3_prefix() -> String {
    "northstar/uploads".to_owned()
}
pub(super) fn default_upload_s3_credential_mode() -> String {
    "ambient".to_owned()
}
pub(super) fn default_upload_s3_cleanup_mode() -> String {
    "exact-version".to_owned()
}
pub(super) fn default_xep_0487_ttl() -> u64 {
    300
}
pub(super) fn default_xep_0487_priority() -> u16 {
    10
}
pub(super) fn default_xep_0487_weight() -> u16 {
    50
}
pub(super) fn default_upload_max() -> u64 {
    26214400
}
pub(super) fn default_upload_download_max_bytes() -> u64 {
    50 * 1024 * 1024
}
pub(super) fn default_upload_mode() -> UploadMode {
    UploadMode::Enabled
}
pub(super) fn default_upload_max_files_per_user() -> i64 {
    1_000
}
pub(super) fn default_upload_max_bytes_per_user() -> i64 {
    1024 * 1024 * 1024
}
pub(super) fn default_upload_download_concurrency() -> usize {
    64
}
pub(super) fn default_upload_download_per_ip() -> usize {
    8
}
pub(super) fn default_upload_download_read_timeout() -> u64 {
    30
}
pub(super) fn default_upload_download_max_seconds() -> u64 {
    600
}
pub(super) fn default_upload_storage_max_pending_jobs() -> i64 {
    100_000
}
pub(super) fn default_upload_storage_max_retained_files() -> i64 {
    1_000_000
}
pub(super) fn default_upload_storage_max_retained_bytes() -> i64 {
    1024_i64 * 1024 * 1024 * 1024
}
pub(super) fn default_upload_retention_seconds() -> u64 {
    30 * 24 * 60 * 60
}
pub(super) fn default_s2s_bind() -> SocketAddr {
    "0.0.0.0:5269".parse().unwrap()
}
pub(super) fn default_s2s_tls_bind() -> SocketAddr {
    "0.0.0.0:5270".parse().unwrap()
}
pub(super) fn default_max_s2s_connections() -> usize {
    512
}
pub(super) fn default_component_bind() -> SocketAddr {
    "127.0.0.1:5347".parse().unwrap()
}
pub(super) fn default_max_component_connections() -> usize {
    128
}
pub(super) fn default_component_handshake_timeout() -> u64 {
    15
}
pub(super) fn default_component_queue_capacity() -> usize {
    512
}
pub(super) fn default_s2s_outbox_ttl() -> u64 {
    7 * 24 * 60 * 60
}
pub(super) fn default_s2s_outbox_max_rows() -> i64 {
    100_000
}
pub(super) fn default_s2s_outbox_max_bytes() -> i64 {
    1024 * 1024 * 1024
}
pub(super) fn default_s2s_outbox_max_per_domain() -> i64 {
    10_000
}
pub(super) fn default_s2s_outbox_retry_base() -> u64 {
    5
}
pub(super) fn default_s2s_outbox_retry_max() -> u64 {
    3600
}
pub(super) fn default_s2s_outbox_max_attempts() -> i32 {
    200
}
pub(super) fn default_s2s_outbox_claim_batch() -> i64 {
    128
}
pub(super) fn default_s2s_outbox_lease() -> u64 {
    120
}
pub(super) fn default_log_dir() -> PathBuf {
    PathBuf::from("logs")
}
pub(super) fn default_log_rotation() -> String {
    "daily".to_string()
}
pub(super) fn default_log_format() -> String {
    "text".to_string()
}
pub(super) fn default_log_retention() -> usize {
    30
}
pub(super) fn default_admin_idle_seconds() -> u64 {
    900
}
