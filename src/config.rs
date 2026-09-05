use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use zeroize::{Zeroize, Zeroizing};

use northstar_web_surface::{
    DownloadCeiling, ListenerConfiguration, RegistrationDependencyLock, RequestedWebCapabilities,
    ResolvedWebCapabilities, UploadRuntimeFacts,
};
pub use northstar_web_surface::{RegistrationMode, UploadMode};

#[derive(Deserialize)]
pub struct RawConfig {
    #[serde(default = "default_domain")]
    pub xmpp_domain: String,

    #[serde(default = "default_server_name")]
    pub server_name: String,

    #[serde(default)]
    pub admin_addresses: Vec<String>,
    #[serde(default)]
    pub abuse_addresses: Vec<String>,
    #[serde(default)]
    pub support_addresses: Vec<String>,
    #[serde(default)]
    pub feedback_addresses: Vec<String>,
    #[serde(default)]
    pub sales_addresses: Vec<String>,
    #[serde(default)]
    pub security_addresses: Vec<String>,

    #[serde(default)]
    pub database_url: String,

    pub database_url_file: Option<PathBuf>,

    /// Dedicated no-table-access login used only to mint and manage opaque
    /// XEP-0133 command sessions. It must not be the runtime or migrator URL.
    #[serde(default)]
    pub admin_command_database_url: String,
    pub admin_command_database_url_file: Option<PathBuf>,

    /// Optional Redis endpoint for the experimental multi-node routing layer.
    /// A normal single-node deployment does not require Redis.
    pub redis_url: Option<String>,
    pub redis_url_file: Option<PathBuf>,
    /// Optional private PKIX root and mTLS identity for a `rediss://` control
    /// plane. The client certificate and key must be configured together.
    pub redis_tls_ca_cert_path: Option<PathBuf>,
    pub redis_tls_client_cert_path: Option<PathBuf>,
    pub redis_tls_client_key_path: Option<PathBuf>,
    /// Stable operator-assigned cluster identity. Redis-enabled nodes must
    /// also mount an Ed25519 private key and an exact peer ACL document.
    pub cluster_node_id: Option<String>,
    pub cluster_signing_private_key_file: Option<PathBuf>,
    pub cluster_signing_previous_public_key_file: Option<PathBuf>,
    pub cluster_signing_staged_next_public_key_file: Option<PathBuf>,
    pub cluster_peer_keys_file: Option<PathBuf>,
    #[serde(default = "default_cluster_signing_key_epoch")]
    pub cluster_signing_key_epoch: i64,
    #[serde(default = "default_cluster_failure_policy")]
    pub cluster_failure_policy: String,
    #[serde(default = "default_cluster_safety_lease_seconds")]
    pub cluster_safety_lease_seconds: u64,

    #[serde(default = "default_db_max_connections")]
    pub database_max_connections: u32,

    pub stun_server: Option<String>,
    pub turn_server: Option<String>,
    pub turn_shared_secret: Option<String>,
    pub turn_shared_secret_file: Option<PathBuf>,
    #[serde(default = "default_turn_credentials_ttl")]
    pub turn_credentials_ttl_seconds: u64,
    #[serde(default = "default_turn_credential_requests_per_minute")]
    pub turn_credential_requests_per_minute: usize,

    #[serde(default = "default_db_min_connections")]
    pub database_min_connections: u32,

    /// Explicit escape hatch for an owner-backed local developer database.
    /// It is rejected unless every listener is loopback, Redis is absent or
    /// uses a local endpoint, and the domain is a reserved localhost/test name.
    #[serde(default)]
    pub database_allow_unsafe_role_for_development: bool,

    #[serde(default = "default_scram_iterations")]
    pub scram_iterations: u32,

    /// Explicit compatibility switch for the obsolete SCRAM-SHA-1 family.
    /// SHA-256 remains advertised first and is always enabled.
    #[serde(default)]
    pub scram_sha1_enabled: bool,

    /// XEP-0484 token derivation key. Prefer FAST_TOKEN_SECRET_FILE in
    /// production so the key never appears in the process environment.
    pub fast_token_secret: Option<String>,
    pub fast_token_secret_file: Option<PathBuf>,
    /// Development-only opt-in for a process-local FAST key. It is accepted
    /// only for a single-node, loopback, reserved-domain setup.
    #[serde(default)]
    pub fast_token_allow_ephemeral_for_development: bool,
    /// Deployment-keyed dummy SCRAM material must not share the FAST root
    /// key: independent rotation prevents a before/after account oracle.
    /// There is deliberately no inline environment-value alternative.
    pub dummy_scram_secret_file: Option<PathBuf>,
    /// Development-only opt-in for an independent process-local dummy SCRAM
    /// key. It has the same single-node/loopback/reserved-domain fence as the
    /// FAST development exception, but is enabled separately.
    #[serde(default)]
    pub dummy_scram_allow_ephemeral_for_development: bool,
    /// Stable HMAC key for de-identifying durable anti-abuse actors. Keep this
    /// separate from FAST token rotation. During rotation configure the old
    /// value as `ABUSE_STATE_HMAC_PREVIOUS_KEY(_FILE)` through the fixed
    /// 30-day tombstone floor and until every live durable old-key reference
    /// has drained.
    pub abuse_state_hmac_key: Option<String>,
    pub abuse_state_hmac_key_file: Option<PathBuf>,
    pub abuse_state_hmac_previous_key: Option<String>,
    pub abuse_state_hmac_previous_key_file: Option<PathBuf>,
    /// Monotonic deployment generation. Increment exactly once when the
    /// current key changes; a rollout with current=new and previous=old opens
    /// the PostgreSQL-authorized overlap for that next epoch.
    #[serde(default = "default_abuse_state_hmac_key_epoch")]
    pub abuse_state_hmac_key_epoch: i64,
    /// Second rotation phase. Enable with both current and previous mounted
    /// only after every node has adopted the overlap keyset. PostgreSQL then
    /// fences old-generation nodes and starts the safe retirement horizon.
    #[serde(default)]
    pub abuse_state_hmac_retire_previous: bool,
    /// Development-only opt-in for a process-local anti-abuse actor key. It is
    /// accepted only for a single-node loopback test deployment.
    #[serde(default)]
    pub abuse_state_allow_ephemeral: bool,
    /// Mounted control-plane key material. There is deliberately no direct
    /// environment-value alternative: replay encryption and idempotency HMAC
    /// keys must come from a permission-checked secret file.
    pub api_control_secret_file: Option<PathBuf>,
    pub api_control_previous_secret_file: Option<PathBuf>,
    /// Development-only opt-in for a process-local idempotency/replay key.
    /// It is rejected with Redis or a non-test/non-loopback deployment.
    #[serde(default)]
    pub api_control_allow_ephemeral: bool,
    #[serde(default = "default_fast_token_ttl")]
    pub fast_token_ttl_days: i64,
    #[serde(default = "default_fast_token_rotation")]
    pub fast_token_rotation_days: i64,
    /// Absolute lifetime of a FAST credential chain before a password/SCRAM
    /// authentication is required again. Rotations inherit, rather than
    /// reset, this deadline.
    #[serde(default = "default_fast_strong_reauth")]
    pub fast_strong_reauth_max_days: i64,

    #[serde(default = "default_sm_resume_timeout")]
    pub sm_resume_timeout_seconds: u64,

    /// Short database lease used to distinguish a live connection from a
    /// process that crashed before it could mark the stream resumable.
    #[serde(default = "default_sm_live_lease")]
    pub sm_live_lease_seconds: u64,
    #[serde(default = "default_sm_claim_lease")]
    pub sm_claim_lease_seconds: u64,
    #[serde(default = "default_sm_max_unacked_stanzas")]
    pub sm_max_unacked_stanzas: usize,
    #[serde(default = "default_sm_max_unacked_bytes")]
    pub sm_max_unacked_bytes: usize,
    /// Complete in-process XEP-0198 snapshot bound, including replay XML and
    /// all resource-scoped metadata retained for exact resume.
    #[serde(default = "default_sm_max_snapshot_bytes")]
    pub sm_max_snapshot_bytes: usize,
    /// Hard process-wide reservation for live and materialized resume state.
    /// Live streams grow an actual-byte lease before retaining more replay
    /// data; a cross-process resume temporarily reserves one maximum snapshot
    /// before the database claim and then shrinks to its measured size.
    #[serde(default = "default_sm_memory_budget_bytes")]
    pub sm_memory_budget_bytes: usize,
    /// Capacity reserved specifically for recovery-queue snapshot ownership.
    #[serde(default = "default_sm_recovery_max_bytes")]
    pub sm_recovery_max_bytes: usize,
    #[serde(default = "default_sm_recovery_max_jobs")]
    pub sm_recovery_max_jobs: usize,
    #[serde(default = "default_sm_max_resumable_sessions")]
    pub sm_max_resumable_sessions: usize,
    #[serde(default = "default_sm_ip_binding")]
    pub sm_ip_binding: String,
    #[serde(default = "default_true")]
    pub sm_require_same_device: bool,

    #[serde(default = "default_offline_message_ttl")]
    pub offline_message_ttl_days: i64,

    /// Upper bound for personal XEP-0313 history. Zero disables automated
    /// deletion; it never means immediate deletion.
    #[serde(default = "default_mam_retention_days")]
    pub mam_retention_days: i64,

    /// Upper bound for room XEP-0313 history. Zero disables automated
    /// deletion; it never means immediate deletion.
    #[serde(default = "default_muc_mam_retention_days")]
    pub muc_mam_retention_days: i64,

    #[serde(default = "default_retention_cleanup_batch_size")]
    pub retention_cleanup_batch_size: i64,

    #[serde(default = "default_retention_cleanup_interval")]
    pub retention_cleanup_interval_seconds: u64,

    /// Resolved reports and their copied evidence are removed after this many
    /// days. Pending reports/appeals are never removed. Zero disables the
    /// automated moderation purge for deployments with a legal hold.
    #[serde(default = "default_moderation_retention_days")]
    pub moderation_retention_days: i64,

    /// Insert-only administrative audit history is removed only through the
    /// bounded database cleanup gate after this many days. Unlike content
    /// retention, zero is not accepted: the audit policy must be explicit and
    /// finite so that privacy-sensitive operational metadata cannot grow
    /// forever.
    #[serde(default = "default_audit_log_retention_days")]
    pub audit_log_retention_days: i64,

    #[serde(default = "default_offline_max_messages")]
    pub offline_max_messages_per_account: i64,

    #[serde(default = "default_offline_max_bytes")]
    pub offline_max_bytes_per_account: i64,

    #[serde(default = "default_xmpp_bind")]
    pub xmpp_bind: SocketAddr,

    #[serde(default = "default_xmpps_bind")]
    pub xmpps_bind: SocketAddr,

    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,

    /// Explicitly enables nonce-bound, child-owned listener readiness records
    /// for hermetic test fixtures. It is rejected outside loopback reserved
    /// domains and is never enabled by a production default.
    #[serde(default)]
    pub test_listener_activation: bool,
    pub test_readiness_file: Option<PathBuf>,
    pub test_readiness_nonce: Option<String>,

    /// Public HTTP capability switches. Routes for disabled capabilities are
    /// not installed at all; handlers therefore cannot be reached through an
    /// alternate path or an accidental static-file fallback.
    #[serde(default = "default_true")]
    pub rest_api_enabled: bool,
    #[serde(default = "default_true")]
    pub websocket_enabled: bool,
    #[serde(default = "default_true")]
    pub web_client_enabled: bool,
    #[serde(default = "default_upload_mode")]
    pub upload_mode: UploadMode,

    /// The administration application and its API have a dedicated listener.
    /// It is loopback-only by default. A non-loopback bind must sit behind a
    /// trusted HTTPS proxy which injects the mounted gateway credential.
    #[serde(default = "default_true")]
    pub web_admin_enabled: bool,
    #[serde(default = "default_web_admin_bind")]
    pub web_admin_bind: SocketAddr,
    pub web_admin_gateway_token_file: Option<PathBuf>,

    /// Dedicated observability listener. It is intentionally separate from
    /// the public HTTP/WebSocket listener so database-backed collection cannot
    /// be exposed accidentally by a custom reverse proxy.
    #[serde(default = "default_metrics_bind")]
    pub metrics_bind: SocketAddr,
    /// Optional bearer credential for the metrics listener. A non-loopback
    /// metrics bind is rejected unless this protected file is configured.
    pub metrics_bearer_token_file: Option<PathBuf>,

    /// Enables XEP-0124/XEP-0206 on `/http-bind` and `/bosh`. Production
    /// clients are accepted only when the HTTP request is known to have
    /// arrived through HTTPS at a trusted reverse proxy.
    #[serde(default = "default_false")]
    pub bosh_enabled: bool,
    #[serde(default = "default_bosh_max_sessions")]
    pub bosh_max_sessions: usize,
    #[serde(default = "default_bosh_max_body_reads")]
    pub bosh_max_concurrent_body_reads: usize,
    #[serde(default = "default_bosh_body_read_timeout")]
    pub bosh_body_read_timeout_seconds: u64,
    #[serde(default = "default_bosh_max_wait")]
    pub bosh_max_wait_seconds: u64,
    #[serde(default = "default_bosh_inactivity")]
    pub bosh_inactivity_seconds: u64,
    #[serde(default = "default_bosh_polling")]
    pub bosh_polling_seconds: u64,
    #[serde(default = "default_bosh_max_pause")]
    pub bosh_max_pause_seconds: u64,
    #[serde(default = "default_bosh_max_request_bytes")]
    pub bosh_max_request_bytes: usize,
    #[serde(default = "default_bosh_max_response_bytes")]
    pub bosh_max_response_bytes: usize,
    #[serde(default = "default_bosh_max_stanzas")]
    pub bosh_max_stanzas_per_request: usize,
    #[serde(default = "default_bosh_output_stanzas")]
    pub bosh_max_output_stanzas: usize,
    #[serde(default = "default_bosh_output_bytes")]
    pub bosh_max_output_bytes: usize,

    #[serde(default = "default_tls_cert_path")]
    pub tls_cert_path: PathBuf,

    #[serde(default = "default_tls_key_path")]
    pub tls_key_path: PathBuf,

    /// Dedicated PKIX roots for optional C2S client-certificate
    /// authentication. System/federation roots are intentionally not reused.
    pub c2s_client_trust_root_cert_path: Option<PathBuf>,

    /// Optional local CRLs for C2S client-certificate authentication. When
    /// configured, revocation status is fail-closed for the complete path.
    pub c2s_client_crl_path: Option<PathBuf>,

    #[serde(default = "default_true")]
    pub open_registration: bool,

    #[serde(default = "default_true")]
    pub require_encrypted_archive: bool,

    #[serde(default = "default_registration_rate")]
    pub registration_rate_per_hour: u32,

    #[serde(default = "default_false")]
    pub invitation_required: bool,

    #[serde(default = "default_pow_base")]
    pub pow_base_work_factor: u64,

    #[serde(default = "default_pow_max")]
    pub pow_max_work_factor: u64,

    #[serde(default = "default_message_free_burst")]
    pub abuse_message_free_burst: usize,

    #[serde(default = "default_pow_max_device_seconds")]
    pub pow_max_device_seconds: u64,

    /// Optional RFC 3339 UTC deadline for accepting legacy challenges which
    /// are not bound to method/path/body. Unset means v2-only. This is a
    /// migration deadline, not a permanent compatibility switch.
    pub pow_v1_compatibility_until: Option<String>,

    #[serde(default = "default_abuse_window")]
    pub abuse_window_seconds: u64,

    #[serde(default = "default_abuse_cooldown")]
    pub abuse_cooldown_seconds: u64,

    #[serde(default = "default_abuse_wait")]
    pub abuse_max_wait_seconds: u64,

    #[serde(default = "default_trusted_ips")]
    pub trusted_proxy_ips: String,

    #[serde(default = "default_session_ttl")]
    pub session_ttl_hours: i64,

    #[serde(default = "default_max_client_connections")]
    pub max_client_connections: usize,

    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,

    #[serde(default = "default_max_sessions_per_account")]
    pub max_sessions_per_account: usize,

    /// Monotonic PostgreSQL authority epoch for deployment-wide resource
    /// ceilings. Every node must present the same values at one epoch; changing
    /// a ceiling requires incrementing this value exactly once for the rollout.
    #[serde(default = "default_deployment_capacity_epoch")]
    pub deployment_capacity_epoch: i64,

    #[serde(default = "default_max_accounts_total")]
    pub max_accounts_total: i64,

    #[serde(default = "default_max_muc_rooms_total")]
    pub max_muc_rooms_total: i64,

    #[serde(default = "default_max_muc_rooms_per_owner")]
    pub max_muc_rooms_per_owner: i64,

    #[serde(default = "default_max_live_sessions_total")]
    pub max_live_sessions_total: i64,

    /// PostgreSQL lease for a committed live binding. Missing heartbeats never
    /// lower a counter directly: maintenance first deletes the expired
    /// authoritative lease, whose trigger releases the exact shard allocation.
    #[serde(default = "default_capacity_session_lease")]
    pub capacity_session_lease_seconds: u64,

    #[serde(default = "default_capacity_session_heartbeat")]
    pub capacity_session_heartbeat_seconds: u64,

    #[serde(default = "default_unauthenticated_timeout")]
    pub unauthenticated_timeout_seconds: u64,

    /// Maximum time after successful SASL for a legacy/unbound stream to bind
    /// a resource. SASL2 Bind 2 and successful inline SM resume are already
    /// bound and therefore never enter this deadline state.
    #[serde(default = "default_resource_bind_timeout")]
    pub resource_bind_timeout_seconds: u64,

    #[serde(default = "default_pubsub_max_nodes_per_owner")]
    pub pubsub_max_nodes_per_owner: i64,

    #[serde(default = "default_pep_max_nodes_per_account")]
    pub pep_max_nodes_per_account: i64,

    #[serde(default = "default_pubsub_max_storage_per_owner")]
    pub pubsub_max_storage_bytes_per_owner: i64,

    #[serde(default = "default_pep_max_storage_per_account")]
    pub pep_max_storage_bytes_per_account: i64,

    /// Enables the Deferred XEP-0408 partial-mirror discovery model. The
    /// default remains false: MUC and MIX are independent services unless an
    /// operator deliberately opts into linking same-owner entities.
    #[serde(default = "default_false")]
    pub mix_muc_mirror_enabled: bool,

    pub bootstrap_admin_username: Option<String>,
    pub bootstrap_admin_password: Option<String>,
    pub bootstrap_admin_password_file: Option<PathBuf>,

    /// Enables XEP-0133 restart/shutdown commands.  Kept separate from the
    /// HTTP factory-reset switch and disabled by default.
    #[serde(default = "default_false")]
    pub enable_xmpp_service_control: bool,

    /// XEP-0133 active/idle boundary based on the last accepted client stanza.
    #[serde(default = "default_admin_idle_seconds")]
    pub admin_idle_seconds: u64,

    pub public_url: Option<String>,

    /// Additional browser origins allowed to open the XMPP WebSocket. The
    /// origin derived from PUBLIC_URL is always implicit; native clients that
    /// omit Origin are unaffected.
    #[serde(default)]
    pub websocket_allowed_origins: String,

    /// Explicit public addresses for XEP-0487. The experimental host-meta v2
    /// marker is emitted only when this list is non-empty, because every
    /// advertised link is required to contain at least one literal IP.
    #[serde(default)]
    pub xep_0487_ips: String,

    #[serde(default = "default_xep_0487_ttl")]
    pub xep_0487_ttl_seconds: u64,

    #[serde(default = "default_xep_0487_priority")]
    pub xep_0487_priority: u16,

    #[serde(default = "default_xep_0487_weight")]
    pub xep_0487_weight: u16,

    /// Independently compiled, runtime-resolved XEP modules. Defaults preserve
    /// the protocol surface from releases before modularization.
    #[serde(default = "default_true")]
    pub xep_0016_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0045_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0059_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0085_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0092_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0115_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0060_enabled: bool,
    /// XEP-0092 requires an operator choice before disclosing the host OS.
    /// This defaults to the historical behavior for upgrade compatibility.
    #[serde(default = "default_true")]
    pub xep_0092_include_os: bool,
    #[serde(default = "default_true")]
    pub xep_0184_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0191_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0198_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0199_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0202_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0215_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0280_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0313_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0352_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0357_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0359_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0363_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0308_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0333_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0380_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0444_enabled: bool,
    #[serde(default = "default_true")]
    pub xep_0461_enabled: bool,

    #[serde(default = "default_upload_dir")]
    pub upload_dir: PathBuf,

    /// `local` is the secure single-node baseline. `s3` uses the maintained
    /// object_store AWS client and immutable attempt-qualified keys.
    #[serde(default = "default_upload_storage_backend")]
    pub upload_storage_backend: String,
    pub upload_s3_endpoint: Option<String>,
    #[serde(default = "default_upload_s3_region")]
    pub upload_s3_region: String,
    pub upload_s3_bucket: Option<String>,
    #[serde(default = "default_upload_s3_prefix")]
    pub upload_s3_prefix: String,
    #[serde(default)]
    pub upload_s3_path_style: bool,
    #[serde(default)]
    pub upload_s3_allow_http: bool,
    #[serde(default = "default_upload_s3_credential_mode")]
    pub upload_s3_credential_mode: String,
    pub upload_s3_credential_bundle_file: Option<PathBuf>,
    pub upload_s3_access_key_id_file: Option<PathBuf>,
    pub upload_s3_secret_access_key_file: Option<PathBuf>,
    pub upload_s3_session_token_file: Option<PathBuf>,
    pub upload_s3_sse_kms_key_id_file: Option<PathBuf>,

    #[serde(default = "default_upload_max")]
    pub upload_max_bytes: u64,
    /// Independent immutable-read ceiling. It may be raised for historical
    /// objects without reopening slot admission in drain-read-only mode.
    #[serde(default = "default_upload_download_max_bytes")]
    pub upload_download_max_bytes: u64,

    #[serde(default = "default_upload_max_files_per_user")]
    pub upload_max_files_per_user: i64,

    #[serde(default = "default_upload_max_bytes_per_user")]
    pub upload_max_bytes_per_user: i64,

    #[serde(default = "default_upload_download_concurrency")]
    pub upload_download_max_concurrent: usize,

    #[serde(default = "default_upload_download_per_ip")]
    pub upload_download_max_per_ip: usize,

    #[serde(default = "default_upload_download_read_timeout")]
    pub upload_download_read_timeout_seconds: u64,

    #[serde(default = "default_upload_download_max_seconds")]
    pub upload_download_max_seconds: u64,

    #[serde(default = "default_upload_storage_max_pending_jobs")]
    pub upload_storage_max_pending_jobs: i64,

    #[serde(default = "default_upload_storage_max_retained_files")]
    pub upload_storage_max_retained_files: i64,

    #[serde(default = "default_upload_storage_max_retained_bytes")]
    pub upload_storage_max_retained_bytes: i64,

    #[serde(default = "default_upload_retention_seconds")]
    pub upload_retention_seconds: u64,

    #[serde(default = "default_s2s_bind")]
    pub s2s_bind: SocketAddr,

    #[serde(default = "default_s2s_tls_bind")]
    pub s2s_tls_bind: SocketAddr,

    #[serde(default = "default_max_s2s_connections")]
    pub max_s2s_connections: usize,

    #[serde(default = "default_component_bind")]
    pub component_bind: SocketAddr,

    #[serde(default = "default_false")]
    pub components_enabled: bool,

    pub components_config_file: Option<PathBuf>,

    #[serde(default = "default_max_component_connections")]
    pub max_component_connections: usize,

    #[serde(default = "default_component_handshake_timeout")]
    pub component_handshake_timeout_seconds: u64,

    #[serde(default = "default_component_queue_capacity")]
    pub component_queue_capacity: usize,

    /// Maximum lifetime of a stanza waiting for a remote federation peer.
    #[serde(default = "default_s2s_outbox_ttl")]
    pub s2s_outbox_ttl_seconds: u64,

    #[serde(default = "default_s2s_outbox_max_rows")]
    pub s2s_outbox_max_rows: i64,

    #[serde(default = "default_s2s_outbox_max_bytes")]
    pub s2s_outbox_max_bytes: i64,

    #[serde(default = "default_s2s_outbox_max_per_domain")]
    pub s2s_outbox_max_per_domain: i64,

    #[serde(default = "default_s2s_outbox_retry_base")]
    pub s2s_outbox_retry_base_seconds: u64,

    #[serde(default = "default_s2s_outbox_retry_max")]
    pub s2s_outbox_retry_max_seconds: u64,

    #[serde(default = "default_s2s_outbox_max_attempts")]
    pub s2s_outbox_max_attempts: i32,

    #[serde(default = "default_s2s_outbox_claim_batch")]
    pub s2s_outbox_claim_batch: i64,

    #[serde(default = "default_s2s_outbox_lease")]
    pub s2s_outbox_lease_seconds: u64,

    #[serde(default = "default_true")]
    pub federation_enabled: bool,

    /// Prefer certificate-authenticated SASL EXTERNAL for S2S. This switch is
    /// primarily useful for interoperability tests and legacy deployments.
    #[serde(default = "default_true")]
    pub s2s_sasl_external_enabled: bool,

    /// Enable TLS-protected, callback-verified XEP-0220 as a compatibility
    /// fallback when SASL EXTERNAL is unavailable.
    #[serde(default = "default_true")]
    pub dialback_enabled: bool,

    pub dialback_secret: Option<String>,
    pub dialback_secret_file: Option<PathBuf>,

    #[serde(default)]
    pub federation_allowlist: String,

    #[serde(default)]
    pub federation_denylist: String,

    #[serde(default = "default_false")]
    pub federation_allow_private_ips: bool,

    #[serde(default)]
    pub federation_dns_overrides: String,

    pub federation_extra_root_cert_path: Option<PathBuf>,

    /// Local RFC 5280 CRLs used by outbound and inbound certificate-
    /// authenticated federation, and by XEP-0487 HTTPS discovery.
    pub federation_crl_path: Option<PathBuf>,

    /// RFC 7712 DNSSEC/DANE policy: off, opportunistic, or required.
    #[serde(default = "default_federation_dane_mode")]
    pub federation_dane_mode: String,

    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,

    #[serde(default = "default_log_rotation")]
    pub log_rotation: String,

    #[serde(default = "default_log_format")]
    pub log_format: String,

    #[serde(default = "default_log_retention")]
    pub log_retention_files: usize,
}

// Defaults
fn default_domain() -> String {
    "localhost".to_string()
}
fn default_server_name() -> String {
    "Northstar".to_string()
}
fn default_db_max_connections() -> u32 {
    32
}
fn default_cluster_signing_key_epoch() -> i64 {
    1
}
fn default_cluster_failure_policy() -> String {
    "fail_closed".to_owned()
}
fn default_cluster_safety_lease_seconds() -> u64 {
    120
}
fn default_db_min_connections() -> u32 {
    2
}
fn default_scram_iterations() -> u32 {
    crate::auth::DEFAULT_SCRAM_ITERATIONS
}
fn default_fast_token_ttl() -> i64 {
    30
}
fn default_fast_token_rotation() -> i64 {
    7
}
fn default_fast_strong_reauth() -> i64 {
    90
}
fn default_sm_resume_timeout() -> u64 {
    300
}
fn default_sm_live_lease() -> u64 {
    // Redis cluster node ownership expires after 90 seconds. A crash-recovery
    // claim must not race a still-alive node, so the durable lease is longer.
    120
}
fn default_sm_claim_lease() -> u64 {
    30
}
fn default_sm_max_unacked_stanzas() -> usize {
    512
}
fn default_sm_max_unacked_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_sm_max_snapshot_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_sm_memory_budget_bytes() -> usize {
    1024 * 1024 * 1024
}
fn default_sm_recovery_max_bytes() -> usize {
    256 * 1024 * 1024
}
fn default_sm_recovery_max_jobs() -> usize {
    1024
}
fn default_sm_max_resumable_sessions() -> usize {
    4096
}
fn default_sm_ip_binding() -> String {
    "subnet".to_owned()
}
fn default_turn_credentials_ttl() -> u64 {
    3600
}
fn default_turn_credential_requests_per_minute() -> usize {
    12
}
fn default_offline_message_ttl() -> i64 {
    30
}
fn default_mam_retention_days() -> i64 {
    365
}
fn default_muc_mam_retention_days() -> i64 {
    365
}
fn default_retention_cleanup_batch_size() -> i64 {
    1_000
}
fn default_retention_cleanup_interval() -> u64 {
    60
}

fn default_moderation_retention_days() -> i64 {
    365
}
fn default_audit_log_retention_days() -> i64 {
    730
}
fn default_offline_max_messages() -> i64 {
    1_000
}
fn default_offline_max_bytes() -> i64 {
    100 * 1024 * 1024
}
fn default_xmpp_bind() -> SocketAddr {
    "0.0.0.0:5222".parse().unwrap()
}
fn default_xmpps_bind() -> SocketAddr {
    "0.0.0.0:5223".parse().unwrap()
}
fn default_http_bind() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}
fn default_web_admin_bind() -> SocketAddr {
    "127.0.0.1:8081".parse().unwrap()
}
fn default_metrics_bind() -> SocketAddr {
    "127.0.0.1:9091".parse().unwrap()
}
fn default_bosh_max_sessions() -> usize {
    2_048
}
fn default_bosh_max_body_reads() -> usize {
    128
}
fn default_bosh_body_read_timeout() -> u64 {
    15
}
fn default_bosh_max_wait() -> u64 {
    60
}
fn default_bosh_inactivity() -> u64 {
    30
}
fn default_bosh_polling() -> u64 {
    5
}
fn default_bosh_max_pause() -> u64 {
    120
}
fn default_bosh_max_request_bytes() -> usize {
    1024 * 1024
}
fn default_bosh_max_response_bytes() -> usize {
    1024 * 1024
}
fn default_bosh_max_stanzas() -> usize {
    64
}
fn default_bosh_output_stanzas() -> usize {
    128
}
fn default_bosh_output_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_tls_cert_path() -> PathBuf {
    PathBuf::from("certs/server.crt")
}
fn default_tls_key_path() -> PathBuf {
    PathBuf::from("certs/server.key")
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_federation_dane_mode() -> String {
    "off".to_owned()
}
fn default_registration_rate() -> u32 {
    20
}
fn default_pow_base() -> u64 {
    1024
}
fn default_pow_max() -> u64 {
    524288
}
fn default_message_free_burst() -> usize {
    60
}
fn default_pow_max_device_seconds() -> u64 {
    8
}
fn default_abuse_window() -> u64 {
    60
}
fn default_abuse_cooldown() -> u64 {
    60
}
fn default_abuse_wait() -> u64 {
    900
}
fn default_abuse_state_hmac_key_epoch() -> i64 {
    1
}
fn default_trusted_ips() -> String {
    "127.0.0.1,::1".to_string()
}
fn default_session_ttl() -> i64 {
    168
}
fn default_max_client_connections() -> usize {
    4096
}
fn default_max_connections_per_ip() -> usize {
    512
}
fn default_max_sessions_per_account() -> usize {
    64
}
fn default_deployment_capacity_epoch() -> i64 {
    1
}
fn default_max_accounts_total() -> i64 {
    100_000
}
fn default_max_muc_rooms_total() -> i64 {
    10_000
}
fn default_max_muc_rooms_per_owner() -> i64 {
    100
}
fn default_max_live_sessions_total() -> i64 {
    4_096
}
fn default_capacity_session_lease() -> u64 {
    120
}
fn default_capacity_session_heartbeat() -> u64 {
    30
}
fn default_unauthenticated_timeout() -> u64 {
    30
}
fn default_resource_bind_timeout() -> u64 {
    30
}
fn default_pubsub_max_nodes_per_owner() -> i64 {
    100
}
fn default_pep_max_nodes_per_account() -> i64 {
    100
}
fn default_pubsub_max_storage_per_owner() -> i64 {
    100 * 1024 * 1024
}
fn default_pep_max_storage_per_account() -> i64 {
    100 * 1024 * 1024
}
fn default_upload_dir() -> PathBuf {
    PathBuf::from("data/uploads")
}
fn default_upload_storage_backend() -> String {
    "local".to_owned()
}
fn default_upload_s3_region() -> String {
    "us-east-1".to_owned()
}
fn default_upload_s3_prefix() -> String {
    "northstar/uploads".to_owned()
}
fn default_upload_s3_credential_mode() -> String {
    "ambient".to_owned()
}
fn default_xep_0487_ttl() -> u64 {
    300
}
fn default_xep_0487_priority() -> u16 {
    10
}
fn default_xep_0487_weight() -> u16 {
    50
}
fn default_upload_max() -> u64 {
    26214400
}
fn default_upload_download_max_bytes() -> u64 {
    50 * 1024 * 1024
}
fn default_upload_mode() -> UploadMode {
    UploadMode::Enabled
}
fn default_upload_max_files_per_user() -> i64 {
    1_000
}
fn default_upload_max_bytes_per_user() -> i64 {
    1024 * 1024 * 1024
}
fn default_upload_download_concurrency() -> usize {
    64
}
fn default_upload_download_per_ip() -> usize {
    8
}
fn default_upload_download_read_timeout() -> u64 {
    30
}
fn default_upload_download_max_seconds() -> u64 {
    600
}
fn default_upload_storage_max_pending_jobs() -> i64 {
    100_000
}
fn default_upload_storage_max_retained_files() -> i64 {
    1_000_000
}
fn default_upload_storage_max_retained_bytes() -> i64 {
    1024_i64 * 1024 * 1024 * 1024
}
fn default_upload_retention_seconds() -> u64 {
    30 * 24 * 60 * 60
}
fn default_s2s_bind() -> SocketAddr {
    "0.0.0.0:5269".parse().unwrap()
}
fn default_s2s_tls_bind() -> SocketAddr {
    "0.0.0.0:5270".parse().unwrap()
}
fn default_max_s2s_connections() -> usize {
    512
}
fn default_component_bind() -> SocketAddr {
    "127.0.0.1:5347".parse().unwrap()
}
fn default_max_component_connections() -> usize {
    128
}
fn default_component_handshake_timeout() -> u64 {
    15
}
fn default_component_queue_capacity() -> usize {
    512
}
fn default_s2s_outbox_ttl() -> u64 {
    7 * 24 * 60 * 60
}
fn default_s2s_outbox_max_rows() -> i64 {
    100_000
}
fn default_s2s_outbox_max_bytes() -> i64 {
    1024 * 1024 * 1024
}
fn default_s2s_outbox_max_per_domain() -> i64 {
    10_000
}
fn default_s2s_outbox_retry_base() -> u64 {
    5
}
fn default_s2s_outbox_retry_max() -> u64 {
    3600
}
fn default_s2s_outbox_max_attempts() -> i32 {
    200
}
fn default_s2s_outbox_claim_batch() -> i64 {
    128
}
fn default_s2s_outbox_lease() -> u64 {
    120
}
fn default_log_dir() -> PathBuf {
    PathBuf::from("logs")
}
fn default_log_rotation() -> String {
    "daily".to_string()
}
fn default_log_format() -> String {
    "text".to_string()
}
fn default_log_retention() -> usize {
    30
}
fn default_admin_idle_seconds() -> u64 {
    900
}

pub struct Config {
    pub raw: RawConfig,
    pub domain: String,
    pub public_url: String,
    pub websocket_allowed_origins: Vec<String>,
    pub trusted_proxy_ips: Vec<IpAddr>,
    pub xep_0487_ips: Vec<IpAddr>,
    pub(crate) xmpp_extensions: Arc<crate::xmpp::extensions::ExtensionRuntime>,
    pub federation_allowlist: Vec<String>,
    pub federation_denylist: Vec<String>,
    /// Test/private-network endpoint overrides. The boolean selects Direct TLS.
    pub federation_dns_overrides: Vec<(String, SocketAddr, bool)>,
    pub federation_dane_mode: crate::s2s::dane::DaneMode,
    pub stun_service: Option<(String, u16)>,
    pub turn_service: Option<(String, u16)>,
    pub components: Vec<ComponentCredential>,
    pub cluster_security: Option<Arc<crate::cluster_security::ClusterSecurityConfig>>,
    /// True only when FAST has a mounted deployment key or the explicit
    /// loopback-only ephemeral development policy was accepted.
    pub(crate) fast_token_enabled: bool,
    pub(crate) dummy_scram_secret: Option<Zeroizing<String>>,
    pub(crate) api_control_secret: Option<String>,
    pub(crate) api_control_previous_secret: Option<String>,
    pub(crate) metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
    pub(crate) web_admin_gateway_token: Option<Arc<Zeroizing<String>>>,
    /// Immutable result of the deployment-surface capability resolver.  All
    /// route, listener and registration decisions derive from this plan.
    pub web_capabilities: Arc<ResolvedWebCapabilities>,
    /// Compatibility projection for older call sites.  The authority is the
    /// registration dependency lock in `web_capabilities`.
    pub invitation_policy_disabled_with_web_client: bool,
    pub pow_v1_compatibility_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone)]
pub struct ComponentCredential {
    pub primary_domain: String,
    pub allowed_domains: Vec<String>,
    /// The validated secret is loaded exactly once during startup and retained
    /// in zeroizing memory. `secret_file` is optional provenance only; runtime
    /// authentication never performs a blocking filesystem read.
    pub secret_value: Option<Arc<Zeroizing<String>>>,
    pub secret_file: Option<PathBuf>,
    pub secret_sha256: [u8; 32],
    pub legacy_0114: bool,
    pub modern_0225: bool,
    pub connection: ComponentConnectionMode,
    pub connect_endpoint: Option<ComponentConnectEndpoint>,
    pub allow_public_connect: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ComponentConnectionMode {
    Accept,
    Connect,
}

fn default_component_connection_mode() -> ComponentConnectionMode {
    ComponentConnectionMode::Accept
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentConnectEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentCredentialFile {
    jid: String,
    secret: Option<String>,
    secret_file: Option<PathBuf>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default = "default_true")]
    legacy_0114: bool,
    #[serde(default = "default_true")]
    modern_0225: bool,
    #[serde(default = "default_component_connection_mode")]
    connection: ComponentConnectionMode,
    connect_endpoint: Option<String>,
    #[serde(default)]
    allow_public_connect: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ComponentConfigDocument {
    List(Vec<ComponentCredentialFile>),
    Object {
        components: Vec<ComponentCredentialFile>,
    },
}

/// Return the canonical serialized origin accepted from a browser `Origin`
/// header or an explicit WebSocket allowlist entry. Only secure origins are
/// accepted outside loopback development hosts.
pub(crate) fn canonical_web_origin(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 2_048 || value.trim() != value || value.contains(',') {
        return None;
    }
    let uri = value.parse::<axum::http::Uri>().ok()?;
    if uri
        .path_and_query()
        .is_some_and(|path| path.as_str() != "/")
    {
        return None;
    }
    canonical_origin_uri(&uri)
}

/// Derive an origin from PUBLIC_URL. A deployment may publish HTTP paths, but
/// browser Origin never contains one, so only scheme/authority participate.
pub(crate) fn canonical_public_web_origin(value: &str) -> Option<String> {
    let uri = value.parse::<axum::http::Uri>().ok()?;
    canonical_origin_uri(&uri)
}

fn canonical_origin_uri(uri: &axum::http::Uri) -> Option<String> {
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(authority.host());
    if host.is_empty() {
        return None;
    }
    if scheme != "https" && !(scheme == "http" && web_origin_host_is_loopback(host)) {
        return None;
    }

    let host = host.to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let port = authority
        .port()
        .map(|port| port.as_str().parse::<u16>())
        .transpose()
        .ok()?;
    let default_port = if scheme == "https" { 443 } else { 80 };
    match port {
        Some(port) if port != default_port => Some(format!("{scheme}://{host}:{port}")),
        _ => Some(format!("{scheme}://{host}")),
    }
}

fn web_origin_host_is_loopback(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost"
        || host
            .strip_suffix(".localhost")
            .is_some_and(|prefix| !prefix.is_empty())
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn validate_redis_transport(
    redis_url: Option<&str>,
    ca_cert: Option<&std::path::Path>,
    client_cert: Option<&std::path::Path>,
    client_key: Option<&std::path::Path>,
) -> Result<()> {
    if client_cert.is_some() != client_key.is_some() {
        anyhow::bail!(
            "REDIS_TLS_CLIENT_CERT_PATH and REDIS_TLS_CLIENT_KEY_PATH must be set together"
        );
    }
    let tls_files = ca_cert.is_some() || client_cert.is_some();
    let Some(redis_url) = redis_url else {
        if tls_files {
            anyhow::bail!("Redis TLS certificate paths require REDIS_URL");
        }
        return Ok(());
    };
    let url = redis::parse_redis_url(redis_url)
        .context("REDIS_URL must be a valid redis, rediss, or local Unix-socket URL")?;
    if url.fragment().is_some() {
        anyhow::bail!("REDIS_URL fragments, including insecure TLS mode, are forbidden");
    }
    match url.scheme() {
        "rediss" | "valkeys" => Ok(()),
        "redis" | "valkey" => {
            if tls_files {
                anyhow::bail!("Redis TLS certificate paths require a rediss:// URL");
            }
            let host = url
                .host_str()
                .context("REDIS_URL TCP endpoints require a host")?;
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .to_ascii_lowercase()
                    .strip_suffix(".localhost")
                    .is_some_and(|prefix| !prefix.is_empty())
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
            if !loopback {
                anyhow::bail!(
                    "unencrypted redis:// is permitted only for an explicit loopback host; use rediss://"
                );
            }
            Ok(())
        }
        "redis+unix" | "valkey+unix" | "unix" => {
            if tls_files {
                anyhow::bail!("Redis TLS certificate paths cannot be used with a Unix socket");
            }
            Ok(())
        }
        _ => anyhow::bail!("REDIS_URL uses an unsupported scheme"),
    }
}

fn redis_endpoint_is_local(redis_url: Option<&str>) -> Result<bool> {
    let Some(redis_url) = redis_url else {
        return Ok(true);
    };
    let url = redis::parse_redis_url(redis_url)
        .context("REDIS_URL must be a valid redis, rediss, or local Unix-socket URL")?;
    match url.scheme() {
        "redis" | "rediss" | "valkey" | "valkeys" => {
            Ok(url.host_str().is_some_and(web_origin_host_is_loopback))
        }
        "redis+unix" | "valkey+unix" | "unix" => Ok(true),
        _ => anyhow::bail!("REDIS_URL uses an unsupported scheme"),
    }
}

fn validate_cluster_dialback_secret(
    clustered: bool,
    dialback_enabled: bool,
    secret_file: Option<&std::path::Path>,
) -> Result<()> {
    if clustered && dialback_enabled && secret_file.is_none() {
        anyhow::bail!(
            "Redis cluster mode with DIALBACK_ENABLED requires DIALBACK_SECRET_FILE so every node verifies the same callback key"
        );
    }
    Ok(())
}

fn validate_cluster_fast_secret(
    clustered: bool,
    secret_file: Option<&std::path::Path>,
) -> Result<()> {
    if clustered && secret_file.is_none() {
        anyhow::bail!(
            "Redis cluster mode requires FAST_TOKEN_SECRET_FILE so every node verifies the same XEP-0484 tokens"
        );
    }
    Ok(())
}

fn validate_shared_runtime_secret(name: &str, secret: Option<&str>) -> Result<()> {
    if secret
        .is_some_and(|secret| secret.len() < 32 || secret.len() > 4096 || secret.contains('\0'))
    {
        anyhow::bail!("{name} must contain 32 to 4096 bytes without NUL");
    }
    Ok(())
}

fn ephemeral_development_secret_allowed(
    opted_in: bool,
    redis_configured: bool,
    listeners_are_loopback: bool,
    reserved_development_domain: bool,
) -> bool {
    opted_in && !redis_configured && listeners_are_loopback && reserved_development_domain
}

fn authentication_master_secrets_are_independent(
    fast: Option<&str>,
    dummy_scram: Option<&str>,
) -> bool {
    !fast.is_some_and(|fast| {
        dummy_scram.is_some_and(|dummy| {
            crate::auth::constant_time_bytes_eq(fast.as_bytes(), dummy.as_bytes())
        })
    })
}

fn requested_registration_mode(raw: &RawConfig) -> RegistrationMode {
    match (raw.open_registration, raw.invitation_required) {
        (false, _) => RegistrationMode::Closed,
        (true, true) => RegistrationMode::InvitationOnly,
        (true, false) => RegistrationMode::Open,
    }
}

fn resolve_web_capability_plan(raw: &RawConfig) -> Result<ResolvedWebCapabilities> {
    let max_concurrent = u32::try_from(raw.upload_download_max_concurrent).ok();
    let upload_ceiling = DownloadCeiling {
        max_bytes: raw.upload_download_max_bytes,
        max_concurrent_streams: max_concurrent,
    };
    RequestedWebCapabilities::default()
        .with_user_rest(raw.rest_api_enabled)
        .with_websocket(raw.websocket_enabled)
        .with_bosh(raw.bosh_enabled)
        .with_web_client(raw.web_client_enabled)
        .with_web_admin(raw.web_admin_enabled)
        .with_upload_mode(raw.upload_mode)
        .with_upload_protocol(raw.xep_0363_enabled)
        // Durable facts are obtained only after the database authority is
        // available.  Disabled plans therefore remain explicitly pending
        // runtime proof and AppState refuses construction unless all facts
        // are empty.
        .with_upload_facts(UploadRuntimeFacts::unknown())
        .with_upload_ceiling(upload_ceiling)
        .with_registration(requested_registration_mode(raw))
        .with_observability(true)
        .with_listeners(
            ListenerConfiguration::new(raw.http_bind, raw.web_admin_bind)
                .with_observability_addr(Some(raw.metrics_bind)),
        )
        .resolve()
        .map_err(anyhow::Error::new)
}

fn validate_web_admin_exposure(enabled: bool, bind: SocketAddr) -> Result<()> {
    if !enabled || bind.ip().is_loopback() {
        return Ok(());
    }
    anyhow::bail!(
        "WEB_ADMIN_BIND must be loopback-only in this release; use a local reverse proxy, SSH tunnel, or future mTLS/Unix-socket transport"
    )
}

fn listener_addresses_overlap(left: SocketAddr, right: SocketAddr) -> bool {
    if left.port() == 0 || right.port() == 0 {
        return false;
    }
    if left.port() != right.port() {
        return false;
    }
    if left.ip() == right.ip() {
        return true;
    }
    if !(left.ip().is_unspecified() || right.ip().is_unspecified()) {
        return false;
    }
    match (left.ip(), right.ip()) {
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
            (left.ip().is_ipv6() && left.ip().is_unspecified())
                || (right.ip().is_ipv6() && right.ip().is_unspecified())
        }
        _ => true,
    }
}

fn validate_listener_plan(raw: &RawConfig, public_http_active: bool) -> Result<()> {
    let mut listeners = vec![
        ("XMPP_BIND", raw.xmpp_bind),
        ("XMPPS_BIND", raw.xmpps_bind),
        ("METRICS_BIND", raw.metrics_bind),
    ];
    if public_http_active {
        listeners.push(("HTTP_BIND", raw.http_bind));
    }
    if raw.web_admin_enabled {
        listeners.push(("WEB_ADMIN_BIND", raw.web_admin_bind));
    }
    if raw.federation_enabled {
        listeners.push(("S2S_BIND", raw.s2s_bind));
        listeners.push(("S2S_TLS_BIND", raw.s2s_tls_bind));
    }
    if raw.components_enabled {
        listeners.push(("COMPONENT_BIND", raw.component_bind));
    }
    for (index, (left_name, left)) in listeners.iter().enumerate() {
        for (right_name, right) in listeners.iter().skip(index + 1) {
            if listener_addresses_overlap(*left, *right) {
                anyhow::bail!(
                    "active listener conflict: {left_name}={left} overlaps {right_name}={right}"
                );
            }
        }
    }
    Ok(())
}

fn validate_test_listener_activation(
    raw: &RawConfig,
    listeners_are_loopback: bool,
    reserved_development_domain: bool,
) -> Result<()> {
    let configured = raw.test_readiness_file.is_some() || raw.test_readiness_nonce.is_some();
    if !raw.test_listener_activation {
        anyhow::ensure!(
            !configured,
            "TEST_READINESS_FILE and TEST_READINESS_NONCE require TEST_LISTENER_ACTIVATION=true"
        );
        return Ok(());
    }
    anyhow::ensure!(
        listeners_are_loopback && reserved_development_domain,
        "TEST_LISTENER_ACTIVATION is restricted to loopback listeners on a reserved development domain"
    );
    let path = raw
        .test_readiness_file
        .as_ref()
        .context("TEST_LISTENER_ACTIVATION requires TEST_READINESS_FILE")?;
    anyhow::ensure!(
        path.is_absolute(),
        "TEST_READINESS_FILE must be an absolute path"
    );
    let nonce = raw
        .test_readiness_nonce
        .as_deref()
        .context("TEST_LISTENER_ACTIVATION requires TEST_READINESS_NONCE")?;
    anyhow::ensure!(
        (16..=128).contains(&nonce.len())
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "TEST_READINESS_NONCE must be 16-128 lowercase hexadecimal characters"
    );
    Ok(())
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let mut raw: RawConfig =
            envy::from_env().context("Failed to parse config from environment")?;
        let xmpp_extensions = Arc::new(crate::xmpp::extensions::ExtensionRuntime::resolve(
            crate::xmpp::extensions::ExtensionSwitches {
                xep_0016: raw.xep_0016_enabled,
                xep_0045: raw.xep_0045_enabled,
                xep_0059: raw.xep_0059_enabled,
                xep_0085: raw.xep_0085_enabled,
                xep_0092: raw.xep_0092_enabled,
                xep_0115: raw.xep_0115_enabled,
                xep_0060: raw.xep_0060_enabled,
                xep_0184: raw.xep_0184_enabled,
                xep_0191: raw.xep_0191_enabled,
                xep_0198: raw.xep_0198_enabled,
                xep_0199: raw.xep_0199_enabled,
                xep_0202: raw.xep_0202_enabled,
                xep_0215: raw.xep_0215_enabled,
                xep_0280: raw.xep_0280_enabled,
                xep_0313: raw.xep_0313_enabled,
                xep_0352: raw.xep_0352_enabled,
                xep_0357: raw.xep_0357_enabled,
                xep_0359: raw.xep_0359_enabled,
                xep_0363: raw.xep_0363_enabled,
                xep_0308: raw.xep_0308_enabled,
                xep_0333: raw.xep_0333_enabled,
                xep_0380: raw.xep_0380_enabled,
                xep_0444: raw.xep_0444_enabled,
                xep_0461: raw.xep_0461_enabled,
            },
        ));
        let web_capabilities = Arc::new(resolve_web_capability_plan(&raw)?);
        let invitation_policy_disabled_with_web_client = matches!(
            web_capabilities.registration.lock,
            RegistrationDependencyLock::LockedWebClientDisabled
        );
        raw.open_registration = !web_capabilities.registration.mode.is_closed();
        raw.invitation_required = web_capabilities.registration.mode.is_invitation_only();
        raw.upload_mode = web_capabilities.upload_mode;
        raw.database_url_file = non_empty_path(raw.database_url_file.take());
        if let Some(path) = &raw.database_url_file {
            if !raw.database_url.trim().is_empty() {
                anyhow::bail!("set only one of DATABASE_URL and DATABASE_URL_FILE");
            }
            raw.database_url = read_secret_file(path, "DATABASE_URL_FILE")?;
        }
        raw.admin_command_database_url_file =
            non_empty_path(raw.admin_command_database_url_file.take());
        if let Some(path) = &raw.admin_command_database_url_file {
            if !raw.admin_command_database_url.trim().is_empty() {
                anyhow::bail!(
                    "set only one of ADMIN_COMMAND_DATABASE_URL and ADMIN_COMMAND_DATABASE_URL_FILE"
                );
            }
            raw.admin_command_database_url =
                read_secret_file(path, "ADMIN_COMMAND_DATABASE_URL_FILE")?;
        }
        raw.bootstrap_admin_username = raw
            .bootstrap_admin_username
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.bootstrap_admin_password = raw
            .bootstrap_admin_password
            .take()
            .filter(|value| !value.is_empty());
        raw.bootstrap_admin_password_file =
            non_empty_path(raw.bootstrap_admin_password_file.take());
        if let Some(path) = &raw.bootstrap_admin_password_file {
            if raw.bootstrap_admin_password.is_some() {
                anyhow::bail!(
                    "set only one of BOOTSTRAP_ADMIN_PASSWORD and BOOTSTRAP_ADMIN_PASSWORD_FILE"
                );
            }
            raw.bootstrap_admin_password =
                Some(read_secret_file(path, "BOOTSTRAP_ADMIN_PASSWORD_FILE")?);
        }
        raw.turn_shared_secret = raw
            .turn_shared_secret
            .take()
            .filter(|value| !value.is_empty());
        raw.turn_shared_secret_file = non_empty_path(raw.turn_shared_secret_file.take());
        if let Some(path) = &raw.turn_shared_secret_file {
            if raw.turn_shared_secret.is_some() {
                anyhow::bail!("set only one of TURN_SHARED_SECRET and TURN_SHARED_SECRET_FILE");
            }
            raw.turn_shared_secret = Some(read_secret_file(path, "TURN_SHARED_SECRET_FILE")?);
        }
        raw.dialback_secret = raw.dialback_secret.take().filter(|value| !value.is_empty());
        raw.dialback_secret_file = non_empty_path(raw.dialback_secret_file.take());
        if let Some(path) = &raw.dialback_secret_file {
            if raw.dialback_secret.is_some() {
                anyhow::bail!("set only one of DIALBACK_SECRET and DIALBACK_SECRET_FILE");
            }
            raw.dialback_secret = Some(read_secret_file(path, "DIALBACK_SECRET_FILE")?);
        }
        raw.fast_token_secret = raw
            .fast_token_secret
            .take()
            .filter(|value| !value.is_empty());
        raw.fast_token_secret_file = non_empty_path(raw.fast_token_secret_file.take());
        if let Some(path) = &raw.fast_token_secret_file {
            if raw.fast_token_secret.is_some() {
                anyhow::bail!("set only one of FAST_TOKEN_SECRET and FAST_TOKEN_SECRET_FILE");
            }
            raw.fast_token_secret = Some(read_secret_file(path, "FAST_TOKEN_SECRET_FILE")?);
        }
        raw.dummy_scram_secret_file = non_empty_path(raw.dummy_scram_secret_file.take());
        let dummy_scram_secret = raw
            .dummy_scram_secret_file
            .as_deref()
            .map(|path| read_secret_file(path, "DUMMY_SCRAM_SECRET_FILE"))
            .transpose()?
            .map(Zeroizing::new);
        raw.abuse_state_hmac_key = raw
            .abuse_state_hmac_key
            .take()
            .filter(|value| !value.is_empty());
        raw.abuse_state_hmac_key_file = non_empty_path(raw.abuse_state_hmac_key_file.take());
        if let Some(path) = &raw.abuse_state_hmac_key_file {
            if raw.abuse_state_hmac_key.is_some() {
                anyhow::bail!("set only one of ABUSE_STATE_HMAC_KEY or ABUSE_STATE_HMAC_KEY_FILE");
            }
            raw.abuse_state_hmac_key = Some(read_secret_file(path, "ABUSE_STATE_HMAC_KEY_FILE")?);
        }
        raw.abuse_state_hmac_previous_key = raw
            .abuse_state_hmac_previous_key
            .take()
            .filter(|value| !value.is_empty());
        raw.abuse_state_hmac_previous_key_file =
            non_empty_path(raw.abuse_state_hmac_previous_key_file.take());
        if let Some(path) = &raw.abuse_state_hmac_previous_key_file {
            if raw.abuse_state_hmac_previous_key.is_some() {
                anyhow::bail!("set only one of ABUSE_STATE_HMAC_PREVIOUS_KEY or ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE");
            }
            raw.abuse_state_hmac_previous_key = Some(read_secret_file(
                path,
                "ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE",
            )?);
        }
        raw.api_control_secret_file = non_empty_path(raw.api_control_secret_file.take());
        raw.api_control_previous_secret_file =
            non_empty_path(raw.api_control_previous_secret_file.take());
        let api_control_secret = raw
            .api_control_secret_file
            .as_ref()
            .map(|path| read_secret_file(path, "API_CONTROL_SECRET_FILE"))
            .transpose()?;
        let api_control_previous_secret = raw
            .api_control_previous_secret_file
            .as_ref()
            .map(|path| read_secret_file(path, "API_CONTROL_PREVIOUS_SECRET_FILE"))
            .transpose()?;
        raw.metrics_bearer_token_file = non_empty_path(raw.metrics_bearer_token_file.take());
        let metrics_bearer_token = raw
            .metrics_bearer_token_file
            .as_ref()
            .map(|path| read_secret_file(path, "METRICS_BEARER_TOKEN_FILE"))
            .transpose()?;
        if metrics_bearer_token
            .as_ref()
            .is_some_and(|token| !valid_http_bearer_secret(token))
        {
            anyhow::bail!(
                "METRICS_BEARER_TOKEN_FILE must contain 32 to 4096 visible ASCII bytes without whitespace"
            );
        }
        if !raw.metrics_bind.ip().is_loopback() && metrics_bearer_token.is_none() {
            anyhow::bail!("a non-loopback METRICS_BIND requires METRICS_BEARER_TOKEN_FILE");
        }
        raw.web_admin_gateway_token_file = non_empty_path(raw.web_admin_gateway_token_file.take());
        let web_admin_gateway_token = if raw.web_admin_enabled {
            raw.web_admin_gateway_token_file
                .as_ref()
                .map(|path| read_secret_file(path, "WEB_ADMIN_GATEWAY_TOKEN_FILE"))
                .transpose()?
        } else {
            // A disabled capability owns no key material and performs no
            // filesystem I/O.  This also permits staged secret rotation while
            // the administration surface is intentionally off.
            None
        };
        if web_admin_gateway_token
            .as_ref()
            .is_some_and(|token| !valid_http_bearer_secret(token))
        {
            anyhow::bail!(
                "WEB_ADMIN_GATEWAY_TOKEN_FILE must contain 32 to 4096 visible ASCII bytes without whitespace"
            );
        }
        if let Some(gateway) = web_admin_gateway_token.as_deref() {
            for (name, other) in [
                ("METRICS_BEARER_TOKEN_FILE", metrics_bearer_token.as_deref()),
                ("API_CONTROL_SECRET_FILE", api_control_secret.as_deref()),
                (
                    "API_CONTROL_PREVIOUS_SECRET_FILE",
                    api_control_previous_secret.as_deref(),
                ),
                ("FAST_TOKEN_SECRET_FILE", raw.fast_token_secret.as_deref()),
                ("DIALBACK_SECRET_FILE", raw.dialback_secret.as_deref()),
                ("TURN_SHARED_SECRET_FILE", raw.turn_shared_secret.as_deref()),
                (
                    "ABUSE_STATE_HMAC_KEY_FILE",
                    raw.abuse_state_hmac_key.as_deref(),
                ),
                (
                    "ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE",
                    raw.abuse_state_hmac_previous_key.as_deref(),
                ),
                (
                    "BOOTSTRAP_ADMIN_PASSWORD_FILE",
                    raw.bootstrap_admin_password.as_deref(),
                ),
            ] {
                if other.is_some_and(|other| {
                    crate::auth::constant_time_bytes_eq(gateway.as_bytes(), other.as_bytes())
                }) {
                    anyhow::bail!(
                        "WEB_ADMIN_GATEWAY_TOKEN_FILE must not reuse {name} key material"
                    );
                }
            }
        }
        raw.public_url = raw
            .public_url
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.redis_url_file = non_empty_path(raw.redis_url_file.take());
        if let Some(path) = &raw.redis_url_file {
            if raw
                .redis_url
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty())
            {
                anyhow::bail!("set only one of REDIS_URL and REDIS_URL_FILE");
            }
            raw.redis_url = Some(read_secret_file(path, "REDIS_URL_FILE")?);
        }
        raw.redis_url = raw
            .redis_url
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.redis_tls_ca_cert_path = non_empty_path(raw.redis_tls_ca_cert_path.take());
        raw.redis_tls_client_cert_path = non_empty_path(raw.redis_tls_client_cert_path.take());
        raw.redis_tls_client_key_path = non_empty_path(raw.redis_tls_client_key_path.take());
        raw.cluster_signing_private_key_file =
            non_empty_path(raw.cluster_signing_private_key_file.take());
        raw.cluster_signing_previous_public_key_file =
            non_empty_path(raw.cluster_signing_previous_public_key_file.take());
        raw.cluster_signing_staged_next_public_key_file =
            non_empty_path(raw.cluster_signing_staged_next_public_key_file.take());
        raw.cluster_peer_keys_file = non_empty_path(raw.cluster_peer_keys_file.take());
        validate_redis_transport(
            raw.redis_url.as_deref(),
            raw.redis_tls_ca_cert_path.as_deref(),
            raw.redis_tls_client_cert_path.as_deref(),
            raw.redis_tls_client_key_path.as_deref(),
        )?;
        raw.federation_extra_root_cert_path = raw
            .federation_extra_root_cert_path
            .take()
            .filter(|path| !path.as_os_str().is_empty());
        raw.federation_crl_path = non_empty_path(raw.federation_crl_path.take());
        raw.c2s_client_trust_root_cert_path = raw
            .c2s_client_trust_root_cert_path
            .take()
            .filter(|path| !path.as_os_str().is_empty());
        raw.c2s_client_crl_path = non_empty_path(raw.c2s_client_crl_path.take());
        raw.components_config_file = non_empty_path(raw.components_config_file.take());
        raw.upload_s3_access_key_id_file = non_empty_path(raw.upload_s3_access_key_id_file.take());
        raw.upload_s3_credential_bundle_file =
            non_empty_path(raw.upload_s3_credential_bundle_file.take());
        raw.upload_s3_secret_access_key_file =
            non_empty_path(raw.upload_s3_secret_access_key_file.take());
        raw.upload_s3_session_token_file = non_empty_path(raw.upload_s3_session_token_file.take());
        raw.upload_s3_sse_kms_key_id_file =
            non_empty_path(raw.upload_s3_sse_kms_key_id_file.take());
        raw.upload_s3_endpoint = raw
            .upload_s3_endpoint
            .take()
            .filter(|value| !value.trim().is_empty());
        raw.upload_s3_bucket = raw
            .upload_s3_bucket
            .take()
            .filter(|value| !value.trim().is_empty());

        let domain = crate::jid::prepare_domainpart(raw.xmpp_domain.trim())
            .context("XMPP_DOMAIN is invalid")?;
        let cluster_fields_present = raw
            .cluster_node_id
            .as_ref()
            .is_some_and(|v| !v.trim().is_empty())
            || raw.cluster_signing_private_key_file.is_some()
            || raw.cluster_signing_previous_public_key_file.is_some()
            || raw.cluster_signing_staged_next_public_key_file.is_some()
            || raw.cluster_peer_keys_file.is_some();
        if raw.redis_url.is_none() && cluster_fields_present {
            anyhow::bail!("cluster signing configuration requires REDIS_URL or REDIS_URL_FILE");
        }
        let cluster_security = raw
            .redis_url
            .as_ref()
            .map(|_| {
                crate::cluster_security::load_configuration(
                    crate::cluster_security::ClusterSecurityConfiguration {
                        namespace: &domain,
                        node_id: raw
                            .cluster_node_id
                            .as_deref()
                            .map(str::trim)
                            .filter(|v| !v.is_empty()),
                        private_key_file: raw.cluster_signing_private_key_file.as_deref(),
                        previous_public_key_file: raw
                            .cluster_signing_previous_public_key_file
                            .as_deref(),
                        staged_next_public_key_file: raw
                            .cluster_signing_staged_next_public_key_file
                            .as_deref(),
                        peer_keys_file: raw.cluster_peer_keys_file.as_deref(),
                        key_epoch: raw.cluster_signing_key_epoch,
                        failure_policy: &raw.cluster_failure_policy,
                        safety_lease_seconds: raw.cluster_safety_lease_seconds,
                    },
                )
            })
            .transpose()?;
        let listeners_are_loopback = [
            raw.xmpp_bind,
            raw.xmpps_bind,
            raw.http_bind,
            raw.metrics_bind,
            raw.s2s_bind,
            raw.s2s_tls_bind,
            raw.component_bind,
        ]
        .iter()
        .all(|address| address.ip().is_loopback())
            && (!raw.web_admin_enabled || raw.web_admin_bind.ip().is_loopback());
        let reserved_development_domain =
            domain == "localhost" || domain.ends_with(".localhost") || domain.ends_with(".test");
        validate_test_listener_activation(
            &raw,
            listeners_are_loopback,
            reserved_development_domain,
        )?;
        let development_redis_is_local = redis_endpoint_is_local(raw.redis_url.as_deref())?;
        let ephemeral_abuse_state_is_allowed = raw.abuse_state_allow_ephemeral
            && raw.redis_url.is_none()
            && listeners_are_loopback
            && reserved_development_domain;
        let ephemeral_fast_is_allowed = ephemeral_development_secret_allowed(
            raw.fast_token_allow_ephemeral_for_development,
            raw.redis_url.is_some(),
            listeners_are_loopback,
            reserved_development_domain,
        );
        let ephemeral_dummy_scram_is_allowed = ephemeral_development_secret_allowed(
            raw.dummy_scram_allow_ephemeral_for_development,
            raw.redis_url.is_some(),
            listeners_are_loopback,
            reserved_development_domain,
        );
        if raw.fast_token_allow_ephemeral_for_development && !ephemeral_fast_is_allowed {
            anyhow::bail!(
                "FAST_TOKEN_ALLOW_EPHEMERAL_FOR_DEVELOPMENT is allowed only for a single-node loopback reserved-domain deployment"
            );
        }
        if !ephemeral_fast_is_allowed && raw.fast_token_secret_file.is_none() {
            anyhow::bail!(
                "production FAST requires FAST_TOKEN_SECRET_FILE; inline or process-local keys are permitted only by explicit loopback development opt-in"
            );
        }
        if raw.dummy_scram_allow_ephemeral_for_development && !ephemeral_dummy_scram_is_allowed {
            anyhow::bail!(
                "DUMMY_SCRAM_ALLOW_EPHEMERAL_FOR_DEVELOPMENT is allowed only for a single-node loopback reserved-domain deployment"
            );
        }
        if !ephemeral_dummy_scram_is_allowed && raw.dummy_scram_secret_file.is_none() {
            anyhow::bail!(
                "production dummy SCRAM requires DUMMY_SCRAM_SECRET_FILE; process-local keys are permitted only by explicit loopback development opt-in"
            );
        }
        if raw.database_allow_unsafe_role_for_development
            && !(development_redis_is_local
                && listeners_are_loopback
                && reserved_development_domain)
        {
            anyhow::bail!(
                "DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT is allowed only for a loopback reserved-domain deployment with absent or loopback Redis"
            );
        }
        if raw.admin_command_database_url.trim().is_empty() {
            if raw.database_allow_unsafe_role_for_development {
                raw.admin_command_database_url = raw.database_url.clone();
            } else {
                anyhow::bail!(
                    "production XEP-0133 commands require ADMIN_COMMAND_DATABASE_URL_FILE (preferred) or ADMIN_COMMAND_DATABASE_URL for the bounded northstar_commands role"
                );
            }
        }
        raw.upload_storage_backend = raw.upload_storage_backend.trim().to_ascii_lowercase();
        raw.upload_s3_credential_mode = raw.upload_s3_credential_mode.trim().to_ascii_lowercase();
        raw.upload_s3_region = raw.upload_s3_region.trim().to_owned();
        raw.upload_s3_prefix = raw.upload_s3_prefix.trim().trim_matches('/').to_owned();
        if raw.upload_mode.keeps_storage_runtime() {
            if !matches!(raw.upload_storage_backend.as_str(), "local" | "s3") {
                anyhow::bail!("UPLOAD_STORAGE_BACKEND must be local or s3");
            }
            if raw.redis_url.is_some()
                && raw.upload_storage_backend != "s3"
                && !(listeners_are_loopback
                    && (domain == "localhost"
                        || domain.ends_with(".localhost")
                        || domain.ends_with(".test")))
            {
                anyhow::bail!(
                    "public Redis cluster mode requires shared UPLOAD_STORAGE_BACKEND=s3"
                );
            }
            if raw.upload_storage_backend == "s3" {
                let bucket = raw
                    .upload_s3_bucket
                    .as_deref()
                    .context("UPLOAD_S3_BUCKET is required for the s3 upload backend")?;
                if !(3..=63).contains(&bucket.len())
                    || bucket.starts_with('.')
                    || bucket.starts_with('-')
                    || bucket.ends_with('.')
                    || bucket.ends_with('-')
                    || bucket.contains("..")
                    || bucket.bytes().any(|byte| {
                        !(byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'.'
                            || byte == b'-')
                    })
                {
                    anyhow::bail!(
                        "UPLOAD_S3_BUCKET must be a canonical lowercase DNS-style bucket name"
                    );
                }
                if raw.upload_s3_region.is_empty()
                    || raw.upload_s3_region.len() > 128
                    || raw
                        .upload_s3_region
                        .chars()
                        .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_')))
                {
                    anyhow::bail!("UPLOAD_S3_REGION is invalid");
                }
                if raw.upload_s3_prefix.len() > 512
                    || (!raw.upload_s3_prefix.is_empty()
                        && raw.upload_s3_prefix.split('/').any(|segment| {
                            segment.is_empty()
                                || matches!(segment, "." | "..")
                                || segment.len() > 128
                                || segment.chars().any(|c| {
                                    !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                                })
                        }))
                {
                    anyhow::bail!("UPLOAD_S3_PREFIX must be a bounded canonical relative prefix");
                }
                let development_storage = listeners_are_loopback
                    && raw.redis_url.is_none()
                    && (domain == "localhost"
                        || domain.ends_with(".localhost")
                        || domain.ends_with(".test"));
                if let Some(endpoint) = raw.upload_s3_endpoint.as_deref() {
                    let uri = endpoint
                        .parse::<axum::http::Uri>()
                        .context("UPLOAD_S3_ENDPOINT must be an absolute HTTP(S) URI")?;
                    let scheme = uri
                        .scheme_str()
                        .context("UPLOAD_S3_ENDPOINT needs a scheme")?;
                    let authority = uri.authority().context("UPLOAD_S3_ENDPOINT needs a host")?;
                    if authority.as_str().contains('@')
                        || uri
                            .path_and_query()
                            .is_some_and(|value| value.as_str() != "/")
                    {
                        anyhow::bail!(
                        "UPLOAD_S3_ENDPOINT cannot contain credentials, a path, query, or fragment"
                    );
                    }
                    match scheme {
                    "https" if !raw.upload_s3_allow_http => {}
                    "http" if raw.upload_s3_allow_http && development_storage => {}
                    "http" => anyhow::bail!("HTTP object storage is allowed only by explicit opt-in in a loopback test deployment"),
                    "https" => anyhow::bail!("UPLOAD_S3_ALLOW_HTTP must be false for an HTTPS endpoint"),
                    _ => anyhow::bail!("UPLOAD_S3_ENDPOINT must use HTTPS"),
                }
                } else if raw.upload_s3_allow_http {
                    anyhow::bail!("UPLOAD_S3_ALLOW_HTTP requires an explicit development endpoint");
                }
                if !development_storage
                    && [
                        "AWS_ACCESS_KEY_ID",
                        "AWS_SECRET_ACCESS_KEY",
                        "AWS_SESSION_TOKEN",
                    ]
                    .iter()
                    .any(|name| std::env::var_os(name).is_some())
                {
                    anyhow::bail!("long-lived inline AWS credential environment variables are forbidden in production; use protected *_FILE mounts or workload credentials");
                }
                match raw.upload_s3_credential_mode.as_str() {
                    "files" => {
                        let bundle = raw.upload_s3_credential_bundle_file.is_some();
                        let legacy_pair = raw.upload_s3_access_key_id_file.is_some()
                            && raw.upload_s3_secret_access_key_file.is_some();
                        let any_legacy = raw.upload_s3_access_key_id_file.is_some()
                            || raw.upload_s3_secret_access_key_file.is_some()
                            || raw.upload_s3_session_token_file.is_some();
                        if bundle == legacy_pair
                            || (bundle && any_legacy)
                            || (!bundle && any_legacy && !legacy_pair)
                        {
                            anyhow::bail!("file S3 credentials require exactly one atomic UPLOAD_S3_CREDENTIAL_BUNDLE_FILE or the legacy access/secret file pair");
                        }
                        if !development_storage && !bundle {
                            anyhow::bail!("production S3 file credentials require the atomically replaced UPLOAD_S3_CREDENTIAL_BUNDLE_FILE");
                        }
                    }
                    "ambient" => {
                        if raw.upload_s3_credential_bundle_file.is_some()
                            || raw.upload_s3_access_key_id_file.is_some()
                            || raw.upload_s3_secret_access_key_file.is_some()
                            || raw.upload_s3_session_token_file.is_some()
                        {
                            anyhow::bail!("ambient S3 credentials cannot be combined with Northstar credential files");
                        }
                        for forbidden in [
                            "AWS_ENDPOINT",
                            "AWS_ENDPOINT_URL_S3",
                            "AWS_ALLOW_HTTP",
                            "AWS_SKIP_SIGNATURE",
                            "AWS_METADATA_ENDPOINT",
                            "AWS_EC2_METADATA_SERVICE_ENDPOINT",
                            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                        ] {
                            if std::env::var_os(forbidden).is_some() {
                                anyhow::bail!(
                                "{forbidden} is not accepted by the constrained S3 provider chain"
                            );
                            }
                        }
                    }
                    _ => anyhow::bail!("UPLOAD_S3_CREDENTIAL_MODE must be files or ambient"),
                }
                if raw.upload_s3_session_token_file.is_some()
                    && raw.upload_s3_credential_mode != "files"
                {
                    anyhow::bail!("UPLOAD_S3_SESSION_TOKEN_FILE requires file credential mode");
                }
            } else if raw.upload_s3_endpoint.is_some()
                || raw.upload_s3_bucket.is_some()
                || raw.upload_s3_access_key_id_file.is_some()
                || raw.upload_s3_credential_bundle_file.is_some()
                || raw.upload_s3_secret_access_key_file.is_some()
                || raw.upload_s3_session_token_file.is_some()
                || raw.upload_s3_sse_kms_key_id_file.is_some()
                || raw.upload_s3_allow_http
            {
                anyhow::bail!("UPLOAD_S3_* settings require UPLOAD_STORAGE_BACKEND=s3");
            }
        }
        if !ephemeral_abuse_state_is_allowed && raw.abuse_state_hmac_key_file.is_none() {
            anyhow::bail!(
                "production abuse state requires ABUSE_STATE_HMAC_KEY_FILE; inline or process-local keys are permitted only in explicit loopback development mode"
            );
        }
        if !ephemeral_abuse_state_is_allowed
            && raw.abuse_state_hmac_previous_key.is_some()
            && raw.abuse_state_hmac_previous_key_file.is_none()
        {
            anyhow::bail!(
                "production abuse-state rotation requires ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE"
            );
        }
        if raw.server_name.trim().is_empty()
            || raw.server_name.len() > 128
            || raw.server_name.chars().any(char::is_control)
        {
            anyhow::bail!("SERVER_NAME must contain 1 to 128 characters without controls");
        }
        raw.server_name = raw.server_name.trim().to_owned();
        if raw.database_url.trim().is_empty() {
            anyhow::bail!("DATABASE_URL must not be empty");
        }
        for (name, addresses) in [
            ("ADMIN_ADDRESSES", &raw.admin_addresses),
            ("ABUSE_ADDRESSES", &raw.abuse_addresses),
            ("SUPPORT_ADDRESSES", &raw.support_addresses),
            ("FEEDBACK_ADDRESSES", &raw.feedback_addresses),
            ("SALES_ADDRESSES", &raw.sales_addresses),
            ("SECURITY_ADDRESSES", &raw.security_addresses),
        ] {
            if addresses.iter().any(|address| {
                address.is_empty()
                    || address.len() > 2_048
                    || !address.contains(':')
                    || address.chars().any(char::is_whitespace)
                    || address.chars().any(char::is_control)
            }) {
                anyhow::bail!("{name} must contain comma-separated URI values without whitespace");
            }
        }
        if raw.database_max_connections == 0
            || raw.database_max_connections > 64
            || raw.database_min_connections > raw.database_max_connections
        {
            anyhow::bail!(
                "DATABASE_MAX_CONNECTIONS must be between 1 and the bounded runtime role limit of 64, and not smaller than DATABASE_MIN_CONNECTIONS"
            );
        }
        if !(crate::auth::MIN_SCRAM_ITERATIONS..=crate::auth::MAX_SCRAM_ITERATIONS)
            .contains(&raw.scram_iterations)
        {
            anyhow::bail!(
                "SCRAM_ITERATIONS must be between {} and {}",
                crate::auth::MIN_SCRAM_ITERATIONS,
                crate::auth::MAX_SCRAM_ITERATIONS
            );
        }
        validate_shared_runtime_secret("FAST_TOKEN_SECRET", raw.fast_token_secret.as_deref())?;
        validate_shared_runtime_secret(
            "DUMMY_SCRAM_SECRET",
            dummy_scram_secret.as_deref().map(String::as_str),
        )?;
        if !authentication_master_secrets_are_independent(
            raw.fast_token_secret.as_deref(),
            dummy_scram_secret.as_deref().map(String::as_str),
        ) {
            anyhow::bail!(
                "DUMMY_SCRAM_SECRET_FILE must contain a key independent from FAST_TOKEN_SECRET_FILE"
            );
        }
        for (name, secret) in [
            ("ABUSE_STATE_HMAC_KEY", raw.abuse_state_hmac_key.as_ref()),
            (
                "ABUSE_STATE_HMAC_PREVIOUS_KEY",
                raw.abuse_state_hmac_previous_key.as_ref(),
            ),
        ] {
            if secret.is_some_and(|secret| {
                secret.len() < 32 || secret.len() > 4096 || secret.contains('\0')
            }) {
                anyhow::bail!("{name} must contain 32 to 4096 bytes without NUL");
            }
        }
        if raw.abuse_state_hmac_key.is_none() && raw.abuse_state_hmac_previous_key.is_some() {
            anyhow::bail!("ABUSE_STATE_HMAC_PREVIOUS_KEY requires ABUSE_STATE_HMAC_KEY");
        }
        if raw.abuse_state_hmac_key_epoch < 1 {
            anyhow::bail!("ABUSE_STATE_HMAC_KEY_EPOCH must be a positive integer");
        }
        if raw.abuse_state_hmac_retire_previous && raw.abuse_state_hmac_previous_key.is_none() {
            anyhow::bail!(
                "ABUSE_STATE_HMAC_RETIRE_PREVIOUS requires ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE"
            );
        }
        if raw.abuse_state_hmac_retire_previous
            && (raw.abuse_state_hmac_key_file.is_none()
                || raw.abuse_state_hmac_previous_key_file.is_none())
        {
            anyhow::bail!(
                "ABUSE_STATE_HMAC_RETIRE_PREVIOUS requires mounted current and previous key files"
            );
        }
        if raw.abuse_state_hmac_previous_key.as_deref() == raw.abuse_state_hmac_key.as_deref()
            && raw.abuse_state_hmac_previous_key.is_some()
        {
            anyhow::bail!("ABUSE_STATE_HMAC_PREVIOUS_KEY must differ from the current key");
        }
        for (name, secret) in [
            ("API_CONTROL_SECRET_FILE", api_control_secret.as_ref()),
            (
                "API_CONTROL_PREVIOUS_SECRET_FILE",
                api_control_previous_secret.as_ref(),
            ),
        ] {
            if secret.is_some_and(|secret| {
                secret.len() < 32 || secret.len() > 4096 || secret.contains('\0')
            }) {
                anyhow::bail!("{name} must contain 32 to 4096 bytes without NUL");
            }
        }
        if api_control_secret.is_none() && api_control_previous_secret.is_some() {
            anyhow::bail!("API_CONTROL_PREVIOUS_SECRET_FILE requires API_CONTROL_SECRET_FILE");
        }
        if !(1..=3650).contains(&raw.fast_token_ttl_days)
            || !(1..=3650).contains(&raw.fast_token_rotation_days)
            || raw.fast_token_rotation_days > raw.fast_token_ttl_days
        {
            anyhow::bail!(
                "FAST token TTL and rotation must be 1..3650 days and rotation must not exceed TTL"
            );
        }
        if !(1..=3650).contains(&raw.fast_strong_reauth_max_days)
            || raw.fast_strong_reauth_max_days < raw.fast_token_ttl_days
        {
            anyhow::bail!(
                "FAST_STRONG_REAUTH_MAX_DAYS must be between FAST_TOKEN_TTL_DAYS and 3650"
            );
        }
        if !(1..=86_400).contains(&raw.sm_resume_timeout_seconds) {
            anyhow::bail!("SM_RESUME_TIMEOUT_SECONDS must be between 1 and 86400");
        }
        if !(5..=300).contains(&raw.sm_live_lease_seconds)
            || !(5..=300).contains(&raw.sm_claim_lease_seconds)
        {
            anyhow::bail!("SM live and claim leases must be between 5 and 300 seconds");
        }
        if !(1..=16_384).contains(&raw.sm_max_unacked_stanzas)
            || !(64 * 1024..=64 * 1024 * 1024).contains(&raw.sm_max_unacked_bytes)
            || !(64 * 1024..=256 * 1024 * 1024).contains(&raw.sm_max_snapshot_bytes)
            || !(64 * 1024..=64 * 1024 * 1024 * 1024).contains(&raw.sm_memory_budget_bytes)
            || !(64 * 1024..=64 * 1024 * 1024 * 1024).contains(&raw.sm_recovery_max_bytes)
            || !(1..=1_000_000).contains(&raw.sm_recovery_max_jobs)
            || !(1..=1_000_000).contains(&raw.sm_max_resumable_sessions)
        {
            anyhow::bail!("SM durable queue/session limits are outside their safe ranges");
        }
        if raw.sm_max_snapshot_bytes < raw.sm_max_unacked_bytes
            || raw.sm_memory_budget_bytes < raw.sm_max_snapshot_bytes
            || raw.sm_recovery_max_bytes < raw.sm_max_snapshot_bytes
        {
            anyhow::bail!(
                "SM snapshot, process-memory, and recovery-queue byte limits are inconsistent"
            );
        }
        if crate::db::SmIpPolicy::parse(&raw.sm_ip_binding).is_none() {
            anyhow::bail!("SM_IP_BINDING must be one of: none, exact, subnet");
        }
        if !(60..=86_400).contains(&raw.turn_credentials_ttl_seconds) {
            anyhow::bail!("TURN_CREDENTIALS_TTL_SECONDS must be between 60 and 86400");
        }
        if !(1..=600).contains(&raw.turn_credential_requests_per_minute) {
            anyhow::bail!("TURN_CREDENTIAL_REQUESTS_PER_MINUTE must be between 1 and 600");
        }
        if !(0..=3650).contains(&raw.offline_message_ttl_days)
            || !(0..=36_500).contains(&raw.mam_retention_days)
            || !(0..=36_500).contains(&raw.muc_mam_retention_days)
            || !(0..=36_500).contains(&raw.moderation_retention_days)
        {
            anyhow::bail!(
                "retention days must be zero (disabled) or within the documented maximum"
            );
        }
        if !(30..=36_500).contains(&raw.audit_log_retention_days) {
            anyhow::bail!("AUDIT_LOG_RETENTION_DAYS must be between 30 and 36500");
        }
        if !(1..=10_000).contains(&raw.retention_cleanup_batch_size)
            || !(60..=86_400).contains(&raw.retention_cleanup_interval_seconds)
        {
            anyhow::bail!(
                "retention cleanup batch size must be 1..10000 and interval 60..86400 seconds"
            );
        }
        if !(1..=100_000).contains(&raw.offline_max_messages_per_account)
            || !(1024 * 1024..=10 * 1024 * 1024 * 1024).contains(&raw.offline_max_bytes_per_account)
        {
            anyhow::bail!("offline queue limits must be 1..100000 messages and 1 MiB..10 GiB");
        }
        if !(1..=8760).contains(&raw.session_ttl_hours) {
            anyhow::bail!("SESSION_TTL_HOURS must be between 1 and 8760");
        }
        if !(100..=1_000_000).contains(&raw.max_client_connections) {
            anyhow::bail!("MAX_CLIENT_CONNECTIONS must be between 100 and 1000000");
        }
        if raw.max_connections_per_ip == 0
            || raw.max_connections_per_ip > raw.max_client_connections
        {
            anyhow::bail!(
                "MAX_CONNECTIONS_PER_IP must be positive and no larger than MAX_CLIENT_CONNECTIONS"
            );
        }
        if !(1..=10_000).contains(&raw.max_sessions_per_account) {
            anyhow::bail!("MAX_SESSIONS_PER_ACCOUNT must be between 1 and 10000");
        }
        if raw.deployment_capacity_epoch < 1 {
            anyhow::bail!("DEPLOYMENT_CAPACITY_EPOCH must be a positive integer");
        }
        if !(1..=100_000_000).contains(&raw.max_accounts_total)
            || !(1..=10_000_000).contains(&raw.max_muc_rooms_total)
            || !(1..=100_000).contains(&raw.max_muc_rooms_per_owner)
            || !(100..=10_000_000).contains(&raw.max_live_sessions_total)
        {
            anyhow::bail!("deployment account, MUC-room, owner-room, or live-session capacity is outside its safe range");
        }
        if raw.max_muc_rooms_per_owner > raw.max_muc_rooms_total {
            anyhow::bail!("MAX_MUC_ROOMS_PER_OWNER cannot exceed MAX_MUC_ROOMS_TOTAL");
        }
        if !(30..=600).contains(&raw.capacity_session_lease_seconds)
            || !(5..=120).contains(&raw.capacity_session_heartbeat_seconds)
            || raw.capacity_session_heartbeat_seconds.saturating_mul(3)
                > raw.capacity_session_lease_seconds
        {
            anyhow::bail!("capacity session lease must be 30..600 seconds and at least three times its 5..120 second heartbeat");
        }
        if !(16..=100_000).contains(&raw.max_s2s_connections) {
            anyhow::bail!("MAX_S2S_CONNECTIONS must be between 16 and 100000");
        }
        if raw.max_component_connections > 10_000
            || !(5..=120).contains(&raw.component_handshake_timeout_seconds)
            || !(16..=10_000).contains(&raw.component_queue_capacity)
        {
            anyhow::bail!("component connection, handshake, or queue limit is invalid");
        }
        if !(60..=30 * 24 * 60 * 60).contains(&raw.s2s_outbox_ttl_seconds) {
            anyhow::bail!("S2S_OUTBOX_TTL_SECONDS must be between 60 and 2592000");
        }
        if !(1..=10_000_000).contains(&raw.s2s_outbox_max_rows)
            || !(1024 * 1024..=1024_i64 * 1024 * 1024 * 1024).contains(&raw.s2s_outbox_max_bytes)
            || !(1..=1_000_000).contains(&raw.s2s_outbox_max_per_domain)
            || raw.s2s_outbox_max_per_domain > raw.s2s_outbox_max_rows
        {
            anyhow::bail!("S2S outbox row, byte, or per-domain capacity is invalid");
        }
        if !(1..=3600).contains(&raw.s2s_outbox_retry_base_seconds)
            || raw.s2s_outbox_retry_max_seconds < raw.s2s_outbox_retry_base_seconds
            || raw.s2s_outbox_retry_max_seconds > 86_400
            || !(1..=10_000).contains(&raw.s2s_outbox_max_attempts)
            || !(1..=10_000).contains(&raw.s2s_outbox_claim_batch)
            || !(30..=3600).contains(&raw.s2s_outbox_lease_seconds)
        {
            anyhow::bail!("S2S outbox retry, batch, attempts, or lease setting is invalid");
        }
        if !(5..=600).contains(&raw.unauthenticated_timeout_seconds) {
            anyhow::bail!("UNAUTHENTICATED_TIMEOUT_SECONDS must be between 5 and 600");
        }
        if !(5..=600).contains(&raw.resource_bind_timeout_seconds) {
            anyhow::bail!("RESOURCE_BIND_TIMEOUT_SECONDS must be between 5 and 600");
        }
        if !(60..=86_400).contains(&raw.admin_idle_seconds) {
            anyhow::bail!("ADMIN_IDLE_SECONDS must be between 60 and 86400");
        }
        if !(1..=10_000).contains(&raw.pubsub_max_nodes_per_owner)
            || !(1..=10_000).contains(&raw.pep_max_nodes_per_account)
        {
            anyhow::bail!("PubSub and PEP node quotas must be between 1 and 10000");
        }
        const MAX_ACCOUNT_STORAGE: i64 = 100 * 1024 * 1024 * 1024;
        if !(1024 * 1024..=MAX_ACCOUNT_STORAGE).contains(&raw.pubsub_max_storage_bytes_per_owner)
            || !(1024 * 1024..=MAX_ACCOUNT_STORAGE).contains(&raw.pep_max_storage_bytes_per_account)
        {
            anyhow::bail!("PubSub and PEP storage quotas must be between 1 MiB and 100 GiB");
        }
        if raw.upload_mode.admits_new_uploads() {
            if raw.upload_max_bytes == 0 || raw.upload_max_bytes > i64::MAX as u64 {
                anyhow::bail!("UPLOAD_MAX_BYTES must be between 1 and i64::MAX");
            }
            if !(1..=1_000_000).contains(&raw.upload_max_files_per_user) {
                anyhow::bail!("UPLOAD_MAX_FILES_PER_USER must be between 1 and 1000000");
            }
            if raw.upload_max_bytes_per_user < raw.upload_max_bytes as i64
                || raw.upload_max_bytes_per_user > MAX_ACCOUNT_STORAGE
            {
                anyhow::bail!(
                "UPLOAD_MAX_BYTES_PER_USER must be at least UPLOAD_MAX_BYTES and at most 100 GiB"
            );
            }
        }
        if raw.upload_mode.keeps_storage_runtime() {
            if raw.upload_download_max_bytes == 0
                || raw.upload_download_max_bytes > i64::MAX as u64
                || (raw.upload_mode.admits_new_uploads()
                    && raw.upload_download_max_bytes < raw.upload_max_bytes)
            {
                anyhow::bail!(
                    "UPLOAD_DOWNLOAD_MAX_BYTES must be positive, at most i64::MAX, and no smaller than UPLOAD_MAX_BYTES while admission is enabled"
                );
            }
            if !(1..=10_000).contains(&raw.upload_download_max_concurrent)
                || !(1..=256).contains(&raw.upload_download_max_per_ip)
                || raw.upload_download_max_per_ip > raw.upload_download_max_concurrent
                || !(5..=300).contains(&raw.upload_download_read_timeout_seconds)
                || !(30..=3600).contains(&raw.upload_download_max_seconds)
            {
                anyhow::bail!("upload download concurrency or read timeout is invalid");
            }
            if !(128..=100_000).contains(&raw.upload_storage_max_pending_jobs)
                || !(1_000..=100_000_000).contains(&raw.upload_storage_max_retained_files)
                || (raw.upload_mode.admits_new_uploads()
                    && raw.upload_storage_max_retained_bytes < raw.upload_max_bytes as i64)
                || raw.upload_storage_max_retained_bytes <= 0
                || raw.upload_storage_max_retained_bytes > 1024_i64 * 1024 * 1024 * 1024 * 1024
            {
                anyhow::bail!("upload physical-retention or reconciliation bounds are invalid");
            }
            if !(60..=10 * 365 * 24 * 60 * 60).contains(&raw.upload_retention_seconds) {
                anyhow::bail!("UPLOAD_RETENTION_SECONDS must be between 60 seconds and 10 years");
            }
        }
        if raw.pow_base_work_factor == 0 || raw.pow_max_work_factor < raw.pow_base_work_factor {
            anyhow::bail!("PoW maximum work factor must be at least the positive base factor");
        }
        raw.pow_v1_compatibility_until = raw
            .pow_v1_compatibility_until
            .take()
            .filter(|value| !value.trim().is_empty());
        let pow_v1_compatibility_until =
            parse_pow_v1_compatibility_until(raw.pow_v1_compatibility_until.as_deref())?;
        if !(10..=10_000).contains(&raw.abuse_message_free_burst)
            || !(1..=30).contains(&raw.pow_max_device_seconds)
        {
            anyhow::bail!("ABUSE_MESSAGE_FREE_BURST must be 10..10000 and POW_MAX_DEVICE_SECONDS must be 1..30");
        }
        if raw.abuse_window_seconds == 0
            || raw.abuse_cooldown_seconds == 0
            || raw.abuse_max_wait_seconds == 0
        {
            anyhow::bail!("anti-abuse window, cooldown and maximum wait must be positive");
        }
        if raw.log_retention_files == 0
            || !matches!(
                raw.log_rotation.to_ascii_lowercase().as_str(),
                "daily" | "hourly" | "minutely" | "never"
            )
        {
            anyhow::bail!("LOG_ROTATION or LOG_RETENTION_FILES is invalid");
        }
        if !matches!(
            raw.log_format.to_ascii_lowercase().as_str(),
            "text" | "json"
        ) {
            anyhow::bail!("LOG_FORMAT must be text or json");
        }
        if raw.bootstrap_admin_username.is_some() != raw.bootstrap_admin_password.is_some() {
            anyhow::bail!(
                "BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD must be set together"
            );
        }

        let default_public_url = if domain == "localhost" {
            format!("http://localhost:{}", raw.http_bind.port())
        } else {
            format!("https://{domain}")
        };
        let public_url = raw
            .public_url
            .clone()
            .unwrap_or(default_public_url)
            .trim_end_matches('/')
            .to_owned();
        if !(public_url.starts_with("http://") || public_url.starts_with("https://"))
            || public_url.chars().any(char::is_whitespace)
        {
            anyhow::bail!("PUBLIC_URL must be an absolute HTTP(S) URL without whitespace");
        }
        if !(1..=100_000).contains(&raw.bosh_max_sessions)
            || !(1..=4_096).contains(&raw.bosh_max_concurrent_body_reads)
            || !(1..=120).contains(&raw.bosh_body_read_timeout_seconds)
            || !(1..=120).contains(&raw.bosh_max_wait_seconds)
            || !(5..=3_600).contains(&raw.bosh_inactivity_seconds)
            || !(1..=60).contains(&raw.bosh_polling_seconds)
            || raw.bosh_max_pause_seconds < raw.bosh_inactivity_seconds
            || raw.bosh_max_pause_seconds > 86_400
            || !(16 * 1024..=4 * 1024 * 1024).contains(&raw.bosh_max_request_bytes)
            || !(16 * 1024..=4 * 1024 * 1024).contains(&raw.bosh_max_response_bytes)
            || !(1..=256).contains(&raw.bosh_max_stanzas_per_request)
            || !(2..=2_048).contains(&raw.bosh_max_output_stanzas)
            || !(64 * 1024..=64 * 1024 * 1024).contains(&raw.bosh_max_output_bytes)
        {
            anyhow::bail!("BOSH session, timer, request, response, stanza, or output bounds are outside their safe ranges");
        }
        if raw.bosh_enabled && !public_url.starts_with("https://") {
            anyhow::bail!("BOSH_ENABLED requires an HTTPS PUBLIC_URL");
        }
        let mut websocket_allowed_origins = Vec::new();
        let mut seen_websocket_origins = HashSet::new();
        for origin in raw.websocket_allowed_origins.split(',') {
            let origin = origin.trim();
            if origin.is_empty() {
                continue;
            }
            let canonical = canonical_web_origin(origin).with_context(|| {
                format!("WEBSOCKET_ALLOWED_ORIGINS contains an invalid origin: {origin}")
            })?;
            if seen_websocket_origins.insert(canonical.clone()) {
                websocket_allowed_origins.push(canonical);
            }
        }
        if websocket_allowed_origins.len() > 64 {
            anyhow::bail!("WEBSOCKET_ALLOWED_ORIGINS may contain at most 64 origins");
        }
        if !(1..=604_800).contains(&raw.xep_0487_ttl_seconds) {
            anyhow::bail!("XEP_0487_TTL_SECONDS must be between 1 and 604800");
        }

        if raw.registration_rate_per_hour == 0 {
            anyhow::bail!("REGISTRATION_RATE_PER_HOUR must be greater than zero");
        }

        let trusted_proxy_ips = raw
            .trusted_proxy_ips
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse())
            .collect::<Result<Vec<IpAddr>, _>>()
            .context("invalid trusted proxy IPs")?;
        validate_web_admin_exposure(raw.web_admin_enabled, raw.web_admin_bind)?;
        if raw.bosh_enabled && trusted_proxy_ips.is_empty() {
            anyhow::bail!("BOSH_ENABLED requires at least one TRUSTED_PROXY_IPS entry");
        }
        let xep_0487_ips = parse_xep_0487_ips(&raw.xep_0487_ips)?;
        let public_http_active =
            web_capabilities.listeners.public.is_some() || !xep_0487_ips.is_empty();
        validate_listener_plan(&raw, public_http_active)?;

        let federation_allowlist = domain_list(&raw.federation_allowlist)
            .context("federation allowlist contains an invalid domain pattern")?;
        let federation_denylist = domain_list(&raw.federation_denylist)
            .context("federation denylist contains an invalid domain pattern")?;
        let federation_dane_mode = crate::s2s::dane::DaneMode::parse(&raw.federation_dane_mode)?;
        raw.federation_dane_mode = match federation_dane_mode {
            crate::s2s::dane::DaneMode::Off => "off",
            crate::s2s::dane::DaneMode::Opportunistic => "opportunistic",
            crate::s2s::dane::DaneMode::Required => "required",
        }
        .to_owned();
        if raw.c2s_client_crl_path.is_some() && raw.c2s_client_trust_root_cert_path.is_none() {
            anyhow::bail!("C2S_CLIENT_CRL_PATH requires C2S_CLIENT_TRUST_ROOT_CERT_PATH");
        }

        let mut federation_dns_overrides = Vec::new();
        for entry in raw.federation_dns_overrides.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (d, endpoint) = entry.split_once('=').context("invalid DNS override")?;
            let d = crate::jid::prepare_domainpart(d.trim())
                .context("invalid domain in DNS override")?;
            let endpoint = endpoint.trim();
            let (endpoint, direct_tls) = endpoint
                .strip_prefix("xmpps://")
                .map(|endpoint| (endpoint, true))
                .or_else(|| {
                    endpoint
                        .strip_prefix("starttls://")
                        .map(|endpoint| (endpoint, false))
                })
                .unwrap_or((endpoint, false));
            federation_dns_overrides.push((
                d,
                endpoint.parse().context("invalid override address")?,
                direct_tls,
            ));
        }
        let stun_service = raw
            .stun_server
            .as_deref()
            .map(parse_external_service)
            .transpose()
            .context("STUN_SERVER is invalid")?;
        let turn_service = raw
            .turn_server
            .as_deref()
            .map(parse_external_service)
            .transpose()
            .context("TURN_SERVER is invalid")?;
        if raw.turn_shared_secret.is_some() && turn_service.is_none() {
            anyhow::bail!("TURN_SHARED_SECRET requires TURN_SERVER");
        }
        if raw
            .turn_shared_secret
            .as_ref()
            .is_some_and(|secret| secret.len() < 32 || secret.len() > 4096 || secret.contains('\0'))
        {
            anyhow::bail!("TURN_SHARED_SECRET must contain 32 to 4096 bytes without NUL");
        }
        validate_shared_runtime_secret("DIALBACK_SECRET", raw.dialback_secret.as_deref())?;
        validate_cluster_dialback_secret(
            raw.redis_url.is_some(),
            raw.dialback_enabled,
            raw.dialback_secret_file.as_deref(),
        )?;
        validate_cluster_fast_secret(
            raw.redis_url.is_some(),
            raw.fast_token_secret_file.as_deref(),
        )?;
        if raw.federation_enabled && !raw.s2s_sasl_external_enabled && !raw.dialback_enabled {
            anyhow::bail!("federation requires S2S_SASL_EXTERNAL_ENABLED or DIALBACK_ENABLED");
        }

        let components = if raw.components_enabled {
            let path = raw
                .components_config_file
                .as_deref()
                .context("COMPONENTS_ENABLED requires COMPONENTS_CONFIG_FILE")?;
            load_component_credentials(path, &domain)?
        } else {
            Vec::new()
        };
        if raw.components_enabled && components.is_empty() {
            anyhow::bail!(
                "component support is enabled but no component credentials are configured"
            );
        }
        validate_component_transport(raw.component_bind, &components)?;
        validate_component_capacity(raw.max_component_connections, &components)?;

        let fast_token_enabled = raw.fast_token_secret.is_some() || ephemeral_fast_is_allowed;
        Ok(Self {
            raw,
            domain,
            public_url,
            websocket_allowed_origins,
            trusted_proxy_ips,
            xep_0487_ips,
            xmpp_extensions,
            federation_allowlist,
            federation_denylist,
            federation_dns_overrides,
            federation_dane_mode,
            stun_service,
            turn_service,
            components,
            cluster_security: cluster_security.map(Arc::new),
            fast_token_enabled,
            dummy_scram_secret,
            api_control_secret,
            api_control_previous_secret,
            metrics_bearer_token: metrics_bearer_token.map(|token| Arc::new(Zeroizing::new(token))),
            web_admin_gateway_token: web_admin_gateway_token
                .map(|token| Arc::new(Zeroizing::new(token))),
            web_capabilities,
            invitation_policy_disabled_with_web_client,
            pow_v1_compatibility_until,
        })
    }

    pub fn configured_registration_mode(&self) -> RegistrationMode {
        self.web_capabilities.registration.mode
    }

    pub fn registration_dependency_locked(&self) -> bool {
        self.web_capabilities.registration.lock.is_locked()
    }

    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        if !self.raw.federation_enabled {
            return false;
        }
        let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
            return false;
        };
        if domain == self.domain
            || domain == format!("conference.{}", self.domain)
            || domain == format!("upload.{}", self.domain)
            || domain == format!("pubsub.{}", self.domain)
            || domain == format!("mix.{}", self.domain)
        {
            return false;
        }

        if self
            .federation_denylist
            .iter()
            .any(|pattern| domain_pattern_matches(pattern, &domain))
        {
            return false;
        }
        self.federation_allowlist.is_empty()
            || self
                .federation_allowlist
                .iter()
                .any(|pattern| domain_pattern_matches(pattern, &domain))
    }

    /// Returns whether a client-originated stanza may leave the local XMPP
    /// service through either a configured external component or S2S.
    ///
    /// Components are an independent routing transport: disabling Internet
    /// federation must not make an explicitly configured XEP-0114/XEP-0225
    /// component domain unreachable.  Keep this separate from
    /// `federation_domain_allowed`, because an inbound S2S peer must never
    /// gain authority merely because the same domain is assigned to a local
    /// component.
    pub fn external_route_domain_allowed(&self, domain: &str) -> bool {
        self.component_domain_configured(domain) || self.federation_domain_allowed(domain)
    }

    pub fn component_credential(&self, domain: &str) -> Option<&ComponentCredential> {
        let domain = crate::jid::prepare_domainpart(domain).ok()?;
        self.components.iter().find(|credential| {
            credential
                .allowed_domains
                .iter()
                .any(|allowed| allowed == &domain)
        })
    }

    pub fn component_domain_configured(&self, domain: &str) -> bool {
        self.component_credential(domain).is_some()
    }
}

fn load_component_credentials(
    path: &std::path::Path,
    server_domain: &str,
) -> Result<Vec<ComponentCredential>> {
    let mut encoded = read_protected_utf8_file(path, "COMPONENTS_CONFIG_FILE", 1024 * 1024, false)?;
    let parsed = serde_json::from_str(&encoded);
    encoded.zeroize();
    let document: ComponentConfigDocument = parsed.context("component config is not valid JSON")?;
    let entries = match document {
        ComponentConfigDocument::List(entries)
        | ComponentConfigDocument::Object {
            components: entries,
        } => entries,
    };
    if entries.len() > 1024 {
        anyhow::bail!("component config contains more than 1024 components");
    }

    let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let reserved = [
        server_domain.to_owned(),
        format!("conference.{server_domain}"),
        format!("upload.{server_domain}"),
        format!("pubsub.{server_domain}"),
        format!("mix.{server_domain}"),
    ];
    let mut claimed_domains = HashSet::new();
    let mut credentials = Vec::with_capacity(entries.len());
    for entry in entries {
        let ComponentCredentialFile {
            jid,
            secret,
            secret_file,
            aliases,
            legacy_0114,
            modern_0225,
            connection,
            connect_endpoint,
            allow_public_connect,
        } = entry;
        if secret.is_some() == secret_file.is_some() {
            anyhow::bail!("set exactly one of component secret or secret_file");
        }
        if aliases.len() > 64 {
            anyhow::bail!("a component cannot configure more than 64 aliases");
        }
        let primary_domain = crate::jid::prepare_domainpart(jid.trim())
            .context("component JID must be a domain identifier")?;
        let mut allowed_domains = Vec::with_capacity(aliases.len() + 1);
        allowed_domains.push(primary_domain.clone());
        for alias in aliases {
            let alias = crate::jid::prepare_domainpart(alias.trim())
                .context("component alias must be a domain identifier")?;
            if !allowed_domains.contains(&alias) {
                allowed_domains.push(alias);
            }
        }
        for component_domain in &allowed_domains {
            if reserved.iter().any(|domain| domain == component_domain) {
                anyhow::bail!("component domain conflicts with a built-in hosted domain");
            }
            if !claimed_domains.insert(component_domain.clone()) {
                anyhow::bail!("component domains and aliases must be globally unique");
            }
        }
        if !legacy_0114 && !modern_0225 {
            anyhow::bail!("each component must enable XEP-0114 or XEP-0225");
        }
        let connect_endpoint = match (connection, connect_endpoint.as_deref()) {
            (ComponentConnectionMode::Accept, None) => None,
            (ComponentConnectionMode::Accept, Some(_)) => {
                anyhow::bail!("accept-mode components cannot configure connect_endpoint")
            }
            (ComponentConnectionMode::Connect, None) => {
                anyhow::bail!("connect-mode components require connect_endpoint")
            }
            (ComponentConnectionMode::Connect, Some(endpoint)) => {
                let (host, port) = parse_external_service(endpoint)
                    .context("component connect_endpoint must use exact host:port syntax")?;
                Some(ComponentConnectEndpoint { host, port })
            }
        };
        if connection == ComponentConnectionMode::Connect && (!legacy_0114 || modern_0225) {
            anyhow::bail!(
                "connect-mode is the legacy XEP-0114 profile and requires legacy_0114=true, modern_0225=false"
            );
        }
        if connection == ComponentConnectionMode::Accept && allow_public_connect {
            anyhow::bail!("allow_public_connect is valid only for connect-mode components");
        }

        let secret_file = secret_file.map(|path| {
            if path.is_absolute() {
                path
            } else {
                base.join(path)
            }
        });
        let mut secret = match (secret, &secret_file) {
            (Some(secret), None) => Zeroizing::new(secret),
            (None, Some(path)) => Zeroizing::new(read_secret_file(path, "component secret_file")?),
            _ => unreachable!("component secret source was validated above"),
        };
        if secret.len() < 32 || secret.len() > 4096 || secret.contains('\0') {
            secret.zeroize();
            anyhow::bail!("component secrets must contain 32 to 4096 bytes without NUL");
        }
        let secret_sha256: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        credentials.push(ComponentCredential {
            primary_domain,
            allowed_domains,
            secret_value: Some(Arc::new(secret)),
            secret_file,
            secret_sha256,
            legacy_0114,
            modern_0225,
            connection,
            connect_endpoint,
            allow_public_connect,
        });
    }
    Ok(credentials)
}

fn validate_component_transport(
    bind: SocketAddr,
    components: &[ComponentCredential],
) -> Result<()> {
    if !bind.ip().is_loopback()
        && components.iter().any(|credential| {
            credential.connection == ComponentConnectionMode::Accept && credential.legacy_0114
        })
    {
        anyhow::bail!(
            "plaintext XEP-0114 components require a loopback COMPONENT_BIND; use XEP-0225 for a public listener"
        );
    }
    Ok(())
}

fn validate_component_capacity(
    max_connections: usize,
    components: &[ComponentCredential],
) -> Result<()> {
    let outbound_domains = components
        .iter()
        .filter(|credential| credential.connection == ComponentConnectionMode::Connect)
        .map(|credential| credential.allowed_domains.len())
        .sum::<usize>();
    let accept_reserve = usize::from(
        components
            .iter()
            .any(|credential| credential.connection == ComponentConnectionMode::Accept),
    );
    if outbound_domains.saturating_add(accept_reserve) > max_connections {
        anyhow::bail!(
            "MAX_COMPONENT_CONNECTIONS must cover every connect-mode domain and one accept-mode reserve"
        );
    }
    Ok(())
}

fn parse_external_service(value: &str) -> Result<(String, u16)> {
    let value = value.trim();
    let bracketed = value.starts_with('[');
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .context("bracketed IPv6 endpoint must end with ]:port")?;
        (host, port)
    } else {
        value
            .rsplit_once(':')
            .context("endpoint must use host:port syntax")?
    };
    if host.is_empty()
        || (!bracketed && host.contains(':'))
        || host.chars().any(char::is_whitespace)
        || host.chars().any(char::is_control)
    {
        anyhow::bail!("service host is empty or contains whitespace");
    }
    let port = port.parse::<u16>().context("service port is invalid")?;
    if port == 0 {
        anyhow::bail!("service port must be non-zero");
    }
    let host = if let Ok(address) = host.parse::<IpAddr>() {
        address.to_string()
    } else {
        crate::jid::prepare_domainpart(host)
            .context("service host is not a valid IP or IDNA domain")?
    };
    Ok((host, port))
}

fn parse_pow_v1_compatibility_until(
    value: Option<&str>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    value
        .map(|value| {
            let parsed = chrono::DateTime::parse_from_rfc3339(value)
                .context("POW_V1_COMPATIBILITY_UNTIL must be an RFC 3339 timestamp")?;
            anyhow::ensure!(
                parsed.offset().local_minus_utc() == 0 && value.ends_with('Z'),
                "POW_V1_COMPATIBILITY_UNTIL must use the canonical UTC Z form"
            );
            Ok(parsed.with_timezone(&chrono::Utc))
        })
        .transpose()
}

fn parse_xep_0487_ips(value: &str) -> Result<Vec<IpAddr>> {
    let addresses = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<IpAddr>, _>>()
        .context("XEP_0487_IPS must contain comma-separated literal IP addresses")?;
    if addresses.len() > 32 {
        anyhow::bail!("XEP_0487_IPS may contain at most 32 addresses");
    }
    if addresses
        .iter()
        .any(|address| !crate::s2s::dns::is_public_ip(*address))
    {
        anyhow::bail!("XEP_0487_IPS must contain only public, globally routable addresses");
    }
    Ok(addresses)
}

fn non_empty_path(path: Option<PathBuf>) -> Option<PathBuf> {
    path.filter(|path| !path.as_os_str().is_empty())
}

fn valid_http_bearer_secret(value: &str) -> bool {
    (32..=4096).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub(crate) fn read_secret_file(path: &std::path::Path, variable: &str) -> Result<String> {
    read_protected_utf8_file(path, variable, 64 * 1024, true)
}

fn read_protected_utf8_file(
    path: &std::path::Path,
    variable: &str,
    max_bytes: u64,
    trim_line_ending: bool,
) -> Result<String> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect secret file configured by {variable}"))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.len() == 0
        || before.len() > max_bytes
    {
        anyhow::bail!(
            "secret file configured by {variable} must be a non-symlink regular file of 1..={max_bytes} bytes"
        );
    }
    validate_secret_permissions(&before, variable)?;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot open secret file configured by {variable}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect opened secret file configured by {variable}"))?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > max_bytes {
        anyhow::bail!(
            "secret file configured by {variable} must be a non-symlink regular file of 1..={max_bytes} bytes"
        );
    }
    validate_secret_metadata(&before, &opened, variable)?;
    validate_secret_permissions(&opened, variable)?;

    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read secret file configured by {variable}"))?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        anyhow::bail!("secret file configured by {variable} is empty or invalid");
    }

    let opened_after = file.metadata().with_context(|| {
        format!("cannot re-inspect opened secret file configured by {variable}")
    })?;
    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("cannot re-inspect secret file configured by {variable}"))?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || opened.len() != opened_after.len()
        || opened.modified().ok() != opened_after.modified().ok()
        || opened.len() != bytes.len() as u64
    {
        anyhow::bail!("secret file configured by {variable} changed while it was being read");
    }
    validate_secret_metadata(&opened, &opened_after, variable)?;
    validate_secret_metadata(&opened, &path_after, variable)?;
    validate_secret_permissions(&opened_after, variable)?;
    validate_secret_permissions(&path_after, variable)?;

    let mut value = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => {
            let mut invalid = error.into_bytes();
            invalid.zeroize();
            anyhow::bail!("secret file configured by {variable} is not valid UTF-8");
        }
    };
    let value = if trim_line_ending {
        let trimmed = value.trim_end_matches(['\r', '\n']).to_owned();
        value.zeroize();
        trimmed
    } else {
        value
    };
    if value.is_empty() || value.contains('\0') {
        anyhow::bail!("secret file configured by {variable} is empty or invalid");
    }
    Ok(value)
}

#[cfg(unix)]
fn validate_secret_permissions(metadata: &fs::Metadata, variable: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o400 && mode != 0o600 {
        anyhow::bail!("secret file configured by {variable} must have permissions 0400 or 0600");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_permissions(_metadata: &fs::Metadata, _variable: &str) -> Result<()> {
    // Linux production preflight is authoritative. Windows ACLs do not have a
    // sound one-to-one mapping to Unix owner-only permission bits.
    Ok(())
}

#[cfg(unix)]
fn validate_secret_metadata(
    before: &fs::Metadata,
    after: &fs::Metadata,
    variable: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        anyhow::bail!("secret file configured by {variable} changed while it was being read");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_metadata(
    before: &fs::Metadata,
    after: &fs::Metadata,
    variable: &str,
) -> Result<()> {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        anyhow::bail!("secret file configured by {variable} changed while it was being read");
    }
    Ok(())
}

// Forward raw fields for convenience
impl std::ops::Deref for Config {
    type Target = RawConfig;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

fn domain_list(value: &str) -> Result<Vec<String>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|pattern| {
            let (wildcard, domain) = pattern
                .strip_prefix("*.")
                .map_or((false, pattern), |domain| (true, domain));
            let domain = crate::jid::prepare_domainpart(domain)?;
            Ok(if wildcard {
                format!("*.{domain}")
            } else {
                domain
            })
        })
        .collect()
}

fn domain_pattern_matches(pattern: &str, domain: &str) -> bool {
    pattern == domain
        || pattern
            .strip_prefix("*.")
            .is_some_and(|suffix| domain != suffix && domain.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::{
        authentication_master_secrets_are_independent, domain_list, domain_pattern_matches,
        ephemeral_development_secret_allowed, listener_addresses_overlap,
        load_component_credentials, parse_external_service, parse_pow_v1_compatibility_until,
        parse_xep_0487_ips, read_secret_file, redis_endpoint_is_local, resolve_web_capability_plan,
        valid_http_bearer_secret, validate_cluster_dialback_secret, validate_cluster_fast_secret,
        validate_component_capacity, validate_component_transport, validate_redis_transport,
        validate_shared_runtime_secret, validate_web_admin_exposure, ComponentConnectionMode,
        ComponentCredential,
    };

    fn web_dependency_fixture() -> super::RawConfig {
        envy::from_iter::<_, super::RawConfig>(std::iter::empty::<(String, String)>())
            .expect("RawConfig defaults must deserialize")
    }

    #[test]
    fn test_listener_activation_is_explicit_and_loopback_only() {
        let mut raw = web_dependency_fixture();
        raw.test_listener_activation = true;
        raw.test_readiness_file = Some(std::env::temp_dir().join("northstar-ready.json"));
        raw.test_readiness_nonce = Some("0123456789abcdef".to_owned());
        super::validate_test_listener_activation(&raw, true, true).unwrap();

        assert!(super::validate_test_listener_activation(&raw, false, true).is_err());
        raw.test_readiness_nonce = Some("not-a-canonical-nonce".to_owned());
        assert!(super::validate_test_listener_activation(&raw, true, true).is_err());

        raw.test_listener_activation = false;
        assert!(super::validate_test_listener_activation(&raw, true, true).is_err());
    }

    #[test]
    fn web_client_requires_its_rest_and_websocket_dependencies() {
        let mut without_rest = web_dependency_fixture();
        without_rest.rest_api_enabled = false;
        assert!(resolve_web_capability_plan(&without_rest).is_err());

        let mut without_websocket = web_dependency_fixture();
        without_websocket.websocket_enabled = false;
        assert!(resolve_web_capability_plan(&without_websocket).is_err());
    }

    #[test]
    fn disabling_web_client_fails_invitation_registration_closed() {
        let mut raw = web_dependency_fixture();
        raw.web_client_enabled = false;
        raw.invitation_required = true;
        raw.open_registration = true;
        let plan = resolve_web_capability_plan(&raw).unwrap();
        assert!(plan.registration.lock.is_locked());
        assert_eq!(plan.registration.mode, super::RegistrationMode::Closed);
    }

    #[test]
    fn disabling_xep_0363_removes_new_upload_admission_but_keeps_safe_drain() {
        let mut raw = web_dependency_fixture();
        raw.xep_0363_enabled = false;
        let plan = resolve_web_capability_plan(&raw).unwrap();
        assert_eq!(plan.upload_mode, super::UploadMode::DrainReadOnly);
        assert!(!plan.upload.slot_admission);
        assert!(!plan.upload.put);
        assert!(!plan.upload.xmpp_advertisement);
        assert!(plan.upload.get);
        assert!(plan.upload.cleanup_worker);
    }

    #[test]
    fn administration_is_strictly_loopback_only() {
        let public = "0.0.0.0:8081".parse().unwrap();
        let loopback = "127.0.0.1:8081".parse().unwrap();
        assert!(validate_web_admin_exposure(true, loopback).is_ok());
        assert!(validate_web_admin_exposure(false, public).is_ok());
        assert!(validate_web_admin_exposure(true, public).is_err());
    }

    #[test]
    fn ephemeral_authentication_keys_require_every_development_fence() {
        assert!(ephemeral_development_secret_allowed(
            true, false, true, true
        ));
        for denied in [
            (false, false, true, true),
            (true, true, true, true),
            (true, false, false, true),
            (true, false, true, false),
        ] {
            assert!(!ephemeral_development_secret_allowed(
                denied.0, denied.1, denied.2, denied.3
            ));
        }
    }

    #[test]
    fn fast_and_dummy_scram_master_keys_cannot_reuse_exact_bytes() {
        let fast = "f".repeat(32);
        let dummy = "d".repeat(32);
        assert!(authentication_master_secrets_are_independent(
            Some(&fast),
            Some(&dummy)
        ));
        assert!(!authentication_master_secrets_are_independent(
            Some(&fast),
            Some(&fast)
        ));
        assert!(authentication_master_secrets_are_independent(
            None,
            Some(&dummy)
        ));
    }

    #[test]
    fn clustered_dialback_requires_a_shared_secret_file() {
        assert!(validate_cluster_dialback_secret(true, true, None).is_err());
        assert!(validate_cluster_dialback_secret(
            true,
            true,
            Some(std::path::Path::new("/run/secrets/dialback")),
        )
        .is_ok());
        assert!(validate_cluster_dialback_secret(false, true, None).is_ok());
        assert!(validate_cluster_dialback_secret(true, false, None).is_ok());
    }

    #[test]
    fn clustered_fast_requires_a_shared_secret_file() {
        assert!(validate_cluster_fast_secret(true, None).is_err());
        assert!(validate_cluster_fast_secret(
            true,
            Some(std::path::Path::new("/run/secrets/fast")),
        )
        .is_ok());
        assert!(validate_cluster_fast_secret(false, None).is_ok());
    }

    #[test]
    fn shared_runtime_secrets_reject_empty_short_long_and_nul_values() {
        assert!(validate_shared_runtime_secret("TEST_SECRET", None).is_ok());
        assert!(validate_shared_runtime_secret("TEST_SECRET", Some("")).is_err());
        assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(31))).is_err());
        assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(32))).is_ok());
        assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(4096))).is_ok());
        assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(4097))).is_err());
        assert!(validate_shared_runtime_secret(
            "TEST_SECRET",
            Some(&format!("{}\0", "x".repeat(32)))
        )
        .is_err());
    }

    #[test]
    fn shared_key_file_length_is_validated_after_protected_read() {
        let path = std::env::temp_dir().join(format!(
            "northstar-short-shared-key-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&path, "x".repeat(31)).unwrap();
        restrict(&path);
        let value = read_secret_file(&path, "FAST_TOKEN_SECRET_FILE").unwrap();
        assert!(validate_shared_runtime_secret("FAST_TOKEN_SECRET", Some(&value)).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    fn restrict(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn restrict(_path: &std::path::Path) {}

    #[test]
    fn external_services_accept_dns_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            parse_external_service("turn.example.test:3478").unwrap(),
            ("turn.example.test".to_owned(), 3478)
        );
        assert_eq!(
            parse_external_service("BÜCHER.example.:3478").unwrap(),
            ("bücher.example".to_owned(), 3478)
        );
        assert_eq!(
            parse_external_service("[2001:db8::1]:5349").unwrap(),
            ("2001:db8::1".to_owned(), 5349)
        );
        assert!(parse_external_service("2001:db8::1:5349").is_err());
        assert!(parse_external_service("host:0").is_err());
        assert!(parse_external_service("bad_domain.example:3478").is_err());
    }

    #[test]
    fn pow_v1_cutover_requires_canonical_utc_and_defaults_closed() {
        assert!(parse_pow_v1_compatibility_until(None).unwrap().is_none());
        assert_eq!(
            parse_pow_v1_compatibility_until(Some("2026-10-01T00:00:00Z"))
                .unwrap()
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "2026-10-01T00:00:00Z"
        );
        assert!(parse_pow_v1_compatibility_until(Some("2026-10-01T09:00:00+09:00")).is_err());
        assert!(parse_pow_v1_compatibility_until(Some("not-a-time")).is_err());
    }

    #[test]
    fn metrics_bearer_secret_has_one_http_representable_shape() {
        assert!(valid_http_bearer_secret(&"a".repeat(32)));
        assert!(valid_http_bearer_secret(
            "0123456789abcdefghijklmnopqrstuvwxyz-._~+/="
        ));
        for invalid in [
            "short",
            "0123456789abcdef0123456789abcde ",
            "0123456789abcdef0123456789abcde\t",
            "0123456789abcdef0123456789abcde\u{00e9}",
        ] {
            assert!(!valid_http_bearer_secret(invalid), "accepted {invalid:?}");
        }
        assert!(!valid_http_bearer_secret(&"a".repeat(4097)));
    }

    #[test]
    fn host_meta_v2_advertises_only_bounded_public_literal_addresses() {
        assert_eq!(
            parse_xep_0487_ips("8.8.8.8,2606:4700:4700::1111")
                .unwrap()
                .len(),
            2
        );
        for invalid in [
            "127.0.0.1",
            "10.0.0.1",
            "192.0.2.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "not-an-ip",
        ] {
            assert!(parse_xep_0487_ips(invalid).is_err(), "accepted {invalid}");
        }
        let too_many = std::iter::repeat_n("8.8.8.8", 33)
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_xep_0487_ips(&too_many).is_err());
    }

    #[test]
    fn federation_domain_patterns_are_idna_canonical_and_strict() {
        let patterns = domain_list("BÜCHER.example,*.FÖÖ.example").unwrap();
        assert_eq!(patterns, vec!["bücher.example", "*.föö.example"]);
        assert!(domain_pattern_matches("*.föö.example", "chat.föö.example"));
        assert!(!domain_pattern_matches("*.föö.example", "föö.example"));
        assert!(domain_list("*.example..test").is_err());
        assert!(domain_list("*.").is_err());
    }

    #[test]
    fn plaintext_legacy_component_listener_is_loopback_only() {
        let legacy = ComponentCredential {
            primary_domain: "gateway.example".to_owned(),
            allowed_domains: vec!["gateway.example".to_owned()],
            secret_value: Some(std::sync::Arc::new(zeroize::Zeroizing::new(
                "this-is-a-32-byte-component-test-secret".to_owned(),
            ))),
            secret_file: None,
            secret_sha256: [0; 32],
            legacy_0114: true,
            modern_0225: true,
            connection: super::ComponentConnectionMode::Accept,
            connect_endpoint: None,
            allow_public_connect: false,
        };
        assert!(validate_component_transport(
            "127.0.0.1:5347".parse().unwrap(),
            std::slice::from_ref(&legacy)
        )
        .is_ok());
        assert!(validate_component_transport(
            "0.0.0.0:5347".parse().unwrap(),
            std::slice::from_ref(&legacy)
        )
        .is_err());
        let modern = ComponentCredential {
            legacy_0114: false,
            ..legacy
        };
        assert!(validate_component_transport("0.0.0.0:5347".parse().unwrap(), &[modern]).is_ok());
    }

    #[test]
    fn connect_supervisors_and_accept_listener_fit_the_global_capacity() {
        let secret_value = Some(std::sync::Arc::new(zeroize::Zeroizing::new(
            "this-is-a-32-byte-component-test-secret".to_owned(),
        )));
        let outbound = ComponentCredential {
            primary_domain: "gateway.example".to_owned(),
            allowed_domains: vec!["gateway.example".to_owned(), "alias.example".to_owned()],
            secret_value: secret_value.clone(),
            secret_file: None,
            secret_sha256: [0; 32],
            legacy_0114: true,
            modern_0225: false,
            connection: ComponentConnectionMode::Connect,
            connect_endpoint: None,
            allow_public_connect: false,
        };
        let accept = ComponentCredential {
            primary_domain: "accept.example".to_owned(),
            allowed_domains: vec!["accept.example".to_owned()],
            secret_value,
            secret_file: None,
            secret_sha256: [0; 32],
            legacy_0114: true,
            modern_0225: false,
            connection: ComponentConnectionMode::Accept,
            connect_endpoint: None,
            allow_public_connect: false,
        };
        assert!(validate_component_capacity(0, &[]).is_ok());
        assert!(validate_component_capacity(0, std::slice::from_ref(&outbound)).is_err());
        assert!(validate_component_capacity(0, std::slice::from_ref(&accept)).is_err());
        assert!(validate_component_capacity(2, std::slice::from_ref(&outbound)).is_ok());
        assert!(validate_component_capacity(2, &[outbound.clone(), accept.clone()]).is_err());
        assert!(validate_component_capacity(3, &[outbound, accept]).is_ok());
    }

    #[test]
    fn connect_component_profile_is_explicit_and_domain_claims_are_unique() {
        let directory = std::env::temp_dir().join(format!(
            "northstar-component-config-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&directory).unwrap();
        let secret = directory.join("component.secret");
        std::fs::write(&secret, "this-is-a-long-random-looking-component-secret\n").unwrap();
        restrict(&secret);
        let config = directory.join("components.json");
        let entry = serde_json::json!({
            "jid": "outbound.example",
            "aliases": ["alias.outbound.example"],
            "secret_file": secret,
            "connection": "connect",
            "connect_endpoint": "127.0.0.1:5347",
            "legacy_0114": true,
            "modern_0225": false
        });
        std::fs::write(
            &config,
            serde_json::json!({"components": [entry.clone()]}).to_string(),
        )
        .unwrap();
        restrict(&config);
        let loaded = load_component_credentials(&config, "example").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].connection, ComponentConnectionMode::Connect);
        assert_eq!(
            loaded[0].secret_value.as_ref().map(|value| value.as_str()),
            Some("this-is-a-long-random-looking-component-secret")
        );
        assert_eq!(loaded[0].secret_file.as_deref(), Some(secret.as_path()));
        assert_eq!(
            loaded[0].connect_endpoint.as_ref().unwrap().host,
            "127.0.0.1"
        );

        let mut inline = entry.clone();
        inline.as_object_mut().unwrap().remove("secret_file");
        inline.as_object_mut().unwrap().insert(
            "secret".to_owned(),
            serde_json::json!("this-is-an-inline-component-secret-value"),
        );
        std::fs::write(
            &config,
            serde_json::json!({"components": [inline.clone()]}).to_string(),
        )
        .unwrap();
        let inline_loaded = load_component_credentials(&config, "example").unwrap();
        assert!(inline_loaded[0].secret_file.is_none());
        assert_eq!(
            inline_loaded[0]
                .secret_value
                .as_ref()
                .map(|value| value.as_str()),
            Some("this-is-an-inline-component-secret-value")
        );

        let mut both_sources = inline.clone();
        both_sources
            .as_object_mut()
            .unwrap()
            .insert("secret_file".to_owned(), serde_json::json!(secret));
        std::fs::write(
            &config,
            serde_json::json!({"components": [both_sources]}).to_string(),
        )
        .unwrap();
        let both_error = match load_component_credentials(&config, "example") {
            Ok(_) => panic!("component accepted both inline and file secret sources"),
            Err(error) => error.to_string(),
        };
        assert!(both_error.contains("exactly one"));

        let mut missing_endpoint = entry.clone();
        missing_endpoint
            .as_object_mut()
            .unwrap()
            .remove("connect_endpoint");
        std::fs::write(
            &config,
            serde_json::json!({"components": [missing_endpoint]}).to_string(),
        )
        .unwrap();
        assert!(load_component_credentials(&config, "example").is_err());

        std::fs::write(
            &config,
            serde_json::json!({"components": [entry.clone(), entry]}).to_string(),
        )
        .unwrap();
        let duplicate = match load_component_credentials(&config, "example") {
            Ok(_) => panic!("duplicate component domain was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(duplicate.contains("globally unique"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn secret_files_drop_only_the_line_ending() {
        let path = std::env::temp_dir().join(format!(
            "northstar-config-secret-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, "  keep surrounding spaces  \r\n").unwrap();
        restrict(&path);
        let value = read_secret_file(&path, "TEST_SECRET_FILE").unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(value, "  keep surrounding spaces  ");
    }

    #[test]
    fn redis_transport_requires_tls_off_loopback_and_forbids_insecure_modes() {
        assert!(validate_redis_transport(None, None, None, None).is_ok());
        assert!(
            validate_redis_transport(Some("redis://127.0.0.1:6379/"), None, None, None).is_ok()
        );
        assert!(
            validate_redis_transport(Some("redis://localhost:6379/"), None, None, None).is_ok()
        );
        assert!(
            validate_redis_transport(Some("redis://cache.localhost:6379/"), None, None, None)
                .is_ok()
        );
        assert!(
            validate_redis_transport(Some("rediss://cache.internal:6379/"), None, None, None)
                .is_ok()
        );
        assert!(
            validate_redis_transport(Some("redis://10.0.0.8:6379/"), None, None, None).is_err()
        );
        assert!(
            validate_redis_transport(Some("redis://cache.internal:6379/"), None, None, None)
                .is_err()
        );
        assert!(validate_redis_transport(
            Some("rediss://cache.internal:6379/#insecure"),
            None,
            None,
            None
        )
        .is_err());
        assert!(
            validate_redis_transport(Some("http://cache.internal:6379/"), None, None, None)
                .is_err()
        );
    }

    #[test]
    fn development_database_role_override_accepts_only_local_redis_endpoints() {
        assert!(redis_endpoint_is_local(None).unwrap());
        assert!(redis_endpoint_is_local(Some("redis://127.0.0.1:6379/")).unwrap());
        assert!(redis_endpoint_is_local(Some("rediss://localhost:6379/")).unwrap());
        assert!(redis_endpoint_is_local(Some("rediss://cache.localhost:6379/")).unwrap());
        assert!(redis_endpoint_is_local(Some("redis+unix:///tmp/northstar-redis.sock")).unwrap());
        assert!(!redis_endpoint_is_local(Some("rediss://cache.internal:6379/")).unwrap());
        assert!(!redis_endpoint_is_local(Some("rediss://10.0.0.8:6379/")).unwrap());
        assert!(redis_endpoint_is_local(Some("https://cache.internal:6379/")).is_err());
    }

    #[test]
    fn redis_tls_files_require_secure_url_and_complete_client_identity() {
        let ca = std::path::Path::new("redis-ca.pem");
        let cert = std::path::Path::new("redis-client.pem");
        let key = std::path::Path::new("redis-client.key");
        assert!(validate_redis_transport(None, Some(ca), None, None).is_err());
        assert!(
            validate_redis_transport(Some("redis://127.0.0.1:6379/"), Some(ca), None, None)
                .is_err()
        );
        assert!(validate_redis_transport(
            Some("rediss://localhost:6379/"),
            Some(ca),
            Some(cert),
            None
        )
        .is_err());
        assert!(validate_redis_transport(
            Some("rediss://localhost:6379/"),
            Some(ca),
            None,
            Some(key)
        )
        .is_err());
        assert!(
            validate_redis_transport(Some("rediss://localhost:6379/"), Some(ca), None, None)
                .is_ok()
        );
        assert!(validate_redis_transport(
            Some("rediss://localhost:6379/"),
            Some(ca),
            Some(cert),
            Some(key)
        )
        .is_ok());
    }

    #[test]
    fn empty_secret_files_are_rejected() {
        let path = std::env::temp_dir().join(format!(
            "northstar-empty-secret-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, "\r\n").unwrap();
        restrict(&path);
        let error = read_secret_file(&path, "TEST_SECRET_FILE").unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert!(error.to_string().contains("empty or invalid"));
    }

    #[cfg(unix)]
    #[test]
    fn permissive_secret_files_are_rejected_without_reading_their_value() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "northstar-permissive-secret-{}.txt",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, "do-not-log-this-value\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_secret_file(&path, "TEST_SECRET_FILE").unwrap_err();
        std::fs::remove_file(path).unwrap();
        let error = error.to_string();
        assert!(error.contains("permissions 0400 or 0600"));
        assert!(!error.contains("do-not-log-this-value"));
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_secret_files_are_rejected() {
        use std::os::unix::fs::symlink;
        let nonce = uuid::Uuid::new_v4();
        let target = std::env::temp_dir().join(format!("northstar-secret-target-{nonce}"));
        let link = std::env::temp_dir().join(format!("northstar-secret-link-{nonce}"));
        std::fs::write(&target, "never-include-this-secret-in-an-error\n").unwrap();
        restrict(&target);
        symlink(&target, &link).unwrap();
        let error = read_secret_file(&link, "TEST_SECRET_FILE")
            .unwrap_err()
            .to_string();
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(target).unwrap();
        assert!(error.contains("non-symlink regular file"));
        assert!(!error.contains("never-include-this-secret"));
    }

    #[test]
    fn test_listener_addresses_overlap_port_zero() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        assert!(!listener_addresses_overlap(a, b));

        let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5222);
        assert!(!listener_addresses_overlap(a, c));

        let d = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5222);
        assert!(listener_addresses_overlap(c, d));
    }
}
