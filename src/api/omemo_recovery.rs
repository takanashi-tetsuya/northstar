use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    api::{
        current_user, ApiJson, ApiPath, OmemoRecoveryConsumeRequest, OmemoRecoveryPollRequest,
        OmemoRecoveryPrepareRequest, OmemoRecoverySealRequest,
    },
    error::AppError,
    services::omemo_recovery::*,
    state::AppState,
};

fn recovery_actor(user: &crate::api::ApiUser) -> OmemoRecoveryActor<'_> {
    OmemoRecoveryActor {
        user_id: user.id,
        auth_generation: user.auth_generation,
        session_token: user.session_token(),
    }
}

fn parse_sha256(value: &str) -> Result<[u8; 32], AppError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "package_sha256 must be exactly 64 hexadecimal characters".into(),
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|_| AppError::BadRequest("package_sha256 is invalid".into()))?;
        digest[index] = u8::from_str_radix(text, 16)
            .map_err(|_| AppError::BadRequest("package_sha256 is invalid".into()))?;
    }
    Ok(digest)
}

fn hex_digest(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_transfer_secret(value: &str, field: &str) -> Result<[u8; 32], AppError> {
    let mut decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        AppError::BadRequest(format!(
            "{field} must be canonical unpadded base64url encoding of exactly 32 bytes"
        ))
    })?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
        decoded.zeroize();
        return Err(AppError::BadRequest(format!(
            "{field} must be canonical unpadded base64url encoding of exactly 32 bytes"
        )));
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(secret)
}

fn transfer_view(transfer: &OmemoRecoveryTransfer) -> Value {
    json!({
        "id": transfer.id,
        "generation": transfer.generation,
        "source_device_id": transfer.source_device_id,
        "package_sha256": transfer.package_sha256.as_ref().map(hex_digest),
        "state": if transfer.expired && matches!(transfer.state.as_str(), "preparing" | "prepared") {
            "expired"
        } else {
            transfer.state.as_str()
        },
        "consumer_commitment": transfer.consumer_commitment.as_ref().map(hex_digest),
        "created_at": transfer.created_at,
        "prepared_at": transfer.prepared_at,
        "consumed_at": transfer.consumed_at,
        "revoked_at": transfer.revoked_at,
        "expires_at": transfer.expires_at,
    })
}

fn transfer_response(
    status: StatusCode,
    transfer: &OmemoRecoveryTransfer,
    replayed: bool,
) -> Result<Response, AppError> {
    let body = serde_json::to_vec(&transfer_view(transfer))
        .map_err(|error| AppError::Internal(error.into()))?;
    let mut response = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store, max-age=0");
    if replayed {
        response = response.header("idempotency-replayed", "true");
    }
    response
        .body(Body::from(body))
        .map_err(|error| AppError::Internal(error.into()))
}

pub async fn prepare_omemo_recovery(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: ApiJson<OmemoRecoveryPrepareRequest>,
) -> Result<Response, AppError> {
    let user = current_user(&state, &headers).await?;
    if request.transfer_id.is_nil() {
        return Err(AppError::BadRequest(
            "transfer_id must be a non-zero UUID".into(),
        ));
    }
    if !(1..=2_147_483_647).contains(&request.source_device_id) {
        return Err(AppError::BadRequest(
            "source_device_id must be between 1 and 2147483647".into(),
        ));
    }
    let source_device_id = i64::from(request.source_device_id);
    let poll_secret = Zeroizing::new(parse_transfer_secret(&request.poll_secret, "poll_secret")?);
    request.value.poll_secret.zeroize();
    let canonical_account = format!(
        "{}@{}",
        user.username,
        state.public_discovery_context().policy().domain
    );
    match state
        .omemo_recovery_service()
        .prepare(PrepareOmemoRecoveryRequest {
            user_id: user.id,
            canonical_account: &canonical_account,
            expected_auth_generation: user.auth_generation,
            presented_session: user.session_token(),
            transfer_id: request.transfer_id,
            source_device_id,
            poll_secret: &poll_secret,
        })
        .await?
    {
        PrepareOmemoRecovery::Prepared(transfer) => {
            transfer_response(StatusCode::CREATED, &transfer, false)
        }
        PrepareOmemoRecovery::Replay(transfer) => {
            transfer_response(StatusCode::OK, &transfer, true)
        }
        PrepareOmemoRecovery::Conflict => Err(AppError::Conflict(
            "the OMEMO recovery transfer identifier is already bound differently".into(),
        )),
        PrepareOmemoRecovery::Unauthorized => Err(AppError::Unauthorized),
    }
}

pub async fn seal_omemo_recovery(
    State(state): State<Arc<AppState>>,
    ApiPath(transfer_id): ApiPath<Uuid>,
    headers: HeaderMap,
    request: ApiJson<OmemoRecoverySealRequest>,
) -> Result<Response, AppError> {
    let user = current_user(&state, &headers).await?;
    let digest = parse_sha256(&request.package_sha256)?;
    match state
        .omemo_recovery_service()
        .seal(recovery_actor(&user), transfer_id, &digest)
        .await?
    {
        SealOmemoRecovery::Sealed(transfer) => transfer_response(StatusCode::OK, &transfer, false),
        SealOmemoRecovery::Replay(transfer) => transfer_response(StatusCode::OK, &transfer, true),
        SealOmemoRecovery::Missing => Err(AppError::NotFound(
            "OMEMO recovery transfer does not exist".into(),
        )),
        SealOmemoRecovery::Expired => Err(AppError::Conflict(
            "OMEMO recovery transfer has expired".into(),
        )),
        SealOmemoRecovery::Conflict => Err(AppError::Conflict(
            "OMEMO recovery transfer cannot be sealed in its current state".into(),
        )),
        SealOmemoRecovery::Unauthorized => Err(AppError::Unauthorized),
    }
}

pub async fn get_omemo_recovery(
    State(state): State<Arc<AppState>>,
    ApiPath(transfer_id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    let transfer = match state
        .omemo_recovery_service()
        .transfer(recovery_actor(&user), transfer_id)
        .await?
    {
        OmemoRecoveryRead::Authorized(value) => value
            .ok_or_else(|| AppError::NotFound("OMEMO recovery transfer does not exist".into()))?,
        OmemoRecoveryRead::Unauthorized => return Err(AppError::Unauthorized),
    };
    Ok(Json(transfer_view(&transfer)))
}

pub async fn get_omemo_recovery_authority(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = current_user(&state, &headers).await?;
    let authority = match state
        .omemo_recovery_service()
        .authority(recovery_actor(&user))
        .await?
    {
        OmemoRecoveryRead::Authorized(value) => value,
        OmemoRecoveryRead::Unauthorized => return Err(AppError::Unauthorized),
    };
    let body = serde_json::to_vec(&json!({
        "next_generation": authority.next_generation,
        "latest_consumed_generation": authority.latest_consumed_generation,
        "latest_consumed_transfer_id": authority.latest_consumed_transfer_id,
        "latest_consumer_commitment": authority.latest_consumer_commitment.as_ref().map(hex_digest),
    }))
    .map_err(|error| AppError::Internal(error.into()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store, max-age=0")
        .body(Body::from(body))
        .map_err(|error| AppError::Internal(error.into()))
}

pub async fn consume_omemo_recovery(
    State(state): State<Arc<AppState>>,
    ApiPath(transfer_id): ApiPath<Uuid>,
    headers: HeaderMap,
    mut request: ApiJson<OmemoRecoveryConsumeRequest>,
) -> Result<Response, AppError> {
    let user = current_user(&state, &headers).await?;
    let digest = parse_sha256(&request.package_sha256)?;
    let consumer_secret = Zeroizing::new(parse_transfer_secret(
        &request.consumer_secret,
        "consumer_secret",
    )?);
    request.value.consumer_secret.zeroize();
    let canonical_account = format!(
        "{}@{}",
        user.username,
        state.public_discovery_context().policy().domain
    );
    let result = state
        .omemo_recovery_service()
        .consume(ConsumeOmemoRecoveryRequest {
            user_id: user.id,
            canonical_account: &canonical_account,
            expected_auth_generation: user.auth_generation,
            presented_session: user.session_token(),
            transfer_id,
            consumer_secret: &consumer_secret,
            package_sha256: &digest,
        })
        .await?;
    let (transfer, replayed) = match result {
        ConsumeOmemoRecovery::Consumed(transfer) => (transfer, false),
        ConsumeOmemoRecovery::Replay(transfer) => (transfer, true),
        ConsumeOmemoRecovery::Missing => {
            return Err(AppError::NotFound(
                "OMEMO recovery transfer does not exist".into(),
            ));
        }
        ConsumeOmemoRecovery::Expired => {
            return Err(AppError::Conflict(
                "OMEMO recovery transfer has expired".into(),
            ));
        }
        ConsumeOmemoRecovery::Conflict => {
            return Err(AppError::Conflict(
                "OMEMO recovery package is stale, changed, or already consumed elsewhere".into(),
            ));
        }
        ConsumeOmemoRecovery::Unauthorized => return Err(AppError::Unauthorized),
    };
    let response = transfer_response(StatusCode::OK, &transfer, replayed)?;

    // Only the first commit owns the post-commit transport teardown.  An exact
    // retry returns the durable result without disconnecting a destination
    // which has already authenticated at the newer generation.
    if !replayed {
        let cutoff = transfer.consumed_auth_generation.ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!(
                "consumed OMEMO recovery transfer has no authorization fence"
            ))
        })?;
        state
            .disconnect_account_before_auth_generation(
                user.id,
                &format!(
                    "{}@{}",
                    user.username,
                    state.public_discovery_context().policy().domain
                ),
                cutoff,
            )
            .await;
    }
    Ok(response)
}

pub async fn poll_omemo_recovery(
    State(state): State<crate::state::OmemoRecoveryPollContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ApiPath(transfer_id): ApiPath<Uuid>,
    headers: HeaderMap,
    mut request: ApiJson<OmemoRecoveryPollRequest>,
) -> Result<Response, AppError> {
    state.record_request();
    let source_ip =
        crate::api::client_ip_with_trusted_proxies(peer.ip(), &headers, state.trusted_proxies());
    let _poll_permit = state.acquire(source_ip).ok_or_else(|| {
        AppError::RateLimited(json!({
            "message": "OMEMO recovery polling is temporarily limited",
            "retry_after_seconds": 2
        }))
    })?;
    let poll_secret = Zeroizing::new(parse_transfer_secret(&request.poll_secret, "poll_secret")?);
    request.value.poll_secret.zeroize();
    // Deliberately do not consult or accept an API bearer here. The first
    // consume invalidates every old bearer in the same commit. This endpoint
    // is a narrowly scoped, read-only capability for resolving that uncertain
    // commit and returns the same not-found result for an unknown ID, a wrong
    // secret, or an expired capability.
    let status = state
        .poll(transfer_id, &poll_secret)
        .await?
        .ok_or_else(|| {
            state.record_not_found();
            AppError::NotFound("OMEMO recovery poll capability is unavailable".into())
        })?;
    let body = serde_json::to_vec(&json!({
        "generation": status.generation,
        "state": status.state,
    }))
    .map_err(|error| AppError::Internal(error.into()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store, max-age=0")
        .body(Body::from(body))
        .map_err(|error| AppError::Internal(error.into()))
}

pub async fn revoke_omemo_recovery(
    State(state): State<Arc<AppState>>,
    ApiPath(transfer_id): ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let user = current_user(&state, &headers).await?;
    match state
        .omemo_recovery_service()
        .revoke(recovery_actor(&user), transfer_id)
        .await?
    {
        RevokeOmemoRecovery::Revoked | RevokeOmemoRecovery::Replay => Ok(StatusCode::NO_CONTENT),
        RevokeOmemoRecovery::Missing => Err(AppError::NotFound(
            "OMEMO recovery transfer does not exist".into(),
        )),
        RevokeOmemoRecovery::Conflict => Err(AppError::Conflict(
            "a consumed OMEMO recovery transfer cannot be revoked".into(),
        )),
        RevokeOmemoRecovery::Unauthorized => Err(AppError::Unauthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_digest_parser_is_exact_and_case_tolerant() {
        assert_eq!(parse_sha256(&"aB".repeat(32)).unwrap(), [0xab; 32]);
        let invalid = [
            String::new(),
            "0".repeat(63),
            "0".repeat(65),
            "z0".repeat(32),
        ];
        for value in invalid {
            assert!(parse_sha256(&value).is_err());
        }
    }

    #[test]
    fn transfer_secret_parser_requires_canonical_256_bits() {
        let canonical = URL_SAFE_NO_PAD.encode([0x5a_u8; 32]);
        assert_eq!(
            parse_transfer_secret(&canonical, "secret").unwrap(),
            [0x5a_u8; 32]
        );
        for invalid in [
            URL_SAFE_NO_PAD.encode([0x5a_u8; 31]),
            format!("{canonical}="),
            "not_base64url!".to_owned(),
        ] {
            assert!(parse_transfer_secret(&invalid, "secret").is_err());
        }
    }
}
