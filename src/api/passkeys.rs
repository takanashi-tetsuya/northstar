use super::*;
use crate::services::passkeys::{CredentialVersion, Login, Registration};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential, Webauthn};
use zeroize::{Zeroize, Zeroizing};

fn relying_party(state: &AppState, headers: &HeaderMap) -> Result<Webauthn> {
    if !state.config.web_client_enabled || !state.config.fast_token_enabled {
        return Err(AppError::NotFound("Passkeys are unavailable".into()));
    }
    let party = crate::services::passkeys::relying_party(&state.config.public_url)
        .map_err(|_| AppError::Unavailable("Passkeys are unavailable for this origin".into()))?;
    let expected = party.get_allowed_origins()[0]
        .origin()
        .ascii_serialization();
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if origins.next().and_then(|origin| origin.to_str().ok()) != Some(expected.as_str())
        || origins.next().is_some()
    {
        return Err(AppError::Forbidden);
    }
    Ok(party)
}

async fn guard_start(
    state: &AppState,
    peer: SocketAddr,
    headers: &HeaderMap,
    username: &str,
    path: &str,
    body: &Value,
    proof: Option<&crate::abuse::PowProof>,
) -> Result<()> {
    let (subject, actors) = login_abuse_identity(client_ip(peer.ip(), headers, state), username)
        .ok_or(AppError::Unauthorized)?;
    let intent = crate::abuse::PowIntent::http_json(AbuseAction::Login, path, body);
    state
        .abuse
        .verify_or_allow_v2(AbuseAction::Login, &subject, &actors, proof, &intent)
        .await?
        .map_err(rate_limited)?;
    Ok(())
}

async fn verify_password(state: &AppState, user: &ApiUser, password: &str) -> Result<()> {
    if password.is_empty() || password.len() > 1024 {
        return Err(AppError::Unauthorized);
    }
    let prepared = db::prepare_login(
        &state.pool,
        &user.username,
        password,
        state.config.scram_iterations,
        state.config.scram_sha1_enabled,
    )
    .await?;
    if !prepared.is_some_and(|login| {
        login.user.id == user.id && login.user.auth_generation == user.auth_generation
    }) {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

pub(super) async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let user = current_user(&state, &headers).await?;
    let mut tx = user.begin_authorized_read(&state).await?;
    let credentials = db::passkeys::credentials_in_tx(&mut tx, user.id).await?;
    tx.commit().await?;
    Ok(Json(json!({"passkeys":credentials})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegisterStart {
    password: String,
    label: String,
    pow: Option<crate::abuse::PowProof>,
}

pub(super) async fn register_start(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut body): Json<RegisterStart>,
) -> Result<Json<Value>> {
    let party = relying_party(&state, &headers)?;
    let user = current_user(&state, &headers).await?;
    let password = Zeroizing::new(std::mem::take(&mut body.password));
    if body.label.trim().is_empty()
        || body.label.chars().count() > 64
        || body.label.chars().any(char::is_control)
    {
        return Err(AppError::BadRequest(
            "Passkey name must contain 1 to 64 characters".into(),
        ));
    }
    guard_start(
        &state,
        peer,
        &headers,
        &user.username,
        "/api/v1/me/passkeys/register/start",
        &json!({"password":password.as_str(),"label":body.label}),
        body.pow.as_ref(),
    )
    .await?;
    verify_password(&state, &user, &password).await?;
    let keys = db::passkeys::credentials(&state.pool, user.id).await?;
    if keys.len() >= 10 {
        return Err(AppError::BadRequest(
            "An account can have at most 10 Passkeys".into(),
        ));
    }
    let excluded = keys
        .into_iter()
        .map(|key| {
            serde_json::from_value::<Passkey>(key.credential).map(|key| key.cred_id().clone())
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| AppError::Internal(error.into()))?;
    let (options, registration) = party
        .start_passkey_registration(user.id, &user.username, &user.username, Some(excluded))
        .map_err(|error| AppError::Internal(error.into()))?;
    let stored = serde_json::to_value(Registration {
        state: registration,
        label: std::mem::take(&mut body.label),
    })
    .map_err(|error| AppError::Internal(error.into()))?;
    let id = db::passkeys::challenge(
        &state.pool,
        user.id,
        user.auth_generation,
        "register",
        Some(&auth::token_hash(user.session_token())),
        &stored,
    )
    .await?
    .ok_or_else(|| AppError::TooManyRequests {
        message: "Too many unfinished Passkey requests; try again later".into(),
        retry_after: 300,
    })?;
    Ok(Json(json!({"challenge_id":id,"options":options})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegisterFinish {
    challenge_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

pub(super) async fn register_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinish>,
) -> Result<Json<Value>> {
    let party = relying_party(&state, &headers)?;
    let user = current_user(&state, &headers).await?;
    let session = auth::token_hash(user.session_token());
    let challenge =
        db::passkeys::consume(&state.pool, body.challenge_id, "register", Some(&session))
            .await?
            .ok_or(AppError::Unauthorized)?;
    if challenge.user_id != user.id || challenge.auth_generation != user.auth_generation {
        return Err(AppError::Unauthorized);
    }
    let registration: Registration = serde_json::from_value(challenge.state)
        .map_err(|error| AppError::Internal(error.into()))?;
    let key = party
        .finish_passkey_registration(&body.credential, &registration.state)
        .map_err(|_| AppError::Unauthorized)?;
    let stored = serde_json::to_value(&key).map_err(|error| AppError::Internal(error.into()))?;
    let id = db::passkeys::register(
        &state.pool,
        user.id,
        user.auth_generation,
        &session,
        key.cred_id().as_ref(),
        &stored,
        &registration.label,
    )
    .await?
    .ok_or_else(|| AppError::BadRequest("Passkey could not be added; start again".into()))?;
    Ok(Json(json!({"id":id})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginStart {
    username: String,
    device_id: Uuid,
    pow: Option<crate::abuse::PowProof>,
}

pub(super) async fn login_start(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginStart>,
) -> Result<Json<Value>> {
    let party = relying_party(&state, &headers)?;
    if body.device_id.get_version_num() != 4 {
        return Err(AppError::BadRequest("Invalid device ID".into()));
    }
    guard_start(
        &state,
        peer,
        &headers,
        &body.username,
        "/api/v1/passkeys/login/start",
        &json!({"username":body.username,"device_id":body.device_id}),
        body.pow.as_ref(),
    )
    .await?;
    let user = db::find_enabled_user(&state.pool, &body.username)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let credentials = db::passkeys::credentials(&state.pool, user.id)
        .await?
        .into_iter()
        .map(|key| {
            Ok(CredentialVersion {
                id: key.id,
                revision: key.revision,
                passkey: serde_json::from_value(key.credential)?,
            })
        })
        .collect::<std::result::Result<Vec<_>, serde_json::Error>>()
        .map_err(|error| AppError::Internal(error.into()))?;
    if credentials.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let keys = credentials
        .iter()
        .map(|key| key.passkey.clone())
        .collect::<Vec<_>>();
    let (options, login) = party
        .start_passkey_authentication(&keys)
        .map_err(|error| AppError::Internal(error.into()))?;
    let stored = serde_json::to_value(Login {
        state: login,
        device_id: body.device_id,
        credentials,
    })
    .map_err(|error| AppError::Internal(error.into()))?;
    let id = db::passkeys::challenge(
        &state.pool,
        user.id,
        user.auth_generation,
        "login",
        None,
        &stored,
    )
    .await?
    .ok_or_else(|| AppError::TooManyRequests {
        message: "Too many unfinished Passkey requests; try again later".into(),
        retry_after: 300,
    })?;
    Ok(Json(json!({"challenge_id":id,"options":options})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginFinish {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
}

pub(super) async fn login_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<LoginFinish>,
) -> Result<Json<Value>> {
    let party = relying_party(&state, &headers)?;
    let challenge = db::passkeys::consume(&state.pool, body.challenge_id, "login", None)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let login: Login = serde_json::from_value(challenge.state)
        .map_err(|error| AppError::Internal(error.into()))?;
    let result = party
        .finish_passkey_authentication(&body.credential, &login.state)
        .map_err(|_| AppError::Unauthorized)?;
    let mut key = login
        .credentials
        .into_iter()
        .find(|key| key.passkey.cred_id() == result.cred_id())
        .ok_or(AppError::Unauthorized)?;
    key.passkey
        .update_credential(&result)
        .ok_or(AppError::Unauthorized)?;
    let stored =
        serde_json::to_value(&key.passkey).map_err(|error| AppError::Internal(error.into()))?;
    let mut tx = state.pool.begin().await?;
    if !db::passkeys::accept(
        &mut tx,
        challenge.user_id,
        challenge.auth_generation,
        key.id,
        key.revision,
        &stored,
        result.counter(),
    )
    .await?
    {
        return Err(AppError::Unauthorized);
    }
    let fast = state
        .authentication_service()
        .issue_passkey_token(
            &mut tx,
            crate::services::authentication::AuthenticationFence {
                user_id: challenge.user_id,
                auth_generation: challenge.auth_generation,
            },
            login.device_id,
            state.config.fast_token_ttl_days,
            state.config.fast_strong_reauth_max_days,
        )
        .await?;
    let session = db::create_api_session_in_tx(
        &mut tx,
        challenge.user_id,
        state.config.session_ttl_hours,
        None,
    )
    .await?;
    let user = db::user_for_token_in_tx(&mut tx, &session.token)
        .await?
        .ok_or(AppError::Unauthorized)?;
    tx.commit().await?;
    Ok(Json(
        json!({"token":session.token,"jid":format!("{}@{}",user.username,state.config.domain),
        "is_admin":user.is_admin,"device_id":login.device_id,
        "fast":{"mechanism":"HT-SHA-256-NONE","token":fast.token.as_str(),"expiry":fast.expires_at.timestamp_millis()}}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Remove {
    id: Uuid,
    password: String,
    pow: Option<crate::abuse::PowProof>,
}

pub(super) async fn remove(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut body): Json<Remove>,
) -> Result<Json<Value>> {
    relying_party(&state, &headers)?;
    let user = current_user(&state, &headers).await?;
    let password = Zeroizing::new(std::mem::take(&mut body.password));
    guard_start(
        &state,
        peer,
        &headers,
        &user.username,
        "/api/v1/me/passkeys/remove",
        &json!({"id":body.id,"password":password.as_str()}),
        body.pow.as_ref(),
    )
    .await?;
    verify_password(&state, &user, &password).await?;
    let generation = db::passkeys::remove(
        &state.pool,
        user.id,
        user.auth_generation,
        &auth::token_hash(user.session_token()),
        body.id,
    )
    .await?
    .ok_or(AppError::Unauthorized)?;
    state
        .disconnect_account_before_auth_generation(
            user.id,
            &format!("{}@{}", user.username, state.config.domain),
            generation,
        )
        .await;
    Ok(Json(json!({"removed":true,"signed_out":true})))
}

impl Drop for RegisterStart {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
impl Drop for Remove {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
