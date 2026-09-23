use super::*;
use crate::services::passkeys::{PasskeyActor, PasskeyError};
use crate::state::{
    account_generation_teardown::AccountGenerationTeardownSequence,
    passkey_http::{PasskeyAccountHttpContext, PasskeyStartHttpContext},
    PasskeyLoginFinishContext,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};
use zeroize::{Zeroize, Zeroizing};

impl From<PasskeyError> for AppError {
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::Unauthorized => Self::Unauthorized,
            PasskeyError::Disabled => Self::NotFound("Passkeys are unavailable".into()),
            PasskeyError::InvalidOrigin => {
                Self::Unavailable("Passkeys are unavailable for this origin".into())
            }
            PasskeyError::Invalid(message) => Self::BadRequest(message.into()),
            PasskeyError::Busy => Self::TooManyRequests {
                message: "Too many unfinished Passkey requests; try again later".into(),
                retry_after: 300,
            },
            PasskeyError::Backend(error) => Self::Internal(error),
        }
    }
}

fn check_expected_origin(expected: &str, headers: &HeaderMap) -> Result<()> {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if origins.next().and_then(|origin| origin.to_str().ok()) != Some(expected)
        || origins.next().is_some()
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn actor(user: &ApiUser) -> PasskeyActor<'_> {
    PasskeyActor {
        id: user.id,
        username: &user.username,
        auth_generation: user.auth_generation,
        session_token: user.session_token(),
    }
}

async fn guard_start(
    state: &PasskeyStartHttpContext,
    peer: SocketAddr,
    headers: &HeaderMap,
    username: &str,
    path: &str,
    body: &Value,
    proof: Option<&crate::abuse::PowProof>,
) -> Result<()> {
    let ip = client_ip_with_trusted_proxies(peer.ip(), headers, state.trusted_proxies());
    let (subject, actors) = login_abuse_identity(ip, username).ok_or(AppError::Unauthorized)?;
    let intent = crate::abuse::PowIntent::http_json(AbuseAction::Login, path, body);
    state
        .verify_start(&subject, &actors, proof, &intent)
        .await?
        .map_err(rate_limited)?;
    Ok(())
}

pub(super) async fn list(
    State(state): State<PasskeyAccountHttpContext>,
    State(queries): State<crate::state::ApiQueryContext>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let user = current_user_with_queries(&queries, &headers).await?;
    let credentials = state.list(actor(&user)).await?;
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
    State(state): State<PasskeyStartHttpContext>,
    State(queries): State<crate::state::ApiQueryContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut body): Json<RegisterStart>,
) -> Result<Json<Value>> {
    check_expected_origin(&state.allowed_origin()?, &headers)?;
    let user = current_user_with_queries(&queries, &headers).await?;
    let password = Zeroizing::new(std::mem::take(&mut body.password));
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
    let start = state
        .register_start(actor(&user), &password, std::mem::take(&mut body.label))
        .await?;
    Ok(Json(
        json!({"challenge_id":start.challenge_id,"options":start.options}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RegisterFinish {
    challenge_id: Uuid,
    credential: RegisterPublicKeyCredential,
}

pub(super) async fn register_finish(
    State(state): State<PasskeyAccountHttpContext>,
    State(queries): State<crate::state::ApiQueryContext>,
    headers: HeaderMap,
    Json(body): Json<RegisterFinish>,
) -> Result<Json<Value>> {
    check_expected_origin(&state.allowed_origin()?, &headers)?;
    let user = current_user_with_queries(&queries, &headers).await?;
    let id = state
        .register_finish(actor(&user), body.challenge_id, body.credential)
        .await?;
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
    State(state): State<PasskeyStartHttpContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginStart>,
) -> Result<Json<Value>> {
    check_expected_origin(&state.allowed_origin()?, &headers)?;
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
    let start = state.login_start(&body.username, body.device_id).await?;
    Ok(Json(
        json!({"challenge_id":start.challenge_id,"options":start.options}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginFinish {
    challenge_id: Uuid,
    credential: PublicKeyCredential,
}

pub(super) async fn login_finish(
    State(state): State<PasskeyLoginFinishContext>,
    headers: HeaderMap,
    Json(body): Json<LoginFinish>,
) -> Result<Json<Value>> {
    check_expected_origin(&state.allowed_origin()?, &headers)?;
    let login = state.finish(body.challenge_id, body.credential).await?;
    Ok(Json(
        json!({"token":login.session.token.as_str(),"jid":login.jid,
        "is_admin":login.session.is_admin,"device_id":login.device_id,
        "fast":{"mechanism":"HT-SHA-256-NONE","token":login.session.fast_token.as_str(),"expiry":login.session.fast_expires_at.timestamp_millis()}}),
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
    State(teardown): State<AccountGenerationTeardownSequence>,
    State(start): State<PasskeyStartHttpContext>,
    State(account): State<PasskeyAccountHttpContext>,
    State(queries): State<crate::state::ApiQueryContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(mut body): Json<Remove>,
) -> Result<Json<Value>> {
    check_expected_origin(&start.allowed_origin()?, &headers)?;
    let user = current_user_with_queries(&queries, &headers).await?;
    let password = Zeroizing::new(std::mem::take(&mut body.password));
    guard_start(
        &start,
        peer,
        &headers,
        &user.username,
        "/api/v1/me/passkeys/remove",
        &json!({"id":body.id,"password":password.as_str()}),
        body.pow.as_ref(),
    )
    .await?;
    let generation = account.remove(actor(&user), &password, body.id).await?;
    teardown
        .run(
            user.id,
            &format!("{}@{}", user.username, queries.domain()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_finish_origin_requires_one_exact_header() {
        let expected = "https://xmpp.example";
        let mut headers = HeaderMap::new();
        assert!(matches!(
            check_expected_origin(expected, &headers),
            Err(AppError::Forbidden)
        ));

        headers.insert(header::ORIGIN, "https://other.example".parse().unwrap());
        assert!(matches!(
            check_expected_origin(expected, &headers),
            Err(AppError::Forbidden)
        ));

        headers.insert(header::ORIGIN, expected.parse().unwrap());
        assert!(check_expected_origin(expected, &headers).is_ok());

        headers.append(header::ORIGIN, expected.parse().unwrap());
        assert!(matches!(
            check_expected_origin(expected, &headers),
            Err(AppError::Forbidden)
        ));
    }
}
