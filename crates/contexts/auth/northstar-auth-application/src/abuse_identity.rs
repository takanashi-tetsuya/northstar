//! The anti-abuse subject and actors of an authentication attempt, shared by the HTTP login and XMPP legacy
//! authentication so that both count against the same budgets.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use northstar_auth_core::{normalize_username, token_hash};
use std::net::IpAddr;

/// The anti-abuse actor of a client address.
pub fn ip_actor(ip: IpAddr) -> String {
    format!("ip:{ip}")
}

/// The anti-abuse subject and actors of a login: the client address and the normalized account, hashed so the
/// account name is not stored. `None` for an empty or oversized username.
pub fn login_abuse_identity(ip: IpAddr, username: &str) -> Option<(String, Vec<String>)> {
    if username.is_empty() || username.len() > 1024 {
        return None;
    }
    let identity = normalize_username(username).unwrap_or_else(|_| username.to_owned());
    let digest = token_hash(&identity);
    let account_actor = format!("login-account:{}", URL_SAFE_NO_PAD.encode(digest));
    Some((
        format!("login:{ip}:{account_actor}"),
        vec![ip_actor(ip), account_actor],
    ))
}

#[cfg(test)]
mod tests;
