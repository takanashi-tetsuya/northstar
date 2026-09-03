//! Bounded, credential-aware XEP-0215 value types.

use crate::constants::{
    MAX_CREDENTIAL_BYTES, MAX_EXTENDED_FIELDS, MAX_FIELD_VALUES, MAX_FIELD_VALUE_BYTES,
    MAX_LABEL_BYTES, MAX_SERVICE_TYPE_BYTES,
};
use crate::error::ExtDiscoError;
use northstar_xmpp_types::jid::prepare_domainpart;
use std::{fmt, net::IpAddr, num::NonZeroU16};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ServiceHost {
    Ip(IpAddr),
    Domain(String),
}

impl ServiceHost {
    pub fn parse(value: &str) -> Result<Self, ExtDiscoError> {
        if value.is_empty()
            || value.len() > 1_023
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ExtDiscoError::InvalidHost(value.to_owned()));
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(address));
        }
        let domain =
            prepare_domainpart(value).map_err(|_| ExtDiscoError::InvalidHost(value.to_owned()))?;
        if domain.starts_with('[') {
            return Err(ExtDiscoError::InvalidHost(value.to_owned()));
        }
        Ok(Self::Domain(domain))
    }
}

impl fmt::Display for ServiceHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(formatter),
            Self::Domain(domain) => formatter.write_str(domain),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceToken(String);

impl ServiceToken {
    pub fn parse_service_type(value: &str) -> Result<Self, ExtDiscoError> {
        validate_ncname(value)
            .then(|| Self(value.to_owned()))
            .ok_or_else(|| ExtDiscoError::InvalidServiceType(value.to_owned()))
    }

    pub fn parse_transport(value: &str) -> Result<Self, ExtDiscoError> {
        validate_ncname(value)
            .then(|| Self(value.to_owned()))
            .ok_or_else(|| ExtDiscoError::InvalidTransport(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_ncname(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_SERVICE_TYPE_BYTES || value.contains(':') {
        return false;
    }
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && chars.all(|character| {
            character == '_' || character == '-' || character == '.' || character.is_alphanumeric()
        })
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceIdentity {
    pub host: ServiceHost,
    pub service_type: ServiceToken,
    pub port: Option<NonZeroU16>,
    pub transport: Option<ServiceToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAction {
    Add,
    Delete,
    Modify,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedField {
    pub var: String,
    pub label: Option<String>,
    pub values: Vec<String>,
}

impl ExtendedField {
    pub fn new(
        var: impl Into<String>,
        label: Option<String>,
        values: Vec<String>,
    ) -> Result<Self, ExtDiscoError> {
        let var = var.into();
        if !valid_text(&var, MAX_LABEL_BYTES)
            || label
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_LABEL_BYTES))
            || values.len() > MAX_FIELD_VALUES
            || values
                .iter()
                .any(|value| !valid_text(value, MAX_FIELD_VALUE_BYTES))
        {
            return Err(ExtDiscoError::ExtendedDataLimit);
        }
        Ok(Self { var, label, values })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicService {
    pub identity: ServiceIdentity,
    pub name: Option<String>,
    pub restricted: bool,
    pub action: Option<ServiceAction>,
    pub extended: Vec<ExtendedField>,
}

impl PublicService {
    pub fn new(identity: ServiceIdentity) -> Self {
        Self {
            identity,
            name: None,
            restricted: false,
            action: None,
            extended: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), ExtDiscoError> {
        if self
            .name
            .as_deref()
            .is_some_and(|value| !valid_text(value, MAX_LABEL_BYTES))
        {
            return Err(ExtDiscoError::InvalidLabel);
        }
        if self.extended.len() > MAX_EXTENDED_FIELDS {
            return Err(ExtDiscoError::ExtendedDataLimit);
        }
        Ok(())
    }
}

pub struct SecretText(Zeroizing<String>);

impl SecretText {
    pub fn new(value: impl Into<String>) -> Result<Self, ExtDiscoError> {
        let value = value.into();
        if !valid_text(&value, MAX_CREDENTIAL_BYTES) {
            return Err(ExtDiscoError::InvalidCredentials);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretText(<redacted>)")
    }
}

#[derive(Debug)]
pub struct ServiceCredentials {
    pub username: String,
    pub password: SecretText,
    pub expires: String,
}

impl ServiceCredentials {
    pub fn new(
        username: impl Into<String>,
        password: SecretText,
        expires: impl Into<String>,
    ) -> Result<Self, ExtDiscoError> {
        let username = username.into();
        let expires = expires.into();
        if !valid_text(&username, MAX_CREDENTIAL_BYTES) {
            return Err(ExtDiscoError::InvalidCredentials);
        }
        let parsed = chrono::DateTime::parse_from_rfc3339(&expires)
            .map_err(|_| ExtDiscoError::InvalidExpiry)?;
        if expires.as_bytes().get(10) != Some(&b'T')
            || !expires.ends_with('Z')
            || parsed.offset().local_minus_utc() != 0
        {
            return Err(ExtDiscoError::InvalidExpiry);
        }
        Ok(Self {
            username,
            password,
            expires,
        })
    }
}

#[derive(Debug)]
pub struct CredentialedService {
    pub service: PublicService,
    pub credentials: ServiceCredentials,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicesRequest {
    pub service_type: Option<ServiceToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialsRequest {
    pub services: Vec<ServiceIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtDiscoRequest {
    Services(ServicesRequest),
    Credentials(CredentialsRequest),
}

fn valid_text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
