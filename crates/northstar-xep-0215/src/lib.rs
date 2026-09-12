#![forbid(unsafe_code)]

//! Capability-free XEP-0215 External Service Discovery wire and policy types.
//!
//! Provider secrets, time, credential derivation, authorization, rate limits,
//! service discovery and push delivery remain application responsibilities.

pub mod builder;
pub mod constants;
pub mod error;
pub mod model;
pub mod policy;
pub mod wire;

pub use builder::{build_credentials_result, build_services_push, build_services_result};
pub use constants::{
    DATA_FORMS_NAMESPACE, DESCRIPTOR, MAX_CREDENTIAL_REQUESTS, MAX_RESULT_SERVICES, NAMESPACE,
    XEP_ID,
};
pub use error::ExtDiscoError;
pub use model::{
    CredentialedService, CredentialsRequest, ExtDiscoRequest, ExtendedField, PublicService,
    SecretText, ServiceAction, ServiceCredentials, ServiceHost, ServiceIdentity, ServiceToken,
    ServicesRequest,
};
pub use policy::{plan_credential_matches, select_services};
pub use wire::{parse_credentials, parse_iq, parse_services};
