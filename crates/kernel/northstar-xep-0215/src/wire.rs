//! Strict, bounded parsing for XEP-0215 request IQs.

use crate::constants::{MAX_CREDENTIAL_REQUESTS, NAMESPACE};
use crate::error::ExtDiscoError;
use crate::model::{
    CredentialsRequest, ExtDiscoRequest, ServiceHost, ServiceIdentity, ServiceToken,
    ServicesRequest,
};
use roxmltree::Node;
use std::{collections::HashSet, num::NonZeroU16};

pub fn parse_iq(root: Node<'_, '_>) -> Result<ExtDiscoRequest, ExtDiscoError> {
    if !root.is_element() || root.tag_name().name() != "iq" {
        return Err(ExtDiscoError::NotIq);
    }
    if root.attribute("type") != Some("get") {
        return Err(ExtDiscoError::WrongIqType);
    }
    let payloads = root.children().filter(Node::is_element).collect::<Vec<_>>();
    if payloads.len() != 1 || payloads[0].tag_name().namespace() != Some(NAMESPACE) {
        return Err(ExtDiscoError::AmbiguousIqPayload);
    }
    match payloads[0].tag_name().name() {
        "services" => parse_services(payloads[0]).map(ExtDiscoRequest::Services),
        "credentials" => parse_credentials(payloads[0]).map(ExtDiscoRequest::Credentials),
        name => Err(ExtDiscoError::UnexpectedElement(name.to_owned())),
    }
}

pub fn parse_services(node: Node<'_, '_>) -> Result<ServicesRequest, ExtDiscoError> {
    ensure_element(node, "services")?;
    if node
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || attribute.name() != "type")
        || has_content(node)
    {
        return Err(ExtDiscoError::InvalidPayloadShape);
    }
    let service_type = node
        .attribute("type")
        .map(ServiceToken::parse_service_type)
        .transpose()?;
    Ok(ServicesRequest { service_type })
}

pub fn parse_credentials(node: Node<'_, '_>) -> Result<CredentialsRequest, ExtDiscoError> {
    ensure_element(node, "credentials")?;
    if node.attributes().len() != 0 || has_non_whitespace_text(node) {
        return Err(ExtDiscoError::InvalidPayloadShape);
    }
    let services = node.children().filter(Node::is_element).collect::<Vec<_>>();
    if services.is_empty() || services.len() > MAX_CREDENTIAL_REQUESTS {
        return Err(ExtDiscoError::CredentialRequestCount {
            limit: MAX_CREDENTIAL_REQUESTS,
        });
    }
    let mut identities = Vec::with_capacity(services.len());
    let mut seen = HashSet::with_capacity(services.len());
    for service in services {
        let identity = parse_credential_service(service)?;
        if seen.insert(identity.clone()) {
            identities.push(identity);
        }
    }
    Ok(CredentialsRequest {
        services: identities,
    })
}

fn parse_credential_service(node: Node<'_, '_>) -> Result<ServiceIdentity, ExtDiscoError> {
    ensure_element(node, "service")?;
    if has_content(node)
        || node.attributes().any(|attribute| {
            attribute.namespace().is_some()
                || !matches!(attribute.name(), "host" | "type" | "port" | "transport")
        })
    {
        return Err(ExtDiscoError::InvalidServiceShape);
    }
    let host_value = node
        .attribute("host")
        .ok_or(ExtDiscoError::InvalidServiceShape)?;
    let type_value = node
        .attribute("type")
        .ok_or(ExtDiscoError::InvalidServiceShape)?;
    let port = node
        .attribute("port")
        .map(|value| {
            value
                .parse::<u16>()
                .ok()
                .and_then(NonZeroU16::new)
                .ok_or(ExtDiscoError::InvalidPort)
        })
        .transpose()?;
    let transport = node
        .attribute("transport")
        .map(ServiceToken::parse_transport)
        .transpose()?;
    Ok(ServiceIdentity {
        host: ServiceHost::parse(host_value)?,
        service_type: ServiceToken::parse_service_type(type_value)?,
        port,
        transport,
    })
}

fn ensure_element(node: Node<'_, '_>, name: &str) -> Result<(), ExtDiscoError> {
    if node.is_element()
        && node.tag_name().namespace() == Some(NAMESPACE)
        && node.tag_name().name() == name
    {
        Ok(())
    } else {
        Err(ExtDiscoError::UnexpectedElement(
            node.tag_name().name().to_owned(),
        ))
    }
}

fn has_content(node: Node<'_, '_>) -> bool {
    node.children()
        .any(|child| child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty()))
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter_map(|child| child.text())
        .any(|text| !text.trim().is_empty())
}
