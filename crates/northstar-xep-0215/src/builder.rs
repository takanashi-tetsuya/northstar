//! Safe XML builders with a type-level public/credential response boundary.

use crate::constants::{DATA_FORMS_NAMESPACE, MAX_RESULT_SERVICES, NAMESPACE};
use crate::error::ExtDiscoError;
use crate::model::{CredentialedService, PublicService, ServiceAction, ServiceToken};

pub fn build_services_result(
    requested_type: Option<&ServiceToken>,
    services: &[PublicService],
) -> Result<String, ExtDiscoError> {
    build_public_services("services", requested_type, services)
}

pub fn build_services_push(
    requested_type: Option<&ServiceToken>,
    services: &[PublicService],
) -> Result<String, ExtDiscoError> {
    build_public_services("services", requested_type, services)
}

pub fn build_credentials_result(services: &[CredentialedService]) -> Result<String, ExtDiscoError> {
    check_result_count(services.len())?;
    let mut xml = String::from("<credentials xmlns='urn:xmpp:extdisco:2'>");
    for service in services {
        service.service.validate()?;
        push_service_start(&mut xml, &service.service);
        push_attr(&mut xml, "username", &service.credentials.username);
        push_attr(&mut xml, "password", service.credentials.password.expose());
        push_attr(&mut xml, "expires", &service.credentials.expires);
        push_service_content_and_end(&mut xml, &service.service);
    }
    xml.push_str("</credentials>");
    Ok(xml)
}

fn build_public_services(
    element: &str,
    requested_type: Option<&ServiceToken>,
    services: &[PublicService],
) -> Result<String, ExtDiscoError> {
    check_result_count(services.len())?;
    let mut xml = String::new();
    xml.push('<');
    xml.push_str(element);
    xml.push_str(" xmlns='");
    xml.push_str(NAMESPACE);
    xml.push('\'');
    if let Some(service_type) = requested_type {
        push_attr(&mut xml, "type", service_type.as_str());
    }
    xml.push('>');
    for service in services {
        service.validate()?;
        push_service_start(&mut xml, service);
        push_service_content_and_end(&mut xml, service);
    }
    xml.push_str("</");
    xml.push_str(element);
    xml.push('>');
    Ok(xml)
}

fn push_service_start(xml: &mut String, service: &PublicService) {
    xml.push_str("<service");
    push_attr(xml, "host", &service.identity.host.to_string());
    push_attr(xml, "type", service.identity.service_type.as_str());
    if let Some(port) = service.identity.port {
        push_attr(xml, "port", &port.to_string());
    }
    if let Some(transport) = &service.identity.transport {
        push_attr(xml, "transport", transport.as_str());
    }
    if let Some(name) = &service.name {
        push_attr(xml, "name", name);
    }
    if service.restricted {
        push_attr(xml, "restricted", "true");
    }
    if let Some(action) = service.action {
        let action = match action {
            ServiceAction::Add => "add",
            ServiceAction::Delete => "delete",
            ServiceAction::Modify => "modify",
        };
        push_attr(xml, "action", action);
    }
}

fn push_service_content_and_end(xml: &mut String, service: &PublicService) {
    if service.extended.is_empty() {
        xml.push_str("/>");
        return;
    }
    xml.push('>');
    xml.push_str("<x xmlns='");
    xml.push_str(DATA_FORMS_NAMESPACE);
    xml.push_str("' type='result'>");
    for field in &service.extended {
        xml.push_str("<field");
        push_attr(xml, "var", &field.var);
        if let Some(label) = &field.label {
            push_attr(xml, "label", label);
        }
        xml.push('>');
        for value in &field.values {
            xml.push_str("<value>");
            escape_text(xml, value);
            xml.push_str("</value>");
        }
        xml.push_str("</field>");
    }
    xml.push_str("</x></service>");
}

fn push_attr(xml: &mut String, name: &str, value: &str) {
    xml.push(' ');
    xml.push_str(name);
    xml.push_str("='");
    escape_attr(xml, value);
    xml.push('\'');
}

fn escape_attr(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            other => output.push(other),
        }
    }
}

fn escape_text(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            other => output.push(other),
        }
    }
}

fn check_result_count(count: usize) -> Result<(), ExtDiscoError> {
    if count > MAX_RESULT_SERVICES {
        Err(ExtDiscoError::ResultServiceLimit {
            limit: MAX_RESULT_SERVICES,
        })
    } else {
        Ok(())
    }
}
