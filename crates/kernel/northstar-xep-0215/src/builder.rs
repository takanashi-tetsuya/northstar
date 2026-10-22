//! Safe XML builders with a type-level public/credential response boundary.

use crate::constants::{DATA_FORMS_NAMESPACE, MAX_RESULT_SERVICES, NAMESPACE};
use crate::error::ExtDiscoError;
use crate::model::{CredentialedService, PublicService, ServiceAction, ServiceToken};
use northstar_xml_builder::XmlElement;

pub fn build_services_result(
    requested_type: Option<&ServiceToken>,
    services: &[PublicService],
) -> Result<String, ExtDiscoError> {
    check_result_count(services.len())?;
    let mut result = XmlElement::namespaced("services", NAMESPACE)
        .optional_attr("type", requested_type.map(ServiceToken::as_str));
    for service in services {
        service.validate()?;
        result.push_child(service_element(service));
    }
    Ok(result.finish())
}

pub fn build_services_push(
    requested_type: Option<&ServiceToken>,
    services: &[PublicService],
) -> Result<String, ExtDiscoError> {
    build_services_result(requested_type, services)
}

pub fn build_credentials_result(services: &[CredentialedService]) -> Result<String, ExtDiscoError> {
    check_result_count(services.len())?;
    let mut result = XmlElement::namespaced("credentials", NAMESPACE);
    for service in services {
        service.service.validate()?;
        result.push_child(
            service_element(&service.service)
                .attr("username", &service.credentials.username)
                .attr("password", service.credentials.password.expose())
                .attr("expires", &service.credentials.expires),
        );
    }
    Ok(result.finish())
}

fn service_element(service: &PublicService) -> XmlElement {
    let action = service.action.map(|action| match action {
        ServiceAction::Add => "add",
        ServiceAction::Delete => "delete",
        ServiceAction::Modify => "modify",
    });
    let mut element = XmlElement::new("service")
        .attr("host", &service.identity.host)
        .attr("type", service.identity.service_type.as_str())
        .optional_attr("port", service.identity.port)
        .optional_attr(
            "transport",
            service
                .identity
                .transport
                .as_ref()
                .map(ServiceToken::as_str),
        )
        .optional_attr("name", service.name.as_deref())
        .optional_attr("restricted", service.restricted.then_some("true"))
        .optional_attr("action", action);
    if !service.extended.is_empty() {
        let mut form = XmlElement::namespaced("x", DATA_FORMS_NAMESPACE).attr("type", "result");
        for field in &service.extended {
            let mut field_element = XmlElement::new("field")
                .attr("var", &field.var)
                .optional_attr("label", field.label.as_deref());
            for value in &field.values {
                field_element.push_child(XmlElement::new("value").text(value.as_str()));
            }
            form.push_child(field_element);
        }
        element.push_child(form);
    }
    element
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
