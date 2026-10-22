//! Exact XEP-0115 verification string canonicalization.
//!
//! Implements Section 5 of XEP-0115:
//! 1. Identifiers are sorted and delimited by `<`.
//! 2. Features are sorted and delimited by `<`.
//! 3. Extended Service Discovery forms (XEP-0128) are sorted by `FORM_TYPE`,
//!    with sorted fields and sorted values, delimited by `<`.
//! 4. Duplicates at any level are strictly rejected.

use crate::constants::MAX_DISCO_PAYLOAD_BYTES;
use crate::error::CapsError;
use crate::model::{DiscoInfo, ExtendedForm, FormField};
use std::collections::HashSet;

/// Generates the canonical verification string from a `DiscoInfo` payload.
///
/// Returns `Err(CapsError)` if there are duplicate identities, duplicate features,
/// duplicate extended forms, duplicate fields within a form, or if limits are exceeded.
pub fn generate_canonical_verification_string(disco: &DiscoInfo) -> Result<String, CapsError> {
    // 1. Process identities
    let mut identity_parts = Vec::with_capacity(disco.identities.len());
    let mut seen_identities = HashSet::with_capacity(disco.identities.len());

    for identity in &disco.identities {
        let part = identity.to_canonical_part();
        if !seen_identities.insert(part.clone()) {
            return Err(CapsError::DuplicateIdentity(part));
        }
        identity_parts.push(part);
    }
    identity_parts.sort_unstable();

    // 2. Process features
    let mut feature_parts = Vec::with_capacity(disco.features.len());
    let mut seen_features = HashSet::with_capacity(disco.features.len());

    for feature in &disco.features {
        let var = feature.var().to_owned();
        if !seen_features.insert(var.clone()) {
            return Err(CapsError::DuplicateFeature(var));
        }
        feature_parts.push(var);
    }
    feature_parts.sort_unstable();

    // 3. Process extended forms
    let mut form_parts = Vec::with_capacity(disco.forms.len());
    let mut seen_forms = HashSet::with_capacity(disco.forms.len());

    for form in &disco.forms {
        let form_type = form.form_type();
        if !seen_forms.insert(form_type.to_owned()) {
            return Err(CapsError::DuplicateForm(form_type.to_owned()));
        }
        let canonical_form = generate_canonical_form_string(form)?;
        form_parts.push((form_type.to_owned(), canonical_form));
    }
    // Sort forms by FORM_TYPE ascending
    form_parts.sort_unstable_by(|(type_a, _), (type_b, _)| type_a.cmp(type_b));

    // 4. Assemble canonical verification string
    let mut output = String::new();

    for identity in identity_parts {
        output.push_str(&identity);
        output.push('<');
    }

    for feature in feature_parts {
        output.push_str(&feature);
        output.push('<');
    }

    for (_, form_str) in form_parts {
        output.push_str(&form_str);
    }

    if output.len() > MAX_DISCO_PAYLOAD_BYTES {
        return Err(CapsError::OversizedPayload {
            size: output.len(),
            limit: MAX_DISCO_PAYLOAD_BYTES,
        });
    }

    Ok(output)
}

/// Generates the canonical string for a single extended data form according to XEP-0115 Section 5.
///
/// Output format: `FORM_TYPE<field1_var<val1<val2<field2_var<val1<...<`
pub fn generate_canonical_form_string(form: &ExtendedForm) -> Result<String, CapsError> {
    let mut output = format!("{}<", form.form_type());

    // Sort fields by var ascending
    let mut sorted_fields: Vec<&FormField> = form.fields().iter().collect();
    sorted_fields.sort_unstable_by(|a, b| a.var().cmp(b.var()));

    for field in sorted_fields {
        output.push_str(field.var());
        output.push('<');

        // Sort values ascending
        let mut sorted_values = field.values().to_vec();
        sorted_values.sort_unstable();

        for val in sorted_values {
            output.push_str(&val);
            output.push('<');
        }
    }

    Ok(output)
}
