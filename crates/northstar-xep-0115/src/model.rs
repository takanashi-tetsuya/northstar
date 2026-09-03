//! Typed domain models for XEP-0115 Entity Capabilities.

use crate::constants::*;
use crate::error::CapsError;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A Service Discovery identity (XEP-0030 / XEP-0115).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Identity {
    category: String,
    kind: String,
    lang: Option<String>,
    name: Option<String>,
}

impl Identity {
    /// Creates and validates a new `Identity`.
    pub fn new(
        category: impl Into<String>,
        kind: impl Into<String>,
        lang: Option<impl Into<String>>,
        name: Option<impl Into<String>>,
    ) -> Result<Self, CapsError> {
        let category = category.into();
        let kind = kind.into();
        let lang = lang.map(Into::into);
        let name = name.map(Into::into);

        validate_identity_parts(&category, &kind, lang.as_deref(), name.as_deref())?;

        Ok(Self {
            category,
            kind,
            lang,
            name,
        })
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn lang(&self) -> Option<&str> {
        self.lang.as_deref()
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Formats the identity according to XEP-0115 Section 5.3:
    /// `category/type/lang/name`
    pub fn to_canonical_part(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.category,
            self.kind,
            self.lang.as_deref().unwrap_or_default(),
            self.name.as_deref().unwrap_or_default()
        )
    }
}

fn validate_identity_parts(
    category: &str,
    kind: &str,
    lang: Option<&str>,
    name: Option<&str>,
) -> Result<(), CapsError> {
    if category.is_empty()
        || category.len() > MAX_CATEGORY_LEN
        || category.chars().any(char::is_control)
        || category.contains('/')
    {
        return Err(CapsError::InvalidIdentity(format!(
            "invalid category: '{category}'"
        )));
    }
    if kind.is_empty()
        || kind.len() > MAX_TYPE_LEN
        || kind.chars().any(char::is_control)
        || kind.contains('/')
    {
        return Err(CapsError::InvalidIdentity(format!(
            "invalid type/kind: '{kind}'"
        )));
    }
    if let Some(l) = lang {
        if l.len() > MAX_LANG_LEN || l.chars().any(char::is_control) || l.contains('/') {
            return Err(CapsError::InvalidIdentity(format!(
                "invalid xml:lang: '{l}'"
            )));
        }
    }
    if let Some(n) = name {
        if n.len() > MAX_NAME_LEN || n.chars().any(char::is_control) {
            return Err(CapsError::InvalidIdentity(format!("invalid name: '{n}'")));
        }
    }
    Ok(())
}

/// A Service Discovery feature (XEP-0030 / XEP-0115).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Feature {
    var: String,
}

impl Feature {
    /// Creates and validates a new `Feature`.
    pub fn new(var: impl Into<String>) -> Result<Self, CapsError> {
        let var = var.into();
        if var.is_empty() || var.len() > MAX_FEATURE_LEN || var.chars().any(char::is_control) {
            return Err(CapsError::InvalidFeature(format!(
                "invalid feature var: '{var}'"
            )));
        }
        Ok(Self { var })
    }

    pub fn var(&self) -> &str {
        &self.var
    }
}

/// A field within an extended data form (XEP-0004 / XEP-0128).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FormField {
    var: String,
    values: Vec<String>,
}

impl FormField {
    /// Creates and validates a new `FormField`.
    pub fn new(var: impl Into<String>, values: Vec<String>) -> Result<Self, CapsError> {
        let var = var.into();
        if var.is_empty() || var.len() > MAX_FIELD_VAR_LEN || var.chars().any(char::is_control) {
            return Err(CapsError::InvalidForm(format!(
                "invalid field var: '{var}'"
            )));
        }
        if values.len() > MAX_FIELD_VALUES {
            return Err(CapsError::InvalidForm(format!(
                "too many field values: {} exceeds limit {}",
                values.len(),
                MAX_FIELD_VALUES
            )));
        }
        for val in &values {
            if val.len() > MAX_FIELD_VALUE_LEN || val.chars().any(char::is_control) {
                return Err(CapsError::InvalidForm(format!(
                    "invalid field value in var '{var}'"
                )));
            }
        }
        Ok(Self { var, values })
    }

    pub fn var(&self) -> &str {
        &self.var
    }

    pub fn values(&self) -> &[String] {
        &self.values
    }
}

/// An Extended Service Discovery Information Form (XEP-0128 / XEP-0004 result form).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExtendedForm {
    form_type: String,
    fields: Vec<FormField>,
}

impl ExtendedForm {
    /// Creates and validates a new `ExtendedForm`.
    pub fn new(form_type: impl Into<String>, fields: Vec<FormField>) -> Result<Self, CapsError> {
        let form_type = form_type.into();
        if form_type.is_empty()
            || form_type.len() > MAX_FORM_TYPE_LEN
            || form_type.chars().any(char::is_control)
        {
            return Err(CapsError::InvalidFormType(form_type));
        }
        if fields.len() > MAX_FORM_FIELDS {
            return Err(CapsError::InvalidForm(format!(
                "too many fields: {} exceeds limit {}",
                fields.len(),
                MAX_FORM_FIELDS
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for field in &fields {
            if field.var == "FORM_TYPE" {
                return Err(CapsError::InvalidForm(
                    "FORM_TYPE must not be in fields list; specify as form_type".to_owned(),
                ));
            }
            if !seen.insert(&field.var) {
                return Err(CapsError::DuplicateFormField(field.var.clone()));
            }
        }
        Ok(Self { form_type, fields })
    }

    pub fn form_type(&self) -> &str {
        &self.form_type
    }

    pub fn fields(&self) -> &[FormField] {
        &self.fields
    }
}

/// Complete Service Discovery Info payload required for XEP-0115 verification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DiscoInfo {
    pub node: Option<String>,
    pub identities: Vec<Identity>,
    pub features: Vec<Feature>,
    pub forms: Vec<ExtendedForm>,
}

impl DiscoInfo {
    pub fn new(
        node: Option<String>,
        identities: Vec<Identity>,
        features: Vec<Feature>,
        forms: Vec<ExtendedForm>,
    ) -> Result<Self, CapsError> {
        if identities.len() > MAX_IDENTITIES {
            return Err(CapsError::TooManyChildren {
                count: identities.len(),
                limit: MAX_IDENTITIES,
            });
        }
        if features.len() > MAX_FEATURES {
            return Err(CapsError::TooManyChildren {
                count: features.len(),
                limit: MAX_FEATURES,
            });
        }
        if forms.len() > MAX_FORMS {
            return Err(CapsError::TooManyChildren {
                count: forms.len(),
                limit: MAX_FORMS,
            });
        }
        if let Some(ref n) = node {
            if n.len() > MAX_NODE_LEN || n.chars().any(char::is_control) {
                return Err(CapsError::InvalidNode(n.clone()));
            }
        }
        Ok(Self {
            node,
            identities,
            features,
            forms,
        })
    }

    pub fn builder() -> DiscoInfoBuilder {
        DiscoInfoBuilder::default()
    }

    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f.var == feature)
    }

    pub fn has_identity(&self, category: &str, kind: &str) -> bool {
        self.identities
            .iter()
            .any(|id| id.category == category && id.kind == kind)
    }

    /// Returns all PEP notification node names requested via `<feature var='{node}+notify'/>`.
    pub fn pep_notify_nodes(&self) -> Vec<&str> {
        self.features
            .iter()
            .filter_map(|f| f.var.strip_suffix("+notify"))
            .filter(|node| !node.is_empty())
            .collect()
    }
}

/// Builder for constructing `DiscoInfo` instances with validation.
#[derive(Clone, Debug, Default)]
pub struct DiscoInfoBuilder {
    node: Option<String>,
    identities: Vec<Identity>,
    features: Vec<Feature>,
    forms: Vec<ExtendedForm>,
}

impl DiscoInfoBuilder {
    pub fn node(mut self, node: impl Into<String>) -> Self {
        self.node = Some(node.into());
        self
    }

    pub fn add_identity(
        mut self,
        category: impl Into<String>,
        kind: impl Into<String>,
        lang: Option<impl Into<String>>,
        name: Option<impl Into<String>>,
    ) -> Result<Self, CapsError> {
        let identity = Identity::new(category, kind, lang, name)?;
        self.identities.push(identity);
        Ok(self)
    }

    pub fn add_feature(mut self, var: impl Into<String>) -> Result<Self, CapsError> {
        let feature = Feature::new(var)?;
        self.features.push(feature);
        Ok(self)
    }

    pub fn add_form(mut self, form: ExtendedForm) -> Self {
        self.forms.push(form);
        self
    }

    pub fn build(self) -> Result<DiscoInfo, CapsError> {
        DiscoInfo::new(self.node, self.identities, self.features, self.forms)
    }
}

/// Presence entity capabilities advertisement `<c xmlns='http://jabber.org/protocol/caps' .../>`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapsAdvertisement {
    pub node: String,
    pub ver: String,
    pub hash: Option<String>,
    pub ext: Option<String>,
}

impl CapsAdvertisement {
    pub fn new(
        node: impl Into<String>,
        ver: impl Into<String>,
        hash: Option<impl Into<String>>,
        ext: Option<impl Into<String>>,
    ) -> Result<Self, CapsError> {
        let node = node.into();
        let ver = ver.into();
        let hash = hash.map(Into::into);
        let ext = ext.map(Into::into);

        if node.is_empty() || node.len() > MAX_NODE_LEN || node.chars().any(char::is_control) {
            return Err(CapsError::InvalidNode(node));
        }
        if ver.is_empty() || ver.len() > MAX_VER_LEN || ver.chars().any(char::is_control) {
            return Err(CapsError::InvalidVersion(ver));
        }
        if let Some(ref h) = hash {
            if h.is_empty() || h.len() > MAX_HASH_LEN || h.chars().any(char::is_control) {
                return Err(CapsError::InvalidHashAlgorithm(h.clone()));
            }
        }
        if let Some(ref e) = ext {
            if e.len() > MAX_EXT_LEN || e.chars().any(char::is_control) {
                return Err(CapsError::InvalidExtension(e.clone()));
            }
        }

        Ok(Self {
            node,
            ver,
            hash,
            ext,
        })
    }
}

/// Pure semantic cache key for entity capabilities.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapsKey {
    pub algorithm: String,
    pub node: String,
    pub version: String,
    pub scope: CapsScope,
}

/// Cache sharing boundary for one capabilities claim.
///
/// Only verified claims may use the global scope. Unsupported or otherwise
/// unverified claims remain isolated to the exact advertising full JID.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CapsScope {
    #[default]
    Global,
    FullJid(String),
}

impl CapsKey {
    pub fn new(
        algorithm: impl Into<String>,
        node: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, CapsError> {
        let algorithm = algorithm.into();
        let node = node.into();
        let version = version.into();

        if algorithm.is_empty()
            || algorithm.len() > MAX_HASH_LEN
            || algorithm.chars().any(char::is_control)
        {
            return Err(CapsError::InvalidHashAlgorithm(algorithm));
        }
        if node.is_empty() || node.len() > MAX_NODE_LEN || node.chars().any(char::is_control) {
            return Err(CapsError::InvalidNode(node));
        }
        if version.is_empty()
            || version.len() > MAX_VER_LEN
            || version.chars().any(char::is_control)
        {
            return Err(CapsError::InvalidVersion(version));
        }

        Ok(Self {
            algorithm,
            node,
            version,
            scope: CapsScope::Global,
        })
    }

    /// Creates a key with algorithm scoping for unsupported or JID-scoped algorithms.
    pub fn scoped(
        algorithm: &str,
        full_jid: &str,
        node: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, CapsError> {
        let mut key = Self::new(algorithm, node, version)?;
        if full_jid.is_empty() || full_jid.len() > 3_071 || full_jid.chars().any(char::is_control) {
            return Err(CapsError::InvalidScopeJid(full_jid.to_owned()));
        }
        key.scope = CapsScope::FullJid(full_jid.to_owned());
        Ok(key)
    }
}

/// Result of verifying an entity capabilities advertisement against disco#info.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapsValidationResult {
    /// Capabilities verification succeeded with canonical verification string and semantic key.
    Valid {
        key: CapsKey,
        canonical_string: String,
    },
    /// The computed hash did not match the advertised `ver`.
    Mismatch { expected: String, computed: String },
    /// The advertisement used an unsupported hash algorithm.
    UnsupportedAlgorithm { algorithm: String },
    /// The advertisement is legacy (no hash attribute).
    LegacyWithoutHash,
    /// The disco#info data was invalid or malformed.
    InvalidData(CapsError),
}

impl CapsValidationResult {
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    pub fn key(&self) -> Option<&CapsKey> {
        match self {
            Self::Valid { key, .. } => Some(key),
            _ => None,
        }
    }
}
