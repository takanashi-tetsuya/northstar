/// An isolated test database schema identifier with safe teardown helpers.
#[derive(Debug, Clone)]
pub struct IsolatedSchema {
    name: String,
}

impl IsolatedSchema {
    /// Generate a fresh unique schema name with a given test suite prefix.
    pub fn new(prefix: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let sanitized_prefix = prefix
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>();
        Self {
            name: format!("{sanitized_prefix}_{pid}_{nonce}"),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// SQL statement to create the isolated schema.
    pub fn create_sql(&self) -> String {
        format!("CREATE SCHEMA IF NOT EXISTS \"{}\";", self.name)
    }

    /// SQL statement to drop the isolated schema CASCADE.
    pub fn drop_cascade_sql(&self) -> String {
        format!("DROP SCHEMA IF EXISTS \"{}\" CASCADE;", self.name)
    }

    /// Set search_path connection parameter.
    pub fn search_path_option(&self) -> String {
        format!("-c search_path={}", self.name)
    }
}
