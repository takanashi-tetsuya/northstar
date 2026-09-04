use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct TopicCatalog {
    version: String,
    topics: Vec<TopicPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TopicPolicy {
    topic: String,
    event_type: String,
    key_strategy: String,
    partitions: u32,
    replication_factor: u16,
    min_insync_replicas: u16,
    max_message_bytes: u32,
    retention_ms: u64,
    region_mode: String,
    producers: Vec<String>,
    consumers: Vec<String>,
    #[serde(default)]
    payload_in_headers: bool,
}

#[derive(Debug, Error)]
enum Error {
    #[error(
        "usage: kafka-policy-generator --catalog <catalog/topics.yaml> --output <policy.json>"
    )]
    Usage,
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid topic catalog: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("topic policy validation failed: {0}")]
    Validation(String),
    #[error("cannot render policy JSON: {0}")]
    Json(#[from] serde_json::Error),
}

fn valid_name(name: &str, max: usize) -> bool {
    !name.is_empty()
        && name.len() <= max
        && name.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && byte.is_ascii_alphanumeric() || index > 0)
                && (byte == b'.' || byte == b'_' || byte == b'-' || byte.is_ascii_alphanumeric())
        })
}

fn validate(catalog: &TopicCatalog) -> Result<(), Error> {
    if catalog.version.trim().is_empty() || catalog.topics.is_empty() {
        return Err(Error::Validation(
            "version and at least one topic are required".into(),
        ));
    }
    let mut names = BTreeSet::new();
    let allowed_keys = [
        "recipient",
        "conversation",
        "room_id",
        "node_id",
        "full_jid",
    ];
    for policy in &catalog.topics {
        if !names.insert(policy.topic.clone()) {
            return Err(Error::Validation(format!(
                "duplicate topic {}",
                policy.topic
            )));
        }
        if !valid_name(&policy.topic, 249) || !valid_name(&policy.event_type, 128) {
            return Err(Error::Validation(format!(
                "invalid topic/event name {}",
                policy.topic
            )));
        }
        if !allowed_keys.contains(&policy.key_strategy.as_str()) {
            return Err(Error::Validation(format!(
                "{} uses an unsupported key strategy",
                policy.topic
            )));
        }
        if policy.partitions == 0 || policy.partitions > 1000 {
            return Err(Error::Validation(format!(
                "{} partition count must be 1..=1000",
                policy.topic
            )));
        }
        if policy.replication_factor < 3
            || policy.min_insync_replicas < 2
            || policy.min_insync_replicas > policy.replication_factor
        {
            return Err(Error::Validation(format!(
                "{} requires replication_factor >= 3 and 2 <= min_insync_replicas <= RF",
                policy.topic
            )));
        }
        if policy.max_message_bytes == 0 || policy.max_message_bytes > 16 * 1024 * 1024 {
            return Err(Error::Validation(format!(
                "{} max message size is outside 1..=16MiB",
                policy.topic
            )));
        }
        if policy.retention_ms == 0
            || policy.retention_ms > 365 * 24 * 60 * 60 * 1000
            || !["regional", "home_region", "global"].contains(&policy.region_mode.as_str())
        {
            return Err(Error::Validation(format!(
                "{} requires a bounded retention and region mode",
                policy.topic
            )));
        }
        if policy.producers.is_empty()
            || policy.consumers.is_empty()
            || policy
                .producers
                .iter()
                .chain(policy.consumers.iter())
                .any(|s| s == "*" || !valid_name(s, 128))
        {
            return Err(Error::Validation(format!(
                "{} requires explicit producer and consumer ACLs",
                policy.topic
            )));
        }
        if policy.payload_in_headers {
            return Err(Error::Validation(format!(
                "{} attempts to place payload in headers",
                policy.topic
            )));
        }
    }
    Ok(())
}

fn run() -> Result<(), Error> {
    let mut args = env::args().skip(1);
    let mut catalog_path = None;
    let mut output_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--catalog" => catalog_path = args.next().map(PathBuf::from),
            "--output" => output_path = args.next().map(PathBuf::from),
            _ => return Err(Error::Usage),
        }
    }
    let catalog_path = catalog_path.ok_or(Error::Usage)?;
    let output_path = output_path.ok_or(Error::Usage)?;
    let bytes = fs::read(&catalog_path).map_err(|source| Error::Read {
        path: catalog_path,
        source,
    })?;
    let catalog: TopicCatalog = serde_yaml::from_slice(&bytes)?;
    validate(&catalog)?;
    let rendered = serde_json::to_string_pretty(&catalog.topics)? + "\n";
    fs::write(&output_path, rendered).map_err(|source| Error::Write {
        path: output_path.clone(),
        source,
    })?;
    println!(
        "Kafka policy valid and rendered to {}",
        output_path.display()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("kafka-policy-generator: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> TopicPolicy {
        TopicPolicy {
            topic: "northstar.message.accepted.v1".into(),
            event_type: "message.accepted.v1".into(),
            key_strategy: "recipient".into(),
            partitions: 12,
            replication_factor: 3,
            min_insync_replicas: 2,
            max_message_bytes: 1024 * 1024,
            retention_ms: 86_400_000,
            region_mode: "home_region".into(),
            producers: vec!["message-ingress".into()],
            consumers: vec!["delivery-router".into()],
            payload_in_headers: false,
        }
    }

    #[test]
    fn policy_requires_explicit_safe_broker_settings() {
        let mut topic = policy();
        assert!(validate(&TopicCatalog {
            version: "2.0.0".into(),
            topics: vec![topic.clone()],
        })
        .is_ok());
        topic.replication_factor = 1;
        assert!(validate(&TopicCatalog {
            version: "2.0.0".into(),
            topics: vec![topic],
        })
        .is_err());
    }
}
