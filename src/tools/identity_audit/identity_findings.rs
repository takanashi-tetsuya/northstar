//! Per-identity findings: malformed, non-canonical and colliding stored identities.

use super::*;

pub(super) fn malformed_finding(
    reporter: &Reporter,
    spec: &ScanSpec,
    locator: &str,
    scope: &str,
    original: &str,
    error: &anyhow::Error,
) -> Finding {
    Finding {
        code: "malformed_identity",
        table: spec.table.to_owned(),
        field: spec.field.to_owned(),
        locator: format!("{}@{}", spec.table, locator),
        canonicalizer: spec.kind.name(),
        scope: (!scope.is_empty()).then(|| reporter.value(scope)),
        original: Some(reporter.value(original)),
        canonical: None,
        related_locations: Vec::new(),
        reference_edge_ids: spec
            .reference_edges
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        explanation: format!(
            "the value cannot be prepared by {}: {}",
            spec.kind.name(),
            safe_error(error)
        ),
        recommendation: spec.remediation.to_owned(),
    }
}

pub(super) fn noncanonical_finding(
    reporter: &Reporter,
    spec: &ScanSpec,
    locator: &str,
    scope: &str,
    original: &str,
    canonical: &str,
) -> Finding {
    Finding {
        code: "noncanonical_identity",
        table: spec.table.to_owned(),
        field: spec.field.to_owned(),
        locator: format!("{}@{}", spec.table, locator),
        canonicalizer: spec.kind.name(),
        scope: (!scope.is_empty()).then(|| reporter.value(scope)),
        original: Some(reporter.value(original)),
        canonical: Some(reporter.value(canonical)),
        related_locations: Vec::new(),
        reference_edge_ids: spec
            .reference_edges
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        explanation: "stored identity differs from its exact RFC 7622/PRECIS/IDNA canonical form"
            .to_owned(),
        recommendation: spec.remediation.to_owned(),
    }
}

pub(super) fn collision_findings(
    reporter: &Reporter,
    identities: Vec<ScannedIdentity>,
) -> Vec<Finding> {
    let mut groups: BTreeMap<(&str, &str, &str), Vec<&ScannedIdentity>> = BTreeMap::new();
    for identity in &identities {
        groups
            .entry((identity.namespace, &identity.scope, &identity.canonical))
            .or_default()
            .push(identity);
    }
    groups
        .into_values()
        .filter(|group| group.len() > 1)
        .map(|group| {
            let first = group[0];
            let idna = group.iter().any(|row| uses_alabel(&row.original))
                && group.iter().any(|row| !uses_alabel(&row.original));
            let edges = group
                .iter()
                .flat_map(|row| row.reference_edges.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .map(str::to_owned)
                .collect();
            Finding {
                code: if idna {
                    "idna_alabel_ulabel_collision"
                } else {
                    "precis_canonical_collision"
                },
                table: first.table.to_owned(),
                field: first.field.to_owned(),
                locator: format!("{}@{}", first.table, first.locator),
                canonicalizer: "canonical-key-collision",
                scope: (!first.scope.is_empty()).then(|| reporter.value(&first.scope)),
                original: Some(reporter.value(&first.original)),
                canonical: Some(reporter.value(&first.canonical)),
                related_locations: group
                    .iter()
                    .skip(1)
                    .map(|row| format!("{}@{}", row.table, row.locator))
                    .collect(),
                reference_edge_ids: edges,
                explanation: if idna {
                    "distinct A-label/U-label spellings resolve to one canonical identity in the same authorization scope".to_owned()
                } else {
                    "multiple stored identities resolve to one canonical key in the same authorization scope".to_owned()
                },
                recommendation: "Determine the intended principal using external account records, then repair or remove all dependent rows together. Do not automatically merge these principals.".to_owned(),
            }
        })
        .collect()
}

pub(super) fn uses_alabel(value: &str) -> bool {
    let address = value.split('/').next().unwrap_or(value);
    let domain = address
        .rsplit_once('@')
        .map_or(address, |(_, domain)| domain);
    domain
        .split('.')
        .any(|label| label.to_ascii_lowercase().starts_with("xn--"))
}

pub(super) fn safe_error(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .take(240)
        .collect()
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
