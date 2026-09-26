//! Explicit trust anchor for the isolated `lab.test` federation fixture.

use crate::{config::read_secret_file, s2s::dane::DaneMode};
use anyhow::{Context, Result};
use hickory_resolver::proto::dnssec::TrustAnchors;
use std::path::Path;

const VARIABLE: &str = "FEDERATION_DNSSEC_LAB_TRUST_ANCHOR_PATH";
const LAB_ZONE: &str = "lab.test.";
const MAX_ANCHOR_BYTES: usize = 8 * 1024;
const MAX_LAB_PEERS: usize = 32;

/// A custom anchor is only usable by an explicitly isolated required-DANE
/// server. An unrestricted allowlist would let the extra key authenticate a
/// DNS answer for a public target because Hickory stores key bytes, not owner.
pub(crate) fn validate_settings(
    path: Option<&Path>,
    mode: DaneMode,
    local_domain: &str,
    federation_enabled: bool,
    allow_private_ips: bool,
    allowlist: &[String],
    dns_overrides: usize,
) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    require_unix()?;

    anyhow::ensure!(
        path.is_absolute(),
        "{VARIABLE} must be an absolute protected path"
    );
    anyhow::ensure!(
        mode == DaneMode::Required && federation_enabled && allow_private_ips,
        "{VARIABLE} requires enabled federation, required DANE and private lab addresses"
    );
    anyhow::ensure!(
        local_domain
            .strip_suffix(".lab.test")
            .is_some_and(|name| !name.is_empty()),
        "{VARIABLE} requires a local XMPP domain beneath lab.test"
    );
    anyhow::ensure!(
        !allowlist.is_empty()
            && allowlist.len() <= MAX_LAB_PEERS
            && allowlist.iter().all(|domain| {
                !domain.contains('*')
                    && domain != local_domain
                    && domain
                        .strip_suffix(".lab.test")
                        .is_some_and(|name| !name.is_empty())
            }),
        "{VARIABLE} requires 1..={MAX_LAB_PEERS} exact peer names beneath lab.test"
    );
    anyhow::ensure!(
        dns_overrides == 0,
        "{VARIABLE} cannot be combined with federation DNS overrides"
    );
    Ok(())
}

fn require_unix() -> Result<()> {
    #[cfg(unix)]
    return Ok(());
    #[cfg(not(unix))]
    anyhow::bail!("{VARIABLE} is supported only on Unix isolated lab hosts");
}

/// The file format deliberately excludes DNSKEY owners other than lab.test.
/// Hickory's TrustAnchors parser discards owner names after parsing; validating
/// the owner here is essential before passing the key to its resolver builder.
fn parse_anchor(input: &str) -> Result<TrustAnchors> {
    anyhow::ensure!(
        !input.is_empty() && input.len() <= MAX_ANCHOR_BYTES,
        "{VARIABLE} must contain one bounded DNSKEY record"
    );
    let mut lines = input.lines();
    let record = lines.next().context("lab DNSKEY record is missing")?;
    anyhow::ensure!(
        lines.next().is_none(),
        "{VARIABLE} must contain exactly one DNSKEY record"
    );
    let fields = record.split_whitespace().collect::<Vec<_>>();
    anyhow::ensure!(
        fields.len() == 8
            && fields[0].eq_ignore_ascii_case(LAB_ZONE)
            && fields[1]
                .parse::<u32>()
                .is_ok_and(|ttl| (1..=3600).contains(&ttl))
            && fields[2].eq_ignore_ascii_case("IN")
            && fields[3].eq_ignore_ascii_case("DNSKEY")
            && fields[4] == "257"
            && fields[5] == "3"
            && fields[6] == "13",
        "{VARIABLE} must contain one lab.test. KSK DNSKEY with algorithm 13"
    );
    let anchors: TrustAnchors = record.parse().context("lab DNSKEY record is invalid")?;
    anyhow::ensure!(
        anchors.len() == 1,
        "lab DNSKEY record did not yield one trust anchor"
    );
    Ok(anchors)
}

pub(crate) fn load_anchor(path: &Path) -> Result<TrustAnchors> {
    let content = read_secret_file(path, VARIABLE)?;
    parse_anchor(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DNSKEY: &str = "lab.test. 300 IN DNSKEY 257 3 13 bKhLob4jADrX1HlEAt3htWeadUWng/CYNc9rzLSz9RhUXf1iazgV5r2xnGkwpcbN0ihDyHyqTlpmRNbruj151w==";

    fn checked(
        path: Option<&Path>,
        mode: DaneMode,
        local: &str,
        private: bool,
        peers: &[&str],
        overrides: usize,
    ) -> Result<()> {
        validate_settings(
            path,
            mode,
            local,
            true,
            private,
            &peers
                .iter()
                .map(|peer| (*peer).to_owned())
                .collect::<Vec<_>>(),
            overrides,
        )
    }

    #[test]
    fn lab_anchor_requires_explicit_isolated_required_dane_settings() {
        let path = Path::new("/tmp/northstar-lab-dnskey");
        assert!(checked(None, DaneMode::Off, "example.org", false, &[], 0).is_ok());
        #[cfg(unix)]
        assert!(checked(
            Some(path),
            DaneMode::Required,
            "ns-a.lab.test",
            true,
            &["prosody.lab.test", "ejabberd.lab.test"],
            0,
        )
        .is_ok());
        for (mode, local, private, peers, overrides) in [
            (
                DaneMode::Off,
                "ns-a.lab.test",
                true,
                vec!["prosody.lab.test"],
                0,
            ),
            (
                DaneMode::Opportunistic,
                "ns-a.lab.test",
                true,
                vec!["prosody.lab.test"],
                0,
            ),
            (
                DaneMode::Required,
                "example.org",
                true,
                vec!["prosody.lab.test"],
                0,
            ),
            (
                DaneMode::Required,
                "ns-a.lab.test",
                false,
                vec!["prosody.lab.test"],
                0,
            ),
            (DaneMode::Required, "ns-a.lab.test", true, vec![], 0),
            (
                DaneMode::Required,
                "ns-a.lab.test",
                true,
                vec!["*.lab.test"],
                0,
            ),
            (
                DaneMode::Required,
                "ns-a.lab.test",
                true,
                vec!["example.org"],
                0,
            ),
            (
                DaneMode::Required,
                "ns-a.lab.test",
                true,
                vec!["prosody.lab.test"],
                1,
            ),
        ] {
            assert!(checked(Some(path), mode, local, private, &peers, overrides).is_err());
        }
        assert!(checked(
            Some(Path::new("relative-anchor")),
            DaneMode::Required,
            "ns-a.lab.test",
            true,
            &["prosody.lab.test"],
            0,
        )
        .is_err());
        assert!(validate_settings(
            Some(path),
            DaneMode::Required,
            "ns-a.lab.test",
            false,
            true,
            &["prosody.lab.test".to_owned()],
            0,
        )
        .is_err());
    }

    #[test]
    fn lab_anchor_rejects_foreign_owner_and_non_dnskey_material() {
        assert_eq!(parse_anchor(TEST_DNSKEY).unwrap().len(), 1);
        for invalid in [
            TEST_DNSKEY.replacen("lab.test.", "evil.test.", 1),
            TEST_DNSKEY.replacen("DNSKEY", "DS", 1),
            TEST_DNSKEY.replacen("257 3 13", "257 3 7", 1),
            format!("{TEST_DNSKEY}\n{TEST_DNSKEY}"),
            String::new(),
        ] {
            assert!(parse_anchor(&invalid).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn lab_anchor_file_must_be_protected_and_not_a_symlink() {
        use std::{
            fs,
            os::unix::fs::{symlink, PermissionsExt},
        };
        let root =
            std::env::temp_dir().join(format!("northstar-lab-anchor-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let anchor = root.join("anchor");
        fs::write(&anchor, TEST_DNSKEY).unwrap();
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_anchor(&anchor).unwrap().len(), 1);
        let link = root.join("link");
        symlink(&anchor, &link).unwrap();
        assert!(load_anchor(&link).is_err());
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_anchor(&anchor).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
