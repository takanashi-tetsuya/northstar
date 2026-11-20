use super::FederatedMessageRequest;
use northstar_room_core::ClusterMucSubjectArchive;
use northstar_xml_builder::message_policy::encrypted_archive_stanza;
use northstar_xmpp_types::jid::CanonicalJid;

pub(crate) fn archive_eligible(
    to: &CanonicalJid,
    permanent_storage: bool,
    encrypted: bool,
    requires_encryption: bool,
) -> bool {
    to.resourcepart().is_none() && permanent_storage && (encrypted || !requires_encryption)
}

pub(super) fn federated_archive_eligible(
    request: &FederatedMessageRequest,
    to: &CanonicalJid,
    requires_encryption: bool,
) -> bool {
    archive_eligible(
        to,
        request.permanent_storage,
        request.encrypted,
        requires_encryption,
    )
}

pub(crate) fn archive_payload(stanza: &str, eligible: bool, encrypted: bool) -> String {
    if eligible && encrypted {
        encrypted_archive_stanza(stanza)
    } else {
        stanza.to_owned()
    }
}

pub(crate) fn cluster_subject_archive<'a>(
    live: &'a str,
    candidate: &'a str,
    eligible: bool,
    logging_enabled: bool,
) -> (&'a str, ClusterMucSubjectArchive<'a>) {
    // The operation key, digest and notification retain the legacy payload.
    // The repository decides the MAM projection from the candidate and its room lock.
    let digest_archive = eligible && logging_enabled;
    (
        if digest_archive { candidate } else { live },
        ClusterMucSubjectArchive {
            eligible_stanza: eligible.then_some(candidate),
            digest_archive,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_xml_builder::{message_policy::has_no_store_hint, stanza::is_encrypted};
    use roxmltree::Document;

    #[test]
    fn local_and_federated_stanza_eligibility_uses_routing_hints_and_encryption() {
        let room = "room@conference.local.test";
        for (to, children, requires_encryption, expected) in [
            ("room@conference.local.test/Bob", "<body>private</body>", false, false),
            (room, "", false, true),
            (room, "<composing xmlns='http://jabber.org/protocol/chatstates'/>", false, false),
            (room, "<composing xmlns='http://jabber.org/protocol/chatstates'/><store xmlns='urn:xmpp:hints'/>", false, true),
            (room, "<body>hello</body><no-store xmlns='urn:xmpp:hints'/>", false, false),
            (room, "<body>hello</body><no-permanent-store xmlns='urn:xmpp:hints'/>", false, false),
            (room, "<body>hello</body>", true, false),
            (room, "<encrypted xmlns='urn:xmpp:omemo:2'/>", true, true),
            (room, "<encrypted xmlns='urn:xmpp:omemo:2'/><no-store xmlns='urn:xmpp:hints'/>", true, false),
        ] {
            let xml = format!("<message xmlns='jabber:client' from='alice@remote.test/phone' to='{to}' type='groupchat'>{children}</message>");
            let document = Document::parse(&xml).unwrap();
            let root = document.root_element();
            let to = CanonicalJid::parse(to).unwrap();
            let request = FederatedMessageRequest::from_node(root, &xml, Ok(()));
            assert_eq!(
                archive_eligible(&to, !has_no_store_hint(root), is_encrypted(root), requires_encryption),
                expected,
                "local {xml}",
            );
            assert_eq!(
                federated_archive_eligible(&request, &to, requires_encryption),
                expected,
                "federated {xml}",
            );
        }
    }

    #[test]
    fn clustered_subject_keeps_digest_inputs_while_carrying_the_encrypted_candidate() {
        let live = "<message><encrypted xmlns='urn:xmpp:omemo:2'/><body>fallback</body></message>";
        let candidate = archive_payload(live, true, true);
        assert!(!candidate.contains("fallback"));
        for logging in [false, true] {
            let (legacy, archive) = cluster_subject_archive(live, &candidate, true, logging);
            assert_eq!(legacy, if logging { candidate.as_str() } else { live });
            assert_eq!(archive.digest_archive, logging);
            assert_eq!(archive.eligible_stanza, Some(candidate.as_str()));
        }
    }
}
