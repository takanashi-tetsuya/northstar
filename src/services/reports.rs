//! Report and appeal validation; repositories own authorization, proof and replay commits.
use crate::services::api_mutations::{
    ApiMutationOutcome, StoredApiResponse, UserMutationAdmission,
};
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Debug)]
pub struct ReportEvidenceInput {
    pub archive_id: Uuid,
    pub client_message_id: Option<String>,
    pub body_text: String,
}
pub(crate) struct ReportInput<'a> {
    pub(crate) reported_jid: &'a str,
    pub(crate) category: &'a str,
    pub(crate) description: Option<&'a str>,
    pub(crate) evidence: Vec<ReportEvidenceInput>,
}
pub(crate) struct ValidatedReport<'a> {
    pub(crate) reported_jid: String,
    pub(crate) category: &'a str,
    pub(crate) description: &'a str,
    pub(crate) evidence: Vec<ReportEvidenceInput>,
}
pub(crate) struct ReportCommand<'a> {
    pub(crate) admission: UserMutationAdmission<'a>,
    pub(crate) content: Result<ValidatedReport<'a>, &'static str>,
}
pub(crate) struct AppealCommand<'a> {
    pub(crate) admission: UserMutationAdmission<'a>,
    pub(crate) report_id: Uuid,
    pub(crate) reason: Result<&'a str, &'static str>,
}
pub(crate) enum ReportEffect {
    None,
    ReportCreated,
    AppealCreated,
    RateLimited,
}
pub(crate) struct ReportCommit {
    pub(crate) response: StoredApiResponse,
    pub(crate) effect: ReportEffect,
}
pub(crate) trait ReportRepository: Send + Sync {
    fn create_report(
        &self,
        command: ReportCommand<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<ReportCommit>>> + Send;
    fn create_appeal(
        &self,
        command: AppealCommand<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<ReportCommit>>> + Send;
}
#[derive(Clone)]
pub(crate) struct ReportService<R> {
    repository: R,
}
impl<R: ReportRepository> ReportService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn create_report<'a>(
        &self,
        admission: UserMutationAdmission<'a>,
        input: ReportInput<'a>,
    ) -> anyhow::Result<ApiMutationOutcome<ReportCommit>> {
        let content = match report_validation_error(&input) {
            Some(error) => Err(error),
            None => Ok(ValidatedReport {
                reported_jid: crate::jid::canonical_bare_key(input.reported_jid.trim())
                    .expect("validated report JID is canonicalizable"),
                category: input.category,
                description: input.description.unwrap_or_default().trim(),
                evidence: input.evidence,
            }),
        };
        self.repository
            .create_report(ReportCommand { admission, content })
            .await
    }
    pub(crate) async fn create_appeal<'a>(
        &self,
        admission: UserMutationAdmission<'a>,
        report_id: Uuid,
        reason: &'a str,
    ) -> anyhow::Result<ApiMutationOutcome<ReportCommit>> {
        let reason = reason.trim();
        let reason = match appeal_validation_error(reason) {
            Some(error) => Err(error),
            None => Ok(reason),
        };
        self.repository
            .create_appeal(AppealCommand {
                admission,
                report_id,
                reason,
            })
            .await
    }
}

const MAX_DESCRIPTION_CHARS: usize = 4_000;
const MAX_DESCRIPTION_BYTES: usize = MAX_DESCRIPTION_CHARS * 4;
const MAX_EVIDENCE_BODY_CHARS: usize = 8_000;
const MAX_EVIDENCE_BODY_BYTES: usize = MAX_EVIDENCE_BODY_CHARS * 4;
const MAX_CLIENT_MESSAGE_ID_CHARS: usize = 128;
const MAX_CLIENT_MESSAGE_ID_BYTES: usize = MAX_CLIENT_MESSAGE_ID_CHARS * 4;

fn is_bidi_override(character: char) -> bool {
    // Ordinary RTL letters, marks and modern isolate controls remain valid.
    // Only the two directional overrides are rejected because they can make
    // moderation text display in an order different from its stored order.
    matches!(character, '\u{202d}' | '\u{202e}')
}

fn valid_user_text(value: &str, min_chars: usize, max_chars: usize, max_bytes: usize) -> bool {
    let count = value.chars().count();
    (min_chars..=max_chars).contains(&count)
        && value.len() <= max_bytes
        && !value.chars().any(|character| {
            (character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
                || is_bidi_override(character)
        })
}

fn valid_client_message_id(value: &str) -> bool {
    let count = value.chars().count();
    (1..=MAX_CLIENT_MESSAGE_ID_CHARS).contains(&count)
        && value.len() <= MAX_CLIENT_MESSAGE_ID_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || is_bidi_override(character))
}

pub(crate) fn report_validation_error(body: &ReportInput<'_>) -> Option<&'static str> {
    if crate::jid::canonical_bare_key(body.reported_jid.trim())
        .ok()
        .filter(|jid| jid.contains('@'))
        .is_none()
    {
        return Some("reported JID is invalid");
    }
    if !matches!(
        body.category,
        "spam" | "harassment" | "threat" | "impersonation" | "illegal" | "other"
    ) {
        return Some("report category is invalid");
    }
    if body.evidence.is_empty() || body.evidence.len() > 20 {
        return Some("select between 1 and 20 messages as evidence");
    }
    let description = body.description.unwrap_or_default().trim();
    if !valid_user_text(description, 0, MAX_DESCRIPTION_CHARS, MAX_DESCRIPTION_BYTES) {
        return Some("report description is invalid");
    }
    let mut archive_ids = HashSet::with_capacity(body.evidence.len());
    for item in &body.evidence {
        if !archive_ids.insert(item.archive_id)
            || !valid_user_text(
                &item.body_text,
                1,
                MAX_EVIDENCE_BODY_CHARS,
                MAX_EVIDENCE_BODY_BYTES,
            )
            || item.body_text.trim().is_empty()
            || item
                .client_message_id
                .as_deref()
                .is_some_and(|id| !valid_client_message_id(id))
        {
            return Some("report evidence is invalid");
        }
    }
    None
}

pub(crate) fn appeal_validation_error(reason: &str) -> Option<&'static str> {
    if valid_user_text(reason, 20, MAX_DESCRIPTION_CHARS, MAX_DESCRIPTION_BYTES) {
        None
    } else {
        Some("appeal reason must be between 20 and 4000 safe Unicode characters")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_report() -> ReportInput<'static> {
        ReportInput {
            reported_jid: "peer@example.test",
            category: "spam",
            evidence: vec![ReportEvidenceInput {
                archive_id: Uuid::new_v4(),
                client_message_id: Some("message-1".into()),
                body_text: "A safe multilingual evidence body. 安全な本文。".into(),
            }],
            description: Some("A safe multilingual description. 描述。"),
        }
    }

    #[test]
    fn report_and_appeal_text_reject_every_postgres_nul_boundary() {
        let mut description = valid_report();
        description.description = Some("unsafe\0description");
        assert_eq!(
            report_validation_error(&description),
            Some("report description is invalid")
        );

        let mut evidence_body = valid_report();
        evidence_body.evidence[0].body_text = "unsafe\0body".into();
        assert_eq!(
            report_validation_error(&evidence_body),
            Some("report evidence is invalid")
        );

        let mut client_id = valid_report();
        client_id.evidence[0].client_message_id = Some("unsafe\0id".into());
        assert_eq!(
            report_validation_error(&client_id),
            Some("report evidence is invalid")
        );

        assert!(appeal_validation_error("A valid appeal reason for review.").is_none());
        assert!(appeal_validation_error("An unsafe appeal\0 reason for review.").is_some());
    }

    #[test]
    fn text_limits_count_unicode_scalars_and_reject_invisible_controls() {
        assert!(report_validation_error(&valid_report()).is_none());
        assert!(valid_user_text("多言語\ntext", 1, 16, 64));
        assert!(!valid_user_text("unsafe\u{0085}text", 1, 32, 128));
        assert!(!valid_user_text("unsafe\u{202e}text", 1, 32, 128));
        assert!(valid_client_message_id("メッセージ-1"));
        assert!(!valid_client_message_id("message\n1"));
        assert!(valid_user_text(&"界".repeat(4_000), 0, 4_000, 16_000));
        assert!(!valid_user_text(&"界".repeat(4_001), 0, 4_000, 16_000));
    }
}
