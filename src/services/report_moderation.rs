//! Validation and command ports for report and appeal moderation.
use crate::services::api_mutations::{
    AdminMutationAdmission, ApiMutationOutcome, ApiMutationRejection, StoredApiResponse,
};
use uuid::Uuid;

pub(crate) struct ModerationCommand<'a> {
    pub(crate) admission: AdminMutationAdmission<'a>,
    pub(crate) id: Uuid,
    pub(crate) status: &'a str,
    pub(crate) resolution: &'a str,
}

pub(crate) trait ReportModerationRepository: Send + Sync {
    fn update_report(
        &self,
        command: ModerationCommand<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;

    fn update_appeal(
        &self,
        command: ModerationCommand<'_>,
    ) -> impl std::future::Future<Output = anyhow::Result<ApiMutationOutcome<StoredApiResponse>>> + Send;
}

#[derive(Clone)]
pub(crate) struct ReportModerationService<R> {
    repository: R,
}

impl<R: ReportModerationRepository> ReportModerationService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn update_report<'a>(
        &self,
        admission: AdminMutationAdmission<'a>,
        id: Uuid,
        status: &'a str,
        resolution: Option<&'a str>,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        let resolution = resolution.unwrap_or_default().trim();
        if let Some(error) = report_validation_error(status, resolution) {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest(error),
            ));
        }
        self.repository
            .update_report(ModerationCommand {
                admission,
                id,
                status,
                resolution,
            })
            .await
    }

    pub(crate) async fn update_appeal<'a>(
        &self,
        admission: AdminMutationAdmission<'a>,
        id: Uuid,
        status: &'a str,
        resolution: Option<&'a str>,
    ) -> anyhow::Result<ApiMutationOutcome<StoredApiResponse>> {
        let resolution = resolution.unwrap_or_default().trim();
        if let Some(error) = appeal_validation_error(status, resolution) {
            return Ok(ApiMutationOutcome::Rejected(
                ApiMutationRejection::BadRequest(error),
            ));
        }
        self.repository
            .update_appeal(ModerationCommand {
                admission,
                id,
                status,
                resolution,
            })
            .await
    }
}

fn report_validation_error(status: &str, resolution: &str) -> Option<&'static str> {
    if !matches!(
        status,
        "submitted" | "reviewing" | "actioned" | "rejected" | "closed"
    ) {
        return Some("invalid report status");
    }
    if (!resolution.is_empty() && !valid_administrative_text(resolution, 8000, 32_000, true))
        || (matches!(status, "actioned" | "rejected" | "closed") && resolution.is_empty())
    {
        return Some("a resolution is required when resolving a report");
    }
    None
}

fn appeal_validation_error(status: &str, resolution: &str) -> Option<&'static str> {
    if !matches!(status, "submitted" | "reviewing" | "upheld" | "denied") {
        return Some("invalid appeal status");
    }
    if (!resolution.is_empty() && !valid_administrative_text(resolution, 8000, 32_000, true))
        || (matches!(status, "upheld" | "denied") && resolution.is_empty())
    {
        return Some("a resolution is required when resolving an appeal");
    }
    None
}

pub(crate) fn valid_administrative_text(
    value: &str,
    max_chars: usize,
    max_bytes: usize,
    multiline: bool,
) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.chars().count() <= max_chars
        && value.chars().all(|character| {
            let code = character as u32;
            let allowed_space = multiline && matches!(character, '\t' | '\n' | '\r');
            (allowed_space || !(code <= 0x1f || (0x7f..=0x9f).contains(&code)))
                && !(0x202a..=0x202e).contains(&code)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moderation_requires_safe_resolutions_for_terminal_states() {
        for status in ["actioned", "rejected", "closed"] {
            assert!(report_validation_error(status, "").is_some());
            assert!(report_validation_error(status, "Resolved after review.").is_none());
        }
        for status in ["upheld", "denied"] {
            assert!(appeal_validation_error(status, "").is_some());
            assert!(appeal_validation_error(status, "Resolved after review.").is_none());
        }
        for status in ["submitted", "reviewing"] {
            assert!(report_validation_error(status, "").is_none());
            assert!(appeal_validation_error(status, "").is_none());
        }
        assert_eq!(
            report_validation_error("upheld", "review"),
            Some("invalid report status")
        );
        assert_eq!(
            appeal_validation_error("closed", "review"),
            Some("invalid appeal status")
        );
        for resolution in ["hidden\0text", "hidden\u{0085}text", "spoof\u{202e}text"] {
            assert!(report_validation_error("reviewing", resolution).is_some());
            assert!(appeal_validation_error("reviewing", resolution).is_some());
        }
        assert!(report_validation_error("closed", &"界".repeat(8_000)).is_none());
        assert!(appeal_validation_error("denied", &"界".repeat(8_001)).is_some());
    }
}
