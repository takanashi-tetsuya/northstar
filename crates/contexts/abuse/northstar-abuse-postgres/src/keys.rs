use crate::effects::AbuseEffects;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use northstar_abuse_application::guard::records::AbuseKeyDeploymentIdentity;
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;

// Serializes the rare bootstrap/rotation state transition without holding a
// row lock across an absent-row race.  The table remains partitioned by domain;
// this process-wide lock is held for one short startup transaction only.
const ABUSE_KEY_DEPLOYMENT_ADVISORY_LOCK: i64 = 4_741_070_036_074_865_761;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeploymentPhase {
    Stable,
    Overlap,
    Retiring,
}

impl DeploymentPhase {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "stable" => Ok(Self::Stable),
            "overlap" => Ok(Self::Overlap),
            "retiring" => Ok(Self::Retiring),
            _ => anyhow::bail!("database contains an invalid anti-abuse key deployment phase"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Overlap => "overlap",
            Self::Retiring => "retiring",
        }
    }
}

#[derive(Clone, Debug)]
struct DeploymentRecord {
    epoch: i64,
    phase: DeploymentPhase,
    current_key_id: String,
    previous_key_id: Option<String>,
    retire_not_before: Option<DateTime<Utc>>,
}

type DeploymentRecordRow = (i64, String, String, Option<String>, Option<DateTime<Utc>>);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ActivePreviousKeyReferences {
    challenges: i64,
    message_admissions: i64,
    offline_admissions: i64,
    personal_message_identities: i64,
    retraction_identities: i64,
    mix_business_identities: i64,
}

impl ActivePreviousKeyReferences {
    fn is_empty(self) -> bool {
        self.challenges == 0
            && self.message_admissions == 0
            && self.offline_admissions == 0
            && self.personal_message_identities == 0
            && self.retraction_identities == 0
            && self.mix_business_identities == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reconciliation {
    Compatible,
    BeginOverlap,
    BeginRetirement,
    FinishOverlap,
}

pub async fn reconcile_abuse_key_deployment(
    pool: &PgPool,
    identity: &AbuseKeyDeploymentIdentity,
    effects: &impl AbuseEffects,
) -> Result<()> {
    validate_identity(identity)?;
    let mut tx = pool
        .begin()
        .await
        .context("could not begin anti-abuse key deployment transaction")?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ABUSE_KEY_DEPLOYMENT_ADVISORY_LOCK)
        .execute(&mut *tx)
        .await
        .context("could not lock anti-abuse key deployment authority")?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .context("could not read the database clock for anti-abuse key deployment")?;

    let Some(record) = load_record(&mut tx, &identity.xmpp_domain, true).await? else {
        insert_initial_record(&mut tx, identity, now).await?;
        tx.commit().await?;
        tracing::info!(
            domain = %identity.xmpp_domain,
            epoch = identity.epoch,
            key_id = %identity.current_key_id,
            rotating = identity.previous_key_id.is_some(),
            "established PostgreSQL anti-abuse key deployment authority"
        );
        return Ok(());
    };

    match decide_reconciliation(&record, identity, now)? {
        Reconciliation::Compatible => {}
        Reconciliation::BeginOverlap => {
            sqlx::query(
                "UPDATE abuse_key_deployments
                 SET epoch=$2,phase='overlap',current_key_id=$3,
                     previous_key_id=$4,transition_started_at=$5,
                     retirement_started_at=NULL,retire_not_before=NULL,
                     updated_at=$5
                 WHERE xmpp_domain=$1",
            )
            .bind(&identity.xmpp_domain)
            .bind(identity.epoch)
            .bind(&identity.current_key_id)
            .bind(&identity.previous_key_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("could not begin anti-abuse key overlap")?;
            tracing::info!(
                domain = %identity.xmpp_domain,
                epoch = identity.epoch,
                key_id = %identity.current_key_id,
                "began PostgreSQL-authorized anti-abuse key overlap"
            );
        }
        Reconciliation::BeginRetirement => {
            let overlap_seconds = overlap_seconds(identity.minimum_overlap)?;
            sqlx::query(
                "UPDATE abuse_key_deployments
                 SET phase='retiring',retirement_started_at=$2,
                     retire_not_before=$2 + ($3::bigint * INTERVAL '1 second'),
                     updated_at=$2
                 WHERE xmpp_domain=$1",
            )
            .bind(&identity.xmpp_domain)
            .bind(now)
            .bind(overlap_seconds)
            .execute(&mut *tx)
            .await
            .context("could not seal the anti-abuse key overlap")?;
            tracing::info!(
                domain = %identity.xmpp_domain,
                epoch = identity.epoch,
                key_id = %identity.current_key_id,
                overlap_seconds,
                "fenced previous-generation nodes and began anti-abuse key retirement"
            );
        }
        Reconciliation::FinishOverlap => {
            let previous_key_id = record
                .previous_key_id
                .as_deref()
                .context("retiring anti-abuse deployment has no previous key ID")?;
            let references =
                active_previous_key_references(&mut tx, effects, previous_key_id, now).await?;
            anyhow::ensure!(
                references.is_empty(),
                "anti-abuse previous key still has active durable references (challenges {}, message admissions {}, offline admissions {}, personal message identities {}, retraction identities {}, MIX business identities {})",
                references.challenges,
                references.message_admissions,
                references.offline_admissions,
                references.personal_message_identities,
                references.retraction_identities,
                references.mix_business_identities,
            );
            sqlx::query(
                "UPDATE abuse_key_deployments
                 SET phase='stable',previous_key_id=NULL,
                     transition_started_at=NULL,retirement_started_at=NULL,
                     retire_not_before=NULL,
                     updated_at=$2
                 WHERE xmpp_domain=$1",
            )
            .bind(&identity.xmpp_domain)
            .bind(now)
            .execute(&mut *tx)
            .await
            .context("could not finish anti-abuse key overlap")?;
            tracing::info!(
                domain = %identity.xmpp_domain,
                epoch = identity.epoch,
                key_id = %identity.current_key_id,
                "retired the previous anti-abuse key deployment generation"
            );
        }
    }
    tx.commit().await?;
    Ok(())
}

/// Final retirement is fail-closed on every durable row that still requires
/// the previous HMAC generation. This check runs inside the same deployment
/// advisory-lock transaction as the stable-phase update. The time deadline is
/// only a lower bound; live offline queue rows may intentionally have no
/// expiry and therefore keep the previous key mounted for longer.
async fn active_previous_key_references(
    tx: &mut Transaction<'_, Postgres>,
    effects: &impl AbuseEffects,
    previous_key_id: &str,
    now: DateTime<Utc>,
) -> Result<ActivePreviousKeyReferences> {
    let (challenges, message_admissions): (i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*)::bigint FROM abuse_pow_challenges
                   WHERE key_id=$1 AND expires_at > $2),
                 (SELECT COUNT(*)::bigint FROM abuse_message_admissions
                   WHERE key_id=$1 AND expires_at > $2)",
    )
    .bind(previous_key_id)
    .bind(now)
    .fetch_one(&mut **tx)
    .await
    .context("could not fence active references to the previous anti-abuse key")?;
    let foreign = effects
        .foreign_key_references(tx, previous_key_id, now)
        .await?;
    Ok(ActivePreviousKeyReferences {
        challenges,
        message_admissions,
        offline_admissions: foreign.offline_admissions,
        personal_message_identities: foreign.personal_message_identities,
        retraction_identities: foreign.retraction_identities,
        mix_business_identities: foreign.mix_business_identities,
    })
}

/// Read-only readiness check.  It intentionally accepts a previous-generation
/// node during an authorized overlap so old and new processes can coexist while
/// a rolling deployment is in progress.  Once the overlap is finalized, an old
/// node immediately becomes unready.
pub async fn validate_abuse_key_deployment(
    pool: &PgPool,
    identity: &AbuseKeyDeploymentIdentity,
) -> Result<()> {
    validate_identity(identity)?;
    let mut tx = pool.begin().await?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let record = load_record(&mut tx, &identity.xmpp_domain, false)
        .await?
        .context("anti-abuse key deployment authority is missing")?;
    match decide_reconciliation(&record, identity, now)? {
        Reconciliation::Compatible => Ok(()),
        Reconciliation::BeginOverlap => {
            anyhow::bail!("anti-abuse key rotation has not been committed at startup")
        }
        Reconciliation::BeginRetirement => {
            anyhow::bail!("anti-abuse key retirement has not been sealed at startup")
        }
        Reconciliation::FinishOverlap => {
            anyhow::bail!("anti-abuse key retirement has not been committed at startup")
        }
    }
}

async fn load_record(
    tx: &mut Transaction<'_, Postgres>,
    domain: &str,
    for_update: bool,
) -> Result<Option<DeploymentRecord>> {
    let suffix = if for_update { " FOR UPDATE" } else { "" };
    let query = format!(
        "SELECT epoch,phase,current_key_id,previous_key_id,retire_not_before
         FROM abuse_key_deployments WHERE xmpp_domain=$1{suffix}"
    );
    let row: Option<DeploymentRecordRow> = sqlx::query_as(&query)
        .bind(domain)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(
        |(epoch, phase, current_key_id, previous_key_id, retire_not_before)| {
            Ok(DeploymentRecord {
                epoch,
                phase: DeploymentPhase::parse(&phase)?,
                current_key_id,
                previous_key_id,
                retire_not_before,
            })
        },
    )
    .transpose()
}

async fn insert_initial_record(
    tx: &mut Transaction<'_, Postgres>,
    identity: &AbuseKeyDeploymentIdentity,
    now: DateTime<Utc>,
) -> Result<()> {
    let phase = if identity.retire_previous {
        DeploymentPhase::Retiring
    } else if identity.previous_key_id.is_some() {
        DeploymentPhase::Overlap
    } else {
        DeploymentPhase::Stable
    };
    let overlap_seconds = overlap_seconds(identity.minimum_overlap)?;
    let transition_started_at = (phase != DeploymentPhase::Stable).then_some(now);
    let retirement_started_at = (phase == DeploymentPhase::Retiring).then_some(now);
    let retire_not_before =
        retirement_started_at.map(|started| started + chrono::Duration::seconds(overlap_seconds));
    sqlx::query(
        "INSERT INTO abuse_key_deployments
         (xmpp_domain,epoch,phase,current_key_id,previous_key_id,
          transition_started_at,retirement_started_at,retire_not_before,updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(&identity.xmpp_domain)
    .bind(identity.epoch)
    .bind(phase.as_str())
    .bind(&identity.current_key_id)
    .bind(&identity.previous_key_id)
    .bind(transition_started_at)
    .bind(retirement_started_at)
    .bind(retire_not_before)
    .bind(now)
    .execute(&mut **tx)
    .await
    .context("could not initialize anti-abuse key deployment authority")?;
    Ok(())
}

fn decide_reconciliation(
    record: &DeploymentRecord,
    identity: &AbuseKeyDeploymentIdentity,
    now: DateTime<Utc>,
) -> Result<Reconciliation> {
    if record.epoch == identity.epoch && record.current_key_id == identity.current_key_id {
        return match record.phase {
            DeploymentPhase::Stable
                if identity.previous_key_id.is_none() && !identity.retire_previous =>
            {
                Ok(Reconciliation::Compatible)
            }
            DeploymentPhase::Overlap
                if record.previous_key_id == identity.previous_key_id
                    && identity.previous_key_id.is_some()
                    && !identity.retire_previous =>
            {
                Ok(Reconciliation::Compatible)
            }
            DeploymentPhase::Overlap
                if record.previous_key_id == identity.previous_key_id
                    && identity.previous_key_id.is_some()
                    && identity.retire_previous =>
            {
                Ok(Reconciliation::BeginRetirement)
            }
            DeploymentPhase::Retiring
                if record.previous_key_id == identity.previous_key_id
                    && identity.previous_key_id.is_some()
                    && identity.retire_previous =>
            {
                Ok(Reconciliation::Compatible)
            }
            DeploymentPhase::Retiring
                if identity.previous_key_id.is_none() && !identity.retire_previous =>
            {
                let retire_not_before = record.retire_not_before.context(
                    "retiring anti-abuse key deployment has no retirement deadline",
                )?;
                if now < retire_not_before {
                    let seconds = retire_not_before
                        .signed_duration_since(now)
                        .num_seconds()
                        .max(1);
                    anyhow::bail!(
                        "anti-abuse previous key cannot be retired for another {seconds} seconds"
                    );
                }
                Ok(Reconciliation::FinishOverlap)
            }
            DeploymentPhase::Stable => anyhow::bail!(
                "ABUSE_STATE_HMAC_PREVIOUS_KEY_FILE requires incrementing ABUSE_STATE_HMAC_KEY_EPOCH"
            ),
            DeploymentPhase::Overlap => anyhow::bail!(
                "configured anti-abuse overlap keys or retirement phase do not match PostgreSQL authority"
            ),
            DeploymentPhase::Retiring => anyhow::bail!(
                "configured anti-abuse retiring keys or retirement phase do not match PostgreSQL authority"
            ),
        };
    }

    // A previous-generation process remains valid only while the authority is
    // in overlap and only if it carries exactly that one old current key.  It
    // cannot extend the overlap or introduce a third key.
    if record.phase == DeploymentPhase::Overlap
        && record.epoch.checked_sub(1) == Some(identity.epoch)
        && record.previous_key_id.as_deref() == Some(identity.current_key_id.as_str())
        && identity.previous_key_id.is_none()
        && !identity.retire_previous
    {
        return Ok(Reconciliation::Compatible);
    }

    // The first new-generation node may atomically establish the overlap, but
    // only for the next epoch and only when its previous key is the exact
    // database-authorized current key.  Subsequent new and old nodes then both
    // pass the rules above, so the first node does not monopolize rollout.
    if record.phase == DeploymentPhase::Stable
        && record.epoch.checked_add(1) == Some(identity.epoch)
        && identity.previous_key_id.as_deref() == Some(record.current_key_id.as_str())
        && identity.current_key_id != record.current_key_id
        && !identity.retire_previous
    {
        return Ok(Reconciliation::BeginOverlap);
    }

    anyhow::bail!(
        "anti-abuse key deployment mismatch (database epoch {}, configured epoch {}, database current ID {}, configured current ID {})",
        record.epoch,
        identity.epoch,
        record.current_key_id,
        identity.current_key_id
    )
}

fn validate_identity(identity: &AbuseKeyDeploymentIdentity) -> Result<()> {
    anyhow::ensure!(identity.epoch >= 1, "anti-abuse key epoch must be positive");
    anyhow::ensure!(
        valid_key_id(&identity.current_key_id),
        "anti-abuse current key ID is malformed"
    );
    if let Some(previous) = &identity.previous_key_id {
        anyhow::ensure!(
            valid_key_id(previous),
            "anti-abuse previous key ID is malformed"
        );
        anyhow::ensure!(
            previous != &identity.current_key_id,
            "anti-abuse current and previous key IDs must differ"
        );
    }
    anyhow::ensure!(
        !identity.retire_previous || identity.previous_key_id.is_some(),
        "anti-abuse retirement phase requires the previous key"
    );
    anyhow::ensure!(
        !identity.minimum_overlap.is_zero(),
        "anti-abuse key overlap must be positive"
    );
    Ok(())
}

fn valid_key_id(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn overlap_seconds(duration: Duration) -> Result<i64> {
    i64::try_from(duration.as_secs()).context("anti-abuse key overlap exceeds PostgreSQL range")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(epoch: i64, current: &str, previous: Option<&str>) -> AbuseKeyDeploymentIdentity {
        AbuseKeyDeploymentIdentity {
            xmpp_domain: "example.test".to_owned(),
            epoch,
            current_key_id: current.to_owned(),
            previous_key_id: previous.map(str::to_owned),
            retire_previous: false,
            minimum_overlap: Duration::from_secs(3_600),
        }
    }

    fn stable(epoch: i64, current: &str) -> DeploymentRecord {
        DeploymentRecord {
            epoch,
            phase: DeploymentPhase::Stable,
            current_key_id: current.to_owned(),
            previous_key_id: None,
            retire_not_before: None,
        }
    }

    fn overlap(epoch: i64, current: &str, previous: &str) -> DeploymentRecord {
        DeploymentRecord {
            epoch,
            phase: DeploymentPhase::Overlap,
            current_key_id: current.to_owned(),
            previous_key_id: Some(previous.to_owned()),
            retire_not_before: None,
        }
    }

    fn retiring(
        epoch: i64,
        current: &str,
        previous: &str,
        retire_not_before: DateTime<Utc>,
    ) -> DeploymentRecord {
        DeploymentRecord {
            epoch,
            phase: DeploymentPhase::Retiring,
            current_key_id: current.to_owned(),
            previous_key_id: Some(previous.to_owned()),
            retire_not_before: Some(retire_not_before),
        }
    }

    const OLD: &str = "AAAAAAAAAAAAAAAA";
    const NEW: &str = "BBBBBBBBBBBBBBBB";
    const WRONG: &str = "CCCCCCCCCCCCCCCC";

    #[test]
    fn stable_generation_requires_an_exact_current_key_and_no_previous() {
        let now = Utc::now();
        assert_eq!(
            decide_reconciliation(&stable(7, NEW), &identity(7, NEW, None), now).unwrap(),
            Reconciliation::Compatible
        );
        assert!(decide_reconciliation(&stable(7, NEW), &identity(7, WRONG, None), now).is_err());
        assert!(decide_reconciliation(&stable(7, NEW), &identity(7, NEW, Some(OLD)), now).is_err());
    }

    #[test]
    fn next_epoch_with_exact_old_key_begins_a_rolling_overlap() {
        let now = Utc::now();
        assert_eq!(
            decide_reconciliation(&stable(7, OLD), &identity(8, NEW, Some(OLD)), now).unwrap(),
            Reconciliation::BeginOverlap
        );
        assert!(decide_reconciliation(&stable(7, OLD), &identity(9, NEW, Some(OLD)), now).is_err());
        assert!(
            decide_reconciliation(&stable(7, OLD), &identity(8, NEW, Some(WRONG)), now).is_err()
        );
    }

    #[test]
    fn old_and_new_nodes_coexist_only_during_the_authorized_overlap() {
        let now = Utc::now();
        let record = overlap(8, NEW, OLD);
        assert_eq!(
            decide_reconciliation(&record, &identity(8, NEW, Some(OLD)), now).unwrap(),
            Reconciliation::Compatible
        );
        assert_eq!(
            decide_reconciliation(&record, &identity(7, OLD, None), now).unwrap(),
            Reconciliation::Compatible
        );
        assert!(decide_reconciliation(&record, &identity(7, WRONG, None), now).is_err());
        assert!(decide_reconciliation(&record, &identity(7, OLD, Some(WRONG)), now).is_err());

        let mut sealing = identity(8, NEW, Some(OLD));
        sealing.retire_previous = true;
        assert_eq!(
            decide_reconciliation(&record, &sealing, now).unwrap(),
            Reconciliation::BeginRetirement
        );
        let sealed = retiring(8, NEW, OLD, now + chrono::Duration::hours(1));
        assert_eq!(
            decide_reconciliation(&sealed, &sealing, now).unwrap(),
            Reconciliation::Compatible
        );
        assert!(decide_reconciliation(&sealed, &identity(7, OLD, None), now).is_err());
    }

    #[test]
    fn previous_key_cannot_be_removed_before_the_database_deadline() {
        let now = Utc::now();
        let early = retiring(8, NEW, OLD, now + chrono::Duration::seconds(1));
        assert!(decide_reconciliation(&early, &identity(8, NEW, None), now).is_err());
        let mature = retiring(8, NEW, OLD, now - chrono::Duration::seconds(1));
        assert_eq!(
            decide_reconciliation(&mature, &identity(8, NEW, None), now).unwrap(),
            Reconciliation::FinishOverlap
        );
    }
}
