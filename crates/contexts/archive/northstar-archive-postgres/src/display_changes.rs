//! Personal archive display writes under the legal-hold barriers.

use anyhow::{ensure, Result};
use northstar_xmpp_types::jid::CanonicalJid;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub struct PersonalArchiveDisplayChange<'a> {
    pub owner_id: Uuid,
    pub archive_id: Uuid,
    pub expected_stanza: &'a str,
    pub display_stanza: &'a str,
    pub actor_bare_jid: &'a str,
    pub action_id: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersonalDisplayWriteOutcome {
    Replaced,
    OverlayInserted,
    MissingOrChanged,
}

pub struct PersonalDisplayWrites<'tx, 'connection> {
    tx: &'tx mut Transaction<'connection, Postgres>,
}

pub async fn begin_personal_display_writes<'tx, 'connection>(
    tx: &'tx mut Transaction<'connection, Postgres>,
) -> Result<PersonalDisplayWrites<'tx, 'connection>> {
    let read_committed: bool =
        sqlx::query_scalar("SELECT current_setting('transaction_isolation') = 'read committed'")
            .fetch_one(&mut **tx)
            .await?;
    ensure!(
        read_committed,
        "personal display writes require READ COMMITTED"
    );
    sqlx::query("LOCK TABLE message_archive IN ROW EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await?;
    Ok(PersonalDisplayWrites { tx })
}

impl<'connection> PersonalDisplayWrites<'_, 'connection> {
    pub fn transaction(&mut self) -> &mut Transaction<'connection, Postgres> {
        self.tx
    }

    pub async fn apply(
        &mut self,
        change: PersonalArchiveDisplayChange<'_>,
    ) -> Result<PersonalDisplayWriteOutcome> {
        use PersonalDisplayWriteOutcome::{MissingOrChanged, OverlayInserted, Replaced};

        let actor = CanonicalJid::parse_bare(change.actor_bare_jid)?;
        ensure!(
            actor.to_string() == change.actor_bare_jid,
            "display change actor must be a canonical bare JID"
        );
        let locked: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM message_archive
             WHERE owner_id=$1 AND id=$2 AND source_stanza_id IS NULL FOR UPDATE",
        )
        .bind(change.owner_id)
        .bind(change.archive_id)
        .fetch_optional(&mut **self.tx)
        .await?;
        if locked.is_none() {
            return Ok(MissingOrChanged);
        }

        // A waiter on the original tuple must see holds and overlays
        // committed while it was waiting for the row lock.
        let (matches_original, held): (bool, bool) = sqlx::query_as(
            "SELECT a.stanza=$3 AND NOT EXISTS (
                        SELECT 1 FROM personal_archive_display_changes d WHERE d.archive_id=a.id
                    ),
                    (EXISTS (
                        SELECT 1 FROM legal_hold_personal_archives l
                        JOIN legal_holds h ON h.id=l.hold_id
                        WHERE l.archive_id=a.id AND h.released_at IS NULL
                    ) OR EXISTS (
                        SELECT 1 FROM legal_hold_scopes s
                        JOIN legal_holds h ON h.id=s.hold_id
                        WHERE s.scope_type='personal_archive_owner'
                          AND s.subject_id=a.owner_id AND h.released_at IS NULL
                    ))
             FROM message_archive a WHERE a.owner_id=$1 AND a.id=$2",
        )
        .bind(change.owner_id)
        .bind(change.archive_id)
        .bind(change.expected_stanza)
        .fetch_one(&mut **self.tx)
        .await?;
        if !matches_original {
            return Ok(MissingOrChanged);
        }
        if held {
            sqlx::query(
                "INSERT INTO personal_archive_display_changes
                    (archive_id,display_stanza,change_kind,actor_bare_jid,action_id)
                 VALUES ($1,$2,'personal_retraction',$3,$4)",
            )
            .bind(change.archive_id)
            .bind(change.display_stanza)
            .bind(change.actor_bare_jid)
            .bind(change.action_id)
            .execute(&mut **self.tx)
            .await?;
            return Ok(OverlayInserted);
        }
        let updated = sqlx::query(
            "UPDATE message_archive SET stanza=$3,encrypted=FALSE
             WHERE owner_id=$1 AND id=$2 AND stanza=$4",
        )
        .bind(change.owner_id)
        .bind(change.archive_id)
        .bind(change.display_stanza)
        .bind(change.expected_stanza)
        .execute(&mut **self.tx)
        .await?;
        Ok(if updated.rows_affected() == 1 {
            Replaced
        } else {
            MissingOrChanged
        })
    }
}
