//! Local MIX MAM snapshots and federated replies under a channel row lock.

use super::*;
use northstar_archive_core::mix_mam_peer_filter_allowed;
use sqlx::{Connection, Postgres, Transaction};

impl<E: RoomEffects> MixMamReadRepository for PostgresMixRepository<E> {
    async fn read_mix_mam(&self, command: MixMamReadCommand) -> Result<MixMamReadOutcome> {
        let MixMamReadActor::Local {
            account_id,
            username,
            auth_generation,
            local_domain,
        } = &command.actor
        else {
            anyhow::bail!("local MIX MAM requires an authenticated account");
        };
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let username = sqlx::query_scalar::<_, String>(
            "SELECT username FROM users
              WHERE id=$1 AND username=$2 AND auth_generation=$3 AND NOT is_disabled",
        )
        .bind(account_id)
        .bind(username)
        .bind(auth_generation)
        .fetch_optional(&mut *transaction)
        .await?;
        #[cfg(any(test, feature = "test-support"))]
        test_pause::pause(*account_id, true).await;

        let channel = crate::mix::mix_channel(
            &mut *transaction,
            &command.target.service_domain,
            &command.target.localpart,
        )
        .await?;
        let outcome = match (channel, username) {
            (None, _) => MixMamReadOutcome::MissingChannel,
            (Some(_), None) => MixMamReadOutcome::StaleAccount,
            (Some(channel), Some(username)) => {
                let actor = format!("{username}@{local_domain}");
                read_authorized_mix_mam_tx(
                    &mut transaction,
                    &channel,
                    &actor,
                    Some(*account_id),
                    &command.operation,
                )
                .await?
            }
        };
        transaction.commit().await?;
        Ok(outcome)
    }

    async fn admit_federated_mix_mam(
        &self,
        command: MixMamReadCommand,
        target_domain: &str,
        policy: S2sOutboxPolicy,
        render: impl FnOnce(MixMamReadOutcome) -> Result<Vec<String>> + Send,
    ) -> Result<MixMamAdmissionOutcome> {
        let MixMamReadActor::Federated { bare_jid } = &command.actor else {
            anyhow::bail!("federated MIX MAM requires an authenticated remote actor");
        };
        // The address lookup supplies the lock key. Use the row returned by
        // the locking SELECT for authority and reject an address change.
        let target = crate::mix::mix_channel(
            &self.pool,
            &command.target.service_domain,
            &command.target.localpart,
        )
        .await?;
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection
            .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
            .await?;
        // Authority and message-node writers take this row FOR UPDATE.
        // Subsequent statements see changes committed while this lock was
        // waiting. Quota reads likewise see commits before their advisory
        // lock was granted.
        let row = sqlx::query("SELECT * FROM mix_channels WHERE id = $1 FOR SHARE")
            .bind(target.as_ref().map(|channel| channel.id))
            .fetch_optional(&mut *transaction)
            .await?;
        let channel = row
            .as_ref()
            .map(crate::mix::channel_from_row)
            .filter(|channel| {
                target.is_some_and(|target| {
                    channel.service_domain == target.service_domain
                        && channel.localpart == target.localpart
                })
            });
        let outcome = match channel {
            Some(channel) => {
                read_authorized_mix_mam_tx(
                    &mut transaction,
                    &channel,
                    bare_jid,
                    None,
                    &command.operation,
                )
                .await?
            }
            None => MixMamReadOutcome::MissingChannel,
        };
        let responses = render(outcome)?;
        anyhow::ensure!(
            !responses.is_empty(),
            "MIX MAM renderer omitted the terminal IQ"
        );
        for response in responses {
            if let Err(error) = self
                .effects
                .enqueue_federated_stanza(&mut transaction, target_domain, &response, None, policy)
                .await
            {
                transaction.rollback().await?;
                return Ok(MixMamAdmissionOutcome::OutboxRejected(error));
            }
        }
        Ok(match transaction.commit().await {
            Ok(()) => MixMamAdmissionOutcome::Queued,
            Err(error) => MixMamAdmissionOutcome::OutboxRejected(error.into()),
        })
    }
}

async fn read_authorized_mix_mam_tx(
    transaction: &mut Transaction<'_, Postgres>,
    channel: &MixChannel,
    actor: &str,
    viewer_id: Option<Uuid>,
    operation: &MixMamReadOperation,
) -> Result<MixMamReadOutcome> {
    let channel_jid = channel.jid();
    let channel =
        match crate::mix::authorize_mix_node_read_tx(transaction, channel.id, actor, NODE_MESSAGES)
            .await?
        {
            crate::mix::MixReadOutcome::Found(channel) => channel,
            crate::mix::MixReadOutcome::Unauthorized => {
                return Ok(MixMamReadOutcome::NotAuthorized { channel_jid });
            }
            crate::mix::MixReadOutcome::NotFound => return Ok(MixMamReadOutcome::MissingChannel),
        };
    #[cfg(any(test, feature = "test-support"))]
    if let Some(viewer_id) = viewer_id {
        test_pause::pause(viewer_id, false).await;
    }
    let result = match operation {
        MixMamReadOperation::Form => MixMamReadResult::Form,
        MixMamReadOperation::Metadata => {
            let (first, last) =
                crate::mix::mix_mam_boundaries_tx(transaction, channel.id, viewer_id).await?;
            MixMamReadResult::Boundaries(first.map(boundary), last.map(boundary))
        }
        MixMamReadOperation::Query(query) => {
            if !mix_mam_peer_filter_allowed(&channel.jid_visibility, query.with_jid.is_some()) {
                return Ok(MixMamReadOutcome::NotAuthorized { channel_jid });
            }
            let query = mam_query_db(query);
            match crate::mix::mix_mam_page_tx(transaction, channel.id, viewer_id, &query).await? {
                Some(page) => MixMamReadResult::Page(mam_page(page)),
                None => MixMamReadResult::MissingReference,
            }
        }
    };
    Ok(MixMamReadOutcome::Authorized {
        channel_jid,
        result,
    })
}

#[cfg(any(test, feature = "test-support"))]
mod test_pause {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    struct LocalReadPause {
        account_id: Uuid,
        after_account: bool,
        entered: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }

    static PAUSE: Mutex<Option<LocalReadPause>> = Mutex::new(None);

    impl<E> PostgresMixRepository<E> {
        /// Pause one local read after the account check or after channel authorization.
        pub fn install_local_mix_mam_test_pause(
            account_id: Uuid,
            after_account: bool,
        ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
            let (entered, wait_for_entry) = oneshot::channel();
            let (release, resume) = oneshot::channel();
            *PAUSE.lock().unwrap() = Some(LocalReadPause {
                account_id,
                after_account,
                entered,
                resume,
            });
            (wait_for_entry, release)
        }
    }

    pub(super) async fn pause(account_id: Uuid, after_account: bool) {
        let pause = {
            let mut pending = PAUSE.lock().unwrap();
            if pending.as_ref().is_some_and(|pause| {
                pause.account_id == account_id && pause.after_account == after_account
            }) {
                pending.take()
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            let _ = pause.entered.send(());
            let _ = pause.resume.await;
        }
    }
}
