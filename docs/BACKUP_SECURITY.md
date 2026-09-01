# Authenticated, Encrypted, and Rollback-Protected Backups

Northstar backup format v2 adds three controls that plain checksums cannot
provide:

1. an Ed25519 signature authenticates the manifest;
2. mandatory production `age` encryption protects the database and uploads at rest; and
3. a persistent generation/sequence floor rejects replay of an older backup.

The original v1 format remains readable only through the explicit
`development-legacy` policy. It is unsigned, has no monotonic sequence, and
cannot satisfy production fail-closed policy. The default scripts and base
Compose reject v1, unsigned v2, and unencrypted payloads.

This format archives upload bytes only for `UPLOAD_STORAGE_BACKEND=local`.
With the S3 backend it is a database/control-plane backup and must not be
described as containing uploaded objects. S3 recovery requires an exact
PostgreSQL locator/version/size/SHA-256 manifest, a separately protected
provider-native bucket/prefix backup, and full validation in an isolated
namespace before traffic. The complete contract, including noncurrent-version,
KMS and Object Lock boundaries, is [UPLOAD_STORAGE.md](UPLOAD_STORAGE.md).

## Threat model and trust boundary

The signed v2 manifest records a canonical backup generation UUID, a positive
monotonic sequence, an RFC 3339 UTC creation time, the Northstar build version,
PostgreSQL version and migration count, encryption/signature algorithms, and
both stored-archive and plaintext SHA-256 digests for:

- the PostgreSQL custom-format dump;
- the PostgreSQL contents listing; and
- the immutable upload-object archive.

The signature covers the complete manifest. The signed archive digests are
checked before decryption. Plaintext digests and archive structure are checked
after decryption. Restore performs all of these checks before it changes either
production data plane. The producer restores its exact dump into an isolated,
one-shot local PostgreSQL cluster on a private Unix socket and proves
that every live upload row referenced by that dump has a same-size archive
member and, when present in the row, the same SHA-256 digest. `READY` is written
only after that check and after all publication files have been `fsync`ed.

This protects against accidental corruption, archive substitution, an
untrusted backup store, the wrong verification key, the wrong age identity,
and rollback to an equal or lower sequence. It does not protect a host on which
an attacker can replace the trusted public key, the restore-state volume, and
the restore program together. Store an independent copy of the public key and
replicate the restore-state file to protected or append-only storage.

## Required tools

The backup image contains the supported toolchain:

- OpenSSL with Ed25519 and `pkeyutl -rawin` support;
- `age` and `age-keygen` for mandatory production encryption;
- Python 3 (including `fcntl`, so the scripts target Linux/WSL containers);
- PostgreSQL client tools, GNU coreutils, tar, gzip, and util-linux `flock`.

Native installations may use the same scripts after installing these tools.
`age` is required by every production backup and non-metadata restore.
OpenSSL is required only for signed backups.

## One-time key creation

Create keys on an administrator-controlled machine, not in the repository:

```bash
umask 077
openssl genpkey -algorithm ED25519 -out backup-signing-ed25519.pem
openssl pkey -in backup-signing-ed25519.pem -pubout \
  -out backup-signing-ed25519.pub.pem

age-keygen -o backup-age-identity.txt
sed -n 's/^# public key: //p' backup-age-identity.txt \
  > backup-age-recipients.txt
```

The unencrypted Ed25519 private key is intentionally accepted only through a
file. The scripts never accept private key text or a private-key passphrase in
an environment variable or command-line argument. Outside a container secret
mount, private files must have no group/other permission bits (normally mode
`0600`). Nothing prints private key, age identity, database URL, or password
contents to logs.

Distribute capabilities separately:

| Capability | Backup job | Restore host | Offline auditor |
|---|---:|---:|---:|
| Ed25519 private signing key | yes | no | no |
| Ed25519 public verification key | optional | yes | yes |
| age public recipients | yes | no | optional |
| age private identity | no | yes | no |
| backup sequence state | read/write | no | optional copy |
| trusted restore floor | no | read/write | optional copy |

## Production Compose use

`scripts/create-production-secrets.sh` creates the complete external production
secret set under `/etc/northstar/secrets` by default and self-tests both backup
key pairs. Its `root:root` mode-`0700` parent must be created before invocation;
real keys must never live in the source checkout. To use backup keys held
outside the project, point Compose at them:

```bash
export BACKUP_SIGNING_KEY_SECRET_FILE=/secure/backup-signing-ed25519.pem
export BACKUP_VERIFY_KEY_SECRET_FILE=/secure/backup-signing-ed25519.pub.pem
export BACKUP_AGE_RECIPIENTS_SECRET_FILE=/secure/backup-age-recipients.txt
export BACKUP_AGE_IDENTITY_SECRET_FILE=/secure/backup-age-identity.txt
```

Create a signed and encrypted backup:

```bash
sudo docker compose \
  --profile backup run --rm backup
```

The base Compose backup profile uses a private `/scratch` tmpfs for the plaintext dump and tar
archive, then writes only ciphertext to the backup destination. Restore also
uses a private `/scratch` tmpfs in the base Compose file; decrypted database
payloads and the initially expanded archive never use the persistent rollback
volume. Their default capacities are 4 GiB. Set
`BACKUP_PLAINTEXT_SCRATCH_SIZE` and `RESTORE_PLAINTEXT_SCRATCH_SIZE` above the
respective working sets. A capacity failure aborts without publishing a
`READY` backup or entering restore cutover.

Run a metadata-only audit without possessing the age identity:

```bash
sudo docker compose \
  --profile restore run --rm --entrypoint bash restore \
  /opt/northstar/verify-backup.sh /backups/northstar-YYYYMMDDTHHMMSSZ \
  --metadata-only
```

For a real restore, stop Northstar and all other target-database clients, then
provide the existing destructive-operation confirmation and rollback path:

```bash
sudo docker compose \
  --profile restore run --rm restore \
  /backups/northstar-YYYYMMDDTHHMMSSZ \
  --confirm-restore NORTHSTAR-RESTORE \
  --rollback-dir /rollback \
  --database-url-file /run/secrets/migrator_database_url \
  --upload-dir /uploads
```

The base production profile deliberately uses two capability-separated volumes:
`backup-sequence-state` contains `/state/backup-sequence` for the producer, and
`restore-floor-state` contains `/state/restore-floor` for the restore role.
Neither job can rewrite the other's monotonic state. Do not delete or silently
recreate either volume during normal deployment. A native state parent must be
owned by the job account with mode `0700`; state and lock files are mode `0600`.
Restore opens an existing lock without truncation and validates the opened
inode against the pathname before taking `flock`.

This replaces the former shared `backup-security-state` volume. Before applying
the updated base profile to an existing installation, stop both maintenance jobs and
copy only `backup-sequence` (and its lock, if retained) into
`backup-sequence-state`, and only `restore-floor` (and its lock) into
`restore-floor-state`. Preserve UID/GID `10001:10001` and modes `0700`/`0600`,
then verify both state files offline. Starting with empty replacement volumes
silently creates a new backup lineage and loses the trusted restore floor, so it
is not an ordinary upgrade procedure.

## Direct script use

Direct production backup (signature, encryption, and monotonic sequence are all
required by the default policy):

```bash
scripts/backup.sh \
  --output /srv/northstar-backups \
  --database-url-file /run/secrets/backup_database_url \
  --upload-dir /srv/northstar-uploads \
  --sequence-state-file /var/lib/northstar-backup/sequence \
  --signing-key-file /run/secrets/backup_signing_key \
  --age-recipient-file /run/secrets/backup_age_recipients \
  --plaintext-staging-dir /secure-ephemeral-scratch \
  --northstar-version 0.2.0
```

Verify and materialize payloads into a pre-created empty directory:

```bash
mkdir -m 0700 /secure-restore/payload
scripts/verify-backup.sh /srv/northstar-backups/northstar-... \
  --public-key-file /etc/northstar/backup-signing.pub.pem \
  --age-identity-file /run/secrets/backup_age_identity \
  --rollback-state-file /var/lib/northstar-restore/floor \
  --materialize-dir /secure-restore/payload
```

`verify-backup.sh` normally deletes its temporary plaintext. The explicit
materialization option is for the restore program and leaves plaintext behind
for the caller to protect and remove.

For direct restore, point `--plaintext-staging-dir` at a private tmpfs and size
the explicit resource limits for the deployment:

```bash
scripts/restore-backup.sh /srv/northstar-backups/northstar-... \
  --confirm-restore NORTHSTAR-RESTORE \
  --database-url-file /run/secrets/migrator_database_url \
  --upload-dir /srv/northstar/uploads \
  --rollback-dir /srv/northstar/restore-rollback \
  --plaintext-staging-dir /run/northstar-restore \
  --max-upload-object-bytes 1073741824 \
  --max-upload-total-bytes 68719476736 \
  --reserve-free-bytes 1073741824
```

The object and aggregate limits are checked from tar metadata before
extraction. Free-space budgets are checked independently for plaintext
materialization/extraction, same-filesystem upload cutover staging, and
rollback retention. These checks prevent predictable exhaustion; they do not
replace filesystem quotas or monitoring because free space can change after a
check.

## Backup/restore maintenance fence and cutover journal

Backup and restore hold the same PostgreSQL session advisory lock within the
target database, serializing these two maintenance jobs. Backup still relies on Northstar's completed-upload
ordering (atomic file activation precedes `uploaded=true`) and validates the
dump-to-archive direction before `READY`; ordinary application writers do not
participate in the advisory lock.

Restore has a stronger fail-closed boundary. Dump preflight happens in a
private, Unix-socket-only temporary PostgreSQL instance and never creates a
validation database on the target cluster. After preflight and the pre-restore
dump, restore keeps one already-open target session and sets the target database
to `ALLOW_CONNECTIONS=false`. It deliberately does not terminate other
sessions or require `pg_signal_backend`; if any peer remains, restore fails and
instructs the operator to stop Northstar and every other database client before
retrying. Once only the restore session remains, replacement runs through that
session. The same checked-in grant body used by post-migration reconciliation
is applied inside the replacement transaction, so `public` is owned by the
migrator and PUBLIC/runtime/backup ACLs and default privileges converge before
the database can reopen. If the restore process is killed without a catchable
signal, PostgreSQL remains closed to new connections rather than serving a
half-switched state.

Incoming objects are copied and verified in a private
`.northstar-restore-cutover-<id>` directory inside the upload volume. The
directory contains expanded objects and hash metadata only. Each old-object
and new-object rename is preceded by an exact, append-only journal intent;
journal records and both source/destination directories are `fsync`ed. This
makes live activation a same-filesystem atomic rename even when rollback
retention is another filesystem. Compensation consumes only journaled intents,
so an old object and an incoming object with the same UUID cannot be confused.

Old objects remain in that same-filesystem area until they have been copied to
rollback retention, checked against the old size/digest manifest and `fsync`ed.
Only then may the restore floor commit. `SIGINT`, `SIGTERM`, shell errors and
ordinary exits all converge on the same compensation path. Before that commit,
if either database or upload compensation, required journal durability, or
database re-enable fails, the script keeps the plaintext work directory and
cutover journal and leaves the database fail-closed. Do not delete those paths;
preserve their exact error output for recovery. Once the floor commit succeeds,
the new data plane is authoritative: a failure to append the final journal
marker retains the journal for inspection but does not roll back or deliberately
keep an otherwise consistent database offline.

`SIGKILL`, kernel panic and power loss cannot execute a shell trap. A remaining
cutover directory makes the strict upload-root preflight reject the next normal
restore. Treat it together with the retained pre-restore dump as recovery
evidence; do not merely remove it or run `ALTER DATABASE ... ALLOW_CONNECTIONS
true`. This release does not provide a fully automatic hard-crash journal
replay command, so hard-crash recovery requires an operator-reviewed restore
drill. That is a documented residual boundary, not an automatic-recovery claim.

The retained pre-restore database dump and old upload copies are plaintext by
default. Put the rollback root on encrypted, access-controlled storage (or move
the verified rollback set into the organization's encryption system after the
restore). The age identity used to decrypt an incoming backup is not an age
recipient and is intentionally not repurposed to invent a rollback key.

## Generation, sequence, and rollback rules

The first backup atomically creates a random generation UUID and reserves
sequence 1. Later invocations take an exclusive file lock and atomically
advance the sequence. A failed backup may leave a harmless gap; a sequence is
never reused. The backup directory timestamp remains unchanged for v1 tooling,
while the signed manifest is authoritative for ordering.

On the first signed restore, the restore floor is bootstrapped only after the
database and uploads have activated successfully. Thereafter:

- the same generation must have a strictly larger sequence;
- an equal or lower sequence requires the explicit `--allow-rollback` flag;
- a different generation requires `--allow-generation-change`;
- a deliberate older restore never lowers the stored replay floor; and
- a restore holds an exclusive state lock from policy check through commit.

Use `--allow-rollback` only after documenting why an older application state is
required. Use `--allow-generation-change` only when intentionally replacing a
lost/reinitialized backup sequence lineage. A valid signature alone cannot
distinguish a legitimate new lineage from rollback after loss of both state
files.

## Key rotation

Signing-key rotation does not require a new generation. Start producing new
backups with the new private key and install the matching public key on restore
hosts. Retain old public keys offline for the retention lifetime of old
backups; verification accepts one explicitly selected public key and checks its
DER SHA-256 fingerprint against `signing_key_id` in the manifest.

For age rotation, put both old and new public recipients in the recipients
file during an overlap window. New backups can then be decrypted by either
identity. Remove the old recipient only after every retained backup and restore
site satisfies the rotation policy. An age identity file may contain multiple
identities for restore overlap.

## Legacy compatibility and fail-closed policy

The default `production` policy requires a file-backed database URL, Ed25519
signature, age encryption, private plaintext scratch, and persistent
generation/sequence or restore-floor state. It rejects v1 and unsigned or
unencrypted v2 before database access or plaintext materialization.

Compatibility has exactly one downgrade boundary:
`--development-insecure-legacy` (equivalently
`BACKUP_SECURITY_POLICY=development-legacy`). It emits an explicit warning and
is unsuitable for real data. The former independent legacy booleans no longer
create alternate downgrade combinations. A rollback-state file is accepted
only with an authenticated v2 manifest; the scripts never claim rollback
protection for unsigned metadata.

## Tests

Run the database-independent adversarial fixture with:

```bash
bash scripts/backup-security-offline.sh
```

It covers a valid signed backup, wrong Ed25519 public key, modified payload,
modified manifest, duplicate/older sequence, approved rollback without lowering
the floor, unapproved/approved generation change, v1 compatibility and strict
rejection, metadata-only encrypted verification, correct age decryption, and a
wrong age identity. The age cases run when `age` is installed. CI runs the full
fixture inside the pinned backup image, where age is always present.

The existing `scripts/backup-restore-wsl.sh` first exercises the full production
path with a read-only backup role, file-backed URLs, Ed25519, age, monotonic
state, a `NOSUPERUSER NOCREATEDB` migrator restore, and post-restore ACL denial
checks. It then uses explicitly selected legacy fixtures for destructive archive
mutation and exercises exact dump-to-upload validation, Unix-socket-only local
restore validation, single-object/aggregate budgets, same-filesystem cutover,
same-UUID old/new objects, refusal (without termination) while another database
session remains, failure after the first old and first new activation, SIGTERM
unified compensation, successful retry, non-truncating floor locks, rollback
retention, and dual-plane compensation. The unsigned fixture path can never be
reached by a default production invocation.

## 中文运维摘要

- 基础 Compose 的正式备份路径已经同时强制签名、age 静态加密及防回滚状态；
  缺少任何一项会在读取正式数据库之前失败，不再依赖可遗漏的 overlay。
- 签名私钥只交给备份任务，恢复端只持有公钥；age 私钥只交给恢复端。
- 恢复在解密、建临时数据库、修改正式数据库或上传目录之前，先验证签名和
  密文摘要；解密后还会再次验证明文摘要。
- 备份序列与恢复下限分别位于两个独立 state volume，是不同权限的防回滚安全
  状态，不能在普通升级中删除或合并。
- 恢复解密/解包默认使用私有 tmpfs；同文件系统 cutover 目录只保存展开后的上传
  对象和精确 journal。补偿不完整时数据库保持 fail-closed，相关目录不得删除。
- rollback 目录中的恢复前数据库与旧上传默认是明文，必须依靠加密文件系统或组织
  的离线加密流程保护。
- `--allow-rollback` 与 `--allow-generation-change` 都是需要审计记录的紧急开关；
  前者不会降低已经记录的最高序列。
- 旧 v1 备份只有明确启用 `development-legacy` 才能读取；它无法证明真实性，也无法防回滚；生产默认会
  直接拒绝它。
