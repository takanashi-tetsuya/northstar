#!/usr/bin/env python3
"""Exercise an explicit maintenance binary in a private Unix-socket PostgreSQL cluster."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import ProxyHandler, build_opener


ROOT = Path(__file__).resolve().parent.parent
HTTP = build_opener(ProxyHandler({}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True, help="existing Linux xmpp-server binary; this fixture never builds")
    args = parser.parse_args()
    binary = args.server.resolve(strict=True)
    if os.getuid() == 0 or not os.access(binary, os.X_OK):
        raise SystemExit("run as an ordinary user with an executable Linux server binary")
    binary_identity = binary.stat()
    digest = hashlib.sha256()
    with binary.open("rb") as executable:
        for block in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(block)
    print(f"fixture binary: {binary}; size={binary_identity.st_size}; mtime={datetime.fromtimestamp(binary_identity.st_mtime, timezone.utc).isoformat()}; sha256={digest.hexdigest()}", flush=True)

    def require_same_binary() -> None:
        current = binary.stat()
        if (current.st_ino, current.st_size, current.st_mtime_ns) != (binary_identity.st_ino, binary_identity.st_size, binary_identity.st_mtime_ns):
            raise RuntimeError("the supplied server binary changed during the fixture; finish the build before testing")

    require_same_binary()
    pg_bin = Path(subprocess.check_output(["pg_config", "--bindir"], text=True).strip())
    environment = {"PATH": f"{pg_bin}:/usr/bin:/bin", "HOME": os.environ["HOME"], "LANG": "C.UTF-8"}
    server_processes: list[subprocess.Popen[bytes]] = []
    server_logs = []
    started = False
    with tempfile.TemporaryDirectory(prefix="northstar-maintenance-fixture.", dir="/tmp") as temporary:
        fixture = Path(temporary)
        fixture.chmod(0o700)
        data = fixture / "data"
        socket_dir = fixture / "socket"
        socket_dir.mkdir(mode=0o700)
        log = fixture / "fixture.log"

        def secret_file(name: str, value: str) -> Path:
            path = fixture / name
            path.write_text(value + "\n", encoding="utf-8")
            path.chmod(0o600)
            return path

        def run(command: list[str], *, extra: dict[str, str] | None = None, sql: str | None = None, capture: bool = False) -> str:
            with log.open("ab") as output:
                result = subprocess.run(
                    command, cwd=fixture, env=environment | (extra or {}),
                    input=sql.encode() if sql is not None else None,
                    stdout=subprocess.PIPE if capture else output, stderr=output,
                    timeout=90, check=True,
                )
            return result.stdout.decode().strip() if capture else ""

        passwords = {role: secrets.token_hex(24) for role in ("bootstrap", "migrator", "runtime", "command", "backup")}
        files = {role: secret_file(f"{role}-password", password) for role, password in passwords.items()}
        try:
            run([str(pg_bin / "initdb"), "-D", str(data), "-U", "northstar_bootstrap", "--pwfile", str(files["bootstrap"]), "--auth-local=scram-sha-256", "--auth-host=reject", "--encoding=UTF8", "--no-locale"])
            run([str(pg_bin / "pg_ctl"), "-D", str(data), "-l", str(fixture / "postgres.log"), "-w", "-t", "15", "start", "-o", f"-F -c listen_addresses='' -c unix_socket_directories={socket_dir} -c unix_socket_permissions=0700"])
            started = True
            run([str(pg_bin / "createdb"), "-h", str(socket_dir), "-U", "northstar_bootstrap", "xmpp"], extra={"PGPASSWORD": passwords["bootstrap"]})
            run([
                "bash", str(ROOT / "scripts/reconcile-database-roles.sh"), "--apply",
                "--host", str(socket_dir), "--connect-as", "northstar_bootstrap",
                "--bootstrap-password-file", str(files["bootstrap"]),
                "--migrator-password-file", str(files["migrator"]),
                "--runtime-password-file", str(files["runtime"]),
                "--command-password-file", str(files["command"]),
                "--backup-password-file", str(files["backup"]),
            ])
            urls = {
                role: secret_file(f"{role}-url", f"postgresql://northstar_{role}:{passwords[role]}@localhost/xmpp?host={quote(str(socket_dir), safe='')}")
                for role in ("migrator", "runtime")
            }
            urls["command"] = secret_file("command-url", f"postgresql://northstar_commands:{passwords['command']}@localhost/xmpp?host={quote(str(socket_dir), safe='')}")
            run([str(binary), "migrate"], extra={"MIGRATOR_DATABASE_URL_FILE": str(urls["migrator"]), "XMPP_DOMAIN": "maintenance.test"})
            run(["bash", str(ROOT / "scripts/reconcile-database-grants.sh"), "--database-url-file", str(urls["migrator"])])

            def query(sql: str) -> str:
                return run(["python3", str(ROOT / "scripts/run-postgres.py"), "--database-url-file", str(urls["migrator"]), "--", "psql", "-XqAt", "-v", "ON_ERROR_STOP=1"], sql=sql, capture=True)

            query("""
INSERT INTO users(id,username,password_hash) VALUES ('10000000-0000-4000-8000-000000000001','maintenance-fixture','fixture-not-a-login');
INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,created_at)
SELECT ('20000000-0000-4000-8000-00000000000' || n)::uuid,
 '10000000-0000-4000-8000-000000000001','peer@maintenance.test','peer@maintenance.test/device','<message/>',true,
 CASE WHEN n=5 THEN clock_timestamp() ELSE clock_timestamp()-INTERVAL '40 days' END
FROM generate_series(1,5) n;
INSERT INTO legal_holds(id,title,authority_reference,reason,created_request_id)
VALUES ('30000000-0000-4000-8000-000000000001','fixture','fixture','preserve held archive','40000000-0000-4000-8000-000000000001');
INSERT INTO legal_hold_personal_archives(hold_id,archive_id,owner_id,encrypted,record_created_at)
SELECT '30000000-0000-4000-8000-000000000001',id,owner_id,encrypted,created_at FROM message_archive
WHERE id='20000000-0000-4000-8000-000000000004';
""")
            # Loading the core's .env would make this clean process fail. No
            # transport, TLS, anti-abuse, admin or message-key capabilities are
            # supplied through its otherwise explicitly empty environment.
            (fixture / ".env").write_text("DATABASE_URL=postgresql://forbidden.invalid/never\nXMPP_DOMAIN=invalid domain\n")
            maintenance_environment = environment | {
                "DATABASE_URL_FILE": str(urls["runtime"]), "XMPP_DOMAIN": "maintenance.test",
                "MAM_RETENTION_DAYS": "30", "MUC_MAM_RETENTION_DAYS": "30",
                "OFFLINE_MESSAGE_TTL_DAYS": "30", "AUDIT_LOG_RETENTION_DAYS": "730",
                "RETENTION_CLEANUP_BATCH_SIZE": "2", "RETENTION_CLEANUP_INTERVAL_SECONDS": "60",
            }

            def unused_port() -> int:
                with socket.socket() as lease:
                    lease.bind(("127.0.0.1", 0))
                    return lease.getsockname()[1]

            def start(name: str, port: int) -> subprocess.Popen[bytes]:
                require_same_binary()
                output = (fixture / f"{name}.log").open("wb")
                server_logs.append(output)
                process = subprocess.Popen([str(binary), "serve", "maintenance"], cwd=fixture,
                    env=maintenance_environment | {"MAINTENANCE_BIND": f"127.0.0.1:{port}"}, stdout=output, stderr=output)
                server_processes.append(process)
                return process

            def ready(process: subprocess.Popen[bytes], port: int) -> None:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError(f"maintenance exited before readiness: {process.returncode}")
                    try:
                        with HTTP.open(f"http://127.0.0.1:{port}/readyz", timeout=1) as response:
                            if response.status == 200:
                                return
                    except OSError:
                        pass
                    time.sleep(0.05)
                raise RuntimeError("maintenance did not become ready within 15 seconds")

            def stop(process: subprocess.Popen[bytes]) -> None:
                process.terminate()
                if process.wait(timeout=20) != 0:
                    raise RuntimeError("server did not shut down cleanly")

            def await_archive_count(expected: int) -> None:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    count = int(query("SELECT count(*) FROM message_archive;"))
                    if count == expected:
                        return
                    if count < expected:
                        raise RuntimeError("retention exceeded its bounded batch or removed protected data")
                    time.sleep(0.05)
                raise RuntimeError("retention did not finish its first bounded pass")

            port = unused_port()
            first = start("first", port)
            ready(first, port)
            await_archive_count(3)
            # Core receives its own protocol credentials, never added to the
            # maintenance environment. Both processes share the same real
            # runtime principal and database/schema. No Redis is configured.
            certificate = fixture / "core.crt"
            private_key = fixture / "core.key"
            run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "1",
                "-subj", "/CN=maintenance.test", "-addext", "subjectAltName=DNS:maintenance.test,IP:127.0.0.1",
                "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature,keyEncipherment", "-addext", "extendedKeyUsage=serverAuth",
                "-keyout", str(private_key), "-out", str(certificate)])
            private_key.chmod(0o600)
            (fixture / "logs").mkdir(mode=0o700)
            core_environment = environment | {
                "NORTHSTAR_DISABLE_DOTENV": "true", "DATABASE_URL_FILE": str(urls["runtime"]), "ADMIN_COMMAND_DATABASE_URL_FILE": str(urls["command"]),
                "XMPP_DOMAIN": "maintenance.test", "TLS_CERT_PATH": str(certificate), "TLS_KEY_PATH": str(private_key),
                "PUBLIC_URL": "http://127.0.0.1:1", "UPLOAD_DIR": str(fixture / "core-uploads"),
                "FEDERATION_ENABLED": "false", "DATABASE_MAX_CONNECTIONS": "8", "DATABASE_MIN_CONNECTIONS": "0",
                "TOKIO_WORKER_THREADS": "2", "TEST_LISTENER_ACTIVATION": "true", "LOG_FORMAT": "json",
            }
            for setting in ("DIALBACK_SECRET", "API_CONTROL_SECRET", "ABUSE_STATE_HMAC_KEY", "FAST_TOKEN_SECRET", "DUMMY_SCRAM_SECRET"):
                core_environment[f"{setting}_FILE"] = str(secret_file(f"core-{setting.lower()}", secrets.token_hex(32)))
            for setting in ("XMPP_BIND", "XMPPS_BIND", "HTTP_BIND", "WEB_ADMIN_BIND", "METRICS_BIND", "S2S_BIND", "S2S_TLS_BIND"):
                core_environment[setting] = "127.0.0.1:0"

            def start_core(name: str) -> subprocess.Popen[bytes]:
                require_same_binary()
                readiness_file = fixture / f"{name}.ready.json"
                nonce = secrets.token_hex(16)
                output = (fixture / f"{name}.log").open("wb")
                server_logs.append(output)
                process = subprocess.Popen([str(binary), "serve", "core"], cwd=fixture,
                    env=core_environment | {"TEST_READINESS_FILE": str(readiness_file), "TEST_READINESS_NONCE": nonce},
                    stdout=output, stderr=output)
                server_processes.append(process)
                deadline = time.monotonic() + 15
                while not readiness_file.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("core did not publish its child-owned listeners")
                    time.sleep(0.05)
                record = json.loads(readiness_file.read_text())
                assert record["version"] == 1 and record["pid"] == process.pid and record["instance_nonce"] == nonce
                address = record["listeners"]["http"]
                assert address.startswith("127.0.0.1:")
                ready(process, int(address.rsplit(":", 1)[1]))
                ready(first, port)
                assert query("SELECT count(*) FROM pg_locks lock JOIN pg_stat_activity activity ON activity.pid=lock.pid WHERE activity.application_name='northstar-maintenance' AND lock.locktype='advisory' AND lock.granted;") == "1"
                return process

            core = start_core("core-first")
            stop(core)
            core = start_core("core-restarted")
            stop(core)
            print("core and maintenance passed: simultaneous readiness on the same runtime database, separate credential environments, core restart without taking maintenance ownership", flush=True)
            # The compatibility command must participate in the same lock.
            # Use the core configuration already proven above so refusal
            # cannot be mistaken for a missing credential or TLS failure.
            require_same_binary()
            standalone_readiness = fixture / "competing-standalone.ready.json"
            standalone_log = fixture / "competing-standalone.log"
            output = standalone_log.open("wb")
            server_logs.append(output)
            standalone = subprocess.Popen([str(binary), "serve", "standalone"], cwd=fixture,
                env=core_environment | {"TEST_READINESS_FILE": str(standalone_readiness), "TEST_READINESS_NONCE": secrets.token_hex(16)},
                stdout=output, stderr=output)
            server_processes.append(standalone)
            assert standalone.wait(timeout=15) != 0, "standalone started a second retention owner"
            assert "archive maintenance is already owned" in standalone_log.read_text(), "standalone failed for an unrelated reason"
            assert not standalone_readiness.exists(), "a conflicting standalone process published listeners"
            ready(first, port)
            second = start("competing", unused_port())
            assert second.wait(timeout=15) != 0, "a second process claimed the same retention authority"
            assert "archive maintenance is already owned" in (fixture / "competing.log").read_text(), "competing process failed for an unrelated reason"
            with HTTP.open(f"http://127.0.0.1:{port}/metrics", timeout=2) as response:
                assert "xmpp_retention_personal_mam_deleted_total 2\n" in response.read().decode()
            # Alter only this disposable cluster after role attestation. A
            # real failed cleanup must affect readiness on its first pass,
            # while the independently locked database session stays healthy.
            query("REVOKE DELETE ON message_archive FROM northstar_runtime;")
            print("maintenance fixture: waiting for the next 60-second pass after revoking archive DELETE", flush=True)
            failure_deadline = time.monotonic() + 65
            while True:
                if first.poll() is not None:
                    raise RuntimeError("maintenance stopped instead of exposing the failed cleanup")
                with HTTP.open(f"http://127.0.0.1:{port}/metrics", timeout=2) as response:
                    if "xmpp_retention_cleanup_failures_total 1\n" in response.read().decode():
                        break
                if time.monotonic() > failure_deadline:
                    raise RuntimeError("the revoked DELETE privilege did not cause the first cleanup failure")
                time.sleep(0.1)
            try:
                HTTP.open(f"http://127.0.0.1:{port}/readyz", timeout=2).close()
            except HTTPError as error:
                assert error.code == 503, "a failed cleanup returned an unexpected readiness status"
            else:
                raise RuntimeError("the first failed cleanup still reported ready")
            with HTTP.open(f"http://127.0.0.1:{port}/healthz", timeout=2) as response:
                assert response.status == 200, "the readiness failure must not fabricate a liveness failure"
            assert query("SELECT count(*) FROM pg_locks lock JOIN pg_stat_activity activity ON activity.pid=lock.pid WHERE activity.application_name='northstar-maintenance' AND lock.locktype='advisory' AND lock.granted;") == "1", "the failed pass must be observed while the ownership connection is still healthy"
            assert query("SELECT count(*) FROM message_archive;") == "3", "the failed cleanup altered protected archive state"
            query("GRANT DELETE ON message_archive TO northstar_runtime;")
            stop(first)
            restarted = start("restarted", port)
            ready(restarted, port)
            await_archive_count(2)
            assert query("SELECT string_agg(id::text, ',' ORDER BY id) FROM message_archive;") == "20000000-0000-4000-8000-000000000004,20000000-0000-4000-8000-000000000005", "restart must resume cleanup while preserving held and fresh rows"
            # Disconnect the exact advisory-lock owner, without stopping the
            # cluster or breaking its other query connections. The process
            # must exit instead of silently reacquiring a different session.
            run([str(pg_bin / "psql"), "-h", str(socket_dir), "-U", "northstar_bootstrap", "-d", "xmpp", "-XqAt", "-v", "ON_ERROR_STOP=1"],
                extra={"PGPASSWORD": passwords["bootstrap"]}, sql="SELECT pg_terminate_backend(activity.pid) FROM pg_locks lock JOIN pg_stat_activity activity ON activity.pid=lock.pid WHERE activity.application_name='northstar-maintenance' AND lock.locktype='advisory' AND lock.granted;")
            assert restarted.wait(timeout=12) != 0, "maintenance survived loss of its exact ownership connection"
            recovered = start("ownership-recovered", port)
            ready(recovered, port)
            assert query("SELECT count(*) FROM message_archive;") == "2"
            stop(recovered)
            require_same_binary()
            print("maintenance subserver passed: real runtime role, no core secrets or .env, bounded retention, legal hold, first-pass readiness, first-failure 503 with healthy ownership, restored-grant recovery, singleton refusal, ownership-connection loss exit and clean restart", flush=True)
            print("evidence scope: this exact binary's core startup/restart and maintenance role on private PostgreSQL; no client message traffic, multi-host failover, production deployment or remote CI result is asserted", flush=True)
        except BaseException:
            for diagnostic in fixture.glob("*.log"):
                if diagnostic.exists():
                    print(f"fixture diagnostic: {diagnostic.name}\n{diagnostic.read_text(errors='replace')[-6000:]}", flush=True)
            raise
        finally:
            for process in server_processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            for output in server_logs:
                output.close()
            if started:
                subprocess.run([str(pg_bin / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "-t", "15", "stop"], env=environment, stdout=subprocess.DEVNULL, check=True, timeout=20)


if __name__ == "__main__":
    main()
