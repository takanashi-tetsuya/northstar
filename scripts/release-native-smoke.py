#!/usr/bin/env python3
"""Run an extracted distribution against its own disposable PostgreSQL cluster."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request

SPEC = importlib.util.spec_from_file_location('readiness', Path(__file__).with_name('wait-test-readiness.py'))
READINESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READINESS)


def print_fixture_diagnostics(log, path):
    """Keep early tool failures observable without emitting configured DSNs."""
    log.flush()
    for line in path.read_text(errors='replace').splitlines()[-30:]:
        print(re.sub(r'postgres(?:ql)?://\S+', '[REDACTED_DATABASE_URL]', line))
    postgres_log = path.with_name('postgres.log')
    if postgres_log.exists():
        for line in postgres_log.read_text(errors='replace').splitlines()[-30:]:
            print(re.sub(r'postgres(?:ql)?://\S+', '[REDACTED_DATABASE_URL]', line))


def run(package, pg_bin, openssl, evidence, image=None):
    package = package.resolve(strict=True)
    binary = package / ('xmpp-server.exe' if os.name == 'nt' else 'xmpp-server')
    manifest = json.loads((package / 'PACKAGE-MANIFEST.json').read_text())
    # In particular, do not pass the CI publication token, inherited database
    # credentials, dotenv configuration or application overrides to children.
    allowed = {'PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'HOME', 'USERPROFILE',
               'APPDATA', 'LOCALAPPDATA', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment['PATH'] = str(pg_bin) + os.pathsep + environment.get('PATH', '')
    suffix = '.exe' if os.name == 'nt' else ''
    tool = lambda name: str(pg_bin / (name + suffix))
    version = subprocess.check_output([tool('postgres'), '--version'], env=environment, text=True).strip()
    if not version.startswith('postgres (PostgreSQL) 17.'):
        raise ValueError('native release smoke requires PostgreSQL 17')
    with tempfile.TemporaryDirectory(prefix='northstar-release-native-') as temporary:
        root = Path(temporary)
        if os.name == 'nt':
            subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                str(Path(__file__).with_name('release-private-directory-windows.ps1')),
                '-Directory', str(root)], env=environment, check=True, timeout=20)
        password = root / 'password'
        password.write_text('xmpp-test-password\n')
        password.chmod(0o600)
        data = root / 'data'
        with (root / 'fixture.log').open('wb') as log:
            def command(arguments, *, env=environment, cwd=root, timeout=30):
                return subprocess.run(arguments, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                                      stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout)
            try:
                command([tool('initdb'), '-D', str(data), '--username=xmpp_test', '--auth-local=trust',
                         '--auth-host=scram-sha-256', '--pwfile=' + str(password), '--no-locale', '--encoding=UTF8'])
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                print_fixture_diagnostics(log, root / 'fixture.log')
                raise
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            postgres = None
            server = None
            started = time.monotonic()
            try:
                options = ['-h', '127.0.0.1', '-p', str(port), '-c', 'unix_socket_directories=',
                           '-c', 'max_connections=32', '-c', 'shared_buffers=16MB', '-c', 'fsync=on']
                if os.name == 'nt':
                    spec = importlib.util.spec_from_file_location('windows_postgres',
                        Path(__file__).with_name('release-postgres-windows.py'))
                    windows_pg = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(windows_pg)
                    postgres = windows_pg.WindowsPostgres(tool, data, options, environment, log)
                else:
                    postgres = subprocess.Popen([tool('postgres'), '-D', str(data), *options],
                        env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                pg_env = dict(environment, PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='xmpp_test',
                              PGPASSWORD='xmpp-test-password', PGDATABASE='postgres', PGCONNECT_TIMEOUT='2')
                deadline = time.monotonic() + 15
                while True:
                    if postgres.poll() is not None:
                        raise RuntimeError('owned PostgreSQL exited before startup')
                    probe = subprocess.run([tool('pg_isready'), '-q'], env=pg_env, timeout=3)
                    if probe.returncode == 0:
                        observed = subprocess.check_output([tool('psql'), '-XqAt', '-v', 'ON_ERROR_STOP=1',
                            '-c', 'SHOW data_directory'], env=pg_env, text=True, timeout=3).strip()
                        if Path(observed).resolve() != data.resolve():
                            raise RuntimeError('loopback PostgreSQL is not the owned cluster')
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeError('PostgreSQL startup timeout')
                    time.sleep(.1)
                database = 'northstar_release_' + secrets.token_hex(8)
                command([tool('createdb'), database], env=pg_env)
                command([tool('psql'), '-XqAt', '-v', 'ON_ERROR_STOP=1', '-c',
                         'ALTER SCHEMA public OWNER TO xmpp_test'], env=dict(pg_env, PGDATABASE=database))
                cert, key = root / 'server.crt', root / 'server.key'
                command([openssl, 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost/OU=Northstar Development Only',
                    '-addext', 'basicConstraints=critical,CA:FALSE',
                    '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment',
                    '-addext', 'extendedKeyUsage=critical,serverAuth',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                    '-keyout', str(key), '-out', str(cert)])
                key.chmod(0o600)
                cert.chmod(0o600)
                (root / 'logs').mkdir(mode=0o700)
                (root / 'uploads').mkdir(mode=0o700)
                url = f'postgres://xmpp_test:xmpp-test-password@127.0.0.1:{port}/{database}'
                env = dict(environment, NORTHSTAR_DISABLE_DOTENV='true', XMPP_DOMAIN='localhost',
                    DATABASE_URL=url, MIGRATOR_DATABASE_URL=url,
                    DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT='true',
                    MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT='true',
                    FAST_TOKEN_ALLOW_EPHEMERAL_FOR_DEVELOPMENT='true',
                    DUMMY_SCRAM_ALLOW_EPHEMERAL_FOR_DEVELOPMENT='true',
                    ABUSE_STATE_ALLOW_EPHEMERAL='true', API_CONTROL_ALLOW_EPHEMERAL='true',
                    DIALBACK_ENABLED='false', FEDERATION_ENABLED='false', COMPONENTS_ENABLED='false',
                    WEB_ADMIN_ENABLED='true',
                    TLS_CERT_PATH=str(cert), TLS_KEY_PATH=str(key), PUBLIC_URL='http://localhost:8080',
                    LOG_DIR=str(root / 'logs'), UPLOAD_DIR=str(root / 'uploads'),
                    TEST_LISTENER_ACTIVATION='true', TEST_READINESS_FILE=str(root / 'ready.json'),
                    TEST_READINESS_NONCE=secrets.token_hex(16))
                for name in ('XMPP_BIND', 'XMPPS_BIND', 'HTTP_BIND', 'WEB_ADMIN_BIND', 'METRICS_BIND',
                             'S2S_BIND', 'S2S_TLS_BIND', 'COMPONENT_BIND'):
                    env[name] = '127.0.0.1:0'
                if image:
                    spec = importlib.util.spec_from_file_location('docker_runtime',
                        Path(__file__).with_name('release-docker-runtime.py'))
                    docker = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(docker)
                    migration = docker.Container(image, env, cert, key, log, ['migrate'])
                    try:
                        migration.wait(timeout=120)
                    finally:
                        migration.close()
                else:
                    command([str(binary), 'migrate'], env=env, cwd=package, timeout=120)
                deadline = time.monotonic() + 15
                if image:
                    server = docker.Container(image, env, cert, key, log)
                else:
                    server = subprocess.Popen([str(binary)], env=env, cwd=package,
                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                listeners = None
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise RuntimeError('extracted server exited during startup')
                    try:
                        record = server.record() if image else READINESS.read_record(root / 'ready.json')
                        listeners = READINESS.verify(record,
                                                     env['TEST_READINESS_NONCE'], server.pid)
                        break
                    except FileNotFoundError:
                        time.sleep(.025)
                if listeners is None or time.monotonic() >= deadline:
                    raise RuntimeError('extracted server missed 15-second readiness deadline')
                if any(not value.startswith('127.0.0.1:') for value in listeners.values()):
                    raise RuntimeError('release fixture published a non-loopback listener')
                while True:
                    if server.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError('extracted server did not become healthy within 15 seconds')
                    status, body = READINESS.probe_http_readiness(f'http://{listeners["http"]}/readyz', deadline)
                    if status == 200 and body.strip() == 'ready':
                        break
                    time.sleep(.025)
                if image:
                    server.healthcheck(listeners['http'])
                else:
                    command([str(binary), '--healthcheck', listeners['http']], env=environment, cwd=package, timeout=5)
                for listener, route, filename in [('http', '/', 'web/client.html'),
                        ('web-admin', '/', 'web/index.html'),
                        ('http', '/api/docs/assets/5.32.14/swagger-ui.css', 'third_party/swagger-ui/dist/swagger-ui.css')]:
                    with urllib.request.urlopen('http://' + listeners[listener] + route, timeout=5) as response:
                        actual = response.read(4 * 1024 * 1024)
                        if response.status != 200 or actual != (package / filename).read_bytes():
                            raise RuntimeError('extracted runtime served mismatched static assets')
                if server.poll() is not None:
                    raise RuntimeError('server exited during package verification')
                result = dict(schema=1, commit=manifest['commit'], target=manifest['target'],
                              version=manifest['version'], postgres=version, native_startup=True,
                              migration=True, readiness=True, web_assets=True,
                              elapsed_ms=round((time.monotonic()-started)*1000, 3))
                if image:
                    result.update(target='docker-linux-amd64', image=image)
            except BaseException:
                # Diagnostics contain only this disposable fixture. Redact the
                # fixed test DSN before emitting a bounded tail to the CI log.
                print_fixture_diagnostics(log, root / 'fixture.log')
                raise
            finally:
                try:
                    if image and server is not None:
                        server.close()
                    elif server is not None and server.poll() is None:
                        server.terminate()  # Owned Popen handle; no name/group-wide kill.
                        try:
                            server.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            server.kill()
                            server.wait(timeout=5)
                finally:
                    try:
                        if postgres is not None and postgres.poll() is None:
                            command([tool('pg_ctl'), '-D', str(data), '-m', 'fast', '-w', '-t', '15', 'stop'], timeout=20)
                            postgres.wait(timeout=5)
                    finally:
                        if os.name == 'nt' and postgres is not None:
                            postgres.close()
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--pg-bin', type=Path, required=True)
    parser.add_argument('--openssl', default='openssl')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--image', help='Verify this Linux container through its default entrypoint and UID')
    args = parser.parse_args()
    run(args.package, args.pg_bin.resolve(), args.openssl, args.evidence, args.image)
