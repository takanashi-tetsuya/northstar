#!/usr/bin/env python3
"""Exercise migration admission and immutable upgrade history with a real binary.

Runs an owned PostgreSQL 15+ cluster on a fresh loopback TCP port, with Unix
sockets disabled. No inherited application credentials or external DSN is used.

Usage:
  python3 scripts/test-migration-preflight.py --binary target/debug/rust-xmpp-server \
      --pg-bin /path/to/postgresql/17/bin --evidence /tmp/migration-preflight.json
"""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'migration_ledger', ROOT / 'scripts/generate-database-migration-ledger.py')
LEDGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER)

# Capture authority and application DDL, not activity/statistics catalogs that
# legitimately change when a connection opens. A rejected migration may not
# create its ledger, change ownership/ACLs, or leave partially installed DDL.
CATALOG_SNAPSHOT = """
SELECT jsonb_build_object(
  'schemas', (SELECT jsonb_agg(to_jsonb(s) ORDER BY s.oid) FROM
    (SELECT oid,nspname,nspowner,nspacl FROM pg_catalog.pg_namespace
      WHERE nspname !~ '^pg_' AND nspname<>'information_schema') s),
  'relations', (SELECT jsonb_agg(to_jsonb(c) ORDER BY c.oid) FROM
    (SELECT c.oid,c.relname,c.relnamespace,c.relowner,c.relacl
       FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema') c),
  'routines', (SELECT jsonb_agg(to_jsonb(p) ORDER BY p.oid) FROM
    (SELECT p.oid,p.proname,p.pronamespace,p.proowner,p.proacl,p.proconfig
       FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema') p),
  'defaults', (SELECT jsonb_agg(to_jsonb(d) ORDER BY d.oid) FROM pg_catalog.pg_default_acl d),
  'database_acl', (SELECT datacl FROM pg_catalog.pg_database WHERE datname=current_database())
)::text AS snapshot;
"""


def quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'


def quote_literal(value):
    return "'" + value.replace("'", "''") + "'"


def clean_environment():
    allowed = {'PATH', 'HOME', 'LD_LIBRARY_PATH', 'LANG', 'LC_ALL', 'TMPDIR'}
    return {key: value for key, value in os.environ.items() if key in allowed}


def run(binary, pg_bin, evidence):
    if hasattr(os, 'getuid') and os.getuid() == 0:
        raise RuntimeError('run this private PostgreSQL fixture as an ordinary user')
    binary = binary.resolve(strict=True)
    if pg_bin is None:
        pg_bin = Path(subprocess.check_output(
            ['pg_config', '--bindir'], text=True, timeout=5).strip())
    pg_bin = pg_bin.resolve(strict=True)
    evidence = evidence.resolve()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    logs = Path(tempfile.mkdtemp(prefix=evidence.stem + '-logs-', dir=evidence.parent))
    environment = clean_environment()
    tool = lambda name: str(pg_bin / name)
    expected = LEDGER.migration_rows()
    cases = []
    result = {'schema': 1, 'status': 'running', 'binary': str(binary),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'logs': str(logs), 'cases': cases, 'postgres_stopped': False,
              'fallback_kill': False, 'postgres_exit_code': None}

    with tempfile.TemporaryDirectory(prefix='northstar-migration-preflight-') as temporary:
        root = Path(temporary)
        postgres = None
        postgres_log = None
        sequence = 0
        primary_error = None

        def command(label, arguments, *, env=environment, stdin=None, timeout=30, success=True):
            nonlocal sequence
            sequence += 1
            process = subprocess.run(arguments, env=env, cwd=root, input=stdin,
                                     capture_output=True, text=True, timeout=timeout)
            log = logs / f'{sequence:03d}-{label}.log'
            log.write_text(process.stdout + process.stderr)
            if success and process.returncode != 0:
                raise AssertionError(f'{label} exited {process.returncode}; see {log}')
            return process

        def sql(label, statement, *, database='migration_fresh', admin=False, csv_output=False):
            env = dict(pg_environment, PGDATABASE=database)
            if not admin:
                env.update(PGUSER='migration_owner', PGPASSWORD='fixture-owner-password')
            options = ['--csv'] if csv_output else ['-At']
            return command(label, [tool('psql'), '-Xq', '-v', 'ON_ERROR_STOP=1', *options],
                           env=env, stdin=statement).stdout.strip()

        def migrate(label, *, database='migration_fresh', schema='public', rejected=None):
            # Escape whitespace for PostgreSQL's options parser independently
            # of URL encoding. Quoted identifiers also cover mixed-case names.
            path = quote_identifier(schema).replace(' ', r'\ ')
            query = urllib.parse.urlencode({'options': '-csearch_path=' + path})
            url = f'postgres://migration_owner:fixture-owner-password@127.0.0.1:{port}/{database}?{query}'
            env = dict(environment, NORTHSTAR_DISABLE_DOTENV='true',
                       XMPP_DOMAIN='localhost', MIGRATOR_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT='true',
                       MIGRATOR_DATABASE_URL=url)
            before = sql(label + '-catalog-before', CATALOG_SNAPSHOT, database=database)
            process = command(label, [str(binary), 'migrate'], env=env, timeout=120, success=rejected is None)
            if rejected is not None:
                if process.returncode == 0 or rejected not in process.stdout + process.stderr:
                    raise AssertionError(f'{label} did not reject with the required diagnostic: {rejected}')
                after = sql(label + '-catalog-after', CATALOG_SNAPSHOT, database=database)
                if before != after:
                    raise AssertionError(f'{label} changed the catalog before rejecting migration')
            case = {'case': label, 'passed': True, 'expected_rejection': rejected}
            if rejected is not None:
                case['catalog_unchanged'] = True
            cases.append(case)

        def bootstrap(database):
            # The documented local bootstrap is deliberately explicit and
            # performed by the unprivileged database owner, never by migrate.
            sql('bootstrap-' + database, f"""
              BEGIN;
              ALTER SCHEMA public OWNER TO CURRENT_USER;
              REVOKE ALL ON DATABASE {quote_identifier(database)} FROM PUBLIC;
              REVOKE ALL ON SCHEMA public FROM PUBLIC;
              ALTER DEFAULT PRIVILEGES REVOKE ALL ON FUNCTIONS FROM PUBLIC;
              ALTER DEFAULT PRIVILEGES REVOKE ALL ON TYPES FROM PUBLIC;
              COMMIT;
            """, database=database)

        def ledger(database, schema='public'):
            output = sql('read-ledger-' + database, f"""
              SELECT version,description,success,encode(checksum,'hex') AS checksum,
                     installed_on,execution_time
                FROM {quote_identifier(schema)}._sqlx_migrations ORDER BY version;
            """, database=database, csv_output=True)
            return list(csv.DictReader(io.StringIO(output)))

        def attest_ledger(actual):
            rows = [(int(row['version']), row['description'], row['checksum']) for row in actual]
            if rows != expected or any(row['success'] != 't' for row in actual):
                raise AssertionError('the applied ledger differs from immutable source migration bytes')

        try:
            version = command('postgres-version', [tool('postgres'), '--version']).stdout.strip()
            major = re.match(r'postgres \(PostgreSQL\) (\d+)\.', version)
            if major is None or int(major.group(1)) < 15:
                raise RuntimeError('migration preflight regression requires PostgreSQL 15 or newer')
            result['postgres'] = version
            password = root / 'password'
            password.write_text('fixture-admin-password\n')
            password.chmod(0o600)
            command('initdb', [tool('initdb'), '-D', str(root / 'data'), '-U', 'migration_admin',
                              '--pwfile=' + str(password), '--auth-host=scram-sha-256',
                              '--auth-local=reject', '--no-locale', '--encoding=UTF8'])
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            postgres_log = (logs / 'postgres.log').open('w')
            postgres = subprocess.Popen([tool('postgres'), '-D', str(root / 'data'),
                '-h', '127.0.0.1', '-p', str(port), '-c', 'unix_socket_directories=',
                '-c', 'max_connections=20', '-c', 'shared_buffers=16MB'], env=environment,
                cwd=root, stdin=subprocess.DEVNULL, stdout=postgres_log, stderr=subprocess.STDOUT)
            pg_environment = dict(environment, PGHOST='127.0.0.1', PGPORT=str(port),
                                  PGUSER='migration_admin', PGPASSWORD='fixture-admin-password',
                                  PGDATABASE='postgres', PGCONNECT_TIMEOUT='3')
            deadline = time.monotonic() + 20
            while True:
                if postgres.poll() is not None:
                    raise RuntimeError('owned PostgreSQL exited during startup')
                probe = subprocess.run([tool('pg_isready'), '-q'], env=pg_environment, timeout=5)
                if probe.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('owned PostgreSQL missed its startup deadline')
                time.sleep(.1)
            directory = sql('verify-owned-server', 'SHOW data_directory;', database='postgres', admin=True)
            if Path(directory).resolve() != (root / 'data').resolve():
                raise RuntimeError('loopback PostgreSQL is not the owned fixture')
            sql('create-fixture-roles-and-databases', """
              CREATE ROLE migration_owner LOGIN PASSWORD 'fixture-owner-password'
                NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
              CREATE ROLE migration_foreign NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                NOINHERIT NOREPLICATION NOBYPASSRLS;
              CREATE DATABASE migration_fresh OWNER migration_owner TEMPLATE template0 ENCODING 'UTF8';
              CREATE DATABASE migration_historical OWNER migration_owner TEMPLATE template0 ENCODING 'UTF8';
            """, database='postgres', admin=True)
            authority = sql('verify-initial-authority', """
              SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls),
                     current_user=session_user,
                     datdba=role.oid,
                     pg_get_userbyid(namespace.nspowner)='pg_database_owner',
                     has_schema_privilege(current_user,namespace.oid,'CREATE')
                FROM pg_roles role JOIN pg_database database ON datname=current_database()
                JOIN pg_namespace namespace ON nspname='public'
               WHERE rolname=current_user;
            """)
            if authority != 't|t|t|t|t':
                raise AssertionError(f'fixture did not establish the real PostgreSQL 15+ owner case: {authority}')
            migrate('default-public-rejected-before-ddl', rejected='directly owned by the migration login')
            sql('create-foreign-schema', """
              CREATE SCHEMA foreign_schema AUTHORIZATION migration_foreign;
              GRANT USAGE, CREATE ON SCHEMA foreign_schema TO migration_owner;
            """, admin=True)
            migrate('foreign-schema-create-is-insufficient', schema='foreign_schema',
                    rejected='directly owned by the migration login')
            for schema in ('pg_catalog', 'information_schema', 'absent_schema'):
                migrate('invalid-schema-' + schema, schema=schema,
                        rejected='existing non-system application schema')
            if sql('no-ledger-after-rejections',
                   "SELECT count(*) FROM pg_class WHERE relname='_sqlx_migrations';") != '0':
                raise AssertionError('a rejected migration created the SQLx ledger')
            bootstrap('migration_fresh')
            migrate('explicit-non-superuser-bootstrap')
            first = ledger('migration_fresh')
            attest_ledger(first)
            migrate('repeat-is-idempotent')
            if ledger('migration_fresh') != first:
                raise AssertionError('repeat migration rewrote applied ledger rows')
            cases.append({'case': 'fresh-and-repeat-exact-source-ledger', 'passed': True,
                          'migration_count': len(expected), 'max_version': expected[-1][0]})
            sql('create-quoted-owned-schema', 'CREATE SCHEMA "Owner only schema" AUTHORIZATION CURRENT_USER;')
            migrate('quoted-owned-schema', schema='Owner only schema')
            attest_ledger(ledger('migration_fresh', 'Owner only schema'))

            # Replay the genuine pre-0114 chain, including no-transaction
            # migrations. Record only migrations actually executed; never
            # apply the full chain and delete rows to manufacture a baseline.
            sql('create-historical-ledger', """
              CREATE TABLE _sqlx_migrations (
                version BIGINT PRIMARY KEY, description TEXT NOT NULL,
                installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(), success BOOLEAN NOT NULL,
                checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL
              );
            """, database='migration_historical')
            for version, description, checksum in expected:
                if version > 113:
                    break
                candidates = list((ROOT / 'migrations').glob(f'{version:04d}_*.sql'))
                if len(candidates) != 1:
                    raise AssertionError(f'cannot resolve immutable migration {version}')
                migration = candidates[0].read_text()
                record = ('INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) '
                          f'VALUES({version},{quote_literal(description)},TRUE,decode({quote_literal(checksum)},\'hex\'),0);')
                if migration.startswith('-- no-transaction'):
                    sql(f'historical-{version:04d}', migration, database='migration_historical')
                    sql(f'historical-ledger-{version:04d}', record, database='migration_historical')
                else:
                    sql(f'historical-{version:04d}', 'BEGIN;\n' + migration + '\n' + record + '\nCOMMIT;',
                        database='migration_historical')
            historical = ledger('migration_historical')
            if len(historical) != len([row for row in expected if row[0] <= 113]):
                raise AssertionError('historical fixture has the wrong migration count')
            migrate('historical-owner-rejection-preserves-catalog', database='migration_historical',
                    rejected='directly owned by the migration login')
            if ledger('migration_historical') != historical:
                raise AssertionError('preflight rewrote historical ledger rows')
            bootstrap('migration_historical')
            migrate('historical-owner-bootstrap-recovery', database='migration_historical')
            recovered = ledger('migration_historical')
            attest_ledger(recovered)
            if recovered[:len(historical)] != historical:
                raise AssertionError('upgrade rewrote previously applied migration rows')
            migrate('historical-repeat-is-idempotent', database='migration_historical')
            if ledger('migration_historical') != recovered:
                raise AssertionError('repeated recovery rewrote the ledger')
            cases.append({'case': 'historical-checksums-and-ledger-preserved', 'passed': True,
                          'historical_version': 113, 'historical_count': len(historical)})
            result['status'] = 'passed'
        except BaseException as error:
            primary_error = error
            result['status'] = 'failed'
            result['error'] = str(error)
            raise
        finally:
            cleanup_error = None
            try:
                if postgres is not None and postgres.poll() is None:
                    command('stop-owned-postgres', [tool('pg_ctl'), '-D', str(root / 'data'),
                        '-m', 'fast', '-w', '-t', '15', 'stop'], timeout=20)
                    postgres.wait(timeout=5)
            except BaseException as error:
                cleanup_error = error
            if postgres is not None and postgres.poll() is None:
                # Only our owned process handle is eligible for fallback.
                result['fallback_kill'] = True
                try:
                    postgres.kill()
                    postgres.wait(timeout=5)
                except BaseException as error:
                    cleanup_error = cleanup_error or error
            exit_code = postgres.poll() if postgres is not None else None
            result['postgres_exit_code'] = exit_code
            result['postgres_stopped'] = postgres is not None and exit_code is not None
            if postgres is not None and exit_code != 0:
                cleanup_error = cleanup_error or RuntimeError(
                    f'owned PostgreSQL did not exit successfully: {exit_code}')
            if cleanup_error is not None:
                result['status'] = 'failed'
                result['cleanup_error'] = str(cleanup_error)
            if postgres_log is not None:
                postgres_log.close()
            evidence.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
            # Cleanup is authoritative, but never hide the original failure.
            if cleanup_error is not None and primary_error is None:
                raise cleanup_error
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--pg-bin', type=Path, help='PostgreSQL server tools directory; defaults to pg_config --bindir')
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary, args.pg_bin, args.evidence)
