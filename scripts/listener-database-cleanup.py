#!/usr/bin/env python3
"""Bounded cleanup of driver-recorded fixture databases.

Each psql process is a directly owned child. No name discovery, reconnecting
worker, global process matching, or database deletion without an owner check.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

STOP = None
STATUSES = {'dropped', 'absent', 'owner_mismatch', 'owner_query_failed',
            'drop_failed', 'postcheck_failed', 'cancelled', 'attestation_failed'}
SUCCESS = {'dropped', 'absent'}


class QueryFailed(Exception):
    pass


def stop(signum, _frame):
    global STOP
    STOP = signum


def names_from_input(prefix, data):
    if not re.fullmatch(r'northstar_listener_(?:federation|mix_federation)_[0-9a-f]{16}', prefix):
        raise ValueError('invalid run prefix')
    if len(data) > 8192:
        raise ValueError('oversized cleanup input')
    names = data.decode('ascii').splitlines()
    if not 1 <= len(names) <= 100 or len(set(names)) != len(names):
        raise ValueError('invalid cleanup count')
    for name in names:
        if len(name) > 63 or not re.fullmatch(re.escape(prefix) + r'_r[1-9][0-9]*_p[1-9][0-9]*_[ab]', name):
            raise ValueError('foreign cleanup name')
    return names


def query(sql, port):
    if STOP is not None:
        raise QueryFailed()
    environment = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    environment.update(PGPASSWORD='xmpp-test-password', PGCONNECT_TIMEOUT='5',
                       PGHOSTADDR='127.0.0.1',
                       PGOPTIONS='-c statement_timeout=30000 -c lock_timeout=5000 -c search_path=pg_catalog')
    process = subprocess.Popen(
        ['psql', '-XqAtw', '--host', '127.0.0.1', '--port', str(port),
         '--username', 'xmpp_test', '--dbname', 'postgres',
         '--set', 'ON_ERROR_STOP=1', '--command', sql],
        env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 35
    try:
        while STOP is None and time.monotonic() < deadline:
            try:
                output, _ = process.communicate(timeout=.1)
                if process.returncode != 0 or len(output) > 4096:
                    raise QueryFailed()
                return output.decode('ascii').strip()
            except subprocess.TimeoutExpired:
                pass
        raise QueryFailed()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=2)
        if process.stdout is not None:
            process.stdout.close()


def cleanup_one(name, port):
    phase = 'owner_query_failed'
    try:
        owner = query("SELECT COALESCE((SELECT CASE WHEN pg_catalog.pg_get_userbyid(datdba)='xmpp_test' "
                      "THEN 'owned' ELSE 'foreign' END FROM pg_catalog.pg_database "
                      f"WHERE datname='{name}'),'absent')", port)
        if owner == 'absent':
            return 'absent'
        if owner == 'foreign':
            return 'owner_mismatch'
        if owner != 'owned':
            return phase
        phase = 'drop_failed'
        query(f'DROP DATABASE "{name}" WITH (FORCE)', port)
        phase = 'postcheck_failed'
        exists = query(f"SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname='{name}')", port)
        return 'dropped' if exists == 'f' else phase
    except (QueryFailed, OSError, UnicodeError):
        return 'cancelled' if STOP is not None else phase


def cleanup(names, port, jobs):
    authorized = False
    try:
        authorized = query("SELECT pg_catalog.host(pg_catalog.inet_server_addr())='127.0.0.1' "
                           "AND current_user='xmpp_test' AND EXISTS(SELECT 1 FROM pg_catalog.pg_roles "
                           "WHERE rolname=current_user AND rolcreatedb)", port) == 't'
    except (QueryFailed, OSError, UnicodeError):
        pass
    if not authorized:
        statuses = ['attestation_failed'] * len(names)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            statuses = list(pool.map(lambda name: cleanup_one(name, port), names))
    return {'schema_version': 1, 'results': [dict(name=name, status=status)
            for name, status in zip(names, statuses)]}


def validate_result(value, names):
    if not isinstance(value, dict) or set(value) != {'schema_version', 'results'} or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('invalid cleanup result')
    rows = value['results']
    if not isinstance(rows, list) or len(rows) != len(names):
        raise ValueError('incomplete cleanup result')
    for row, name in zip(rows, names):
        if not isinstance(row, dict) or set(row) != {'name', 'status'} or row['name'] != name or not isinstance(row['status'], str) or row['status'] not in STATUSES:
            raise ValueError('invalid cleanup record')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--port', type=int, default=5432)
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=1)
    parser.add_argument('--verify-result', type=Path)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('invalid loopback port')
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stop)
    try:
        names = names_from_input(args.prefix, sys.stdin.buffer.read(8193))
        if args.verify_result:
            with args.verify_result.open('rb') as stream:
                data = stream.read(16385)
            if len(data) > 16384:
                raise ValueError('oversized cleanup result')
            rows = validate_result(json.loads(data), names)
            for row in rows:
                print(row['name'] + '\t' + row['status'])
            return 0
        value = cleanup(names, args.port, args.jobs)
        print(json.dumps(value, separators=(',', ':')), flush=True)
        return 0 if all(row['status'] in SUCCESS for row in value['results']) else 1
    except (ValueError, OSError, UnicodeError):
        print('listener_cleanup_error=invalid_input_or_result', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
