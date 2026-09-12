#!/usr/bin/env python3
"""Check real Windows release fixture tools before compiling an application."""
import argparse
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(pg_bin):
    if os.name != 'nt':
        raise RuntimeError('this real fixture regression requires Windows')
    native = load('native_fixture', 'release-native-smoke.py')
    windows = load('windows_postgres', 'release-postgres-windows.py')
    environment = native.fixture_environment(pg_bin)
    tool = lambda name: str(pg_bin / (name + '.exe'))
    with tempfile.TemporaryDirectory(prefix='northstar-release-pg-preflight-') as temporary:
        root = Path(temporary)
        native.prepare_fixture_directory(root, environment)
        password = root / 'password'
        password.write_text('xmpp-test-password\n')
        password.chmod(0o600)
        data = root / 'data'
        with (root / 'fixture.log').open('wb') as log:
            postgres = None
            try:
                subprocess.run([tool('initdb'), '-D', str(data), '--username=xmpp_test',
                    '--auth-local=trust', '--auth-host=scram-sha-256', '--pwfile=' + str(password),
                    '--no-locale', '--encoding=UTF8'], env=environment, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)
                print('Restricted initdb read the private password and initialized the cluster', flush=True)
                with socket.socket() as reservation:
                    reservation.bind(('127.0.0.1', 0))
                    port = reservation.getsockname()[1]
                postgres = windows.WindowsPostgres(tool, data,
                    ['-h', '127.0.0.1', '-p', str(port), '-c', 'unix_socket_directories=',
                     '-c', 'max_connections=32', '-c', 'shared_buffers=16MB', '-c', 'fsync=on'],
                    environment, log)
                connection = dict(environment, PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='xmpp_test',
                                  PGPASSWORD='xmpp-test-password', PGDATABASE='postgres', PGCONNECT_TIMEOUT='2')
                actual = subprocess.check_output([tool('psql'), '-XqAt', '-v', 'ON_ERROR_STOP=1',
                    '-c', 'SHOW data_directory'], env=connection, text=True, timeout=3).strip()
                if Path(actual).resolve() != data.resolve() or postgres.poll() is not None:
                    raise RuntimeError('Windows PostgreSQL is not the owned live cluster')
                print('Restricted PostgreSQL startup and owned data directory verified', flush=True)
            except BaseException:
                native.print_fixture_diagnostics(log, root / 'fixture.log')
                raise
            finally:
                if postgres is not None:
                    try:
                        if postgres.poll() is None:
                            postgres.command(['-m', 'fast', '-w', '-t', '15', 'stop'], 20)
                        if postgres.wait(timeout=5) != 0:
                            raise RuntimeError('owned Windows PostgreSQL did not shut down cleanly')
                    finally:
                        postgres.close()
    print('Windows PostgreSQL fixture preflight PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pg-bin', type=Path, required=True)
    main(parser.parse_args().pg_bin.resolve(strict=True))
