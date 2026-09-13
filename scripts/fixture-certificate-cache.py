#!/usr/bin/env python3
"""Reuse one pair's private certificates only inside its owning stress run."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time


def names(fixture):
    if fixture == 'federation':
        return {'federation-ca.' + ext for ext in ('key', 'crt', 'srl')} | {
            f'federation-{side}.{ext}' for side in ('a', 'b')
            for ext in ('key', 'csr', 'crt')} | {
            f'federation-{side}-leaf.crt' for side in ('a', 'b')} | {
            'federation-evil.' + ext for ext in ('key', 'csr', 'crt')}
    return {'ca.' + ext for ext in ('key', 'crt', 'srl')} | {
        f'{side}.{ext}' for side in ('a', 'b') for ext in ('key', 'csr', 'crt')}


def directory(path, private=False):
    info = path.lstat()
    if (not path.is_absolute() or path.resolve() != path or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or info.st_mode & 0o022
            or (private and stat.S_IMODE(info.st_mode) != 0o700)):
        raise ValueError('invalid certificate directory')


def read(path, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 32768
                or (private and stat.S_IMODE(info.st_mode) != 0o600)):
            raise ValueError('invalid certificate file')
        data = stream.read(32769)
        if len(data) != info.st_size:
            raise ValueError('certificate changed during read')
        return data


def write(path, data):
    with path.open('xb') as stream:
        path.chmod(0o600)
        stream.write(data)


def transfer(mode, cache, output, fixture, scope):
    if not re.fullmatch(r'northstar_listener_' + fixture.replace('-', '_') + r'_[0-9a-f]{16}:[1-9][0-9]*', scope):
        raise ValueError('invalid certificate scope')
    directory(cache, True)
    directory(cache.parent, True)
    directory(output)
    published = cache / 'complete'
    expected = names(fixture)
    if mode == 'restore':
        if not published.exists() and not published.is_symlink():
            print('listener_certificate_cache=miss')
            return 3
        directory(published, True)
        if {p.name for p in published.iterdir()} != expected | {'manifest.json'}:
            raise ValueError('incomplete certificate cache')
        manifest = json.loads(read(published / 'manifest.json', True))
        if (not isinstance(manifest, dict) or set(manifest) != {'schema', 'scope', 'expires', 'hashes'}
                or type(manifest['schema']) is not int or manifest['schema'] != 1
                or manifest['scope'] != scope or type(manifest['expires']) is not int
                or manifest['expires'] <= time.time() or not isinstance(manifest['hashes'], dict)
                or set(manifest['hashes']) != expected):
            raise ValueError('foreign or expired certificate cache')
        data = {name: read(published / name, True) for name in expected}
        if any(hashlib.sha256(value).hexdigest() != manifest['hashes'][name] for name, value in data.items()):
            raise ValueError('changed certificate cache')
        if any(output.iterdir()):
            raise ValueError('certificate destination is not empty')
        for name, value in data.items():
            write(output / name, value)
        print('listener_certificate_cache=hit')
        return 0
    if published.exists() or published.is_symlink():
        raise ValueError('certificate cache already published')
    if {p.name for p in output.iterdir()} != expected:
        raise ValueError('incomplete generated certificates')
    data = {name: read(output / name, name.endswith('.key')) for name in expected}
    expires = []
    for name in sorted(expected):
        if name.endswith('.crt'):
            line = subprocess.check_output(['openssl', 'x509', '-in', str(output / name),
                '-noout', '-enddate'], stderr=subprocess.DEVNULL, timeout=5).decode('ascii').strip()
            value = datetime.datetime.strptime(line, 'notAfter=%b %d %H:%M:%S %Y GMT')
            expires.append(int(value.replace(tzinfo=datetime.timezone.utc).timestamp()))
    if min(expires) <= time.time():
        raise ValueError('generated certificate expired')
    with tempfile.TemporaryDirectory(prefix='.publishing-', dir=cache) as temporary:
        stage = Path(temporary) / 'complete'
        stage.mkdir(mode=0o700)
        for name, value in data.items():
            write(stage / name, value)
        write(stage / 'manifest.json', json.dumps(dict(schema=1, scope=scope, expires=min(expires),
            hashes={name: hashlib.sha256(value).hexdigest() for name, value in data.items()})).encode())
        # Each pair has one worker per sequential round; publication is once.
        stage.rename(published)
    print('listener_certificate_cache=saved')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['restore', 'save'])
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixture', choices=['federation', 'mix-federation'], required=True)
    parser.add_argument('--scope', required=True)
    args = parser.parse_args()
    try:
        return transfer(args.mode, args.cache, args.output, args.fixture, args.scope)
    except (OSError, ValueError, subprocess.SubprocessError):
        print('listener_certificate_cache=invalid')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
