#!/usr/bin/env python3
"""Transfer a checked runtime binary between jobs of one exact GitHub run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('runtime_profile', ROOT / 'scripts/check-runtime-test-profile.py')
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
BINARY_LIMIT = 2 * 1024 * 1024 * 1024


def digest(path, limit=BINARY_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('invalid artifact file')
        value = hashlib.sha256()
        while block := stream.read(1024 * 1024):
            value.update(block)
        after = os.fstat(stream.fileno())
        if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('artifact changed during hashing')
        return value.hexdigest()


def source_digest(project):
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=project).split(b'\0')
    value = hashlib.sha256()
    for raw in sorted(path for path in paths if path):
        path = project / os.fsdecode(raw)
        if path.is_symlink() or not path.is_file():
            raise ValueError('unsupported source entry')
        value.update(raw + b'\0')
        # Empty tracked files are valid source inputs.
        value.update(hashlib.sha256(path.read_bytes()).digest())
    return value.hexdigest()


def identity(project, environment):
    required = ['GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_REPOSITORY']
    values = {name: environment.get(name, '') for name in required}
    if (not re.fullmatch('[0-9a-f]{40}', values['GITHUB_SHA'])
            or any(not re.fullmatch('[1-9][0-9]*', values[name]) for name in required[1:3])
            or not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', values['GITHUB_REPOSITORY'])):
        raise ValueError('explicit GitHub run identity required')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=project, text=True).strip()
    if head != values['GITHUB_SHA']:
        raise ValueError('checkout differs from evaluated commit')
    for options in ([], ['--cached']):
        subprocess.run(['git', 'diff', '--quiet', *options, '--'], cwd=project, check=True)
    rustc = subprocess.check_output(['rustc', '--version'], text=True).strip()
    if not rustc.startswith('rustc 1.97.1 '):
        raise ValueError('runtime artifact requires pinned Rust 1.97.1')
    release = platform.freedesktop_os_release()
    return dict(run=values, source_digest=source_digest(project), rustc=rustc,
                platform=[platform.system(), platform.machine(), release['ID'], release['VERSION_ID']])


def validate_manifest(value, expected):
    if (not isinstance(value, dict) or set(value) != {'schema', 'identity', 'profile', 'binary_sha256'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['identity'] != expected
            or value['profile'] != GUARD.EXPECTED_PROFILE
            or any(type(value['profile'].get(k)) is not type(v) for k, v in GUARD.EXPECTED_PROFILE.items())
            or not isinstance(value['binary_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', value['binary_sha256'])):
        raise ValueError('artifact provenance or profile mismatch')


def checked_copy(source, destination, expected_digest):
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.runtime-artifact-', dir=destination.parent)
    os.close(fd)
    try:
        shutil.copyfile(source, name)
        if digest(Path(name)) != expected_digest:
            raise ValueError('copied artifact digest mismatch')
        os.chmod(name, 0o755)
        os.replace(name, destination)
    finally:
        Path(name).unlink(missing_ok=True)


def transfer(mode, project, bundle, binary, build_log=None):
    GUARD.validate_environment(os.environ)
    with (project / 'Cargo.toml').open('rb') as stream:
        GUARD.validate_manifest(tomllib.load(stream))
    current = identity(project, os.environ)
    if bundle.is_symlink() or bundle.resolve() != bundle:
        raise ValueError('artifact directory must not use symlinks')
    if mode == 'pack':
        if not build_log or not os.access(binary, os.X_OK):
            raise ValueError('checked build evidence required')
        GUARD.validate_build_records(GUARD.read_build_records(build_log), binary, project / 'src/main.rs')
        value = dict(schema=1, identity=current, profile=GUARD.EXPECTED_PROFILE, binary_sha256=digest(binary))
        bundle.mkdir(parents=True, exist_ok=True)
        if any(bundle.iterdir()):
            raise ValueError('artifact output must be empty')
        checked_copy(binary, bundle / 'rust-xmpp-server', value['binary_sha256'])
        (bundle / 'manifest.json').write_text(json.dumps(value, sort_keys=True) + '\n')
    else:
        if {p.name for p in bundle.iterdir()} != {'manifest.json', 'rust-xmpp-server'}:
            raise ValueError('incomplete runtime artifact')
        manifest = bundle / 'manifest.json'
        digest(manifest, 16384)
        value = json.loads(manifest.read_text())
        validate_manifest(value, current)
        if digest(bundle / 'rust-xmpp-server') != value['binary_sha256']:
            raise ValueError('runtime binary digest mismatch')
        checked_copy(bundle / 'rust-xmpp-server', binary, value['binary_sha256'])
    print('runtime_artifact=' + mode + '_verified')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['pack', 'restore'])
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--build-log', type=Path)
    args = parser.parse_args()
    try:
        transfer(args.mode, ROOT, args.bundle.absolute(), args.binary.absolute(), args.build_log)
        return 0
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print('runtime_artifact=invalid')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
