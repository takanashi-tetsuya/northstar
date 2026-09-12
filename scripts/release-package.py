#!/usr/bin/env python3
"""Build and independently unpack a complete, identified native distribution."""
import argparse
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import time
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {'linux-amd64': 'xmpp-server', 'windows-amd64': 'xmpp-server.exe'}
SINGLE_FILES = {'.env.example', '.env.development.example', 'README.md', 'README.zh-TW.md',
                'LICENSE', 'THIRD_PARTY_NOTICES.md', 'docs/INSTALL.md',
                'third_party/swagger-ui/LICENSE', 'third_party/swagger-ui/NOTICE'}
PREFIXES = ('web/', 'third_party/swagger-ui/dist/')
MANIFEST = 'PACKAGE-MANIFEST.json'
MAX_TOTAL = 2 * 1024 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def identifier(version, commit, target):
    if (not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version)
            or not re.fullmatch(r'[0-9a-f]{40}', commit) or target not in TARGETS):
        raise ValueError('invalid release identity')


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_TOTAL:
        raise ValueError('package input must be a bounded regular file')
    return path.read_bytes()


def archive_names(version, target):
    base = f'northstar-{version}-{target}'
    return (base + ('.zip' if target == 'windows-amd64' else '.tar.gz'),
            base + ('.exe' if target == 'windows-amd64' else ''))


def pack(project, binary, output, version, commit, target, epoch):
    identifier(version, commit, target)
    if not 315532800 <= epoch <= 4354819199:
        raise ValueError('release timestamp is outside the portable ZIP range')
    with (project / 'Cargo.toml').open('rb') as stream:
        if tomllib.load(stream)['package']['version'] != version:
            raise ValueError('package version differs from Cargo.toml')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=project, text=True).strip()
    if head != commit:
        raise ValueError('source checkout differs from release commit')
    for flags in ([], ['--cached']):
        subprocess.run(['git', 'diff', '--quiet', *flags, '--'], cwd=project, check=True)
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=project).decode().split('\0')
    selected = {name for name in tracked if name in SINGLE_FILES or name.startswith(PREFIXES)}
    if not SINGLE_FILES <= selected:
        raise ValueError('required distribution source is not tracked')
    files = {name: regular(project / name) for name in sorted(selected)}
    files[TARGETS[target]] = regular(binary)
    magic = b'MZ' if target == 'windows-amd64' else b'\x7fELF'
    if not files[TARGETS[target]].startswith(magic):
        raise ValueError('binary format differs from package target')
    if sum(map(len, files.values())) > MAX_TOTAL:
        raise ValueError('package exceeds size bound')
    manifest = dict(schema=1, version=version, commit=commit, target=target,
                    files={name: dict(sha256=sha256(data), size=len(data)) for name, data in files.items()})
    files[MANIFEST] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    output.mkdir(parents=True, exist_ok=True)
    archive_name, raw_name = archive_names(version, target)
    archive = output / archive_name
    raw = output / raw_name
    if archive.exists() or raw.exists():
        raise ValueError('refusing to overwrite existing release assets')
    raw.write_bytes(files[TARGETS[target]])
    raw.chmod(0o755)
    if target == 'windows-amd64':
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as zipped:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(name, time.gmtime(epoch)[:6])
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | (0o755 if name == TARGETS[target] else 0o644)) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zipped.writestr(info, data)
    else:
        with archive.open('xb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mtime = len(data), epoch
                    info.mode = 0o755 if name == TARGETS[target] else 0o644
                    tar.addfile(info, io.BytesIO(data))
    print(json.dumps(dict(package=str(archive), sha256=sha256(archive.read_bytes()), commit=commit)))
    return archive, raw


@contextlib.contextmanager
def entries(archive):
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as opened:
            members = opened.infolist()
            yield [(m.filename, m.file_size, not m.is_dir() and
                    stat.S_IFMT(m.external_attr >> 16) in (0, stat.S_IFREG),
                    lambda m=m: opened.read(m)) for m in members]
    else:
        with tarfile.open(archive, 'r:gz') as opened:
            yield [(m.name, m.size, m.isfile(), lambda m=m: opened.extractfile(m).read())
                   for m in opened.getmembers()]


def unpack(archive, raw, destination, version, commit, target):
    identifier(version, commit, target)
    if destination.exists():
        raise ValueError('verification destination must be new')
    payload = {}
    total = 0
    with entries(archive) as members:
        if not 1 <= len(members) <= 10000:
            raise ValueError('invalid archive entry count')
        for name, size, is_file, read in members:
            path = PurePosixPath(name)
            if (not is_file or path.is_absolute() or path.as_posix() != name
                    or any(part in ('', '.', '..') or ':' in part or '\\' in part for part in path.parts)
                    or name in payload or type(size) is not int or not 0 <= size <= MAX_TOTAL):
                raise ValueError('unsafe or duplicate archive member')
            total += size
            if total > MAX_TOTAL:
                raise ValueError('archive exceeds size bound')
            data = read()
            if len(data) != size:
                raise ValueError('archive size mismatch')
            payload[name] = data
    document = payload.pop(MANIFEST, b'')
    if len(document) > 4 * 1024 * 1024:
        raise ValueError('package manifest exceeds size bound')
    manifest = json.loads(document)
    if (not isinstance(manifest, dict) or set(manifest) != {'schema', 'version', 'commit', 'target', 'files'}
            or type(manifest['schema']) is not int or manifest['schema'] != 1
            or (manifest['version'], manifest['commit'], manifest['target']) != (version, commit, target)
            or not isinstance(manifest['files'], dict) or set(manifest['files']) != set(payload)):
        raise ValueError('package identity or membership mismatch')
    required = SINGLE_FILES | {TARGETS[target], 'web/index.html', 'third_party/swagger-ui/dist/swagger-ui.css'}
    if not required <= set(payload):
        raise ValueError('required runtime resource is missing')
    for name, data in payload.items():
        if manifest['files'][name] != dict(sha256=sha256(data), size=len(data)):
            raise ValueError('package content digest mismatch')
    if payload[TARGETS[target]] != regular(raw):
        raise ValueError('raw binary differs from archive binary')
    destination.mkdir(parents=True)
    try:
        for name, data in (payload | {MANIFEST: document}).items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if name == TARGETS[target] else 0o644)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['pack', 'verify'])
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--epoch', type=int)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    if args.mode == 'pack':
        pack(ROOT, args.binary, args.output, args.version, args.commit, args.target, args.epoch)
    else:
        unpack(args.archive, args.binary, args.output, args.version, args.commit, args.target)
        binary = (args.output / TARGETS[args.target]).resolve()
        result = subprocess.run([str(binary), '--version'], cwd=args.output, capture_output=True,
                                text=True, check=True, timeout=15)
        if result.stdout.strip() != f'xmpp-server {args.version}':
            raise ValueError('extracted binary version mismatch')
        print(json.dumps(dict(package_verified=True, commit=args.commit, target=args.target,
                              archive_sha256=sha256(args.archive.read_bytes()),
                              binary_sha256=sha256(regular(binary)))))


if __name__ == '__main__':
    main()
