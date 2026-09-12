#!/usr/bin/env python3
"""Check a fresh complete Release download against its exact manifest and SHA."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def verify(directory, version, commit):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('invalid expected download identity')
    assets = {f'northstar-{version}-linux-amd64', f'northstar-{version}-linux-amd64.tar.gz',
              f'northstar-{version}-windows-amd64.exe', f'northstar-{version}-windows-amd64.zip',
              'IMAGE_DIGESTS', 'RELEASE-EVIDENCE.json'}
    if {p.name for p in directory.iterdir()} != assets | {'SHA256SUMS'}:
        raise ValueError('Release download is missing assets or includes unexpected assets')
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Release download must contain regular files only')
    checksums = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]+)', line)
        if not match or match[2] in checksums:
            raise ValueError('invalid or duplicate checksum entry')
        checksums[match[2]] = match[1]
    if set(checksums) != assets:
        raise ValueError('checksum manifest does not cover exactly the Release assets')
    for name, expected in checksums.items():
        with (directory / name).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                raise ValueError('downloaded asset checksum mismatch: ' + name)
    evidence = json.loads((directory / 'RELEASE-EVIDENCE.json').read_text())
    if (evidence.get('commit') != commit or evidence.get('version') != version
            or evidence.get('published_images') is not True):
        raise ValueError('downloaded evidence does not match the release commit')
    images = (directory / 'IMAGE_DIGESTS').read_text().splitlines()
    if len(images) != 3 or sorted(images) != sorted(item['image'] for item in evidence['images']):
        raise ValueError('downloaded image references differ from verified evidence')
    print(json.dumps(dict(download_verified=True, commit=commit, version=version, assets=len(assets) + 1)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    verify(args.directory, args.version, args.commit)
