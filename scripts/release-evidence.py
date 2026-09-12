#!/usr/bin/env python3
"""Assemble successful native package and container proofs for one release run."""
import argparse
import json
from pathlib import Path
import re


def read_record(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError('invalid release evidence file')
    return json.loads(path.read_text())


def assemble(directory, output, commit, version, run_id, attempt, image_directory, published):
    if (not re.fullmatch('[0-9a-f]{40}', commit) or not re.fullmatch(r'\d+\.\d+\.\d+', version)
            or not re.fullmatch('[1-9][0-9]*', run_id) or not re.fullmatch('[1-9][0-9]*', attempt)):
        raise ValueError('invalid release evidence identity')
    targets = ('linux-amd64', 'windows-amd64')
    if {path.name for path in directory.iterdir()} != {target + '.json' for target in targets}:
        raise ValueError('native package evidence is missing or unexpected')
    records = []
    for target in targets:
        path = directory / (target + '.json')
        value = read_record(path)
        if (not isinstance(value, dict) or value.get('schema') != 1
                or (value.get('commit'), value.get('version'), value.get('target')) != (commit, version, target)
                or any(value.get(name) is not True for name in
                       ('native_startup', 'migration', 'readiness', 'web_assets'))):
            raise ValueError('native package did not pass required validation for this release')
        records.append(value)
    names = ('northstar', 'northstar-backup', 'northstar-database-grants')
    if {path.name for path in image_directory.iterdir()} != {name + '.json' for name in (*names, 'container-runtime')}:
        raise ValueError('container evidence is missing or unexpected')
    images = []
    for name in names:
        value = read_record(image_directory / (name + '.json'))
        expected_ref = (r'ghcr\.io/[a-z0-9._-]+/' + name + r'@sha256:[0-9a-f]{64}' if published
                        else 'northstar-release-test:' + commit)
        if (not isinstance(value, dict) or value.get('schema') != 1
                or (value.get('commit'), value.get('version'), value.get('name')) != (commit, version, name)
                or value.get('platform') != 'linux/amd64' or value.get('user') != '10001:10001'
                or not re.fullmatch(expected_ref, value.get('image', ''))
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', value.get('image_id', ''))
                or any(value.get(key) is not True for key in ('labels', 'entrypoint', 'runtime_files'))):
            raise ValueError('image did not pass required validation for this release')
        images.append(value)
    runtime = read_record(image_directory / 'container-runtime.json')
    if (not isinstance(runtime, dict) or runtime.get('schema') != 1
            or (runtime.get('commit'), runtime.get('version'), runtime.get('target')) !=
               (commit, version, 'docker-linux-amd64') or runtime.get('image') != images[0]['image']
            or any(runtime.get(key) is not True for key in ('native_startup', 'migration', 'readiness', 'web_assets'))):
        raise ValueError('container runtime did not pass required validation for this release')
    result = dict(schema=1, commit=commit, version=version, workflow_run_id=int(run_id),
                  workflow_run_attempt=int(attempt), fixture_profile='isolated-loopback-development',
                  native_packages=records, images=images, container_runtime=runtime,
                  published_images=published)
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image-directory', type=Path, required=True)
    parser.add_argument('--published', choices=('true', 'false'), required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--attempt', required=True)
    args = parser.parse_args()
    assemble(args.directory, args.output, args.commit, args.version, args.run_id, args.attempt,
             args.image_directory, args.published == 'true')
