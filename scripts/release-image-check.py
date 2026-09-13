#!/usr/bin/env python3
"""Verify the loaded exact-commit release image through its real container user."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def verify(image, name, version, commit, evidence):
    if (not re.fullmatch('[0-9a-f]{40}', commit) or not re.fullmatch(r'\d+\.\d+\.\d+', version)
            or name not in {'northstar', 'northstar-backup', 'northstar-database-grants'}
            or not re.fullmatch(r'(?:ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}|northstar-release-test:[0-9a-f]{40})', image)):
        raise ValueError('invalid release image identity')
    result = subprocess.check_output(['docker', 'image', 'inspect', image], text=True, timeout=15)
    items = json.loads(result)
    if len(items) != 1:
        raise ValueError('expected one release image')
    item = items[0]
    labels = item['Config'].get('Labels', {})
    expected = {'org.opencontainers.image.revision': commit, 'org.opencontainers.image.version': version,
                'org.opencontainers.image.source': 'https://github.com/takanashi-tetsuya/northstar',
                'org.opencontainers.image.licenses': 'AGPL-3.0-only'}
    if (item['Os'] != 'linux' or item['Architecture'] != 'amd64' or item['Config']['User'] != '10001:10001'
            or any(labels.get(key) != value for key, value in expected.items())):
        raise ValueError('release image platform, labels or default user differ')
    entrypoints = {'northstar': ['/usr/local/bin/northstar-entrypoint'],
        'northstar-backup': ['bash', '/opt/northstar/backup.sh'],
        'northstar-database-grants': ['bash', '/workspace/scripts/reconcile-database-grants.sh']}
    if item['Config']['Entrypoint'] != entrypoints[name]:
        raise ValueError('release image entrypoint differs')
    check = '''set -eu
test "$(id -u):$(id -g)" = 10001:10001
test -r /usr/share/licenses/northstar/LICENSE
test -r /usr/share/licenses/northstar/THIRD_PARTY_NOTICES.md
'''
    if name == 'northstar':
        if item['Config'].get('Healthcheck', {}).get('Test') != [
                'CMD', '/usr/local/bin/xmpp-server', '--healthcheck', '127.0.0.1:8080']:
            raise ValueError('release image health check differs')
        check += '''test -r /app/web/client.html
test -r /app/web/index.html
test -r /app/third_party/swagger-ui/dist/swagger-ui.css
test -w /data/uploads
test -w /data/logs
'''
        actual = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', image,
            '/usr/local/bin/xmpp-server', '--version'], text=True, timeout=15).strip()
        if actual != f'xmpp-server {version}':
            raise ValueError('release image executable version differs')
    elif name == 'northstar-backup':
        check += '''for tool in age bash openssl pg_dump pg_restore python3; do command -v "$tool" >/dev/null; done
test -x /opt/northstar/backup.sh
test -x /opt/northstar/restore-backup.sh
test -x /opt/northstar/verify-backup.sh
'''
    else:
        check += '''for tool in bash psql python3; do command -v "$tool" >/dev/null; done
test -x /workspace/scripts/reconcile-database-grants.sh
test -r /workspace/deploy/postgres-init/lib/reconcile-northstar-grants.sql
'''
    subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'sh', image, '-c', check],
                   check=True, timeout=20)
    value = dict(schema=1, name=name, version=version, commit=commit, image=image,
                 image_id=item['Id'], platform='linux/amd64', user='10001:10001',
                 labels=True, entrypoint=True, runtime_files=True)
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    print(json.dumps(value))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'name', 'version', 'commit'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    verify(args.image, args.name, args.version, args.commit, args.evidence)
