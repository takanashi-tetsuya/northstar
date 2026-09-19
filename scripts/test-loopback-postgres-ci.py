#!/usr/bin/env python3
"""Check fixture resource settings and failed-start cleanup without Docker."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'scripts/loopback-postgres-ci.sh'
DOCKER = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
root = Path(os.environ['STUB_ROOT'])
with (root / 'calls.jsonl').open('a') as stream:
    stream.write(json.dumps(args) + '\n')
if args[:2] == ['container', 'inspect']:
    sys.exit(0 if os.environ.get('STUB_EXISTING') == 'true' else 1)
if args[0] == 'run':
    (root / 'shares').write_text(args[args.index('--cpu-shares') + 1])
    print('fixture-container')
elif args[:3] == ['inspect', '--format', '{{.HostConfig.CpuShares}}']:
    print(os.environ.get('STUB_APPLIED', (root / 'shares').read_text()))
elif args[0] == 'exec' and 'pg_isready' in args:
    pass
elif args[0] == 'exec' and 'psql' in args:
    print('127.0.0.1')
elif args[0] in {'logs', 'rm'}:
    pass
else:
    sys.exit('unexpected Docker command: ' + repr(args))
'''


class LoopbackPostgresTests(unittest.TestCase):
    def invoke(self, shares=None, **overrides):
        with tempfile.TemporaryDirectory(prefix='northstar-loopback-test-') as directory:
            root = Path(directory)
            docker = root / 'docker'
            docker.write_text(DOCKER)
            docker.chmod(0o755)
            environment = {key: value for key, value in os.environ.items()
                           if not key.startswith('NORTHSTAR_') and key != 'GITHUB_ENV'}
            environment.update(PATH=f'{root}:/usr/bin:/bin', CI='true',
                               GITHUB_ACTIONS='true', STUB_ROOT=str(root))
            environment.update(overrides)
            if shares is not None:
                environment['NORTHSTAR_LOOPBACK_POSTGRES_CPU_SHARES'] = shares
            result = subprocess.run(['bash', str(HELPER), 'start'], env=environment,
                                    capture_output=True, text=True, timeout=10)
            log = root / 'calls.jsonl'
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, calls

    def test_default_and_explicit_shares_are_applied_and_reported(self):
        for setting, expected in [(None, '0'), ('0', '0'), ('2', '2'),
                                  ('8192', '8192'), ('262144', '262144')]:
            with self.subTest(setting=setting):
                result, calls = self.invoke(setting)
                self.assertEqual(result.returncode, 0, result.stderr)
                run = next(call for call in calls if call[0] == 'run')
                self.assertEqual(run[run.index('--cpu-shares') + 1], expected)
                self.assertIn(f'cpu_shares={expected}', result.stdout)
                self.assertFalse(any(call[0] == 'rm' for call in calls))

    def test_invalid_shares_fail_before_any_docker_call(self):
        for setting in ['', '1', '-1', '262145', '01', '0x2000', '8.5', ' 8192',
                        '8192\n', '999999999999999999999999', 'x[$(false)]']:
            with self.subTest(setting=setting):
                result, calls = self.invoke(setting)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('NORTHSTAR_LOOPBACK_POSTGRES_CPU_SHARES', result.stderr)
                self.assertEqual(calls, [])

    def test_unapplied_or_missing_setting_fails_and_cleans_fixture(self):
        for applied in ['0', '', '<no value>']:
            with self.subTest(applied=applied):
                result, calls = self.invoke('8192', STUB_APPLIED=applied)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('CPU shares mismatch', result.stderr)
                self.assertIn(['rm', '--force', 'northstar-ci-loopback-postgres'], calls)
                self.assertFalse(any(call[0] == 'exec' for call in calls))
                self.assertNotIn('fixture ready', result.stdout)

    def test_existing_container_is_never_replaced(self):
        result, calls = self.invoke('8192', STUB_EXISTING='true')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('refusing to replace', result.stderr)
        self.assertEqual(calls, [['container', 'inspect', 'northstar-ci-loopback-postgres']])

    def test_fixture_remains_restricted_to_github_ci(self):
        result, calls = self.invoke('8192', GITHUB_ACTIONS='false')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
