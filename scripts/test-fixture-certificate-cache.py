#!/usr/bin/env python3
"""Exercise the actual fixture certificate blocks and private round reuse."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('certificate_cache', ROOT / 'scripts/fixture-certificate-cache.py')
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='northstar-certificate-test-')
        cls.root = Path(cls.temporary.name)
        cls.examples = {}
        for fixture, filename, end_marker in [
                ('federation', 'federation-wsl.sh', '# The relays'),
                ('mix-federation', 'mix-federation-runtime-wsl.sh', '# Both Northstar')]:
            base = cls.root / fixture
            base.mkdir(mode=0o700)
            cache = base / 'pair-1'
            cache.mkdir(mode=0o700)
            scope = 'northstar_listener_' + fixture.replace('-', '_') + '_0123456789abcdef:1'
            source = (ROOT / 'scripts' / filename).read_text()
            source = source[source.index('fixture_certificates_restore '):source.index(end_marker)]
            first = cls.generate(base / 'round-1', cache, scope, source)
            second = cls.generate(base / 'round-2', cache, scope, source)
            cls.examples[fixture] = (cache, scope, first, second, source)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @staticmethod
    def generate(runtime, cache, scope, source):
        runtime.mkdir(mode=0o700)
        (runtime / 'certs').mkdir(mode=0o700)
        environment = dict(os.environ, NORTHSTAR_LISTENER_STRESS_CERTIFICATE_CACHE=str(cache),
                           NORTHSTAR_LISTENER_STRESS_CERTIFICATE_SCOPE=scope)
        prefix = 'set -euo pipefail\nproject_dir="$1"\nruntime_dir="$2"\ncert_dir="$runtime_dir/certs"\nsource "$project_dir/scripts/lib/test-fixture-certificates.sh"\n'
        result = subprocess.run(['bash', '-c', prefix + source, 'certificate-test', str(ROOT), str(runtime)],
                                env=environment, capture_output=True, text=True, timeout=45)
        if result.returncode:
            raise AssertionError(f'fixture certificate generation failed: {result.stdout} {result.stderr}; '
                                 f'files={sorted(p.name for p in (runtime / "certs").iterdir())}')
        return runtime

    def test_real_fixtures_restore_identical_certificates_but_fresh_secrets(self):
        for fixture, (cache, _scope, first, second, _source) in self.examples.items():
            with self.subTest(fixture=fixture):
                self.assertEqual({p.name for p in (first / 'certs').iterdir()}, CACHE.names(fixture))
                for name in CACHE.names(fixture):
                    self.assertEqual((first / 'certs' / name).read_bytes(), (second / 'certs' / name).read_bytes())
                    self.assertEqual((cache / 'complete' / name).stat().st_mode & 0o777, 0o600)
                secrets = list(first.glob('*.secret'))
                self.assertGreaterEqual(len(secrets), 4)
                for secret in secrets:
                    self.assertNotEqual(secret.read_bytes(), (second / secret.name).read_bytes())
                self.assertFalse(list((cache / 'complete').glob('*.secret')))

    def test_cached_chains_retain_positive_and_wrong_identity_checks(self):
        for fixture, (_cache, _scope, _first, second, _source) in self.examples.items():
            prefix = 'federation-' if fixture == 'federation' else ''
            certs = second / 'certs'
            for side, host in [('a', 'localhost'), ('b', 'remote.localhost')]:
                args = ['openssl', 'verify', '-CAfile', str(certs / (prefix + 'ca.crt')),
                        '-verify_hostname', host, str(certs / (prefix + side + '.crt'))]
                self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
                args[-2] = 'foreign.localhost'
                self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            if fixture == 'federation':
                args = ['openssl', 'verify', '-CAfile', str(certs / 'federation-ca.crt'),
                        '-verify_hostname', 'remote.localhost', str(certs / 'federation-evil.crt')]
                self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)

    def test_another_pair_has_an_independent_ca(self):
        cache, scope, first, _second, source = self.examples['federation']
        other = cache.parent / 'pair-2'
        other.mkdir(mode=0o700)
        runtime = self.generate(cache.parent / 'other-round', other, scope[:-1] + '2', source)
        self.assertNotEqual((first / 'certs/federation-ca.crt').read_bytes(),
                            (runtime / 'certs/federation-ca.crt').read_bytes())

    def test_foreign_expired_changed_partial_or_unsafe_cache_is_rejected_before_copy(self):
        original, scope, _first, _second, _source = self.examples['federation']
        for mutation in ['scope', 'expiry', 'digest', 'missing', 'symlink', 'permissions']:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as temp:
                base = Path(temp)
                cache = base / 'pair'
                shutil.copytree(original, cache)
                output = base / 'output'
                output.mkdir(mode=0o700)
                manifest = cache / 'complete/manifest.json'
                value = json.loads(manifest.read_text())
                target = cache / 'complete/federation-a.key'
                if mutation == 'scope': value['scope'] = scope[:-1] + '2'
                if mutation == 'expiry': value['expires'] = 1
                if mutation == 'digest': target.write_bytes(target.read_bytes() + b'changed')
                if mutation == 'missing': target.unlink()
                if mutation == 'symlink':
                    target.unlink()
                    target.symlink_to(original / 'complete/federation-a.key')
                if mutation == 'permissions': target.chmod(0o644)
                manifest.write_text(json.dumps(value))
                with self.assertRaises((ValueError, OSError)):
                    CACHE.transfer('restore', cache, output, 'federation', scope)
                self.assertEqual(list(output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
