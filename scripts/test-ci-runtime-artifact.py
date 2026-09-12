#!/usr/bin/env python3
"""Artifact provenance failures must precede execution or destination replacement."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('runtime_artifact', ROOT / 'scripts/ci-runtime-artifact.py')
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='northstar-runtime-artifact-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'bundle'
        self.binary = self.root / 'build/rust-xmpp-server'
        self.binary.parent.mkdir()
        self.binary.write_bytes(b'fixture binary bytes; never executed\n')
        self.binary.chmod(0o755)
        self.destination = self.root / 'restore/rust-xmpp-server'
        self.destination.parent.mkdir()
        self.destination.write_bytes(b'original')
        self.log = self.root / 'build.jsonl'
        self.records = [dict(reason='compiler-artifact', executable=str(self.binary),
            target=dict(name='rust-xmpp-server', kind=['bin'], src_path=str(ROOT / 'src/main.rs')),
            profile=dict(opt_level='2', debug_assertions=True, overflow_checks=True, test=False)),
            dict(reason='build-finished', success=True)]
        self.log.write_text('\n'.join(map(json.dumps, self.records)))
        self.expected = dict(run=dict(GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                                     GITHUB_REPOSITORY='owner/repo'), source_digest='b' * 64,
                             rustc='rustc 1.97.1 (fixture)', platform=['Linux', 'x86_64', 'ubuntu', '24.04'])
        mock = patch.object(ARTIFACT, 'identity', return_value=self.expected)
        mock.start()
        self.addCleanup(mock.stop)

    def pack(self):
        ARTIFACT.transfer('pack', ROOT, self.bundle, self.binary, self.log)

    def test_round_trip_restores_verified_bytes_and_executable_mode(self):
        self.pack()
        (self.bundle / 'rust-xmpp-server').chmod(0o644)  # Actions strips executable mode.
        ARTIFACT.transfer('restore', ROOT, self.bundle, self.destination)
        self.assertEqual(self.destination.read_bytes(), self.binary.read_bytes())
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o755)

    def test_wrong_run_source_platform_toolchain_or_profile_cannot_replace_destination(self):
        self.pack()
        manifest = self.bundle / 'manifest.json'
        original = json.loads(manifest.read_text())
        changes = [('identity', name) for name in ['source_digest', 'rustc', 'platform']]
        changes += [('run', name) for name in self.expected['run']]
        changes += [('profile', name) for name in ARTIFACT.GUARD.EXPECTED_PROFILE]
        for group, key in changes:
            with self.subTest(group=group, key=key):
                value = copy.deepcopy(original)
                target = value['identity']['run'] if group == 'run' else value[group]
                target[key] = 'different'
                manifest.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    ARTIFACT.transfer('restore', ROOT, self.bundle, self.destination)
                self.assertEqual(self.destination.read_bytes(), b'original')

    def test_changed_binary_and_symlink_are_rejected(self):
        self.pack()
        binary = self.bundle / 'rust-xmpp-server'
        binary.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            ARTIFACT.transfer('restore', ROOT, self.bundle, self.destination)
        binary.unlink()
        binary.symlink_to(self.binary)
        with self.assertRaises(OSError):
            ARTIFACT.transfer('restore', ROOT, self.bundle, self.destination)
        self.assertEqual(self.destination.read_bytes(), b'original')

    def test_pack_requires_successful_profile_evidence_for_selected_source_and_binary(self):
        for mutate in [lambda r: r[1].update(success=False),
                       lambda r: r[0]['profile'].update(debug_assertions=False),
                       lambda r: r[0].update(executable=str(self.destination)),
                       lambda r: r[0]['target'].update(src_path='/other/src/main.rs')]:
            records = copy.deepcopy(self.records)
            mutate(records)
            self.log.write_text('\n'.join(map(json.dumps, records)))
            with self.assertRaises(ValueError):
                self.pack()
            self.assertFalse(self.bundle.exists())


class SourceIdentityTests(unittest.TestCase):
    def test_checkout_and_run_identity_are_verified_against_real_git(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            env = dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=project, env=env, stderr=subprocess.DEVNULL).decode().strip()
            git('init')
            (project / 'source.rs').write_text('source')
            (project / 'empty').touch()
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture')
            environment = dict(GITHUB_SHA=git('rev-parse', 'HEAD'), GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_REPOSITORY='owner/repo')
            original = subprocess.check_output
            def tool(command, **kwargs):
                if command == ['rustc', '--version']: return 'rustc 1.97.1 (fixture)\n'
                return original(command, **kwargs)
            with patch.object(ARTIFACT.subprocess, 'check_output', side_effect=tool):
                first = ARTIFACT.identity(project, environment)
                self.assertEqual(first, ARTIFACT.identity(project, environment))
                with self.assertRaises(ValueError): ARTIFACT.identity(project, dict(environment, GITHUB_SHA='f' * 40))
                with self.assertRaises(ValueError): ARTIFACT.identity(project, dict(environment, GITHUB_RUN_ID=''))
                (project / 'source.rs').write_text('changed')
                self.assertNotEqual(first['source_digest'], ARTIFACT.source_digest(project))
                with self.assertRaises(subprocess.CalledProcessError): ARTIFACT.identity(project, environment)


if __name__ == '__main__':
    unittest.main()
