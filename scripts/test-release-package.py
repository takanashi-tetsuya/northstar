#!/usr/bin/env python3
"""Verify package completeness and rejection of corrupted or unsafe archives."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('release_package', Path(__file__).with_name('release-package.py'))
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)
SPEC = importlib.util.spec_from_file_location('release_evidence', Path(__file__).with_name('release-evidence.py'))
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
SPEC = importlib.util.spec_from_file_location('release_download', Path(__file__).with_name('release-download.py'))
DOWNLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOWNLOAD)
SPEC = importlib.util.spec_from_file_location('release_notes', Path(__file__).with_name('release-notes.py'))
NOTES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTES)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='northstar-package-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'source'
        self.project.mkdir()
        names = PACKAGE.SINGLE_FILES | {'web/index.html', 'third_party/swagger-ui/dist/swagger-ui.css'}
        for name in names:
            path = self.project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture content: ' + name)
        (self.project / 'Cargo.toml').write_text('[package]\nversion="0.2.0"\n')
        env = dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=self.project, env=env, stderr=subprocess.DEVNULL).decode().strip()
        git('init')
        git('add', '.')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-m', 'fixture')
        self.commit = git('rev-parse', 'HEAD')
        (self.project / 'web/private.secret').write_text('untracked content must not be shipped')
        self.binary = self.root / 'binary'
        self.destination = self.root / 'unpacked'

    def pack(self, target='linux-amd64', directory='dist'):
        self.binary.write_bytes((b'MZ' if target == 'windows-amd64' else b'\x7fELF') + b'fixture')
        return PACKAGE.pack(self.project, self.binary, self.root / directory, '0.2.0', self.commit, target, 1789218000)

    def test_both_formats_have_identical_raw_binary_complete_assets_and_no_untracked_files(self):
        for target in PACKAGE.TARGETS:
            with self.subTest(target=target):
                archive, raw = self.pack(target, target)
                destination = self.root / ('unpacked-' + target)
                manifest = PACKAGE.unpack(archive, raw, destination, '0.2.0', self.commit, target)
                self.assertEqual((destination / PACKAGE.TARGETS[target]).read_bytes(), raw.read_bytes())
                self.assertEqual(manifest['commit'], self.commit)
                self.assertFalse((destination / 'web/private.secret').exists())
                self.assertTrue((destination / '.env.development.example').is_file())
                self.assertTrue((destination / 'docs/INSTALL.md').is_file())

    def test_archives_are_reproducible_for_the_same_source_and_epoch(self):
        for target in PACKAGE.TARGETS:
            first, _ = self.pack(target, target + '-1')
            second, _ = self.pack(target, target + '-2')
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_wrong_commit_or_raw_binary_is_rejected_before_unpacking(self):
        archive, raw = self.pack()
        with self.assertRaises(ValueError):
            PACKAGE.unpack(archive, raw, self.destination, '0.2.0', 'a' * 40, 'linux-amd64')
        raw.write_bytes(b'changed binary')
        with self.assertRaises(ValueError):
            PACKAGE.unpack(archive, raw, self.destination, '0.2.0', self.commit, 'linux-amd64')
        self.assertFalse(self.destination.exists())

    def test_corruption_missing_resource_and_traversal_are_rejected(self):
        archive, raw = self.pack('windows-amd64')
        with zipfile.ZipFile(archive) as source:
            original = {name: source.read(name) for name in source.namelist()}
        for mutation in ('corrupt', 'missing', 'traversal', 'duplicate', 'symlink'):
            with self.subTest(mutation=mutation):
                payload = dict(original)
                if mutation == 'corrupt': payload['web/index.html'] = b'tampered'
                if mutation == 'missing':
                    del payload['web/index.html']
                    manifest = json.loads(payload[PACKAGE.MANIFEST])
                    del manifest['files']['web/index.html']
                    payload[PACKAGE.MANIFEST] = json.dumps(manifest).encode()
                if mutation == 'traversal': payload['../outside'] = b'escape'
                modified = self.root / (mutation + '.zip')
                with zipfile.ZipFile(modified, 'w') as target:
                    for name, data in payload.items(): target.writestr(name, data)
                    if mutation == 'duplicate':
                        import warnings
                        with warnings.catch_warnings():
                            warnings.simplefilter('ignore', UserWarning)
                            target.writestr('web/index.html', b'duplicate')
                    if mutation == 'symlink':
                        info = zipfile.ZipInfo('linked')
                        info.create_system = 3
                        info.external_attr = 0o120777 << 16
                        target.writestr(info, b'outside')
                with self.assertRaises(ValueError):
                    PACKAGE.unpack(modified, raw, self.destination, '0.2.0', self.commit, 'windows-amd64')
                self.assertFalse(self.destination.exists())

    def test_evidence_requires_both_native_targets_at_the_exact_commit(self):
        directory = self.root / 'evidence'
        directory.mkdir()
        output = self.root / 'RELEASE-EVIDENCE.json'
        images = self.root / 'images'
        images.mkdir()
        for name in ('northstar', 'northstar-backup', 'northstar-database-grants'):
            (images / (name + '.json')).write_text(json.dumps(dict(schema=1, commit=self.commit,
                version='0.2.0', name=name, image='northstar-release-test:' + self.commit,
                image_id='sha256:' + 'b' * 64, platform='linux/amd64', user='10001:10001',
                labels=True, entrypoint=True, runtime_files=True)))
        runtime = dict(schema=1, commit=self.commit, version='0.2.0', target='docker-linux-amd64',
            image='northstar-release-test:' + self.commit, native_startup=True, migration=True,
            readiness=True, web_assets=True)
        (images / 'container-runtime.json').write_text(json.dumps(runtime))
        def assemble(published=False):
            return EVIDENCE.assemble(directory, output, self.commit, '0.2.0', '123', '1', images, published)
        values = {}
        for target in PACKAGE.TARGETS:
            value = dict(schema=1, commit=self.commit, version='0.2.0', target=target,
                         native_startup=True, migration=True, readiness=True, web_assets=True)
            values[target] = value
            (directory / (target + '.json')).write_text(json.dumps(value))
        assemble()
        self.assertEqual(len(json.loads(output.read_text())['native_packages']), 2)
        self.assertEqual(len(json.loads(output.read_text())['images']), 3)
        with self.assertRaises(ValueError):
            assemble(published=True)  # A local preview image is not a published digest.
        for key in ('commit', 'image', 'native_startup', 'migration', 'readiness', 'web_assets'):
            with self.subTest(container_key=key):
                invalid = dict(runtime)
                invalid[key] = False if key in ('native_startup', 'migration', 'readiness', 'web_assets') else 'other'
                (images / 'container-runtime.json').write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    assemble()
        (images / 'container-runtime.json').write_text(json.dumps(runtime))
        for key in ('commit', 'version', 'target', 'native_startup', 'migration', 'readiness', 'web_assets'):
            with self.subTest(key=key):
                invalid = dict(values['windows-amd64'])
                invalid[key] = False if key in ('native_startup', 'migration', 'readiness', 'web_assets') else 'other'
                (directory / 'windows-amd64.json').write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):
                    assemble()
        (directory / 'windows-amd64.json').unlink()
        with self.assertRaises(ValueError):
            assemble()

    def test_fresh_download_requires_complete_checksums_and_matching_image_evidence(self):
        import hashlib
        root = self.root / 'downloaded'
        root.mkdir()
        images = ['ghcr.io/takanashi-tetsuya/' + name + '@sha256:' + str(i) * 64
                  for i, name in enumerate(('northstar', 'northstar-backup', 'northstar-database-grants'), 1)]
        payload = {name: b'download fixture' for name in (
            'northstar-0.2.0-linux-amd64', 'northstar-0.2.0-linux-amd64.tar.gz',
            'northstar-0.2.0-windows-amd64.exe', 'northstar-0.2.0-windows-amd64.zip')}
        payload['IMAGE_DIGESTS'] = ('\n'.join(images) + '\n').encode()
        payload['RELEASE-EVIDENCE.json'] = json.dumps(dict(commit=self.commit, version='0.2.0',
            published_images=True, images=[dict(image=image) for image in images])).encode()
        sums = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                       for name, data in sorted(payload.items()))
        for name, data in payload.items(): (root / name).write_bytes(data)
        (root / 'SHA256SUMS').write_text(sums)
        DOWNLOAD.verify(root, '0.2.0', self.commit)
        for mutation in ('corruption', 'missing', 'duplicate', 'outside', 'image', 'commit'):
            with self.subTest(mutation=mutation):
                for name, data in payload.items(): (root / name).write_bytes(data)
                (root / 'SHA256SUMS').write_text(sums)
                if mutation == 'corruption': (root / 'northstar-0.2.0-linux-amd64').write_bytes(b'changed')
                if mutation == 'missing': (root / 'northstar-0.2.0-windows-amd64.zip').unlink()
                if mutation == 'duplicate': (root / 'SHA256SUMS').write_text(sums + sums.splitlines()[0] + '\n')
                if mutation == 'outside': (root / 'SHA256SUMS').write_text(sums + 'a' * 64 + '  ../outside\n')
                if mutation == 'image':
                    (root / 'IMAGE_DIGESTS').write_text('\n'.join(reversed(images[1:])) + '\n')
                    changed = dict(payload, IMAGE_DIGESTS=(root / 'IMAGE_DIGESTS').read_bytes())
                    (root / 'SHA256SUMS').write_text(''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                                                          for name, data in sorted(changed.items())))
                with self.assertRaises(ValueError):
                    DOWNLOAD.verify(root, '0.2.0', 'a' * 40 if mutation == 'commit' else self.commit)

    def test_draft_notes_bind_ci_and_only_claim_completion_after_download_validation(self):
        q, e, output = (self.root / name for name in ('qualification.json', 'evidence.json', 'notes.md'))
        q.write_text(json.dumps(dict(commit=self.commit, tag='v0.2.0', ciRunId=123, ciAttempt=1,
            ciUrl='https://github.com/takanashi-tetsuya/northstar/actions/runs/123')))
        evidence = dict(commit=self.commit, version='0.2.0', published_images=True, workflow_run_id=456)
        e.write_text(json.dumps(evidence))
        NOTES.render(q, e, output, False)
        self.assertIn('Draft verification is still running', output.read_text())
        self.assertNotIn('Ready for publication.', output.read_text())
        NOTES.render(q, e, output, True)
        self.assertIn('Ready for publication.', output.read_text())
        self.assertIn(self.commit, output.read_text())
        self.assertIn('Windows is for development', output.read_text())
        e.write_text(json.dumps(dict(evidence, commit='a' * 40)))
        with self.assertRaises(ValueError):
            NOTES.render(q, e, output, True)


if __name__ == '__main__':
    unittest.main()
