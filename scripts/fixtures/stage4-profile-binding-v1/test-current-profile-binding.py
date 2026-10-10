#!/usr/bin/env python3
"""Pure metadata controls for a versioned public fixture snapshot.
Both explicit consumer copies and all nine test method bodies are unchanged.

The two 941-key maps are real source data. Records, contracts, summaries and
receipt references constructed below are unit inputs only. They authenticate
no build, artifact, actual prepared root, process, saved frame or authority.
Only _inventory_source is exercised. No production constants are patched.
Execution results are recorded separately; fixture metadata is never authority.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parent
EXPECTED = {
    'historical': {'sha256': '26342ca7654011d6fa9e94aa514220a1d9614f18d670cd2ec0fc3a758369f611',
                   'bytes': 18596296,
                   'consumer': '97631b9cb9f2c1e351cb8ae62d073201046309fc74acf5ea087d5ba07150dae6'},
    'current': {'sha256': '23f4e5fb67e85a7154a2472799b671b691e0c3b604da3acda88f75143a2d0b98',
                'bytes': 18606272,
                'consumer': '892ccf54daeaca3fe7ad3fa086553c4ecbf00109c982f88ad9788ea24b66cffc'},
}
BASE_SHA256 = '3992877f58e37849ec1e0b73554f434e6bf0d702a204a6470dc686f11e7eaaba'
PUBLIC_PINS = {
    'historical': 'aace73b19356a555a90f8f4f878b2a5f52de25ca5a8625fc3b7375a2d513bb03',
    'current': '7a94f05d2af5e2193d4ca25ad2847ee466897961e7a1c9383058cc5c2ad3a12c',
}
PRIOR_CURRENT_CONSUMER_SHA256 = '56a54ef511b7c37ea0e8bd51fd6bb209dd8cf978fc6d334b3e7dd6ffb4abf427'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


# Exact fixed source checks precede imports. The bounded test invoker also
# authenticates the complete fixture and namespace import layout.
for lane in ('historical', 'current'):
    directory = ROOT / lane / 'scripts/lib'
    if digest((directory / 'stage4_build_record.py').read_bytes()) != EXPECTED[lane]['consumer']:
        raise ValueError('consumer_source_identity:' + lane)
    if digest((directory / 'direct_build_record.py').read_bytes()) != BASE_SHA256:
        raise ValueError('base_source_identity:' + lane)
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from historical.scripts.lib import stage4_build_record as historical
from current.scripts.lib import stage4_build_record as current

for lane, module in (('historical', historical), ('current', current)):
    if Path(module.__file__) != ROOT / lane / 'scripts/lib/stage4_build_record.py':
        raise ValueError('loaded_consumer_path:' + lane)
    if Path(module.base.__file__) != ROOT / lane / 'scripts/lib/direct_build_record.py':
        raise ValueError('loaded_base_path:' + lane)


class CurrentCompilationBindingControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        public_raw = (ROOT / 'current-public-correspondence.json').read_bytes()
        if digest(public_raw) != '2587c49f134ba405dc13e22b99cb2c880a601ee449dd747430453a336dce2227':
            raise ValueError('constructed_public_correspondence_fixture_identity')
        public_fixture = json.loads(public_raw)
        if (public_fixture['original_receipt_sha256'] != PUBLIC_PINS['current'] or
                public_fixture['actual_authority'] is not False or
                public_fixture['status'] != 'ConstructedPathSanitizedControlFixture_NotAuthority'):
            raise ValueError('constructed_public_correspondence_fixture_classification')
        cls.maps = {}
        for lane in ('historical', 'current'):
            raw = (ROOT / (lane + '-compilation-map.json')).read_bytes()
            value = json.loads(raw)
            if raw != canonical(value) + b'\n' or len(value) != 941 or digest(canonical(value)) != EXPECTED[lane]['sha256']:
                raise ValueError('real_projection_data_identity:' + lane)
            cls.maps[lane] = value
        helper_raw = (ROOT / 'helper-metadata.json').read_bytes()
        if digest(helper_raw) != 'afc50d69b7971ed78eacf5b53df9c15fb7a5212898441eec905a90f2144bec44':
            raise ValueError('constructed_historical_helper_metadata_identity')
        cls.helpers = json.loads(helper_raw)['files']
        if len(cls.helpers) != 22 or sum(row['bytes'] for row in cls.helpers.values()) != 1609036:
            raise ValueError('historical_helper_metadata_shape')

    def constructed_input(self, lane, *, changed_map=None, changed_bytes=None, public_pin=None):
        """Construct detached metadata, never an actual contract or build record."""
        projection = copy.deepcopy(self.maps[lane] if changed_map is None else changed_map)
        helpers = {key: row['sha256'] for key, row in self.helpers.items()}
        helpers['scripts/lib/stage4_build_record.py'] = EXPECTED[lane]['consumer']
        sources = dict(projection, **helpers)
        byte_count = EXPECTED[lane]['bytes'] if changed_bytes is None else changed_bytes
        measured = {'sha256': digest(canonical(projection)), 'files': 941, 'bytes': byte_count}
        summary = {'sha256': digest(canonical(sources)), 'files': 963,
                   'bytes': byte_count + sum(row['bytes'] for row in self.helpers.values())}
        synthetic_review = digest(b'constructed metadata only: no accepted effect review')
        contract = {'provenance': {'source_files': sources, 'source_sha256': summary['sha256'],
            'cargo_lock_sha256': sources['Cargo.lock']}, 'helper_source_files': helpers,
            'release': {'effect_review_sha256': synthetic_review}}
        source = {'manifest_sha256': summary['sha256'], 'file_count': summary['files'],
            'bytes': summary['bytes'], 'patch_sha256': None,
            'cargo_lock_sha256': sources['Cargo.lock'],
            'toolchain_file_sha256': sources['rust-toolchain.toml'],
            'after_preparation': 'ExactManifestMembershipAndAbsences'}
        compilation = {'root': '/constructed-metadata-only/' + lane,
            'source_sha256': measured['sha256'], 'file_count': 941, 'bytes': byte_count,
            'helper_overlay_review_sha256': synthetic_review}
        for name in ('before_snapshot', 'after_snapshot', 'build_postcheck', 'runtime_tools',
                     'toolchain_manifest', 'public_correspondence'):
            compilation[name] = {'path': '/constructed-metadata-only/receipt-' + name,
                'bytes': 1, 'sha256': digest(('constructed non-authority ' + name).encode())}
        # The current pin names the separately accepted public/actual-C2 source
        # correspondence. This synthetic receipt path still authenticates no
        # private overlay, constructed record or runtime authority.
        compilation['public_correspondence']['sha256'] = (PUBLIC_PINS[lane] if public_pin is None else public_pin)
        return {'artifact_role': 'baseline', 'source': source, 'compilation': compilation}, contract, summary, measured

    def check(self, consumer, lane, **changes):
        return consumer._inventory_source(*self.constructed_input(lane, **changes))

    def reject_current(self, lane, *, expected_diagnostic='inventory_frozen_compilation_projection', **changes):
        self.check(current, 'current')
        try:
            try:
                self.check(current, lane, **changes)
            except current.base.BuildRecordError as error:
                self.assertIs(type(error), current.base.BuildRecordError)
                self.assertEqual(str(error), expected_diagnostic)
            else:
                self.fail('Current consumer accepted the wrong projection binding')
        finally:
            self.check(current, 'current')

    def test_current_consumer_accepts_real_current_map_and_bytes(self):
        self.assertIsNone(self.check(current, 'current'))

    def test_historical_consumer_accepts_real_historical_map_and_bytes(self):
        self.assertIsNone(self.check(historical, 'historical'))

    def test_current_consumer_rejects_real_historical_map(self):
        self.reject_current('historical')

    def test_current_consumer_rejects_self_consistent_wrong_map(self):
        changed = dict(self.maps['current'])
        changed['src/bosh.rs'] = '0' * 64
        self.reject_current('current', changed_map=changed)

    def test_current_consumer_rejects_old_and_off_by_one_byte_counts(self):
        for wrong in (18596296, 18606271, 18606273):
            with self.subTest(bytes=wrong):
                self.reject_current('current', changed_bytes=wrong)

    def test_historical_consumer_rejects_current_map_without_rebinding(self):
        self.check(historical, 'historical')
        try:
            with self.assertRaises(historical.base.BuildRecordError) as caught:
                self.check(historical, 'current')
            self.assertIs(type(caught.exception), historical.base.BuildRecordError)
            self.assertEqual(str(caught.exception), 'inventory_frozen_compilation_projection')
        finally:
            self.check(historical, 'historical')

    def test_consumer_lineage_has_only_two_then_one_constant_changes(self):
        old = (ROOT / 'historical/scripts/lib/stage4_build_record.py').read_bytes()
        prior = (ROOT / 'prior-current-consumer.py.txt').read_bytes()
        self.assertEqual(digest(prior), PRIOR_CURRENT_CONSUMER_SHA256)
        new = (ROOT / 'current/scripts/lib/stage4_build_record.py').read_bytes()
        for before, after in (
            (b"COMPILATION_BASELINE_SHA256 = '" + EXPECTED['historical']['sha256'].encode() + b"'",
             b"COMPILATION_BASELINE_SHA256 = '" + EXPECTED['current']['sha256'].encode() + b"'"),
            (b'COMPILATION_BASELINE_BYTES = 18596296', b'COMPILATION_BASELINE_BYTES = 18606272')):
            self.assertEqual(old.count(before), 1)
            old = old.replace(before, after)
        self.assertEqual(old, prior)
        old_selector = b"PUBLIC_CORRESPONDENCE_SHA256 = '" + PUBLIC_PINS['historical'].encode() + b"'"
        new_selector = b"PUBLIC_CORRESPONDENCE_SHA256 = '" + PUBLIC_PINS['current'].encode() + b"'"
        self.assertEqual(prior.count(old_selector), 1)
        self.assertEqual(prior.replace(old_selector, new_selector), new)
        self.assertEqual((historical.COMPILATION_FILES, current.COMPILATION_FILES), (941, 941))
        for lane, module in (('historical', historical), ('current', current)):
            self.assertEqual(module.COMPILATION_BASELINE_SHA256, EXPECTED[lane]['sha256'])
            self.assertEqual(module.COMPILATION_BASELINE_BYTES, EXPECTED[lane]['bytes'])
            self.assertEqual(module.PUBLIC_CORRESPONDENCE_SHA256, PUBLIC_PINS[lane])

    def test_current_consumer_rejects_historical_public_pin(self):
        self.reject_current('current', public_pin=PUBLIC_PINS['historical'],
                            expected_diagnostic='inventory_public_correspondence')

    def test_current_consumer_rejects_wrong_public_pin(self):
        self.reject_current('current', public_pin='0' * 64,
                            expected_diagnostic='inventory_public_correspondence')


if __name__ == '__main__':
    unittest.main()
