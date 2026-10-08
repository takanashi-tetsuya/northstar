#!/usr/bin/env python3
"""Run the fixed historical 75 controls in their original isolated namespace.

The input is a separately prepared 11-file historical source root. This script
reads those fixed inputs and runs only pure/mocked controls. It creates no source
assembly, child, service, binary or saved corpus. Use a bounded test invoker.
Current compilation binding is tested separately by the nine-control fixture.
"""
_BINDINGS_FROZEN = True
_PACKAGE_NAME = '_stage4_profile_historical_public_v1'
_PROFILE_ROOT = None
_SOURCE_BINDINGS = (('scripts/lib/controlled_admission_supervision.py', 122899, 'ae280d9afeca63ffd2518cefa1c650583dafdb56e62871c6ead9a71fe48f5a64'), ('scripts/lib/direct_build_record.py', 19397, '3992877f58e37849ec1e0b73554f434e6bf0d702a204a6470dc686f11e7eaaba'), ('scripts/lib/stage4_build_record.py', 24012, '97631b9cb9f2c1e351cb8ae62d073201046309fc74acf5ea087d5ba07150dae6'), ('scripts/lib/stage4_case.py', 146754, 'aa7daefd7265c6804443fcf44c94ffb9c63a7561e6da1577c1e31fe2e94095c0'), ('scripts/lib/stage4_compact.py', 27490, 'd5005a7e838900f507479ba662de2b36d8fe3887208eb1fc3ea47568db4ccc74'), ('scripts/lib/stage4_compact_shapes.json', 122189, '0d28af4728b2a9fb08abf6408d0b5a970442307c69eae93cd225ab436622f7e4'), ('scripts/lib/stage4_corpus_join.py', 13961, '54f3826b3ed5b8621973ce940c861523e7e3344e69d841a557d993ea55ff2e72'), ('scripts/lib/stage4_saved_case.py', 6331, 'd5d36dcd3d5c453261e8212f8d1a63502b25274d416e514debf5a2282c11ca90'), ('scripts/lib/stage4_shapes.json', 159956, 'fc481c94bbd99e3891235b54f32450ec951c41ab4d56b3b04477ed3c01d30e38'), ('scripts/test-stage4-saved-profile.py', 52987, 'ea766e39f1519d7c3c2ad11f873e3bb1919dc55336346c5b55cb525db99e7acd'), ('src/bosh/response_owner.rs', 115084, '6c346f097c60ea3cc6e50a4e931becb1f03ea2b587d32894995da692bba6fccb'))
_SOURCE_TOTAL_BYTES = 811060
_EXPECTED_TESTS = 75
_FIXED_SELECTION = (('FixedRoutingControls', 'test_original_profile_shapes_unchanged'), ('FixedRoutingControls', 'test_exact_two_profiles_no_mutant_positive_or_shrink_tail'), ('FixedRoutingControls', 'test_unchanged_nonlegacy_limits'), ('FixedRoutingControls', 'test_structural_contracts_only'), ('FixedRoutingControls', 'test_v3_v4_profile_confusion_rejected'), ('FixedRoutingControls', 'test_stage3_no_flush_role_rejected'), ('FixedRoutingControls', 'test_no_per_occurrence_binary_field'), ('FixedRoutingControls', 'test_changed_count_budget_and_release_rejected'), ('FixedRoutingControls', 'test_external_occurrence_repeat_bytes'), ('FixedRoutingControls', 'test_single_fixed_entry_and_fd0'), ('FixedRoutingControls', 'test_only_frozen_sixteen_non_rust_source_leaves'), ('FixedRoutingControls', 'test_no_in_contract_shrink_fallback'), ('FixedRoutingControls', 'test_explicit_v2_identifiers_reject_historical_stage4_contracts'), ('FixedRoutingControls', 'test_current_v2_producer_reader_and_tables_are_exactly_pinned'), ('FrameBoundaryControls', 'test_exact_frame_preserved_with_diagnostics'), ('FrameBoundaryControls', 'test_duplicate_missing_or_stage3_tag_rejected'), ('FrameBoundaryControls', 'test_bad_size_or_trailer_rejected'), ('FrameBoundaryControls', 'test_whole_frame_and_stdout_caps'), ('FrameBoundaryControls', 'test_v2_route_rejects_old_stage4_and_mixed_frame_streams'), ('FrameBoundaryControls', 'test_codec_version_selection_is_explicit_in_both_directions'), ('ExactMutationSourceControls', 'test_exact_baseline_and_in_memory_branch_delta'), ('ExactMutationSourceControls', 'test_no_flush_or_callback_preserving_mutation_rejected'), ('ExactMutationSourceControls', 'test_offset_and_baseline_reference_rejected'), ('ExactMutationSourceControls', 'test_second_owner_edit_rejected_even_with_self_rehashed_source'), ('ExactMutationSourceControls', 'test_second_source_map_edit_rejected'), ('ExactMutationSourceControls', 'test_missing_current_source_never_authenticates'), ('BuildRecordBoundaryControls', 'test_stage3_contract_rejected_before_record_decode'), ('BuildRecordBoundaryControls', 'test_external_hash_precedes_record_parsing'), ('BuildRecordBoundaryControls', 'test_postbuild_review_packet_is_not_a_build_record_field'), ('BuildRecordBoundaryControls', 'test_ordinary_acceptance_must_match_external_contract'), ('OccurrenceGuardControls', 'test_guard_allows_pid_and_literal_hash_reuse_with_distinct_occurrences'), ('OccurrenceGuardControls', 'test_guard_rejects_duplicate_whole_tuple'), ('OccurrenceGuardControls', 'test_guard_rejects_duplicate_record_hash_despite_new_ordinal'), ('OccurrenceGuardControls', 'test_guard_rejects_missing_occurrence'), ('OccurrenceGuardControls', 'test_guard_rejects_reused_external_invocation'), ('DistinctRootSourceControls', 'test_saved_worker_still_rejects_foreign_executing_root'), ('DistinctRootSourceControls', 'test_retained_route_authenticates_unmodified_external_root_as_data'), ('DistinctRootSourceControls', 'test_join_rejects_foreign_executing_baseline_root_before_reads'), ('DistinctRootSourceControls', 'test_join_rejects_different_external_helper_map_before_reads'), ('DistinctRootSourceControls', 'test_executing_helper_reads_stay_in_baseline_root'), ('DistinctRootSourceControls', 'test_transitive_direct_build_module_must_be_from_baseline_root'), ('DistinctRootSourceControls', 'test_loaded_compact_codec_must_be_from_baseline_root'), ('ExactNegativeDiagnosticControls', 'test_exact_supervision_diagnostic_is_required'), ('ExactNegativeDiagnosticControls', 'test_unrelated_file_failure_is_not_control_coverage'), ('ExactNegativeDiagnosticControls', 'test_subclass_is_not_the_exact_exception_type'), ('ExactNegativeDiagnosticControls', 'test_unexpected_success_is_not_control_coverage'), ('InventoriedRecordControls', 'test_exact_current_projection_and_ack_pins'), ('InventoriedRecordControls', 'test_explicit_inventory_toolchain_tag'), ('InventoriedRecordControls', 'test_unknown_toolchain_tag_rejected'), ('InventoriedRecordControls', 'test_inventory_hash_still_precedes_parse'), ('InventoriedRecordControls', 'test_schema_and_toolchain_pairs_are_closed'), ('InventoriedRecordControls', 'test_unknown_record_schema_rejected'), ('InventoriedRecordControls', 'test_old_route_delegates_only_unchanged_validators'), ('InventoriedRecordControls', 'test_new_route_delegates_only_inventory_validators'), ('InventoriedRecordControls', 'test_mixed_record_ancestry_rejected_before_role_or_source'), ('InventoriedRecordControls', 'test_compilation_summary_uses_same_reads_and_fixed_helper_set'), ('InventoriedRecordControls', 'test_stage3_source_return_shape_unchanged'), ('InventoriedRecordControls', 'test_compilation_summary_forwarding_is_stage4_only'), ('InventoriedRecordControls', 'test_independent_compilation_summary_required'), ('InventoriedRecordControls', 'test_record_cannot_replace_measured_compilation_summary'), ('InventoriedRecordControls', 'test_source_record_summary_rejects_float_and_bool'), ('InventoriedRecordControls', 'test_compilation_record_summary_rejects_float_and_bool'), ('InventoriedRecordControls', 'test_helper_overlay_requires_external_effect_review'), ('InventoriedRecordControls', 'test_public_correspondence_requires_exact_reviewed_receipt'), ('InventoriedRecordControls', 'test_inventory_build_accepts_only_detached_list_metadata'), ('InventoriedRecordControls', 'test_no_run_recipe_cannot_claim_list_variant'), ('InventoriedRecordControls', 'test_build_root_is_compilation_root_not_loaded_helper_root'), ('InventoriedRecordControls', 'test_recorded_path_and_absent_rustc_override_are_required'), ('InventoriedRecordControls', 'test_inventory_selection_stays_bound_to_original_and_entry'), ('InventoriedRecordControls', 'test_merged_result_rejects_incomplete_failed_or_split_claims'), ('InventoriedRecordControls', 'test_derivative_detached_metadata_keeps_static_only_limit'), ('InventoriedRecordControls', 'test_derivative_recipe_and_compilation_cwd_are_closed'), ('InventoriedRecordControls', 'test_derivative_cannot_relax_existing_runnable_cap'), ('InventoriedRecordControls', 'test_derivative_cannot_claim_runtime_or_structural_equivalence'), ('InventoriedRecordControls', 'test_old_stream_reader_stays_strict'))

def run_profile_controls(authenticated_snapshot, fixed_selection):
    """Run only the frozen ordinary selectors over authenticated held buffers.

    This fragment is inert preparation until the owner supplies and authenticates
    the final literal bindings prefix. The owner enforces the single isolated
    300-second command and 256-KiB combined-output cap and checks unchanged inputs.
    The two shape tables and owner source are read from the materialized private
    source root, whose fixed membership/identity the owner checks before and after.
    Synthetic controls never establish saved-execution or build provenance.
    """
    import __future__
    import array
    import builtins
    import copy
    import ctypes
    import dataclasses
    import errno
    import hashlib
    import json
    import os
    import pathlib
    import re
    import resource
    import select
    import signal
    import socket
    import stat
    import sys
    import time
    import types
    import unittest
    import unittest.mock
    import xml
    import xml.etree.ElementTree

    def need(ok, message):
        if not ok:
            raise RuntimeError(message)

    need(_BINDINGS_FROZEN is True, 'Profile bootstrap bindings remain pending')
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and
         sys.flags.optimize == 0, 'Profile controls require unoptimized -I -S -B')
    need(type(fixed_selection) is tuple and fixed_selection == _FIXED_SELECTION and
         len(fixed_selection) == _EXPECTED_TESTS and len(set(fixed_selection)) == len(fixed_selection),
         'Fixed ordinary selector mismatch')
    need(all(type(row) is tuple and len(row) == 2 and
             all(type(part) is str and part.isidentifier() for part in row) and
             row[1].startswith('test_') for row in fixed_selection), 'Malformed fixed selector')
    need(type(authenticated_snapshot) is dict and set(authenticated_snapshot) == {'buffers'},
         'Unexpected authenticated snapshot fields')
    supplied = authenticated_snapshot['buffers']
    need(type(_SOURCE_BINDINGS) is tuple and len(_SOURCE_BINDINGS) == 11 and
         type(supplied) is dict and set(supplied) == {row[0] for row in _SOURCE_BINDINGS},
         'Profile source closure mismatch')
    buffers = {}
    for relative, size, digest in _SOURCE_BINDINGS:
        raw = supplied[relative]
        need(type(raw) is bytes and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
             'Unauthenticated profile source: ' + relative)
        buffers[relative] = raw
    need(sum(map(len, buffers.values())) == _SOURCE_TOTAL_BYTES, 'Profile source-byte total mismatch')

    module_order = (
        'controlled_admission_supervision', 'direct_build_record', 'stage4_compact',
        'stage4_case', 'stage4_build_record', 'stage4_saved_case', 'stage4_corpus_join')
    module_paths = {'scripts/lib/' + suffix + '.py' for suffix in module_order}
    control_path = 'scripts/test-stage4-saved-profile.py'
    data_paths = ('scripts/lib/stage4_shapes.json', 'scripts/lib/stage4_compact_shapes.json',
                  'src/bosh/response_owner.rs')
    need(set(buffers) == module_paths | {control_path} | set(data_paths), 'Unexpected profile closure member')
    root = pathlib.PurePosixPath(_PROFILE_ROOT)
    need(root.is_absolute() and str(root) == _PROFILE_ROOT and '..' not in root.parts,
         'Invalid fixed profile root')
    ordinary_imports = {
        '__future__': __future__, 'array': array, 'copy': copy, 'ctypes': ctypes,
        'dataclasses': dataclasses, 'errno': errno, 'hashlib': hashlib, 'json': json,
        'os': os, 'pathlib': pathlib, 're': re, 'resource': resource,
        'select': select, 'signal': signal, 'socket': socket, 'stat': stat,
        'sys': sys, 'time': time, 'unittest': unittest, 'unittest.mock': unittest.mock,
        'xml.etree.ElementTree': xml}
    # Exact project-facing import signatures, including from-list and level.
    imports = {
        'controlled_admission_supervision': (
            ('__future__', ('annotations',), 0), ('array', (), 0), ('copy', (), 0),
            ('ctypes', (), 0), ('errno', (), 0), ('hashlib', (), 0), ('json', (), 0),
            ('os', (), 0), ('pathlib', ('Path',), 0), ('re', (), 0),
            ('resource', (), 0), ('select', (), 0), ('signal', (), 0),
            ('socket', (), 0), ('stat', (), 0), ('sys', (), 0), ('time', (), 0)),
        'direct_build_record': (
            ('__future__', ('annotations',), 0), ('copy', (), 0), ('hashlib', (), 0),
            ('json', (), 0), ('pathlib', ('PurePosixPath',), 0), ('re', (), 0)),
        'stage4_compact': (
            ('dataclasses', ('dataclass',), 0), ('pathlib', ('Path',), 0),
            ('hashlib', (), 0), ('json', (), 0)),
        'stage4_case': (
            ('dataclasses', ('dataclass',), 0), ('pathlib', ('Path',), 0),
            ('copy', (), 0), ('hashlib', (), 0), ('json', (), 0), ('re', (), 0),
            ('xml.etree.ElementTree', (), 0), ('', ('stage4_compact',), 1)),
        'stage4_build_record': (('copy', (), 0), ('', ('direct_build_record',), 1)),
        'stage4_saved_case': (
            ('copy', (), 0), ('pathlib', ('Path',), 0),
            ('', ('controlled_admission_supervision',), 1),
            ('', ('stage4_build_record',), 1), ('', ('stage4_case',), 1)),
        'stage4_corpus_join': (
            ('pathlib', ('Path',), 0), ('stat', (), 0),
            ('', ('controlled_admission_supervision',), 1), ('', ('stage4_saved_case',), 1),
            ('', ('stage4_build_record',), 1), ('', ('stage4_case',), 1)),
        'controls': (
            ('copy', (), 0), ('pathlib', ('Path',), 0), ('sys', (), 0),
            ('unittest', (), 0), ('unittest.mock', ('patch',), 0),
            ('lib', ('controlled_admission_supervision',), 0),
            ('lib', ('stage4_build_record',), 0), ('lib', ('stage4_saved_case',), 0),
            ('lib', ('stage4_corpus_join',), 0), ('lib', ('stage4_case',), 0))}
    namespace_names = (_PACKAGE_NAME,) + tuple(_PACKAGE_NAME + '.' + suffix
                                               for suffix in module_order + ('controls',))
    need(_PACKAGE_NAME.isidentifier() and _PACKAGE_NAME.startswith('_stage4_profile_') and
         all(name not in sys.modules for name in namespace_names), 'Profile namespace already occupied')
    package = types.ModuleType(_PACKAGE_NAME)
    package.__path__ = ()
    package.__package__ = _PACKAGE_NAME
    registered = {package.__name__: package}
    sys.modules[package.__name__] = package
    compile_held, execute_held = builtins.compile, builtins.exec

    def load(relative, suffix):
        module = types.ModuleType(_PACKAGE_NAME + '.' + suffix)
        module.__file__ = str(root / relative)
        module.__package__ = _PACKAGE_NAME

        def fixed_import(name, globals=None, locals=None, fromlist=(), level=0):
            members = tuple(fromlist or ())
            need((name, members, level) in imports[suffix], 'Unexpected profile import: ' + name)
            if level == 1 or name == 'lib':
                need(all(_PACKAGE_NAME + '.' + member in registered and
                         getattr(package, member, None) is registered[_PACKAGE_NAME + '.' + member]
                         for member in members), 'Profile import is not a held module')
                return package
            need(level == 0 and name in ordinary_imports, 'Unexpected standard-library import')
            return ordinary_imports[name]

        safe_builtins = dict(vars(builtins))
        for name in ('open', 'input', 'eval', 'exec', 'compile', '__import__'):
            safe_builtins.pop(name, None)
        safe_builtins['__import__'] = fixed_import
        module.__dict__['__builtins__'] = safe_builtins
        registered[module.__name__] = module
        sys.modules[module.__name__] = module
        setattr(package, suffix, module)
        execute_held(compile_held(buffers[relative], module.__file__, 'exec',
                                 dont_inherit=True, optimize=0), module.__dict__, module.__dict__)
        return module

    try:
        for suffix in module_order:
            load('scripts/lib/' + suffix + '.py', suffix)
        controls = load(control_path, 'controls')
        tests = []
        for class_name, method_name in fixed_selection:
            cls = controls.__dict__.get(class_name)
            need(type(cls) is type and issubclass(cls, unittest.TestCase) and
                 cls.__module__ == controls.__name__ and method_name in cls.__dict__ and
                 callable(cls.__dict__[method_name]), 'Frozen ordinary control missing')
            tests.append(cls(method_name))
        suite = unittest.TestSuite(tests)
        need(suite.countTestCases() == len(fixed_selection), 'Frozen ordinary control count mismatch')
        result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, failfast=False,
                                         buffer=False).run(suite)
        successful = (result.wasSuccessful() and result.testsRun == _EXPECTED_TESTS and
                      not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)
        return {'schema': 'stage4-fixed-profile-ordinary-result-v1',
                'status': 'Passed' if successful else 'Failed',
                'expected_tests': len(fixed_selection), 'tests_run': result.testsRun,
                'failures': len(result.failures), 'errors': len(result.errors),
                'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures),
                'unexpected_successes': len(result.unexpectedSuccesses),
                'selection': [{'class': cls, 'method': method} for cls, method in fixed_selection],
                'source_files': len(buffers), 'source_bytes': _SOURCE_TOTAL_BYTES,
                'provenance': False,
                'qualification': 'Synthetic ordinary controls only; no actual saved-corpus or build acceptance'}
    finally:
        for name, module in reversed(tuple(registered.items())):
            need(sys.modules.get(name) is module, 'Authenticated profile namespace identity changed')
            del sys.modules[name]


def main(argv=None):
    import hashlib
    import json
    import os
    from pathlib import Path
    import stat
    import sys

    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and sys.flags.optimize == 0):
        raise RuntimeError('Historical controls require unoptimized -I -S -B')
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        raise RuntimeError('Supply exactly one preassembled historical 11-file source root')
    root = Path(arguments[0])
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise RuntimeError('Historical input root must be a canonical absolute directory')
    buffers = {}
    for relative, size, digest in _SOURCE_BINDINGS:
        path = root / relative
        if path.resolve() != path:
            raise RuntimeError('Historical input path must not contain a symlink')
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                raise RuntimeError('Historical source type or size mismatch: ' + relative)
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                raw = stream.read(size + 1)
            after = os.fstat(descriptor)
            identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            if identity(before) != identity(after) or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                raise RuntimeError('Historical source identity mismatch: ' + relative)
            buffers[relative] = raw
        finally:
            os.close(descriptor)
    global _PROFILE_ROOT
    _PROFILE_ROOT = str(root)
    result = run_profile_controls({'buffers': buffers}, _FIXED_SELECTION)
    result['binding_lane'] = 'Historical976_75Assertions_Unchanged'
    result['current_compilation_binding_tested'] = False
    print(json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if result['status'] == 'Passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
