#!/usr/bin/env python3
"""Fixed pure public regressions: 47 earlier-stage methods, then 53 codec methods.

Inputs and receipt-like objects are constructed controls, never runtime authority.
The loader never dispatches test-script mains, saved profiles, binaries or services.
A selected CLI rejection test calls its main only with invalid workload arguments.
Use the separately bounded invoker with source/namespace preflight and source
preservation checks. This file adds only fixed import and named-test selection.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_BINDINGS = (('scripts/capture-controlled-admission.py', 14141, '1d51989a711d52d71dd64ffda86a5f7766da1559406351149010a85ff4306bc0'), ('scripts/lib/controlled_admission.py', 112557, '526922ae45d484626d846eda5b696780ab5ae2418e506b078a4d650809aff12c'), ('scripts/lib/controlled_admission_supervision.py', 122899, 'ae280d9afeca63ffd2518cefa1c650583dafdb56e62871c6ead9a71fe48f5a64'), ('scripts/lib/direct_build_record.py', 19397, '3992877f58e37849ec1e0b73554f434e6bf0d702a204a6470dc686f11e7eaaba'), ('scripts/lib/direct_case.py', 234726, '5343078783827b0a65dcb8797f1de5967831d5b0fbd995c1749e4c4447e48a76'), ('scripts/lib/experiment_contract.py', 29666, '04ee1bc5f475d027eaf3c3f5a4834746252a5d9f49524478f7e120912eba3eac'), ('scripts/lib/stage4_case.py', 146754, 'aa7daefd7265c6804443fcf44c94ffb9c63a7561e6da1577c1e31fe2e94095c0'), ('scripts/lib/stage4_compact.py', 27490, 'd5005a7e838900f507479ba662de2b36d8fe3887208eb1fc3ea47568db4ccc74'), ('scripts/lib/stage4_compact_shapes.json', 122189, '0d28af4728b2a9fb08abf6408d0b5a970442307c69eae93cd225ab436622f7e4'), ('scripts/lib/stage4_shapes.json', 159956, 'fc481c94bbd99e3891235b54f32450ec951c41ab4d56b3b04477ed3c01d30e38'), ('scripts/test-controlled-admission.py', 121742, 'b6d27d486c539402ce85c0b922df1fcba803245855d5620993a0cc0b64670aa6'), ('scripts/test-direct-build-record.py', 29253, '128622db47f399a614d0f329659b08b154c7483fd9820b726901b4b9a3402119'), ('scripts/test-direct-case.py', 202729, 'f8db247677779e13b6b41d9038ee90a3453264bcf97d71969d68c99efbc72a6f'), ('scripts/test-experiment-contract.py', 52778, 'b5ca4126350e69354bca4173dcfdaffd64c4503d9fa091b99a9f683099b0cd95'), ('scripts/test-stage4-compact-codec.py', 19958, '329d9156b0b44c1237bad7d30b51b294add9548419e1f560631125108407a884'))
_SELECTION = (('scripts/test-experiment-contract.py', (('SchemaTests', 'test_unknown_fields_rejected_at_every_input_layer'), ('SchemaTests', 'test_boolean_never_counts_as_integer'), ('SchemaTests', 'test_schema_policy_identity_and_effect_schedule_rejections'))), ('scripts/test-controlled-admission.py', (('IndependentOracleTests', 'test_stage1_bridge_matches_accepted_independent_goldens'), ('DriverTests', 'test_legacy_unbounded_execution_is_closed_before_any_launch'), ('DriverTests', 'test_regression_cli_cannot_select_dedicated_record_or_replay'), ('SupervisionSchemaTests', 'test_contract_rejects_boolean_limits_missing_helpers_extra_budget_and_combined_modes'), ('SupervisionSchemaTests', 'test_common_case_validator_applies_to_rejection_and_all_shrink_records'), ('SupervisionSchemaTests', 'test_complete_capture_wall_boundary_is_contract_bounded'), ('SupervisionSchemaTests', 'test_historical_seven_field_execution_never_becomes_supervised'), ('SupervisionSchemaTests', 'test_prefix_output_cannot_be_parsed_into_an_invariant'), ('SupervisionSchemaTests', 'test_stream_cap_plus_one_is_a_lower_bound_not_full_length'), ('SupervisionSchemaTests', 'test_expected_domain_negatives_still_match_the_entire_fixed_fixture'), ('SupervisionSchemaTests', 'test_rejection_requires_exact_reason_output_and_actual_exit_two'), ('SupervisionSchemaTests', 'test_malformed_complete_output_is_saved_as_an_unexpected_stop'), ('SupervisionSchemaTests', 'test_not_started_observation_has_no_invented_pid_or_wait_status'))), ('scripts/test-direct-case.py', (('ClosedProfileTests', 'test_legacy_counts_budgets_argv_and_mechanism_stay_exact'), ('ClosedProfileTests', 'test_stage3_profiles_have_exact_finite_counts_roles_and_limits'), ('ClosedProfileTests', 'test_versions_profiles_counts_and_artifact_roles_do_not_cross'), ('ClosedProfileTests', 'test_only_v3_accepts_the_larger_individual_file_bound'), ('ClosedProfileTests', 'test_literal_plan_and_case_references_are_bound_to_inventory'), ('ClosedProfileTests', 'test_bad_current_record_stops_caller_and_worker_before_collection_or_hello'), ('ClosedProfileTests', 'test_worker_bootstrap_profile_must_match_external_contract'), ('DirectFrameTests', 'test_one_bounded_frame_preserves_only_its_payload_for_the_dto_reader'), ('DirectFrameTests', 'test_frame_payload_is_utf8_text_without_bom_or_encoding_autodetection'), ('DirectFrameTests', 'test_legacy_json_byte_decoder_behavior_is_unchanged'), ('DirectFrameTests', 'test_missing_duplicate_truncated_extra_end_and_bad_json_frames_fail'), ('DirectFrameTests', 'test_incomplete_process_never_calls_dto_or_oracle'), ('DirectFrameTests', 'test_direct_rejection_requires_exit_zero_and_empty_complete_streams'), ('DirectOwnerTests', 'test_hello_requires_profile_count_and_begin_uses_its_kinds_and_deadline'), ('DirectOwnerTests', 'test_fixed16_done_needs_no_shrink_tail_and_fixed4_stops_at_four'), ('DirectOwnerTests', 'test_caller_completion_uses_selected_total_and_profile_mechanism'), ('DirectInventoryTests', 'test_audited_root_and_manifest_counts_are_source_fixed'), ('DirectInventoryTests', 'test_exact_membership_rejects_added_missing_nonregular_and_omitted_inputs'), ('DirectInventoryTests', 'test_import_shadow_cache_and_native_alternatives_fail_before_import'), ('DirectMaterialAdapterTests', 'test_build_record_and_runnable_adapters_forward_independent_facts'), ('DirectMaterialAdapterTests', 'test_provenance_metadata_is_closed_and_bound_without_reading_material'), ('DirectMaterialAdapterTests', 'test_source_summary_counts_actual_read_bytes_and_retains_mutation_input'), ('DirectMaterialAdapterTests', 'test_record_authentication_precedes_binary_open_and_closes_temporary_descriptor'), ('DirectMaterialAdapterTests', 'test_bad_external_record_hash_stops_before_any_runnable_descriptor'), ('DirectMaterialAdapterTests', 'test_actual_descriptor_mode_and_size_are_not_copied_from_record'), ('DirectMaterialAdapterTests', 'test_v3_ancestor_metadata_rejection_precedes_binary_open'), ('DirectMaterialAdapterTests', 'test_legacy_current_material_keeps_original_signature'), ('DirectMaterialAdapterTests', 'test_caller_forwards_current_source_facts_before_other_material_reads'), ('DirectMaterialAdapterTests', 'test_caller_repeats_material_verification_after_mocked_capture'))), ('scripts/test-direct-build-record.py', (('BuildRecordTests', 'test_scope_claims_and_v2_are_not_silently_widened'), ('BuildRecordTests', 'test_reader_never_opens_files_or_executes_recorded_commands'))), ('scripts/test-stage4-compact-codec.py', (('ConstructedCodecControls', 'test_constructed_rejection_shape_roundtrip'), ('ConstructedCodecControls', 'test_named_field_order_does_not_choose_slots'), ('ConstructedCodecControls', 'test_wrapper_declares_actual_named_commitment'), ('ConstructedCodecControls', 'test_explicit_v2_rejects_v1_tag'), ('ConstructedCodecControls', 'test_explicit_v1_rejects_v2_tag'), ('ConstructedCodecControls', 'test_no_unknown_version_or_auto_selection'), ('ConstructedCodecControls', 'test_whole_frame_cap'), ('ConstructedCodecControls', 'test_wrong_marker'), ('ConstructedCodecControls', 'test_marker_wrong_type'), ('ConstructedCodecControls', 'test_wrapper_extra_missing_wrong_container'), ('ConstructedCodecControls', 'test_envelope_tuple_arity'), ('ConstructedCodecControls', 'test_unknown_sum_codes_are_json'), ('ConstructedCodecControls', 'test_wrong_tuple_slot_type'), ('ConstructedCodecControls', 'test_no_reference_or_pool_syntax_at_other_positions'), ('ConstructedCodecControls', 'test_unknown_and_duplicate_named_map_keys'), ('ConstructedCodecControls', 'test_named_identity_map_must_not_be_positional'), ('ConstructedCodecControls', 'test_declared_size_bounds_and_type'), ('ConstructedCodecControls', 'test_declared_size_and_digest_mismatch'), ('ConstructedCodecControls', 'test_digest_noncanonical_hex'), ('ConstructedCodecControls', 'test_length_trailer_duplicate_and_truncation'), ('ConstructedCodecControls', 'test_canonical_whitespace_escape_and_negative_zero'), ('ConstructedCodecControls', 'test_invalid_raw_utf8'), ('ConstructedCodecControls', 'test_lone_surrogates_are_controlled_json'), ('ConstructedCodecControls', 'test_canonical_unicode_controls_bytes_and_no_normalization'), ('ConstructedCodecControls', 'test_surrogate_pair_is_scalar_but_escape_spelling_is_noncanonical'), ('ConstructedCodecControls', 'test_hex_mode_requires_non_utf8'), ('ConstructedCodecControls', 'test_byte_mode_type_arity_and_code'), ('ConstructedCodecControls', 'test_hex_case_parity_and_invalid_digits'), ('ConstructedCodecControls', 'test_bytes_original_bounds_and_text_nul'), ('ConstructedCodecControls', 'test_identity_reference_types_and_range'), ('ConstructedCodecControls', 'test_reference_clones_complete_labels_without_mutable_alias'), ('ConstructedCodecControls', 'test_bounded_integer_types_and_endpoints'), ('ConstructedCodecControls', 'test_lexical_scan_before_generic_parser'), ('ConstructedCodecControls', 'test_lexical_mismatched_and_unterminated_structure'), ('ConstructedCodecControls', 'test_visit_boundary_is_inclusive_and_no_refund'), ('ConstructedCodecControls', 'test_byte_work_boundary_is_inclusive_and_precharged'), ('ConstructedCodecControls', 'test_expanded_writer_actual_boundary_and_preallocation'), ('ConstructedCodecControls', 'test_shape_depth_boundary'), ('ConstructedCodecControls', 'test_reference_expansion_reserves_all_nodes_before_clone'), ('ConstructedCodecControls', 'test_oversized_primitive_and_float_never_escape_as_python_errors'), ('ConstructedCodecControls', 'test_controlled_failures_wrap_as_evidence_invalid_with_raw_hash'), ('ConstructedCodecControls', 'test_exact_base_pass_reservations_on_constructed_shell'), ('ConstructedCodecControls', 'test_identity_index_extra_work_is_not_a_free_preflight'), ('ConstructedCodecControls', 'test_exact_wire_limit_is_not_classified_as_too_large'), ('ConstructedCodecControls', 'test_digest_hex_reserves_source_and_destination_before_conversion'), ('ConstructedCodecControls', 'test_global_integer_overflow_precedes_unknown_sum_code'), ('ConstructedCodecControls', 'test_global_integer_overflow_at_integer_value_site'), ('ConstructedCodecControls', 'test_global_integer_endpoints_remain_exact_at_admissible_leaves'), ('ConstructedCodecControls', 'test_identity_uuid_equality_charges_both_operands'), ('ConstructedCodecControls', 'test_identity_uuid_ordering_charges_second_comparison'), ('ConstructedCodecControls', 'test_identity_index_uses_first_duplicate_introduction'), ('ConstructedCodecControls', 'test_parser_objects_have_only_bounded_identity_key_vocabulary'), ('ConstructedCodecControls', 'test_negative_zero_wrong_type_slot_rejects_encoding_precontext'))))


def source_snapshot():
    observed = {}
    for relative, size, digest in _SOURCE_BINDINGS:
        path = ROOT / relative
        if path.resolve() != path:
            raise RuntimeError('Source symlink is not permitted: ' + relative)
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                raise RuntimeError('Source type or size mismatch: ' + relative)
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                raw = stream.read(size + 1)
            after = os.fstat(descriptor)
            identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
            if identity(before) != identity(after) or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                raise RuntimeError('Source identity mismatch: ' + relative)
            observed[relative] = (digest, identity(after))
        finally:
            os.close(descriptor)
    return observed


def load_fixed(index, relative):
    name = '_stage4_public_regression_' + str(index)
    if name in sys.modules:
        raise RuntimeError('Fixed test module already loaded')
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError('Fixed test module loader unavailable')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    if Path(module.__file__).resolve() != ROOT / relative:
        raise RuntimeError('Fixed test module location changed')
    return module


def run_selection(indexes, expected):
    tests = []
    for index in indexes:
        relative, names = _SELECTION[index]
        module = load_fixed(index, relative)
        for class_name, method_name in names:
            cls = module.__dict__.get(class_name)
            if (type(cls) is not type or not issubclass(cls, unittest.TestCase) or
                    cls.__module__ != module.__name__ or method_name not in cls.__dict__):
                raise RuntimeError('Fixed public regression selector changed')
            tests.append(cls(method_name))
    suite = unittest.TestSuite(tests)
    if suite.countTestCases() != expected:
        raise RuntimeError('Fixed public regression count changed')
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, failfast=False, buffer=False).run(suite)
    passed = (result.wasSuccessful() and result.testsRun == expected and not result.skipped and
              not result.expectedFailures and not result.unexpectedSuccesses)
    return {'passed': bool(passed), 'expected': expected, 'tests_run': result.testsRun,
            'failures': len(result.failures), 'errors': len(result.errors),
            'skipped': len(result.skipped), 'expected_failures': len(result.expectedFailures),
            'unexpected_successes': len(result.unexpectedSuccesses)}


def main():
    if len(sys.argv) != 1:
        raise RuntimeError('This fixed regression entry accepts no selectors or workload arguments')
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and sys.flags.optimize == 0):
        raise RuntimeError('Public pure controls require unoptimized -I -S -B')
    if any(name == 'lib' or name.startswith('lib.') for name in sys.modules):
        raise RuntimeError('Project helper namespace already loaded')
    before = source_snapshot()
    sys.path.insert(0, str(ROOT / 'scripts'))
    earlier = run_selection(range(4), 47)
    if any(name.startswith('lib.stage4_') for name in sys.modules):
        raise RuntimeError('Earlier-stage pure controls unexpectedly loaded Stage4 helpers')
    codec = run_selection((4,), 53)
    after = source_snapshot()
    if before != after:
        raise RuntimeError('Public regression source changed')
    passed = earlier['passed'] and codec['passed']
    report = {'schema': 'stage4-public-fixed-pure-regressions-v1',
              'status': 'Passed' if passed else 'Failed', 'tests_expected': 100,
              'tests_run': earlier['tests_run'] + codec['tests_run'],
              'earlier_stages': earlier, 'constructed_codec': codec,
              'source_files': len(_SOURCE_BINDINGS), 'source_preserved': True,
              'actual_build_process_or_corpus_authority': False}
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
