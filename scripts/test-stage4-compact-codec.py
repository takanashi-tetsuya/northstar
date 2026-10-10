"""Constructed V2 codec fixtures, separate from actual semantic evidence.

These controls never establish a positive owner execution or replace any of the
136 actual-frame semantic controls. Private leaf calls exercise codec machinery;
public decode remains fixed to Envelope and never takes an input-selected root.
"""
import copy
import hashlib
import json
import unittest

from lib import stage4_compact as codec
from lib import stage4_case as reader


def shell():
    # A constructed rejection-shaped codec object, deliberately no owner facts.
    return {'schema': reader.EVIDENCE_SCHEMA, 'entry': reader.ENTRY,
            'input_sha256': '0' * 64, 'rejection': 'Json', 'execution': None,
            'resource_stop': None, 'identity_map': [], 'facts': [],
            'observation_status': {'kind': 'Complete', 'data': {}}}


def frame_payload(payload):
    return codec.FRAME_TAG + str(len(payload)).encode('ascii') + b'\n' + payload + codec.TRAILER


def raw_json(value):
    # Test corruption helper, intentionally outside the qualifying codec path.
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def payload_of(frame):
    return json.loads(frame.split(b'\n', 1)[1][:-len(codec.TRAILER)])


def altered(change):
    value = payload_of(codec.encode_compact_frame(shell()))
    change(value)
    return frame_payload(raw_json(value))


class ConstructedCodecControls(unittest.TestCase):
    def rejects(self, raw, reason):
        with self.assertRaises(codec.Stage4Invalid) as caught:
            codec.decode_compact_frame(raw)
        self.assertEqual(str(caught.exception), reason)

    def leaf(self, value, node, introductions=()):
        walk = codec._Walk(codec._Budget(), 'decode')
        walk.set_introductions(list(introductions))
        return walk.walk(value, node, 'expand')

    def leaf_rejects(self, value, node, reason, introductions=()):
        with self.assertRaises(codec.Stage4Invalid) as caught:
            self.leaf(value, node, introductions)
        self.assertEqual(str(caught.exception), reason)

    def test_constructed_rejection_shape_roundtrip(self):
        value = shell()
        frame = codec.encode_compact_frame(value)
        self.assertEqual(codec.decode_compact_frame(frame), value)
        self.assertEqual(codec.encode_compact_frame(codec.decode_compact_frame(frame)), frame)

    def test_named_field_order_does_not_choose_slots(self):
        value = shell()
        reordered = dict(reversed(list(value.items())))
        self.assertEqual(codec.encode_compact_frame(value), codec.encode_compact_frame(reordered))

    def test_wrapper_declares_actual_named_commitment(self):
        value = shell()
        p = payload_of(codec.encode_compact_frame(value))
        expanded = raw_json(value)
        self.assertEqual(p[:3], [codec.MARKER, len(expanded), hashlib.sha256(expanded).hexdigest()])
        self.assertEqual(len(p[3]), 9)
        self.assertEqual(p[3][8], [0, []])

    def test_explicit_v2_rejects_v1_tag(self):
        frame = codec.encode_compact_frame(shell()).replace(codec.FRAME_TAG, reader.FRAME_TAG, 1)
        self.rejects(frame, codec.SCHEMA)

    def test_explicit_v1_rejects_v2_tag(self):
        with self.assertRaises(reader.Stage4Invalid):
            reader.parse_frame(codec.encode_compact_frame(shell()), wire_version='V1')

    def test_no_unknown_version_or_auto_selection(self):
        for version in ('auto', 'V3', None):
            with self.subTest(version=version), self.assertRaises(reader.Stage4Invalid) as caught:
                reader.parse_frame(codec.encode_compact_frame(shell()), wire_version=version)
            self.assertEqual(str(caught.exception), codec.SCHEMA)

    def test_whole_frame_cap(self):
        self.rejects(b'x' * (codec.MAX_FRAME + 1), 'TooLarge:Frame')

    def test_wrong_marker(self):
        self.rejects(altered(lambda p: p.__setitem__(0, 'unknown')), codec.SCHEMA)

    def test_marker_wrong_type(self):
        self.rejects(altered(lambda p: p.__setitem__(0, 2)), codec.JSON)

    def test_wrapper_extra_missing_wrong_container(self):
        p = payload_of(codec.encode_compact_frame(shell()))
        for value in (p + [None], p[:-1], {'v': p}):
            with self.subTest(value=value):
                self.rejects(frame_payload(raw_json(value)), codec.JSON)

    def test_envelope_tuple_arity(self):
        self.rejects(altered(lambda p: p[3].append(None)), codec.JSON)
        self.rejects(altered(lambda p: p[3].pop()), codec.JSON)

    def test_unknown_sum_codes_are_json(self):
        for code in (-1, 2, 999, True, 0.0, '0'):
            with self.subTest(code=code):
                self.rejects(altered(lambda p: p[3].__setitem__(8, [code, []])), codec.JSON)

    def test_wrong_tuple_slot_type(self):
        self.rejects(altered(lambda p: p[3].__setitem__(7, {})), codec.JSON)

    def test_no_reference_or_pool_syntax_at_other_positions(self):
        for value in (0, {'ref': 0}, {'pool': [[]], 'root': 0}):
            with self.subTest(value=value):
                self.rejects(altered(lambda p: p[3].__setitem__(7, value)), codec.JSON)

    def test_unknown_and_duplicate_named_map_keys(self):
        label = {'kind': 'Opaque', 'data': {'ordinal': 1}}
        intro = {'label': label, 'first_seq': 0, 'locus': 'Frame'}
        self.rejects(altered(lambda p: p[3].__setitem__(6, [dict(intro, unknown=0)])), codec.JSON)
        value = shell(); value['identity_map'] = [intro]
        frame = codec.encode_compact_frame(value)
        payload = frame.split(b'\n', 1)[1][:-len(codec.TRAILER)]
        self.rejects(frame_payload(payload.replace(b'"first_seq":0', b'"first_seq":0,"first_seq":0')), codec.JSON)

    def test_named_identity_map_must_not_be_positional(self):
        self.rejects(altered(lambda p: p[3].__setitem__(6, [[[1, 1], 0, 'Frame']])), codec.JSON)

    def test_declared_size_bounds_and_type(self):
        for value in (-1, codec.MAX_EXPANDED + 1):
            self.rejects(altered(lambda p: p.__setitem__(1, value)), codec.BOUND)
        for value in (True, 1.0, '1'):
            self.rejects(altered(lambda p: p.__setitem__(1, value)), codec.JSON)

    def test_declared_size_and_digest_mismatch(self):
        self.rejects(altered(lambda p: p.__setitem__(1, p[1] + 1)), codec.ENCODING)
        self.rejects(altered(lambda p: p.__setitem__(2, 'f' * 64)), codec.ENCODING)

    def test_digest_noncanonical_hex(self):
        for digest in ('A' * 64, 'g' * 64, '0' * 63):
            self.rejects(altered(lambda p: p.__setitem__(2, digest)), codec.ENCODING)

    def test_length_trailer_duplicate_and_truncation(self):
        f = codec.encode_compact_frame(shell())
        for bad in (f[:-1], f + f, codec.FRAME_TAG + b'0' + f[len(codec.FRAME_TAG):],
                    f.replace(codec.TRAILER, b'\nEND\n')):
            self.rejects(bad, codec.ENCODING)

    def test_canonical_whitespace_escape_and_negative_zero(self):
        f = codec.encode_compact_frame(shell())
        p = f.split(b'\n', 1)[1][:-len(codec.TRAILER)]
        for bad in (p + b' ', p.replace(b'northstar', b'\\u006eorthstar', 1),
                    p.replace(b'[0,[]]', b'[-0,[]]')):
            self.rejects(frame_payload(bad), codec.ENCODING)

    def test_invalid_raw_utf8(self):
        self.rejects(frame_payload(b'["\xff"]'), codec.JSON)

    def test_lone_surrogates_are_controlled_json(self):
        f = codec.encode_compact_frame(shell())
        p = f.split(b'\n', 1)[1][:-len(codec.TRAILER)]
        for escape in (b'\\ud800', b'\\udfff'):
            self.rejects(frame_payload(p.replace(b'Json', escape)), codec.JSON)
        value = shell(); value['schema'] = '\ud800'
        with self.assertRaises(codec.Stage4Invalid) as caught:
            codec.encode_compact_frame(value)
        self.assertEqual(str(caught.exception), codec.JSON)

    def test_canonical_unicode_controls_bytes_and_no_normalization(self):
        for text in ('', '\0\b\f\n\r\t\x01"\\/', 'é', 'e\u0301', '\u2028\u2029', '😀'):
            with self.subTest(text=text):
                decoded = self.leaf([0, text], ['bytes', 16384])
                self.assertEqual(decoded, text.encode('utf-8').hex())
                self.assertEqual(codec._encode_bytes(decoded, 16384, codec._Budget()), [0, text])

    def test_surrogate_pair_is_scalar_but_escape_spelling_is_noncanonical(self):
        b = codec._Budget()
        self.assertEqual(codec._json_payload(b'"\\ud83d\\ude00"', b), '😀')
        value = shell(); value['schema'] = '😀'
        f = codec.encode_compact_frame(value)
        p = f.split(b'\n', 1)[1][:-len(codec.TRAILER)]
        self.rejects(frame_payload(p.replace('😀'.encode('utf-8'), b'\\ud83d\\ude00')), codec.ENCODING)

    def test_hex_mode_requires_non_utf8(self):
        self.assertEqual(self.leaf([1, '00ff80'], ['bytes', 4096]), '00ff80')
        for text in ('', '00', 'c3a9', '61'):
            self.leaf_rejects([1, text], ['bytes', 4096], codec.ENCODING)

    def test_byte_mode_type_arity_and_code(self):
        for value in ([True, ''], [0.0, ''], ['0', ''], [0], [0, '', None], ''):
            self.leaf_rejects(value, ['bytes', 4096], codec.JSON)
        for mode in (-1, 2):
            self.leaf_rejects([mode, ''], ['bytes', 4096], codec.ENCODING)

    def test_hex_case_parity_and_invalid_digits(self):
        for text in ('FF', 'f', 'gg'):
            self.leaf_rejects([1, text], ['bytes', 4096], codec.ENCODING)

    def test_bytes_original_bounds_and_text_nul(self):
        for cap in (64, 4096, 16384):
            self.assertEqual(len(self.leaf([0, 'a' * cap], ['bytes', cap])), 2 * cap)
            self.leaf_rejects([0, 'a' * (cap + 1)], ['bytes', cap], codec.BOUND)
        self.leaf_rejects('\0', ['text', 64], codec.BOUND)

    def test_identity_reference_types_and_range(self):
        intro = [{'label': {'kind': 'Opaque', 'data': {'ordinal': 1}}, 'first_seq': 1, 'locus': 'Frame'}]
        for ref in (True, False, 0.0, '0', None, {'ref': 0}):
            self.leaf_rejects(ref, ['EvidenceId'], codec.JSON, intro)
        for ref in (-1, 1, 2 ** 64 - 1):
            self.leaf_rejects(ref, ['EvidenceId'], codec.BOUND, intro)
        self.leaf_rejects(0, ['EvidenceId'], codec.BOUND)

    def test_reference_clones_complete_labels_without_mutable_alias(self):
        intro = [{'label': {'kind': 'Opaque', 'data': {'ordinal': 1}}, 'first_seq': 1, 'locus': 'Frame'}]
        a = self.leaf(0, ['EvidenceId'], intro)
        b = self.leaf(0, ['EvidenceId'], intro)
        a['data']['ordinal'] = 2
        self.assertEqual(b, intro[0]['label'])
        self.assertIsNot(b, intro[0]['label'])
        self.assertIsNot(b['data'], intro[0]['label']['data'])

    def test_bounded_integer_types_and_endpoints(self):
        for value in (0, 2 ** 64 - 1):
            self.assertEqual(self.leaf(value, ['int', 0, 2 ** 64 - 1]), value)
        for value in (-1, 2 ** 64):
            self.leaf_rejects(value, ['int', 0, 2 ** 64 - 1], codec.BOUND)
        for value in (True, 0.0, '0'):
            self.leaf_rejects(value, ['int', 0, 2 ** 64 - 1], codec.JSON)

    def test_lexical_scan_before_generic_parser(self):
        # Failure is fixed before json.loads would see excessive nesting/token.
        for payload in (b'[' * 49 + b']' * 49, b'1' * 21):
            with self.assertRaises(codec.Stage4Invalid) as caught:
                codec._json_payload(payload, codec._Budget())
            self.assertEqual(str(caught.exception), codec.BOUND)
        codec._json_payload(b'[' * 48 + b'0' + b']' * 48, codec._Budget())
        self.assertEqual(codec._json_payload(b'"[[[\\"\\\\]]]"', codec._Budget()), '[[["\\]]]')

    def test_lexical_mismatched_and_unterminated_structure(self):
        for payload in (b'[}', b'"unfinished', b'[', b'01', b'NaN', b'Infinity', b'1.0'):
            with self.assertRaises(codec.Stage4Invalid) as caught:
                codec._json_payload(payload, codec._Budget())
            self.assertEqual(str(caught.exception), codec.JSON)

    def test_visit_boundary_is_inclusive_and_no_refund(self):
        b = codec._Budget(visits=codec.MAX_VISITS - 1)
        b.values(1)
        with self.assertRaises(codec.Stage4Invalid) as caught:
            b.values(1)
        self.assertEqual(str(caught.exception), codec.BOUND)
        self.assertEqual(b.visits, codec.MAX_VISITS)

    def test_byte_work_boundary_is_inclusive_and_precharged(self):
        b = codec._Budget(byte_work=codec.MAX_BYTE_WORK - 4)
        self.assertEqual(codec._scalar('a', b), 1)
        with self.assertRaises(codec.Stage4Invalid) as caught:
            codec._scalar('a', b)
        self.assertEqual(str(caught.exception), codec.BOUND)
        self.assertEqual(b.byte_work, codec.MAX_BYTE_WORK)

    def test_expanded_writer_actual_boundary_and_preallocation(self):
        b = codec._Budget()
        w = codec._Writer(b, codec.MAX_EXPANDED)
        w.size = codec.MAX_EXPANDED - 1
        w.emit(b'x')
        before = b.byte_work
        with self.assertRaises(codec.Stage4Invalid) as caught:
            w.emit(b'y')
        self.assertEqual(str(caught.exception), codec.BOUND)
        self.assertEqual((w.size, b.byte_work), (codec.MAX_EXPANDED, before))

    def test_shape_depth_boundary(self):
        walk = codec._Walk(codec._Budget(), 'decode')
        self.assertTrue(walk.walk(True, ['bool'], 'expand', depth=48))
        with self.assertRaises(codec.Stage4Invalid) as caught:
            walk.walk(True, ['bool'], 'expand', depth=49)
        self.assertEqual(str(caught.exception), codec.BOUND)

    def test_reference_expansion_reserves_all_nodes_before_clone(self):
        walk = codec._Walk(codec._Budget(visits=codec.MAX_VISITS - 13), 'decode')
        walk.set_introductions([{'label': {'kind': 'Opaque', 'data': {'ordinal': 1}}, 'first_seq': 1, 'locus': 'Frame'}])
        with self.assertRaises(codec.Stage4Invalid) as caught:
            walk.walk(0, ['EvidenceId'], 'expand')
        self.assertEqual(str(caught.exception), codec.BOUND)

    def test_oversized_primitive_and_float_never_escape_as_python_errors(self):
        for value, reason in ((b'9' * 1000, codec.BOUND), (b'1e999', codec.JSON)):
            self.rejects(frame_payload(value), reason)

    def test_controlled_failures_wrap_as_evidence_invalid_with_raw_hash(self):
        frame = frame_payload(b'["bad"]')
        result = reader.inspect_semantics(b'not-input', frame, wire_version='V2')
        self.assertEqual(result.category, 'EvidenceInvalid')
        self.assertEqual(result.findings, (codec.JSON,))
        self.assertEqual(result.evidence_sha256, hashlib.sha256(frame).hexdigest())
        self.assertNotEqual(result.findings, (reader.TARGET,))

    def test_exact_base_pass_reservations_on_constructed_shell(self):
        # Hand-counted: N_E=12/N_C=16, plus one empty-map index scan.
        encode_budget=codec._Budget()
        framed=codec._encode(shell(),encode_budget)
        self.assertEqual(encode_budget.visits,2*12+16+1)
        decode_budget=codec._Budget()
        self.assertEqual(codec._decode(framed,decode_budget),shell())
        self.assertEqual(decode_budget.visits,3*12+2*16+1)

    def test_identity_index_extra_work_is_not_a_free_preflight(self):
        value=shell()
        value['identity_map']=[{'label':{'kind':'Opaque','data':{'ordinal':1}},'first_seq':0,'locus':'Frame'}]
        # Seven added nodes; extra map1 + introduction1 + label4 visits.
        encode_budget=codec._Budget();framed=codec._encode(value,encode_budget)
        self.assertEqual(encode_budget.visits,2*19+23+6)
        decode_budget=codec._Budget();codec._decode(framed,decode_budget)
        self.assertEqual(decode_budget.visits,3*19+2*23+6)

    def test_exact_wire_limit_is_not_classified_as_too_large(self):
        length=codec.MAX_FRAME-len(codec.FRAME_TAG)-6-1-len(codec.TRAILER)
        framed=frame_payload(b' '*length)
        self.assertEqual(len(framed),codec.MAX_FRAME)
        self.rejects(framed,codec.JSON)

    def test_digest_hex_reserves_source_and_destination_before_conversion(self):
        digest=hashlib.sha256(b'')
        exact=codec._Budget(byte_work=codec.MAX_BYTE_WORK-96)
        self.assertEqual(codec._digest_hex(digest,exact),hashlib.sha256(b'').hexdigest())
        self.assertEqual(exact.byte_work,codec.MAX_BYTE_WORK)
        short=codec._Budget(byte_work=codec.MAX_BYTE_WORK-95)
        with self.assertRaises(codec.Stage4Invalid) as caught:
            codec._digest_hex(digest,short)
        self.assertEqual(str(caught.exception),codec.BOUND)
        self.assertEqual(short.byte_work,codec.MAX_BYTE_WORK-95)

    def test_global_integer_overflow_precedes_unknown_sum_code(self):
        # Additive contract clarification: these tokens are legal JSON integers,
        # but globally outside the original signed/unsigned64 value domain.
        for code in (-(2**63)-1,2**64):
            self.rejects(altered(lambda p:p[3].__setitem__(8,[code,[]])),codec.BOUND)
        for code in (-(2**63),2**64-1):
            self.rejects(altered(lambda p:p[3].__setitem__(8,[code,[]])),codec.JSON)

    def test_global_integer_overflow_at_integer_value_site(self):
        for value in (-(2**63)-1,2**64):
            self.rejects(altered(lambda p:p.__setitem__(1,value)),codec.BOUND)

    def test_global_integer_endpoints_remain_exact_at_admissible_leaves(self):
        for value in (-(2**63),2**64-1):
            parsed=codec._json_payload(str(value).encode('ascii'),codec._Budget())
            self.assertIs(type(parsed),int)
            self.assertEqual(parsed,value)
            self.assertEqual(self.leaf(parsed,['int',-(2**63),2**64-1]),value)

    def test_identity_uuid_equality_charges_both_operands(self):
        key=(0,b'0'*36)
        exact=codec._Walk(codec._Budget(byte_work=codec.MAX_BYTE_WORK-72),'decode')
        self.assertEqual(exact.compare_keys(key,(0,bytes(bytearray(key[1])))),0)
        self.assertEqual(exact.budget.byte_work,codec.MAX_BYTE_WORK)
        short=codec._Walk(codec._Budget(byte_work=codec.MAX_BYTE_WORK-71),'decode')
        with self.assertRaises(codec.Stage4Invalid) as caught:
            short.compare_keys(key,key)
        self.assertEqual(str(caught.exception),codec.BOUND)
        self.assertEqual(short.budget.byte_work,codec.MAX_BYTE_WORK-71)

    def test_identity_uuid_ordering_charges_second_comparison(self):
        walk=codec._Walk(codec._Budget(),'decode')
        self.assertEqual(walk.compare_keys((0,b'0'*36),(0,b'1'*36)),-1)
        self.assertEqual(walk.budget.byte_work,144)

    def test_identity_index_uses_first_duplicate_introduction(self):
        walk=codec._Walk(codec._Budget(),'encode')
        self.assertEqual(walk.identity_lookup((1,2),7),7)
        self.assertEqual(walk.identity_lookup((1,1),3),3)
        self.assertEqual(walk.identity_lookup((1,2),8),7)
        self.assertEqual(walk.identity_lookup((1,2)),7)
        self.assertEqual(len(walk.identity_index),2)

    def test_parser_objects_have_only_bounded_identity_key_vocabulary(self):
        for payload in (b'{"arbitrary":0}',b'{"label":0,"kind":0,"data":0,"uuid":0}',
                        b'{"kind":0,"kind":1}'):
            with self.assertRaises(codec.Stage4Invalid) as caught:
                codec._json_payload(payload,codec._Budget())
            self.assertEqual(str(caught.exception),codec.JSON)
        self.assertEqual(codec._json_payload(b'{"kind":"Opaque","data":{"ordinal":1}}',codec._Budget()),
                         {'kind':'Opaque','data':{'ordinal':1}})

    def test_negative_zero_wrong_type_slot_rejects_encoding_precontext(self):
        value=payload_of(codec.encode_compact_frame(shell()))
        value[3][0]=0  # The original schema slot is Text, not integer.
        payload=raw_json(value).replace(b'[0,',b'[-0,',1)
        self.rejects(frame_payload(payload),codec.ENCODING)
        self.rejects(frame_payload(raw_json(value)),codec.JSON)


if __name__ == '__main__':
    unittest.main()
