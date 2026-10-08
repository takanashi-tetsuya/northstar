"""Independent output-only V2 inverse and control repacker.

No producer import, executable discovery, fallback, value pool, input codec or
qualification API exists here. The fixed sibling table is the approved Envelope
closure, not an input-selected grammar. All public decoding is explicitly V2.
The repacker is for constructed codec fixtures and negative copies, never proof
that an owner executed or that a historical V1 occurrence emitted V2.
"""
from dataclasses import dataclass
from pathlib import Path
import hashlib
import json

FRAME_TAG = b'\x1eNORTHSTAR_STAGE4_COMPOSITION_V2 '
TRAILER = b'\n\x1eEND\n'
MARKER = 'northstar-stage4-composition-compact-v2'
MAX_FRAME = 131072
MAX_EXPANDED = 4194304
MAX_VISITS = 262144
MAX_BYTE_WORK = 33554432
MAX_WIRE_DEPTH = MAX_SHAPE_DEPTH = 48
DESIGN_SHA256 = '40f6fec8ce8a2558502b0747c55b46d5e39450a97753f5c6eb5ce4b377176698'
NUMBER_CLARIFICATION_SHA256 = 'cafc85014790bba40b7172b240f3fd63686a8f1f218c3646b3ae0c085a729e75'
SHAPES_SHA256 = '0d28af4728b2a9fb08abf6408d0b5a970442307c69eae93cd225ab436622f7e4'
ORIGINAL_SHAPES_SHA256 = 'fc481c94bbd99e3891235b54f32450ec951c41ab4d56b3b04477ed3c01d30e38'
JSON = 'Json:Compact'
BOUND = 'Bound:Compact'
ENCODING = 'Encoding:Compact'
SCHEMA = 'Schema:CompactVersion'
HEX_DIGITS = frozenset('0123456789abcdef')
UUID_HYPHENS = (8, 13, 18, 23)
_NAMED_KEYS = (('label', b'label'), ('first_seq', b'first_seq'),
               ('locus', b'locus'), ('kind', b'kind'), ('data', b'data'),
               ('uuid', b'uuid'), ('ordinal', b'ordinal'))


class Stage4Invalid(ValueError):
    """Controlled wire/input failure; never a semantic invariant finding."""


def _need(ok, reason=JSON):
    if not ok:
        raise Stage4Invalid(reason)


@dataclass
class _Budget:
    visits: int = 0
    byte_work: int = 0

    def values(self, count):
        _need(type(count) is int and 0 <= count <= MAX_VISITS - self.visits, BOUND)
        self.visits += count

    def work(self, count):
        _need(type(count) is int and 0 <= count <= MAX_BYTE_WORK - self.byte_work, BOUND)
        self.byte_work += count


def _scalar(text, budget):
    _need(type(text) is str)
    # Python integer arithmetic does not wrap. The subtraction check in work()
    # occurs before this scan and before any UTF-8 encoding can allocate.
    budget.work(4 * len(text))
    size = 0
    for char in text:
        cp = ord(char)
        _need(not 0xd800 <= cp <= 0xdfff)
        size += 1 if cp < 0x80 else 2 if cp < 0x800 else 3 if cp < 0x10000 else 4
    return size


def _utf8(text, budget, size=None):
    if size is None:
        size = _scalar(text, budget)
    budget.work(2 * size)
    try:
        return text.encode('utf-8', 'strict')
    except UnicodeError as error:
        raise Stage4Invalid(JSON) from error


def _equal(a, b, budget):
    budget.work(len(a) + len(b))
    return a == b


def _fields(value, names, budget):
    _need(type(value) is dict and len(value) == len(names))
    for key in value:
        size = _scalar(key, budget)
        # Account dynamic-key hashing/lookup input before consulting the closed
        # constant names. No content-interning or arbitrary shape lookup exists.
        budget.work(size)
        _need(key in names)


def _table():
    raw = Path(__file__).with_name('stage4_compact_shapes.json').read_bytes()
    _need(len(raw) == 122189 and hashlib.sha256(raw).hexdigest() == SHAPES_SHA256,
          'ReaderSource:CompactShapeDigest')
    table = json.loads(raw)
    _need(table['root'] == 'Envelope' and table['shape_count'] == 231 and
          table['source_table_sha256'] == ORIGINAL_SHAPES_SHA256,
          'ReaderSource:CompactShapeBinding')
    return table['shapes']


SHAPES = _table()


def _json_payload(payload, budget):
    # Strict raw UTF-8 is checked BEFORE the generic JSON parser. The decoded
    # string is used by that parser, so there is no second uncharged raw decode.
    budget.work(2 * len(payload))
    try:
        text = payload.decode('utf-8', 'strict')
    except UnicodeError as error:
        raise Stage4Invalid(JSON) from error
    budget.work(len(payload))
    stack = []
    quoted = escaped = False
    token = 0
    for byte in payload:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            continue
        if byte == 34:
            quoted = True
            token = 0
        elif byte in (91, 123):
            _need(len(stack) < MAX_WIRE_DEPTH, BOUND)
            stack.append(byte)
            token = 0
        elif byte in (93, 125):
            _need(bool(stack) and stack.pop() == (91 if byte == 93 else 123))
            token = 0
        elif byte in (9, 10, 13, 32, 44, 58):
            token = 0
        else:
            token += 1
            _need(token <= 20, BOUND)
    _need(not quoted and not escaped and not stack)

    def pairs(items):
        # Only the unchanged named identity-map descendants can be objects in
        # legal V2. Canonicalize their <=3 keys to fixed source constants before
        # authored dict insertion, avoiding arbitrary-key hashing/collisions.
        _need(len(items) <= 3)
        out = {}
        seen = 0
        for key, value in items:
            size = _scalar(key, budget)
            _need(size <= 9)
            encoded = _utf8(key, budget, size)
            selected = None
            for i, (name, literal) in enumerate(_NAMED_KEYS):
                if _equal(encoded, literal, budget):
                    selected = (i, name)
                    break
            _need(selected is not None)
            i, name = selected
            _need(not (seen & (1 << i)))
            seen |= 1 << i
            out[name] = value
        return out

    def reject_number(_):
        raise Stage4Invalid(JSON)

    def integer(token):
        # Outside the global original integer domain is Bound before shape
        # context; legal-domain unknown sum codes still are Json.
        _need(token != '-0', ENCODING)
        value = int(token)
        _need(-(1 << 63) <= value <= (1 << 64) - 1, BOUND)
        return value

    budget.work(len(payload))
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_float=reject_number,
                          parse_constant=reject_number, parse_int=integer)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, Stage4Invalid):
            raise
        raise Stage4Invalid(JSON) from error


def _extract(raw, budget):
    _need(type(raw) is bytes)
    _need(len(raw) <= MAX_FRAME, 'TooLarge:Frame')
    budget.work(len(raw))
    _need(raw.startswith(FRAME_TAG), SCHEMA)
    end = raw.find(b'\n', len(FRAME_TAG))
    _need(end >= 0, ENCODING)
    digit_count = end - len(FRAME_TAG)
    _need(1 <= digit_count <= 6, ENCODING)
    budget.work(digit_count)
    digits = raw[len(FRAME_TAG):end]
    _need(all(48 <= x <= 57 for x in digits) and
          (len(digits) == 1 or digits[0] != 48), ENCODING)
    length = int(digits)
    start = end + 1
    _need(start + length + len(TRAILER) == len(raw), ENCODING)
    budget.work(len(TRAILER))
    tail = raw[start + length:]
    _need(_equal(tail, TRAILER, budget), ENCODING)
    budget.work(length)
    return raw[start:start + length]


def _leaf(value, node, budget):
    tag = node[0]
    if tag == 'bool':
        _need(type(value) is bool)
    elif tag == 'int':
        _need(type(value) is int)
        _need(node[1] <= value <= node[2], BOUND)
    elif tag in ('text', 'enum', 'hex', 'bytes', 'Id'):
        size = _scalar(value, budget)
        if tag == 'text':
            _need(size <= node[1], BOUND)
            budget.work(size)
            _need('\0' not in value, BOUND)
        elif tag == 'enum':
            budget.work(size)
            _need(value in node[1])
        elif tag in ('hex', 'bytes'):
            # Length bound is checked before character inspection/conversion.
            _need(size <= 2 * node[1], BOUND)
            if tag == 'hex':
                _need(size == 2 * node[1], ENCODING)
            budget.work(size)
            _need(len(value) % 2 == 0 and all(x in HEX_DIGITS for x in value), ENCODING)
        else:
            budget.work(size)
            _need(len(value) == 36 and all(c == '-' if i in UUID_HYPHENS else c in HEX_DIGITS
                                        for i, c in enumerate(value)), ENCODING)
    else:
        raise Stage4Invalid('ReaderSource:CompactUnknownShape')
    return value


def _label_node(value, budget):
    _fields(value, ('kind', 'data'), budget)
    size = _scalar(value['kind'], budget)
    budget.work(size)
    kind = value['kind']
    _need(kind in ('Fixed', 'Opaque'))
    child = ['object', [['uuid', ['Id']]]] if kind == 'Fixed' else ['object', [['ordinal', ['int', 0, 255]]]]
    return ['object', [['kind', ['enum', ['Fixed', 'Opaque']]], ['data', child]]]


def _valid_utf8(raw, budget):
    # Reserve a full-size destination even on failure: work is never refunded.
    budget.work(2 * len(raw))
    try:
        return raw.decode('utf-8', 'strict')
    except UnicodeError:
        return None


def _unhex(text, cap, budget):
    _leaf(text, ['bytes', cap], budget)
    budget.work(len(text) + len(text) // 2)
    return bytes.fromhex(text)


def _decode_bytes(value, cap, budget):
    _need(type(value) is list and len(value) == 2)
    budget.values(4)  # two additional compact nodes, two visits each
    mode, content = value
    _need(type(mode) is int)
    _need(mode in (0, 1), ENCODING)
    size = _scalar(content, budget)
    if mode == 0:
        _need(size <= cap, BOUND)
        raw = _utf8(content, budget, size)
    else:
        raw = _unhex(content, cap, budget)
        _need(_valid_utf8(raw, budget) is None, ENCODING)
    budget.work(len(raw) + 2 * len(raw))
    return raw.hex()


def _encode_bytes(value, cap, budget):
    raw = _unhex(value, cap, budget)
    text = _valid_utf8(raw, budget)
    if text is None:
        # The immutable validated canonical hex leaf can be borrowed safely.
        return [1, value]
    return [0, text]


class _Walk:
    def __init__(self, budget, operation):
        self.budget = budget
        self.operation = operation
        self.introductions = None
        self.identity_index = []

    def reserve(self, expanded, compact, phase):
        if phase == 'expand':
            self.budget.values(3 * expanded + 2 * compact)
        elif phase == 'project' and self.operation == 'encode':
            # Expanded nodes were reserved by the first canonical count pass.
            self.budget.values(compact)

    def identity_key(self, label):
        # This bounded lookup is ONLY the existing identity map. Each additional
        # terminal inspection is charged, rather than a free subtree preflight.
        self.budget.values(4)
        node = _label_node(label, self.budget)
        kind = _leaf(label['kind'], ['enum', ['Fixed', 'Opaque']], self.budget)
        field, leaf = node[1][1][1][1][0]
        _fields(label['data'], (field,), self.budget)
        value = _leaf(label['data'][field], leaf, self.budget)
        # Native dictionary hashing/collision/equality work is deliberately
        # avoided. Fixed UUID bytes get a charged bounded conversion; opaque
        # ordinals stay exact integers in the private sorted terminal index.
        return (0, _utf8(value, self.budget, 36)) if kind == 'Fixed' else (1, value)

    def compare_keys(self, left, right):
        if left[0] != right[0]:
            return -1 if left[0] < right[0] else 1
        if left[0] == 0:
            if _equal(left[1], right[1], self.budget):
                return 0
            # Ordering is a second byte comparison, charged independently.
            self.budget.work(len(left[1]) + len(right[1]))
        elif left[1] == right[1]:
            return 0
        return -1 if left[1] < right[1] else 1

    def identity_lookup(self, key, introduction=None):
        # <=64 source introductions, sorted terminal keys, at most seven
        # controlled comparisons. No input-selected map/hash implementation.
        low, high = 0, len(self.identity_index)
        while low < high:
            middle = (low + high) // 2
            existing, index = self.identity_index[middle]
            order = self.compare_keys(key, existing)
            if order == 0:
                return index
            if order < 0:
                high = middle
            else:
                low = middle + 1
        _need(introduction is not None, ENCODING)
        self.identity_index.insert(low, (key, introduction))
        return introduction

    def set_introductions(self, introductions):
        self.introductions = introductions
        if self.operation == 'encode':
            self.budget.values(1)  # extra identity_map-container index scan
            # The first duplicate label retains its index. Whether a duplicate
            # introduction is legal belongs to the unchanged semantic walk.
            for i, item in enumerate(introductions):
                self.budget.values(1)
                key = self.identity_key(item['label'])
                self.identity_lookup(key, i)

    def walk(self, value, node, phase, depth=0, named=False, root=False):
        _need(depth <= MAX_SHAPE_DEPTH, BOUND)
        tag = node[0]
        if tag == 'ref':
            _need(node[1] in SHAPES, 'ReaderSource:CompactUnknownShape')
            return self.walk(value, SHAPES[node[1]], phase, depth + 1, named, node[1] == 'Envelope')
        if tag == 'nullable' and value is not None:
            return self.walk(value, node[1], phase, depth + 1, named)
        if tag in ('IdentityLabel', 'EvidenceId'):
            if tag == 'EvidenceId' and not named and phase == 'expand':
                self.reserve(0, 1, phase)
                _need(type(value) is int)
                _need(self.introductions is not None and 0 <= value < len(self.introductions), BOUND)
                # Clone every occurrence; reserve all four expanded nodes before
                # allocating either dict. Terminal inspection is extra work.
                self.reserve(4, 0, phase)
                label = self.introductions[value]['label']
                # Account the terminal inspection separately, but retain the
                # already validated immutable original scalar without another
                # decode/copy. Every occurrence still owns fresh label dicts.
                self.identity_key(label)
                kind = label['kind']
                field = 'uuid' if kind == 'Fixed' else 'ordinal'
                return {'kind': kind, 'data': {field: label['data'][field]}}
            label_node = _label_node(value, self.budget)
            if tag == 'EvidenceId' and not named and phase == 'project':
                self.reserve(0, 1, phase)
                key = self.identity_key(value)
                return self.identity_lookup(key)
            return self.walk(value, label_node, phase, depth, True)
        if tag == 'bytes' and not named:
            if phase == 'expand':
                self.reserve(1, 1, phase)
                return _decode_bytes(value, node[1], self.budget)
            if phase == 'project':
                self.reserve(0, 3, phase)
                return _encode_bytes(value, node[1], self.budget)
        if tag == 'nullable':
            self.reserve(1, 1, phase)
            _need(value is None)
            return None
        if tag in ('object', 'sum'):
            if tag == 'sum' and not named and phase == 'expand':
                self.reserve(2, 2, phase)  # compact array+code; expanded dict+kind
                _need(type(value) is list and len(value) == 2 and type(value[0]) is int)
                _need(0 <= value[0] < len(node[1]))
                kind, child = node[1][value[0]]
                return {'kind': kind, 'data': self.walk(value[1], child, phase, depth + 1)}
            if tag == 'sum':
                _fields(value, ('kind', 'data'), self.budget)
                size = _scalar(value['kind'], self.budget)
                self.budget.work(size)
                variants = node[1]
                choices = [i for i, (kind, _) in enumerate(variants) if kind == value['kind']]
                _need(len(choices) == 1)
                code = choices[0]
                if phase == 'project' and not named:
                    self.reserve(0, 2, phase)
                    return [code, self.walk(value['data'], variants[code][1], phase, depth + 1)]
                fields = [('kind', ['enum', [x[0] for x in variants]]), ('data', variants[code][1])]
            else:
                fields = node[1]
            self.reserve(1, 1, phase)
            positional = not named and phase == 'expand'
            if positional:
                _need(type(value) is list and len(value) == len(fields))
            else:
                _fields(value, tuple(x[0] for x in fields), self.budget)
            if root:
                # Identity introductions precede facts in the fixed Envelope.
                # There are no EvidenceId values in earlier Envelope slots.
                _need(fields[6][0] == 'identity_map', 'ReaderSource:CompactEnvelopeOrder')
            result = None if phase == 'validate' else ({} if phase == 'expand' or named else [])
            for i, (name, child) in enumerate(fields):
                current = value[i] if positional else value[name]
                child_named = named or (root and name == 'identity_map')
                restored = self.walk(current, child, phase, depth + 1, child_named)
                if phase == 'validate':
                    continue
                if type(result) is dict:
                    result[name] = restored
                else:
                    result.append(restored)
                if root and name == 'identity_map':
                    self.set_introductions(restored if phase == 'expand' else current)
            return value if phase == 'validate' else result
        if tag in ('list', 'array'):
            self.reserve(1, 1, phase)
            _need(type(value) is list)
            _need(len(value) == node[2] if tag == 'array' else len(value) <= node[2], BOUND)
            if phase == 'validate':
                for item in value:
                    self.walk(item, node[1], phase, depth + 1, named)
                return value
            result = []
            for item in value:
                result.append(self.walk(item, node[1], phase, depth + 1, named))
            return result
        self.reserve(1, 1, phase)
        return _leaf(value, node, self.budget)


# Fixed punctuation/escapes avoid dynamic construction before reservation.
_ESCAPES = {34: b'\\"', 92: b'\\\\', 8: b'\\b', 12: b'\\f', 10: b'\\n', 13: b'\\r', 9: b'\\t'}
_CONTROLS = tuple(('\\u%04x' % i).encode('ascii') for i in range(32))


class _Writer:
    def __init__(self, budget, cap, retain=False, hash_output=False, count_expanded=False, cap_reason=BOUND):
        self.budget, self.cap = budget, cap
        self.size = 0
        self.cap_reason = cap_reason
        self.buffer = [] if retain else None
        self.digest = hashlib.sha256() if hash_output else None
        self.count_expanded = count_expanded

    def emit(self, part):
        _need(len(part) <= self.cap - self.size, self.cap_reason)
        self.budget.work(len(part))
        if self.digest is not None:
            self.budget.work(len(part))
        self.size += len(part)
        if self.digest is not None:
            self.digest.update(part)
        if self.buffer is not None:
            self.buffer.append(part)  # retain an immutable chunk; no byte copy

    def string(self, value):
        _scalar(value, self.budget)
        self.emit(b'"')
        for char in value:
            cp = ord(char)
            if cp in _ESCAPES:
                self.emit(_ESCAPES[cp])
            elif cp < 32:
                self.emit(_CONTROLS[cp])
            else:
                size = 1 if cp < 128 else 2 if cp < 2048 else 3 if cp < 65536 else 4
                _need(size <= self.cap - self.size, self.cap_reason)
                self.emit(_utf8(char, self.budget, size))
        self.emit(b'"')

    def write(self, value, node=None, depth=0):
        if node is not None:
            _need(depth <= MAX_SHAPE_DEPTH, BOUND)
        elif type(value) in (dict, list):
            _need(depth <= MAX_WIRE_DEPTH, BOUND)
        if node is not None:
            if node[0] == 'ref':
                return self.write(value, SHAPES[node[1]], depth + 1)
            if node[0] == 'nullable' and value is not None:
                return self.write(value, node[1], depth + 1)
            if node[0] in ('EvidenceId', 'IdentityLabel'):
                node = _label_node(value, self.budget)
            if node[0] in ('object', 'sum'):
                _need(type(value) is dict)
            elif node[0] in ('list', 'array'):
                _need(type(value) is list)
            elif node[0] == 'nullable':
                _need(value is None)
        if self.count_expanded:
            self.budget.values(2)
        if type(value) is dict:
            if node is None:
                fields = [(key, None) for key in value]
            elif node[0] == 'sum':
                _fields(value, ('kind', 'data'), self.budget)
                size = _scalar(value['kind'], self.budget)
                self.budget.work(size)
                variants = dict(node[1])
                _need(value['kind'] in variants)
                fields = [('kind', None), ('data', variants[value['kind']])]
            else:
                _need(node[0] == 'object')
                fields = node[1]
            _fields(value, tuple(x[0] for x in fields), self.budget)
            self.emit(b'{')
            for i, (key, child) in enumerate(fields):
                if i:
                    self.emit(b',')
                self.string(key)
                self.emit(b':')
                self.write(value[key], child, depth + 1)
            self.emit(b'}')
        elif type(value) is list:
            if node is not None:
                _need(node[0] in ('list', 'array'))
                _need(len(value) == node[2] if node[0] == 'array' else len(value) <= node[2], BOUND)
            self.emit(b'[')
            for i, item in enumerate(value):
                if i:
                    self.emit(b',')
                self.write(item, node[1] if node is not None else None, depth + 1)
            self.emit(b']')
        elif type(value) is str:
            if node is not None:
                _leaf(value, node, self.budget)
            self.string(value)
        elif value is None:
            _need(node is None or node[0] == 'nullable')
            self.emit(b'null')
        elif type(value) is bool:
            if node is not None:
                _leaf(value, node, self.budget)
            self.emit(b'true' if value else b'false')
        elif type(value) is int:
            if node is not None:
                _leaf(value, node, self.budget)
            _need(-(1 << 63) <= value <= (1 << 64) - 1, BOUND)
            n, digits = abs(value), 1 + int(value < 0)
            while n >= 10:
                digits += 1
                n //= 10
            _need(digits <= self.cap - self.size, self.cap_reason)
            self.budget.work(3 * digits)
            self.emit(str(value).encode('ascii'))
        else:
            raise Stage4Invalid(JSON)

    def finish(self):
        if self.buffer is None:
            return None
        self.budget.work(self.size)
        return b''.join(self.buffer)


def _digest_hex(digest, budget):
    budget.work(32 + 64)  # digest source bytes plus hexadecimal destination
    return digest.hexdigest()


def _commit(envelope, budget, encode=False):
    writer = _Writer(budget, MAX_EXPANDED, hash_output=True, count_expanded=encode)
    writer.write(envelope, ['ref', 'Envelope'])
    return writer.size, _digest_hex(writer.digest, budget)


def _payload_bytes(value, budget):
    writer = _Writer(budget, MAX_FRAME, retain=True, cap_reason='TooLarge:Frame')
    # Generic compact JSON has root depth one, unlike the named shape root ref.
    writer.write(value, depth=1)
    return writer.finish()


def _decode(raw, budget):
    payload = _extract(raw, budget)
    compact = _json_payload(payload, budget)
    _need(type(compact) is list and len(compact) == 4)
    budget.values(8)  # wrapper plus three primitive header values, twice
    marker, declared_size, declared_hash, body = compact
    _scalar(marker, budget)
    _need(marker == MARKER, SCHEMA)
    _need(type(declared_size) is int)
    _need(0 <= declared_size <= MAX_EXPANDED, BOUND)
    _leaf(declared_hash, ['hex', 32], budget)
    walk = _Walk(budget, 'decode')
    envelope = walk.walk(body, ['ref', 'Envelope'], 'expand')
    # Original closed named grammar, including all old per-field bounds. This
    # pass is reserved before expansion, without an uncharged deepcopy.
    walk.walk(envelope, ['ref', 'Envelope'], 'validate', named=True)
    actual_size, actual_hash = _commit(envelope, budget)
    _need(actual_size == declared_size, ENCODING)
    _need(_equal(_utf8(actual_hash, budget), _utf8(declared_hash, budget), budget), ENCODING)
    # Identity-index construction is extra accounted work; no counter reset.
    walk.operation = 'decode-reproject'
    walk.identity_index = []
    budget.values(1)  # extra identity_map-container index scan
    for i, item in enumerate(envelope['identity_map']):
        budget.values(1)
        walk.identity_lookup(walk.identity_key(item['label']), i)
    projected = walk.walk(envelope, ['ref', 'Envelope'], 'project')
    canonical = _payload_bytes([MARKER, actual_size, actual_hash, projected], budget)
    _need(_equal(canonical, payload, budget), ENCODING)
    return envelope


def decode_compact_frame(raw):
    """Decode only the exact V2 frame; output is NOT occurrence authentication."""
    try:
        return _decode(raw, _Budget())
    except (UnicodeError, RecursionError, OverflowError) as error:
        raise Stage4Invalid(JSON if isinstance(error, UnicodeError) else BOUND) from error


def _encode(envelope, budget):
    size, digest = _commit(envelope, budget, encode=True)
    walk = _Walk(budget, 'encode')
    body = walk.walk(envelope, ['ref', 'Envelope'], 'project')
    budget.values(4)  # compact outer wrapper and its three primitive headers
    payload = _payload_bytes([MARKER, size, digest, body], budget)
    digits_count = 1
    remaining = len(payload)
    while remaining >= 10:
        digits_count += 1
        remaining //= 10
    whole_size = len(FRAME_TAG) + digits_count + 1 + len(payload) + len(TRAILER)
    _need(whole_size <= MAX_FRAME, 'TooLarge:Frame')
    budget.work(3 * digits_count)
    digits = str(len(payload)).encode('ascii')
    budget.work(len(FRAME_TAG) + len(digits) + 1 + len(TRAILER))  # framing emission
    budget.work(whole_size)  # final bounded concatenation
    return b''.join((FRAME_TAG, digits, b'\n', payload, TRAILER))


def encode_compact_frame(envelope):
    """Repack a named Envelope for codec/negative controls, never actual evidence."""
    try:
        return _encode(envelope, _Budget())
    except (UnicodeError, RecursionError, OverflowError) as error:
        raise Stage4Invalid(JSON if isinstance(error, UnicodeError) else BOUND) from error
