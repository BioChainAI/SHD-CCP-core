# SPDX-License-Identifier: CC0-1.0
# Part of contract_vectors/ (CC0-1.0, see ../LICENSE).
"""An executable reading of rfcs/07_shdccp2_contract.md, written from the RFC's text (standard library only).

Purpose: a self-check that the RFC's prose is complete and exact. check.py runs every contract vector through it, so
a rule the RFC states wrongly, or leaves out, shows up as a disagreement. It is not the reference implementation
(Owl-Academy owns that, D5) and it does not count as an independent implementation for the two-implementation rule
(D8), because the RFC it reads was itself written from Owl's code. Section numbers below are RFC 07's.
"""
import base64
import hashlib
import hmac
import json
import math
import re
from fractions import Fraction

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
CHUNK = 720
SEGMENTS = 7
MAX_BYTES = 60000
STREAM_VERSION = 'shdccp/2'


# ── 2. conventions ──────────────────────────────────────────────────────────

def H(s):
    """Lower-case hex SHA-256 of the UTF-8 encoding of the string s (2.2)."""
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def utf8_of_text(text):
    """3.1: the WHATWG UTF-8 encoding of a string; a lone surrogate encodes as U+FFFD."""
    return ''.join('�' if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in text).encode('utf-8')


def i32(x):
    return ((x + (1 << 31)) & M32) - (1 << 31)


def u32(x):
    return x & M32


def to_fixed(x, f):
    """2.4: Number.prototype.toFixed(f) for |x| < 1e21: the exact binary value, the nearer multiple of 10^-f, the
    larger magnitude on a tie; '-' iff x < 0 (so -0 prints unsigned and a small negative prints '-0.000...')."""
    if x != x or abs(x) >= 1e21:
        raise ValueError('outside the range RFC 07 uses')
    neg = x < 0
    q = Fraction(-x if neg else x) * (10 ** f)
    n = math.floor(q)
    if q - n >= Fraction(1, 2):
        n += 1
    digits = str(n).rjust(f + 1, '0')
    return ('-' if neg else '') + (digits[:-f] + '.' + digits[-f:] if f else digits)


# ── 5. the crystal packet ───────────────────────────────────────────────────

def fold64(data):
    a = 0x9E3779B97F4A7C15
    for b in data:
        a = (((a << 7) | (a >> 57)) & M64) ^ ((b * 0x100000001B3) & M64)
    return a


def crystal32(data):
    a = fold64(data)
    return (a ^ (a >> 32)) & M32


def _with_parity(word):
    ones = bin(word & ~(1 << 59) & M64).count('1')
    return word | ((ones & 1) << 59)


def packet(data, crystal=None):
    c = crystal32(data) if crystal is None else crystal
    csum = sum(data) & 0xFF
    word = (9 << 60) | (c << 24) | ((len(data) & 0xFFFF) << 8) | ((csum >> 3) << 3) | (csum & 7)
    return '%016X' % _with_parity(word)


def kernel_normalized_packet(data):
    """5.4, informative only: each crystal byte 0x80 written as 0x81, parity recomputed."""
    c = crystal32(data)
    c = sum(((0x81 if ((c >> s) & 0xFF) == 0x80 else (c >> s) & 0xFF) << s) for s in (24, 16, 8, 0))
    return packet(data, c)


def unpack(hex16):
    w = int(hex16, 16)
    return {'form': (w >> 60) & 0xF, 'parity': (w >> 59) & 1, 'spin': (w >> 56) & 7, 'quat32': (w >> 24) & M32,
            'payload16': (w >> 8) & 0xFFFF, 'freq': (w >> 3) & 0x1F, 'amp': w & 7,
            'parity_ok': bin(w).count('1') % 2 == 0}


def signed_codes(c):
    return [((c >> s) & 0xFF) - 256 if ((c >> s) & 0xFF) >= 128 else (c >> s) & 0xFF for s in (24, 16, 8, 0)]


# ── 6. the rank coder ───────────────────────────────────────────────────────

def _gamma(bits, n):
    w = n.bit_length()
    bits.extend([0] * (w - 1))
    bits.extend((n >> k) & 1 for k in range(w - 1, -1, -1))


def _candidates(table):
    return sorted(table, key=lambda b: (-table[b], b))


def encode_chunk(data):
    tables, bits, ctx = {}, [], (0, 0)
    for b in data:
        t = tables.setdefault(ctx, {})
        cands = _candidates(t)
        if b in t:
            _gamma(bits, cands.index(b) + 1)
        else:
            _gamma(bits, len(cands) + 1)
            bits.extend((b >> k) & 1 for k in range(7, -1, -1))
        t[b] = t.get(b, 0) + 1
        ctx = (ctx[1], b)
    bits.extend([0] * (-len(bits) % 8))
    return bytes(int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)).hex()


def decode_chunk(hexs, n):
    data = bytes.fromhex(hexs)
    pos = [0]

    def bit():
        if pos[0] >= 8 * len(data):
            raise ValueError('residual truncated')
        v = (data[pos[0] >> 3] >> (7 - (pos[0] & 7))) & 1
        pos[0] += 1
        return v

    def read(k):
        v = 0
        for _ in range(k):
            v = (v << 1) | bit()
        return v

    tables, out, ctx = {}, [], (0, 0)
    for _ in range(n):
        t = tables.setdefault(ctx, {})
        cands = _candidates(t)
        z = 0
        while bit() == 0:
            z += 1
        r = (1 << z) | read(z) if z else 1
        b = cands[r - 1] if r - 1 < len(cands) else read(8)
        out.append(b)
        t[b] = t.get(b, 0) + 1
        ctx = (ctx[1], b)
    return bytes(out)


# ── 4. frames and the stream ────────────────────────────────────────────────

def frame(pkt, residual):
    return pkt + '%08x' % (len(residual) // 2) + residual


_FRAME = re.compile(r'([0-9A-F]{16})([0-9a-f]{8})')


def parse_stream_strict(stream):
    """4.3: canonical case, exact lengths, no trailing characters, at least one frame."""
    frames, p = [], 0
    while p < len(stream):
        m = _FRAME.match(stream, p)
        if not m:
            raise ValueError('frame header at %d is not canonical' % p)
        n = int(m.group(2), 16)
        res = stream[m.end():m.end() + 2 * n]
        if len(res) != 2 * n or not re.fullmatch(r'[0-9a-f]*', res):
            raise ValueError('residual at %d is short or not canonical' % m.end())
        frames.append((m.group(1), res))
        p = m.end() + 2 * n
    if not frames:
        raise ValueError('no frames')
    return frames


# ── 7. leaves and the shdccp/2 Merkle rule ──────────────────────────────────

def leaf(i, chunk):
    return H(str(i) + '|' + H(''.join(chr(b) for b in chunk)))


def merkle_root(leaves):
    level = list(leaves)
    if not level:
        raise ValueError('K = 0 has no shdccp/2 root')
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [H(level[j] + level[j + 1]) for j in range(0, len(level), 2)]
    return level[0]


# ── 8. weaves ───────────────────────────────────────────────────────────────

def hypot_v8(xs):
    absx, has_nan, mx = [], False, 0.0
    for x in xs:
        if x != x:
            has_nan = True
            absx.append(0.0)
            continue
        a = abs(x)
        absx.append(a)
        if a > mx:
            mx = a
    if mx == math.inf:
        return math.inf
    if has_nan:
        return math.nan
    if mx == 0:
        return 0.0
    s = comp = 0.0
    for a in absx:
        n = a / mx
        summand = n * n - comp
        prelim = s + summand
        comp = (prelim - s) - summand
        s = prelim
    return math.sqrt(s) * mx


def qn(a):
    n = hypot_v8(a)
    if n == 0 or n != n:
        n = 1.0
    return [x / n for x in a]


def qmul(a, b):
    return [((a[0] * b[0] - a[1] * b[1]) - a[2] * b[2]) - a[3] * b[3],
            ((a[0] * b[1] + a[1] * b[0]) + a[2] * b[3]) - a[3] * b[2],
            ((a[0] * b[2] - a[1] * b[3]) + a[2] * b[0]) + a[3] * b[1],
            ((a[0] * b[3] + a[1] * b[2]) - a[2] * b[1]) + a[3] * b[0]]


def qconj(a):
    return [a[0], -a[1], -a[2], -a[3]]


def crystal_quat(chunk):
    w, x, y, z = signed_codes(crystal32(chunk))
    return qn([0.5 + w / 254, x / 127, y / 127, z / 127])


def quat_text(q):
    return ','.join(to_fixed(v, 12) for v in q)


def weave_steps(chunks):
    wf, wm, chiral, mirror = [1.0, 0.0, 0.0, 0.0], [1.0, 0.0, 0.0, 0.0], [], []
    quats = [crystal_quat(c) for c in chunks]
    for q in quats:
        wf = qn(qmul(q, wf))
        chiral.append(wf)
    for q in reversed(quats):
        wm = qn(qmul(qconj(q), wm))
        mirror.append(wm)
    return quats, chiral, mirror


def seg_cuts(k):
    return [(2 * i * k + 7) // 14 for i in range(SEGMENTS + 1)]


# ── 9. engram/1 ─────────────────────────────────────────────────────────────

def mulberry32_u32(seed, count):
    out, s = [], i32(seed)
    for _ in range(count):
        s = i32(s + 0x6D2B79F5)
        t = i32((u32(s ^ (u32(s) >> 15)) * u32(1 | s)) & M32)
        t2 = i32((u32(t ^ (u32(t) >> 7)) * u32(61 | t)) & M32)
        t = i32(i32(t + t2) ^ t)
        out.append(u32(t ^ (u32(t) >> 14)))
    return out


def letter_grid(ch):
    seed, raw = 0, ch.encode('utf-16-be', 'surrogatepass')
    for k in range(0, len(raw), 2):
        seed = i32(seed * 31 + int.from_bytes(raw[k:k + 2], 'big'))
    return [1 if v > (1 << 31) else 0 for v in mulberry32_u32(seed, 64)]


def tokens_of(text):
    return re.findall(r"[A-Za-z0-9']+", text)


def token_grid(token):
    acc = [0] * 64
    for ch in token.upper():
        if 'A' <= ch <= 'Z':
            acc = [a ^ g for a, g in zip(acc, letter_grid(ch))]
    return acc


def grid_hex(grid):
    return ''.join('%02X' % sum(grid[8 * i + b] << b for b in range(8)) for i in range(8))


def j_num(grid):
    upper = sum(grid[r * 8 + c] for r in range(8) for c in range(8) if c > r)
    lower = sum(grid[r * 8 + c] for r in range(8) for c in range(8) if c < r)
    return upper - lower


def engram_layer(text):
    toks = tokens_of(text)
    grids = [token_grid(t) for t in toks]
    jsum = sum(j_num(g) for g in grids) / 32
    mean = float(to_fixed(jsum / len(toks), 4)) if toks else 0
    return {'tokens': toks, 'grids': grids, 'stream': ''.join(grid_hex(g) for g in grids), 'count': len(toks),
            'meanJ': mean}


# ── 3, 10, 11. the record ───────────────────────────────────────────────────

class GrowError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def grow(text, engrams=True):
    data = utf8_of_text(text)
    if not data:
        raise GrowError('empty-input')
    if len(data) > MAX_BYTES:
        raise GrowError('input-too-large')
    chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]
    k = len(chunks)
    packets = [packet(c) for c in chunks]
    residuals = [encode_chunk(c) for c in chunks]
    leaves = [leaf(i, c) for i, c in enumerate(chunks)]
    root = merkle_root(leaves)
    _, chiral, mirror = weave_steps(chunks)
    wc, wm = quat_text(chiral[-1]), quat_text(mirror[-1])
    stream = ''.join(frame(p, r) for p, r in zip(packets, residuals))
    rec = {'chainId': 'BC-' + H(root + '|' + wc)[:24], 'stream': stream, 'streamVersion': STREAM_VERSION,
           'leafHashes': leaves, 'merkleRoot': root, 'weaveChiral': wc, 'weaveMirror': wm, 'segCuts': seg_cuts(k),
           'segments': SEGMENTS}
    eng_len = 0
    if engrams:
        e = engram_layer(text)
        rec.update(engramStream=e['stream'], engramCount=e['count'], engramMeanJ=e['meanJ'])
        eng_len = len(e['stream']) // 2
    ship = len(stream) // 2 + eng_len + 32 * k + 40
    rec.update(origBytes=len(data), shippedBytes=ship, value=float(to_fixed(len(data) / ship, 4)))
    return rec


def grown_commitment(rec):
    return '|'.join(['GROWN/1', rec['chainId'], rec['merkleRoot'], rec['weaveChiral'], rec['weaveMirror'],
                     str(rec['origBytes'])])


def growth_commitment(rec):
    return '|'.join(['GROWTH/1', rec['parentChainId'], rec['chainId'], rec['parentMerkleRoot'], rec['merkleRoot'],
                     str(rec['addedBytes'])])


# ── 12. the validity predicate ──────────────────────────────────────────────

GROWN_FIELDS = ('chainId', 'stream', 'streamVersion', 'leafHashes', 'merkleRoot', 'weaveChiral', 'weaveMirror',
                'segCuts', 'segments', 'origBytes', 'shippedBytes', 'value')
ENGRAM_FIELDS = ('engramStream', 'engramCount', 'engramMeanJ')


def validate(rec):
    """12.1: returns None for a valid record, else the name of the first failing step."""
    if rec.get('streamVersion') != STREAM_VERSION or not isinstance(rec.get('stream'), str):
        return 'version'
    try:
        frames = parse_stream_strict(rec['stream'])
    except ValueError:
        return 'parse'
    chunks = []
    for i, (pkt, res) in enumerate(frames):
        n = unpack(pkt)['payload16']
        if not unpack(pkt)['parity_ok'] or n < 1 or n > CHUNK or (i < len(frames) - 1 and n != CHUNK):
            return 'parity-or-length'
        try:
            chunks.append(decode_chunk(res, n))
        except ValueError:
            return 'decode'
    data = b''.join(chunks)
    try:
        text = data.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return 'utf8'
    has_eng = any(f in rec for f in ENGRAM_FIELDS)
    try:
        want = grow(text, engrams=has_eng)
    except GrowError:
        return 'size'
    for f in GROWN_FIELDS + (ENGRAM_FIELDS if has_eng else ()):
        if f not in rec or rec[f] != want[f]:
            return 'field:' + f
    return None


# ── 12.3, 12.4. the strict checks and the verdict ───────────────────────────

STRICT_CHECKS = ('parity', 'canonical', 'crystal', 'leaves', 'weaves', 'derived')


def _num_eq(x, y):
    """12.3: numbers compare as binary64 values and must be JSON numbers (a string or a boolean is not one)."""
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == y


def strict_verdict(rec):
    """12.3 and 12.4: the verdict {'ok', 'failed', 'legacy'} of a strict verifier for any JSON value."""
    if not isinstance(rec, dict):
        return {'ok': False, 'failed': 'parity', 'legacy': False}
    if not isinstance(rec.get('stream'), str) or rec.get('streamVersion') != STREAM_VERSION:
        return {'ok': False, 'failed': 'parity', 'legacy': True}

    def fail(name):
        return {'ok': False, 'failed': name, 'legacy': False}

    # 1. parity: the strict parse (4.3, items 1-3) and every packet's parity (5.5)
    try:
        frames = parse_stream_strict(rec['stream'])
    except ValueError:
        return fail('parity')
    if not all(unpack(p)['parity_ok'] for p, _ in frames):
        return fail('parity')
    # 2. canonical: the 720-byte cut, at most 60,000 bytes, canonical residuals, the framing, well-formed UTF-8
    lens, k = [unpack(p)['payload16'] for p, _ in frames], len(frames)
    if any(n != CHUNK for n in lens[:-1]) or not 1 <= lens[-1] <= CHUNK or sum(lens) > MAX_BYTES:
        return fail('canonical')
    chunks = []
    for (_, r), n in zip(frames, lens):
        try:
            c = decode_chunk(r, n)
        except ValueError:
            return fail('canonical')
        if encode_chunk(c) != r:
            return fail('canonical')
        chunks.append(c)
    if ''.join(frame(p, r) for p, r in frames) != rec['stream']:
        return fail('canonical')
    data = b''.join(chunks)
    try:
        text = data.decode('utf-8')          # 12.1 step 2: strict, a leading U+FEFF kept
    except UnicodeDecodeError:
        return fail('canonical')
    # 3. crystal: every packet is crystallize(chunk) under the raw rule (5.4)
    if any(packet(c) != p for c, (p, _) in zip(chunks, frames)):
        return fail('crystal')
    # 4. leaves: exactly K entries, each the leaf; merkleRoot present and the root of the leaves
    leaves = [leaf(i, c) for i, c in enumerate(chunks)]
    lh, root = rec.get('leafHashes'), merkle_root(leaves)
    if not isinstance(lh, list) or len(lh) != k or any(a != b for a, b in zip(lh, leaves)) \
            or not isinstance(rec.get('merkleRoot'), str) or rec['merkleRoot'] != root:
        return fail('leaves')
    # 5. weaves: weaveChiral, weaveMirror, segCuts, segments and the chainId (8, 10)
    _, chiral, mirror = weave_steps(chunks)
    wc, wm, cuts, segs = quat_text(chiral[-1]), quat_text(mirror[-1]), seg_cuts(k), rec.get('segCuts')
    if rec.get('weaveChiral') != wc or rec.get('weaveMirror') != wm or not isinstance(segs, list) \
            or len(segs) != len(cuts) or not all(_num_eq(a, b) for a, b in zip(segs, cuts)) \
            or not _num_eq(rec.get('segments'), SEGMENTS) or rec.get('chainId') != 'BC-' + H(root + '|' + wc)[:24]:
        return fail('weaves')
    # 6. derived: the engram fields when any is present (9.5), origBytes, shippedBytes and value (10)
    eng_len = 0
    if any(f in rec for f in ENGRAM_FIELDS):
        e = engram_layer(text)
        if rec.get('engramStream') != e['stream'] or not _num_eq(rec.get('engramCount'), e['count']) \
                or not _num_eq(rec.get('engramMeanJ'), e['meanJ']):
            return fail('derived')
        eng_len = len(e['stream']) // 2
    ship = len(rec['stream']) // 2 + eng_len + 32 * k + 40
    if not _num_eq(rec.get('origBytes'), len(data)) or not _num_eq(rec.get('shippedBytes'), ship) \
            or not _num_eq(rec.get('value'), float(to_fixed(len(data) / ship, 4))):
        return fail('derived')
    return {'ok': True, 'failed': None, 'legacy': False}


# ── 4.4, 6.6. size limits ───────────────────────────────────────────────────

def code_bits(data):
    """6.2, 6.3: the length in bits of each byte's code, with the candidates the code saw and whether it escaped."""
    tables, out, ctx = {}, [], (0, 0)
    for b in data:
        t = tables.setdefault(ctx, {})
        cands = _candidates(t)
        if b in t:
            out.append((2 * (cands.index(b) + 1).bit_length() - 1, len(cands), False))
        else:
            out.append((2 * (len(cands) + 1).bit_length() - 1 + 8, len(cands), True))
        t[b] = t.get(b, 0) + 1
        ctx = (ctx[1], b)
    return out


MAX_BITS_PER_BYTE = 2 * (256).bit_length() - 1 + 8     # 6.6: gamma(256) + 8 = 25


def max_residual_bytes(n):
    """6.6: the largest residual of an n-byte chunk."""
    return -(-MAX_BITS_PER_BYTE * n // 8)


def stream_bound(n):
    """4.4: the chunk count, the bound on the stream of an n-byte input, and the cap for its frame count."""
    k = -(-n // CHUNK)
    lens = [min(CHUNK, n - CHUNK * i) for i in range(k)]
    return {'chunks': k, 'last_chunk_bytes': lens[-1], 'max_bits_per_byte': MAX_BITS_PER_BYTE,
            'max_residual_bytes_full_chunk': max_residual_bytes(CHUNK),
            'max_stream_hex': sum(16 + 8 + 2 * max_residual_bytes(x) for x in lens),
            'cap_hex': k * (16 + 8 + 2 * max_residual_bytes(CHUNK))}


# ── 7.4. BIOSEED/1 ──────────────────────────────────────────────────────────

def bioseed_leaf(i, chunk):
    return hashlib.sha256(i.to_bytes(4, 'big') + hashlib.sha256(bytes(chunk)).digest()).hexdigest()


def bioseed_root(leaves):
    level = [bytes.fromhex(x) for x in leaves] or [bytes(32)]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[j] + level[j + 1]).digest() for j in range(0, len(level), 2)]
    return level[0].hex()


# ── 7.5. RFC 6962 trees, proofs and their verification ──────────────────────

def _k_below(n):
    k = 1
    while 2 * k < n:
        k *= 2
    return k


def rfc_leaf(d):
    return hashlib.sha256(b'\x00' + bytes(d)).digest()


def rfc_node(left, right):
    return hashlib.sha256(b'\x01' + left + right).digest()


def mth(entries):
    n = len(entries)
    if n == 0:
        return hashlib.sha256(b'').digest()
    if n == 1:
        return rfc_leaf(entries[0])
    k = _k_below(n)
    return rfc_node(mth(entries[:k]), mth(entries[k:]))


def audit_path(m, entries):
    n = len(entries)
    if n == 1:
        return []
    k = _k_below(n)
    if m < k:
        return audit_path(m, entries[:k]) + [mth(entries[k:])]
    return audit_path(m - k, entries[k:]) + [mth(entries[:k])]


def _subproof(m, entries, b):
    n = len(entries)
    if m == n:
        return [] if b else [mth(entries)]
    k = _k_below(n)
    if m <= k:
        return _subproof(m, entries[:k], b) + [mth(entries[k:])]
    return _subproof(m - k, entries[k:], False) + [mth(entries[:k])]


def consistency_proof(m, entries):
    return _subproof(m, entries, True)


def verify_inclusion(index, size, leaf_hash, path, root):
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = rfc_node(p, r)
            while fn % 2 == 0 and fn != 0:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = rfc_node(r, p)
        fn, sn = fn >> 1, sn >> 1
    return sn == 0 and r == root


def verify_consistency(m, n, root_m, root_n, proof):
    if not 1 <= m <= n:
        return False
    if m == n:
        return not proof and root_m == root_n
    if not proof:
        return False
    path = ([root_m] if m & (m - 1) == 0 else []) + list(proof)
    fn, sn = m - 1, n - 1
    while fn % 2 == 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr, sr = rfc_node(c, fr), rfc_node(c, sr)
            while fn % 2 == 0 and fn != 0:
                fn, sn = fn >> 1, sn >> 1
        else:
            sr = rfc_node(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return fr == root_m and sr == root_n and sn == 0


# ── 9.6. the engram key of a string ─────────────────────────────────────────

def key_letters(text):
    """The letters A-Z of the string after full (Unicode default) upper-casing, in order."""
    return ''.join(ch for ch in text.upper() if 'A' <= ch <= 'Z')


def engram_key(text):
    acc = [0] * 64
    for ch in key_letters(text):
        acc = [a ^ g for a, g in zip(acc, letter_grid(ch))]
    return grid_hex(acc)


# ── 13. identities, keys, payloads, signatures, the snapshot ────────────────

JS_TRIM = '\t\n\x0b\x0c\r \xa0                　﻿'
PARAMS = '{"lattice":"E8","hilbertDim":64,"modulus":240,"manifold":"clifford","coherency":0.75,"torsion":0.5}'


def vector64(s):
    """13.2: the 64-bit vector of a string: SHA-256 of its UTF-8, then the 32 bytes and their complements, folded."""
    h = hashlib.sha256(s.encode('utf-8')).digest()
    b = h + bytes(255 - x for x in h)
    acc = 0
    for x in range(4):
        for y in range(4):
            for z in range(4):
                acc = (acc * 31 + b[16 * x + 4 * y + z] * (x + 1) * (y + 1) * (z + 1)) & M64
    return '%016X' % acc


def identity_id(seed, uid):
    s = seed.strip(JS_TRIM)
    if not s:
        raise ValueError('empty-seed')
    return '0x%016X' % (int(vector64(s), 16) ^ int(hashlib.sha256(uid.encode('utf-8')).hexdigest()[:16], 16))


def key_vector(identity, token):
    return vector64(identity + '|' + PARAMS + '|' + token)


P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def _ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P256_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + P256_A) * pow(2 * p[1], -1, P256_P) % P256_P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P256_P) % P256_P
    x = (lam * lam - p[0] - q[0]) % P256_P
    return x, (lam * (p[0] - x) - p[1]) % P256_P


def ec_mul(k, p=P256_G):
    r = None
    while k:
        if k & 1:
            r = _ec_add(r, p)
        p = _ec_add(p, p)
        k >>= 1
    return r


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def public_jwk(d):
    x, y = ec_mul(d)
    return {'kty': 'EC', 'crv': 'P-256', 'x': _b64u(x.to_bytes(32, 'big')), 'y': _b64u(y.to_bytes(32, 'big'))}


def fingerprint(prefix, jwk):
    """13.3: keyId ('K-') and sealId ('S-'): the first 24 hex digits of H(x + '|' + y)."""
    return prefix + H(jwk['x'] + '|' + jwk['y'])[:24]


def rfc6979_sign(d, message):
    """13.5: ECDSA P-256 / SHA-256 over the UTF-8 of message, nonce by RFC 6979 section 3.2 (HMAC-SHA-256)."""
    h1 = hashlib.sha256(message.encode('utf-8')).digest()
    e = int.from_bytes(h1, 'big')
    x, hb = d.to_bytes(32, 'big'), (e % P256_N).to_bytes(32, 'big')
    v, k = b'\x01' * 32, b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + x + hb, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    k = hmac.new(k, v + b'\x01' + x + hb, 'sha256').digest()
    v = hmac.new(k, v, 'sha256').digest()
    while True:
        v = hmac.new(k, v, 'sha256').digest()
        n = int.from_bytes(v, 'big')
        if 1 <= n < P256_N:
            r = ec_mul(n)[0] % P256_N
            s = pow(n, -1, P256_N) * (e + r * d) % P256_N
            if r and s:
                return r, s
        k = hmac.new(k, v + b'\x00', 'sha256').digest()
        v = hmac.new(k, v, 'sha256').digest()


def ecdsa_verify(jwk, message, r, s):
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    q = tuple(int.from_bytes(base64.urlsafe_b64decode(jwk[c] + '=' * (-len(jwk[c]) % 4)), 'big') for c in 'xy')
    e = int.from_bytes(hashlib.sha256(message.encode('utf-8')).digest(), 'big')
    w = pow(s, -1, P256_N)
    pt = _ec_add(ec_mul(e * w % P256_N), ec_mul(r * w % P256_N, q))
    return pt is not None and pt[0] % P256_N == r


def p1363(r, s):
    return '%064x%064x' % (r, s)


def der(r, s):
    def integer(v):
        b = v.to_bytes((v.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = integer(r) + integer(s)
    return (b'\x30' + bytes([len(body)]) + body).hex()


def high_s(s):
    return s > P256_N // 2


def signature_fields(d, jwk, payload, other_payload=None):
    r, s = rfc6979_sign(d, payload)
    t = P256_N - s
    out = {'sig': p1363(r, s), 'high_s': high_s(s), 'twin': p1363(r, t), 'der': der(r, s), 'der_twin': der(r, t),
           'verifies': {'sig': ecdsa_verify(jwk, payload, r, s), 'twin': ecdsa_verify(jwk, payload, r, t)}}
    if other_payload is not None:
        out['verifies']['other_content'] = ecdsa_verify(jwk, other_payload, r, s)
    out['sig_low_s'] = p1363(r, min(s, t))
    return out


def attest_payload(key_id, kvec, content_hash, epoch_token):
    return '|'.join(['ATTEST/1', key_id, kvec, content_hash, epoch_token])


def seal_payload(seal_id, svec, content_hash, tick_token):
    return '|'.join(['SEAL/1', seal_id, svec, content_hash, tick_token])


KEY_STATUSES = ('active', 'revoked', 'retired')


def snapshot_text(entries):
    """13.6: the registry snapshot: a JSON array without spaces of {keyId, publicJwk {kty, crv, x, y}, keyVector,
    status}, keys in that order, sorted by keyId, keyIds distinct, statuses from KEY_STATUSES."""
    rows = []
    for e in entries:
        if e['status'] not in KEY_STATUSES:
            raise ValueError('unknown-status')
        j = e['publicJwk']
        rows.append({'keyId': fingerprint('K-', j), 'publicJwk': {'kty': j['kty'], 'crv': j['crv'], 'x': j['x'], 'y': j['y']},
                     'keyVector': e['keyVector'], 'status': e['status']})
    rows.sort(key=lambda r: r['keyId'])
    if len({r['keyId'] for r in rows}) != len(rows):
        raise ValueError('duplicate-key')
    return json.dumps(rows, separators=(',', ':'), ensure_ascii=False)
