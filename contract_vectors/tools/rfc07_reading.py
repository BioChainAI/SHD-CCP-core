# SPDX-License-Identifier: CC0-1.0
# Part of contract_vectors/ (CC0-1.0, see ../LICENSE).
"""An executable reading of rfcs/07_shdccp2_contract.md, written from the RFC's text (standard library only).

Purpose: a self-check that the RFC's prose is complete and exact. check.py runs every contract vector through it, so
a rule the RFC states wrongly, or leaves out, shows up as a disagreement. It is not the reference implementation
(Owl-Academy owns that, D5) and it does not count as an independent implementation for the two-implementation rule
(D8), because the RFC it reads was itself written from Owl's code. Section numbers below are RFC 07's.
"""
import hashlib
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
