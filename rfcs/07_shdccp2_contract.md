<!-- SPDX-License-Identifier: CC0-1.0 -->
# RFC 07: the shdccp/2 biochain contract

| | |
| :--- | :--- |
| **Status** | Draft text. The wire format it describes is already deployed and frozen: every published chainId commits to it (D6). |
| **Spec version** | 0.1.0 |
| **Wire version** | `shdccp/2` (the record field `streamVersion`) |
| **Vectors** | [`contract_vectors/`](../contract_vectors/): `shdccp2_packet`, `shdccp2_chunk`, `shdccp2_merkle`, `shdccp2_arith`, `shdccp2_weave`, `engram1`, `shdccp2_record` |
| **Reference implementation** | Owl-Academy `scripts/biomesh.js` at `7f45f356f5c46ea0eb099905b2505a06e8c28fd7` (MIT), to become `scripts/biomesh-core.js` |
| **Licence** | CC0-1.0 ([`LICENSE`](LICENSE) in this folder). The code of this repository stays GPL-3.0 (see [`../NOTICE`](../NOTICE)). |

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119.

## 1. Scope, status and ownership

This RFC specifies the `shdccp/2` biochain as Owl-Academy grows and verifies it today: how a text becomes a framed
stream of crystal packets and rank-coded residuals, how its leaves, Merkle root, weaves and chainId are computed, which
fields a grown record carries, and which commitment strings attestations sign. It is written so that an implementation
in any language reproduces every field bit for bit, including the floating-point weaves.

**Ownership (decisions D5, D5b, D5c).**

| Part | Owner |
| :--- | :--- |
| This text and the contract vectors | SHD-CCP-core (`rfcs/`, `contract_vectors/`) |
| The reference implementation | Owl-Academy (`scripts/biomesh.js`, later `biomesh-core.js`, `manifest.js`, `biochain-package.js`) |
| ATTEST/1, identity, and the rules pattern of BioChain-AI aa8cf0b | BioChain-AI |
| The independent oracle | the Hyperbolic Lexicon in Ebayednoob (`reference/lexicon/chain.py`); never a dependency |

SHD-CCP keeps its RFCs 00-06 as history; this RFC continues their numbering so that "RFC 07" names one document across
the repositories. SHD-CCP-core holds it because Geometric-Labs names SHD-CCP-core the home of message and schema
sources of truth (`AGENTS.md:18`, `ecosystem/contracts/INTERFACES.md:26` at Geometric-Labs `3e63eab`).

**What this RFC does not change.** SHD-CCP-core's existing specification, `spec/shdccp_einstein_v1.json`
(SHDCCP-EINSTEIN-1, the 64-bit Einstein Tile), its vectors and its codecs are untouched. That specification lists
"Transport envelope byte layout" as out of its scope; this RFC does not fill that gap for the tile either. Section 14
explains why a `shdccp/2` packet is not an Einstein Tile.

**Out of scope.** App-layer record fields (owners, titles, lineage, transfers, ratings; section 11.2), CODEX/1 codices,
LATTICE-SEED/1 and ENVIRONMENT/1, Firestore rules, signature formats (section 13 points to their owner), and BIOSEED/1
and RFC 6962 trees beyond naming them (section 7.3).

## 2. Conventions

### 2.1 Bits, bytes and integers

Bit 0 is the least significant bit. A 64-bit word is written as 16 hexadecimal digits, most significant first. Integer
operations on 64-bit words are taken modulo 2^64. `a ⊕ b` is bitwise exclusive or, `rotl64(a, 7)` is
`((a << 7) | (a >> 57)) mod 2^64`.

### 2.2 The hash helper H

`H(s)` is the SHA-256 digest (FIPS 180-4) of the UTF-8 encoding of the string `s`, written as 64 **lower-case**
hexadecimal digits. Every hash in this RFC is H of a string; none hashes raw bytes directly. (Owl computes it with
`sha256Hex` in `scripts/seal-crypto.js`, Web Crypto over `TextEncoder`.)

### 2.3 Hex text

Packets are **upper-case** hex. Residual lengths, residuals, hashes and chainIds are **lower-case** hex. engram/1
packets are upper-case hex. Section 4.3 makes the stream's case part of its canonical form.

### 2.4 Numbers

All floating-point values are IEEE-754 binary64. Each `+`, `-`, `*`, `/` and `sqrt` is one correctly rounded binary64
operation (round to nearest, ties to even), evaluated in exactly the order written, left to right. Implementations
MUST NOT contract a multiply and an add into a fused multiply-add, MUST NOT use extended precision for intermediates,
and MUST NOT reorder or reassociate.

`toFixed(x, f)` is ECMAScript's `Number.prototype.toFixed` for |x| < 10^21, which the values here always satisfy:

1. Let `neg` be true when x < 0. (Negative zero is not < 0, so it prints without a sign.)
2. Let `n` be the integer for which n / 10^f − |x| is closest to zero, computed on the **exact** binary value of x.
   If two integers are equally close, take the **larger** one (ties round away from zero).
3. Write `n` in decimal with at least f + 1 digits (left-padded with zeros), insert a point before the last f digits,
   and prefix "-" when `neg`.

So `toFixed(1/8192, 12)` is `0.000122070313`, `toFixed(-1e-15, 12)` is `-0.000000000000`, and `toFixed(-0, 12)` is
`0.000000000000`. C's and Python's "%.12f" differ in two ways: they round ties to even (giving `0.000122070312`)
and they print negative zero as `-0.000000000000`. Such formatting MUST NOT be used unchanged.
`number(s)` is the binary64 value nearest to the decimal string s (ECMAScript unary `+`).

## 3. Input and chunking

1. **Encoding.** The input is a string. Its bytes `D` are its UTF-8 encoding as WHATWG `TextEncoder` produces it: an
   unpaired surrogate code unit encodes as U+FFFD (`EF BF BD`).
2. **Limits.** Let n = |D|. If n = 0 the grow fails with `empty-input`. If n > 60,000 it fails with `input-too-large`.
   The limit counts bytes, not characters.
3. **Chunks.** `D` is cut into K = ⌈n / 720⌉ chunks: chunk i is bytes 720·i … min(720·i + 719, n − 1). Every chunk but
   the last holds exactly 720 bytes; the last holds 1 to 720. K is 1 to 84. The cut ignores character boundaries: a
   multi-byte character may be split between two chunks.

## 4. Frames and the stream

### 4.1 Frame

The frame of chunk i is the concatenation of:

| Part | Length | Content |
| :--- | :--- | :--- |
| packet | 16 hex digits, upper-case | `crystallize(chunk_i)` (section 5) |
| residual length | 8 hex digits, lower-case, zero-padded | L = the residual's length in bytes |
| residual | 2·L hex digits, lower-case | `encode(chunk_i)` (section 6) |

The chunk's length is not written separately: it is the packet's payload16 field.

### 4.2 Stream

The record field `stream` is the concatenation of the frames of chunks 0 … K−1, in order, with nothing between, before
or after them.

### 4.3 Strict parsing

A conforming verifier parses a stream as follows and rejects it on any failure:

1. at each frame start, 16 characters `[0-9A-F]` then 8 characters `[0-9a-f]`;
2. then exactly 2·L characters `[0-9a-f]`;
3. the stream ends exactly after the last frame, and holds at least one frame;
4. each packet has even parity (section 5.5); its payload16 is 720 for every frame but the last, and 1 to 720 for the
   last;
5. each residual decodes to payload16 bytes (section 6.4) and is canonical (section 6.5).

Owl's `parseBiochainStream` today is more lenient: it accepts either case, does not check that residual characters
are hex digits, and the decoder ignores residual bytes after the last code. Records grown by Owl always satisfy the
strict form.

### 4.4 Size bound

A residual costs at most 25 bits per byte (section 6.6), so L ≤ 2,250 for a full chunk and the stream of a
60,000-byte input has at most 84 × (16 + 8 + 4,500) = 380,016 hex digits.

## 5. The crystal packet

### 5.1 fold64 and crystal32

```
fold64(bytes):
    a = 0x9E3779B97F4A7C15
    for b in bytes:                        # b in 0..255
        a = rotl64(a, 7) ⊕ ((b · 0x100000001B3) mod 2^64)
    return a

crystal32(bytes) = (fold64(bytes) ⊕ (fold64(bytes) >> 32)) mod 2^32
```

The four bytes of crystal32 are named by the quaternion slot they feed in section 8.1:
`w` = bits 31..24, `x` = bits 23..16, `y` = bits 15..8, `z` = bits 7..0.

### 5.2 Word layout

| Bits | Field | Value in a `shdccp/2` crystal packet |
| :--- | :--- | :--- |
| 63..60 | form | 9 |
| 59 | parity | set so that the whole word has an even number of one bits |
| 58..56 | spin | 0 |
| 55..24 | quat32 | crystal32 of the chunk, **raw** (section 5.4) |
| 23..8 | payload16 | the chunk length in bytes (1 to 720) |
| 7..3 | freq | csum >> 3 |
| 2..0 | amp | csum & 7 |

where csum = (sum of the chunk's bytes) mod 256. Bits 7..0 are therefore csum itself.

### 5.3 crystallize

```
crystallize(chunk):
    word = (9 << 60) | (crystal32(chunk) << 24) | ((len(chunk) & 0xFFFF) << 8) | ((csum >> 3) << 3) | (csum & 7)
    word = word | (parity(word without bit 59) << 59)      # parity = number of one bits mod 2
    return word as 16 upper-case hex digits
```

Example: the bytes 0, 1, …, 59 give `9841D88D8B003CEA` (vector `shdccp2_packet/golden_bytes_0_59`).

### 5.4 The 0x80 rule (D6)

The four crystal bytes are written into bits 55..24 **unchanged**. A crystal byte 0x80 stays 0x80 in the packet, and
section 8.1 reads it as the signed value −128.

BioChain-AI's Python kernel (`protocol/shdccp_kernel.py:28, 74-89` at c975161) treats the same 32 bits as four int8
quaternion codes and rewrites the code −128 as −127 (byte 0x81) before packing. That **kernel normalisation** governs
the kernel's ABI and codex words only. It MUST NOT be applied to `shdccp/2` packets: every deployed chainId commits to
the raw packets, and about 1.5 % of real chunks have a 0x80 crystal byte. There is no `shdccp/3`. The vectors carry the
kernel-normalised packet as an informative value so that implementations can test that they do not produce it. A
Python grower that must emit `shdccp/2` packets needs a raw packer (BioChain-AI's planned `stream_packet`).

### 5.5 Reading a packet

`unpack(word)`: form = bits 63..60, parity = bit 59, spin = 58..56, quat32 = 55..24, payload16 = 23..8, freq = 7..3,
amp = 2..0. A packet's parity holds when the whole 64-bit word has an even number of one bits.

## 6. The rank coder

An order-2 adaptive rank coder with Elias-gamma ranks and raw-byte escapes. Each chunk is coded on its own; no state
crosses chunks.

### 6.1 State

A table maps each context (c1, c2), an ordered pair of byte values, to counts of the bytes that followed it. The
context starts as (0, 0) at the start of every chunk. The **candidates** of a context are the bytes with a non-zero
count in it, ordered by count descending, then by byte value ascending.

### 6.2 Elias gamma

`gamma(m)` for m ≥ 1: with w the bit length of m, write w − 1 zero bits, then m in w bits, most significant first.
(`gamma(1)` = `1`, `gamma(2)` = `010`, `gamma(5)` = `00101`.)

### 6.3 Encoding

```
encode(chunk):
    bits = []; ctx = (0, 0)
    for b in chunk:
        cands = candidates(ctx)
        if b in cands: append gamma(index of b in cands + 1)          # index from 0
        else:          append gamma(len(cands) + 1), then b in 8 bits, most significant first
        count[ctx][b] += 1
        ctx = (ctx.c2, b)
    pad bits with zero bits to a multiple of 8
    return the bytes (first bit = most significant bit of the first byte) as lower-case hex
```

### 6.4 Decoding

`decode(residual, n)` reverses it for n bytes: read zero bits until a one bit, z = the number of zeros; m = 1 when
z = 0, else m = (1 << z) | (the next z bits); if m − 1 < len(cands) the byte is cands[m − 1], else the byte is the next
8 bits. Update the table and context as in encoding. Reading past the end of the residual is an error.

### 6.5 Canonical residuals

The decoder accepts some residuals that the encoder never produces: an escape whose rank exceeds len(cands) + 1, an
escaped byte that is already a candidate, nonzero padding, or bytes after the last code. A residual is **canonical**
when `encode(decode(residual, n)) == residual`. A strict verifier MUST require canonical residuals; otherwise two
different streams can carry the same text.

### 6.6 Bound

A context has at most 256 candidates. A hit costs at most `gamma(256)` = 17 bits; an escape happens only when fewer
than 256 candidates exist, so it costs at most `gamma(256)` + 8 = 25 bits. Hence at most 25 bits per byte.

## 7. Leaves and the shdccp/2 Merkle rule

### 7.1 Leaves

```
leaf(i, chunk) = H( decimal(i) + "|" + H( latin1(chunk) ) )
```

- `decimal(i)` is the chunk index in base 10 without leading zeros (0, 1, …, 83).
- `latin1(chunk)` is the string whose code units are the chunk's byte values. Because H hashes UTF-8, a byte below
  0x80 is hashed as itself and a byte b ≥ 0x80 as the two bytes `0xC0 | (b >> 6)`, `0x80 | (b & 0x3F)`. This is what
  Owl's `String.fromCharCode(...chunk)` followed by `sha256Hex` does. Hashing the raw chunk bytes gives a different
  leaf for every chunk with a byte ≥ 0x80 and is not conforming.
- Leaves are **index-bound**: the same chunk at two indices has two different leaves (vectors
  `shdccp2_chunk/index_bound_0` and `_1`).

The record field `leafHashes` is the list leaf(0, chunk_0) … leaf(K−1, chunk_{K−1}).

### 7.2 The Merkle rule

```
root(leaves):                          # K = len(leaves) ≥ 1
    level = leaves
    while len(level) > 1:
        if len(level) is odd: append a copy of the last element
        level = [ H(level[2j] + level[2j+1]) for j in 0 .. len(level)/2 − 1 ]
    return level[0]
```

The concatenation joins two 64-digit lower-case hex strings, so each node hashes 128 ASCII characters. With one leaf
the root is that leaf, unhashed. `merkleRoot` = root(leafHashes).

Under the duplicate-last rule a list and the same list with its last leaf repeated can have the same root. A verifier
MUST therefore require `leafHashes` to have exactly K entries and MUST recompute each leaf from its chunk.

Owl's code falls back to `H("empty")` when there are no leaves. A `shdccp/2` record always has K ≥ 1, so that value is
never a valid `merkleRoot`.

### 7.3 Other rules that share these field names (informative)

Three leaf and tree rules are in use under the same field names `leafHashes` and `merkleRoot`, and records carry no
rule tag (F16). Only the first is `shdccp/2`.

| Rule | Leaf | Node | Odd level | Used by |
| :--- | :--- | :--- | :--- | :--- |
| `shdccp/2` (this RFC) | `H(i + "\|" + H(latin1(chunk)))` | `H(left_hex + right_hex)` | duplicate last | Owl, BioChain-AI JS, Ebayednoob |
| BIOSEED/1 | `SHA-256(u32be(i) ‖ SHA-256(chunk))`, raw digests | `SHA-256(left ‖ right)`, raw digests | duplicate last; empty = 32 zero bytes | BioChain-AI `protocol/codex_engine.py:196-207` |
| RFC 6962 | `SHA-256(0x00 ‖ d)` | `SHA-256(0x01 ‖ L ‖ R)` | split at the largest power of two below K | Lexicon corpus manifests |

A verifier MUST dispatch on `streamVersion` and MUST NOT accept a root computed under another rule.

## 8. Weaves

The weaves are binary64 quaternion products. Their text forms enter `weaveChiral`, `weaveMirror`, the chainId and the
GROWN/1 commitment, so the arithmetic below is normative to the last bit (D7). Conformance is bit for bit, as for every
other field; the `shdccp2_arith` and `shdccp2_weave` vectors give binary64 bit patterns for every intermediate value.

### 8.1 crystalQuat

```
crystalQuat(chunk):
    c = crystal32(chunk)
    s(k) = the byte (c >> k) & 0xFF read as two's complement: v − 256 if v ≥ 128, else v      # 0x80 → −128
    return qn([ 0.5 + s(24) / 254,  s(16) / 127,  s(8) / 127,  s(0) / 127 ])
```

Each division is one binary64 division of two exactly representable integers; the addition is one binary64 addition.
The −128 of a 0x80 byte is used as is (so a component may lie slightly outside [−1, 1] before normalising).

### 8.2 qmul and qconj

The Hamilton product, each component evaluated left to right exactly as written (so `p − q − r − s` is
`((p − q) − r) − s`):

```
qmul(a, b) = [ a0·b0 − a1·b1 − a2·b2 − a3·b3,
               a0·b1 + a1·b0 + a2·b3 − a3·b2,
               a0·b2 − a1·b3 + a2·b0 + a3·b1,
               a0·b3 + a1·b2 − a2·b1 + a3·b0 ]

qconj(a) = [ a0, −a1, −a2, −a3 ]                         # negation is exact
```

### 8.3 qn and hypot

```
qn(a):
    n = hypotV8(a0, a1, a2, a3)
    if n is 0 or NaN: n = 1
    return [ a0 / n, a1 / n, a2 / n, a3 / n ]
```

`hypotV8` is the algorithm of V8's `Math.hypot`, which Owl calls; ECMAScript leaves `Math.hypot`'s algorithm to the
engine, so it is pinned here:

```
hypotV8(x_1 … x_m):
    if any x_k is ±∞: return +∞
    if any x_k is NaN: return NaN
    M = max |x_k|
    if M = 0: return 0
    sum = 0; comp = 0
    for k = 1 .. m, in argument order:
        t = |x_k| / M
        summand = t·t − comp
        prelim = sum + summand
        comp = (prelim − sum) − summand
        sum = prelim
    return sqrt(sum) · M
```

This is a Kahan-compensated sum of squares scaled by the largest magnitude. It is not the correctly rounded hypot of
C99 or CPython (`math.hypot` differs from it on about 31 % of calls) and not `sqrt(a0² + a1² + a2² + a3²)`; vectors
`shdccp2_arith/hypot_differs_*` are inputs on which the plain form gives another double.

### 8.4 The two weaves

```
wf = [1, 0, 0, 0]
for i = 0 .. K−1:          wf = qn(qmul(crystalQuat(chunk_i), wf))          # chiral: chunks in order, left product
wm = [1, 0, 0, 0]
for i = K−1 down to 0:     wm = qn(qmul(qconj(crystalQuat(chunk_i)), wm))   # mirror: chunks in reverse
```

### 8.5 Text form

`quatText(q)` = `toFixed(q0, 12) + "," + toFixed(q1, 12) + "," + toFixed(q2, 12) + "," + toFixed(q3, 12)` with
toFixed as in section 2.4. `weaveChiral` = quatText(wf) and `weaveMirror` = quatText(wm).

### 8.6 Segment cuts

`segments` = 7 and `segCuts` is the flat list of 8 integers `round(i · K / 7)` for i = 0 … 7, which equals
`floor((2·i·K + 7) / 14)` in integers (i·K/7 is never exactly halfway between integers). The list is flat because
Firestore rejects nested arrays.

### 8.7 Engines (informative, D7)

Every published record was grown in a browser, and records grown in V8-based browsers follow sections 8.1-8.5
exactly. Records grown in Firefox or WebKit used those engines' `Math.hypot`, which this RFC does not assume equal to
hypotV8; Owl's CI measures them against V8 (O3). If they differ, Owl's core gains an explicit `hypotV8` so new grows
are engine-independent, and existing non-V8 records are labelled as having a weave that cannot be reproduced. This RFC
does not change in either case: the weave is defined by hypotV8.

## 9. The engram/1 layer

Present only when the record was grown with engrams on (Owl's default). It is computed from the input **string**, not
from the chunks.

### 9.1 Tokens

The tokens are the maximal runs of the characters `A-Z`, `a-z`, `0-9` and `'` (apostrophe, U+0027) in the string, in
order. Every other character, including every non-ASCII character, separates tokens: "Straße" gives "Stra" and "e".

### 9.2 mulberry32

With int32(v) = v reduced to the signed 32-bit range, uint32(v) = v mod 2^32, `>>>` the unsigned right shift and
`imul(a, b)` = int32(uint32(a) · uint32(b) mod 2^32):

```
mulberry32(seed):  seed = int32(seed) once, then for each draw:
    seed = int32(seed + 0x6D2B79F5)
    t = imul(seed ⊕ (seed >>> 15), 1 | seed)
    t = int32(int32(t + imul(t ⊕ (t >>> 7), 61 | t)) ⊕ t)
    u = uint32(t ⊕ (t >>> 14))                  # the draw is u / 2^32
```

### 9.3 Grids

A grid is 64 bits g[0] … g[63]. The grid of one letter `ch` uses the seed `code(ch)` (its UTF-16 code unit; for a
single ASCII letter this is its ASCII code) and 64 draws: g[k] = 1 when draw k has u > 2^31 (that is, u / 2^32 > 0.5),
else 0. The grid of a token is the bitwise ⊕ of the grids of its letters A-Z after upper-casing the token (ASCII
upper-casing; the token is ASCII). Digits and apostrophes contribute nothing; a token without letters has the all-zero
grid.

### 9.4 Hex and J

`gridHex(g)` is 8 bytes, byte i = Σ_{b=0..7} g[8i + b] · 2^b (least significant bit first), as 16 upper-case hex
digits. `Jnum(g)` = (Σ g[8r + c] over c > r) − (Σ g[8r + c] over c < r), with r, c in 0 … 7, and J = Jnum / 32.

### 9.5 Stream, count and mean

`engramStream` is the concatenation of gridHex over the tokens (the empty string when there are none), `engramCount`
is the number of tokens, and `engramMeanJ` = number(toFixed((Σ J) / engramCount, 4)), or 0 when there are no tokens.
Σ J is exact in binary64. Ties are common here (a single token with an odd Jnum gives an exact tie at the fourth
decimal), so toFixed's rule matters: "GEODESIC" gives `5C896A4801C9C24C` and the word "academy" gives 0.1563.

## 10. chainId and derived numbers

```
merkleRoot   = root(leafHashes)                                      (section 7.2)
chainId      = "BC-" + first 24 hex digits of H(merkleRoot + "|" + weaveChiral)
origBytes    = n
ship         = len(stream)/2 + (len(engramStream)/2 if engrams on, else 0) + 32·K + 40
shippedBytes = ship                                                   (an integer; Owl writes Math.round(ship))
value        = number(toFixed(origBytes / ship, 4))
```

`origBytes / ship` is one binary64 division. `weaveMirror`, `segCuts` and the engram fields do not enter the chainId.

## 11. The record

### 11.1 Grown fields

A grown record is a JSON object with these fields. Key order carries no meaning (Owl's order is shown).

| Field | Type | Rule |
| :--- | :--- | :--- |
| `chainId` | string | section 10 |
| `stream` | string | section 4.2 |
| `streamVersion` | string | exactly `"shdccp/2"` |
| `leafHashes` | array of K strings | section 7.1 |
| `merkleRoot` | string | section 7.2 |
| `weaveChiral` | string | section 8.5 |
| `weaveMirror` | string | section 8.5 |
| `segCuts` | array of 8 integers | section 8.6 |
| `segments` | integer | 7 |
| `engramStream` | string | section 9.5; present only with engrams on |
| `engramCount` | integer | section 9.5; present only with engrams on |
| `engramMeanJ` | number | section 9.5; present only with engrams on |
| `origBytes` | integer | section 10 |
| `shippedBytes` | integer | section 10 |
| `value` | number | section 10 |

The three engram fields are present together or absent together; with engrams on and no tokens they are `""`, 0
and 0. Numbers compare as binary64 values (so −0 equals 0).

A record without `stream`, or whose `streamVersion` is missing or not `"shdccp/2"`, is not a `shdccp/2` record. Owl
still reads pre-stream records with parallel `streams` and `chunkLens` arrays; a verifier reports such a record as
legacy and does not accept it as `shdccp/2`.

### 11.2 App-layer fields (informative)

Owl's `publishBiochain` adds title, description, grower and owner identities, `grownSeal`, `growthSeal`, lineage,
`lastTransferId`, status, `tickToken` and `createdAt`; an extended record adds `parentChainId`, `parentMerkleRoot`,
`epoch` and `addedBytes`. BioChain-AI uses its own names for the same roles. These fields belong to the app layer of
each repository (and its Firestore rules) and are not part of this contract, except for the commitments of section 13.

### 11.3 Record kinds (informative)

Callers already pass these `kind` strings, which the publish paths drop today: `text`, `language-session`,
`language-shard`, `mindseye.lattice_seed`, `mindseye.environment`, `latticeforge.lattice_seed` and
`latticeforge.environment`. A registry of kinds is planned in Owl (O3); this RFC will list it once it exists.

## 12. Validity and verification

### 12.1 The validity predicate

A record R is a valid `shdccp/2` record exactly when:

1. `R.streamVersion` is `"shdccp/2"` and `R.stream` parses strictly (section 4.3), giving chunks c_0 … c_{K−1};
2. the bytes c_0 ‖ … ‖ c_{K−1} are well-formed UTF-8 (TextEncoder output always is), and T is the string whose UTF-8
   encoding (section 3, step 1) is exactly those bytes;
3. growing T with engrams on when R has any of the three engram fields of section 11.1, and off when it has none of
   them, succeeds; and
4. every field of section 11.1 that the grow produced is present in R and equal to the grown value.

Fields that section 11.1 does not list (the app-layer fields of section 11.2) are ignored by this predicate.

Step 2 decodes strictly and keeps every byte. Ill-formed UTF-8 makes R invalid; it is never replaced by U+FFFD. A
leading byte order mark (EF BB BF) is part of the text: it decodes to U+FEFF at the start of T. In JavaScript the
decoder is `new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })`; the default `TextDecoder` drops a leading
U+FEFF and replaces ill-formed bytes, so it regrows another chainId for an honest record whose text starts with U+FEFF.
In Python it is `bytes.decode('utf-8')` (not `'utf-8-sig'`). The vector `shdccp2_record/leading_bom` is such a record.

Step 3 grows with engrams on as soon as R has one engram field, so a record that has some but not all three engram
fields is invalid at step 4.

Step 4 covers each packet against its chunk, the leaf count and each leaf, the root, both weaves, `segCuts`,
`segments`, the chainId and the derived numbers.

### 12.2 What Owl's verifyIntegrity checks today (informative)

`verifyIntegrity` (Owl `scripts/biomesh.js:341-384`) decodes the frames, checks packet parity, compares each recomputed
leaf with `leafHashes[i]` when the record has `leafHashes`, the recomputed root with `merkleRoot` when the record has
one, `weaveChiral`, and the engram stream when the record has one. It does not check the strict stream form, packets
against chunks, the length of `leafHashes`, `weaveMirror`, `segCuts`, `segments`, the chainId, `origBytes`,
`shippedBytes` or `value`. It is a self-consistency check, not the predicate of section 12.1. Owl's `recreateText`
(`scripts/biomesh.js:333-336`) decodes with the default `TextDecoder`, which drops a leading U+FEFF that step 2 of
section 12.1 keeps.

### 12.3 Order of strict checks (draft, for Owl's strict verifier, O3)

A strict verifier reports the first failing check in this order: (1) parity: version, strict parse, at least one
frame, packet parity; (2) canonical: the 720-byte cut, at most 60,000 bytes, canonical residuals, re-framing equals
the stream; (3) crystal: each packet equals crystallize(chunk); (4) leaves: exactly K leaves, each equal, and the
root; (5) weaves: `weaveChiral`, `weaveMirror`, `segCuts`, `segments` and the chainId; (6) derived: the engram fields
when present, `origBytes`, `shippedBytes`, `value`. A record without `stream` or with an unknown `streamVersion` is
reported as legacy and not accepted. A tamper suite with the expected first failing check per case will be added when
the verifier exists.

## 13. Commitments and the attestation profile

A grown record is attested by signing a commitment string; the signature is over H(commitment), carried as
`contentHash`.

```
GROWN/1  commitment = "GROWN/1|" + chainId + "|" + merkleRoot + "|" + weaveChiral + "|" + weaveMirror + "|" + decimal(origBytes)
GROWTH/1 commitment = "GROWTH/1|" + parentChainId + "|" + chainId + "|" + parentMerkleRoot + "|" + merkleRoot + "|" + decimal(addedBytes)
contentHash         = H(commitment)
```

(Owl `scripts/biomesh.js:394-395, 428-429`; BioChain-AI `src/biomesh/biomesh.js:420` has the same GROWN/1 string.)
The `shdccp2_record` vectors carry the GROWN/1 commitment and its contentHash for every record as **informative**
values, outside the lock. Only the generator (Owl) and the RFC reading compute them: the independent oracle has no
GROWN/1 function, and BioChain-AI's `grownCommitment` is the same code as Owl's, so neither counts as a second
implementation. They become normative in a separate suite once one exists (section 17).

**The attestation profile is not specified here.** ATTEST/1 is owned by BioChain-AI: its payload is
`"ATTEST/1|" + keyId + "|" + keyVector + "|" + contentHash + "|" + epochToken`, signed with ECDSA P-256 over SHA-256
(`src/identity/crypto-core.js:136-137` at c975161). Owl's deployed seals use the predecessor SEAL/1
(`"SEAL/1|sealId|sealVector|contentHash|tickToken"`, Owl `scripts/seal-crypto.js:137-138`). Key identity, epoch
grammars, the SEAL/1 mapping and revocation are decided under D9 and D10 and specified by BioChain-AI; this RFC will
point to that profile by version once it is written down there.

## 14. Identifiers that cannot be read as one another (non-normative)

Three 64-bit words in use are all called SHD-CCP. They share a width and nothing else, and none can be decoded as
another:

| Identifier | Where | Form (bits) | What the top byte means |
| :--- | :--- | :--- | :--- |
| `shdccp/2` crystal packet | this RFC; Owl, BioChain-AI, Ebayednoob | 63..60 (always 9) | form, parity, spin |
| RFC 01 draft tile | SHD-CCP `geometric-engine-spec/rfcs/01_einstein_tile_64bit.md:22-26` ("layout NOT frozen") | 39..36 | South Halo |
| `SHDCCP-EINSTEIN-1` | SHD-CCP-core `spec/shdccp_einstein_v1.json:9-18`; PolyShard-Agent and Polycentric-Orchestrator use it as an envelope `protocol_id` | 43..40 | South Halo: cycle step, wheel unit, structure |

The `SHDCCP-EINSTEIN-1` layout copies the Fifteen Lemmas monograph §6.1, Table 4, field for field (Geometric-Labs
RP-0020, extracted text lines 1673-1696 at `3e63eab`; source PDF SHA-256
`df9e4096a67ca198db4673b594e7b7d00eca5fac5a2a2d4451e77c051ba42968`). RFC 01 put the Form ID on the monograph's
stream-slot nibble (36..39). The survey of 2026-11-07 (D18) found:

- The golden packet `9841D88D8B003CEA` is Form 9 with payload16 = 60 as `shdccp/2`, Form 8 under RFC 01, and under
  `SHDCCP-EINSTEIN-1` Form 8 with gate 65, stream slot 8, scale 13, step index 13, structure 0, wheel unit 6 and cycle
  step 4.
- SHD-CCP-core's own vector `69a5412304112233` is Form 1 under `SHDCCP-EINSTEIN-1`, Form 2 under RFC 01 and Form 6 at
  bits 63..60 (where SHD-CCP's Kernel Ontology also puts its header).
- Of SHD-CCP's 66 RFC 01 tile vectors, the Form ID agrees under the 40..43 layout in 8 and the South Halo in all 66.
- The `shdccp/2` form nibble (63..60) lies on `SHDCCP-EINSTEIN-1`'s cycle step and the top bit of its wheel unit.

So a `shdccp/2` packet is no more an Einstein Tile than it is an RFC 01 tile, and no decoder of one may be pointed at
another. Which repository owns the tile layout is a separate decision (S4); it does not affect this RFC.

## 15. Contract vectors

[`contract_vectors/`](../contract_vectors/) holds the vectors of this RFC, with their own `schema.json`, generator,
drift check and lock (D8). Two rules govern them:

1. A suite is **normative** only when two independent implementations agree on every case: the generator runs Owl's
   `scripts/biomesh.js` at the pinned commit, and an implementation independent of it (today the Lexicon's
   `chain.py`, run at test time only) reproduces every expected value. A value the independent implementation does
   not compute is informative, not expected (today the GROWN/1 commitment and its hash, section 13). Lock entries are
   added only by `check.py --promote`, for cases the oracle reproduced in that run, and CI runs the oracle on every
   pull request and push: an entry added to the lock relative to the base commit that the oracle did not reproduce in
   the same run fails the check.
2. A normative case **never changes**. `lock.json` pins each locked case by the SHA-256 of the canonical JSON of its
   id, input and expected value, so neither its input nor its expected value can change. CI refuses any change or
   removal relative to the base commit, and fails when the base commit cannot be resolved. A change to the contract
   needs a new wire version and a new suite.

`contract_vectors/tools/rfc07_reading.py` is an executable reading of this text; CI runs every vector through it, so
the text and the vectors cannot drift apart unnoticed. It does not count as an independent implementation.

## 16. Changes

This text may be clarified without changing the wire format. Any change that alters a field of a record grown from
the same input is a new wire version (`shdccp/3`), which D6 rules out for this overhaul.

## 17. Open items

- [ ] The ATTEST/1 profile pointer (section 13), once BioChain-AI writes the profile down (D9).
- [ ] The strict verifier and its tamper suite (section 12.3, O3).
- [ ] The D7 measurement of Firefox and WebKit against V8 (section 8.7, O3).
- [ ] The kind registry (section 11.3, O3).
- [ ] Appendices for `lineage[].epoch` (number in Owl, token in BioChain-AI), CODEX/1's two payloads, and the
      engram/1 text form used outside records (Owl upper-cases "ß" to "SS" in `engramOf`), carried over from the plan.
- [ ] A normative GROWN/1 suite (section 13), once an implementation independent of Owl's computes the commitment;
      until then `grown_commitment` and `grown_content_hash` stay informative in `shdccp2_record`.
- [ ] `biochain-package/1` (draft), the package that carries a record, its commitment and its attestation: S3 adds
      the section together with its `biochain_package` suite. It waits for the attestation profile (D9, D10), which
      the package carries and this RFC does not specify (section 13).
- [ ] The digest limb convention (F100): how a SHA-256 digest is carried as four 64-bit limbs in a SHDGEV01 binary
      mirror. The choice is between limb i = digest bytes 8i … 8i+7 read big-endian, and the same bytes read
      little-endian, so that a little-endian SHDGEV01 file holds the digest bytes in order; SHD-CCP's one precedent,
      `gram_tqf_collinearity`, lists its low limb first. None of this RFC's suites has a binary mirror. S2 states
      the convention here, before E4 relies on it.

## Appendix A. Source map (Owl-Academy `scripts/biomesh.js` at 7f45f35)

| Section | Lines |
| :--- | :--- |
| 3 limits and chunking | 33-35, 278-281 |
| 4 frames, stream | 218-238 |
| 5 fold64, crystallize, unpack | 40-44, 65-93 |
| 6 rank coder | 239-272 |
| 7 leaves, Merkle | 286, 289-295, 302 |
| 8 crystalQuat, qmul, qconj, qn, quatHex, weaves, segCuts | 45-55, 298-301 |
| 9 engram/1 | 112-165 |
| 10 chainId, ship, value | 303, 305-313 |
| 12.2 verifyIntegrity | 341-384 |
| 13 GROWTH/1, GROWN/1 | 394-395, 428-429 |

## Appendix B. Worked example

Input "GEODESIC", engrams on (vector `shdccp2_record/geodesic`):

```
D            = 47 45 4F 44 45 53 49 43                     n = 8, K = 1
packet       = 9023153CCA000843                             crystal32 = 23153CCA, payload16 = 8, csum = 0x43
residual     = a3d169f44a2d4e9343                           L = 9
stream       = 9023153CCA00084300000009a3d169f44a2d4e9343
leafHashes   = [6ba8d71b6ebeb9b200710dfc47ac493989fb1323eea51794a3b94ff9fa588a07]
merkleRoot   = 6ba8d71b6ebeb9b200710dfc47ac493989fb1323eea51794a3b94ff9fa588a07   (K = 1: the leaf)
weaveChiral  = 0.696672708558,0.180618850367,0.516053858191,-0.464448472372
weaveMirror  = 0.696672708558,-0.180618850367,-0.516053858191,0.464448472372
segCuts      = [0,0,0,0,1,1,1,1]
engramStream = 5C896A4801C9C24C      engramCount = 1      engramMeanJ = 0.125
chainId      = BC-787287da41a1375701094b64
shippedBytes = 21 + 8 + 32 + 40 = 101                     value = 0.0792
```
