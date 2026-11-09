<!-- SPDX-License-Identifier: CC0-1.0 -->
# RFC 07: the shdccp/2 biochain contract

| | |
| :--- | :--- |
| **Status** | Draft text. The wire format it describes is already deployed and frozen: every published chainId commits to it (D6). |
| **Spec version** | 0.1.0 |
| **Wire version** | `shdccp/2` (the record field `streamVersion`) |
| **Vectors** | [`contract_vectors/`](../contract_vectors/): `shdccp2_packet`, `shdccp2_chunk`, `shdccp2_merkle`, `shdccp2_arith`, `shdccp2_weave`, `engram1`, `shdccp2_record`, `shdccp2_limits`, `merkle_rules_same_bytes`, `rfc6962_lists`, `attest1_profile`, `engram1_keys`, `rng_mulberry32`, `shdccp2_tamper`, and the drafts `shdccp2_tamper_open` and `attest1_profile_open` (section 15) |
| **Reference implementation** | Owl-Academy `scripts/biomesh.js` at `7f45f356f5c46ea0eb099905b2505a06e8c28fd7` (MIT), the generator's pin; its functions moved unchanged to `scripts/biomesh-core.js` at `9e7701fa26eb4b1be40fc96521dde76fa9d320d6`. The strict verifier of section 12.3 is `verifyIntegrityStrict` in `scripts/biomesh-core.js` at O3's commit `f1d31afd48f8424348972b4d68abf8e23830a539` (Appendix D; the pin follows O3's published commit) |
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

**Out of scope.** App-layer record fields (owners, titles, lineage, transfers, ratings; section 11.2) other than the
`kind` registry (section 11.3), CODEX/1 codices, LATTICE-SEED/1 and ENVIRONMENT/1, and Firestore rules. Appendices E
and F describe, as informative text only, the two meanings of CODEX/1 and the two shapes of `lineage[].epoch` (D20).
BIOSEED/1 and RFC 6962 trees (sections 7.4, 7.5) and the attestation profile (sections 13.1-13.7) are stated only as
far as the contract vectors need them, as their owners' code computes them; their owners' own documents take
precedence.

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

### 2.5 Digests as 64-bit limbs

Where a 32-byte digest, such as a SHA-256 of this RFC, is carried as four 64-bit integers, for example the `u64`
fields `sha_0` … `sha_3` of a SHDGEV01 binary mirror (F100), limb i is the integer whose **big-endian** bytes are
digest bytes 8i … 8i+7, for i = 0 … 3. So `sha_0` holds the first eight bytes, and the 16 hex digits of limb i are
digits 16i … 16i+15 of the digest's hex text: the reading section 13.1 already uses for the first eight bytes of a
SHA-256, and the order in which section 2.1 writes every 64-bit word. A container then stores each limb in its own byte order:
a little-endian SHDGEV01 file holds limb i as digest bytes 8i+7 … 8i, and so does not hold the digest bytes in order.
In JSON a limb above 2^53 is carried as SHD-CCP's envelope carries any such value (a string).

For H("") = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` the limbs are `E3B0C44298FC1C14`,
`9AFBF4C8996FB924`, `27AE41E4649B934C` and `A495991B7852B855`; a little-endian file holds the first as the bytes
`14 1C FC 98 42 C4 B0 E3`. SHD-CCP's `gram_tqf_collinearity` lists the low limb of a 128-bit integer first
(`tqf_lo`, then `tqf_hi`); a digest is a byte string, not an integer, so that order does not carry over. No suite of
this RFC has a binary mirror yet.

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

A residual costs at most 25 bits per byte (section 6.6), so a chunk of len bytes has L ≤ ⌈25 · len / 8⌉, which is
2,250 for a full chunk, and the stream of an n-byte input has at most Σ_i (16 + 8 + 2 · ⌈25 · len_i / 8⌉) hex digits.
For 60,000 bytes (83 full chunks and one of 240 bytes) that is 377,016. A bound that depends only on the frame count
K is K × 4,524 hex digits, at most 84 × (16 + 8 + 4,500) = 380,016; size caps (for example on a stored record) use
this one. The bounds are not reached: the highest-cost text vector, `shdccp2_limits/grow_de_bruijn_60000`, has a
stream of 189,622 hex digits (P8).

The bounds are arithmetic on this section's formula, which no implementation independent of the generator computes,
so the vectors carry them as informative values: `informative.stream_bound` on each grown record of
`shdccp2_limits` (n = 1, 720, 721, 59,760 and 60,000) gives the chunk count, the last chunk's length, 25 bits per
byte, 2,250 residual bytes for a full chunk, the length-exact bound and the frame-count cap for that record's n. The
expected values of those cases are the streams themselves, which the independent implementation reproduces.

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

Within one 720-byte chunk the largest codes do not occur. A context gains a candidate only on a visit with a byte it
has not seen, and its next visit needs the context's two bytes again after that byte, so new candidates are at least
three bytes apart, except when the new byte is one of the context's own bytes. A context therefore holds at most 241
candidates in a chunk (`shdccp2_limits/chunk_hub_720` reaches 241 in the start context (0, 0)), and no code inside a
chunk exceeds `gamma(241)` + 8 = 23 bits. The 25-bit escape and the 17-bit hit at rank 256 need longer inputs
(`shdccp2_limits/coder_escape_after_255_candidates` and `coder_hit_at_rank_256` run the coder on 764 and 767
bytes). Size limits still use 25 bits per byte (section 4.4).

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
rule tag (F16). Only the first is `shdccp/2`. Sections 7.4 and 7.5 state the other two exactly, and the vectors
`merkle_rules_same_bytes` apply all three to the same chunks: the three roots always differ.

| Rule | Leaf | Node | Odd level | Used by |
| :--- | :--- | :--- | :--- | :--- |
| `shdccp/2` (this RFC) | `H(i + "\|" + H(latin1(chunk)))` | `H(left_hex + right_hex)` | duplicate last | Owl, BioChain-AI JS, Ebayednoob |
| BIOSEED/1 | `SHA-256(u32be(i) ‖ SHA-256(chunk))`, raw digests | `SHA-256(left ‖ right)`, raw digests | duplicate last; empty = 32 zero bytes | BioChain-AI `protocol/codex_engine.py:196-207` |
| RFC 6962 | `SHA-256(0x00 ‖ d)` | `SHA-256(0x01 ‖ L ‖ R)` | split at the largest power of two below K | Lexicon corpus manifests |

A verifier MUST dispatch on `streamVersion` and MUST NOT accept a root computed under another rule.

### 7.4 BIOSEED/1 (informative; owned by BioChain-AI)

BioChain-AI's `protocol/codex_engine.py` (`_chunk_hash`, `merkle_root`) commits its chunks with this rule. Hashes are
over raw bytes, and hex is lower-case:

```
bioseedLeaf(i, chunk) = hex( SHA-256( u32be(i) ‖ SHA-256(chunk) ) )     # u32be(i): i as 4 bytes, big-endian;
                                                                          # the inner digest as its 32 raw bytes
bioseedRoot(leaves):
    level = [the 32 bytes of each leaf]; an empty list gives 32 zero bytes as the root
    while len(level) > 1:
        if len(level) is odd: append a copy of the last element
        level = [ SHA-256(level[2j] ‖ level[2j+1]) for j in 0 .. len(level)/2 − 1 ]
    return hex(level[0])
```

BIOSEED/1 records cut their data at the chunk size their codex names (64 to 4,096 bytes); the vectors apply the rule
to the 720-byte cut of section 3 only to compare the three rules over the same bytes.

### 7.5 RFC 6962 trees

The Hyperbolic Lexicon's corpus manifests use RFC 6962 trees. Entries are byte strings; hashes are 32 raw bytes,
written as lower-case hex in the vectors.

- The tree hash is RFC 6962 section 2.1's: MTH({}) = SHA-256(""), MTH({d}) = SHA-256(0x00 ‖ d), and for n > 1,
  MTH(D[n]) = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n])) with k the largest power of two smaller than n. No node is
  duplicated.
- The audit path PATH(m, D[n]) and the consistency proof PROOF(m, D[n]) = SUBPROOF(m, D[n], true) are RFC 6962
  sections 2.1.1 and 2.1.2's. PROOF is used for 0 < m ≤ n; for m = n it is the empty list.
- Verification is RFC 9162's: section 2.1.3.2 for an inclusion proof (an index not below the size fails) and section
  2.1.4.2 for a consistency proof with 0 < m < n. For m = n a proof verifies exactly when it is empty and the two
  roots are equal (RFC 9162's algorithm fails every empty proof); m = 0 and m > n fail.
- Verification checks a proof against the size and the root it is given; it does not check that they belong together.
  A verifier MUST take the size and the root together from one tree head
  (`rfc6962_lists/verify_inclusion_node_as_leaf_other_size` is a proof that checks out against the root of a tree of
  another size).

The vectors `rfc6962_lists` give roots for K = 0 … 64 entries, audit paths, consistency proofs and verification on
altered inputs; their first eight entries are the RFC 6962 test entries of the certificate-transparency project.

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

The seeds engram/1 uses are the codes of the letters A … Z, 65 … 90 (section 9.3). Because the seed is reduced to
int32 first, seeds equal modulo 2^32 give the same draws. The vectors `rng_mulberry32` give the first 64 draws of each
letter seed and 16 draws of edge seeds. mulberry32 is the only pseudo-random generator in this contract (P6); the
others in these repositories (xoshiro128** seeded by splitmix32, SplitMix64) never enter a record.

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

### 9.6 The engram key of a string

Outside records Owl computes an engram key for any string: `engramOf(text)` in `scripts/biomesh.js` (and `engramHex`
in `biomesh-core.js` since `9e7701f`) is the grid of the string's letters. The key of a string S is gridHex of the ⊕
of the grids of the letters A-Z of S after full Unicode default upper-casing (ECMAScript
`String.prototype.toUpperCase`, which applies the unconditional mappings of SpecialCasing: "ß" becomes "SS", "ﬁ"
becomes "FI", "ŉ" becomes "ʼN", "ı" becomes "I"), in order, every other character skipped. Letters cancel in pairs, so
the key records the parity of each letter's count ("Geodesic geodesic" has the all-zero key).

The key is written as 16 **upper-case** hex digits; that is its canonical form, and a copy that prints lower-case
(the Engram page's `ttmpt_core_v1.js`) upper-cases before comparing (F114). Inside a record (section 9.1) the tokens are
ASCII, so the upper-casing there is ASCII: the text "Straße" contributes the two tokens "Stra" and "e" to a record's
engram stream, while as one string its key is that of "STRASSE". The vectors `engram1_keys` give the letters and the key
of 34 strings, among them "GEODESIC" → `5C896A4801C9C24C`.

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

### 11.3 Record kinds (the registry)

A published record may carry `kind`, a string naming what the grown text is. These are the registered kinds:

| Kind | What the grown text is |
| :--- | :--- |
| `text` | text grown in a console |
| `language-session` | a Language Growing session transcript |
| `language-shard` | a language shard grown for a seed corpus (the Lexicon's packages) |
| `mindseye.lattice_seed` | an Owl Mind's Eye 3D lattice seed (LATTICE-SEED/1) |
| `mindseye.environment` | an Owl Mind's Eye 3D environment (ENVIRONMENT/1) |
| `latticeforge.lattice_seed` | a BioChain-AI Lattice Forge lattice seed |
| `latticeforge.environment` | a BioChain-AI Lattice Forge environment |

Owl's Mind's Eye 3D already passes the two `mindseye` kinds and BioChain-AI's Lattice Forge the two `latticeforge`
kinds; the publish paths dropped them until the registry (P14).

A publisher stores `kind` only when it is one of these strings and refuses any other (Owl's `KINDS` and
`validateKind`, O3; BioChain-AI's generated copy, B2). A reader treats a record without `kind` (one published before
the registry) as of unknown kind. `kind` is an app-layer field (section 11.2): it is not a grown field, it does not
enter the chainId or a commitment, and the validity predicate (section 12.1) ignores it. A new kind is registered by a
change to this table, never by a publisher alone.

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

### 12.3 Order of strict checks

A strict verifier (Owl's `verifyIntegrityStrict`, O3, and the copies generated from it for BioChain-AI, B2, and the
Engram page, E3) checks the predicate of section 12.1 as six checks, in this order. It stops at the first check that
fails and reports that check's name.

1. **parity**: R is an object (a JSON object, not an array) with a string `stream` and `streamVersion` "shdccp/2"
   (otherwise R fails here, and a record of that kind is legacy, below); the stream parses strictly (section 4.3,
   items 1-3) into at least one frame; every packet's parity holds (section 5.5).
2. **canonical**: the payload16 of every frame but the last is 720, and the last is 1 to 720 (the 720-byte cut); the
   total is at most 60,000 bytes; each residual decodes to payload16 bytes (section 6.4) and is canonical (section
   6.5); framing the packets and residuals again gives the stream exactly (section 4.2); and the decoded bytes are
   well-formed UTF-8 (section 12.1, step 2).
3. **crystal**: every packet equals `crystallize(chunk_i)` under the raw rule (section 5.4).
4. **leaves**: `leafHashes` is present with exactly K entries, entry i equal to `leaf(i, chunk_i)` (section 7.1), and
   `merkleRoot` is present and equal to the root of the leaves (section 7.2).
5. **weaves**: `weaveChiral`, `weaveMirror`, `segCuts`, `segments` (7) and `chainId` equal the values sections 8 and
   10 give for the chunks.
6. **derived**: when R has any of the three engram fields, all three equal the engram layer of T (section 9.5); and
   `origBytes`, `shippedBytes` and `value` equal section 10's values.

Numbers compare as binary64 values and must be JSON numbers (the string "7" is not the number 7). The six checks
together are the predicate of section 12.1: a record passes all six exactly when it is valid.

A record without a string `stream`, and a record whose `streamVersion` is missing or is not "shdccp/2", are **legacy**
(section 11.1): the verdict is a failure at parity with `legacy` set, and such a record is never accepted as
`shdccp/2`. A value that is not a record (null, an array, a string, a number) also fails at parity, but it is not
legacy: there is no older format it could be in.

### 12.4 The strict verdict

The verdict of a strict verifier is `{ok, failed, legacy, checks}`: `ok` is true exactly when all six checks pass;
`failed` is the name of the first failing check, or null; `legacy` is true only for a legacy record; `checks` lists the
checks that ran, in order, each as `{name, ok, detail}`. Owl's verifier is synchronous and takes the SHA-256 function
as a parameter, so a copy can run with another implementation of H.

Pages label records by their verdict (D15): "strict ok", "legacy", "failed at <check>", or "self-consistent only,
failed at <check>" for a record that the self-consistency check of section 12.2 accepts. A failing or legacy record is
labelled, kept out of seeds and success scores, and never deleted.

### 12.5 Tamper vectors

The suite `shdccp2_tamper` pins, for each value given to a strict verifier, the verdict of section 12.4 without its
`checks` and `legacy`: `ok` and the first failing check of section 12.3. Its expected values are the verdicts of Owl's
`verifyIntegrityStrict` (Appendix D). The independent verifier is the Hyperbolic Lexicon's hardened verifier, steps
1-6 (parity .. derived: the same names in the same order) of `reference/lexicon/verify.py`, the reference that
`lexicon_core.js verifyPackage` follows check for check. The two agree on all 79 cases, and `verifyPackage` itself
gives the same first failing check on every one.

`legacy` is informative: the independent verifier has no notion of it (its parity step gives the one reason "no
shdccp/2 record" both for a value that is not an object and for an object with another `streamVersion`), so the
suite's `informative.legacy` is Owl's flag. `check.py` maps the independent verifier's parity reasons to a legacy flag
and compares it with that value, but the mapping is the adapter's, not the verifier's, and does not count towards
rule 1 of section 15. The values are:

- five honest records of `shdccp2_record` (among them a leading U+FEFF, a 0x80 crystal byte and a four-byte character
  split by the 720-byte cut), which every verifier accepts;
- **parity**: legacy records (parallel `streams` and `chunkLens`; `streamVersion` missing, "shdccp/3" or "SHDCCP/2";
  `stream` missing or not a string), values that are not records, an empty stream, a truncated residual or frame
  header, trailing bytes, a non-hex character in a packet, a length or a residual, a negative length ("-000000c"), a
  length one more than its residual, a packet whose parity bit is flipped, and a crystal bit flipped without the
  parity fix;
- **canonical**: the same 1,441 bytes cut 720/719/2 (a 719-byte middle frame) and 1/720/720, an empty last frame,
  60,001 bytes in 84 frames, T9 (a residual bit flip that decodes to the same chunk, inside an escape code and in the
  padding), a residual with an extra zero byte, one byte short, or zeroed, and payload16 one less or one more;
- **crystal**: T2 (a crystal bit flipped, parity fixed), a checksum bit (amp, freq), the form, the spin, the packets of
  two frames swapped, and a 0x80 crystal byte written 0x81, as the kernel normalisation would write it;
- **leaves**: T1 (leafHashes and merkleRoot removed), each of them removed alone, merkleRoot null, an extra leaf, a
  missing leaf, a changed leaf, a leaf in upper case, a changed root, the BIOSEED/1 root of the same chunks, and two
  whole frames swapped;
- **weaves**: T8 (chainId changed), chainId in upper case or missing, weaveMirror changed or equal to weaveChiral,
  weaveChiral changed, segCuts changed, given as strings or with seven entries, and segments 8, "7" or missing;
- **derived**: the engram stream changed or in lower case, engramCount and engramMeanJ changed, engramStream removed
  alone, all three engram fields removed (shippedBytes and value still count them), an engram field added to a record
  grown without engrams, origBytes changed or a string, shippedBytes and value changed, and value a string.

`informative` gives Owl's `legacy` flag and detail, whether the self-consistency check of section 12.2 accepts the
value (it accepts T1, T2, T8 and T9, among others), and the label of section 12.4.

**Where the independent verifier disagrees.** On ten more values the Lexicon's verifier names another first failing
check than this text. They are in the draft suite `shdccp2_tamper_open`, whose expected values are this text's (and
Owl's); `lexicon_core.js verifyPackage` gives the same answers as `verify.py`. Every verifier rejects every one of
these records; only the check that reports it differs.

| Values | This text (Owl) | The Lexicon's verifier | Why |
| :--- | :--- | :--- | :--- |
| a packet in lower case, or one letter of it | parity | crystal | its parse reads hex digits of either case (section 4.3 asks for upper case); the packet then differs from `crystallize(chunk)` |
| a residual in upper case, or one letter of it | parity | canonical | the residual differs from the re-encoded chunk |
| a residual length in upper case | parity | canonical | the re-framed stream writes the length in lower case |
| ill-formed UTF-8 in records whose other fields are computed from the same bytes (a lead byte at the end, an overlong form, an encoded surrogate, a lone continuation byte, an invalid sequence across the 720-byte cut) | canonical | derived | it has no UTF-8 check of its own; its derived step fails when the normaliser of its V0 id stream refuses the bytes |

The suite stays draft until the order is settled (section 17). Either this text moves the two rules (hex digits of
either case at parity, the case then enforced by crystal and canonical as in the table; the UTF-8 check at the start
of derived) and Owl's verifier moves with it, or the Phase 2 criterion of matching `verifyPackage` case for case leaves
these values out. The Lexicon's code does not change either way (D4), and the validity predicate of section 12.1 is
the same under both orders.

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

**The attestation profile.** ATTEST/1 is owned by BioChain-AI (D5) and is the canonical profile (D9); Owl's deployed
seals use its predecessor SEAL/1, which stays valid for existing seals. Sections 13.1-13.7 record both exactly as the
pinned code computes them (BioChain-AI `src/identity/crypto-core.js` and `epoch-service.js` at
`dfbe3f2e94c2ff8101f39054bedf29ec67f75704`; Owl `scripts/seal-crypto.js` and `scripts/schumann-oracle.js` at
`7f45f35`; Appendix C), so that the `attest1_profile` vectors have a text to be read against. BioChain-AI's own profile
document, once written (D9, D10), takes precedence, and this RFC will point to it by version. What a key's status
means for verification (D10) is not specified here.

### 13.1 Identities

```
identityId(seed, uid) = "0x" + hex16( V(trim(seed)) ⊕ u64be(first 8 bytes of SHA-256(UTF-8(uid))) )
```

`trim` is ECMAScript's `String.prototype.trim`; an empty trimmed seed is an error (`empty-seed`). V is the 64-bit
vector of section 13.2 read as an integer, and hex16 writes a 64-bit integer as 16 upper-case hex digits. Owl's
`cosmologicalId` has the same derivation.

`trim` removes from both ends exactly the code points ECMAScript calls WhiteSpace or LineTerminator: U+0009 to
U+000D, U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000 and U+FEFF. Other
languages' trims use other sets: Python's `str.strip()` keeps U+FEFF and removes U+001C to U+001F and U+0085. A seed
that starts or ends with one of those code points therefore gives another identity there. The draft suite
`attest1_profile_open` holds three such seeds; the Lexicon's `attest.py`, which uses `str.strip()`, disagrees on all
three (section 17).

### 13.2 Vectors of strings, key vectors and seal vectors

```
V(s):
    h = SHA-256(UTF-8(s))                                   # 32 bytes
    b = h ‖ (255 − h[0], …, 255 − h[31])                     # 64 bytes: each byte, then its complement
    acc = 0
    for x in 0..3, for y in 0..3, for z in 0..3:             # x outermost
        acc = (acc · 31 + b[16x + 4y + z] · (x+1)(y+1)(z+1)) mod 2^64
    return the 16 upper-case hex digits of acc

PARAMS      = {"lattice":"E8","hilbertDim":64,"modulus":240,"manifold":"clifford","coherency":0.75,"torsion":0.5}
keyVector   = V(identityId + "|" + PARAMS + "|" + epochToken)          # ATTEST/1
sealVector  = V(cosmologicalId + "|" + PARAMS + "|" + tickToken)       # SEAL/1
```

PARAMS is the canonical parameter string of the default parameters, JSON without spaces in this key order (Owl's and
BioChain-AI's `canonicalParams({})`). Other parameters give another PARAMS; the vectors use the defaults only. The
floating-point coordinates and entropy that the same code computes enter no payload.

### 13.3 Public keys and fingerprints

Keys are ECDSA keys on P-256 (FIPS 186-4). A public key is carried as a JWK `{kty: "EC", crv: "P-256", x, y}`, x and
y being the base64url encodings, without padding, of the 32-byte big-endian coordinates; a coordinate below 2^248
keeps its leading zero bytes (`attest1_profile/attest_key_C_short_x` and `attest_key_D_short_y`).

```
keyId  = "K-" + first 24 hex digits of H(x + "|" + y)          # x, y: the JWK strings
sealId = "S-" + first 24 hex digits of H(x + "|" + y)
```

One key therefore has the same 24 digits as a keyId and as a sealId. (BioChain-AI's Python mesh,
`protocol/biochain_mesh.py:132` at `dfbe3f2`, names another value sealId: "S-" + the first 24 hex digits of H over
the lower-case hex of the integer coordinates, `"%x|%x"`; it is not SEAL/1's sealId. See Appendix E.)

Only Owl's `seal-crypto.js` builds SEAL/1, so the vectors carry a SEAL/1 sealId as an informative value and give the
SEAL/1 payloads as inputs; the seal vector and the signatures over those payloads are expected values (section 15).

### 13.4 Payloads

```
ATTEST/1 payload = "ATTEST/1|" + keyId  + "|" + keyVector  + "|" + contentHash + "|" + epochToken
SEAL/1 payload   = "SEAL/1|"   + sealId + "|" + sealVector + "|" + contentHash + "|" + tickToken
contentHash      = H(commitment)                                 # a GROWN/1, GROWTH/1 or other commitment string
```

An ATTEST/1 block carries `{keyId, keyVector, contentHash, epochToken, sig}` (an Owl seal block `{sealId, sealVector,
contentHash, tickToken, sig}`); a verifier rebuilds the payload with the key vector from its registry, not the one in
the block.

### 13.5 Signatures

A signature is ECDSA P-256 with SHA-256 over the UTF-8 of the payload, carried as IEEE P1363 r ‖ s: 64 bytes, each half
left-padded to 32 bytes, written as 128 lower-case hex digits.

- WebCrypto signs with random nonces, so live signatures cannot be reproduced. The vectors sign with the deterministic
  nonce of RFC 6979 section 3.2 (HMAC-SHA-256), which a verifier accepts like any other nonce;
  `attest1_profile/rfc6979_a25_sample` and `_test` reproduce RFC 6979 appendix A.2.5.
- (r, s) and its twin (r, n − s) both verify for the same payload; s is high when s > (n − 1) / 2. BioChain-AI's
  `signPayload` writes the low-S form (`toLowS`) and its `verifyPayload` accepts both; Owl's `signPayload` writes
  what WebCrypto returns. Nothing may be keyed or deduplicated by signature bytes.
- DER (X.690; SEC 1's Ecdsa-Sig-Value) is `SEQUENCE { INTEGER r, INTEGER s }` with minimal two's-complement integers:
  an integer whose top bit is set gains a leading 0x00 byte, and one below 2^248 is shorter
  (`attest_key_B_short_r`, `attest_key_B_short_s`). Libraries that verify DER (Python's `cryptography`, OpenSSL) need
  the P1363 form converted, and the conversion back left-pads r and s to 32 bytes.

### 13.6 The registry snapshot text

A snapshot is a pinned list of the keys a verifier trusts without a live registry (the Lexicon's packages pin one).
Its text is a JSON array, written without spaces (as `JSON.stringify` writes it), of one object per key,
`{keyId, publicJwk: {kty, crv, x, y}, keyVector, status}` with the keys in this order, sorted by keyId; keyId is the
fingerprint of publicJwk (section 13.3). status is one of `active`, `revoked` and `retired`. Two entries with one keyId,
or any other status (Owl's `recalled` and `archived` are seal states, not key states), make the snapshot invalid. A
snapshot is pinned by H(its text).

### 13.7 Epoch and tick tokens

D9 fixes the grammars. The canonical epoch token is `EPOCH.<n>`, n = ⌊t / 10,800,000⌋ for a time t in milliseconds
since the Unix epoch (3-hour windows; BioChain-AI `computeEpoch`). Two alternatives are registered:

- Owl's tick token `SCHU.<n>.<freq>.<kp>` (`computeTick`), carried by SEAL/1: n as above; kp the planetary K-index
  clamped to 0 … 9, or 2 when none is known; freq = number(toFixed(7.83 · (1 + kp / 100), 4)); freq and kp written
  as ECMAScript writes numbers;
- `EPOCH-OFFLINE-<YYYY-MM-DD>`, a UTC date, for keys made offline (the Lexicon's).

A token enters a key vector and a payload as its exact text. The vectors use one token of each grammar; how a token
was derived from a time is given there as informative.

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

1. A suite is **normative** only when two independent implementations agree on every case. The generator computes
   each suite with the code its `source` names, read-only at a pinned commit: Owl's `scripts/biomesh.js` for the codec
   suites; BioChain-AI's `crypto-core.js` and Owl's `seal-crypto.js` for `attest1_profile`; Owl's
   `verifyIntegrityStrict` (`biomesh-core.js`, O3) for the tamper suites; and its own `cv_spec.mjs`, written from the
   specifications it cites, for what neither computes (RFC 6962 trees and proofs, BIOSEED/1, deterministic signatures
   and DER, the coder's code lengths, the snapshot text). An implementation independent of that code reproduces every
   expected value at test time: the Lexicon's `chain.py`, `manifest.py`, `attest.py` (with Python's `cryptography`)
   and `verify.py` (steps 1-6), the Engram reference's `ttmpt.py`, and for BIOSEED/1 BioChain-AI's `codex_engine.py`.
   A value the independent implementation does not compute is informative, not expected, and so is a value that only
   an adapter in `check.py` or the RFC reading computes: the GROWN/1 commitment and its hash (section 13), the size
   bound of section 4.4, the sealId of SEAL/1 (section 13.3) and the strict verdict's `legacy` (section 12.5). Lock
   entries are added only by `check.py --promote`, for cases the oracle reproduced in that run, and CI runs the oracle
   on every pull request and push: an entry added to the lock relative to the base commit that the oracle did not
   reproduce in the same run fails the check.
2. A normative case **never changes**. `lock.json` pins each locked case by the SHA-256 of the canonical JSON of its
   id, input and expected value, so neither its input nor its expected value can change. CI refuses any change or
   removal relative to the base commit, and fails when the base commit cannot be resolved. A change to the contract
   needs a new wire version and a new suite.

`contract_vectors/tools/rfc07_reading.py` is an executable reading of this text; CI runs every vector through it, so
the text and the vectors cannot drift apart unnoticed. It does not count as an independent implementation. A draft
suite (one not yet agreed) is checked against this reading like the others; the oracle's disagreements with it are
listed, not failures, and it is never locked while they last.

| Suite | Sections | Generator's source | Independent implementation |
| :--- | :--- | :--- | :--- |
| `shdccp2_packet`, `shdccp2_chunk`, `shdccp2_merkle`, `shdccp2_arith`, `shdccp2_weave`, `engram1`, `shdccp2_record` | 3-12 | Owl `biomesh.js` | Lexicon `chain.py`, Engram `ttmpt.py` |
| `shdccp2_limits` | 4.4, 6.6 | Owl `biomesh.js` (residuals, grown streams), `cv_spec.mjs` (code lengths) | Lexicon `chain.py` (the coder and its decode trace, grown streams); the bound of section 4.4 is informative |
| `merkle_rules_same_bytes` | 7.2-7.5 | Owl `biomesh.js` (shdccp/2), `cv_spec.mjs` (BIOSEED/1, RFC 6962) | Lexicon `chain.py`, `manifest.py`; BioChain-AI `codex_engine.py` |
| `rfc6962_lists` | 7.5 | `cv_spec.mjs` | Lexicon `manifest.py` |
| `attest1_profile` | 13.1-13.7 | BioChain-AI `crypto-core.js`, Owl `seal-crypto.js`, `cv_spec.mjs` (signatures, DER, snapshot) | Lexicon `attest.py` with `cryptography`; it has no SEAL/1 code, so a SEAL/1 case's payloads are inputs and its sealId informative |
| `attest1_profile_open` (draft) | 13.1 | BioChain-AI `crypto-core.js` (`computeIdentityId`) | none yet: `attest.py` trims with Python's `str.strip()`, not ECMAScript's `trim` |
| `engram1_keys` | 9.6 | Owl `biomesh.js` (`engramOf`) | Engram `ttmpt.py` |
| `rng_mulberry32` | 9.2 | Owl `biomesh.js` (`mulberry32`) | Engram `ttmpt.py` |
| `shdccp2_tamper` | 12.3-12.5 | Owl `verifyIntegrityStrict` (O3, `biomesh-core.js`) | Lexicon `verify.py` (`verifyPackage`), steps 1-6: `ok` and the first failing check; `legacy` is informative |
| `shdccp2_tamper_open` (draft) | 12.5 | Owl `verifyIntegrityStrict` | none yet: the Lexicon's verifier names another first failing check (section 12.5) |

## 16. Changes

This text may be clarified without changing the wire format. Any change that alters a field of a record grown from
the same input is a new wire version (`shdccp/3`), which D6 rules out for this overhaul.

## 17. Open items

- [ ] The ATTEST/1 profile pointer (section 13): sections 13.1-13.7 now record ATTEST/1 and SEAL/1 as the pinned code
      computes them (`attest1_profile`); open are BioChain-AI's own profile document (D9) and what key statuses mean
      for verification (D10).
- [x] The tamper suite (section 12.5): `shdccp2_tamper`, 79 cases on which Owl's strict verifier and the Lexicon's
      agree on `ok` and the first failing check.
- [ ] The strict verdict's `legacy` flag (section 12.5) stays informative until an implementation independent of Owl's
      reports it; the Lexicon's verifier has no notion of legacy.
- [ ] The first failing check for hex case and ill-formed UTF-8 (section 12.5, `shdccp2_tamper_open`): this text
      reports them at parity and at canonical, the Lexicon's verifier at crystal or canonical and at derived. Decide
      whether this text and Owl's verifier move to the Lexicon's order, or the Phase 2 criterion leaves these values
      out. Until then the ten cases stay draft.
- [ ] Owl's deployed `verifyIntegrity` (section 12.2; `scripts/biomesh.js` at `7f45f35`, and the same function in
      `scripts/biomesh-core.js` at `9e7701f`) does not return on a stream whose length field a lenient `parseInt`
      reads as negative (`shdccp2_tamper/length_negative`): its frame loop goes back to the frame start and keeps
      growing. O3's commit (`f1d31af`) makes that lenient parse throw on a negative length, so `verifyIntegrity` there
      returns a failure; until O3 is deployed, a page should not run the deployed `verifyIntegrity` after a strict
      failure at parity. The strict parse already rejects such a stream.
- [ ] The D7 measurement of Firefox and WebKit against V8 (section 8.7, O3).
- [x] The kind registry (section 11.3).
- [x] The engram/1 key of a string used outside records (section 9.6, `engram1_keys`).
- [x] Appendices for CODEX/1's two meanings (Appendix E) and `lineage[].epoch` (Appendix F), informative (D20).
      Renaming the Python mesh payload and the schema converter are Phase 6 (D20).
- [ ] ECMAScript's `trim` in identities (section 13.1, `attest1_profile_open`): the Lexicon's `attest.py` uses Python's
      `str.strip()` and gives other identities for seeds that start with U+FEFF, U+0085 or U+001C. The three cases stay
      draft until an implementation independent of BioChain-AI's trims as section 13.1 says. Issued identities fix the
      rule, so this text does not change.
- [ ] A second SEAL/1 implementation (section 13.3): until one exists, the SEAL/1 sealId stays informative and the
      SEAL/1 payloads are inputs of `attest1_profile`.
- [ ] A normative GROWN/1 suite (section 13), once an implementation independent of Owl's computes the commitment;
      until then `grown_commitment` and `grown_content_hash` stay informative in `shdccp2_record`.
- [ ] `biochain-package/1` (draft), the package that carries a record, its commitment and its attestation: S3 adds
      the section together with its `biochain_package` suite. It waits for the attestation profile (D9, D10), which
      the package carries and this RFC does not specify (section 13).
- [x] The digest limb convention (F100): section 2.5 (limb i is digest bytes 8i … 8i+7 read big-endian). E4 brings
      the golden-vector proposal's text in line with it. None of this RFC's suites has a binary mirror yet.

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

## Appendix C. Source map (attestation profile)

| Section | File and lines |
| :--- | :--- |
| 13.1 identityId | BioChain-AI `src/identity/crypto-core.js` 113-136 (at `dfbe3f2`); Owl `scripts/spire-registrar.js` 134 (cosmologicalId, at `7f45f35`) |
| 13.2 V, key and seal vectors | `crypto-core.js` 72-111, 141-160; Owl `scripts/seal-crypto.js` 54-107 |
| 13.3 keyId, sealId | `crypto-core.js` 227-229; `seal-crypto.js` 132-134 |
| 13.4 payloads | `crypto-core.js` 232-233; `seal-crypto.js` 137-138 |
| 13.5 low-S form, sign, verify | `crypto-core.js` 168-224; `seal-crypto.js` 123-130 |
| 13.7 tokens | BioChain-AI `src/identity/epoch-service.js` 23-30; Owl `scripts/schumann-oracle.js` 21-29 |

## Appendix D. Source map (strict verifier, Owl-Academy `scripts/biomesh-core.js` at O3's commit)

At `f1d31afd48f8424348972b4d68abf8e23830a539` (file SHA-256 `0c7e9b3e…`), O3's commit. The pin follows O3's published
commit and then its merge commit. The file's hash may change with the pin, but the verdicts at the new pin must
reproduce every locked case of `shdccp2_tamper` (a changed verdict changes a locked case, which rule 2 of section 15
refuses), and these line numbers are checked again.

| Section | Lines |
| :--- | :--- |
| 4.3 strict parse (`parseBiochainStreamStrict`) | 271-289 |
| 2.2 H in plain JS (`sha256HexSync`); leaves, root and weaves (`leafHashSync`, `merkleRootSync`, `chainWeaves`) | 467-516 |
| 12.3 the checks in order (`STRICT_CHECKS`, `verifyIntegrityStrict`) | 518-644 |
| 12.4 the verdict's failing check and label (`failedCheck`, `strictLabel`) | 646-657 |
| 11.3 the kind registry (`KINDS`, `validateKind`) | 757-770 |

## Appendix E. CODEX/1: one tag, two meanings (informative, D20)

The tag `CODEX/1` names two different things. Neither is part of the `shdccp/2` contract, and a verifier MUST NOT read
one as the other. Phase 6 renames the Python mesh payload; live collections and fields keep their names (D20).

**1. The JS codex commitment** (Owl `scripts/biomesh.js` 499-541 and 562 at `7f45f35`; BioChain-AI
`src/biomesh/biomesh.js` 488-529 and 551 at `dfbe3f2`, the same code).

- A codex is a packet stream: GEAR (form 1, spin = order, payload16 = chunk), then one PRIME per entry (form 2, spin
  = order, crystal codes `[byte >> 4, byte & 15, min(count, 127), 0]`, payload16 = the two context bytes), then HALT
  (form 0). `deriveCodex` uses order 2 and by default chunk 720 and the 120 most frequent (context, byte) pairs, by
  count descending, then by the three bytes read as one integer, ascending.
- `codexHash = "CX-" + first 24 hex digits of H(stream)`, where stream is the concatenated upper-case packet hex.
- The signed string is a commitment, `CODEX/1|codexHash|order|entryCount`, signed through its contentHash like
  GROWN/1 (section 13): SEAL/1 in Owl, ATTEST/1 in BioChain-AI. `PAIR/1|chainId|codexHash` pairs a codex with a
  chain.
- `parseCodexStream` checks packet alignment, parity, GEAR first, HALT last and form 2 in between. The codex is not
  read by `growBiochain`: the `shdccp/2` coder is fixed and unprimed.

**2. The Python codex and mesh payload** (BioChain-AI `protocol/codex_engine.py` 46-47 and 149-190,
`protocol/biochain_mesh.py` 132 and 148-149, at `dfbe3f2`; byte-identical copies in Owl-Academy's
`BioChain-AI/BioChain_Enterprise/`).

- `build_codex` writes the same GEAR/PRIME/HALT layout, but a PRIME's spin is the length of its context.
- `codex_hash` is the full SHA-256, 64 lower-case hex digits without a prefix, over the packets' 8-byte big-endian
  words as raw bytes, not over their hex text.
- `parse_codex` also requires order 1 … 3 and chunk 64 … 4,096, and drops PRIME entries whose context is shorter
  than the order.
- The mesh signs a payload, not a commitment: `CODEX/1|codexHash|packets|authorSealId|tick`, with the packet count,
  the author's mesh sealId (section 13.3's note) and a tick token.

The second field tells them apart: `CX-` and 24 hex digits in the JS commitment, 64 hex digits in the mesh payload.
No vector relates the two hashes, and none is planned before the Phase 6 rename.

## Appendix F. `lineage[].epoch` (informative, D20)

A published biochain carries `lineage`, a list of events: one when it is grown or extended, one per accepted transfer.
Owl and BioChain-AI write the same events under different field names, and the field `epoch` means different things:

| Field | Owl (`scripts/biomesh.js` 448-452, 622-625 at `7f45f35`) | BioChain-AI (`src/biomesh/biomesh.js` 438-442, 626-629 at `dfbe3f2`) |
| :--- | :--- | :--- |
| who | `genesisId` (grown, extended); `fromGenesisId`, `toGenesisId` (transfer) | `identityId`; `fromIdentityId`, `toIdentityId` |
| time token | `tick`: the SCHU tick token (section 13.7) | `epoch`: the `EPOCH.<n>` token (section 13.7) |
| chain epoch (extended only) | `epoch`: the record's epoch number, the parent's epoch (1 when it has none) plus 1 | `chainEpoch`: the same number |

So `lineage[i].epoch` is a number in Owl and a string in BioChain-AI. A reader that takes both tells them apart by
type: a number is Owl's chain epoch, a string is BioChain-AI's epoch token. The record-level field `epoch` (the chain
epoch number that `extendBiochain` sets) is the same in both; the record's own token is `tickToken` in Owl and
`epochToken` in BioChain-AI. No field of this appendix enters the `shdccp/2` record of section 11.1 or any commitment
of section 13. Phase 6 adds a converter, a JSON Schema per kind with golden round trips (D20).
