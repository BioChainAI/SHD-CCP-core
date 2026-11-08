<!-- SPDX-License-Identifier: CC0-1.0 -->
# RFC 07 contract vectors (`shdccp/2`)

Golden vectors for [RFC 07, the shdccp/2 biochain contract](../rfcs/07_shdccp2_contract.md). Everything in this
folder is CC0-1.0 ([`LICENSE`](LICENSE)), except a small fragment of `schema.json` copied from SHD-CCP, which stays
MIT (its `binary` property and `spec_version` pattern; see [`../NOTICE`](../NOTICE)). The rest of SHD-CCP-core stays
GPL-3.0. Repositories under other licences may carry copies of these files and should pin each copy by its SHA-256.

**Do not edit `suites/` by hand.** Every file there is written by [`tools/generate.mjs`](tools/generate.mjs), and CI
fails if a file is stale, missing or unknown.

## The two rules (D8)

1. **A vector is normative only when two independent implementations agree.** The generator computes each suite with
   the code its `source` names, read-only from git objects at a pinned commit: Owl-Academy's `scripts/biomesh.js`
   (the reference implementation, MIT) at `7f45f356f5c46ea0eb099905b2505a06e8c28fd7` for the codec suites;
   BioChain-AI's `src/identity/crypto-core.js` and `epoch-service.js` (MIT) at
   `dfbe3f2e94c2ff8101f39054bedf29ec67f75704` and Owl's `seal-crypto.js` and `schumann-oracle.js` for
   `attest1_profile`; Owl's strict verifier (`verifyIntegrityStrict` in `scripts/biomesh-core.js`, O3) at
   `f1d31afd48f8424348972b4d68abf8e23830a539` for the tamper suites (the pin follows O3's published commit; the file's
   hash may change with it, but its verdicts must reproduce every locked case); and its own [`tools/cv_spec.mjs`](tools/cv_spec.mjs),
   written from the specifications it cites, for what neither computes (RFC 6962, BIOSEED/1, RFC 6979 signatures and DER, the coder's code lengths, the
   snapshot text). An implementation independent of that code must reproduce every expected value of a suite before
   the suite is locked: the Hyperbolic Lexicon's `chain.py`, `manifest.py` and `attest.py` (with Python's
   `cryptography`), its hardened verifier `verify.py` (steps 1-6 of `verifyPackage`, for the tamper suites) and the
   Engram reference's `ttmpt.py` (Ebayednoob, GPL-3.0), and for BIOSEED/1 BioChain-AI's
   `protocol/codex_engine.py` (MIT), all imported at test time only and never copied here. [`lock.json`](lock.json)
   records which implementations agreed, at which commits and file hashes. Only `check.py --promote` adds lock entries, and only
   for cases the oracle reproduced in that run. A suite the oracle does not fully reproduce stays **draft**: it is
   checked against the RFC reading like the others, the oracle's disagreements with it are listed as `OPEN`, not as
   failures, and it is never locked while they last. CI runs the oracle on every pull request and push, and fails when an
   entry added to the lock relative to the base commit was not reproduced by the oracle in that run, so a hand-edited
   entry cannot pass. A value the oracle cannot compute is not an expected value, and neither is a value only an
   adapter in `check.py` or the RFC reading computes: the GROWN/1 commitment and its hash in `shdccp2_record` are
   informative until an implementation independent of Owl's computes them (BioChain-AI's `grownCommitment` is the same
   code as Owl's and does not count); so are RFC 07 section 4.4's stream bound in `shdccp2_limits` (arithmetic on the
   section's formula), the sealId of a SEAL/1 case in `attest1_profile` (only Owl's `seal-crypto.js` builds SEAL/1, so
   the SEAL/1 payloads are inputs there and the signatures are expected over exactly that text) and the strict
   verdict's `legacy` flag in the tamper suites (`verify.py` has no notion of legacy).
2. **A normative case never changes.** `lock.json` pins every locked case by the SHA-256 of the canonical JSON of its
   `id`, `input` and `expect` (sorted keys, no spaces, UTF-8, as `check.py`'s `case_hash` writes it with Python's
   `json.dumps`), so neither the input nor the expected value of a locked case can change. CI refuses a change or
   removal of any lock entry relative to the base commit, and fails if the base commit cannot be resolved. A change
   to the contract needs a new wire version and a new suite, never an edit.

`informative` values and `note` texts are outside the lock: they explain, they do not bind.

## Layout

| Path | What |
| :--- | :--- |
| `schema.json` | JSON Schema (draft 2020-12) of a suite file: SHD-CCP's envelope (suite, spec_version, rfc, status, description, generator, cases) with `binary` optional, plus `wire`, `source` and `license`, and a case schema per suite |
| `suites/*.json` | the vectors, one file per suite |
| `lock.json` | implementations and the normative lock |
| `tools/owl_namegrab.mjs` | loads Owl's `biomesh.js` and `seal-crypto.js` read-only from an Owl-Academy clone's git objects at the pinned commit, checks their SHA-256, and exposes their functions; loads `biomesh-core.js` (the strict verifier) the same way at O3's commit |
| `tools/pinned_sources.mjs` | loads import-free modules the same way: BioChain-AI's `crypto-core.js` and `epoch-service.js`, Owl's `schumann-oracle.js` |
| `tools/cv_spec.mjs` | the generator's own code, written from the specifications it cites: RFC 6962 trees, proofs and verification, BIOSEED/1, ECDSA P-256 with RFC 6979 nonces and DER, the rank coder's code lengths, the snapshot text |
| `tools/generate.mjs` | the single generator (`--write`) and drift check (`--check`) |
| `tools/check.py` | schema, both rules, agreement with the RFC reading and (optionally) with the oracle; `--promote` locks fully agreed suites and agreed new cases of normative suites |
| `tools/rfc07_reading.py` | an executable reading of RFC 07 written from its text; a self-check of the RFC, not counted towards rule 1 |
| `tools/oracle-requirements.txt` | the oracle's third-party dependencies, numpy 2.5.3 and cryptography 50.0.1 (with cffi and pycparser), pinned by version and wheel hash |

## Suites

Fourteen are **normative**. The first seven: Owl's JS and the Lexicon oracle agreed on all 207 cases (2026-11-07,
numpy 2.5.3). The next six: the generator's sources and the independent oracle agreed on all 276 cases (2026-11-08,
numpy 2.5.3, cryptography 50.0.1 with OpenSSL 4.0.2). `shdccp2_tamper`: Owl's strict verifier and the Lexicon's
`verify.py` agreed on all 79 cases (2026-11-08). Two suites are **draft**, and `check.py` lists the oracle's
disagreements with them as `OPEN`: `shdccp2_tamper_open`, ten values on which the Lexicon's verifier names another
first failing check than RFC 07 (section 12.5), and `attest1_profile_open`, three seeds on which ECMAScript's `trim`
(RFC 07 section 13.1) and the oracle's Python `str.strip` differ.

| Suite | Cases | RFC 07 | Pins |
| :--- | ---: | :--- | :--- |
| `shdccp2_packet` | 53 | §5 | `crystallize(chunk)`: packet, crystal32, signed crystal codes and fields. 40 chunks with exactly one 0x80 crystal byte (10 in each of the slots w, x, y, z) and 6 with two, found by seeded search; the golden bytes 0..59 → `9841D88D8B003CEA`; 1- and 720-byte edges. `informative.kernel_normalized_packet` is the packet the kernel normalisation would give (not shdccp/2). |
| `shdccp2_chunk` | 17 | §4, §6, §7.1 | chunk at index i → rank-coder residual, frame and leaf. Bytes ≥ 0x80 (Latin-1 leaf rule), characters split by the 720-byte cut, a context with 94 candidates, indices 0..83, and one chunk at two indices (leaves are index-bound). |
| `shdccp2_merkle` | 13 | §7.2 | root of K leaves for K = 1..9, 16, 17, 33, 84 (duplicate-last). |
| `shdccp2_arith` | 59 | §2.4, §8 | the exact binary64 arithmetic: V8's `Math.hypot` (including 12 inputs where the plain square root of the sum of squares gives another double), `qn`, `qmul`, `qconj`, `toFixed(12)` ties, negative zero and tiny negatives, `toFixed(4)` ties read back as numbers. |
| `shdccp2_weave` | 6 | §8 | per-chunk crystalQuat and every chiral and mirror step as binary64 bit patterns, then the weave strings; chunks with 0x80 in the w, x, y and z bytes. |
| `engram1` | 35 | §9 | tokens, grids, J numerators, engram stream, count and mean J; the 26 letter grids; mulberry32 draws for seeds 65 and 90. |
| `shdccp2_record` | 24 | §3-§12 | whole grown records: 1, 719, 720, 721, 1,440, 1,441 and 60,000 bytes, multi-byte characters split at byte 720, a text that starts with U+FEFF (§12.1), 0x80 crystal bytes, engrams on and off, no tokens, mean-J ties, and the errors `empty-input` and `input-too-large`. `informative.grown_commitment` and `grown_content_hash` are the GROWN/1 commitment and its hash (§13), outside the lock. |
| `shdccp2_limits` | 11 | §4.4, §6.6 | the size limits (P8): the rank coder's largest codes (a 25-bit escape after 255 candidates and a 17-bit hit at rank 256, on inputs longer than a chunk; at most 23 bits within a 720-byte chunk), bits used before padding, and the streams of records of 1, 720, 721, 59,760 and 60,000 bytes of a high-cost text (189,622 hex digits for 60,000 bytes). `informative.stream_bound` is section 4.4's bound for the record's n bytes (377,016 hex digits for 60,000 bytes; `cap_hex` 380,016 for 84 frames): arithmetic on the section's formula, which no independent implementation computes. |
| `merkle_rules_same_bytes` | 11 | §7.2-§7.5 | shdccp/2, BIOSEED/1 and RFC 6962 over the same chunks (F16): leaves and roots under each rule, which always differ; ASCII, Latin-1, split characters and two identical chunks; K = 1 to 9. |
| `rfc6962_lists` | 167 | §7.5 | RFC 6962 roots for K = 0..64, audit paths (every leaf of K ≤ 8, some of 17 and 64), consistency proofs, and RFC 9162 verification of proofs and of altered inputs (index, size, path, root, leaf, an interior node offered as a leaf). |
| `attest1_profile` | 18 | §13.1-§13.7 | identities, P-256 JWKs (coordinates below 2^248 included), keyId, ATTEST/1 key vectors and payloads over `EPOCH.<n>` and `EPOCH-OFFLINE-<date>`, SEAL/1 seal vectors over Owl's `SCHU` ticks and signatures over the SEAL/1 payloads given as inputs (the sealId is informative), RFC 6979 signatures (RFC 6979 A.2.5 reproduced) as r ‖ s and DER, high-S twins flagged, BioChain-AI's low-S form, verification, and the registry snapshot text. |
| `engram1_keys` | 34 | §9.6 | the engram key of a string outside a record (F114): letters after full Unicode upper-casing ("ß" → "SS", ligatures, dotless i) and the canonical upper-case key; GEODESIC → `5C896A4801C9C24C`. |
| `rng_mulberry32` | 35 | §9.2 | mulberry32 (P6): 64 draws for each engram/1 letter seed 65..90 and 16 draws for edge seeds (int32 wrap-around, the increment). |
| `shdccp2_tamper` | 79 | §12.3-§12.5 | the strict verdict (ok and the first failing check) for five honest records and 74 altered ones: T1, T2, T8, T9, legacy records, values that are not records, the strict stream form, the 720-byte cut (a 719-byte middle frame), 60,001 bytes, non-canonical residuals, packet fields, leaves and root, the weaves, segCuts, segments, chainId and the derived fields. `informative` gives Owl's `legacy` flag, its detail, the self-consistency verdict and the label. |
| `shdccp2_tamper_open` (draft) | 10 | §12.5 | hex digits in the wrong case and ill-formed UTF-8: RFC 07 reports them at parity and canonical, the Lexicon's verifier at crystal or canonical and at derived. |
| `attest1_profile_open` (draft) | 3 | §13.1 | identities whose seed starts with U+FEFF (removed by ECMAScript's `trim`, kept by Python's `str.strip`), U+0085 or U+001C (kept by `trim`, removed by `str.strip`); the expected values are BioChain-AI's `computeIdentityId`. |

## Encodings

- Packets are upper-case hex; residuals, lengths, hashes and chainIds lower-case, exactly as in a record.
- Doubles (`f64`) are the 16 hex digits of the IEEE-754 binary64 bit pattern, big-endian, so negative zero and every
  last bit are exact. Record numbers (`value`, `engramMeanJ`) are JSON numbers, compared as binary64 values.
- A tamper input is `record`: any JSON value, given to the verifier as it is.
- A record input is `text`, or `text_parts`: the concatenation of strings and `{repeat, length}` parts, where a part
  is the first `length` characters of the ASCII string `repeat` repeated.
- A `stream` or `engramStream` longer than 8,192 characters is given as `<field>_sha256` (SHA-256 of the ASCII text,
  lower-case hex) and `<field>_length`.
- Byte strings that are not text (chunks, coder inputs, RFC 6962 entries) are lower-case hex. Tree hashes of all three
  rules are lower-case hex of the 32 bytes.
- In `attest1_profile`, private scalars `d` are 64 lower-case hex digits, public keys are JWKs (base64url coordinates),
  signatures are r ‖ s as 128 lower-case hex digits and DER as lower-case hex, and identities and key vectors are 16
  upper-case hex digits (identities with `0x`). A SEAL/1 case gives the signed text as `input.payload` and
  `input.other_payload`.

## Running

From the repository root, with Node 20 or later, an Owl-Academy clone that holds the pinned commits (the generator's,
and O3's for the strict verifier; `--owl-strict DIR` names another clone for the latter) and a BioChain-AI clone that
holds its pinned commit (only their git object stores are read; their working trees are never touched):

```sh
python3 -B tools/run_checks.py --owl ../Owl-Academy --biochain ../BioChain-AI        # drift, schema, rules, RFC reading
node contract_vectors/tools/generate.mjs --owl ../Owl-Academy --biochain ../BioChain-AI --write   # regenerate
python3 -B contract_vectors/tools/check.py --lexicon-root ../Ebayednoob --biochain-root ../BioChain-AI   # the oracle
python3 -B tools/run_checks.py --owl ../Owl-Academy --biochain ../BioChain-AI --lexicon-root ../Ebayednoob --base origin/main   # what CI runs
```

With `--base`, the ref must resolve to a commit in the clone, and every lock entry added since it must be reproduced
by the oracle in the same run, so `--base` needs `--lexicon-root` (and, for `merkle_rules_same_bytes`, a BioChain-AI
checkout whose `protocol/codex_engine.py` matches the lock) once the lock has gained entries. The oracle needs numpy
and cryptography, and `verify.py` reads the Lexicon's `reference/golden` (the V0 vocabulary);
`tools/oracle-requirements.txt` pins the versions CI installs (hash-pinned wheels for Linux x86-64,
CPython 3.12 and 3.13).

To add a suite: extend `generate.mjs`, the schema, `SUITE_GENERATOR` and `SUITE_ORACLE` and both adapters in
`check.py`, and `rfc07_reading.py` with the RFC text it reads; generate; run the oracle with
`--promote` (it locks only suites on which the oracle agrees with every case and never alters an existing entry);
generate again so the file says `normative`; commit the lock and the suite together. To add a case to a normative
suite (rule 2 allows additions): extend `generate.mjs`, generate, and run the oracle with `--promote`, which locks the
new case only if the oracle reproduces it.

CI ([`../.github/workflows/contract-vectors.yml`](../.github/workflows/contract-vectors.yml)) runs
`tools/run_checks.py --owl --owl-strict --biochain --lexicon-root` on every pull request and push to main, with the
immutability check and the added-entry check against the base commit. The generator's Owl commit (`7f45f35`) is pinned
in the workflow and in `tools/owl_namegrab.mjs` (`OWL_PIN`); the other commits are read from `lock.json`: the strict
verifier's (`owl-biomesh-core-strict-js`, checked out as `--owl-strict`), BioChain-AI's and the oracle's (Ebayednoob).
