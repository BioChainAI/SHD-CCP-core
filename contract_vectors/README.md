<!-- SPDX-License-Identifier: CC0-1.0 -->
# RFC 07 contract vectors (`shdccp/2`)

Golden vectors for [RFC 07, the shdccp/2 biochain contract](../rfcs/07_shdccp2_contract.md). Everything in this
folder is CC0-1.0 ([`LICENSE`](LICENSE)), except a small fragment of `schema.json` copied from SHD-CCP, which stays
MIT (its `binary` property and `spec_version` pattern; see [`../NOTICE`](../NOTICE)). The rest of SHD-CCP-core stays
GPL-3.0. Repositories under other licences may carry copies of these files and should pin each copy by its SHA-256.

**Do not edit `suites/` by hand.** Every file there is written by [`tools/generate.mjs`](tools/generate.mjs), and CI
fails if a file is stale, missing or unknown.

## The two rules (D8)

1. **A vector is normative only when two independent implementations agree.** The generator runs Owl-Academy's
   `scripts/biomesh.js` (the reference implementation, MIT) at commit `7f45f356f5c46ea0eb099905b2505a06e8c28fd7`;
   an implementation independent of it must reproduce every expected value of a suite before the suite is locked.
   Today that implementation is the Hyperbolic Lexicon's `chain.py` with the Engram reference's `ttmpt.py`
   (Ebayednoob, GPL-3.0), imported at test time only and never copied here. [`lock.json`](lock.json) records which
   implementations agreed, at which commits and file hashes. Only `check.py --promote` adds lock entries, and only
   for cases the oracle reproduced in that run. CI runs the oracle on every pull request and push, and fails when an
   entry added to the lock relative to the base commit was not reproduced by the oracle in that run, so a hand-edited
   entry cannot pass. A value the oracle cannot compute is not an expected value: the GROWN/1 commitment and its hash
   in `shdccp2_record` are informative until an implementation independent of Owl's computes them (BioChain-AI's
   `grownCommitment` is the same code as Owl's and does not count).
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
| `tools/owl_namegrab.mjs` | loads Owl's `biomesh.js` and `seal-crypto.js` read-only from an Owl-Academy clone's git objects at the pinned commit, checks their SHA-256, and exposes their functions |
| `tools/generate.mjs` | the single generator (`--write`) and drift check (`--check`) |
| `tools/check.py` | schema, both rules, agreement with the RFC reading and (optionally) with the oracle; `--promote` locks fully agreed suites and agreed new cases of normative suites |
| `tools/rfc07_reading.py` | an executable reading of RFC 07 written from its text; a self-check of the RFC, not counted towards rule 1 |
| `tools/oracle-requirements.txt` | the oracle's one third-party dependency, numpy 2.5.3, pinned by version and wheel hash (the version of the agreement run) |

## Suites

All seven are **normative**: Owl's JS and the Lexicon oracle agreed on all 207 cases (2026-11-07, numpy 2.5.3).

| Suite | Cases | RFC 07 | Pins |
| :--- | ---: | :--- | :--- |
| `shdccp2_packet` | 53 | §5 | `crystallize(chunk)`: packet, crystal32, signed crystal codes and fields. 40 chunks with exactly one 0x80 crystal byte (10 in each of the slots w, x, y, z) and 6 with two, found by seeded search; the golden bytes 0..59 → `9841D88D8B003CEA`; 1- and 720-byte edges. `informative.kernel_normalized_packet` is the packet the kernel normalisation would give (not shdccp/2). |
| `shdccp2_chunk` | 17 | §4, §6, §7.1 | chunk at index i → rank-coder residual, frame and leaf. Bytes ≥ 0x80 (Latin-1 leaf rule), characters split by the 720-byte cut, a context with 94 candidates, indices 0..83, and one chunk at two indices (leaves are index-bound). |
| `shdccp2_merkle` | 13 | §7.2 | root of K leaves for K = 1..9, 16, 17, 33, 84 (duplicate-last). |
| `shdccp2_arith` | 59 | §2.4, §8 | the exact binary64 arithmetic: V8's `Math.hypot` (including 12 inputs where the plain square root of the sum of squares gives another double), `qn`, `qmul`, `qconj`, `toFixed(12)` ties, negative zero and tiny negatives, `toFixed(4)` ties read back as numbers. |
| `shdccp2_weave` | 6 | §8 | per-chunk crystalQuat and every chiral and mirror step as binary64 bit patterns, then the weave strings; chunks with 0x80 in the w, x, y and z bytes. |
| `engram1` | 35 | §9 | tokens, grids, J numerators, engram stream, count and mean J; the 26 letter grids; mulberry32 draws for seeds 65 and 90. |
| `shdccp2_record` | 24 | §3-§12 | whole grown records: 1, 719, 720, 721, 1,440, 1,441 and 60,000 bytes, multi-byte characters split at byte 720, a text that starts with U+FEFF (§12.1), 0x80 crystal bytes, engrams on and off, no tokens, mean-J ties, and the errors `empty-input` and `input-too-large`. `informative.grown_commitment` and `grown_content_hash` are the GROWN/1 commitment and its hash (§13), outside the lock. |

## Encodings

- Packets are upper-case hex; residuals, lengths, hashes and chainIds lower-case, exactly as in a record.
- Doubles (`f64`) are the 16 hex digits of the IEEE-754 binary64 bit pattern, big-endian, so negative zero and every
  last bit are exact. Record numbers (`value`, `engramMeanJ`) are JSON numbers, compared as binary64 values.
- A record input is `text`, or `text_parts`: the concatenation of strings and `{repeat, length}` parts, where a part
  is the first `length` characters of the ASCII string `repeat` repeated.
- A `stream` or `engramStream` longer than 8,192 characters is given as `<field>_sha256` (SHA-256 of the ASCII text,
  lower-case hex) and `<field>_length`.

## Running

From the repository root, with Node 20 or later and an Owl-Academy clone that holds the pinned commit (only its git
object store is read; its working tree is never touched):

```sh
python3 -B tools/run_checks.py --owl ../Owl-Academy                  # drift check, schema, rules, RFC reading
node contract_vectors/tools/generate.mjs --owl ../Owl-Academy --write # regenerate after a generator change
python3 -B contract_vectors/tools/check.py --lexicon-root ../Ebayednoob   # agreement with the oracle (needs numpy)
python3 -B tools/run_checks.py --owl ../Owl-Academy --lexicon-root ../Ebayednoob --base origin/main   # what CI runs
```

With `--base`, the ref must resolve to a commit in the clone, and every lock entry added since it must be reproduced
by the oracle in the same run, so `--base` needs `--lexicon-root` once the lock has gained entries. The oracle needs
numpy; `tools/oracle-requirements.txt` pins the version CI installs (hash-pinned wheels for Linux x86-64, CPython 3.12
and 3.13).

To add a suite: extend `generate.mjs`, the schema and both adapters in `check.py`; generate; run the oracle with
`--promote` (it locks only suites on which the oracle agrees with every case and never alters an existing entry);
generate again so the file says `normative`; commit the lock and the suite together. To add a case to a normative
suite (rule 2 allows additions): extend `generate.mjs`, generate, and run the oracle with `--promote`, which locks the
new case only if the oracle reproduces it.

CI ([`../.github/workflows/contract-vectors.yml`](../.github/workflows/contract-vectors.yml)) runs
`tools/run_checks.py --lexicon-root` on every pull request and push to main, with the immutability check and the
added-entry check against the base commit; the oracle's commit is read from `lock.json`.
