#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Part of contract_vectors/ (CC0-1.0, see ../LICENSE).
"""Checks the RFC 07 contract vectors without running their generator (standard library only).

    python3 -B contract_vectors/tools/check.py                         schema, D8 rules, RFC-reading agreement
    python3 -B contract_vectors/tools/check.py --base origin/main --lexicon-root DIR --biochain-root DIR
                                                                       ... and no locked case changed since that ref,
                                                                       and the oracle reproduces every entry added since
    python3 -B contract_vectors/tools/check.py --lexicon-root DIR --biochain-root DIR
                                                                       ... and agreement with the independent oracle
    python3 -B contract_vectors/tools/check.py --lexicon-root DIR --biochain-root DIR --promote
                                                                       lock every draft suite the oracle fully agrees
                                                                       with, and every new case of a normative suite the
                                                                       oracle agrees with; existing entries never change

What it checks:
  1. schema: every suites/*.json validates against schema.json (a dependency-free validator for the subset the schema
     uses; if the `jsonschema` package is installed it is used as well).
  2. D8 rule 1 (two implementations): a suite is "normative" only if lock.json records that the implementations the
     generator runs for it (SUITE_GENERATOR: Owl's biomesh.js, Owl's strict verifier in biomesh-core.js, BioChain-AI's
     crypto-core.js, Owl's seal-crypto.js or the generator's own cv_spec.mjs) and an implementation independent of them
     agreed on every case; a normative suite
     has no case outside the lock and the lock has no case outside the suite. With --base REF, every lock entry added
     since REF (all of them when REF has no lock.json) must be reproduced by the oracle in the same run, so
     --lexicon-root (and, for merkle_rules_same_bytes, --biochain-root) is required whenever the lock gained entries.
  3. D8 rule 2 (immutability): every locked case still hashes to its locked SHA-256, taken over the canonical JSON of
     its id, input and expect (case_hash), so neither the input nor the expected value of a locked case can change;
     with --base REF, every lock entry present at REF is present unchanged now (entries may be added, never changed or
     removed). REF must resolve to a commit in this clone, or the check fails.
  4. RFC reading: tools/rfc07_reading.py (written from the RFC text) reproduces every expected value and the
     informative values it computes. A disagreement means the RFC text or the vectors are wrong; it does not count
     towards rule 1.
  5. With --lexicon-root: the independent oracle (SUITE_ORACLE). The Hyperbolic Lexicon's chain.py, manifest.py (RFC 6962)
     and attest.py (ATTEST/1 with the `cryptography` package), its hardened verifier verify.py (verifyPackage steps 1-6
     for the tamper suites, with the V0 vocabulary it reads) and the Engram reference's ttmpt.py (Ebayednoob,
     GPL-3.0) are imported from DIR at test time only, as their own tests import them; nothing of them is copied here
     (D13). A disagreement with a normative suite fails the check; a disagreement with a draft suite is listed as OPEN
     and does not (a draft suite is not yet agreed, and --promote never locks it while it disagrees). DIR is an Ebayednoob checkout (or an archive of it) holding "Pages/Hyperbolic Lexicon/reference",
     "Pages/Engram Minds Eye/reference" and "Pages/Hyperbolic Oracles/reference" (and, for verify.py, the Lexicon's
     reference/golden). With --biochain-root: BioChain-AI's
     protocol/codex_engine.py (MIT), the owner's BIOSEED/1 code, imported the same way from a BioChain-AI checkout.
     Every imported file's SHA-256 must match lock.json. The oracle needs numpy (the Lexicon's hpstep package imports
     it) and cryptography (attest.py); CI installs the versions in oracle-requirements.txt. The oracle has no GROWN/1
     function, so the GROWN/1 commitment and its hash are informative values of shdccp2_record, outside the lock.
"""
import argparse
import copy
import hashlib
import importlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
CV = os.path.dirname(HERE)
REPO = os.path.dirname(CV)
sys.path.insert(0, HERE)
import rfc07_reading as R  # noqa: E402

INLINE_LIMIT = 8192
GENERATOR_IMPL = 'owl-biomesh-js'
STRICT_IMPL = 'owl-biomesh-core-strict-js'
ORIGINAL_SUITES = ('shdccp2_packet', 'shdccp2_chunk', 'shdccp2_merkle', 'shdccp2_arith', 'shdccp2_weave', 'engram1',
                   'shdccp2_record')
# The implementations whose code computes each suite's expected values in generate.mjs (the first implementation of
# D8 rule 1), and the independent implementations the oracle runs for it (the second).
SUITE_GENERATOR = dict({name: [GENERATOR_IMPL] for name in ORIGINAL_SUITES}, **{
    'shdccp2_limits': [GENERATOR_IMPL, 'cv-generate-mjs'],
    'merkle_rules_same_bytes': [GENERATOR_IMPL, 'cv-generate-mjs'],
    'rfc6962_lists': ['cv-generate-mjs'],
    'attest1_profile': ['biochain-crypto-core-js', 'owl-seal-crypto-js', 'cv-generate-mjs'],
    'attest1_profile_open': ['biochain-crypto-core-js'],
    'engram1_keys': [GENERATOR_IMPL],
    'rng_mulberry32': [GENERATOR_IMPL],
    'shdccp2_tamper': [STRICT_IMPL],
    'shdccp2_tamper_open': [STRICT_IMPL],
})
SUITE_ORACLE = {name: ['lexicon-chain-py'] for name in SUITE_GENERATOR}
SUITE_ORACLE['merkle_rules_same_bytes'] = ['lexicon-chain-py', 'biochain-codex-engine-py']
SUITE_ORACLE['shdccp2_tamper'] = SUITE_ORACLE['shdccp2_tamper_open'] = ['lexicon-verify-py']
# The verify.py checks the tamper suites run (verifyPackage steps 1-6); the other four need a package, not a record.
VERIFY_SKIP = ('commitment', 'attestation', 'inclusion', 'consistency')


# ── a small JSON Schema validator (the subset schema.json uses) ─────────────

def _type_ok(v, t):
    if isinstance(t, list):
        return any(_type_ok(v, x) for x in t)
    return {'object': lambda: isinstance(v, dict), 'array': lambda: isinstance(v, list),
            'string': lambda: isinstance(v, str), 'boolean': lambda: isinstance(v, bool),
            'null': lambda: v is None,
            'integer': lambda: isinstance(v, int) and not isinstance(v, bool),
            'number': lambda: isinstance(v, (int, float)) and not isinstance(v, bool)}[t]()


def validate(v, s, root, path='$'):
    """Returns a list of error strings (empty when v is valid)."""
    if '$ref' in s:
        ref = s['$ref']
        assert ref.startswith('#/$defs/'), ref
        return validate(v, root['$defs'][ref[8:]], root, path)
    errs = []
    if 'type' in s and not _type_ok(v, s['type']):
        return [f'{path}: not of type {s["type"]}']
    if 'const' in s and v != s['const']:
        errs.append(f'{path}: is not {s["const"]!r}')
    if 'enum' in s and v not in s['enum']:
        errs.append(f'{path}: not one of {s["enum"]}')
    if isinstance(v, str):
        if 'pattern' in s and not re.search(s['pattern'], v):
            errs.append(f'{path}: does not match {s["pattern"]}')
        if len(v) < s.get('minLength', 0) or len(v) > s.get('maxLength', math.inf):
            errs.append(f'{path}: length out of range')
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if v < s.get('minimum', -math.inf) or v > s.get('maximum', math.inf):
            errs.append(f'{path}: out of range')
    if isinstance(v, list):
        if len(v) < s.get('minItems', 0) or len(v) > s.get('maxItems', math.inf):
            errs.append(f'{path}: item count out of range')
        if 'items' in s:
            for i, x in enumerate(v):
                errs += validate(x, s['items'], root, f'{path}[{i}]')
    if isinstance(v, dict):
        for k in s.get('required', []):
            if k not in v:
                errs.append(f'{path}: missing {k}')
        props = s.get('properties', {})
        for k, x in v.items():
            if k in props:
                errs += validate(x, props[k], root, f'{path}.{k}')
            elif s.get('additionalProperties') is False:
                errs.append(f'{path}: unexpected key {k}')
            elif isinstance(s.get('additionalProperties'), dict):
                errs += validate(x, s['additionalProperties'], root, f'{path}.{k}')
    for sub in s.get('allOf', []):
        errs += validate(v, sub, root, path)
    if 'oneOf' in s:
        n = sum(1 for sub in s['oneOf'] if not validate(v, sub, root, path))
        if n != 1:
            errs.append(f'{path}: matches {n} of the oneOf alternatives, not exactly 1')
    if 'if' in s and not validate(v, s['if'], root, path):
        errs += validate(v, s.get('then', {}), root, path)
    return errs


# ── helpers ─────────────────────────────────────────────────────────────────

def f64(h):
    return struct.unpack('>d', bytes.fromhex(h))[0]


def f64hex(x):
    return struct.pack('>d', x).hex()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


LOCKED_KEYS = ('id', 'input', 'expect')


def case_hash(case):
    """What lock.json pins for a case: SHA-256 of the canonical JSON of its id, input and expect (rule 2)."""
    return hashlib.sha256(canon({k: case[k] for k in LOCKED_KEYS}).encode('utf-8')).hexdigest()


def text_of(inp):
    if 'text' in inp:
        return inp['text']
    out = []
    for p in inp['text_parts']:
        out.append(p if isinstance(p, str) else (p['repeat'] * (p['length'] // len(p['repeat']) + 1))[:p['length']])
    return ''.join(out)


def long_or_inline(key, s):
    if len(s) > INLINE_LIMIT:
        return {key + '_sha256': hashlib.sha256(s.encode('ascii')).hexdigest(), key + '_length': len(s)}
    return {key: s}


def record_expect(rec):
    out = {}
    for k, v in rec.items():
        if k in ('stream', 'engramStream'):
            out.update(long_or_inline(k, v))
        elif k in R.GROWN_FIELDS or k in R.ENGRAM_FIELDS:
            out[k] = v
    return out


def grown_informative(rec):
    """The GROWN/1 commitment and its content hash (RFC section 13), from the RFC reading only. Informative: no
    implementation independent of the generator computes them yet, so the oracle adapter does not return them."""
    g = R.grown_commitment(rec)
    return {'grown_commitment': g, 'grown_content_hash': R.H(g)}


def packet_fields(p, form, spin, payload16, freq, amp):
    return {'form': form, 'parity': (int(p, 16) >> 59) & 1, 'spin': spin, 'payload16': payload16, 'freq': freq,
            'amp': amp}


# ── implementation adapters: each returns (expect, informative-or-None) for a case ──

class Reading:
    name = 'rfc07-reading'

    def packet(self, c):
        d = bytes.fromhex(c['input']['chunk_hex'])
        p = R.packet(d)
        u = R.unpack(p)
        e = {'packet': p, 'crystal32': p[2:10], 'crystal_codes': R.signed_codes(int(p[2:10], 16)),
             'fields': packet_fields(p, u['form'], u['spin'], u['payload16'], u['freq'], u['amp'])}
        k = R.kernel_normalized_packet(d)
        return e, {'kernel_normalized_packet': k, 'kernel_normalized_differs': k != p}

    def chunk(self, c):
        d, i = bytes.fromhex(c['input']['chunk_hex']), c['input']['index']
        p, r = R.packet(d), R.encode_chunk(d)
        if R.decode_chunk(r, len(d)) != d:
            raise AssertionError('decode(encode(chunk)) != chunk')
        return {'packet': p, 'residual': r, 'residual_bytes': len(r) // 2, 'frame': R.frame(p, r),
                'leaf': R.leaf(i, d)}, None

    def merkle(self, c):
        return {'root': R.merkle_root(c['input']['leaves'])}, None

    def arith(self, c):
        return arith_with(c, R.hypot_v8, R.qn, R.qmul, R.qconj, R.to_fixed)

    def weave(self, c):
        chunks = [bytes.fromhex(h) for h in c['input']['chunks_hex']]
        quats, chiral, mirror = R.weave_steps(chunks)
        return {'crystal32': ['%08X' % R.crystal32(x) for x in chunks], 'crystal_quat': [list(map(f64hex, q)) for q in quats],
                'chiral_steps': [list(map(f64hex, q)) for q in chiral], 'mirror_steps': [list(map(f64hex, q)) for q in mirror],
                'weaveChiral': R.quat_text(chiral[-1]), 'weaveMirror': R.quat_text(mirror[-1])}, None

    def engram(self, c):
        inp = c['input']
        if 'mulberry32_seed' in inp:
            return {'u32': R.mulberry32_u32(inp['mulberry32_seed'], inp['draws'])}, None
        e = R.engram_layer(inp['text'])
        return {'tokens': e['tokens'], 'grids_hex': [R.grid_hex(g) for g in e['grids']],
                'j_num': [R.j_num(g) for g in e['grids']], 'engramStream': e['stream'], 'engramCount': e['count'],
                'engramMeanJ': e['meanJ']}, None

    def record(self, c):
        try:
            rec = R.grow(text_of(c['input']), c['input']['engrams'])
        except R.GrowError as e:
            return {'error': e.code}, None
        bad = R.validate(rec)
        if bad:
            raise AssertionError('the RFC validity predicate rejects a grown record at ' + bad)
        return record_expect(rec), grown_informative(rec)

    def limits(self, c):
        inp = c['input']
        if 'coder_input_hex' in inp:
            d = bytes.fromhex(inp['coder_input_hex'])
            r = R.encode_chunk(d)
            if R.decode_chunk(r, len(d)) != d:
                raise AssertionError('decode(encode(input)) != input')
            codes = R.code_bits(d)
            bits = [b for b, _, _ in codes]
            mx = max(bits)
            at = bits.index(mx)
            return ({'residual': r, 'residual_bytes': len(r) // 2, 'used_bits': sum(bits), 'max_code_bits': mx,
                     'max_code_index': at},
                    {'max_code_candidates': codes[at][1], 'max_code_escape': codes[at][2],
                     'in_chunk_domain': len(d) <= R.CHUNK})
        text = text_of(inp)
        rec = R.grow(text, engrams=False)
        # the bound of section 4.4 for the record's n bytes: informative, checked here against the RFC text only
        return (limits_grow_expect(rec['stream'], [len(res) // 2 for _, res in R.parse_stream_strict(rec['stream'])]),
                {'stream_bound': R.stream_bound(len(R.utf8_of_text(text)))})

    def merkle_rules(self, c):
        data = R.utf8_of_text(text_of(c['input']))
        chunks = [data[i:i + R.CHUNK] for i in range(0, len(data), R.CHUNK)]
        sl = [R.leaf(i, ch) for i, ch in enumerate(chunks)]
        bl = [R.bioseed_leaf(i, ch) for i, ch in enumerate(chunks)]
        return {'chunks': len(chunks), 'shdccp2': {'leafHashes': sl, 'merkleRoot': R.merkle_root(sl)},
                'bioseed1': {'leafHashes': bl, 'merkleRoot': R.bioseed_root(bl)},
                'rfc6962': {'leafHashes': [R.rfc_leaf(ch).hex() for ch in chunks], 'root': R.mth(chunks).hex()}}, None

    def rfc6962(self, c):
        return rfc6962_with(c, R.rfc_leaf, R.mth, R.audit_path, R.consistency_proof, R.verify_inclusion,
                            R.verify_consistency)

    def attest(self, c):
        inp = c['input']
        op = inp['op']
        if op == 'identity':
            try:
                return {'identityId': R.identity_id(inp['seed'], inp['uid'])}, None
            except ValueError as e:
                return {'error': str(e)}, None
        if op == 'snapshot':
            try:
                t = R.snapshot_text(inp['entries'])
            except ValueError as e:
                return {'error': str(e)}, None
            return {'snapshot_text': t, 'snapshot_sha256': R.H(t), 'key_ids': [e['keyId'] for e in json.loads(t)]}, None
        d = int(inp['d'], 16)
        jwk = R.public_jwk(d)
        if op == 'sign_message':
            f = R.signature_fields(d, jwk, inp['message'])
            del f['sig_low_s']
            return dict(publicJwk=jwk, **f), None
        ident = R.identity_id(inp['seed'], inp['uid'])
        ch, other = R.H(inp['commitment']), R.H(inp['other_commitment'])
        if op == 'attest':
            kid, tok = R.fingerprint('K-', jwk), inp['epochToken']
            kv = R.key_vector(ident, tok)
            payload = R.attest_payload(kid, kv, ch, tok)
            f = R.signature_fields(d, jwk, payload, R.attest_payload(kid, kv, other, tok))
            return dict(identityId=ident, publicJwk=jwk, keyId=kid, keyVector=kv, contentHash=ch, payload=payload, **f), None
        sid, tok = R.fingerprint('S-', jwk), inp['tickToken']
        sv = R.key_vector(ident, tok)
        # SEAL/1: the payloads are inputs (only Owl's code builds them); they must be this text's (section 13.4)
        if inp['payload'] != R.seal_payload(sid, sv, ch, tok) or inp['other_payload'] != R.seal_payload(sid, sv, other, tok):
            raise AssertionError('the SEAL/1 payloads given are not the ones section 13.4 builds from the other inputs')
        f = R.signature_fields(d, jwk, inp['payload'], inp['other_payload'])
        del f['sig_low_s']
        return dict(cosmologicalId=ident, publicJwk=jwk, sealVector=sv, contentHash=ch, **f), {'sealId': sid}

    def engram_keys(self, c):
        t = c['input']['key_text']
        return {'letters': R.key_letters(t), 'key_hex': R.engram_key(t)}, None

    def rng(self, c):
        return {'u32': R.mulberry32_u32(c['input']['seed'], c['input']['draws'])}, None

    def tamper(self, c):
        v = R.strict_verdict(c['input']['record'])
        return {'ok': v['ok'], 'failed': v['failed']}, {'legacy': v['legacy']}


def arith_with(c, hypot, qn, qmul, qconj, to_fixed):
    inp = c['input']
    op = inp['op']
    if op == 'hypot':
        return {'result': f64hex(hypot([f64(h) for h in inp['args']]))}, None
    if op == 'qn':
        return {'result': [f64hex(x) for x in qn([f64(h) for h in inp['args']])]}, None
    if op == 'qmul':
        return {'result': [f64hex(x) for x in qmul([f64(h) for h in inp['a']], [f64(h) for h in inp['b']])]}, None
    if op == 'qconj':
        return {'result': [f64hex(x) for x in qconj([f64(h) for h in inp['a']])]}, None
    t = to_fixed(f64(inp['x']), inp['digits'])
    return ({'text': t, 'number': f64hex(float(t))} if inp['digits'] == 4 else {'text': t}), None


def limits_grow_expect(stream, residual_bytes):
    return {'chunks': len(residual_bytes), 'residual_bytes': residual_bytes, 'stream_length': len(stream),
            'stream_sha256': hashlib.sha256(stream.encode('ascii')).hexdigest()}


def rfc6962_with(c, leaf, root, path, proof, verify_inclusion, verify_consistency):
    """An rfc6962_lists case from one implementation's functions: leaf(entry) and root(entries) -> 32 bytes,
    path(m, entries) and proof(m, entries) -> lists of 32 bytes, and the two RFC 9162 verifiers."""
    inp, hb = c['input'], bytes.fromhex
    op = inp.get('op')
    if op is None:
        return {'root': root([hb(e) for e in inp['entries_hex']]).hex()}, None
    if op == 'inclusion':
        ents, m = [hb(e) for e in inp['entries_hex']], inp['index']
        p, lh, rt = path(m, ents), leaf(ents[m]), root(ents)
        return {'leaf_hash': lh.hex(), 'path': [x.hex() for x in p], 'root': rt.hex(),
                'valid': verify_inclusion(m, len(ents), lh, p, rt)}, None
    if op == 'consistency':
        ents, m = [hb(e) for e in inp['entries_hex']], inp['m']
        pr, rm, rn = proof(m, ents), root(ents[:m]), root(ents)
        return {'root_m': rm.hex(), 'root_n': rn.hex(), 'proof': [x.hex() for x in pr],
                'valid': verify_consistency(m, len(ents), rm, rn, pr)}, None
    if op == 'verify_inclusion':
        return {'valid': verify_inclusion(inp['index'], inp['size'], hb(inp['leaf_hash']), [hb(x) for x in inp['path']],
                                          hb(inp['root']))}, None
    return {'valid': verify_consistency(inp['m'], inp['n'], hb(inp['root_m']), hb(inp['root_n']),
                                        [hb(x) for x in inp['proof']])}, None


def check_pinned_files(root, pin, what):
    for rel, want in pin['files'].items():
        got = hashlib.sha256(open(os.path.join(root, rel), 'rb').read()).hexdigest()
        if got != want:
            raise SystemExit(f'{what} file {rel}: sha256 {got}, lock.json pins {want}')


class Lexicon:
    """The independent oracle, imported in place at test time: the Hyperbolic Lexicon's chain.py, manifest.py (RFC 6962)
    and attest.py (ATTEST/1, with the `cryptography` package) and the Engram reference's ttmpt.py; with a BioChain-AI
    checkout, also its protocol/codex_engine.py (BIOSEED/1)."""
    name = 'lexicon-chain-py'
    ROOTS = ('Pages/Hyperbolic Lexicon/reference', 'Pages/Engram Minds Eye/reference', 'Pages/Hyperbolic Oracles/reference')

    def __init__(self, root, pin, biochain_root=None, biochain_pin=None, verify_pin=None):
        check_pinned_files(root, pin, 'oracle')
        self.verify_pin, self.V, self.session = verify_pin, None, None
        for r in self.ROOTS:
            sys.path.insert(0, os.path.join(root, r))
        sys.dont_write_bytecode = True
        self.root = root
        self.C = importlib.import_module('lexicon.chain')
        self.T = importlib.import_module('engram.ttmpt')
        self.M = importlib.import_module('lexicon.manifest')
        self.A = importlib.import_module('lexicon.attest')
        self.B = None
        if biochain_root:
            check_pinned_files(biochain_root, biochain_pin, 'BioChain-AI oracle')
            sys.path.insert(0, os.path.join(biochain_root, 'protocol'))
            self.B = importlib.import_module('codex_engine')

    def packet(self, c):
        C = self.C
        d = bytes.fromhex(c['input']['chunk_hex'])
        p = C.crystallize(d)
        u = C.unpack_packet(p)
        codes = [C._int8((int(p[2:10], 16) >> s) & 255) for s in (24, 16, 8, 0)]
        e = {'packet': p, 'crystal32': p[2:10], 'crystal_codes': codes,
             'fields': packet_fields(p, u['form'], u['spin'], u['payload16'], u['freq'], u['amp'])}
        k = C.kernel_crystallize(d)
        return e, {'kernel_normalized_packet': k, 'kernel_normalized_differs': k != p}

    def chunk(self, c):
        C = self.C
        d, i = bytes.fromhex(c['input']['chunk_hex']), c['input']['index']
        p, r = C.crystallize(d), C.encode_chunk(d)
        return {'packet': p, 'residual': r, 'residual_bytes': len(r) // 2, 'frame': C.frame_stream([p], [r]),
                'leaf': C.leaf_hash(i, d)}, None

    def merkle(self, c):
        return {'root': self.C.merkle_shdccp2(c['input']['leaves'])}, None

    def arith(self, c):
        C = self.C
        return arith_with(c, C.v8_hypot, C.qn, C.qmul, C.qconj, C.js_to_fixed)

    def weave(self, c):
        C = self.C
        chunks = [bytes.fromhex(h) for h in c['input']['chunks_hex']]
        quats = [C.crystal_quat(x) for x in chunks]
        wf, wm, chiral, mirror = [1.0, 0.0, 0.0, 0.0], [1.0, 0.0, 0.0, 0.0], [], []
        for q in quats:
            wf = C.qn(C.qmul(q, wf))
            chiral.append(wf)
        for q in reversed(quats):
            wm = C.qn(C.qmul(C.qconj(q), wm))
            mirror.append(wm)
        fin_c, fin_m = C.weaves(chunks)
        if fin_c != wf or fin_m != wm:
            raise AssertionError('chain.weaves disagrees with its own primitives')
        return {'crystal32': [C.crystallize(x)[2:10] for x in chunks], 'crystal_quat': [list(map(f64hex, q)) for q in quats],
                'chiral_steps': [list(map(f64hex, q)) for q in chiral], 'mirror_steps': [list(map(f64hex, q)) for q in mirror],
                'weaveChiral': C.quat_hex(fin_c), 'weaveMirror': C.quat_hex(fin_m)}, None

    def engram(self, c):
        T, inp = self.T, c['input']
        if 'mulberry32_seed' in inp:
            f = T.mulberry32(inp['mulberry32_seed'])
            return {'u32': [int(f() * 4294967296) for _ in range(inp['draws'])]}, None
        toks = T.tokenize_biomesh(inp['text'])
        grids = [T.crystallize(t) for t in toks]
        s = T.engram_stream(inp['text'])
        return {'tokens': toks, 'grids_hex': [T.hex_lsb(g).upper() for g in grids], 'j_num': [T.j_num(g) for g in grids],
                'engramStream': s['stream'], 'engramCount': s['count'], 'engramMeanJ': s['meanJ']}, None

    def record(self, c):
        try:
            rec = self.C.grow(text_of(c['input']), engrams=c['input']['engrams'])
        except ValueError as e:
            m = str(e)
            return {'error': 'empty-input' if m.startswith('Nothing to grow') else
                    'input-too-large' if m.startswith('Grow input capped') else 'unexpected:' + m}, None
        return record_expect(rec), None

    def limits(self, c):
        C, inp = self.C, c['input']
        if 'coder_input_hex' in inp:
            d = bytes.fromhex(inp['coder_input_hex'])
            r = C.encode_chunk(d)
            if bytes(C.decode_chunk(r, len(d))) != d:
                raise AssertionError('chain.decode_chunk does not give the input back')
            # the bits the decoder reads for the first k codes, k = 0..n (decode_chunk's trace)
            used = [C.decode_chunk(r, k, trace=True)[1] for k in range(len(d) + 1)]
            costs = [used[k + 1] - used[k] for k in range(len(d))]
            mx = max(costs)
            return {'residual': r, 'residual_bytes': len(r) // 2, 'used_bits': used[-1], 'max_code_bits': mx,
                    'max_code_index': costs.index(mx)}, None
        # a grown record (the bound of section 4.4 on these cases is informative: chain.py does not compute it)
        rec = C.grow(text_of(inp), engrams=False)
        return limits_grow_expect(rec['stream'], [len(res) // 2 for _, res, _ in C.frames(rec['stream'])]), None

    def merkle_rules(self, c):
        C, M = self.C, self.M
        if self.B is None:
            raise RuntimeError('BIOSEED/1 needs --biochain-root (BioChain-AI protocol/codex_engine.py)')
        data = C.js_utf8(text_of(c['input']))
        chunks = [data[i:i + C.CHUNK] for i in range(0, len(data), C.CHUNK)]
        sl = [C.leaf_hash(i, ch) for i, ch in enumerate(chunks)]
        bl = [self.B._chunk_hash(i, ch) for i, ch in enumerate(chunks)]
        return {'chunks': len(chunks), 'shdccp2': {'leafHashes': sl, 'merkleRoot': C.merkle_shdccp2(sl)},
                'bioseed1': {'leafHashes': bl, 'merkleRoot': self.B.merkle_root(bl)},
                'rfc6962': {'leafHashes': [M.leaf_hash(ch).hex() for ch in chunks], 'root': M.root(chunks).hex()}}, None

    def rfc6962(self, c):
        M = self.M
        return rfc6962_with(c, M.leaf_hash, M.root, lambda m, e: M.Log(e).path(m), lambda m, e: M.Log(e).consistency(m),
                            M.verify_inclusion, M.verify_consistency)

    def attest(self, c):
        A, inp = self.A, c['input']
        op = inp['op']
        if op == 'identity':
            try:
                return {'identityId': A.identity_id(inp['seed'], inp['uid'])}, None
            except ValueError as e:
                return {'error': 'empty-seed' if 'empty' in str(e) else 'unexpected:' + str(e)}, None
        if op == 'snapshot':
            try:
                t = A.snapshot_text(inp['entries'])
            except ValueError as e:
                m = str(e)
                return {'error': 'duplicate-key' if 'share a keyId' in m else
                        'unknown-status' if 'unknown key status' in m else 'unexpected:' + m}, None
            return {'snapshot_text': t, 'snapshot_sha256': A.sha256hex(t), 'key_ids': [e['keyId'] for e in json.loads(t)]}, None
        priv = A.private_key(int(inp['d'], 16))
        pub = priv.public_key()
        jwk = A.jwk_of(pub)

        def signed(payload, other=None):
            sig = A.sign_p1363(priv, payload, deterministic=True)       # RFC 6979, by cryptography (OpenSSL)
            twin = A.high_s_twin(sig)
            high = int.from_bytes(sig[32:], 'big') > A.P256_N // 2
            ver = {'sig': A.verify_p1363(pub, sig, payload), 'twin': A.verify_p1363(pub, twin, payload)}
            if other is not None:
                ver['other_content'] = A.verify_p1363(pub, sig, other)
            return {'sig': sig.hex(), 'high_s': high, 'twin': twin.hex(), 'der': A.p1363_to_der(sig).hex(),
                    'der_twin': A.p1363_to_der(twin).hex(), 'verifies': ver}, (twin if high else sig).hex()

        if op == 'sign_message':
            f, _ = signed(inp['message'])
            return dict(publicJwk=jwk, **f), None
        ident = A.identity_id(inp['seed'], inp['uid'])
        ch, other = A.sha256hex(inp['commitment']), A.sha256hex(inp['other_commitment'])
        if op == 'attest':
            kid, tok = A.key_id(jwk), inp['epochToken']
            kv = A.key_vector(ident, tok)
            payload = A.attestation_payload(kid, kv, ch, tok)
            f, low = signed(payload, A.attestation_payload(kid, kv, other, tok))
            return dict(identityId=ident, publicJwk=jwk, keyId=kid, keyVector=kv, contentHash=ch, payload=payload,
                        sig_low_s=low, **f), None
        # SEAL/1: attest.py has no SEAL/1 code. The seal vector is its key-vector derivation over the cosmologicalId and
        # the tick token (RFC 07 section 13.2); the signatures are over the payload text the case gives as input. The
        # sealId and the payload construction are not computed here (they are informative or inputs in the suite).
        sv = A.key_vector(ident, inp['tickToken'])
        f, _ = signed(inp['payload'], inp['other_payload'])
        return dict(cosmologicalId=ident, publicJwk=jwk, sealVector=sv, contentHash=ch, **f), None

    def engram_keys(self, c):
        t = c['input']['key_text']
        return {'letters': ''.join(ch for ch in t.upper() if 'A' <= ch <= 'Z'),
                'key_hex': self.T.hex_lsb(self.T.crystallize(t)).upper()}, None

    def rng(self, c):
        f = self.T.mulberry32(c['input']['seed'])
        return {'u32': [int(f() * 4294967296) for _ in range(c['input']['draws'])]}, None

    def tamper(self, c):
        """The Lexicon's hardened verifier (verify.py, the reference of lexicon_core.js verifyPackage) on a package that
        holds only the record, with the four package checks skipped: its steps 1-6, parity .. derived, which are the
        checks of RFC 07 section 12.3 under the same names. Its 'derived' also computes the V0 id stream (the session's
        vocabulary) and the exact weave, which a record cannot fail."""
        if self.V is None:
            check_pinned_files(self.root, self.verify_pin, 'oracle (verify.py)')
            self.V = importlib.import_module('lexicon.verify')
            if tuple(self.V.CHECKS[:6]) != R.STRICT_CHECKS or set(self.V.CHECKS[6:]) != set(VERIFY_SKIP):
                raise SystemExit('verify.py does not run the checks of RFC 07 section 12.3 first, in that order')
            vocab = importlib.import_module('lexicon.wordpiece').load_v0()
            self.session = types.SimpleNamespace(vocab=vocab)          # what steps 1-6 read of a Session
        rec = c['input']['record']
        v = self.V.verify({'record': copy.deepcopy(rec)}, self.session, skip=VERIFY_SKIP)
        failed = None if v['failed'] == '-' else v['failed']
        # legacy (RFC 07 section 12.3) is informative: verify.py has no notion of it. This adapter maps verify.py's
        # parity reasons for a JSON object that is not shdccp/2 ("no shdccp/2 record": streamVersion) or has no string
        # stream (chain.frames' "no stream on the record") to legacy, and a value that is not an object to not legacy;
        # the mapping is compared with the suite's informative value, and it is not counted towards rule 1.
        reason = v['checks'][0][2]
        legacy = failed == 'parity' and isinstance(rec, dict) and reason in (
            'no shdccp/2 record', 'ValueError: no stream on the record')
        return {'ok': failed is None, 'failed': failed}, {'legacy': legacy}


DISPATCH = {'shdccp2_packet': 'packet', 'shdccp2_chunk': 'chunk', 'shdccp2_merkle': 'merkle', 'shdccp2_arith': 'arith',
            'shdccp2_weave': 'weave', 'engram1': 'engram', 'shdccp2_record': 'record', 'shdccp2_limits': 'limits',
            'merkle_rules_same_bytes': 'merkle_rules', 'rfc6962_lists': 'rfc6962', 'attest1_profile': 'attest',
            'engram1_keys': 'engram_keys', 'rng_mulberry32': 'rng', 'shdccp2_tamper': 'tamper',
            'shdccp2_tamper_open': 'tamper', 'attest1_profile_open': 'attest'}


def run_impl(impl, suite):
    """Returns {case id: [failure, ...]}, with an empty list for a case that agrees. Informative values are compared
    where both sides have them."""
    out = {}
    meth = getattr(impl, DISPATCH[suite['suite']])
    for c in suite['cases']:
        fails = out.setdefault(c['id'], [])
        try:
            got, info = meth(c)
        except Exception as e:  # noqa: BLE001 (any crash is a disagreement)
            fails.append(f'{suite["suite"]}/{c["id"]}: {type(e).__name__}: {e}')
            continue
        if got != c['expect']:
            keys = sorted(k for k in set(got) | set(c['expect']) if got.get(k) != c['expect'].get(k))
            shown = '; '.join(f'{k}: {json.dumps(got.get(k))[:40]}, expected {json.dumps(c["expect"].get(k))[:40]}'
                              for k in keys[:4])
            fails.append(f'{suite["suite"]}/{c["id"]}: differs in {keys} ({shown})')
        if info:
            for k, v in info.items():
                if c.get('informative', {}).get(k, v) != v:
                    fails.append(f'{suite["suite"]}/{c["id"]}: informative {k} differs')
    return out


def base_lock(ref):
    """(commit, lock.json at that commit or None when the commit has none). Raises LookupError when ref does not
    resolve to a commit in this clone, so the immutability rule is never skipped silently."""
    git = ['git', '-C', REPO]
    r = subprocess.run(git + ['rev-parse', '--verify', '--quiet', ref + '^{commit}'], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        raise LookupError(ref)
    commit = r.stdout.strip()
    if subprocess.run(git + ['cat-file', '-e', f'{commit}:contract_vectors/lock.json'], capture_output=True).returncode:
        return commit, None
    shown = subprocess.run(git + ['show', f'{commit}:contract_vectors/lock.json'], capture_output=True, text=True,
                           check=True)
    return commit, json.loads(shown.stdout)


# ── main ────────────────────────────────────────────────────────────────────

def load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--base', help='git commit whose lock.json entries must still be present unchanged; entries added '
                                   'since must be reproduced by the oracle in this run (needs --lexicon-root)')
    ap.add_argument('--lexicon-root', help='Ebayednoob checkout or archive holding the Lexicon oracle (test time only)')
    ap.add_argument('--biochain-root', help='BioChain-AI checkout holding protocol/codex_engine.py, the BIOSEED/1 oracle '
                                            '(test time only; needed for merkle_rules_same_bytes)')
    ap.add_argument('--promote', action='store_true', help='with --lexicon-root: lock every fully agreed draft suite '
                                                           'and every agreed new case of a normative suite')
    a = ap.parse_args()

    schema = load_json(os.path.join(CV, 'schema.json'))
    lock_path = os.path.join(CV, 'lock.json')
    lock = load_json(lock_path)
    impls = lock['implementations']
    suites, errors = {}, []
    known = set(schema['properties']['suite']['enum'])
    for f in sorted(os.listdir(os.path.join(CV, 'suites'))):
        if f[:-5] not in known or not f.endswith('.json'):
            errors.append(f'unknown file contract_vectors/suites/{f}')
            continue
        try:
            suites[f] = load_json(os.path.join(CV, 'suites', f))
        except (ValueError, OSError) as e:
            errors.append(f'unreadable contract_vectors/suites/{f}: {e}')
    for name in sorted(known - {f[:-5] for f in suites}):
        errors.append(f'missing contract_vectors/suites/{name}.json')

    # 1. schema
    try:
        import jsonschema  # optional cross-check
    except ImportError:
        jsonschema = None
    for f, s in suites.items():
        errors += [f'schema {f}: {e}' for e in validate(s, schema, schema)[:5]]
        if s.get('suite') + '.json' != f:
            errors.append(f'schema {f}: file name does not match suite {s.get("suite")}')
        if jsonschema is not None:
            for e in list(jsonschema.Draft202012Validator(schema).iter_errors(s))[:3]:
                errors.append(f'jsonschema {f}: {e.message[:200]}')
    print(f'schema: {len(suites)} suites checked' + (' (also with jsonschema)' if jsonschema else ''))

    # 2 and 3. the two rules of D8
    by_suite = {s['suite']: s for s in suites.values()}
    unlocked = []  # (suite, case id): a case of a normative suite without a lock entry; --promote may lock it
    for name, entry in lock['normative'].items():
        s = by_suite.get(name)
        if s is None:
            errors.append(f'lock: {name} is locked but its suite file is missing')
            continue
        agreed = entry.get('agreed_by', [])
        indep = [i for i in agreed if impls.get(i, {}).get('independent_of_generator')]
        if not all(g in agreed for g in SUITE_GENERATOR.get(name, [GENERATOR_IMPL])) or not indep \
                or any(i not in impls for i in agreed):
            errors.append(f'rule 1: {name} is locked without its generator source and an independent implementation')
        if s['status'] != 'normative':
            errors.append(f'rule 1: {name} is locked but its file says {s["status"]} (regenerate)')
        ids = {c['id']: c for c in s['cases']}
        for cid, h in entry['cases'].items():
            if cid not in ids:
                errors.append(f'rule 2: {name}/{cid} is locked but no longer in the suite')
            elif case_hash(ids[cid]) != h:
                errors.append(f'rule 2: {name}/{cid} changed its locked id, input or expected value')
        unlocked += [(name, cid) for cid in ids if cid not in entry['cases']]
    for s in suites.values():
        if s['status'] == 'normative' and s['suite'] not in lock['normative']:
            errors.append(f'rule 1: {s["suite"]} says normative without a lock entry')
    old_entries = None  # with --base: the set of (suite, case id) locked at the base commit
    if a.base:
        try:
            commit, old = base_lock(a.base)
        except LookupError:
            commit, old = None, None
            errors.append(f'base: {a.base} does not resolve to a commit in this clone; the immutability rule cannot '
                          'run (fetch the base, or pass a ref that exists)')
        if commit and old is None:
            old_entries = set()
            print(f'rule 2: no contract_vectors/lock.json at {a.base} ({commit[:12]}); every lock entry counts as added')
        elif commit:
            old_entries = set()
            for name, entry in old.get('normative', {}).items():
                now = lock['normative'].get(name)
                if now is None:
                    errors.append(f'rule 2: {name} was locked at {a.base} and is no longer locked')
                for cid, h in entry['cases'].items():
                    old_entries.add((name, cid))
                    if now is not None and now['cases'].get(cid) != h:
                        errors.append(f'rule 2: {name}/{cid} changed or vanished since {a.base}')
    n_locked = sum(len(e['cases']) for e in lock['normative'].values())
    print(f'rules: {len(lock["normative"])} normative suites, {n_locked} locked cases'
          + (f', compared with {a.base}' if a.base else ''))

    # 4. the RFC reading
    total = n_bad = 0
    for s in suites.values():
        res = run_impl(Reading(), s)
        total += len(res)
        n_bad += sum(1 for v in res.values() if v)
        errors += ['rfc07-reading ' + x for v in res.values() for x in v]
    print(f'rfc07-reading: {total} cases, {n_bad} disagreements')

    # 5. the Lexicon oracle
    agreed_suites, oracle_agreed = [], set()  # suites and (suite, case id) the oracle reproduced in this run
    open_items = []  # the oracle's disagreements with draft suites: listed, not failures
    if a.lexicon_root:
        lex = Lexicon(a.lexicon_root, impls['lexicon-chain-py'], a.biochain_root, impls['biochain-codex-engine-py'],
                      impls['lexicon-verify-py'])
        for s in suites.values():
            res = run_impl(lex, s)
            ok = [cid for cid, v in res.items() if not v]
            who = ' + '.join(SUITE_ORACLE[s['suite']])
            print(f'{who} {s["suite"]}: {len(ok)}/{len(res)} cases agree' + (' (draft)' if s['status'] == 'draft' else ''))
            found = [who + ' ' + x for v in res.values() for x in v]
            if s['status'] == 'draft':
                open_items += found
            else:
                errors += found
            oracle_agreed.update((s['suite'], cid) for cid in ok)
            if len(ok) == len(res):
                agreed_suites.append(s['suite'])
    if a.promote:
        if not a.lexicon_root:
            raise SystemExit('--promote needs --lexicon-root')
        if errors:
            for e in errors:
                print('FAIL ' + e)
            raise SystemExit('not promoting: fix the errors first')
        added = []
        for name in agreed_suites:
            if name in lock['normative']:
                continue
            lock['normative'][name] = {'agreed_by': SUITE_GENERATOR[name] + SUITE_ORACLE[name],
                                       'cases': {c['id']: case_hash(c) for c in by_suite[name]['cases']}}
            added.append(name)
        ids_of = {name: {c['id']: c for c in s['cases']} for name, s in by_suite.items()}
        for name, cid in unlocked:
            # a new case of a suite that is already normative: locked only because the oracle reproduced it in this
            # run; existing entries are never touched
            if (name, cid) in oracle_agreed and cid not in lock['normative'][name]['cases']:
                lock['normative'][name]['cases'][cid] = case_hash(ids_of[name][cid])
                added.append(f'{name}/{cid}')
        unlocked = [(n, c) for n, c in unlocked if c not in lock['normative'][n]['cases']]
        with open(lock_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(lock, indent=2, ensure_ascii=False) + '\n')
        print('promoted: ' + (', '.join(added) or 'nothing new') + '; now run generate.mjs --write so the files say normative')
    errors += [f'rule 1: {n}/{c} is in a normative suite but not locked (lock it with --promote)' for n, c in unlocked]

    # rule 1 against the base: every entry the lock gained since the base was reproduced by the oracle in this run
    if old_entries is not None:
        new = [(n, c) for n, e in lock['normative'].items() for c in e['cases'] if (n, c) not in old_entries]
        if new and not a.lexicon_root:
            errors.append(f'rule 1: {len(new)} lock entries were added since {a.base}; run with --lexicon-root so the '
                          'oracle reproduces them')
        elif new:
            errors += [f'rule 1: {n}/{c} was added to the lock since {a.base} but the oracle did not reproduce it in '
                       'this run' for n, c in new if (n, c) not in oracle_agreed]
        print(f'rule 1: {len(new)} lock entries added since {a.base}'
              + (f', {sum(1 for x in new if x in oracle_agreed)} reproduced by the oracle in this run' if a.lexicon_root else ''))

    for e in open_items:
        print('OPEN ' + e)
    for e in errors:
        print('FAIL ' + e)
    print('check: ' + ('FAILED' if errors else 'ok')
          + (f' ({len(open_items)} open disagreements in draft suites)' if open_items else ''))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
