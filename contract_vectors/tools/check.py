#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# Part of contract_vectors/ (CC0-1.0, see ../LICENSE).
"""Checks the RFC 07 contract vectors without running their generator (standard library only).

    python3 -B contract_vectors/tools/check.py                         schema, D8 rules, RFC-reading agreement
    python3 -B contract_vectors/tools/check.py --base origin/main --lexicon-root DIR
                                                                       ... and no locked case changed since that ref,
                                                                       and the oracle reproduces every entry added since
    python3 -B contract_vectors/tools/check.py --lexicon-root DIR      ... and agreement with the Lexicon oracle
    python3 -B contract_vectors/tools/check.py --lexicon-root DIR --promote
                                                                       lock every draft suite the oracle fully agrees
                                                                       with, and every new case of a normative suite the
                                                                       oracle agrees with; existing entries never change

What it checks:
  1. schema: every suites/*.json validates against schema.json (a dependency-free validator for the subset the schema
     uses; if the `jsonschema` package is installed it is used as well).
  2. D8 rule 1 (two implementations): a suite is "normative" only if lock.json records that the generator's source
     (Owl's biomesh.js) and an implementation independent of it agreed on every case; a normative suite has no case
     outside the lock and the lock has no case outside the suite. With --base REF, every lock entry added since REF
     (all of them when REF has no lock.json) must be reproduced by the oracle in the same run, so --lexicon-root is
     required whenever the lock gained entries.
  3. D8 rule 2 (immutability): every locked case still hashes to its locked SHA-256, taken over the canonical JSON of
     its id, input and expect (case_hash), so neither the input nor the expected value of a locked case can change;
     with --base REF, every lock entry present at REF is present unchanged now (entries may be added, never changed or
     removed). REF must resolve to a commit in this clone, or the check fails.
  4. RFC reading: tools/rfc07_reading.py (written from the RFC text) reproduces every expected value and the
     informative GROWN/1 commitment. A disagreement means the RFC text or the vectors are wrong; it does not count
     towards rule 1.
  5. With --lexicon-root: the Hyperbolic Lexicon's chain.py and the Engram reference's ttmpt.py (Ebayednoob, GPL-3.0)
     are imported from DIR at test time only, as their own tests import them; nothing of them is copied here (D13).
     DIR is an Ebayednoob checkout (or an archive of it) holding "Pages/Hyperbolic Lexicon/reference",
     "Pages/Engram Minds Eye/reference" and "Pages/Hyperbolic Oracles/reference". Their SHA-256 must match lock.json.
     The oracle needs numpy (its hpstep package imports it; CI installs the version in oracle-requirements.txt);
     nothing else here needs a third-party package. The oracle has no GROWN/1 function, so the GROWN/1 commitment and
     its hash are informative values of shdccp2_record, outside the lock.
"""
import argparse
import hashlib
import importlib
import json
import math
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CV = os.path.dirname(HERE)
REPO = os.path.dirname(CV)
sys.path.insert(0, HERE)
import rfc07_reading as R  # noqa: E402

INLINE_LIMIT = 8192
GENERATOR_IMPL = 'owl-biomesh-js'


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


class Lexicon:
    """The Hyperbolic Lexicon's chain.py and the Engram reference's ttmpt.py, imported in place at test time."""
    name = 'lexicon-chain-py'
    ROOTS = ('Pages/Hyperbolic Lexicon/reference', 'Pages/Engram Minds Eye/reference', 'Pages/Hyperbolic Oracles/reference')

    def __init__(self, root, pin):
        for rel, want in pin['files'].items():
            got = hashlib.sha256(open(os.path.join(root, rel), 'rb').read()).hexdigest()
            if got != want:
                raise SystemExit(f'oracle file {rel}: sha256 {got}, lock.json pins {want}')
        for r in self.ROOTS:
            sys.path.insert(0, os.path.join(root, r))
        sys.dont_write_bytecode = True
        self.C = importlib.import_module('lexicon.chain')
        self.T = importlib.import_module('engram.ttmpt')

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


DISPATCH = {'shdccp2_packet': 'packet', 'shdccp2_chunk': 'chunk', 'shdccp2_merkle': 'merkle', 'shdccp2_arith': 'arith',
            'shdccp2_weave': 'weave', 'engram1': 'engram', 'shdccp2_record': 'record'}


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
            fails.append(f'{suite["suite"]}/{c["id"]}: differs in {keys}')
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
        if GENERATOR_IMPL not in agreed or not indep:
            errors.append(f'rule 1: {name} is locked without the generator and an independent implementation')
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
    if a.lexicon_root:
        lex = Lexicon(a.lexicon_root, impls['lexicon-chain-py'])
        for s in suites.values():
            res = run_impl(lex, s)
            ok = [cid for cid, v in res.items() if not v]
            print(f'lexicon-chain-py {s["suite"]}: {len(ok)}/{len(res)} cases agree')
            errors += ['lexicon-chain-py ' + x for v in res.values() for x in v]
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
            lock['normative'][name] = {'agreed_by': [GENERATOR_IMPL, 'lexicon-chain-py'],
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

    for e in errors:
        print('FAIL ' + e)
    print('check: ' + ('FAILED' if errors else 'ok'))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
