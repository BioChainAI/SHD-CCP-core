#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Minimal check runner for SHD-CCP-core (what CI runs).

    python3 -B tools/run_checks.py [--owl DIR] [--owl-strict DIR] [--biochain DIR] [--base REF] [--lexicon-root DIR]
                                   [--biochain-root DIR]

Steps, each must pass:
  1. drift: node contract_vectors/tools/generate.mjs --check  (regenerates every suite from the pinned sources, read
     only: Owl-Academy's scripts/biomesh.js, seal-crypto.js and schumann-oracle.js, Owl's strict verifier in
     scripts/biomesh-core.js at its pinned commit, BioChain-AI's crypto-core.js and epoch-service.js, and the
     generator's own cv_spec.mjs; fails on a stale, missing or unknown file)
  2. rules: python3 -B contract_vectors/tools/check.py        (schema, the two rules of D8, the RFC 07 reading;
     with --lexicon-root (and --biochain-root), agreement with the independent oracle; with --base, no locked case
     changed since REF, REF must resolve to a commit, and every lock entry added since REF must be reproduced by the
     oracle in the same run, so --base needs the oracle whenever the lock gained entries)

--owl DIR is an Owl-Academy clone holding commit 7f45f356f5c46ea0eb099905b2505a06e8c28fd7, the generator's pin
(default: $OWL_ACADEMY_DIR, then ../Owl-Academy); --owl-strict DIR a clone holding the strict verifier's commit,
cf1227a6912394ca6424d931ef0330c6be97a915 (default: $OWL_ACADEMY_STRICT_DIR, then --owl); --biochain DIR a BioChain-AI
clone holding dfbe3f2e94c2ff8101f39054bedf29ec67f75704 (default: $BIOCHAIN_AI_DIR, then ../BioChain-AI). Only their git
object stores are read. --biochain-root DIR is a BioChain-AI checkout at that commit whose protocol/codex_engine.py the
oracle imports (it defaults to --biochain when the oracle runs). The existing codecs are not built or tested here.
CI runs all of them: python -B tools/run_checks.py --owl DIR --owl-strict DIR --biochain DIR --lexicon-root DIR
--base REF. The workflow (.github/workflows/contract-vectors.yml) checks out the generator's Owl commit, which it pins
itself as owl_namegrab.mjs's OWL_PIN does, and reads the other commits from contract_vectors/lock.json: the strict
verifier's (owl-biomesh-core-strict-js), BioChain-AI's (biochain-codex-engine-py) and the oracle's (lexicon-chain-py).
"""
import argparse
import os
import shutil
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def step(name, cmd):
    print(f'== {name}: {" ".join(cmd)}', flush=True)
    rc = subprocess.run(cmd, cwd=REPO).returncode
    print(f'== {name}: {"ok" if rc == 0 else f"FAILED ({rc})"}', flush=True)
    return rc == 0


def main():
    ap = argparse.ArgumentParser(description='SHD-CCP-core checks: contract-vector drift and rules')
    ap.add_argument('--owl', help='Owl-Academy clone (default: $OWL_ACADEMY_DIR, then ../Owl-Academy)')
    ap.add_argument('--owl-strict', help="Owl-Academy clone holding the strict verifier's commit "
                                         "(default: $OWL_ACADEMY_STRICT_DIR, then --owl)")
    ap.add_argument('--biochain', help='BioChain-AI clone (default: $BIOCHAIN_AI_DIR, then ../BioChain-AI)')
    ap.add_argument('--base', help='git commit whose locked contract vectors must be unchanged (needs --lexicon-root '
                                   'when the lock gained entries since)')
    ap.add_argument('--lexicon-root', help='Ebayednoob checkout for the test-time oracle (optional)')
    ap.add_argument('--biochain-root', help='BioChain-AI checkout for the BIOSEED/1 oracle (default: --biochain)')
    a = ap.parse_args()
    if not shutil.which('node'):
        print('node (20 or later) is required for the drift check')
        return 2
    gen = ['node', 'contract_vectors/tools/generate.mjs', '--check'] + (['--owl', a.owl] if a.owl else []) \
        + (['--owl-strict', a.owl_strict] if a.owl_strict else []) + (['--biochain', a.biochain] if a.biochain else [])
    chk = [sys.executable, '-B', 'contract_vectors/tools/check.py']
    if a.base:
        chk += ['--base', a.base]
    if a.lexicon_root:
        chk += ['--lexicon-root', a.lexicon_root]
        bc = a.biochain_root or a.biochain or os.environ.get('BIOCHAIN_AI_DIR') or os.path.join(REPO, '..', 'BioChain-AI')
        chk += ['--biochain-root', os.path.abspath(bc)]
    ok = step('drift', gen)
    ok = step('rules', chk) and ok
    print('run_checks: ' + ('ok' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
