#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Minimal check runner for SHD-CCP-core (what CI runs).

    python3 -B tools/run_checks.py [--owl DIR] [--base REF] [--lexicon-root DIR]

Steps, each must pass:
  1. drift: node contract_vectors/tools/generate.mjs --check  (regenerates every suite from Owl-Academy's
     scripts/biomesh.js at the pinned commit, read-only, and fails on a stale, missing or unknown file)
  2. rules: python3 -B contract_vectors/tools/check.py        (schema, the two rules of D8, the RFC 07 reading;
     with --lexicon-root, agreement with the Lexicon oracle; with --base, no locked case changed since REF, REF must
     resolve to a commit, and every lock entry added since REF must be reproduced by the oracle in the same run, so
     --base needs --lexicon-root whenever the lock gained entries)

--owl DIR is an Owl-Academy clone holding commit 7f45f356f5c46ea0eb099905b2505a06e8c28fd7 (default: $OWL_ACADEMY_DIR,
then ../Owl-Academy). Only its git object store is read. The existing codecs are not built or tested here.
CI runs all three: python -B tools/run_checks.py --owl DIR --lexicon-root DIR --base REF.
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
    ap.add_argument('--base', help='git commit whose locked contract vectors must be unchanged (needs --lexicon-root '
                                   'when the lock gained entries since)')
    ap.add_argument('--lexicon-root', help='Ebayednoob checkout for the test-time oracle (optional)')
    a = ap.parse_args()
    if not shutil.which('node'):
        print('node (20 or later) is required for the drift check')
        return 2
    gen = ['node', 'contract_vectors/tools/generate.mjs', '--check'] + (['--owl', a.owl] if a.owl else [])
    chk = [sys.executable, '-B', 'contract_vectors/tools/check.py']
    if a.base:
        chk += ['--base', a.base]
    if a.lexicon_root:
        chk += ['--lexicon-root', a.lexicon_root]
    ok = step('drift', gen)
    ok = step('rules', chk) and ok
    print('run_checks: ' + ('ok' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
