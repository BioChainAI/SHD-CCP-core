// SPDX-License-Identifier: CC0-1.0
// Part of contract_vectors/ (CC0-1.0, see ../LICENSE). Written for SHD-CCP-core; contains no code from the
// repositories it reads.
//
// Loads import-free ES modules of other repositories READ-ONLY, as owl_namegrab.mjs loads Owl's biomesh.js: each file
// is read from the clone's git object store at the pinned commit (`git show <commit>:<path>`), its SHA-256 must equal
// the pinned value, it must have no import statement, and it is evaluated in memory unchanged. Nothing is written.
//
//   BIOCHAIN_PIN   BioChain-AI src/identity/crypto-core.js and src/identity/epoch-service.js (MIT, (c) Schism-Labs-AI):
//                  the owner's ATTEST/1 code (D5): identity, key vector, keyId, payload, low-S form, WebCrypto
//                  verification, and the EPOCH.<n> token
//   OWL_TICK_PIN   Owl-Academy scripts/schumann-oracle.js (MIT, (c) Ebayednoob) at the generator's Owl commit: the
//                  SCHU tick token that SEAL/1 payloads carry

import { readPinned, asModule, OWL_PIN } from './owl_namegrab.mjs';

export const BIOCHAIN_PIN = Object.freeze({
  repository: 'BioChainAI/BioChain-AI',
  commit: 'dfbe3f2e94c2ff8101f39054bedf29ec67f75704',
  license: 'MIT',
  files: Object.freeze({
    'src/identity/crypto-core.js': '68d0494678abf815f0f626b651f8b071437f1bafd0bf97d1448442576d344375',
    'src/identity/epoch-service.js': 'eadfb554c1e134aee5a5a8c73bd26a92aa5e4414ea09c439a131acd1b5e0920b',
  }),
});

export const OWL_TICK_PIN = Object.freeze({
  repository: OWL_PIN.repository,
  commit: OWL_PIN.commit,
  license: 'MIT',
  files: Object.freeze({
    'scripts/seal-crypto.js': OWL_PIN.files['scripts/seal-crypto.js'],
    'scripts/schumann-oracle.js': '2be1abf77ae23916828fd2bb14a3eb4bdcc172769c69602329512d55ad9a2dca',
  }),
});

/** {path: module} for every file of `pin`, read from `dir`'s git objects at pin.commit. */
export async function loadPlainModules(dir, pin) {
  const out = {};
  for (const [path, sha] of Object.entries(pin.files)) {
    const text = readPinned(dir, path, sha, pin.commit);
    if (/^\s*import\s/m.test(text)) throw new Error(`${path} has an import statement; the loader must be reviewed`);
    out[path] = await asModule(text);
  }
  return out;
}
