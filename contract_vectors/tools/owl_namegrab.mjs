// SPDX-License-Identifier: CC0-1.0
// Part of contract_vectors/ (CC0-1.0, see ../LICENSE). Written for SHD-CCP-core; contains no code from Owl-Academy.
//
// Loads Owl-Academy's scripts/biomesh.js and scripts/seal-crypto.js (MIT, (c) Ebayednoob) READ-ONLY, by name-grab
// (loadOwl), and scripts/biomesh-core.js at the strict verifier's commit with its one import bound (loadOwlCore):
//   - each file is read from the Owl-Academy git object store at the pinned commit (`git show <commit>:<path>`),
//     so the checkout's working tree is never read, written or switched;
//   - its SHA-256 must equal the pinned value, or loading stops;
//   - the text is evaluated in memory as an ES module. seal-crypto.js has no imports and runs unchanged.
//     biomesh.js's import statements are replaced by bindings: `SC` is the loaded seal-crypto module, and every
//     Firestore, registrar, oracle and seal helper becomes a stub that throws (the pure grow cell never calls them).
//     A trailing `export { ... }` exposes the pure internal functions (crystallize, crystalQuat, ...) by name.
// Nothing is written to disk. The returned object holds Owl's own functions; this file computes nothing itself.
// readPinned and asModule are also used by pinned_sources.mjs, which loads import-free modules the same way.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';

export const OWL_PIN = Object.freeze({
  repository: 'BioChainAI/Owl-Academy',
  commit: '7f45f356f5c46ea0eb099905b2505a06e8c28fd7',
  license: 'MIT',
  files: Object.freeze({
    'scripts/biomesh.js': '7ffd768ce8458345b912ed96e4f70db580b31f0b533faba1b880be4887743eb1',
    'scripts/seal-crypto.js': 'ba0a41ae28542d3c38745d817fc9580d34ee9b13ccc36b67e6c2fd4fd300c0e1',
  }),
});

// Internal (non-exported) names of biomesh.js that the generator reads. Exported names are reachable already.
const INTERNAL = [
  'fold64', 'qmul', 'qconj', 'qn', 'crystalQuat', 'quatHex', 'crystallize', 'unpackPacket', 'packWord',
  'mulberry32', 'engramCharGrid', 'engramGridHex', 'frameStream', 'encodeChunk', 'chainFrames',
  'CHUNK', 'SEGMENTS',
];

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export function readPinned(owlDir, path, expected, commit) {
  let buf;
  try {
    buf = execFileSync('git', ['-C', owlDir, 'show', `${commit}:${path}`], { maxBuffer: 1 << 26 });
  } catch (e) {
    throw new Error(`cannot read ${path} at ${commit} from ${owlDir} (is it a clone holding that `
      + `commit?): ${String(e.stderr || e.message).trim()}`);
  }
  const got = sha256(buf);
  if (got !== expected) throw new Error(`${path} at ${commit}: sha256 ${got}, pinned ${expected}`);
  return buf.toString('utf8');
}

export const asModule = (text) => import('data:text/javascript;base64,' + Buffer.from(text, 'utf8').toString('base64'));

function rewriteImports(text) {
  const re = /^import\s+([\s\S]*?)\s+from\s+"([^"]+)";[ \t]*$/gm;
  let seen = 0;
  const out = text.replace(re, (_m, clause, spec) => {
    seen++;
    clause = clause.trim();
    const ns = /^\*\s+as\s+([A-Za-z_$][\w$]*)$/.exec(clause);
    if (ns) {
      if (spec !== './seal-crypto.js') throw new Error(`unexpected namespace import from ${spec}`);
      return `const ${ns[1]} = globalThis.__shdccpOwlNamegrab.SC;`;
    }
    const named = /^\{([\s\S]*)\}$/.exec(clause);
    if (!named) throw new Error(`unexpected import clause ${clause} from ${spec}`);
    const names = named[1].split(',').map((s) => s.trim()).filter(Boolean);
    return names.map((n) => {
      if (!/^[A-Za-z_$][\w$]*$/.test(n)) throw new Error(`unexpected import name ${n}`);
      return `const ${n} = globalThis.__shdccpOwlNamegrab.stub(${JSON.stringify(spec + '#' + n)});`;
    }).join(' ');
  });
  if (seen !== 5) throw new Error(`expected 5 import statements in biomesh.js, found ${seen}`);
  return out;
}

// Owl-Academy's scripts/biomesh-core.js at the strict verifier's commit: verifyIntegrityStrict (RFC 07 section 12.3, in
// the order of section 17's option (a)), whose verdicts are the expected values of shdccp2_tamper and
// shdccp2_tamper_open. The file's codec functions are biomesh.js's at OWL_PIN, moved unchanged; it imports only
// sha256Hex from ./seal-crypto.js (the same file as at OWL_PIN). The pin follows the verifier's published commit (O3's
// f1d31af, then cf1227a for option (a)); the file's hash may change with it, but its verdicts must reproduce every
// locked case.
export const OWL_STRICT_PIN = Object.freeze({
  repository: 'BioChainAI/Owl-Academy',
  commit: 'cf1227a6912394ca6424d931ef0330c6be97a915',
  license: 'MIT',
  files: Object.freeze({
    'scripts/biomesh-core.js': '4475fe7a361df616315b1e7b6369501e39c341d477c322c247aa8da946272263',
    'scripts/seal-crypto.js': 'ba0a41ae28542d3c38745d817fc9580d34ee9b13ccc36b67e6c2fd4fd300c0e1',
  }),
});

/** biomesh-core.js at pin.commit, evaluated in memory with its one import (sha256Hex from ./seal-crypto.js) bound to
 *  seal-crypto.js of the same commit. Only exported names are reachable; the text is otherwise unchanged. */
export async function loadOwlCore(owlDir, pin = OWL_STRICT_PIN) {
  const scText = readPinned(owlDir, 'scripts/seal-crypto.js', pin.files['scripts/seal-crypto.js'], pin.commit);
  const coreText = readPinned(owlDir, 'scripts/biomesh-core.js', pin.files['scripts/biomesh-core.js'], pin.commit);
  if (/^\s*import\s/m.test(scText)) throw new Error('seal-crypto.js gained an import; the loader must be reviewed');
  const imports = coreText.match(/^\s*import\b.*$/gm) || [];
  const ONE = 'import { sha256Hex } from "./seal-crypto.js";';
  if (imports.length !== 1 || imports[0].trim() !== ONE || /\bimport\s*\(/.test(coreText)) {
    throw new Error('biomesh-core.js has other imports than sha256Hex from ./seal-crypto.js; the loader must be reviewed');
  }
  globalThis.__shdccpOwlCore = { SC: await asModule(scText) };
  return { CORE: await asModule(coreText.replace(ONE, 'const { sha256Hex } = globalThis.__shdccpOwlCore.SC;')), pin };
}

export async function loadOwl(owlDir, pin = OWL_PIN) {
  const scText = readPinned(owlDir, 'scripts/seal-crypto.js', pin.files['scripts/seal-crypto.js'], pin.commit);
  const bmText = readPinned(owlDir, 'scripts/biomesh.js', pin.files['scripts/biomesh.js'], pin.commit);
  if (/^\s*import\s/m.test(scText)) throw new Error('seal-crypto.js gained an import; the loader must be reviewed');
  const SC = await asModule(scText);
  globalThis.__shdccpOwlNamegrab = {
    SC,
    stub: (name) => () => { throw new Error(`${name} is not available under the name-grab`); },
  };
  const exported = (n) => new RegExp(`^export\\s+(?:async\\s+)?(?:function|const|let|class)\\s+${n}\\b`, 'm').test(bmText);
  for (const n of INTERNAL) {
    if (exported(n)) throw new Error(`${n} is exported now; drop it from INTERNAL`);
    // CHUNK and SEGMENTS share one `const` line, so a declaration is matched after `const`, `function`, `class` or `,`.
    if (!new RegExp(`(?:function|const|class|,)\\s+${n}\\s*(?:=|\\()`).test(bmText)) throw new Error(`${n} not found in biomesh.js`);
  }
  const BM = await asModule(rewriteImports(bmText) + `\nexport { ${INTERNAL.join(', ')} };\n`);
  return { BM, SC, pin };
}
