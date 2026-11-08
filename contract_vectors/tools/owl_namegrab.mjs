// SPDX-License-Identifier: CC0-1.0
// Part of contract_vectors/ (CC0-1.0, see ../LICENSE). Written for SHD-CCP-core; contains no code from Owl-Academy.
//
// Loads Owl-Academy's scripts/biomesh.js and scripts/seal-crypto.js (MIT, (c) Ebayednoob) READ-ONLY, by name-grab:
//   - each file is read from the Owl-Academy git object store at the pinned commit (`git show <commit>:<path>`),
//     so the checkout's working tree is never read, written or switched;
//   - its SHA-256 must equal the pinned value, or loading stops;
//   - the text is evaluated in memory as an ES module. seal-crypto.js has no imports and runs unchanged.
//     biomesh.js's import statements are replaced by bindings: `SC` is the loaded seal-crypto module, and every
//     Firestore, registrar, oracle and seal helper becomes a stub that throws (the pure grow cell never calls them).
//     A trailing `export { ... }` exposes the pure internal functions (crystallize, crystalQuat, ...) by name.
// Nothing is written to disk. The returned object holds Owl's own functions; this file computes nothing itself.

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

function readPinned(owlDir, path, expected, commit) {
  let buf;
  try {
    buf = execFileSync('git', ['-C', owlDir, 'show', `${commit}:${path}`], { maxBuffer: 1 << 26 });
  } catch (e) {
    throw new Error(`cannot read ${path} at ${commit} from ${owlDir} (is it an Owl-Academy clone holding that `
      + `commit?): ${String(e.stderr || e.message).trim()}`);
  }
  const got = sha256(buf);
  if (got !== expected) throw new Error(`${path} at ${commit}: sha256 ${got}, pinned ${expected}`);
  return buf.toString('utf8');
}

const asModule = (text) => import('data:text/javascript;base64,' + Buffer.from(text, 'utf8').toString('base64'));

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
