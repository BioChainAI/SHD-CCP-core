#!/usr/bin/env node
// SPDX-License-Identifier: CC0-1.0
// Part of contract_vectors/ (CC0-1.0, see ../LICENSE).
//
// The single generator of the RFC 07 contract vectors (contract_vectors/suites/*.json).
//
// Every expected value comes from the code each suite's `source` names, loaded read-only from git objects at a pinned
// commit, and from the V8 built-ins that code calls (Math.hypot, Number.prototype.toFixed, String.prototype.toUpperCase):
//   - Owl-Academy's scripts/biomesh.js (the reference implementation, D5), by owl_namegrab.mjs, for the codec suites;
//   - Owl-Academy's scripts/biomesh-core.js at O3's commit (verifyIntegrityStrict, the strict verifier), by
//     owl_namegrab.mjs, for the verdicts of shdccp2_tamper and shdccp2_tamper_open;
//   - BioChain-AI's src/identity/crypto-core.js and epoch-service.js (the owner of ATTEST/1, D5) and Owl's
//     seal-crypto.js and schumann-oracle.js (SEAL/1), by pinned_sources.mjs, for attest1_profile and the draft
//     attest1_profile_open;
//   - cv_spec.mjs, the generator's own code written from the cited specifications, for what neither computes (RFC 6962
//     trees and proofs, BIOSEED/1, deterministic RFC 6979 signatures and DER, the rank coder's code lengths, the
//     registry snapshot text). Every such value is checked here against the pinned code wherever that code can check
//     it (WebCrypto verifies every signature; Owl's encodeChunk gives the padded residual).
// This file only chooses inputs (fixed lists and seeded searches whose results are stored as explicit inputs), calls
// those functions and writes the results. Where it combines Owl's functions itself (the weave intermediates), it
// asserts that the combination reproduces Owl's own growBiochain output.
//
// Usage:
//   node contract_vectors/tools/generate.mjs [--owl DIR] [--owl-strict DIR] [--biochain DIR] --write    regenerate
//                                                     suites/ in place
//   node contract_vectors/tools/generate.mjs [--owl DIR] [--owl-strict DIR] [--biochain DIR] --check    drift check:
//                                                     fail on a stale, missing or unknown file in suites/, or an
//                                                     unknown top-level entry
// --owl DIR defaults to $OWL_ACADEMY_DIR, then ../Owl-Academy beside this repository; --owl-strict DIR (a clone holding
// O3's commit) to $OWL_ACADEMY_STRICT_DIR, then the --owl clone; --biochain DIR to $BIOCHAIN_AI_DIR, then
// ../BioChain-AI. Only their git object stores are read (git show <pinned commit>:<path>);
// their working trees are never touched.

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { loadOwl, loadOwlCore, OWL_PIN, OWL_STRICT_PIN } from './owl_namegrab.mjs';
import { loadPlainModules, BIOCHAIN_PIN, OWL_TICK_PIN } from './pinned_sources.mjs';
import * as SPEC from './cv_spec.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CV = resolve(HERE, '..');                       // contract_vectors/
const REPO = resolve(CV, '..');
const SUITES_DIR = join(CV, 'suites');
const SPEC_VERSION = '0.1.0';
const RFC = '07';
const WIRE = 'shdccp/2';
const INLINE_LIMIT = 8192;                            // longer streams are written as sha256 + length
// The only entries allowed at the top of contract_vectors/ (the drift check fails on any other).
const TOP_LEVEL = ['LICENSE', 'README.md', 'lock.json', 'schema.json', 'suites', 'tools'];

// ─── arguments ────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const mode = argv.includes('--write') ? 'write' : argv.includes('--check') ? 'check' : null;
const owlArg = argv.indexOf('--owl') >= 0 ? argv[argv.indexOf('--owl') + 1] : null;
const bcArg = argv.indexOf('--biochain') >= 0 ? argv[argv.indexOf('--biochain') + 1] : null;
const owlStrictArg = argv.indexOf('--owl-strict') >= 0 ? argv[argv.indexOf('--owl-strict') + 1] : null;
if (!mode) { console.error('usage: generate.mjs [--owl DIR] [--owl-strict DIR] [--biochain DIR] (--write | --check)'); process.exit(2); }
const OWL_DIR = resolve(owlArg || process.env.OWL_ACADEMY_DIR || join(REPO, '..', 'Owl-Academy'));
if (!existsSync(OWL_DIR)) {
  console.error(`Owl-Academy not found at ${OWL_DIR}; pass --owl DIR or set OWL_ACADEMY_DIR`);
  process.exit(2);
}
const BC_DIR = resolve(bcArg || process.env.BIOCHAIN_AI_DIR || join(REPO, '..', 'BioChain-AI'));
if (!existsSync(BC_DIR)) {
  console.error(`BioChain-AI not found at ${BC_DIR}; pass --biochain DIR or set BIOCHAIN_AI_DIR`);
  process.exit(2);
}

const OWL_STRICT_DIR = resolve(owlStrictArg || process.env.OWL_ACADEMY_STRICT_DIR || OWL_DIR);
if (!existsSync(OWL_STRICT_DIR)) {
  console.error(`Owl-Academy (strict verifier) not found at ${OWL_STRICT_DIR}; pass --owl-strict DIR or set OWL_ACADEMY_STRICT_DIR`);
  process.exit(2);
}

const { BM, SC } = await loadOwl(OWL_DIR);
const { CORE } = await loadOwlCore(OWL_STRICT_DIR);
const BCM = await loadPlainModules(BC_DIR, BIOCHAIN_PIN);
const BC = BCM['src/identity/crypto-core.js'], BEPOCH = BCM['src/identity/epoch-service.js'];
const OTM = await loadPlainModules(OWL_DIR, OWL_TICK_PIN);
const OS = OTM['scripts/seal-crypto.js'], OTICK = OTM['scripts/schumann-oracle.js'];

// ─── helpers (formatting and input selection only) ───────────────────────────
const enc = new TextEncoder();
const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const f64hex = (x) => { const b = Buffer.alloc(8); b.writeDoubleBE(x); return b.toString('hex'); };
const CRYSTAL_BYTE = { w: 24, x: 16, y: 8, z: 0 };   // the four crystal bytes, named by the quaternion slot they feed
const crystal32Of = (packetHex) => packetHex.slice(2, 10);  // bits 55..24 of the packet word
const signedCodes = (c32hex) => [0, 2, 4, 6].map((i) => { const v = parseInt(c32hex.slice(i, i + 2), 16); return v >= 128 ? v - 256 : v; });
const x80Slots = (c32hex) => Object.keys(CRYSTAL_BYTE).filter((_, i) => c32hex.slice(2 * i, 2 * i + 2) === '80');

// A deterministic PRNG for the searches. Its only job is to propose inputs; every chosen input is stored verbatim,
// so no implementation needs it. It is Owl's own mulberry32, reached through the name-grab.
const rngFor = (seed) => { const r = BM.mulberry32(seed); return { next: () => Math.floor(r() * 4294967296), int: (n) => Math.floor(r() * n) }; };
const WORDS = ('owl academy chain grows reads seals tome spire lattice weave mirror chiral packet stream crystal leaf '
  + 'root merkle frame residual engram token gamma rank coder byte chunk record value epoch growth lineage geodesic '
  + 'halo form gate slot scale cycle wheel structure core quaternion hypot fixed digits north south east west').split(' ');
const randomWords = (rng, nBytes) => { let s = ''; while (s.length < nBytes) s += WORDS[rng.int(WORDS.length)] + (rng.int(9) === 0 ? '. ' : ' '); return s.slice(0, nBytes); };

// Input texts: a plain string, or parts concatenated, where a part {repeat, length} is the first `length`
// characters of `repeat` repeated (repeat is ASCII, so characters are bytes).
function textOf(input) {
  if (typeof input.text === 'string') return input.text;
  return input.text_parts.map((p) => typeof p === 'string' ? p : p.repeat.repeat(Math.ceil(p.length / p.repeat.length)).slice(0, p.length)).join('');
}
const longOrInline = (key, s) => s.length > INLINE_LIMIT ? { [key + '_sha256']: sha256hex(s), [key + '_length']: s.length } : { [key]: s };

async function grow(text, engrams) { return BM.growBiochain(text, { engrams }); }

// ─── suite: shdccp2_packet ───────────────────────────────────────────────────
function packetCase(id, bytes, note) {
  const packet = BM.crystallize(bytes);
  const c32 = crystal32Of(packet);
  const f = BM.unpackPacket(packet);
  const codes = signedCodes(c32);
  const csum = bytes.reduce((a, b) => a + b, 0) & 0xff;
  // informative: BioChain-AI's kernel normalisation (code -128 written as -127), packed with Owl's own packWord
  const kernel = BM.packWord(9, 0, codes.map((c) => c === -128 ? -127 : c), bytes.length & 0xffff, csum >> 3, csum & 7);
  const c = {
    id, input: { chunk_hex: hexOf(bytes) },
    expect: {
      packet, crystal32: c32, crystal_codes: codes,
      fields: { form: f.form, parity: Number((BigInt('0x' + packet) >> 59n) & 1n), spin: f.spin, payload16: f.payload16, freq: f.freq, amp: f.amp },
    },
    informative: { crystal_0x80_slots: x80Slots(c32), kernel_normalized_packet: kernel, kernel_normalized_differs: kernel !== packet },
  };
  if (note) c.note = note;
  return c;
}

function packetSuite() {
  const cases = [];
  cases.push(packetCase('golden_bytes_0_59', [...Array(60).keys()], 'the long-standing cross-language golden; it has no 0x80 crystal byte'));
  cases.push(packetCase('one_byte_00', [0x00]));
  cases.push(packetCase('one_byte_ff', [0xff]));
  cases.push(packetCase('one_byte_80', [0x80]));
  cases.push(packetCase('ascii_owl_academy', [...enc.encode('Owl Academy')]));
  cases.push(packetCase('full_720_ramp', Array.from({ length: 720 }, (_, i) => i & 0xff), 'a full chunk; payload16 = 720'));
  cases.push(packetCase('full_720_ff', Array(720).fill(0xff)));
  // seeded search: 10 chunks per crystal slot with exactly that byte 0x80, then 6 with two 0x80 bytes
  const rng = rngFor(0x5eed0080);
  const want = { w: 10, x: 10, y: 10, z: 10 };
  const got = { w: 0, x: 0, y: 0, z: 0 }, pairs = [], found = [];
  let tries = 0;
  while ((Object.keys(want).some((k) => got[k] < want[k]) || pairs.length < 6) && tries < 5_000_000) {
    tries++;
    const len = 1 + rng.int(720);
    const bytes = Array.from({ length: len }, () => rng.int(256));
    const slots = x80Slots(crystal32Of(BM.crystallize(bytes)));
    if (slots.length === 1 && got[slots[0]] < want[slots[0]]) {
      found.push(packetCase(`x80_${slots[0]}_${String(got[slots[0]]).padStart(2, '0')}`, bytes));
      got[slots[0]]++;
    } else if (slots.length === 2 && pairs.length < 6) {
      pairs.push(1);
      found.push(packetCase(`x80_${slots.join('')}_${String(pairs.length - 1).padStart(2, '0')}`, bytes));
    }
  }
  // single-slot cases first (w, x, y, z), then the two-slot ones, each in discovery order
  const rank = (c) => { const slot = c.id.split('_')[1]; return [slot.length, slot]; };
  found.sort((a, b) => { const [la, sa] = rank(a), [lb, sb] = rank(b); return la - lb || (sa < sb ? -1 : sa > sb ? 1 : 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0); });
  cases.push(...found);
  if (Object.keys(want).some((k) => got[k] < want[k]) || pairs.length < 6) throw new Error('0x80 search did not finish');
  return {
    suite: 'shdccp2_packet',
    description: 'crystallize(chunk): the shdccp/2 crystal packet of one chunk (RFC 07 section 5), with 0x80 crystal bytes '
      + 'in each of the four slots. The raw rule is normative; informative.kernel_normalized_packet shows the packet '
      + 'under the kernel normalisation (code -128 written as -127), which shdccp/2 does not use.',
    cases,
  };
}

// ─── texts used by several suites ─────────────────────────────────────────────
const ASCII_UNIT = 'The owl reads the chain; the chain remembers the owl. ';
function findX80Text(rngSeed, nChunks, slotsWanted) {
  // ASCII random-word chunks of 720 bytes; chunk k must have a 0x80 crystal byte iff slotsWanted[k] is set.
  const rng = rngFor(rngSeed);
  let text = '';
  for (let k = 0; k < nChunks; k++) {
    const last = k === nChunks - 1;
    for (let t = 0; ; t++) {
      if (t > 200000) throw new Error('0x80 text search did not finish');
      const len = last ? 100 + rng.int(620) : 720;
      const chunk = randomWords(rng, len);
      const slots = x80Slots(crystal32Of(BM.crystallize([...enc.encode(chunk)])));
      const want = slotsWanted[k];
      if (want === null ? slots.length === 0 : (slots.length === 1 && slots[0] === want)) { text += chunk; break; }
    }
  }
  return text;
}

// ─── suite: shdccp2_chunk (rank coder, frame, leaf) ──────────────────────────
async function chunkSuite() {
  const sources = [
    { id: 'hello', text: 'hello' },
    { id: 'repeat_a_720', text: 'a'.repeat(720) },
    { id: 'eacute', text: 'é' },
    { id: 'split_2byte', text: 'x'.repeat(719) + 'é' + ' tail' },
    { id: 'split_4byte', text: 'y'.repeat(718) + '🦉' + '!' },
    { id: 'latin1_range', text: Array.from({ length: 160 }, (_, i) => String.fromCodePoint(0xa0 + i)).join('') },
    { id: 'many_candidates', text: Array.from({ length: 240 }, (_, i) => 'qz' + String.fromCodePoint(0x21 + (i % 94))).join('') },
    { id: 'random_words_3', text: randomWords(rngFor(0xc0de0003), 2000) },
    { id: 'ascii_60000_tail', text: ASCII_UNIT.repeat(1200).slice(0, 60000) },
  ];
  const cases = [];
  for (const s of sources) {
    const rec = await grow(s.text, false);
    const frames = BM.parseBiochainStream(rec.stream);
    const chunks = BM.recreateChunks(rec);
    const pick = s.id === 'ascii_60000_tail' ? [0, 82, 83] : s.id === 'random_words_3' ? [0, 1, 2] : chunks.map((_, i) => i);
    for (const i of pick) {
      const residual = frames[i].residual;
      const packet = frames[i].packet;
      if (BM.encodeChunk(chunks[i]) !== residual) throw new Error('encodeChunk disagrees with the grown stream');
      cases.push({
        id: `${s.id}_${i}`, input: { index: i, chunk_hex: hexOf(chunks[i]) },
        expect: { packet, residual, residual_bytes: residual.length / 2, frame: BM.frameStream([packet], [residual]), leaf: rec.leafHashes[i] },
      });
    }
  }
  // the same chunk at two indices: leaves are index-bound
  const rec = await grow('same'.repeat(180) + 'same'.repeat(180), false);
  const chunks = BM.recreateChunks(rec);
  for (const i of [0, 1]) {
    const f = BM.parseBiochainStream(rec.stream)[i];
    cases.push({ id: `index_bound_${i}`, note: 'chunks 0 and 1 are byte-identical; only the index differs',
      input: { index: i, chunk_hex: hexOf(chunks[i]) },
      expect: { packet: f.packet, residual: f.residual, residual_bytes: f.residual.length / 2, frame: BM.frameStream([f.packet], [f.residual]), leaf: rec.leafHashes[i] } });
  }
  return {
    suite: 'shdccp2_chunk',
    description: 'One chunk at index i: the rank-coder residual (RFC 07 section 6), the frame (section 4) and the leaf hash '
      + '(section 7). Every chunk is a chunk of a real grow, taken from Owl\'s growBiochain output.',
    cases,
  };
}

// ─── suite: shdccp2_merkle ───────────────────────────────────────────────────
async function merkleSuite() {
  const cases = [];
  for (const k of [1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 33, 84]) {
    const rng = rngFor(0x6e7c1e00 + k);
    const text = randomWords(rng, k === 84 ? 60000 : 720 * (k - 1) + 1 + rng.int(720));
    const rec = await grow(text, false);
    if (rec.leafHashes.length !== k) throw new Error('merkle case size');
    cases.push({ id: `k_${String(k).padStart(2, '0')}`, input: { leaves: rec.leafHashes }, expect: { root: rec.merkleRoot } });
  }
  return {
    suite: 'shdccp2_merkle',
    description: 'The shdccp/2 Merkle rule (RFC 07 section 7.2): root of K leaf hashes, K = 1..9, 16, 17, 33, 84. Leaves '
      + 'and roots are taken from Owl\'s growBiochain output.',
    cases,
  };
}

// ─── suite: shdccp2_arith (D7: the exact float arithmetic) ───────────────────
function arithSuite() {
  const cases = [];
  const H = (v) => v.map(f64hex);
  // hypot: V8's Math.hypot on four arguments, as qn calls it
  const hyp = [
    ['unit', [1, 0, 0, 0]], ['zero', [0, 0, 0, 0]], ['negzero', [-0, -0, -0, -0]], ['half', [0.5, 0.5, 0.5, 0.5]],
    ['crystal_min', [0.5 + (-128) / 254, -128 / 127, -128 / 127, -128 / 127]],
    ['crystal_max', [0.5 + 127 / 254, 127 / 127, 127 / 127, 127 / 127]],
    ['tiny', [1e-300, 2e-300, 3e-300, 4e-300]], ['huge', [1e300, 1e300, 1e300, 1e300]],
  ];
  for (const [id, a] of hyp) cases.push({ id: `hypot_${id}`, input: { op: 'hypot', args: H(a) }, expect: { result: f64hex(Math.hypot(...a)) } });
  // seeded search: inputs from the crystalQuat domain where V8's hypot differs from sqrt of the plain sum of squares
  const rng = rngFor(0x4879707f);
  let found = 0, same = 0;
  for (let t = 0; t < 200000 && (found < 12 || same < 4); t++) {
    const s = () => { const v = rng.int(256); return v >= 128 ? v - 256 : v; };
    const a = [0.5 + s() / 254, s() / 127, s() / 127, s() / 127];
    const naive = Math.sqrt(a[0] * a[0] + a[1] * a[1] + a[2] * a[2] + a[3] * a[3]);
    const v8 = Math.hypot(...a);
    if (v8 !== naive && found < 12) cases.push({ id: `hypot_differs_${String(found++).padStart(2, '0')}`, note: 'sqrt of the plain sum of squares gives another double', input: { op: 'hypot', args: H(a) }, expect: { result: f64hex(v8) }, informative: { plain_sqrt_sum: f64hex(naive) } });
    else if (v8 === naive && same < 4) cases.push({ id: `hypot_agrees_${String(same++).padStart(2, '0')}`, input: { op: 'hypot', args: H(a) }, expect: { result: f64hex(v8) } });
  }
  // qn: Owl's normaliser (hypot, `|| 1`, then four divisions)
  const qnIn = [['unit', [1, 0, 0, 0]], ['zero', [0, 0, 0, 0]], ['negzero', [-0, 0, -0, 0]], ['crystal_min', [0.5 + (-128) / 254, -128 / 127, -128 / 127, -128 / 127]], ['mixed', [0.25, -0.75, 1.5, -2]]];
  for (const [id, a] of qnIn) cases.push({ id: `qn_${id}`, input: { op: 'qn', args: H(a) }, expect: { result: H(BM.qn(a)) } });
  // qmul and qconj: Owl's Hamilton product in its own operation order
  const r2 = rngFor(0x716d756c);
  const rq = () => BM.qn([r2.next() / 4294967296 - 0.5, r2.next() / 4294967296 - 0.5, r2.next() / 4294967296 - 0.5, r2.next() / 4294967296 - 0.5]);
  for (let i = 0; i < 8; i++) { const a = rq(), b = rq(); cases.push({ id: `qmul_${i}`, input: { op: 'qmul', a: H(a), b: H(b) }, expect: { result: H(BM.qmul(a, b)) } }); }
  { const a = rq(); cases.push({ id: 'qconj_0', input: { op: 'qconj', a: H(a) }, expect: { result: H(BM.qconj(a)) } }); }
  // toFixed(12) through Owl's quatHex, one component at a time
  const t12 = [
    ['tie_up_1', 1 / 8192], ['tie_up_3', 3 / 8192], ['tie_neg_5', -5 / 8192], ['tie_up_8191', 8191 / 8192],
    ['negzero', -0], ['tiny_negative', -1e-15], ['tiny_positive', 4e-13], ['near_one', 0.9999999999995], ['near_minus_one', -0.9999999999995],
    ['one', 1], ['minus_one', -1], ['third', 1 / 3], ['crystal_min_w', 0.5 + (-128) / 254], ['below_minus_one', -128 / 127],
  ];
  for (const [id, x] of t12) cases.push({ id: `fixed12_${id}`, input: { op: 'toFixed', digits: 12, x: f64hex(x) }, expect: { text: BM.quatHex([x]) } });
  // toFixed(4), as value and engramMeanJ use it, then read back as a double (`+x.toFixed(4)`)
  const t4 = [['tie_1_32', 1 / 32], ['tie_3_32', 3 / 32], ['tie_neg_1_32', -1 / 32], ['tie_neg_5_32', -5 / 32], ['tiny_negative', -1e-6], ['ratio', 8 / 101], ['one', 1]];
  for (const [id, x] of t4) cases.push({ id: `fixed4_${id}`, input: { op: 'toFixed', digits: 4, x: f64hex(x) }, expect: { text: x.toFixed(4), number: f64hex(+x.toFixed(4)) } });
  return {
    suite: 'shdccp2_arith',
    description: 'The exact binary64 arithmetic of the weaves and derived numbers (RFC 07 section 8, D7): V8 Math.hypot on '
      + 'four arguments, Owl\'s qn, qmul and qconj, Number.prototype.toFixed(12) through Owl\'s quatHex, and toFixed(4) read '
      + 'back as a number. Doubles are 16 hex digits of the IEEE-754 binary64 bit pattern, big-endian.',
    cases,
  };
}

// ─── suite: shdccp2_weave ────────────────────────────────────────────────────
async function weaveSuite() {
  const sources = [
    { id: 'one_chunk', text: 'GEODESIC' },
    { id: 'x80_w_then_plain', text: findX80Text(0x77ea0001, 2, ['w', null]) },
    { id: 'x80_x_y_z', text: findX80Text(0x77ea0002, 4, [null, 'x', 'y', 'z']) },
    { id: 'x80_w_x80_w', text: findX80Text(0x77ea0003, 3, ['w', null, 'w']) },
    { id: 'eight_chunks', text: randomWords(rngFor(0x77ea0008), 720 * 7 + 333) },
    { id: 'repeat_20_chunks', text: ASCII_UNIT.repeat(300).slice(0, 720 * 19 + 5) },
  ];
  const cases = [];
  for (const s of sources) {
    const rec = await grow(s.text, false);
    const chunks = BM.recreateChunks(rec);
    const quats = chunks.map((c) => BM.crystalQuat(c));
    // intermediates, combined from Owl's functions; checked against Owl's own growBiochain below
    let wf = [1, 0, 0, 0], wm = [1, 0, 0, 0];
    const chiralSteps = [], mirrorSteps = [];
    for (const q of quats) { wf = BM.qn(BM.qmul(q, wf)); chiralSteps.push(wf.map(f64hex)); }
    for (const q of [...quats].reverse()) { wm = BM.qn(BM.qmul(BM.qconj(q), wm)); mirrorSteps.push(wm.map(f64hex)); }
    if (BM.quatHex(wf) !== rec.weaveChiral || BM.quatHex(wm) !== rec.weaveMirror) throw new Error(`weave intermediates disagree with growBiochain (${s.id})`);
    const crystals = BM.parseBiochainStream(rec.stream).map((f) => crystal32Of(f.packet));
    cases.push({
      id: s.id, input: { chunks_hex: chunks.map(hexOf) },
      expect: {
        crystal32: crystals, crystal_quat: quats.map((q) => q.map(f64hex)),
        chiral_steps: chiralSteps, mirror_steps: mirrorSteps,
        weaveChiral: rec.weaveChiral, weaveMirror: rec.weaveMirror,
      },
      informative: { crystal_0x80_slots: crystals.map(x80Slots) },
    });
  }
  return {
    suite: 'shdccp2_weave',
    description: 'crystalQuat per chunk and the chiral and mirror weaves (RFC 07 section 8), including chunks whose crystal '
      + 'has a 0x80 byte (read as -128). Intermediate accumulators are binary64 bit patterns after each step; the final '
      + 'strings equal Owl\'s growBiochain output for the same chunks.',
    cases,
  };
}

// ─── suite: engram1 ──────────────────────────────────────────────────────────
function engramSuite() {
  const cases = [];
  const texts = [
    ['geodesic', 'GEODESIC'], ['mixed_case', 'Geodesic geodesic GEODESIC'], ['apostrophe_digits', "Don't count 42 owls, 7x9 won't"],
    ['non_ascii', 'Straße café naïve Ωmega 日本'], ['punctuation_only', '!!! ... ???'], ['empty', ''],
    ['sentence', 'The owl reads the chain; the chain remembers the owl.'],
  ];
  for (const [id, text] of texts) {
    const tokens = BM.tokenizeEngrams(text);
    const grids = tokens.map((t) => BM.engramGrid(t));
    const s = BM.engramStreamFromText(text);
    cases.push({
      id, input: { text },
      expect: {
        tokens, grids_hex: grids.map((g) => BM.engramGridHex(g)), j_num: grids.map((g) => BM.engramJ(g) * 32),
        engramStream: s.stream, engramCount: s.count, engramMeanJ: s.meanJ,
      },
    });
  }
  for (let c = 65; c <= 90; c++) {
    const ch = String.fromCharCode(c);
    cases.push({ id: `letter_${ch}`, input: { text: ch }, expect: { tokens: [ch], grids_hex: [BM.engramGridHex(BM.engramGrid(ch))], j_num: [BM.engramJ(BM.engramGrid(ch)) * 32], engramStream: BM.engramStreamFromText(ch).stream, engramCount: 1, engramMeanJ: BM.engramStreamFromText(ch).meanJ } });
  }
  for (const seed of [65, 90]) {
    const r = BM.mulberry32(seed);
    cases.push({ id: `mulberry32_${seed}`, input: { mulberry32_seed: seed, draws: 64 }, expect: { u32: Array.from({ length: 64 }, () => r() * 4294967296) } });
  }
  return {
    suite: 'engram1',
    description: 'The engram/1 layer of a record (RFC 07 section 9): tokens, per-token grids (LSB-first, upper-case hex), '
      + 'J numerators, the engram stream, count and mean J; the 26 letter grids; mulberry32 draws as unsigned 32-bit integers.',
    cases,
  };
}

// ─── suite: shdccp2_record ───────────────────────────────────────────────────
function findMeanJTie(sign) {
  // a one-token text whose J numerator is odd and has the given sign, so meanJ = odd/32 is a toFixed(4) tie
  for (const w of WORDS.concat(WORDS.map((x) => x.toUpperCase() + 'Q'))) {
    const jn = BM.engramJ(BM.engramGrid(w)) * 32;
    if (jn % 2 !== 0 && Math.sign(jn) === sign) return w;
  }
  throw new Error('no meanJ tie word');
}

// The record suite's inputs, also the honest records that shdccp2_tamper alters (computed once).
let RECORD_INPUTS = null;
function recordInputs() {
  if (RECORD_INPUTS) return RECORD_INPUTS;
  const R = (length) => ({ repeat: ASCII_UNIT, length });
  RECORD_INPUTS = [
    ['one_byte', { text: 'a', engrams: true }],
    ['geodesic', { text: 'GEODESIC', engrams: true }],
    ['geodesic_no_engrams', { text: 'GEODESIC', engrams: false }],
    ['leading_bom', { text: '﻿GEODESIC', engrams: true,
      note: 'the text starts with U+FEFF (bytes EF BB BF); a verifier keeps it when decoding (RFC 07 section 12.1, step 2)' }],
    ['no_tokens', { text: '!!! ... ???', engrams: true }],
    ['tokens_mixed', { text: "Don't count 42 owls; Straße, café, naïve, GEODESIC.", engrams: true }],
    ['utf8_multibyte', { text: '日本語のテキスト 🦉 émigré Ωmega', engrams: true }],
    ['meanj_tie_positive', { text: findMeanJTie(1), engrams: true }],
    ['meanj_tie_negative', { text: findMeanJTie(-1), engrams: true }],
    ['ascii_719', { text_parts: [R(719)], engrams: true }],
    ['ascii_720', { text_parts: [R(720)], engrams: true }],
    ['ascii_721', { text_parts: [R(721)], engrams: true }],
    ['ascii_1440', { text_parts: [R(1440)], engrams: true }],
    ['ascii_1441', { text_parts: [R(1441)], engrams: false }],
    ['split_2byte_at_720', { text_parts: [R(719), 'é tail'], engrams: true }],
    ['split_4byte_at_720', { text_parts: [R(718), '🦉!'], engrams: true }],
    ['x80_single_chunk', { text: findX80Text(0x2ec00001, 1, ['w']), engrams: true }],
    ['x80_three_chunks', { text: findX80Text(0x2ec00003, 3, ['z', null, 'x']), engrams: true }],
    ['words_7_chunks', { text: randomWords(rngFor(0x2ec00007), 720 * 6 + 101), engrams: true }],
    ['max_60000_repeat', { text_parts: [R(60000)], engrams: true }],
    ['max_60000_words', { text: null, gen: () => randomWords(rngFor(0x2ec60000), 60000), engrams: false }],
    ['error_empty', { text: '', engrams: true }],
    ['error_60001', { text_parts: [R(60001)], engrams: true }],
    ['error_60002_multibyte', { text_parts: ['é'.repeat(30001)], engrams: true }],
  ];
  return RECORD_INPUTS;
}
/** The text and engram flag of the record suite's input `id`. */
function recordText(id) {
  const hit = recordInputs().find(([k]) => k === id);
  if (!hit) throw new Error(`no record input ${id}`);
  const raw = hit[1];
  return { text: raw.gen ? raw.gen() : textOf(raw.text_parts ? { text_parts: raw.text_parts } : { text: raw.text }), engrams: raw.engrams };
}

async function recordSuite() {
  const inputs = recordInputs();
  const cases = [];
  for (const [id, raw] of inputs) {
    const input = { engrams: raw.engrams };
    if (raw.gen) {
      // too long to store inline as text: store its exact repeat-free form as parts of at most 8,000 characters
      const t = raw.gen(); const parts = []; for (let i = 0; i < t.length; i += 8000) parts.push(t.slice(i, i + 8000));
      input.text_parts = parts;
    } else if (raw.text_parts) input.text_parts = raw.text_parts; else input.text = raw.text;
    const text = textOf(input);
    let rec, err = null;
    try { rec = await grow(text, raw.engrams); } catch (e) { err = e.message; }
    if (err !== null) {
      const code = /^Nothing to grow/.test(err) ? 'empty-input' : /^Grow input capped/.test(err) ? 'input-too-large' : null;
      if (!code) throw new Error(`unexpected grow error ${err}`);
      cases.push({ id, input, expect: { error: code }, informative: { owl_message: err } });
      continue;
    }
    const v = await BM.verifyIntegrity(rec);
    if (!v.ok) throw new Error(`Owl's verifyIntegrity rejects its own record ${id}`);
    const expect = {};
    for (const [k, val] of Object.entries(rec)) {
      if (k === 'stream' || k === 'engramStream') Object.assign(expect, longOrInline(k, val)); else expect[k] = val;
    }
    // informative, outside the lock: no implementation independent of Owl's computes GROWN/1 yet (RFC 07 section 13)
    const informative = { grown_commitment: BM.grownCommitment(rec), grown_content_hash: await SC.sha256Hex(BM.grownCommitment(rec)) };
    const k80 = BM.parseBiochainStream(rec.stream).map((f) => x80Slots(crystal32Of(f.packet)));
    if (k80.some((s) => s.length)) informative.crystal_0x80_slots = k80;
    cases.push({ id, ...(raw.note ? { note: raw.note } : {}), input, expect, informative });
  }
  return {
    suite: 'shdccp2_record',
    description: 'growBiochain(text, {engrams}): the whole grown record (RFC 07 sections 3-10); size edges '
      + '1/719/720/721/1,440/1,441/60,000 bytes, characters split by the 720-byte cut, a leading U+FEFF, 0x80 crystal '
      + 'bytes, engram edge cases, and the two input errors. The GROWN/1 commitment and its content hash (section 13) are '
      + 'informative, outside the lock, until an implementation independent of Owl\'s computes them. Streams longer than '
      + '8,192 hex characters are given as <field>_sha256 (lower-case hex SHA-256 of the ASCII stream) and <field>_length.',
    cases,
  };
}

// ─── sources named in the envelope ──────────────────────────────────────────
const pinSource = (pin) => ({ repository: pin.repository, commit: pin.commit, files: { ...pin.files }, license: pin.license, engine: 'V8' });
const OWL_SOURCE = pinSource(OWL_PIN);
const specSource = (basis) => ({ code: 'contract_vectors/tools/cv_spec.mjs', license: 'CC0-1.0', engine: 'V8', basis });
const textParts = (t) => { const parts = []; for (let i = 0; i < t.length; i += 8000) parts.push(t.slice(i, i + 8000)); return parts; };

// ─── suite: shdccp2_limits (P8) ──────────────────────────────────────────────
const MAX_BITS_PER_BYTE = 2 * 9 - 1 + 8;   // gamma(256) + 8: an escape after 255 candidates (RFC 07 section 6.6)
function coderCase(id, bytes, note) {
  const residual = BM.encodeChunk(bytes);
  const codes = SPEC.codeBits(bytes);
  const used = codes.reduce((a, c) => a + c.bits, 0);
  // the generator's code lengths must account for Owl's residual exactly: ceil(used / 8) bytes and zero padding
  if (Math.ceil(used / 8) * 2 !== residual.length) throw new Error(`code lengths disagree with encodeChunk (${id})`);
  const padBits = BigInt(residual.length * 4 - used);
  if ((BigInt('0x' + residual) & ((1n << padBits) - 1n)) !== 0n) throw new Error(`nonzero padding (${id})`);
  const back = BM.decodeChunk(residual, bytes.length);
  if (back.length !== bytes.length || back.some((b, i) => b !== bytes[i])) throw new Error(`decodeChunk (${id})`);
  const max = Math.max(...codes.map((c) => c.bits));
  const at = codes.findIndex((c) => c.bits === max);
  const c = {
    id, input: { coder_input_hex: hexOf(bytes) },
    expect: { residual, residual_bytes: residual.length / 2, used_bits: used, max_code_bits: max, max_code_index: at },
    informative: { max_code_candidates: codes[at].candidates, max_code_escape: codes[at].escape, in_chunk_domain: bytes.length <= BM.CHUNK },
  };
  if (note) c.note = note;
  return c;
}
function deBruijn3(alphabet) {
  // the lexicographically least de Bruijn sequence of order 3 (every 3-symbol word once, cyclically), FKM algorithm
  const k = alphabet.length, n = 3, a = Array(k * n).fill(0), seq = [];
  const db = (t, p) => {
    if (t > n) { if (n % p === 0) for (let j = 1; j <= p; j++) seq.push(a[j]); return; }
    a[t] = a[t - p]; db(t + 1, p);
    for (let j = a[t - p] + 1; j < k; j++) { a[t] = j; db(t + 1, t); }
  };
  db(1, 1);
  return seq.map((i) => alphabet[i]).join('');
}
async function limitsSuite() {
  const cases = [];
  // the coder outside the chunk domain: context (0, 0) collects 255 followers, then a 256th byte escapes (25 bits)
  const h255 = [0]; for (let x = 1; x <= 254; x++) h255.push(x, 0, 0); h255.push(255);
  cases.push(coderCase('coder_escape_after_255_candidates', h255,
    'longer than a chunk: context (0,0) holds 255 candidates when byte 255 arrives, so its escape costs gamma(256) + 8 = 25 bits'));
  cases.push(coderCase('coder_hit_at_rank_256', [...h255, 0, 0, 255],
    'longer than a chunk: byte 255 again in context (0,0) is a hit at rank 256, gamma(256) = 17 bits'));
  // the chunk domain: at most 241 followers of one context fit in 720 bytes, so a code costs at most 23 bits
  const hub = [0]; for (let x = 1; x <= 240; x++) { hub.push(x); if (x < 240) hub.push(0, 0); }
  hub.push(0);
  if (hub.length !== 720) throw new Error('hub chunk length');
  cases.push(coderCase('chunk_hub_720', hub,
    'a full chunk in which context (0,0) collects 241 followers; within 720 bytes no code exceeds 23 bits (RFC 07 section 6.6)'));
  const DB = deBruijn3('abcdefghi').slice(0, 720);
  cases.push(coderCase('chunk_de_bruijn_720', [...enc.encode(DB)],
    'printable ASCII: the first 720 characters of the order-3 de Bruijn sequence over a..i, a high-cost text chunk'));
  cases.push(coderCase('chunk_one_byte_ff', [0xff]));
  cases.push(coderCase('chunk_720_same_byte', Array(720).fill(0x61)));
  // records of n bytes of a high-cost text, n = 1, 720, 721, 59,760 and 60,000: the expected values are the streams Owl
  // grows. The bound of section 4.4 for n bytes is informative on each: it is arithmetic on the section's formula,
  // which no implementation independent of this file computes (RFC 07 section 15, rule 1).
  const maxRes = (len) => Math.ceil(MAX_BITS_PER_BYTE * len / 8);
  const boundOf = (n) => {
    const K = Math.ceil(n / BM.CHUNK);
    const lens = Array.from({ length: K }, (_, i) => Math.min(BM.CHUNK, n - BM.CHUNK * i));
    return {
      chunks: K, last_chunk_bytes: lens[K - 1], max_bits_per_byte: MAX_BITS_PER_BYTE,
      max_residual_bytes_full_chunk: maxRes(BM.CHUNK),
      max_stream_hex: lens.reduce((a, l) => a + 16 + 8 + 2 * maxRes(l), 0),
      cap_hex: K * (16 + 8 + 2 * maxRes(BM.CHUNK)),
    };
  };
  for (const n of [1, 720, 721, 59760, 60000]) {
    if (n > BM.MAX_GROW_BYTES) throw new Error('grow input');
    const input = { text_parts: [{ repeat: DB, length: n }] };
    const rec = await grow(textOf(input), false);
    const frames = BM.parseBiochainStream(rec.stream);
    const bound = boundOf(n);
    if (frames.length !== bound.chunks || frames[frames.length - 1].chunkLen !== bound.last_chunk_bytes
      || rec.stream.length > bound.max_stream_hex || bound.max_stream_hex > bound.cap_hex) throw new Error(`stream bound (${n})`);
    cases.push({
      id: `grow_de_bruijn_${String(n).padStart(5, '0')}`, input,
      expect: {
        chunks: frames.length, residual_bytes: frames.map((f) => f.residual.length / 2),
        stream_length: rec.stream.length, stream_sha256: sha256hex(rec.stream),
      },
      informative: { stream_hex_per_input_byte: +(rec.stream.length / n).toFixed(4), stream_bound: bound },
    });
  }
  return {
    suite: 'shdccp2_limits',
    description: 'The size limits of a shdccp/2 stream (RFC 07 sections 4.4 and 6.6, P8): the rank coder\'s codes at their '
      + 'largest (25 bits for an escape after 255 candidates, which needs more than one chunk; 23 bits within a 720-byte '
      + 'chunk), the bits used before padding, and the streams of records of 1, 720, 721, 59,760 and 60,000 bytes of a '
      + 'high-cost text. Residuals and streams come from Owl\'s encodeChunk and growBiochain; code lengths from '
      + 'cv_spec.mjs, checked against them. informative.stream_bound is the bound of section 4.4 for the record\'s n '
      + 'bytes (377,016 hex digits for 60,000 bytes; cap_hex, 84 x 4,524 = 380,016, is the bound for any 84 frames): '
      + 'arithmetic on the section\'s formula, which no independent implementation computes, so it is not an expected value.',
    source: [OWL_SOURCE, specSource(['RFC 07 sections 4.4, 6.2, 6.3 and 6.6: the rank coder\'s code lengths'])],
    cases,
  };
}

// ─── suite: merkle_rules_same_bytes (F16) ───────────────────────────────────
async function merkleRulesSuite() {
  const R = (length) => ({ repeat: ASCII_UNIT, length });
  const W = (seed, n) => textParts(randomWords(rngFor(seed), n));
  const sources = [
    ['one_chunk_ascii', { text: 'GEODESIC' }],
    ['one_chunk_latin1', { text: Array.from({ length: 160 }, (_, i) => String.fromCodePoint(0xa0 + i)).join('') }],
    ['one_chunk_720', { text_parts: [R(720)] }],
    ['two_chunks_split_char', { text_parts: [R(719), 'é tail'] }],
    ['two_identical_chunks', { text: 'same'.repeat(360) }],
    ['three_chunks', { text_parts: W(0x3e7c0003, 720 * 2 + 77) }],
    ['four_chunks_emoji', { text_parts: [R(718), '🦉', R(1440 + 9)] }],
    ['five_chunks', { text_parts: W(0x3e7c0005, 720 * 4 + 500) }],
    ['seven_chunks', { text_parts: W(0x3e7c0007, 720 * 6 + 1) }],
    ['eight_chunks', { text_parts: W(0x3e7c0008, 720 * 8) }],
    ['nine_chunks', { text_parts: W(0x3e7c0009, 720 * 8 + 360) }],
  ];
  const cases = [];
  for (const [id, input] of sources) {
    const rec = await grow(textOf(input), false);
    const chunks = BM.recreateChunks(rec);
    const bLeaves = chunks.map((c, i) => SPEC.bioseedLeaf(i, c));
    const rLeaves = chunks.map((c) => SPEC.rfcLeafHash(c).toString('hex'));
    const expect = {
      chunks: chunks.length,
      shdccp2: { leafHashes: rec.leafHashes, merkleRoot: rec.merkleRoot },
      bioseed1: { leafHashes: bLeaves, merkleRoot: SPEC.bioseedRoot(bLeaves) },
      rfc6962: { leafHashes: rLeaves, root: SPEC.rfcTree(chunks).root().toString('hex') },
    };
    const roots = [expect.shdccp2.merkleRoot, expect.bioseed1.merkleRoot, expect.rfc6962.root];
    if (new Set(roots).size !== 3) throw new Error(`two rules gave one root (${id})`);
    cases.push({ id, input, expect });
  }
  return {
    suite: 'merkle_rules_same_bytes',
    description: 'Three leaf and tree rules over the same chunks (RFC 07 sections 7.2-7.5, F16): the chunks are the 720-byte '
      + 'cut of the UTF-8 input (section 3); shdccp2 is Owl\'s growBiochain output, bioseed1 the BIOSEED/1 rule of '
      + 'BioChain-AI protocol/codex_engine.py, rfc6962 the RFC 6962 tree with the raw chunks as entries. The three roots '
      + 'always differ, so a root read under the wrong rule never verifies; records carry no rule tag, so a verifier '
      + 'dispatches on streamVersion.',
    source: [OWL_SOURCE, specSource(['RFC 07 section 7.4: BIOSEED/1 leaves and root', 'RFC 6962 section 2.1: the Merkle Tree Hash'])],
    cases,
  };
}

// ─── suite: rfc6962_lists ───────────────────────────────────────────────────
const CT8 = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'];
const RFC_ENTRIES = [...CT8, ...Array.from({ length: 56 }, (_, i) => (i + 8).toString(16).padStart(8, '0'))];
function rfc6962Suite() {
  const bytesL = RFC_ENTRIES.map((h) => Buffer.from(h, 'hex'));
  const T = SPEC.rfcTree(bytesL);
  const H = (b) => b.toString('hex');
  const cases = [];
  for (let k = 0; k <= 64; k++) cases.push({ id: `root_k_${String(k).padStart(2, '0')}`, input: { entries_hex: RFC_ENTRIES.slice(0, k) }, expect: { root: H(T.root(k)) } });
  const inclusion = (n, m) => {
    const path = T.path(m, n), leaf = SPEC.rfcLeafHash(bytesL[m]), root = T.root(n);
    const valid = SPEC.rfcVerifyInclusion(m, n, leaf, path, root);
    if (!valid) throw new Error('own inclusion proof does not verify');
    return { id: `inclusion_n${String(n).padStart(2, '0')}_m${String(m).padStart(2, '0')}`, input: { op: 'inclusion', entries_hex: RFC_ENTRIES.slice(0, n), index: m }, expect: { leaf_hash: H(leaf), path: path.map(H), root: H(root), valid } };
  };
  for (let n = 1; n <= 8; n++) for (let m = 0; m < n; m++) cases.push(inclusion(n, m));
  for (const [n, ms] of [[17, [0, 7, 15, 16]], [64, [0, 31, 32, 37, 63]]]) for (const m of ms) cases.push(inclusion(n, m));
  const consistency = (m, n) => {
    const proof = T.consistency(m, n), rm = T.root(m), rn = T.root(n);
    const valid = SPEC.rfcVerifyConsistency(m, n, rm, rn, proof);
    if (!valid) throw new Error('own consistency proof does not verify');
    return { id: `consistency_m${String(m).padStart(2, '0')}_n${String(n).padStart(2, '0')}`, input: { op: 'consistency', entries_hex: RFC_ENTRIES.slice(0, n), m }, expect: { root_m: H(rm), root_n: H(rn), proof: proof.map(H), valid } };
  };
  for (const [m, n] of [[1, 1], [1, 2], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8], [6, 8], [7, 8], [8, 8], [2, 3], [3, 7], [4, 7], [6, 7],
    [5, 17], [16, 17], [17, 64], [32, 64], [33, 64], [63, 64], [1, 64]]) cases.push(consistency(m, n));
  // verification with altered inputs (RFC 9162 sections 2.1.3.2 and 2.1.4.2)
  const flip = (b) => { const c = Buffer.from(b); c[0] ^= 1; return c; };
  const vi = (id, index, size, leaf, path, root, note) => {
    const c = { id: `verify_inclusion_${id}`, input: { op: 'verify_inclusion', index, size, leaf_hash: H(leaf), path: path.map(H), root: H(root) }, expect: { valid: SPEC.rfcVerifyInclusion(index, size, leaf, path, root) } };
    if (note) c.note = note;
    return c;
  };
  {
    const n = 7, m = 3, p = T.path(m, n), leaf = SPEC.rfcLeafHash(bytesL[m]), root = T.root(n);
    cases.push(vi('ok', m, n, leaf, p, root));
    cases.push(vi('index_plus_one', m + 1, n, leaf, p, root));
    cases.push(vi('size_plus_one', m, n + 1, leaf, p, root));
    cases.push(vi('size_minus_one', m, n - 1, leaf, p, root));
    cases.push(vi('path_element_flipped', m, n, leaf, [flip(p[0]), ...p.slice(1)], root));
    cases.push(vi('path_truncated', m, n, leaf, p.slice(0, -1), root));
    cases.push(vi('path_extended', m, n, leaf, [...p, p[p.length - 1]], root));
    cases.push(vi('path_swapped', m, n, leaf, [p[1], p[0], ...p.slice(2)], root));
    cases.push(vi('root_of_other_size', m, n, leaf, p, T.root(n - 1)));
    cases.push(vi('index_equals_size', n, n, leaf, p, root));
    cases.push(vi('size_zero', 0, 0, leaf, [], T.root(0)));
    cases.push(vi('leaf_of_other_entry', m, n, SPEC.rfcLeafHash(bytesL[m + 1]), p, root));
    cases.push(vi('leaf_without_prefix', m, n, createHash('sha256').update(bytesL[m]).digest(), p, root,
      'SHA-256 of the entry without the 0x00 prefix is not its leaf hash'));
    const n4 = T.root(4), node01 = SPEC.rfcTree(bytesL.slice(0, 2)).root(), node23 = SPEC.rfcTree(bytesL.slice(2, 4)).root();
    cases.push(vi('node_as_leaf_same_size', 0, 4, node01, [node23], n4,
      'the interior node over entries 0-1 offered as leaf 0 of the 4-entry tree, with a path one level short'));
    cases.push(vi('node_as_leaf_other_size', 0, 2, node01, [node23], n4,
      'the same node and path against the 4-entry root with size 2: the proof checks out, because verification takes the '
      + 'size and the root as given; RFC 07 section 7.5 requires both from one tree head'));
  }
  const vc = (id, m, n, rm, rn, proof, note) => {
    const c = { id: `verify_consistency_${id}`, input: { op: 'verify_consistency', m, n, root_m: H(rm), root_n: H(rn), proof: proof.map(H) }, expect: { valid: SPEC.rfcVerifyConsistency(m, n, rm, rn, proof) } };
    if (note) c.note = note;
    return c;
  };
  for (const [m, n] of [[3, 7], [4, 8]]) {
    const pr = T.consistency(m, n), rm = T.root(m), rn = T.root(n), tag = `m${m}_n${n}`;
    cases.push(vc(`${tag}_ok`, m, n, rm, rn, pr));
    cases.push(vc(`${tag}_swapped_sizes`, n, m, rn, rm, pr));
    cases.push(vc(`${tag}_truncated`, m, n, rm, rn, pr.slice(0, -1)));
    cases.push(vc(`${tag}_extended`, m, n, rm, rn, [...pr, pr[pr.length - 1]]));
    cases.push(vc(`${tag}_element_flipped`, m, n, rm, rn, [flip(pr[0]), ...pr.slice(1)]));
    cases.push(vc(`${tag}_root_m_other`, m, n, T.root(m - 1), rn, pr));
    cases.push(vc(`${tag}_root_n_other`, m, n, rm, T.root(n - 1), pr));
    cases.push(vc(`${tag}_as_m_plus_one`, m + 1, n, T.root(m + 1), rn, pr));
  }
  cases.push(vc('m4_n8_root_m_prepended', 4, 8, T.root(4), T.root(8), [T.root(4), ...T.consistency(4, 8)],
    'm is a power of two, so the verifier prepends root_m itself; a proof that already starts with it does not verify'));
  cases.push(vc('m0_n5', 0, 5, T.root(0), T.root(5), T.consistency(1, 5)));
  cases.push(vc('equal_sizes_empty_proof', 5, 5, T.root(5), T.root(5), []));
  cases.push(vc('equal_sizes_other_root', 5, 5, T.root(5), T.root(6), []));
  cases.push(vc('equal_sizes_nonempty_proof', 5, 5, T.root(5), T.root(5), [T.root(5)]));
  return {
    suite: 'rfc6962_lists',
    description: 'RFC 6962 Merkle trees (RFC 07 section 7.5): roots for K = 0..64 entries, audit paths and consistency proofs '
      + '(RFC 6962 sections 2.1.1 and 2.1.2), and their verification (RFC 9162 sections 2.1.3.2 and 2.1.4.2) on proofs '
      + 'and on altered inputs. The entries are hex byte strings: the first eight are the RFC 6962 test entries used by the '
      + 'certificate-transparency project, entry i >= 8 is i as 4 big-endian bytes. Hashes are lower-case hex.',
    source: [specSource(['RFC 6962 sections 2.1, 2.1.1 and 2.1.2', 'RFC 9162 sections 2.1.3.2 and 2.1.4.2', 'RFC 07 section 7.5'])],
    cases,
  };
}

// ─── suite: attest1_profile (ATTEST/1 and SEAL/1) ───────────────────────────
const N256 = SPEC.P256.n;
const dOfLabel = (label) => BigInt('0x' + createHash('sha256').update(label, 'utf8').digest('hex')) % (N256 - 1n) + 1n;
const hex64 = (v) => v.toString(16).padStart(64, '0');
function findKey(prefix, want) {
  for (let i = 0; i < 100000; i++) { const d = dOfLabel(`${prefix} ${i}`); const j = SPEC.publicJwk(d); if (want(j)) return { d, label: `${prefix} ${i}` }; }
  throw new Error('key search did not finish');
}
const short32 = (b64u) => Buffer.from(b64u, 'base64url')[0] === 0;
async function sigFields(d, jwk, payload, otherPayload, verify) {
  const { r, s } = SPEC.signRfc6979(d, payload);
  const twin = N256 - s;
  const sig = SPEC.p1363(r, s), tw = SPEC.p1363(r, twin);
  const Q = SPEC.jwkPoint(jwk);
  if (!SPEC.verifyEcdsa(Q, payload, r, s) || !SPEC.verifyEcdsa(Q, payload, r, twin)) throw new Error('own verify');
  const verifies = { sig: await verify(jwk, payload, sig), twin: await verify(jwk, payload, tw), other_content: await verify(jwk, otherPayload, sig) };
  if (!verifies.sig || !verifies.twin || verifies.other_content) throw new Error('WebCrypto disagrees with the generator\'s signature');
  return { sig, high_s: SPEC.highS(s), twin: tw, der: SPEC.der(r, s), der_twin: SPEC.der(r, twin), verifies, r, s };
}
async function attestSuite() {
  const cases = [];
  const keys = {
    A: { d: 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721n, label: 'RFC 6979 A.2.5' },
    B: { d: dOfLabel('SHD-CCP-core contract vectors attest1_profile key B'), label: 'SHD-CCP-core contract vectors attest1_profile key B' },
    C: findKey('SHD-CCP-core contract vectors attest1_profile key C', (j) => short32(j.x)),
    D: findKey('SHD-CCP-core contract vectors attest1_profile key D', (j) => short32(j.y)),
  };
  for (const k of Object.values(keys)) {
    k.jwk = SPEC.publicJwk(k.d);
    // WebCrypto must accept the generator's key: a signature made with d verifies under (x, y)
    const priv = await crypto.subtle.importKey('jwk', { ...k.jwk, d: Buffer.from(hex64(k.d), 'hex').toString('base64url') }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, enc.encode('key check'));
    if (!(await BC.verifyPayload(k.jwk, 'key check', Buffer.from(sig).toString('hex')))) throw new Error('generated key rejected by WebCrypto');
  }
  // identities (BioChain-AI computeIdentityId; Owl's cosmologicalId is the same derivation)
  const identities = [
    ['identity_lexicon', 'hyperbolic-lexicon/phase3', 'lexicon'],
    ['identity_trimmed_seed', '  owl academy seed\n', 'uid-0001'],
    ['identity_unicode', 'Straße café 🦉', 'ünïcode-uid'],
    ['identity_empty_seed', ' \t\n ', 'uid-0002'],
  ];
  const ids = {};
  for (const [id, seed, uid] of identities) {
    let expect;
    try { expect = { identityId: (await BC.computeIdentityId(seed, uid)).identityId }; ids[id] = expect.identityId; }
    catch (e) { if (!/seed is empty/.test(e.message)) throw e; expect = { error: 'empty-seed' }; }
    cases.push({ id, input: { op: 'identity', seed, uid }, expect });
  }
  // seeds that start with a character on which ECMAScript's trim (section 13.1) and Python's str.strip differ: the draft
  // suite attest1_profile_open, since the independent implementation strips with str.strip (section 17)
  const openCases = [];
  for (const [id, seed, note] of [
    ['identity_seed_leading_bom', '\ufeffowl academy seed', 'U+FEFF is ECMAScript white space, so trim removes it and the identity is identity_trimmed_seed\'s; Python\'s str.strip keeps it'],
    ['identity_seed_leading_nel', '\u0085owl academy seed', 'U+0085 (NEL) is not ECMAScript white space, so trim keeps it; Python\'s str.strip removes it'],
    ['identity_seed_leading_fs', '\u001cowl academy seed', 'U+001C (FS) is not ECMAScript white space, so trim keeps it; Python\'s str.strip removes it'],
  ]) {
    openCases.push({ id, note, input: { op: 'identity', seed, uid: 'uid-0001' }, expect: { identityId: (await BC.computeIdentityId(seed, 'uid-0001')).identityId } });
  }
  if (openCases[0].expect.identityId !== ids.identity_trimmed_seed || openCases.slice(1).some((c) => c.expect.identityId === ids.identity_trimmed_seed)) {
    throw new Error('computeIdentityId does not trim as ECMAScript String.prototype.trim');
  }
  // RFC 6979's published P-256 / SHA-256 vectors (section A.2.5)
  const ownVerify = (jwk, m, sigHex) => SPEC.verifyEcdsa(SPEC.jwkPoint(jwk), m, BigInt('0x' + sigHex.slice(0, 64)), BigInt('0x' + sigHex.slice(64)));
  for (const msg of ['sample', 'test']) {
    const f = await sigFields(keys.A.d, keys.A.jwk, msg, msg + '.', async (j, m, s) => (await BC.verifyPayload(j, m, s)) && ownVerify(j, m, s));
    const { k } = SPEC.signRfc6979(keys.A.d, msg);
    cases.push({
      id: `rfc6979_a25_${msg}`, note: 'RFC 6979 appendix A.2.5, P-256 with SHA-256',
      input: { op: 'sign_message', d: hex64(keys.A.d), message: msg },
      expect: { publicJwk: keys.A.jwk, sig: f.sig, high_s: f.high_s, twin: f.twin, der: f.der, der_twin: f.der_twin, verifies: { sig: f.verifies.sig, twin: f.verifies.twin } },
      informative: { k: hex64(k).toUpperCase() },
    });
  }
  // commitments: GROWN/1 strings of records Owl grows
  const commitmentOf = async (text) => BM.grownCommitment(await grow(text, true));
  const cGeo = await commitmentOf('GEODESIC'), cOne = await commitmentOf('a');
  // epoch tokens: EPOCH.<window> (BioChain-AI computeEpoch), EPOCH-OFFLINE-<date>, and Owl's SCHU tick tokens
  const NOW = Date.UTC(2026, 10, 7, 12, 0, 0);
  const ep = BEPOCH.computeEpoch({ now: NOW });
  const tickBase = OTICK.computeTick({ now: NOW }), tickKp = OTICK.computeTick({ now: NOW, kp: 5.33 });
  const attestCase = async (id, key, identity, epochToken, commitment, otherCommitment, epochInfo, note) => {
    const k = keys[key], identityId = ids[identity];
    const keyId = await BC.keyIdFromPublic(k.jwk);
    const keyVector = (await BC.deriveKeyVector(identityId, {}, epochToken)).vector64;
    const contentHash = await BC.sha256Hex(commitment);
    const payload = BC.attestationPayload({ keyId, keyVector, contentHash, epochToken });
    const other = BC.attestationPayload({ keyId, keyVector, contentHash: await BC.sha256Hex(otherCommitment), epochToken });
    const f = await sigFields(k.d, k.jwk, payload, other, BC.verifyPayload);
    const lowS = Buffer.from(BC.toLowS(Buffer.from(f.sig, 'hex'))).toString('hex');
    if (lowS !== SPEC.p1363(f.r, f.high_s ? N256 - f.s : f.s)) throw new Error('toLowS');
    const seedUid = identities.find((x) => x[0] === identity);
    const c = {
      id, input: { op: 'attest', d: hex64(k.d), seed: seedUid[1], uid: seedUid[2], epochToken, commitment, other_commitment: otherCommitment },
      expect: { identityId, publicJwk: k.jwk, keyId, keyVector, contentHash, payload, sig: f.sig, high_s: f.high_s, sig_low_s: lowS, twin: f.twin, der: f.der, der_twin: f.der_twin, verifies: f.verifies },
      informative: { key: k.label, ...(epochInfo ? { epoch: epochInfo } : {}) },
    };
    if (note) c.note = note;
    return c;
  };
  const epochInfo = { grammar: 'EPOCH.<window>', now_ms: NOW, computeEpoch_token: ep.token };
  cases.push(await attestCase('attest_key_A_epoch_window', 'A', 'identity_lexicon', ep.token, cGeo, cOne, epochInfo));
  cases.push(await attestCase('attest_key_B_epoch_offline', 'B', 'identity_trimmed_seed', 'EPOCH-OFFLINE-2026-11-07', cGeo, cOne, { grammar: 'EPOCH-OFFLINE-<YYYY-MM-DD>' }));
  cases.push(await attestCase('attest_key_C_short_x', 'C', 'identity_unicode', ep.token, cOne, cGeo, epochInfo,
    'the public x coordinate is below 2^248: its JWK x and the keyId hash its 32-byte, zero-led form'));
  cases.push(await attestCase('attest_key_D_short_y', 'D', 'identity_lexicon', ep.token, cOne, cGeo, epochInfo,
    'the public y coordinate is below 2^248'));
  // signatures whose r or s is below 2^248 (a leading zero byte in r || s, a shorter DER integer)
  for (const [which, test] of [['r', (f) => f.r < (1n << 248n)], ['s', (f) => f.s < (1n << 248n)]]) {
    let found = null;
    for (let i = 0; i < 20000 && !found; i++) {
      const commitment = await commitmentOf(`attest1_profile short ${which} ${i}`);
      const keyId = await BC.keyIdFromPublic(keys.B.jwk);
      const keyVector = (await BC.deriveKeyVector(ids.identity_lexicon, {}, ep.token)).vector64;
      const payload = BC.attestationPayload({ keyId, keyVector, contentHash: await BC.sha256Hex(commitment), epochToken: ep.token });
      if (test(SPEC.signRfc6979(keys.B.d, payload))) found = commitment;
    }
    if (!found) throw new Error('short signature search did not finish');
    cases.push(await attestCase(`attest_key_B_short_${which}`, 'B', 'identity_lexicon', ep.token, found, cGeo, epochInfo,
      `${which} is below 2^248: r || s keeps 32 bytes for each half, the DER integer is shorter`));
  }
  // SEAL/1 (Owl seal-crypto.js) with Owl's tick tokens
  const sealCase = async (id, key, identity, tick, commitment, otherCommitment, kp) => {
    const k = keys[key], cosmologicalId = ids[identity];
    const sealId = await OS.sealIdFromPublic(k.jwk);
    const sealVector = (await OS.deriveSealVector(cosmologicalId, {}, tick.token)).vector64;
    const contentHash = await OS.sha256Hex(commitment);
    const payload = OS.sealContentPayload({ sealId, sealVector, contentHash, tickToken: tick.token });
    const other = OS.sealContentPayload({ sealId, sealVector, contentHash: await OS.sha256Hex(otherCommitment), tickToken: tick.token });
    const f = await sigFields(k.d, k.jwk, payload, other, OS.verifyPayload);
    const seedUid = identities.find((x) => x[0] === identity);
    // The sealId and the payload text are Owl's alone (no implementation independent of seal-crypto.js builds SEAL/1),
    // so the payloads are inputs, the signatures are expected over exactly that text, and the sealId is informative.
    return {
      id, input: { op: 'seal', d: hex64(k.d), seed: seedUid[1], uid: seedUid[2], tickToken: tick.token, commitment, other_commitment: otherCommitment, payload, other_payload: other },
      expect: { cosmologicalId, publicJwk: k.jwk, sealVector, contentHash, sig: f.sig, high_s: f.high_s, twin: f.twin, der: f.der, der_twin: f.der_twin, verifies: f.verifies },
      informative: { sealId, key: k.label, tick: { grammar: 'SCHU.<window>.<freq>.<kp>', now_ms: NOW, kp, computeTick_token: tick.token } },
      note: 'payload and other_payload are the SEAL/1 payloads Owl\'s seal-crypto.js builds from the other inputs (RFC 07 section 13.4), given so that the signatures are checked over exactly that text',
    };
  };
  cases.push(await sealCase('seal_key_A_tick_base', 'A', 'identity_lexicon', tickBase, cGeo, cOne, null));
  cases.push(await sealCase('seal_key_C_tick_kp', 'C', 'identity_unicode', tickKp, cOne, cGeo, 5.33));
  // the registry snapshot text (keyId, public JWK, keyVector, status), sorted by keyId, pinned by its SHA-256
  const kv = async (identity, token) => (await BC.deriveKeyVector(ids[identity], {}, token)).vector64;
  const entry = async (key, identity, token, status) => ({ publicJwk: keys[key].jwk, keyVector: await kv(identity, token), status });
  const snap = async (id, entries, note) => {
    let expect;
    try {
      for (const e of entries) e.keyId = await BC.keyIdFromPublic(e.publicJwk);
      for (const e of entries) if (!['active', 'revoked', 'retired'].includes(e.status)) throw new Error('unknown-status');
      const text = SPEC.snapshotText(entries);
      expect = { snapshot_text: text, snapshot_sha256: sha256hex(text), key_ids: JSON.parse(text).map((e) => e.keyId) };
    } catch (e) {
      if (e.message === 'unknown-status') expect = { error: 'unknown-status' };
      else if (e.message === 'duplicate keyId') expect = { error: 'duplicate-key' };
      else throw e;
    }
    const c = { id, input: { op: 'snapshot', entries: entries.map(({ publicJwk, keyVector, status }) => ({ publicJwk, keyVector, status })) }, expect };
    if (note) c.note = note;
    return c;
  };
  cases.push(await snap('snapshot_three_statuses', [await entry('A', 'identity_lexicon', ep.token, 'active'), await entry('B', 'identity_trimmed_seed', 'EPOCH-OFFLINE-2026-11-07', 'revoked'), await entry('C', 'identity_unicode', ep.token, 'retired')]));
  cases.push(await snap('snapshot_four_keys', [await entry('D', 'identity_lexicon', ep.token, 'active'), await entry('C', 'identity_unicode', ep.token, 'active'), await entry('B', 'identity_lexicon', ep.token, 'active'), await entry('A', 'identity_lexicon', ep.token, 'retired')],
    'entries given out of order; the text sorts them by keyId'));
  cases.push(await snap('snapshot_duplicate_key', [await entry('A', 'identity_lexicon', ep.token, 'active'), await entry('A', 'identity_lexicon', ep.token, 'revoked')]));
  cases.push(await snap('snapshot_unknown_status', [await entry('A', 'identity_lexicon', ep.token, 'recalled')],
    'Owl\'s seal statuses (recalled, archived) are not key statuses'));
  return [{
    suite: 'attest1_profile',
    description: 'The attestation profile (RFC 07 section 13): identities, P-256 public keys as JWK, keyId and sealId '
      + 'fingerprints, ATTEST/1 key vectors over EPOCH.<window> and EPOCH-OFFLINE-<date> tokens, SEAL/1 seal vectors '
      + 'over Owl\'s SCHU tick tokens, the payloads, deterministic signatures (RFC 6979, ECDSA P-256 / SHA-256) as r || s '
      + 'and as DER, each with its high-S twin (r, n - s) flagged and the low-S form BioChain-AI\'s signPayload writes, '
      + 'verification of both twins and of another content, and the registry snapshot text. Identities, key vectors, '
      + 'fingerprints, payloads and low-S forms come from BioChain-AI\'s crypto-core.js (ATTEST/1) and Owl\'s seal-crypto.js '
      + '(SEAL/1); signatures, DER and the snapshot text from cv_spec.mjs, each signature verified by their WebCrypto '
      + 'verifyPayload. A SEAL/1 case gives its payloads as inputs and its sealId as informative: only Owl\'s code builds '
      + 'them. How tokens are derived from a time is informative.',
    source: [pinSource(BIOCHAIN_PIN), pinSource(OWL_TICK_PIN),
      specSource(['RFC 6979 section 3.2 (HMAC-SHA-256)', 'SEC 1 section 4.1 and FIPS 186-4 P-256', 'X.690 DER (SEC 1 Ecdsa-Sig-Value)', 'RFC 7518 section 6.2.1', 'RFC 07 section 13.6'])],
    cases,
  }, {
    suite: 'attest1_profile_open',
    description: 'Draft. Identities (RFC 07 section 13.1) whose seed starts with a character on which ECMAScript\'s '
      + 'String.prototype.trim, which section 13.1 names, and Python\'s str.strip differ: U+FEFF (removed by trim only), '
      + 'U+0085 and U+001C (removed by str.strip only). The expected values are BioChain-AI\'s computeIdentityId; the '
      + 'independent implementation (the Lexicon\'s attest.py, which uses str.strip) gives other identities, so the suite '
      + 'stays draft (RFC 07 section 17).',
    source: [pinSource(BIOCHAIN_PIN)],
    cases: openCases,
  }];
}

// ─── suite: engram1_keys (F114) ─────────────────────────────────────────────
function engramKeysSuite() {
  const texts = [
    ['geodesic_upper', 'GEODESIC'], ['geodesic_lower', 'geodesic'], ['geodesic_mixed', 'GeOdEsIc'],
    ['geodesic_twice', 'Geodesic geodesic'], ['alphabet_lower', 'abcdefghijklmnopqrstuvwxyz'],
    ['alphabet_upper', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'], ['digits_only', '2026'], ['digits_and_letters', 'R2D2'],
    ['apostrophe', "don't"], ['no_apostrophe', 'dont'], ['apostrophes_only', "'''"],
    ['strasse_sharp_s', 'straße'], ['strasse_double_s', 'STRASSE'], ['strasse_title', 'Straße'],
    ['stra_token', 'Stra'], ['e_token', 'e'], ['capital_sharp_s', 'ẞ'], ['cafe', 'café'], ['naive', 'naïve'],
    ['omega', 'Ωmega'], ['cjk', '日本'], ['ligature_fi', 'ﬁle'], ['ligature_st', 'ﬅ'], ['long_s', 'ſ'],
    ['dotless_i', 'ı'], ['dotted_capital_i', 'İ'], ['n_preceded_by_apostrophe', 'ŉ'], ['j_with_caron', 'ǰ'],
    ['kelvin_sign', '\u212a'], ['decomposed_e_acute', 'e\u0301'], ['fullwidth_a', 'ａ'], ['owl_emoji', '🦉'], ['empty', ''],
    ['sentence', "Don't count 42 owls; Straße, café, naïve, GEODESIC."],
  ];
  const cases = [];
  for (const [id, text] of texts) {
    const letters = [...text.toUpperCase()].filter((ch) => /^[A-Z]$/.test(ch)).join('');
    const key = BM.engramGridHex(BM.engramOf(text));
    // the key is the XOR of the letters' grids: check the letters against Owl's own grids
    const acc = new Array(64).fill(0);
    for (const ch of letters) BM.engramGrid(ch).forEach((b, i) => { acc[i] ^= b; });
    if (BM.engramGridHex(acc) !== key || key !== key.toUpperCase() || !/^[0-9A-F]{16}$/.test(key)) throw new Error(`engram key (${id})`);
    cases.push({ id, input: { key_text: text }, expect: { letters, key_hex: key } });
  }
  return {
    suite: 'engram1_keys',
    description: 'The engram/1 key of a string outside a record (RFC 07 section 9.6, F114): Owl\'s engramOf(text) as '
      + 'engramGridHex, the XOR of the grids of the letters A-Z of the string after full Unicode upper-casing '
      + '(String.prototype.toUpperCase, so "ß" counts as "SS"), every other character skipped, written as 16 upper-case hex '
      + 'digits (the canonical form; lower-case hex is not). letters lists those letters in order. Inside a record the '
      + 'tokens are ASCII (section 9.1), so "Straße" contributes "Stra" and "e" there.',
    cases,
  };
}

// ─── suite: rng_mulberry32 (P6) ─────────────────────────────────────────────
function rngSuite() {
  const draws = (seed, n) => { const r = BM.mulberry32(seed); return Array.from({ length: n }, () => r() * 4294967296); };
  const cases = [];
  for (let c = 65; c <= 90; c++) cases.push({ id: `letter_${String.fromCharCode(c)}`, input: { seed: c, draws: 64 }, expect: { u32: draws(c, 64) } });
  for (const [id, seed, note] of [
    ['seed_zero', 0], ['seed_one', 1], ['seed_minus_one', -1, 'int32(-1); the same draws as seed 4294967295'],
    ['seed_int32_max', 2147483647], ['seed_two_pow_31', 2147483648, 'int32(2^31) = -2^31'], ['seed_int32_min', -2147483648],
    ['seed_uint32_max', 4294967295], ['seed_two_pow_32_plus_65', 4294967361, 'int32 wraps it to 65: the same draws as letter_A'],
    ['seed_minus_increment', -1831565813, 'the first state is 0'],
  ]) {
    const c = { id, input: { seed, draws: 16 }, expect: { u32: draws(seed, 16) } };
    if (note) c.note = note;
    cases.push(c);
  }
  return {
    suite: 'rng_mulberry32',
    description: 'mulberry32 (RFC 07 section 9.2, P6), the one generator that enters the contract: 64 draws for each engram/1 '
      + 'letter seed (the code of A..Z, 65..90) and 16 draws for edge seeds (int32 wrap-around, the increment). A draw '
      + 'is u / 2^32; u is given as an unsigned 32-bit integer.',
    cases,
  };
}

// ─── suites: shdccp2_tamper and shdccp2_tamper_open (RFC 07 sections 12.3-12.5) ─────────
// Each case is a value given to a strict verifier: an honest record of shdccp2_record altered in one way, a record
// assembled from other chunks, or a value that is not a record. The expected value is Owl's strict verdict
// (verifyIntegrityStrict at OWL_STRICT_PIN): ok and the first failing check of section 12.3. Its legacy flag is
// informative: the independent verifier has no notion of legacy (section 12.5). This file only
// builds the inputs (with Owl's own codec functions) and states, per case, the check the alteration is meant to
// reach; generation stops when Owl's verdict names another check, so a surprise is never written silently.
// Cases on which the independent oracle (the Lexicon's verifyPackage steps 1-6, verify.py) names another first
// failing check are listed in OPEN_TAMPER and written to the draft suite shdccp2_tamper_open instead (section 12.5).
const OPEN_TAMPER = new Set([
  'packet_lower_case', 'packet_mixed_case', 'residual_upper_case', 'residual_mixed_case', 'length_upper_case',
  'utf8_lead_byte_at_end', 'utf8_overlong', 'utf8_encoded_surrogate', 'utf8_lone_continuation', 'utf8_invalid_across_cut',
]);
const STRICT_SOURCE = pinSource(OWL_STRICT_PIN);
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const word16 = (w) => w.toString(16).toUpperCase().padStart(16, '0');
const withParity = (w) => { w &= ~(1n << 59n); let c = 0n; for (let b = w; b; b >>= 1n) c ^= b & 1n; return w | (c << 59n); };
/** The packet `hex` with f applied to its 64-bit word; the parity bit set again unless keepParityBit. */
const editPacket = (hex, f, keepParityBit = false) => { const w = f(BigInt('0x' + hex)); return word16(keepParityBit ? w : withParity(w)); };
const lenHexOf = (residual) => (residual.length / 2).toString(16).padStart(8, '0');
const framesOf = (stream) => BM.parseBiochainStream(stream).map((f) => ({ packet: f.packet, residual: f.residual }));
const streamOf = (frames) => BM.frameStream(frames.map((f) => f.packet), frames.map((f) => f.residual));
const frameOf = (bytes) => ({ packet: BM.crystallize(bytes), residual: BM.encodeChunk(bytes) });
const rawStream = (frames) => frames.map((f) => f.packet + (f.lenHex || lenHexOf(f.residual)) + f.residual).join('');
const lastDigit = (s) => s.slice(0, -1) + (s.endsWith('0') ? '1' : '0');   // the Lexicon's T3/T8 rule (spike S4)
const firstDigit = (s) => (s[0] === '0' ? '1' : '0') + s.slice(1);
const chunksOfBytes = (data) => { const out = []; for (let i = 0; i < data.length; i += BM.CHUNK) out.push(data.slice(i, i + BM.CHUNK)); return out; };
/** Bit `bit` of a residual flipped; bit 0 is the most significant bit of its first byte (the coder's bit order). */
function flipResidualBit(hex, bit) {
  const at = bit >> 3, v = parseInt(hex.slice(2 * at, 2 * at + 2), 16) ^ (0x80 >> (bit & 7));
  return hex.slice(0, 2 * at) + v.toString(16).padStart(2, '0') + hex.slice(2 * at + 2);
}
/** The first single-bit flip of frame i's residual that decodes to the same chunk, inside an escape code
 *  (kind 'escape') or in the zero padding after the last code (kind 'padding'), or null. */
function silentFlip(frames, chunks, i, kind) {
  const res = frames[i].residual, codes = SPEC.codeBits(chunks[i]);
  const used = codes.reduce((a, c) => a + c.bits, 0);
  const inEscape = (bit) => { let at = 0; for (const c of codes) { if (bit < at + c.bits) return c.escape && bit < at + c.bits - 8; at += c.bits; } return false; };
  for (let bit = 0; bit < res.length * 4; bit++) {
    if (kind === 'padding' ? bit < used : !inEscape(bit)) continue;
    const alt = flipResidualBit(res, bit);
    let back;
    try { back = BM.decodeChunk(alt, chunks[i].length); } catch { continue; }
    if (back.length === chunks[i].length && back.every((b, j) => b === chunks[i][j])) return { bit, residual: alt };
  }
  return null;
}
/** A record assembled from bytes with Owl's functions, engrams off: what growBiochain gives for the text whose UTF-8
 *  they are. It also takes bytes that are not UTF-8, which no grow produces (checked against growBiochain below). */
function recordOfBytes(data) {
  const chunks = chunksOfBytes(data), k = chunks.length;
  const stream = streamOf(chunks.map(frameOf));
  const leafHashes = chunks.map((c, i) => CORE.leafHashSync(i, c));
  const merkleRoot = CORE.merkleRootSync(leafHashes);
  const { weaveChiral, weaveMirror } = CORE.chainWeaves(chunks);
  const ship = stream.length / 2 + k * 32 + 40;
  return {
    chainId: 'BC-' + CORE.sha256HexSync(merkleRoot + '|' + weaveChiral).slice(0, 24), stream, streamVersion: CORE.STREAM_VERSION,
    leafHashes, merkleRoot, weaveChiral, weaveMirror,
    segCuts: Array.from({ length: BM.SEGMENTS + 1 }, (_, i) => Math.round(i * k / BM.SEGMENTS)), segments: BM.SEGMENTS,
    origBytes: data.length, shippedBytes: Math.round(ship), value: +(data.length / ship).toFixed(4),
  };
}

async function tamperSuites() {
  // honest records: shdccp2_record's inputs, grown as that suite grows them
  const base = {};
  for (const id of ['ascii_1441', 'tokens_mixed', 'x80_single_chunk', 'leading_bom', 'split_4byte_at_720']) {
    const t = recordText(id);
    const rec = await grow(t.text, t.engrams);
    // the strict core grows the same record (its codec is biomesh.js's, moved), and its verifier accepts it
    if (JSON.stringify(await CORE.growBiochain(t.text, { engrams: t.engrams })) !== JSON.stringify(rec)) throw new Error(`biomesh-core.js grows another record (${id})`);
    if (!CORE.verifyIntegrityStrict(clone(rec)).ok) throw new Error(`the strict verifier rejects the honest record ${id}`);
    base[id] = { rec, text: t.text, frames: framesOf(rec.stream), chunks: BM.recreateChunks(rec) };
  }
  for (const id of ['ascii_1441', 'geodesic_no_engrams', 'ascii_1440', 'max_60000_words']) {
    const t = recordText(id);
    if (JSON.stringify(recordOfBytes([...enc.encode(t.text)])) !== JSON.stringify(await grow(t.text, false))) throw new Error(`recordOfBytes differs from growBiochain (${id})`);
  }
  const B3 = base.ascii_1441, BE = base.tokens_mixed, BX = base.x80_single_chunk;
  const K3 = B3.frames.length;
  if (K3 !== 3 || B3.chunks[0].length !== 720 || B3.chunks[1].length !== 720 || B3.frames[0].residual === B3.frames[1].residual) throw new Error('ascii_1441 is not three chunks, the first two full and different');
  if (B3.rec.engramStream !== undefined || BE.rec.engramStream === undefined || BE.frames.length !== 1) throw new Error('base records');

  const cases = [];
  // add(id, note, value, want, {base, lax}): `value` is given to the verifiers; `want` is the check the alteration is
  // meant to fail first (null for an honest record); lax false skips Owl's verifyIntegrity, which does not return on
  // some streams.
  const add = async (id, note, value, want, opt = {}) => {
    const v = CORE.verifyIntegrityStrict(clone(value));
    const wantFailed = want === null ? null : want.replace(/^legacy:/, '');
    const wantLegacy = want !== null && want.startsWith('legacy:');
    if (v.failed !== wantFailed || v.legacy !== wantLegacy || v.ok !== (want === null)) {
      throw new Error(`${id}: Owl's strict verifier gives ${JSON.stringify({ ok: v.ok, failed: v.failed, legacy: v.legacy })}, the case is built for ${want}`);
    }
    const informative = { legacy: v.legacy };
    if (opt.base) informative.base = `shdccp2_record/${opt.base}`;
    const fc = CORE.failedCheck(v);
    if (fc) { informative.owl_detail = fc.detail; if (fc.fields) informative.owl_fields = fc.fields; }
    let lax;
    if (opt.lax !== false) {
      try { lax = (await BM.verifyIntegrity(clone(value))).ok; } catch { lax = false; }
      informative.self_consistent = lax;
    }
    informative.label = CORE.strictLabel(v, lax);
    cases.push({ id, note, input: { record: value }, expect: { ok: v.ok, failed: v.failed }, informative });
  };
  const r3 = () => clone(B3.rec), re = () => clone(BE.rec);
  const fr3 = () => clone(B3.frames);
  const with3 = (frames) => ({ ...r3(), stream: streamOf(frames) });
  const withRaw3 = (frames) => ({ ...r3(), stream: rawStream(frames) });
  const B = { base: 'ascii_1441' }, BEO = { base: 'tokens_mixed' };

  // honest records: every verifier accepts them
  for (const id of Object.keys(base)) {
    const notes = { leading_bom: 'the text starts with U+FEFF, which strict decoding keeps (RFC 07 section 12.1)',
      split_4byte_at_720: 'a four-byte character split by the 720-byte cut; the bytes are well-formed as a whole',
      x80_single_chunk: 'a packet with a 0x80 crystal byte, raw rule (section 5.4)' };
    await add(`honest_${id}`, notes[id] || 'an honest record', clone(base[id].rec), null, { base: id });
  }

  // ---- parity: legacy records, values that are not records, the strict stream form, packet parity
  {
    const r = r3(); delete r.stream; delete r.streamVersion;
    r.streams = B3.frames.map((f) => f.residual); r.chunkLens = B3.chunks.map((c) => c.length);
    await add('legacy_streams', 'a pre-stream record: parallel streams (residuals) and chunkLens, no stream or streamVersion', r, 'legacy:parity', B);
  }
  { const r = r3(); delete r.streamVersion; await add('streamversion_missing', 'streamVersion removed', r, 'legacy:parity', B); }
  await add('streamversion_unknown', 'streamVersion "shdccp/3"', { ...r3(), streamVersion: 'shdccp/3' }, 'legacy:parity', B);
  await add('streamversion_upper_case', 'streamVersion "SHDCCP/2"', { ...r3(), streamVersion: 'SHDCCP/2' }, 'legacy:parity', B);
  { const r = r3(); delete r.stream; await add('stream_missing', 'stream removed, streamVersion kept', r, 'legacy:parity', B); }
  await add('stream_not_string', 'the stream as a one-element array', { ...r3(), stream: [B3.rec.stream] }, 'legacy:parity', B);
  await add('not_a_record_null', 'null instead of a record', null, 'parity');
  await add('not_a_record_array', 'an array holding the record', [r3()], 'parity');
  await add('not_a_record_string', 'the stream string instead of a record', B3.rec.stream, 'parity');
  await add('stream_empty', 'an empty stream: no frame', { ...r3(), stream: '' }, 'parity', B);
  await add('stream_truncated_residual', 'the last two hex digits of the stream removed: the last residual is short', { ...r3(), stream: B3.rec.stream.slice(0, -2) }, 'parity', B);
  await add('stream_truncated_header', 'a frame header cut after 20 of its 24 characters appended', { ...r3(), stream: B3.rec.stream + B3.rec.stream.slice(0, 20) }, 'parity', B);
  await add('trailing_bytes', 'one byte (two hex digits) after the last frame', { ...r3(), stream: B3.rec.stream + '00' }, 'parity', B);
  {
    const f = fr3(); const i = f[0].residual.search(/[0-9]/);
    f[0].residual = f[0].residual.slice(0, i) + 'g' + f[0].residual.slice(i + 1);
    await add('residual_not_hex', 'a residual digit replaced by "g"', withRaw3(f), 'parity', B);
  }
  { const f = fr3(); f[1].packet = f[1].packet.slice(0, 15) + 'G'; await add('packet_not_hex', 'the last digit of packet 1 replaced by "G"', withRaw3(f), 'parity', B); }
  { const f = fr3(); f[0].lenHex = 'z' + lenHexOf(f[0].residual).slice(1); await add('length_not_hex', 'the first digit of residual length 0 replaced by "z"', withRaw3(f), 'parity', B); }
  {
    const f = fr3(); f[0].lenHex = '-000000c';
    await add('length_negative', 'residual length 0 written "-000000c", which a lenient parseInt reads as -12: a lenient parser '
      + 'returns to the frame start (self_consistent is left out: Owl\'s verifyIntegrity does not return on it)', withRaw3(f), 'parity', { ...B, lax: false });
  }
  { const f = fr3(); f[K3 - 1].lenHex = (f[K3 - 1].residual.length / 2 + 1).toString(16).padStart(8, '0'); await add('length_plus_one', 'the last residual length one more than its residual', withRaw3(f), 'parity', B); }
  { const f = fr3(); f[1].packet = editPacket(f[1].packet, (w) => w ^ (1n << 59n), true); await add('parity_bit_flipped', 'the parity bit of packet 1 flipped', with3(f), 'parity', B); }
  {
    const f = fr3(); f[0].packet = editPacket(f[0].packet, (w) => w ^ (1n << 30n), true);
    await add('crystal_bit_parity_not_fixed', 'a crystal bit of packet 0 flipped, parity not set again (T2 without its parity fix)', with3(f), 'parity', B);
  }

  // ---- canonical: the 720-byte cut, the 60,000-byte limit, canonical residuals, well-formed UTF-8
  {
    const d = B3.chunks.flat();
    await add('cut_719_middle', 'the same 1,441 bytes framed as 720, 719 and 2 bytes: a 719-byte middle frame',
      with3([frameOf(d.slice(0, 720)), frameOf(d.slice(720, 1439)), frameOf(d.slice(1439))]), 'canonical', B);
    await add('cut_1_720_720', 'the same 1,441 bytes framed as 1, 720 and 720 bytes',
      with3([frameOf(d.slice(0, 1)), frameOf(d.slice(1, 721)), frameOf(d.slice(721))]), 'canonical', B);
    await add('cut_empty_last_frame', 'a frame of 0 bytes (payload16 0, empty residual) after the last frame', with3([...fr3(), frameOf([])]), 'canonical', B);
  }
  {
    const d = [...enc.encode(recordText('error_60001').text)];
    await add('over_60000_bytes', 'the 60,001 bytes of shdccp2_record/error_60001 framed as 83 frames of 720 bytes and one of 241',
      with3(chunksOfBytes(d).map(frameOf)), 'canonical', B);
  }
  for (const kind of ['escape', 'padding']) {
    let hit = null, i = 0;
    for (; i < K3 && !hit; i++) hit = silentFlip(B3.frames, B3.chunks, i, kind);
    if (!hit) throw new Error(`no silent ${kind} flip`);
    const f = fr3(); f[i - 1].residual = hit.residual;
    await add(`T9_${kind}_flip`, `T9: bit ${hit.bit} of residual ${i - 1} flipped; it decodes to the same chunk (${kind === 'escape' ? 'inside the rank code of an escape' : 'a padding bit after the last code'})`,
      with3(f), 'canonical', B);
  }
  { const f = fr3(); f[K3 - 1].residual += '00'; await add('residual_extra_zero_byte', 'a zero byte after the last residual, its length raised by one', with3(f), 'canonical', B); }
  { const f = fr3(); f[0].residual = f[0].residual.slice(0, -2); await add('residual_short_byte', 'residual 0 one byte short, its length lowered by one', with3(f), 'canonical', B); }
  { const f = fr3(); f[0].residual = '0'.repeat(f[0].residual.length); await add('residual_zeroed', 'residual 0 replaced by zero bytes of the same length', with3(f), 'canonical', B); }
  {
    for (const [id, d] of [['payload_one_less', -1n], ['payload_one_more', 1n]]) {
      const f = clone(BE.frames);
      f[0].packet = editPacket(f[0].packet, (w) => (w & ~(0xFFFFn << 8n)) | ((((w >> 8n) & 0xFFFFn) + d) << 8n));
      await add(id, `payload16 of the only packet ${d < 0n ? 'one less' : 'one more'} than its chunk, parity set again`, { ...re(), stream: streamOf(f) }, 'canonical', BEO);
    }
  }

  // ---- crystal: each packet against crystallize(chunk), raw rule
  { const f = fr3(); f[K3 - 1].packet = editPacket(f[K3 - 1].packet, (w) => w ^ (1n << 55n)); await add('T2_crystal_last_packet_bit31', 'T2: bit 31 of the last packet\'s crystal32 flipped, parity set again', with3(f), 'crystal', B); }
  { const f = fr3(); f[0].packet = editPacket(f[0].packet, (w) => w ^ (1n << 24n)); await add('T2_crystal_packet0_bit0', 'T2: bit 0 of packet 0\'s crystal32 flipped, parity set again', with3(f), 'crystal', B); }
  { const f = fr3(); f[0].packet = editPacket(f[0].packet, (w) => w ^ 1n); await add('csum_amp_bit', 'the lowest checksum bit (amp) of packet 0 flipped, parity set again', with3(f), 'crystal', B); }
  { const f = fr3(); f[1].packet = editPacket(f[1].packet, (w) => w ^ (1n << 3n)); await add('csum_freq_bit', 'the lowest freq bit of packet 1 flipped, parity set again', with3(f), 'crystal', B); }
  { const f = fr3(); f[0].packet = editPacket(f[0].packet, (w) => (w & ~(0xFn << 60n)) | (8n << 60n)); await add('form_changed', 'the form of packet 0 written 8 instead of 9, parity set again', with3(f), 'crystal', B); }
  { const f = fr3(); f[0].packet = editPacket(f[0].packet, (w) => w | (1n << 56n)); await add('spin_changed', 'spin 1 in packet 0, parity set again', with3(f), 'crystal', B); }
  { const f = fr3(); [f[0].packet, f[1].packet] = [f[1].packet, f[0].packet]; await add('packets_swapped', 'the packets of frames 0 and 1 swapped, the residuals in place', with3(f), 'crystal', B); }
  {
    const f = clone(BX.frames), j = f.findIndex((x) => x80Slots(crystal32Of(x.packet)).length);
    const slot = x80Slots(crystal32Of(f[j].packet))[0], shift = BigInt(24 + CRYSTAL_BYTE[slot]);
    f[j].packet = editPacket(f[j].packet, (w) => w ^ (1n << shift));   // 0x80 -> 0x81
    await add('kernel_normalized_0x80', `the 0x80 crystal byte (slot ${slot}) written 0x81, as the kernel normalisation would, parity set again`,
      { ...clone(BX.rec), stream: streamOf(f) }, 'crystal', { base: 'x80_single_chunk' });
  }

  // ---- leaves: leafHashes mandatory, K entries, each equal; merkleRoot present and equal
  { const r = r3(); delete r.leafHashes; delete r.merkleRoot; await add('T1_no_leaves_no_root', 'T1: leafHashes and merkleRoot removed', r, 'leaves', B); }
  { const r = r3(); delete r.leafHashes; await add('leafhashes_missing', 'leafHashes removed', r, 'leaves', B); }
  { const r = r3(); delete r.merkleRoot; await add('merkleroot_missing', 'merkleRoot removed', r, 'leaves', B); }
  await add('merkleroot_null', 'merkleRoot null', { ...r3(), merkleRoot: null }, 'leaves', B);
  { const r = r3(); r.leafHashes.push(r.leafHashes[K3 - 1]); await add('extra_leaf', 'the last leaf repeated at the end of leafHashes', r, 'leaves', B); }
  { const r = r3(); r.leafHashes.pop(); await add('leaf_missing', 'the last leaf removed from leafHashes', r, 'leaves', B); }
  { const r = r3(); r.leafHashes[1] = firstDigit(r.leafHashes[1]); await add('leaf_changed', 'the first digit of leaf 1 changed', r, 'leaves', B); }
  { const r = r3(); r.leafHashes[0] = r.leafHashes[0].toUpperCase(); await add('leaf_upper_case', 'leaf 0 in upper-case hex', r, 'leaves', B); }
  await add('merkleroot_changed', 'the first digit of merkleRoot changed', { ...r3(), merkleRoot: firstDigit(B3.rec.merkleRoot) }, 'leaves', B);
  {
    const bl = B3.chunks.map((c, i) => SPEC.bioseedLeaf(i, c));
    await add('merkleroot_bioseed1', 'merkleRoot replaced by the BIOSEED/1 root of the same chunks (section 7.4)', { ...r3(), merkleRoot: SPEC.bioseedRoot(bl) }, 'leaves', B);
  }
  { const f = fr3(); [f[0], f[1]] = [f[1], f[0]]; await add('frames_swapped', 'frames 0 and 1 swapped (both 720 bytes)', with3(f), 'leaves', B); }

  // ---- weaves: weaveChiral, weaveMirror, segCuts, segments, chainId
  await add('T8_chainid_last_digit', 'T8: the last digit of chainId changed', { ...r3(), chainId: lastDigit(B3.rec.chainId) }, 'weaves', B);
  await add('chainid_upper_case', 'chainId in upper-case hex', { ...r3(), chainId: 'BC-' + B3.rec.chainId.slice(3).toUpperCase() }, 'weaves', B);
  { const r = r3(); delete r.chainId; await add('chainid_missing', 'chainId removed', r, 'weaves', B); }
  await add('weavemirror_changed', 'the last digit of weaveMirror changed', { ...r3(), weaveMirror: lastDigit(B3.rec.weaveMirror) }, 'weaves', B);
  await add('weavemirror_is_chiral', 'weaveMirror replaced by weaveChiral', { ...r3(), weaveMirror: B3.rec.weaveChiral }, 'weaves', B);
  await add('weavechiral_changed', 'the last digit of weaveChiral changed', { ...r3(), weaveChiral: lastDigit(B3.rec.weaveChiral) }, 'weaves', B);
  { const r = r3(); r.segCuts[7] += 1; await add('segcuts_changed', 'the last segment cut one more', r, 'weaves', B); }
  await add('segcuts_strings', 'segCuts as strings', { ...r3(), segCuts: B3.rec.segCuts.map(String) }, 'weaves', B);
  { const r = r3(); r.segCuts.pop(); await add('segcuts_seven', 'the last segment cut removed', r, 'weaves', B); }
  await add('segments_8', 'segments 8', { ...r3(), segments: 8 }, 'weaves', B);
  await add('segments_string', 'segments as the string "7"', { ...r3(), segments: '7' }, 'weaves', B);
  { const r = r3(); delete r.segments; await add('segments_missing', 'segments removed', r, 'weaves', B); }

  // ---- derived: the engram fields, origBytes, shippedBytes, value
  await add('engramstream_changed', 'the first digit of the engram stream changed', { ...re(), engramStream: firstDigit(BE.rec.engramStream) }, 'derived', BEO);
  await add('engramstream_lower_case', 'the engram stream in lower-case hex', { ...re(), engramStream: BE.rec.engramStream.toLowerCase() }, 'derived', BEO);
  await add('engramcount_plus_one', 'engramCount one more', { ...re(), engramCount: BE.rec.engramCount + 1 }, 'derived', BEO);
  await add('engrammeanj_changed', 'engramMeanJ plus 0.0001', { ...re(), engramMeanJ: BE.rec.engramMeanJ + 0.0001 }, 'derived', BEO);
  { const r = re(); delete r.engramStream; await add('engramstream_missing', 'engramStream removed, engramCount and engramMeanJ kept', r, 'derived', BEO); }
  {
    const r = re(); delete r.engramStream; delete r.engramCount; delete r.engramMeanJ;
    await add('engram_layer_removed', 'all three engram fields removed: shippedBytes and value still count the engram stream', r, 'derived', BEO);
  }
  await add('engram_field_added', 'engramCount 0 added to a record grown without engrams', { ...r3(), engramCount: 0 }, 'derived', B);
  await add('origbytes_plus_one', 'origBytes one more', { ...r3(), origBytes: B3.rec.origBytes + 1 }, 'derived', B);
  await add('origbytes_string', 'origBytes as a string', { ...r3(), origBytes: String(B3.rec.origBytes) }, 'derived', B);
  await add('shippedbytes_minus_one', 'shippedBytes one less', { ...r3(), shippedBytes: B3.rec.shippedBytes - 1 }, 'derived', B);
  await add('value_changed', 'value plus 0.0001', { ...r3(), value: B3.rec.value + 0.0001 }, 'derived', B);
  await add('value_string', 'value as a string', { ...r3(), value: String(B3.rec.value) }, 'derived', B);

  // ---- open: hex case (section 4.3) and ill-formed UTF-8 (section 12.1, step 2)
  {
    const f = fr3(); f[0].packet = f[0].packet.toLowerCase();
    if (f[0].packet === B3.frames[0].packet) throw new Error('packet 0 has no letter');
    await add('packet_lower_case', 'packet 0 in lower-case hex', withRaw3(f), 'parity', B);
  }
  const letterAt = (s, re) => { const i = s.search(re); if (i < 0) throw new Error('no letter to change case'); return i; };
  { const f = fr3(); const i = letterAt(f[1].packet, /[A-F]/); f[1].packet = f[1].packet.slice(0, i) + f[1].packet[i].toLowerCase() + f[1].packet.slice(i + 1); await add('packet_mixed_case', 'one letter of packet 1 in lower case', withRaw3(f), 'parity', B); }
  { const f = fr3(); letterAt(f[0].residual, /[a-f]/); f[0].residual = f[0].residual.toUpperCase(); await add('residual_upper_case', 'residual 0 in upper-case hex', withRaw3(f), 'parity', B); }
  { const f = fr3(); const i = letterAt(f[1].residual, /[a-f]/); f[1].residual = f[1].residual.slice(0, i) + f[1].residual[i].toUpperCase() + f[1].residual.slice(i + 1); await add('residual_mixed_case', 'one letter of residual 1 in upper case', withRaw3(f), 'parity', B); }
  {
    const bid = Object.keys(base).find((id) => base[id].frames.some((x) => /[a-f]/.test(lenHexOf(x.residual))));
    if (!bid) throw new Error('no residual length with a letter');
    const f = clone(base[bid].frames), j = f.findIndex((x) => /[a-f]/.test(lenHexOf(x.residual)));
    f[j].lenHex = lenHexOf(f[j].residual).toUpperCase();
    await add('length_upper_case', `residual length ${j} in upper-case hex`, { ...clone(base[bid].rec), stream: rawStream(f) }, 'parity', { base: bid });
  }
  const bad = (pre, mid, post) => [...enc.encode(pre), ...mid, ...enc.encode(post)];
  for (const [id, note, d] of [
    ['utf8_lead_byte_at_end', 'the bytes end with 0xC3, the first byte of a two-byte character', bad('The owl reads the chain ', [0xc3], '')],
    ['utf8_overlong', 'the overlong form C0 AF of "/"', bad('path ', [0xc0, 0xaf], ' end')],
    ['utf8_encoded_surrogate', 'ED A0 80, the UTF-8 form of the surrogate U+D800', bad('pair ', [0xed, 0xa0, 0x80], ' end')],
    ['utf8_lone_continuation', 'a continuation byte 0x80 at the start', bad('', [0x80], ' start')],
    ['utf8_invalid_across_cut', 'byte 719 is 0xC3 and byte 720, the first of chunk 1, is "a": invalid across the cut', bad(ASCII_UNIT.repeat(14).slice(0, 719), [0xc3], 'a tail')],
  ]) {
    await add(id, `${note}; every other field is computed from these bytes (engrams off)`, recordOfBytes(d), 'canonical');
  }

  const open = cases.filter((c) => OPEN_TAMPER.has(c.id));
  if (open.length !== OPEN_TAMPER.size) throw new Error('an open tamper case is missing');
  const common = 'Owl\'s strict verdict (verifyIntegrityStrict, scripts/biomesh-core.js at the pinned O3 commit) for a value given '
    + 'to a strict verifier (RFC 07 sections 12.3 and 12.4): ok and the first failing check (parity, canonical, crystal, '
    + 'leaves, weaves, derived). Values are honest shdccp2_record records altered in one way (informative.base), records '
    + 'assembled from other chunks or bytes with Owl\'s codec functions, and values that are not records. informative '
    + 'gives Owl\'s legacy flag (informative because the independent verifier has no notion of legacy), Owl\'s detail, '
    + 'the self-consistency check of section 12.2 (Owl\'s verifyIntegrity at the generator\'s pin) and the label of '
    + 'section 12.4.';
  return [{
    suite: 'shdccp2_tamper',
    description: common + ' The independent verifier (the Lexicon\'s verifyPackage, steps 1-6) gives the same verdict on every case.',
    source: [OWL_SOURCE, STRICT_SOURCE],
    cases: cases.filter((c) => !OPEN_TAMPER.has(c.id)),
  }, {
    suite: 'shdccp2_tamper_open',
    description: common + ' Draft: the independent verifier gives another verdict on these cases (RFC 07 section 12.5 lists them); '
      + 'the expected values are RFC 07\'s.',
    source: [OWL_SOURCE, STRICT_SOURCE],
    cases: open,
  }];
}

// ─── envelope, serialisation, write / check ─────────────────────────────────
function loadLock() {
  const p = join(CV, 'lock.json');
  return existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : { normative: {} };
}

function envelope(s, lock) {
  return {
    suite: s.suite, spec_version: SPEC_VERSION, rfc: RFC, wire: WIRE,
    status: lock.normative && lock.normative[s.suite] ? 'normative' : 'draft',
    description: s.description,
    generator: 'contract_vectors/tools/generate.mjs',
    source: s.source || OWL_SOURCE,
    license: 'CC0-1.0',
    cases: s.cases,
  };
}

function serialise(env) {
  const head = Object.entries(env).filter(([k]) => k !== 'cases').map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`);
  const ids = new Set();
  for (const c of env.cases) { if (ids.has(c.id)) throw new Error(`duplicate case id ${env.suite}/${c.id}`); ids.add(c.id); }
  // U+FEFF and U+0085 are written as JSON escapes so inputs that hold them stay visible in the file (same value)
  const line = (c) => '    ' + JSON.stringify(c).replace(/﻿/g, '\\ufeff').replace(/\u0085/g, '\\u0085');
  return '{\n' + head.join(',\n') + ',\n  "cases": [\n' + env.cases.map(line).join(',\n') + '\n  ]\n}\n';
}

const builders = [packetSuite, chunkSuite, merkleSuite, arithSuite, weaveSuite, engramSuite, recordSuite,
  limitsSuite, merkleRulesSuite, rfc6962Suite, attestSuite, engramKeysSuite, rngSuite, tamperSuites];
const lock = loadLock();
const out = new Map();
for (const b of builders) {
  const t0 = Date.now();
  const built = await b();
  for (const s of Array.isArray(built) ? built : [built]) {
    out.set(`${s.suite}.json`, serialise(envelope(s, lock)));
    if (process.env.CV_VERBOSE) console.error(`${s.suite}: ${s.cases.length} cases, ${Date.now() - t0} ms`);
  }
}

if (mode === 'write') {
  mkdirSync(SUITES_DIR, { recursive: true });
  for (const f of readdirSync(SUITES_DIR)) if (!out.has(f)) { console.error(`unknown file in suites/: ${f} (remove it by hand)`); process.exitCode = 1; }
  for (const [f, text] of out) writeFileSync(join(SUITES_DIR, f), text);
  let n = 0; for (const t of out.values()) n += JSON.parse(t).cases.length;
  console.log(`wrote ${out.size} suites, ${n} cases`);
} else {
  const problems = [];
  for (const e of readdirSync(CV)) if (!TOP_LEVEL.includes(e)) problems.push(`unknown entry contract_vectors/${e}`);
  const have = existsSync(SUITES_DIR) ? readdirSync(SUITES_DIR) : [];
  for (const f of have) {
    if (statSync(join(SUITES_DIR, f)).isDirectory() || !out.has(f)) { problems.push(`unknown file contract_vectors/suites/${f}`); continue; }
    if (readFileSync(join(SUITES_DIR, f), 'utf8') !== out.get(f)) problems.push(`stale file contract_vectors/suites/${f} (regenerate with --write)`);
  }
  for (const f of out.keys()) if (!have.includes(f)) problems.push(`missing file contract_vectors/suites/${f}`);
  if (problems.length) { for (const p of problems) console.error('DRIFT ' + p); process.exit(1); }
  let n = 0; for (const t of out.values()) n += JSON.parse(t).cases.length;
  console.log(`drift check ok: ${out.size} suites, ${n} cases, generated from ${OWL_PIN.repository}@${OWL_PIN.commit.slice(0, 7)}`
    + ` (strict verifier @${OWL_STRICT_PIN.commit.slice(0, 7)})`);
}
