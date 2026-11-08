#!/usr/bin/env node
// SPDX-License-Identifier: CC0-1.0
// Part of contract_vectors/ (CC0-1.0, see ../LICENSE).
//
// The single generator of the RFC 07 contract vectors (contract_vectors/suites/*.json).
//
// Every expected value comes from Owl-Academy's own scripts/biomesh.js at the pinned commit, loaded read-only by
// owl_namegrab.mjs, and from the V8 built-ins that code calls (Math.hypot, Number.prototype.toFixed). This file
// only chooses inputs (fixed lists and seeded searches whose results are stored as explicit inputs), calls Owl's
// functions and writes the results. Where it combines Owl's functions itself (the weave intermediates), it asserts
// that the combination reproduces Owl's own growBiochain output.
//
// Usage:
//   node contract_vectors/tools/generate.mjs [--owl DIR] --write    regenerate suites/ in place
//   node contract_vectors/tools/generate.mjs [--owl DIR] --check    drift check: fail on a stale, missing or unknown
//                                                                   file in suites/, or an unknown top-level entry
// DIR defaults to $OWL_ACADEMY_DIR, then ../Owl-Academy beside this repository. Only the git object store of DIR is
// read (git show <pinned commit>:<path>); its working tree is never touched.

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { loadOwl, OWL_PIN } from './owl_namegrab.mjs';

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
if (!mode) { console.error('usage: generate.mjs [--owl DIR] (--write | --check)'); process.exit(2); }
const OWL_DIR = resolve(owlArg || process.env.OWL_ACADEMY_DIR || join(REPO, '..', 'Owl-Academy'));
if (!existsSync(OWL_DIR)) {
  console.error(`Owl-Academy not found at ${OWL_DIR}; pass --owl DIR or set OWL_ACADEMY_DIR`);
  process.exit(2);
}

const { BM, SC } = await loadOwl(OWL_DIR);

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

async function recordSuite() {
  const R = (length) => ({ repeat: ASCII_UNIT, length });
  const inputs = [
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
    source: { repository: OWL_PIN.repository, commit: OWL_PIN.commit, files: { ...OWL_PIN.files }, license: OWL_PIN.license, engine: 'V8' },
    license: 'CC0-1.0',
    cases: s.cases,
  };
}

function serialise(env) {
  const head = Object.entries(env).filter(([k]) => k !== 'cases').map(([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`);
  const ids = new Set();
  for (const c of env.cases) { if (ids.has(c.id)) throw new Error(`duplicate case id ${env.suite}/${c.id}`); ids.add(c.id); }
  // U+FEFF is written as the JSON escape ﻿ so the leading_bom input stays visible in the file (same value)
  const line = (c) => '    ' + JSON.stringify(c).replace(/﻿/g, '\\ufeff');
  return '{\n' + head.join(',\n') + ',\n  "cases": [\n' + env.cases.map(line).join(',\n') + '\n  ]\n}\n';
}

const builders = [packetSuite, chunkSuite, merkleSuite, arithSuite, weaveSuite, engramSuite, recordSuite];
const lock = loadLock();
const out = new Map();
for (const b of builders) {
  const t0 = Date.now();
  const s = await b();
  out.set(`${s.suite}.json`, serialise(envelope(s, lock)));
  if (process.env.CV_VERBOSE) console.error(`${s.suite}: ${s.cases.length} cases, ${Date.now() - t0} ms`);
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
  console.log(`drift check ok: ${out.size} suites, ${n} cases, generated from ${OWL_PIN.repository}@${OWL_PIN.commit.slice(0, 7)}`);
}
