// SPDX-License-Identifier: CC0-1.0
// Part of contract_vectors/ (CC0-1.0, see ../LICENSE). Written for SHD-CCP-core from the specifications cited below;
// it contains no code from Owl-Academy, BioChain-AI, Ebayednoob or any other implementation.
//
// The generator's own implementations ("cv-generate-mjs" in lock.json), for the values that Owl's reference code does
// not compute:
//   - codeBits: the length of each code of the rank coder (RFC 07 sections 6.2, 6.3), so a vector can state the bits
//     used before padding and the largest code; generate.mjs checks them against Owl's encodeChunk;
//   - BIOSEED/1 leaves and root (RFC 07 section 7.4);
//   - RFC 6962 tree hashes, audit paths and consistency proofs (RFC 6962 sections 2.1, 2.1.1, 2.1.2) and their
//     verification (RFC 9162 sections 2.1.3.2 and 2.1.4.2, with RFC 07 section 7.5's rule for m = n);
//   - ECDSA on P-256 with SHA-256 (SEC 1 section 4.1, FIPS 186-4 curve P-256), deterministic nonces (RFC 6979
//     section 3.2 with HMAC-SHA-256), public keys as JWK coordinates (RFC 7518 section 6.2.1), signatures as IEEE P1363
//     r || s and as DER (X.690, SEC 1 Ecdsa-Sig-Value);
//   - the registry snapshot text (RFC 07 section 13.6).
// SHA-256 and HMAC come from node:crypto. Big-integer arithmetic uses BigInt.

import { createHash, createHmac } from 'node:crypto';

const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const hex = (buf) => Buffer.from(buf).toString('hex');

// ─── the rank coder's code lengths (RFC 07 section 6) ───────────────────────
const gammaBits = (m) => 2 * (32 - Math.clz32(m)) - 1;   // Elias gamma of m >= 1: (w - 1) zeros, then w bits

/** The length in bits of the code of each byte of `bytes`, with the candidates each code saw and whether it escaped. */
export function codeBits(bytes) {
  const tables = new Map();
  let p1 = 0, p2 = 0;
  const out = [];
  for (const b of bytes) {
    const ctx = p1 * 256 + p2;
    let counts = tables.get(ctx);
    if (!counts) { counts = new Map(); tables.set(ctx, counts); }
    const cands = [...counts.keys()].sort((x, y) => counts.get(y) - counts.get(x) || x - y);
    const rank = cands.indexOf(b);
    out.push(rank >= 0
      ? { bits: gammaBits(rank + 1), candidates: cands.length, escape: false }
      : { bits: gammaBits(cands.length + 1) + 8, candidates: cands.length, escape: true });
    counts.set(b, (counts.get(b) || 0) + 1);
    p1 = p2; p2 = b;
  }
  return out;
}

// ─── BIOSEED/1 (RFC 07 section 7.4) ─────────────────────────────────────────
const u32be = (i) => { const b = Buffer.alloc(4); b.writeUInt32BE(i); return b; };
export const bioseedLeaf = (i, chunk) => hex(sha256(u32be(i), sha256(Buffer.from(chunk))));
export function bioseedRoot(leavesHex) {
  let level = leavesHex.map((h) => Buffer.from(h, 'hex'));
  if (level.length === 0) return '00'.repeat(32);
  while (level.length > 1) {
    if (level.length % 2) level.push(level[level.length - 1]);
    const next = [];
    for (let j = 0; j < level.length; j += 2) next.push(sha256(level[j], level[j + 1]));
    level = next;
  }
  return hex(level[0]);
}

// ─── RFC 6962 trees (RFC 6962 section 2.1) ──────────────────────────────────
const B0 = Buffer.from([0]), B1 = Buffer.from([1]);
export const rfcLeafHash = (entry) => sha256(B0, Buffer.from(entry));
const rfcNode = (l, r) => sha256(B1, l, r);
const splitK = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };   // largest power of two below n (n >= 2)

/** MTH over entries (arrays of bytes); memoised per [lo, hi). Returns a function mth(lo, hi) -> Buffer. */
export function rfcTree(entries) {
  const memo = new Map();
  const mth = (lo, hi) => {
    const key = lo * 65536 + hi;
    if (memo.has(key)) return memo.get(key);
    let v;
    if (hi === lo) v = sha256(Buffer.alloc(0));
    else if (hi - lo === 1) v = rfcLeafHash(entries[lo]);
    else { const k = splitK(hi - lo); v = rfcNode(mth(lo, lo + k), mth(lo + k, hi)); }
    memo.set(key, v);
    return v;
  };
  // PATH(m, D[lo:hi]) (section 2.1.1)
  const path = (m, lo, hi) => {
    if (hi - lo === 1) return [];
    const k = splitK(hi - lo);
    return m < k ? [...path(m, lo, lo + k), mth(lo + k, hi)] : [...path(m - k, lo + k, hi), mth(lo, lo + k)];
  };
  // SUBPROOF(m, D[lo:hi], b) (section 2.1.2)
  const subproof = (m, lo, hi, b) => {
    const n = hi - lo;
    if (m === n) return b ? [] : [mth(lo, hi)];
    const k = splitK(n);
    return m <= k ? [...subproof(m, lo, lo + k, b), mth(lo + k, hi)] : [...subproof(m - k, lo + k, hi, false), mth(lo, lo + k)];
  };
  return {
    root: (n = entries.length) => mth(0, n),
    path: (m, n = entries.length) => { if (!(m >= 0 && m < n)) throw new Error('no audit path'); return path(m, 0, n); },
    consistency: (m, n = entries.length) => { if (!(m > 0 && m <= n)) throw new Error('no consistency proof'); return subproof(m, 0, n, true); },
  };
}

/** RFC 9162 section 2.1.3.2: does `proof` show that leafHash is entry `index` of the tree of `size` with `root`? */
export function rfcVerifyInclusion(index, size, leafHash, proof, root) {
  if (!(index >= 0 && index < size)) return false;
  let fn = BigInt(index), sn = BigInt(size - 1), r = Buffer.from(leafHash);
  for (const p of proof) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = rfcNode(p, r);
      if ((fn & 1n) === 0n) while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else r = rfcNode(r, p);
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n && r.equals(Buffer.from(root));
}

/** RFC 9162 section 2.1.4.2 for 0 < m < n; for m = n, RFC 07 section 7.5: valid iff the proof is empty and the roots
 *  are equal. */
export function rfcVerifyConsistency(m, n, rootM, rootN, proof) {
  if (!(m >= 1 && m <= n)) return false;
  if (m === n) return proof.length === 0 && Buffer.from(rootM).equals(Buffer.from(rootN));
  if (proof.length === 0) return false;
  const path = (m & (m - 1)) === 0 ? [Buffer.from(rootM), ...proof] : [...proof];
  let fn = BigInt(m - 1), sn = BigInt(n - 1);
  while ((fn & 1n) === 1n) { fn >>= 1n; sn >>= 1n; }
  let fr = Buffer.from(path[0]), sr = Buffer.from(path[0]);
  for (const c of path.slice(1)) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      fr = rfcNode(c, fr); sr = rfcNode(c, sr);
      if ((fn & 1n) === 0n) while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else sr = rfcNode(sr, c);
    fn >>= 1n; sn >>= 1n;
  }
  return fr.equals(Buffer.from(rootM)) && sr.equals(Buffer.from(rootN)) && sn === 0n;
}

// ─── P-256 (FIPS 186-4 D.1.2.3) ─────────────────────────────────────────────
export const P256 = Object.freeze({
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
});
const mod = (x, m) => { const r = x % m; return r < 0n ? r + m : r; };
function inv(x, m) {           // extended Euclid
  let [a, b, u, v] = [mod(x, m), m, 1n, 0n];
  while (b !== 0n) { const q = a / b; [a, b] = [b, a - q * b]; [u, v] = [v, u - q * v]; }
  if (a !== 1n) throw new Error('not invertible');
  return mod(u, m);
}
// Jacobian coordinates (X, Y, Z) for x = X/Z^2, y = Y/Z^3; Z = 0 is the point at infinity
const INF = [0n, 1n, 0n];
function jDouble([X, Y, Z]) {
  const { p, a } = P256;
  if (Z === 0n || Y === 0n) return INF;
  const YY = mod(Y * Y, p), S = mod(4n * X * YY, p), Z2 = mod(Z * Z, p);
  const M = mod(3n * X * X + a * Z2 * Z2, p);
  const X3 = mod(M * M - 2n * S, p);
  return [X3, mod(M * (S - X3) - 8n * YY * YY, p), mod(2n * Y * Z, p)];
}
function jAdd(P, Q) {
  const { p } = P256;
  if (P[2] === 0n) return Q;
  if (Q[2] === 0n) return P;
  const [X1, Y1, Z1] = P, [X2, Y2, Z2] = Q;
  const Z1Z1 = mod(Z1 * Z1, p), Z2Z2 = mod(Z2 * Z2, p);
  const U1 = mod(X1 * Z2Z2, p), U2 = mod(X2 * Z1Z1, p);
  const S1 = mod(Y1 * Z2 * Z2Z2, p), S2 = mod(Y2 * Z1 * Z1Z1, p);
  if (U1 === U2) return S1 === S2 ? jDouble(P) : INF;
  const H = mod(U2 - U1, p), R = mod(S2 - S1, p), HH = mod(H * H, p), HHH = mod(H * HH, p);
  const X3 = mod(R * R - HHH - 2n * U1 * HH, p);
  return [X3, mod(R * (U1 * HH - X3) - S1 * HHH, p), mod(H * Z1 * Z2, p)];
}
function toAffine([X, Y, Z]) {
  const { p } = P256;
  if (Z === 0n) throw new Error('point at infinity');
  const zi = inv(Z, p), zi2 = mod(zi * zi, p);
  return [mod(X * zi2, p), mod(Y * zi2 * zi, p)];
}
export function mulG(k, P = [P256.Gx, P256.Gy]) {
  let R = INF, A = [P[0], P[1], 1n];
  for (let e = k; e > 0n; e >>= 1n) { if (e & 1n) R = jAdd(R, A); A = jDouble(A); }
  return R[2] === 0n ? null : toAffine(R);
}
const onCurve = ([x, y]) => mod(y * y - (x * x * x + P256.a * x + P256.b), P256.p) === 0n;

const be32 = (v) => Buffer.from(v.toString(16).padStart(64, '0'), 'hex');
const intOf = (buf) => BigInt('0x' + (Buffer.from(buf).toString('hex') || '0'));

/** The public key of d as JWK coordinates (base64url of the 32-byte big-endian x and y). */
export function publicJwk(d) {
  const Q = mulG(d);
  if (!Q || !onCurve(Q)) throw new Error('bad public key');
  return { kty: 'EC', crv: 'P-256', x: be32(Q[0]).toString('base64url'), y: be32(Q[1]).toString('base64url') };
}
export const jwkPoint = (jwk) => [intOf(Buffer.from(jwk.x, 'base64url')), intOf(Buffer.from(jwk.y, 'base64url'))];

/** RFC 6979 section 3.2 nonce for private key d and message hash h1 (32 bytes), qlen = hlen = 256. Returns the
 *  candidates in order (a generator: the caller takes the first that gives r != 0 and s != 0). */
function* rfc6979Nonces(d, h1) {
  const { n } = P256;
  const hmac = (key, ...parts) => { const m = createHmac('sha256', key); for (const p of parts) m.update(p); return m.digest(); };
  const x = be32(d), h = be32(mod(intOf(h1), n));          // int2octets(x), bits2octets(h1)
  let V = Buffer.alloc(32, 1), K = Buffer.alloc(32, 0);
  K = hmac(K, V, Buffer.from([0]), x, h); V = hmac(K, V);
  K = hmac(K, V, Buffer.from([1]), x, h); V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);                                          // tlen = qlen = 256: one block
    const k = intOf(V);
    if (k >= 1n && k < n) yield k;
    K = hmac(K, V, Buffer.from([0])); V = hmac(K, V);
  }
}

/** Deterministic ECDSA P-256 / SHA-256 over the UTF-8 of `message`: {k, r, s} as BigInt (s as computed, not
 *  normalised). */
export function signRfc6979(d, message) {
  const { n } = P256;
  const h1 = sha256(Buffer.from(message, 'utf8'));
  const e = intOf(h1);
  for (const k of rfc6979Nonces(d, h1)) {
    const R = mulG(k);
    const r = mod(R[0], n);
    if (r === 0n) continue;
    const s = mod(inv(k, n) * (e + r * d), n);
    if (s === 0n) continue;
    return { k, r, s };
  }
  throw new Error('unreachable');
}

/** ECDSA verification (SEC 1 section 4.1.4) of (r, s) over the UTF-8 of `message` with the public point Q. */
export function verifyEcdsa(Q, message, r, s) {
  const { n } = P256;
  if (!(r >= 1n && r < n && s >= 1n && s < n) || !onCurve(Q)) return false;
  const e = intOf(sha256(Buffer.from(message, 'utf8')));
  const w = inv(s, n);
  const X = (() => {
    const A = mulG(mod(e * w, n)), B = mulG(mod(r * w, n), Q);
    if (!A) return B; if (!B) return A;
    const S = jAdd([A[0], A[1], 1n], [B[0], B[1], 1n]);
    return S[2] === 0n ? null : toAffine(S);
  })();
  return X !== null && mod(X[0], n) === r;
}

export const p1363 = (r, s) => be32(r).toString('hex') + be32(s).toString('hex');
export const highS = (s) => s > P256.n / 2n;           // s > (n - 1) / 2, n odd
const derInt = (v) => {
  let h = v.toString(16);
  if (h.length % 2) h = '0' + h;
  if (parseInt(h.slice(0, 2), 16) >= 0x80) h = '00' + h;
  return '02' + (h.length / 2).toString(16).padStart(2, '0') + h;
};
/** DER Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } (every length here is below 128: short form). */
export const der = (r, s) => { const body = derInt(r) + derInt(s); return '30' + (body.length / 2).toString(16).padStart(2, '0') + body; };

// ─── the registry snapshot text (RFC 07 section 13.6) ───────────────────────
export function snapshotText(entries) {
  const rows = entries.map((e) => ({ keyId: e.keyId, publicJwk: { kty: e.publicJwk.kty, crv: e.publicJwk.crv, x: e.publicJwk.x, y: e.publicJwk.y }, keyVector: e.keyVector, status: e.status }));
  rows.sort((a, b) => (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0));
  for (let i = 1; i < rows.length; i++) if (rows[i].keyId === rows[i - 1].keyId) throw new Error('duplicate keyId');
  return JSON.stringify(rows);
}
