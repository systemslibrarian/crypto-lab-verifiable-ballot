/**
 * The group: RFC 5114 §2.3, "2048-bit MODP Group with 256-bit Prime Order
 * Subgroup". p is a 2048-bit prime, q a 256-bit prime dividing p − 1, and g
 * generates the subgroup of order q. Every element that crosses a module boundary
 * is checked to lie in that subgroup (x^q ≡ 1 mod p, 1 ≤ x < p) before it is used.
 *
 * Helios used a 2048-bit p with a 256-bit q of the same shape; these are the IETF's
 * published parameters, checked in the tests against the RFC's Appendix A.3 vector.
 */
export interface Group {
  readonly name: string;
  readonly p: bigint;
  readonly q: bigint;
  readonly g: bigint;
}

export const RFC5114_2048_256: Group = {
  name: 'RFC 5114 §2.3 (2048-bit p, 256-bit q)',
  p: 0x87a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a1597n,
  g: 0x3fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc41659n,
  q: 0x8cf83642a709a097b447997640129da299b1a47d1eb3750ba308b0fe64f5fbd3n,
};

export function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  if (e < 0n) throw new RangeError('negative exponent');
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    if (e > 0n) b = (b * b) % mod;
  }
  return result;
}

/** Modular inverse by the extended Euclidean algorithm. */
export function modinv(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const qt = oldR / r;
    [oldR, r] = [r, oldR - qt * r];
    [oldS, s] = [s, oldS - qt * s];
  }
  if (oldR !== 1n) throw new RangeError('not invertible');
  return ((oldS % m) + m) % m;
}

export const mul = (G: Group, a: bigint, b: bigint): bigint => (a * b) % G.p;
export const div = (G: Group, a: bigint, b: bigint): bigint => (a * modinv(b, G.p)) % G.p;
export const exp = (G: Group, b: bigint, e: bigint): bigint => modpow(b, ((e % G.q) + G.q) % G.q, G.p);
export const gpow = (G: Group, e: bigint): bigint => exp(G, G.g, e);
export const modq = (G: Group, a: bigint): bigint => ((a % G.q) + G.q) % G.q;

/** Subgroup membership: 1 ≤ x < p and x^q ≡ 1 (mod p). */
export function isElement(G: Group, x: bigint): boolean {
  return typeof x === 'bigint' && x >= 1n && x < G.p && modpow(x, G.q, G.p) === 1n;
}

export function isScalar(G: Group, s: bigint): boolean {
  return typeof s === 'bigint' && s >= 0n && s < G.q;
}

/** Structural checks that are cheap enough to run on every page load. Primality is checked in the unit tests. */
export function validateGroup(G: Group): string[] {
  const problems: string[] = [];
  if (G.p.toString(2).length !== 2048) problems.push('p is not 2048 bits');
  if (G.q.toString(2).length !== 256) problems.push('q is not 256 bits');
  if ((G.p - 1n) % G.q !== 0n) problems.push('q does not divide p − 1');
  if (G.g <= 1n || G.g >= G.p) problems.push('g is out of range');
  if (modpow(G.g, G.q, G.p) !== 1n) problems.push('g does not have order q');
  return problems;
}

/** A source of random bytes. The page uses crypto.getRandomValues; tests inject a seeded one. */
export type ByteSource = (n: number) => Uint8Array;
export const cryptoBytes: ByteSource = (n) => crypto.getRandomValues(new Uint8Array(n));

export function bytesToBig(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

/** A uniform scalar in [0, q), by rejection sampling 32 random bytes. */
export function randomScalar(G: Group, bytes: ByteSource): bigint {
  for (;;) {
    const v = bytesToBig(bytes(32));
    if (v < G.q) return v;
  }
}
