import { div, exp, gpow, isElement, mul, randomScalar, type ByteSource, type Group } from '../group/modp';

/**
 * Exponential ElGamal: Enc(v; r) = (R, S) = (g^r, g^v · X^r). Multiplying ciphertexts
 * component by component adds the plaintexts, which is what makes a homomorphic tally
 * possible; decryption yields g^v, so v is recovered by a small search.
 */
export interface Ciphertext {
  readonly R: bigint;
  readonly S: bigint;
}

export interface KeyPair {
  readonly x: bigint;
  readonly X: bigint;
}

export function keygen(G: Group, bytes: ByteSource): KeyPair {
  const x = randomScalar(G, bytes);
  return { x, X: gpow(G, x) };
}

export function encrypt(G: Group, X: bigint, v: bigint, r: bigint): Ciphertext {
  return { R: gpow(G, r), S: mul(G, gpow(G, v), exp(G, X, r)) };
}

export function isCiphertext(G: Group, c: Ciphertext): boolean {
  return isElement(G, c.R) && isElement(G, c.S);
}

/** Homomorphic sum: the component-wise product of the ciphertexts. */
export function addAll(G: Group, cts: readonly Ciphertext[]): Ciphertext {
  let R = 1n;
  let S = 1n;
  for (const c of cts) {
    R = mul(G, R, c.R);
    S = mul(G, S, c.S);
  }
  return { R, S };
}

/** The trustee's decryption factor T = R^x. */
export function decryptionFactor(G: Group, x: bigint, c: Ciphertext): bigint {
  return exp(G, c.R, x);
}

/** Recover t from g^t = S / T by trying t = 0 … max. Returns null if no t ≤ max works. */
export function recoverSmall(G: Group, c: Ciphertext, T: bigint, max: number): number | null {
  const target = div(G, c.S, T);
  let acc = 1n;
  for (let t = 0; t <= max; t++) {
    if (acc === target) return t;
    acc = mul(G, acc, G.g);
  }
  return null;
}
