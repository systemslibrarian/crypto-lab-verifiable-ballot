import { DOMAIN, hashToScalar } from '../group/hash';
import type { Group } from '../group/modp';
import type { Ciphertext } from '../elgamal/exp';

/**
 * The 0/1 proof's Fiat–Shamir challenge, in the two forms Bernhard, Pereira and
 * Warinschi (2012) distinguish.
 *
 *  strong: c = H(domain, "zero-one", election context, g, X, R, S, A0, B0, A1, B1)
 *          — the statement (key and ciphertext) and the election are hashed. The default.
 *  weak:   c = H(A0, B0, A1, B1) — only the commitments, as Helios hashed them
 *          (BPW Appendix B, step 3: "neither the actual ciphertext (R, S) nor the
 *          election public key is hashed"). BROKEN; used only in the exhibit that shows why.
 *
 * Helios hashed decimal strings with SHA-1; this lab uses its own length-prefixed
 * encoding and SHA-256 for both forms. What matters is which values go in.
 */
export type FsMode = 'strong' | 'weak';

export interface Commitments {
  readonly A0: bigint;
  readonly B0: bigint;
  readonly A1: bigint;
  readonly B1: bigint;
}

export function zeroOneChallenge(G: Group, mode: FsMode, context: string, X: bigint, ct: Ciphertext, k: Commitments): bigint {
  if (mode === 'weak') return hashToScalar(G, [k.A0, k.B0, k.A1, k.B1]);
  return hashToScalar(G, [DOMAIN, 'zero-one', context, G.g, X, ct.R, ct.S, k.A0, k.B0, k.A1, k.B1]);
}

/** Decryption proof challenge: always strong, and — unlike Helios's — it includes X (BPW §4 caveat). */
export function decryptionChallenge(G: Group, context: string, X: bigint, ct: Ciphertext, T: bigint, A: bigint, B: bigint): bigint {
  return hashToScalar(G, [DOMAIN, 'decrypt', context, G.g, X, ct.R, ct.S, T, A, B]);
}
