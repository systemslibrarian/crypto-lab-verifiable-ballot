import { exp, gpow, isElement, isScalar, mul, type Group } from '../group/modp';
import type { Ciphertext } from '../elgamal/exp';
import { decryptionChallenge } from './challenge';

/**
 * The VERIFIER for a decryption factor (separate from cp.ts): checks
 *   (a) g^f = A · X^c     (b) R^f = B · T^c     (c) c = H(…)
 * with every element in the subgroup.
 */
export interface DecryptionProofLike {
  readonly A: bigint;
  readonly B: bigint;
  readonly c: bigint;
  readonly f: bigint;
}

export function verifyDecryption(G: Group, X: bigint, ct: Ciphertext, T: bigint, pf: DecryptionProofLike, context: string): { ok: boolean; failures: string[] } {
  const failures: string[] = [];
  for (const [n, v] of [['X', X], ['R', ct.R], ['S', ct.S], ['T', T], ['A', pf.A], ['B', pf.B]] as const) {
    if (!isElement(G, v)) failures.push(`${n} is not an element of the order-q subgroup`);
  }
  if (!isScalar(G, pf.c) || !isScalar(G, pf.f)) failures.push('c or f is not a scalar in [0, q)');
  if (failures.length) return { ok: false, failures };
  if (gpow(G, pf.f) !== mul(G, pf.A, exp(G, X, pf.c))) failures.push('equation (a) g^f = A·X^c fails');
  if (exp(G, ct.R, pf.f) !== mul(G, pf.B, exp(G, T, pf.c))) failures.push('equation (b) R^f = B·T^c fails');
  if (decryptionChallenge(G, context, X, ct, T, pf.A, pf.B) !== pf.c) failures.push('equation (c) the challenge does not match');
  return { ok: failures.length === 0, failures };
}
