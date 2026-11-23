import { div, exp, gpow, isElement, isScalar, modq, mul, type Group } from '../group/modp';
import type { Ciphertext } from '../elgamal/exp';
import { zeroOneChallenge, type FsMode } from './challenge';

/**
 * The VERIFIER for the 0/1 proof — written separately from the prover (invariant 2).
 * It checks the five equations of BPW Appendix B:
 *   (1) g^f0 = A0 · R^c0      (2) g^f1 = A1 · R^c1
 *   (3) X^f0 = B0 · S^c0      (4) X^f1 = B1 · (S/g)^c1
 *   (5) c0 + c1 = H(…)  (mod q)
 * after checking that every group element lies in the order-q subgroup and every
 * scalar is in [0, q).
 */
export interface ProofLike {
  readonly A0: bigint;
  readonly B0: bigint;
  readonly A1: bigint;
  readonly B1: bigint;
  readonly c0: bigint;
  readonly c1: bigint;
  readonly f0: bigint;
  readonly f1: bigint;
}

export interface Verdict {
  readonly ok: boolean;
  /** The equation numbers (1–5) that hold, and any structural failure. */
  readonly holds: readonly number[];
  readonly failures: readonly string[];
}

export function verifyZeroOne(G: Group, X: bigint, ct: Ciphertext, pf: ProofLike, context: string, mode: FsMode = 'strong'): Verdict {
  const failures: string[] = [];
  for (const [n, v] of [['X', X], ['R', ct.R], ['S', ct.S], ['A0', pf.A0], ['B0', pf.B0], ['A1', pf.A1], ['B1', pf.B1]] as const) {
    if (!isElement(G, v)) failures.push(`${n} is not an element of the order-q subgroup`);
  }
  for (const [n, v] of [['c0', pf.c0], ['c1', pf.c1], ['f0', pf.f0], ['f1', pf.f1]] as const) {
    if (!isScalar(G, v)) failures.push(`${n} is not a scalar in [0, q)`);
  }
  if (failures.length) return { ok: false, holds: [], failures };
  const eq = [
    gpow(G, pf.f0) === mul(G, pf.A0, exp(G, ct.R, pf.c0)),
    gpow(G, pf.f1) === mul(G, pf.A1, exp(G, ct.R, pf.c1)),
    exp(G, X, pf.f0) === mul(G, pf.B0, exp(G, ct.S, pf.c0)),
    exp(G, X, pf.f1) === mul(G, pf.B1, exp(G, div(G, ct.S, G.g), pf.c1)),
    modq(G, pf.c0 + pf.c1) === zeroOneChallenge(G, mode, context, X, ct, pf),
  ];
  const holds = eq.flatMap((ok, i) => (ok ? [i + 1] : []));
  for (let i = 0; i < 5; i++) if (!eq[i]) failures.push(`equation (${i + 1}) fails`);
  return { ok: failures.length === 0, holds, failures };
}
