import { div, exp, gpow, modq, randomScalar, type ByteSource, type Group } from '../group/modp';
import type { Ciphertext } from '../elgamal/exp';
import { zeroOneChallenge, type FsMode } from './challenge';

/**
 * The PROVER for "this ciphertext encrypts 0 or 1" — the disjunctive Chaum–Pedersen
 * proof exactly as Helios builds it (BPW Appendix B; the OR construction of Cramer,
 * Damgård and Schoenmakers, CRYPTO 1994). For the true value v it proves honestly;
 * for the other value w = 1 − v it simulates, choosing (c_w, f_w) first.
 *
 * The verifier is a separate module (orverify.ts) that does not import this one.
 */
export interface ZeroOneProof {
  readonly A0: bigint;
  readonly B0: bigint;
  readonly A1: bigint;
  readonly B1: bigint;
  readonly c0: bigint;
  readonly c1: bigint;
  readonly f0: bigint;
  readonly f1: bigint;
}

export class ProverRefusal extends Error {}

export function proveZeroOne(
  G: Group,
  X: bigint,
  ct: Ciphertext,
  v: bigint,
  r: bigint,
  context: string,
  bytes: ByteSource,
  mode: FsMode = 'strong',
): ZeroOneProof {
  if (v !== 0n && v !== 1n) throw new ProverRefusal(`an honest prover cannot prove that an encryption of ${v} is 0 or 1`);
  const w = 1n - v;
  // Simulated branch w: pick (c_w, f_w), then A_w = g^f_w / R^c_w, B_w = X^f_w / (S / g^w)^c_w.
  const cw = randomScalar(G, bytes);
  const fw = randomScalar(G, bytes);
  const Aw = div(G, gpow(G, fw), exp(G, ct.R, cw));
  const Bw = div(G, exp(G, X, fw), exp(G, div(G, ct.S, gpow(G, w)), cw));
  // Real branch v: A_v = g^a, B_v = X^a.
  const a = randomScalar(G, bytes);
  const Av = gpow(G, a);
  const Bv = exp(G, X, a);
  const k = v === 0n ? { A0: Av, B0: Bv, A1: Aw, B1: Bw } : { A0: Aw, B0: Bw, A1: Av, B1: Bv };
  const c = zeroOneChallenge(G, mode, context, X, ct, k);
  const cv = modq(G, c - cw);
  const fv = modq(G, a + cv * r);
  return v === 0n ? { ...k, c0: cv, c1: cw, f0: fv, f1: fw } : { ...k, c0: cw, c1: cv, f0: fw, f1: fv };
}
