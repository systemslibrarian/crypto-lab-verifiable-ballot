import { gpow, modinv, modq, mul, exp, randomScalar, type ByteSource, type Group } from '../group/modp';
import type { Ciphertext } from '../elgamal/exp';
import { zeroOneChallenge } from '../proofs/challenge';
import type { ZeroOneProof } from '../proofs/orproof';

/**
 * Bernhard, Pereira and Warinschi, "How not to Prove Yourself", ASIACRYPT 2012, §3
 * ("Disjunctive Chaum-Pedersen Proofs", Application to Helios). BROKEN MODE.
 *
 * With the WEAK challenge c = H(A0, B0, A1, B1), corrupt trustees can pick the
 * election key AFTER seeing the challenge, and then build a ciphertext that encrypts
 * any m together with a proof that passes as "0 or 1":
 *   1. a0, b0, a1, b1 ← Z_q;  A0 = g^a0, B0 = g^b0, A1 = g^a1, B1 = g^b1;  c = H(A0, B0, A1, B1)
 *   2. x = [(b0 + c·m)(1 − m) − b1·m] / [a0(1 − m) − a1·m],  X = g^x
 *   3. r ← Z_q;  (R, S) = (g^r, g^m · X^r)
 *   4. c1 = (b1 − a1·x)/(1 − m),  c0 = c − c1,  f0 = a0 + c0·r,  f1 = a1 + c1·r
 * Re-derived here: equation (3) needs x·a0 − c0·m = b0 and equation (4) needs
 * x·a1 − c1·(m − 1) = b1; solving both with c0 + c1 = c gives the x and c1 above.
 * With the STRONG challenge X, R and S are inside the hash, so x cannot be chosen after c.
 */
export interface Forgery {
  readonly x: bigint;
  readonly X: bigint;
  readonly ct: Ciphertext;
  readonly proof: ZeroOneProof;
  readonly m: bigint;
}

export function forgeWeak(G: Group, m: bigint, bytes: ByteSource): Forgery {
  if (m === 1n) throw new RangeError('m = 1 is an honest value; the construction divides by 1 − m');
  for (;;) {
    const [a0, b0, a1, b1] = [0, 1, 2, 3].map(() => randomScalar(G, bytes));
    const A0 = gpow(G, a0);
    const B0 = gpow(G, b0);
    const A1 = gpow(G, a1);
    const B1 = gpow(G, b1);
    // The weak challenge depends on the commitments only, so it can be computed before X and the ciphertext exist.
    const c = zeroOneChallenge(G, 'weak', '', 0n, { R: 0n, S: 0n }, { A0, B0, A1, B1 });
    const oneMinusM = modq(G, 1n - m);
    const den = modq(G, a0 * oneMinusM - a1 * modq(G, m));
    if (den === 0n) continue;
    const x = modq(G, (modq(G, (b0 + c * m) * oneMinusM) - b1 * m) * modinv(den, G.q));
    const X = gpow(G, x);
    const r = randomScalar(G, bytes);
    const ct = { R: gpow(G, r), S: mul(G, gpow(G, m), exp(G, X, r)) };
    const c1 = modq(G, (b1 - a1 * x) * modinv(oneMinusM, G.q));
    const c0 = modq(G, c - c1);
    const proof = { A0, B0, A1, B1, c0, c1, f0: modq(G, a0 + c0 * r), f1: modq(G, a1 + c1 * r) };
    return { x, X, ct, proof, m };
  }
}
