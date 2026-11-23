import { exp, gpow, modq, randomScalar, type ByteSource, type Group } from '../group/modp';
import type { Ciphertext } from '../elgamal/exp';
import { decryptionChallenge } from './challenge';

/**
 * The PROVER for a correct decryption factor: Chaum–Pedersen equality of discrete
 * logs, log_g(X) = log_R(T) = x. Helios 2008 §2 proves decryptions this way.
 * a ← Z_q, A = g^a, B = R^a, c = H(…, X, R, S, T, A, B), f = a + c·x.
 */
export interface DecryptionProof {
  readonly A: bigint;
  readonly B: bigint;
  readonly c: bigint;
  readonly f: bigint;
}

export function proveDecryption(G: Group, x: bigint, X: bigint, ct: Ciphertext, T: bigint, context: string, bytes: ByteSource): DecryptionProof {
  const a = randomScalar(G, bytes);
  const A = gpow(G, a);
  const B = exp(G, ct.R, a);
  const c = decryptionChallenge(G, context, X, ct, T, A, B);
  return { A, B, c, f: modq(G, a + c * x) };
}
