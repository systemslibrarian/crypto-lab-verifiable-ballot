import type { ByteSource } from '../group/modp';
import { decryptionFactor, recoverSmall, type Ciphertext } from '../elgamal/exp';
import { proveDecryption, type DecryptionProof } from '../proofs/cp';
import { verifyDecryption } from '../proofs/cpverify';
import type { Board } from './board';

/**
 * "Tallied as recorded": multiply the ballots on the board, have the trustee publish
 * T = R^x with a Chaum–Pedersen proof, and recover the total t from g^t = S/T.
 * A published tally that fails its proof is withheld, never announced.
 */
// [extension] point — mixnet tally. Helios 1.0 shuffled the encrypted ballots through a
// verifiable mixnet and decrypted each one (Adida 2008, §2); this lab uses the
// homomorphic tally instead. Not built here.
export interface PublishedTally {
  readonly product: Ciphertext;
  readonly T: bigint;
  readonly proof: DecryptionProof;
}

export function trusteeDecrypts(board: Board, bytes: ByteSource): PublishedTally {
  const e = board.election;
  const product = board.product();
  const T = decryptionFactor(e.G, e.x, product);
  return { product, T, proof: proveDecryption(e.G, e.x, e.X, product, T, e.context, bytes) };
}

export type TallyResult = { ok: true; total: number } | { ok: false; reason: string };

/** Anyone's check: recompute the product from the board, verify the proof, then recover the total. */
export function verifyTally(board: Board, pub: PublishedTally): TallyResult {
  const e = board.election;
  const mine = board.product();
  if (mine.R !== pub.product.R || mine.S !== pub.product.S) return { ok: false, reason: 'the published product is not the product of the ballots on the board' };
  const v = verifyDecryption(e.G, e.X, mine, pub.T, pub.proof, e.context);
  if (!v.ok) return { ok: false, reason: `decryption proof invalid (${v.failures.join('; ')}) — tally withheld` };
  const total = recoverSmall(e.G, mine, pub.T, board.entries.length);
  if (total === null) return { ok: false, reason: 'no total between 0 and the number of ballots decrypts — tally withheld' };
  return { ok: true, total };
}
