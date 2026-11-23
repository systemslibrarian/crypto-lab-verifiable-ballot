import { digestHex } from '../group/hash';
import { randomScalar, type ByteSource, type Group } from '../group/modp';
import { encrypt, keygen, type Ciphertext } from '../elgamal/exp';
import type { FsMode } from '../proofs/challenge';
import { proveZeroOne, type ZeroOneProof } from '../proofs/orproof';

export interface Election {
  readonly G: Group;
  readonly context: string;
  readonly X: bigint;
  /** Held by the trustee; never shown on the board. */
  readonly x: bigint;
}

export interface Ballot {
  readonly ct: Ciphertext;
  readonly proof: ZeroOneProof;
}

export function newElection(G: Group, context: string, bytes: ByteSource): Election {
  const { x, X } = keygen(G, bytes);
  return { G, context, x, X };
}

/**
 * The tracker (Helios: "a hash of the ciphertext", §2.1): SHA-256 over the encoded
 * ciphertext and proof. The voter keeps it; the board shows it next to the ballot.
 * Encoding: fields "tracker", R, S, A0, B0, A1, B1, c0, c1, f0, f1 (see group/hash.ts).
 */
export function tracker(b: Ballot): string {
  const p = b.proof;
  return digestHex(['tracker', b.ct.R, b.ct.S, p.A0, p.B0, p.A1, p.B1, p.c0, p.c1, p.f0, p.f1]);
}

/** Short form for display: the first 16 hex digits in groups of four. */
export const shortTracker = (t: string): string => t.slice(0, 16).match(/..../g)!.join(' ');

/** An honest ballot: encrypt v with fresh r and prove it is 0 or 1. Returns r so an audit can reveal it. */
export function makeBallot(e: Election, v: 0 | 1, bytes: ByteSource, mode: FsMode = 'strong'): { ballot: Ballot; r: bigint } {
  const r = randomScalar(e.G, bytes);
  const ct = encrypt(e.G, e.X, BigInt(v), r);
  return { ballot: { ct, proof: proveZeroOne(e.G, e.X, ct, BigInt(v), r, e.context, bytes, mode) }, r };
}
