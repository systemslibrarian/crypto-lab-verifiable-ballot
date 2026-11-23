import { randomScalar, type ByteSource } from '../group/modp';
import { encrypt } from '../elgamal/exp';
import { proveZeroOne } from '../proofs/orproof';
import type { Rng } from '../rng';
import { tracker, type Ballot, type Election } from './election';

/**
 * Cast-or-audit (Benaloh, EVT 2006, §4.2.1; as Helios 2008 §2.1 implements it).
 * The device encrypts the voter's choice and COMMITS by showing the tracker. Only
 * then does the voter choose: cast it, or audit it. An audit reveals the randomness;
 * the voter recomputes the encryption of the choice she made and compares it with
 * the committed ballot. An audited ballot is spoiled and a new one is made.
 *
 * A cheating device here encrypts the other choice with probability flip. It must
 * decide before it knows whether this ballot will be audited — that is the point.
 */
export interface Device {
  /** Probability that the device encrypts the opposite of the voter's choice. */
  readonly flip: number;
}

export interface Prepared {
  readonly choice: 0 | 1;
  readonly ballot: Ballot;
  readonly tracker: string;
  /** Device-private until an audit. */
  readonly secret: { readonly encrypted: 0 | 1; readonly r: bigint };
}

export function prepare(e: Election, device: Device, choice: 0 | 1, rng: Rng, bytes: ByteSource): Prepared {
  const cheat = rng() < device.flip;
  const encrypted: 0 | 1 = cheat ? ((1 - choice) as 0 | 1) : choice;
  const r = randomScalar(e.G, bytes);
  const ct = encrypt(e.G, e.X, BigInt(encrypted), r);
  const ballot = { ct, proof: proveZeroOne(e.G, e.X, ct, BigInt(encrypted), r, e.context, bytes) };
  return { choice, ballot, tracker: tracker(ballot), secret: { encrypted, r } };
}

/** What the device hands over when audited: the randomness of THIS ballot. */
export function reveal(p: Prepared): bigint {
  return p.secret.r;
}

/**
 * The voter's check, run by her own tool. It uses only what she saw BEFORE choosing
 * (the committed ballot and its tracker) plus the revealed randomness — nothing the
 * device says about itself.
 */
export function auditCheck(e: Election, committed: Ballot, committedTracker: string, choice: 0 | 1, r: bigint): { ok: boolean; reason: string } {
  if (tracker(committed) !== committedTracker) return { ok: false, reason: 'the ballot does not match the tracker shown before the choice' };
  const mine = encrypt(e.G, e.X, BigInt(choice), r);
  if (mine.R !== committed.ct.R) return { ok: false, reason: 'the revealed randomness does not reproduce this ballot' };
  if (mine.S !== committed.ct.S) return { ok: false, reason: `the ballot does not encrypt your choice (${choice}) — the device changed your vote` };
  return { ok: true, reason: `the ballot encrypts your choice (${choice})` };
}

/** P(a cheating device is caught on one ballot) = a · f, for audit rate a and flip rate f. */
export function catchProbability(auditRate: number, flip: number): number {
  return auditRate * flip;
}

/** Seeded or crypto-random rounds of the game, counting catches (no group arithmetic: the outcome is decided by the two coins). */
export function simulateCatches(auditRate: number, flip: number, n: number, rng: Rng): { caught: number; n: number } {
  let caught = 0;
  for (let i = 0; i < n; i++) {
    const cheats = rng() < flip;
    const audits = rng() < auditRate;
    if (cheats && audits) caught++;
  }
  return { caught, n };
}
