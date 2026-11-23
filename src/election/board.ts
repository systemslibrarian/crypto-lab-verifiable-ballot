import { addAll, type Ciphertext } from '../elgamal/exp';
import type { FsMode } from '../proofs/challenge';
import { verifyZeroOne } from '../proofs/orverify';
import { tracker, type Ballot, type Election } from './election';

/**
 * The bulletin board. It accepts a ballot only if its ballot ID is new and its 0/1
 * proof verifies; every entry is public. Voter names, when shown, are a separate
 * list (Helios "with detached names", Küsters–Truderung–Vogt §3.1).
 */
export interface Entry {
  readonly id: string;
  readonly ballot: Ballot;
  readonly tracker: string;
}

export type Admission = { ok: true; entry: Entry } | { ok: false; reason: string };

export class Board {
  readonly entries: Entry[] = [];
  readonly names: string[] = [];
  constructor(
    readonly election: Election,
    /** Which Fiat–Shamir hash the board's verifier uses. 'weak' is the broken mode. */
    readonly mode: FsMode = 'strong',
  ) {}

  submit(id: string, ballot: Ballot): Admission {
    if (this.entries.some((e) => e.id === id)) return { ok: false, reason: `ballot ID ${id} is already on the board` };
    const v = verifyZeroOne(this.election.G, this.election.X, ballot.ct, ballot.proof, this.election.context, this.mode);
    if (!v.ok) return { ok: false, reason: `the 0/1 proof fails: ${v.failures.join('; ')}` };
    const entry = { id, ballot, tracker: tracker(ballot) };
    this.entries.push(entry);
    return { ok: true, entry };
  }

  /** "Recorded as cast": is this tracker on the board? */
  has(t: string): boolean {
    return this.entries.some((e) => e.tracker === t);
  }

  /** The homomorphic product of every accepted ballot. */
  product(): Ciphertext {
    return addAll(this.election.G, this.entries.map((e) => e.ballot.ct));
  }
}
