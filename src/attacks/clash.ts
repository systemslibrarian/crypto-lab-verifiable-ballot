import { randomScalar, type ByteSource } from '../group/modp';
import { encrypt } from '../elgamal/exp';
import { proveZeroOne } from '../proofs/orproof';
import { verifyZeroOne } from '../proofs/orverify';
import { Board } from '../election/board';
import { makeBallot, tracker, type Ballot, type Election } from '../election/election';
import { trusteeDecrypts, verifyTally, type TallyResult } from '../election/tally';

/**
 * The clash attack (Küsters, Truderung, Vogt, "Clash Attacks on the Verifiability of
 * E-Voting Systems", §3.2, Helios with detached names). BROKEN MODE: never the default.
 *
 * A dishonest ballot-preparation device and a dishonest bulletin board work together.
 * Voters who make the same choice are given the SAME ballot — same randomness, so the
 * same ciphertext, proof and tracker (receipt). The board keeps one copy and replaces
 * the other by a ballot of its own choosing, so the board still holds exactly one
 * ballot per voter, the names list is complete, and every voter finds her tracker.
 * The tallying itself is done honestly.
 *
 * Kept separate, as the paper does: the voter's NAME (on a detached list), her
 * TRACKER (receipt), the BALLOT ID (the board's row key) and the CIPHERTEXT.
 */
export interface ClashVoter {
  readonly name: string;
  readonly vote: 0 | 1;
  readonly receipt: string;
  readonly finds: boolean;
}

export interface ClashRun {
  readonly board: Board;
  readonly voters: readonly ClashVoter[];
  readonly proofsOk: boolean;
  readonly distinctIds: boolean;
  readonly distinctTrackers: boolean;
  readonly ballotsMatchNames: boolean;
  readonly tally: TallyResult;
  readonly votesCast: number;
}

/** Fixture D: V1, V2 and V3 all vote 1; V1 and V2 are given the same ballot. */
export function runClash(e: Election, bytes: ByteSource): ClashRun {
  const board = new Board(e);
  // The device reuses one random coin for every "1" it encrypts — the extreme case in §2.2/§3.2.
  const r = randomScalar(e.G, bytes);
  const shared: Ballot = (() => {
    const ct = encrypt(e.G, e.X, 1n, r);
    return { ct, proof: proveZeroOne(e.G, e.X, ct, 1n, r, e.context, bytes) };
  })();
  const v3 = makeBallot(e, 1, bytes).ballot;
  // The board keeps one copy of the shared ballot and substitutes a ballot of its choice: here, a 0.
  const substitute = makeBallot(e, 0, bytes).ballot;
  board.names.push('V1', 'V2', 'V3');
  for (const [id, b] of [['b-01', shared], ['b-02', v3], ['b-03', substitute]] as const) {
    const res = board.submit(id, b);
    if (!res.ok) throw new Error(`fixture ballot refused: ${res.reason}`);
  }
  const receipts = [tracker(shared), tracker(shared), tracker(v3)];
  const voters = (['V1', 'V2', 'V3'] as const).map((name, i) => ({ name, vote: 1 as const, receipt: receipts[i], finds: board.has(receipts[i]) }));
  const proofsOk = board.entries.every((en) => verifyZeroOne(e.G, e.X, en.ballot.ct, en.ballot.proof, e.context).ok);
  const ids = board.entries.map((en) => en.id);
  const trackers = board.entries.map((en) => en.tracker);
  const tally = verifyTally(board, trusteeDecrypts(board, bytes));
  return {
    board,
    voters,
    proofsOk,
    distinctIds: new Set(ids).size === ids.length,
    distinctTrackers: new Set(trackers).size === trackers.length,
    ballotsMatchNames: board.entries.length === board.names.length,
    tally,
    votesCast: voters.filter((v) => v.vote === 1).length,
  };
}

/** The check the procedure does not require: do any two voters hold the same receipt? */
export function receiptsCollide(voters: readonly ClashVoter[]): [string, string] | null {
  for (let i = 0; i < voters.length; i++) for (let j = i + 1; j < voters.length; j++) if (voters[i].receipt === voters[j].receipt) return [voters[i].name, voters[j].name];
  return null;
}
