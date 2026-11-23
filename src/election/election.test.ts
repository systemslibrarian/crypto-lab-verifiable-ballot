import { describe, expect, it } from 'vitest';
import { seeded, seededBytes } from '../testing/seeded';
import { div, exp, gpow, mul, randomScalar, RFC5114_2048_256 as G } from '../group/modp';
import { encrypt } from '../elgamal/exp';
import { proveZeroOne } from '../proofs/orproof';
import { runClash, receiptsCollide } from '../attacks/clash';
import { auditCheck, catchProbability, prepare, reveal, simulateCatches } from './audit';
import { Board } from './board';
import { makeBallot, newElection, tracker } from './election';
import { trusteeDecrypts, verifyTally } from './tally';

const bytes = seededBytes(7);
const e = newElection(G, 'election-test', bytes);

describe('B. Homomorphic tally', () => {
  it('101 random ballots: the decrypted tally equals the count of ones, counted from the plaintexts', () => {
    const rng = seeded(101);
    const board = new Board(e);
    const plain: number[] = [];
    for (let i = 0; i < 101; i++) {
      const v = rng() < 0.5 ? 0 : 1;
      plain.push(v);
      expect(board.submit(`b-${i}`, makeBallot(e, v as 0 | 1, bytes).ballot).ok).toBe(true);
    }
    const count = plain.filter((v) => v === 1).length;
    const res = verifyTally(board, trusteeDecrypts(board, bytes));
    expect(res).toEqual({ ok: true, total: count });
    // Independent route: the product's second component, divided by R^x, is g^count.
    const prod = board.product();
    expect(div(G, prod.S, exp(G, prod.R, e.x))).toBe(gpow(G, BigInt(count)));
  }, 120_000);

  it('the product multiplies BOTH components (R alone is not enough to decrypt the sum)', () => {
    const board = new Board(e);
    const rs = [randomScalar(G, bytes), randomScalar(G, bytes)];
    board.submit('a', { ct: encrypt(G, e.X, 1n, rs[0]), proof: proveZeroOne(G, e.X, encrypt(G, e.X, 1n, rs[0]), 1n, rs[0], e.context, bytes) });
    board.submit('b', { ct: encrypt(G, e.X, 1n, rs[1]), proof: proveZeroOne(G, e.X, encrypt(G, e.X, 1n, rs[1]), 1n, rs[1], e.context, bytes) });
    const p = board.product();
    expect(p.R).toBe(gpow(G, rs[0] + rs[1]));
    expect(p.S).toBe(mul(G, gpow(G, 2n), exp(G, e.X, rs[0] + rs[1])));
  });
});

describe('G. Fail-closed edge cases', () => {
  it('a ballot encrypting 2 is rejected: its 0/1 proof fails', () => {
    const board = new Board(e);
    const r = randomScalar(G, bytes);
    const two = encrypt(G, e.X, 2n, r);
    const borrowed = makeBallot(e, 1, bytes).ballot.proof;
    const res = board.submit('x', { ct: two, proof: borrowed });
    expect(res.ok).toBe(false);
    expect(!res.ok && res.reason).toMatch(/0\/1 proof fails/);
    expect(board.entries).toHaveLength(0);
  });
  it('a duplicate ballot ID is rejected', () => {
    const board = new Board(e);
    expect(board.submit('b-1', makeBallot(e, 1, bytes).ballot).ok).toBe(true);
    const res = board.submit('b-1', makeBallot(e, 0, bytes).ballot);
    expect(!res.ok && res.reason).toMatch(/already on the board/);
    expect(board.entries).toHaveLength(1);
  });
  it('an invalid decryption proof: the tally is withheld, not announced', () => {
    const board = new Board(e);
    for (const v of [1, 0, 1] as const) board.submit(`b-${board.entries.length}`, makeBallot(e, v, bytes).ballot);
    const honest = trusteeDecrypts(board, bytes);
    const res = verifyTally(board, { ...honest, T: mul(G, honest.T, G.g) });
    expect(res.ok).toBe(false);
    expect(!res.ok && res.reason).toMatch(/withheld/);
    expect(verifyTally(board, honest)).toEqual({ ok: true, total: 2 });
  });
  it('a published product that is not the product of the board is refused', () => {
    const board = new Board(e);
    board.submit('b', makeBallot(e, 1, bytes).ballot);
    const pub = trusteeDecrypts(board, bytes);
    expect(verifyTally(board, { ...pub, product: { R: pub.product.R, S: mul(G, pub.product.S, G.g) } }).ok).toBe(false);
  });
  it('invariant 3: the board verifies with the strong hash unless told otherwise', () => {
    expect(new Board(e).mode).toBe('strong');
  });
});

describe('C. Cast-or-audit (Benaloh)', () => {
  it('an honest device passes every audit: the revealed randomness reproduces the committed ballot', () => {
    for (const choice of [0, 1] as const) {
      const p = prepare(e, { flip: 0 }, choice, seeded(choice), bytes);
      expect(auditCheck(e, p.ballot, p.tracker, choice, reveal(p)).ok).toBe(true);
    }
  });
  it('a device that always flips is caught by the first audit, whatever the choice', () => {
    for (const choice of [0, 1] as const) {
      const p = prepare(e, { flip: 1 }, choice, seeded(5), bytes);
      const res = auditCheck(e, p.ballot, p.tracker, choice, reveal(p));
      expect(res.ok).toBe(false);
      expect(res.reason).toMatch(/changed your vote/);
    }
  });
  it('the check uses the ballot committed before the choice: a swapped ballot fails the tracker', () => {
    const p = prepare(e, { flip: 0 }, 1, seeded(1), bytes);
    const other = makeBallot(e, 1, bytes).ballot;
    expect(auditCheck(e, other, p.tracker, 1, reveal(p)).ok).toBe(false);
  });
  it('P(caught in one round) = a · f, exactly', () => {
    expect(catchProbability(0.1, 0.5)).toBeCloseTo(0.05, 15);
    expect(catchProbability(1, 1)).toBe(1);
    expect(catchProbability(0, 1)).toBe(0);
  });
  it('the simulation is deterministic at the edges (never audits → never caught; always both → always caught)', () => {
    expect(simulateCatches(0, 1, 500, seeded(3)).caught).toBe(0);
    expect(simulateCatches(1, 1, 500, seeded(3)).caught).toBe(500);
    expect(simulateCatches(1, 0, 500, seeded(3)).caught).toBe(0);
  });
});

describe('D. Clash attack fixture (Küsters–Truderung–Vogt §3.2)', () => {
  const run = runClash(e, seededBytes(42));
  it('all three voters find their receipt on the board', () => {
    expect(run.voters.map((v) => v.finds)).toEqual([true, true, true]);
  });
  it('every 0/1 proof verifies, ballot IDs and trackers on the board are all distinct, and there is one ballot per listed voter', () => {
    expect(run.proofsOk).toBe(true);
    expect(run.distinctIds).toBe(true);
    expect(run.distinctTrackers).toBe(true);
    expect(run.ballotsMatchNames).toBe(true);
    expect(run.board.entries).toHaveLength(3);
  });
  it('the decryption proof verifies and the tally is 2, not the 3 votes cast', () => {
    expect(run.tally).toEqual({ ok: true, total: 2 });
    expect(run.votesCast).toBe(3);
  });
  it('V1 and V2 hold the same receipt — the one comparison the procedure does not require', () => {
    expect(receiptsCollide(run.voters)).toEqual(['V1', 'V2']);
    expect(run.voters[0].receipt).toBe(tracker(run.board.entries[0].ballot));
  });
});
