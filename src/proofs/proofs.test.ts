import { describe, expect, it } from 'vitest';
import { seededBytes } from '../testing/seeded';
import { div, exp, gpow, isElement, modq, mul, randomScalar, RFC5114_2048_256 as G } from '../group/modp';
import { encrypt } from '../elgamal/exp';
import { newElection, makeBallot } from '../election/election';
import { forgeWeak } from '../attacks/weakfs';
import { zeroOneChallenge } from './challenge';
import { ProverRefusal, proveZeroOne, type ZeroOneProof } from './orproof';
import { verifyZeroOne } from './orverify';
import { proveDecryption } from './cp';
import { verifyDecryption } from './cpverify';
import { decryptionChallenge } from './challenge';

const bytes = seededBytes(2026);
const e = newElection(G, 'test-election', bytes);
const FIELDS = ['A0', 'B0', 'A1', 'B1', 'c0', 'c1', 'f0', 'f1'] as const;

describe('A. 0/1 proof soundness', () => {
  it('1,000 seeded ballots, v ∈ {0, 1}: every proof verifies', () => {
    const b = seededBytes(1000);
    let n = 0;
    for (let i = 0; i < 1000; i++) {
      const v = (i * 7919) % 3 === 0 ? 1 : 0;
      const { ballot } = makeBallot(e, v as 0 | 1, b);
      if (verifyZeroOne(G, e.X, ballot.ct, ballot.proof, e.context).ok) n++;
    }
    expect(n).toBe(1000);
  }, 300_000);

  it('the honest prover refuses to prove v = 2 (and −1)', () => {
    const r = randomScalar(G, bytes);
    expect(() => proveZeroOne(G, e.X, encrypt(G, e.X, 2n, r), 2n, r, e.context, bytes)).toThrow(ProverRefusal);
    expect(() => proveZeroOne(G, e.X, encrypt(G, e.X, -1n, r), -1n, r, e.context, bytes)).toThrow(ProverRefusal);
  });

  it('every field of a valid transcript, perturbed, fails — and so does the ciphertext, the key or the context', () => {
    const { ballot } = makeBallot(e, 1, bytes);
    for (const f of FIELDS) {
      const isGroupElt = f.startsWith('A') || f.startsWith('B');
      const bad = { ...ballot.proof, [f]: isGroupElt ? mul(G, ballot.proof[f], G.g) : modq(G, ballot.proof[f] + 1n) } as ZeroOneProof;
      expect(verifyZeroOne(G, e.X, ballot.ct, bad, e.context).ok, f).toBe(false);
    }
    expect(verifyZeroOne(G, e.X, { R: mul(G, ballot.ct.R, G.g), S: ballot.ct.S }, ballot.proof, e.context).ok).toBe(false);
    expect(verifyZeroOne(G, e.X, { R: ballot.ct.R, S: mul(G, ballot.ct.S, G.g) }, ballot.proof, e.context).ok).toBe(false);
    expect(verifyZeroOne(G, mul(G, e.X, G.g), ballot.ct, ballot.proof, e.context).ok).toBe(false);
    expect(verifyZeroOne(G, e.X, ballot.ct, ballot.proof, 'another-election').ok).toBe(false);
  });

  it('elements outside the subgroup and scalars outside [0, q) are refused before any equation', () => {
    const { ballot } = makeBallot(e, 0, bytes);
    expect(verifyZeroOne(G, e.X, ballot.ct, { ...ballot.proof, A0: G.p - 1n }, e.context).failures[0]).toMatch(/subgroup/);
    expect(verifyZeroOne(G, e.X, ballot.ct, { ...ballot.proof, f0: ballot.proof.f0 + G.q }, e.context).failures[0]).toMatch(/scalar/);
  });

  describe('curated forgery attempts for an encryption of 2 — each must fail', () => {
    const r = randomScalar(G, bytes);
    const two = encrypt(G, e.X, 2n, r);
    const check = (pf: ZeroOneProof): boolean => verifyZeroOne(G, e.X, two, pf, e.context).ok;
    it('F1: a valid proof for an encryption of 1, attached to the encryption of 2', () => {
      expect(check(makeBallot(e, 1, bytes).ballot.proof)).toBe(false);
    });
    it('F2: "prove 1" run on the encryption of 2 (real branch 1, simulated branch 0)', () => {
      const a = randomScalar(G, bytes), c0 = randomScalar(G, bytes), f0 = randomScalar(G, bytes);
      const A0 = div(G, gpow(G, f0), exp(G, two.R, c0)), B0 = div(G, exp(G, e.X, f0), exp(G, two.S, c0));
      const A1 = gpow(G, a), B1 = exp(G, e.X, a);
      const c = zeroOneChallenge(G, 'strong', e.context, e.X, two, { A0, B0, A1, B1 });
      const c1 = modq(G, c - c0);
      expect(check({ A0, B0, A1, B1, c0, c1, f0, f1: modq(G, a + c1 * r) })).toBe(false);
    });
    it('F3: both branches simulated (c0, c1 chosen freely)', () => {
      const [c0, f0, c1, f1] = [0, 1, 2, 3].map(() => randomScalar(G, bytes));
      const A0 = div(G, gpow(G, f0), exp(G, two.R, c0)), B0 = div(G, exp(G, e.X, f0), exp(G, two.S, c0));
      const A1 = div(G, gpow(G, f1), exp(G, two.R, c1)), B1 = div(G, exp(G, e.X, f1), exp(G, div(G, two.S, G.g), c1));
      expect(check({ A0, B0, A1, B1, c0, c1, f0, f1 })).toBe(false);
    });
    it('F4: both branches simulated, then c1 forced to c − c0 without recomputing A1, B1', () => {
      const [c0, f0, c1s, f1] = [0, 1, 2, 3].map(() => randomScalar(G, bytes));
      const A0 = div(G, gpow(G, f0), exp(G, two.R, c0)), B0 = div(G, exp(G, e.X, f0), exp(G, two.S, c0));
      const A1 = div(G, gpow(G, f1), exp(G, two.R, c1s)), B1 = div(G, exp(G, e.X, f1), exp(G, div(G, two.S, G.g), c1s));
      const c = zeroOneChallenge(G, 'strong', e.context, e.X, two, { A0, B0, A1, B1 });
      expect(check({ A0, B0, A1, B1, c0, c1: modq(G, c - c0), f0, f1 })).toBe(false);
    });
    it('F5: c0 = 0 (BPW footnote 4\'s trick), branch 1 simulated', () => {
      const [f0, a1] = [0, 1].map(() => randomScalar(G, bytes));
      const A0 = gpow(G, f0), B0 = exp(G, e.X, f0);
      const A1 = gpow(G, a1), B1 = exp(G, e.X, a1);
      const c = zeroOneChallenge(G, 'strong', e.context, e.X, two, { A0, B0, A1, B1 });
      expect(check({ A0, B0, A1, B1, c0: 0n, c1: c, f0, f1: modq(G, a1 + c * r) })).toBe(false);
    });
    it('F6: the BPW weak-Fiat–Shamir forgery, checked by the strong verifier', () => {
      const fg = forgeWeak(G, 2n, bytes);
      expect(verifyZeroOne(G, fg.X, fg.ct, fg.proof, e.context, 'strong').ok).toBe(false);
    });
  });
});

describe('E. Weak Fiat–Shamir (Bernhard–Pereira–Warinschi 2012, §3)', () => {
  it('the forgery passes the WEAK verifier for m = 3 and m = −2, and the ciphertext really encrypts m', () => {
    for (const m of [3n, -2n]) {
      const fg = forgeWeak(G, m, bytes);
      const v = verifyZeroOne(G, fg.X, fg.ct, fg.proof, 'any-context', 'weak');
      expect(v.ok).toBe(true);
      expect(v.holds).toEqual([1, 2, 3, 4, 5]);
      // Decrypt with the trustees' key: S / R^x = g^m.
      expect(div(G, fg.ct.S, exp(G, fg.ct.R, fg.x))).toBe(gpow(G, m));
      expect(isElement(G, fg.X)).toBe(true);
    }
  });
  it('the same forgery fails the STRONG verifier at equation (5) only', () => {
    const fg = forgeWeak(G, 3n, bytes);
    const v = verifyZeroOne(G, fg.X, fg.ct, fg.proof, e.context, 'strong');
    expect(v.ok).toBe(false);
    expect(v.holds).toEqual([1, 2, 3, 4]);
  });
  it('BPW §3 rerandomisation: (R·g^u, S·X^u, f0 + c0·u, f1 + c1·u) passes the weak verifier and fails the strong one', () => {
    const r = randomScalar(G, bytes);
    const ct = encrypt(G, e.X, 1n, r);
    for (const mode of ['weak', 'strong'] as const) {
      const pf = proveZeroOne(G, e.X, ct, 1n, r, e.context, bytes, mode);
      const u = randomScalar(G, bytes);
      const ct2 = { R: mul(G, ct.R, gpow(G, u)), S: mul(G, ct.S, exp(G, e.X, u)) };
      const pf2 = { ...pf, f0: modq(G, pf.f0 + pf.c0 * u), f1: modq(G, pf.f1 + pf.c1 * u) };
      expect(verifyZeroOne(G, e.X, ct2, pf2, e.context, mode).ok, mode).toBe(mode === 'weak');
    }
  });
  it('honest proofs are bound to their mode: a weak proof fails the strong check and vice versa', () => {
    const r = randomScalar(G, bytes);
    const ct = encrypt(G, e.X, 1n, r);
    const weak = proveZeroOne(G, e.X, ct, 1n, r, e.context, bytes, 'weak');
    const strong = proveZeroOne(G, e.X, ct, 1n, r, e.context, bytes, 'strong');
    expect(verifyZeroOne(G, e.X, ct, weak, e.context, 'weak').ok).toBe(true);
    expect(verifyZeroOne(G, e.X, ct, weak, e.context, 'strong').ok).toBe(false);
    expect(verifyZeroOne(G, e.X, ct, strong, e.context, 'weak').ok).toBe(false);
  });
});

describe('Decryption proof (Chaum–Pedersen)', () => {
  const { ballot } = makeBallot(e, 1, bytes);
  const ct = ballot.ct;
  const T = exp(G, ct.R, e.x);
  it('an honest decryption factor and proof verify', () => {
    expect(verifyDecryption(G, e.X, ct, T, proveDecryption(G, e.x, e.X, ct, T, e.context, bytes), e.context).ok).toBe(true);
  });
  it('a wrong decryption factor fails', () => {
    const bad = mul(G, T, G.g);
    expect(verifyDecryption(G, e.X, ct, bad, proveDecryption(G, e.x, e.X, ct, T, e.context, bytes), e.context).ok).toBe(false);
  });
  it('a transcript where only equation (b) fails is rejected', () => {
    const bad = mul(G, T, G.g);
    const a = randomScalar(G, bytes);
    const A = gpow(G, a), B = exp(G, ct.R, a);
    const c = decryptionChallenge(G, e.context, e.X, ct, bad, A, B);
    const v = verifyDecryption(G, e.X, ct, bad, { A, B, c, f: modq(G, a + c * e.x) }, e.context);
    expect(v.ok).toBe(false);
    expect(v.failures).toEqual(['equation (b) R^f = B·T^c fails']);
  });
  it('a transcript where only equation (a) fails is rejected', () => {
    const a = randomScalar(G, bytes), a2 = randomScalar(G, bytes);
    const A = gpow(G, a2), B = exp(G, ct.R, a);
    const c = decryptionChallenge(G, e.context, e.X, ct, T, A, B);
    const v = verifyDecryption(G, e.X, ct, T, { A, B, c, f: modq(G, a + c * e.x) }, e.context);
    expect(v.failures).toEqual(['equation (a) g^f = A·X^c fails']);
  });
});
