import { cryptoBytes, randomScalar, RFC5114_2048_256 as G } from '../group/modp';
import { encrypt } from '../elgamal/exp';
import { makeBallot, newElection, shortTracker, tracker, type Ballot } from '../election/election';
import { ProverRefusal, proveZeroOne } from '../proofs/orproof';
import { verifyZeroOne } from '../proofs/orverify';
import { checkRow, clear, evidenceRetired, field, h, note, panelIntro, verdict } from './dom';

const EQUATIONS = [
  'g^f0 = A0 · R^c0',
  'g^f1 = A1 · R^c1',
  'X^f0 = B0 · S^c0',
  'X^f1 = B1 · (S/g)^c1',
  'c0 + c1 = H(election, X, R, S, A0, B0, A1, B1)',
];

export function equationList(holds: readonly number[], prefix: string): HTMLElement {
  return h('ul', { class: 'check-list' }, ...EQUATIONS.map((eq, i) => checkRow(holds.includes(i + 1), `(${i + 1}) ${eq}`, `${prefix}-eq${i + 1}`)));
}

export function ballotFields(b: Ballot, X: bigint): HTMLElement {
  const p = b.proof;
  return h(
    'details',
    { class: 'disclosure', id: 'cast-fields' },
    h('summary', {}, 'The full ciphertext and proof (hex)'),
    field('Election public key X', X.toString(16)),
    field('R = g^r', b.ct.R.toString(16)),
    field('S = g^v · X^r', b.ct.S.toString(16)),
    ...(['A0', 'B0', 'A1', 'B1', 'c0', 'c1', 'f0', 'f1'] as const).map((k) => field(k, p[k].toString(16))),
    h('p', { class: 'help' }, 'Election context hashed into the challenge: ', h('code', { 'data-claim': 'cast-context' }, CONTEXT)),
  );
}

export const CONTEXT = 'crypto-lab-verifiable-ballot/measure-1';

export function renderCastPanel(root: HTMLElement): void {
  const e = newElection(G, CONTEXT, cryptoBytes);
  const yes = h('input', { type: 'radio', name: 'cast-choice', id: 'cast-yes', value: '1', checked: true }) as HTMLInputElement;
  const no = h('input', { type: 'radio', name: 'cast-choice', id: 'cast-no', value: '0' }) as HTMLInputElement;
  const run = h('button', { class: 'btn btn-primary', type: 'button', id: 'cast-run' }, 'Encrypt and prove') as HTMLButtonElement;
  const two = h('button', { class: 'btn btn-ghost', type: 'button', id: 'cast-two' }, 'Try a ballot that encrypts 2') as HTMLButtonElement;
  const out = h('div', { class: 'output', id: 'cast-out' });
  let shown = false;

  const retire = (): void => {
    if (!shown) return;
    shown = false;
    clear(out);
    out.append(evidenceRetired('The choice changed, so the ballot shown was for the other answer. Encrypt again.'));
  };
  yes.addEventListener('change', retire);
  no.addEventListener('change', retire);

  run.addEventListener('click', () => {
    const v = yes.checked ? 1 : 0;
    const { ballot } = makeBallot(e, v, cryptoBytes);
    const check = verifyZeroOne(G, e.X, ballot.ct, ballot.proof, e.context);
    clear(out);
    out.append(
      h('p', {}, 'Tracker (your receipt): ', h('code', { 'data-claim': 'cast-tracker' }, shortTracker(tracker(ballot)))),
      h('h3', {}, 'Anyone can check the proof'),
      equationList(check.holds, 'cast'),
      check.ok
        ? verdict('pass', 'All five equations hold: this ciphertext encrypts 0 or 1. It does not say which.')
        : verdict('fail', `The proof does not verify: ${check.failures.join('; ')}.`),
      note('info', 'What this check supports: the ballot is well formed, so one ballot cannot add 2 votes or subtract one. What it does not show: that the device encrypted YOUR choice — that is the Audit tab.'),
      ballotFields(ballot, e.X),
    );
    shown = true;
  });

  two.addEventListener('click', () => {
    const r = randomScalar(G, cryptoBytes);
    const ct = encrypt(G, e.X, 2n, r);
    clear(out);
    let refusal = '';
    try {
      proveZeroOne(G, e.X, ct, 2n, r, e.context, cryptoBytes);
    } catch (err) {
      if (err instanceof ProverRefusal) refusal = err.message;
      else throw err;
    }
    // The best a cheater can do without a forgery: attach a valid proof made for an encryption of 1.
    const borrowed = makeBallot(e, 1, cryptoBytes).ballot.proof;
    const check = verifyZeroOne(G, e.X, ct, borrowed, e.context);
    out.append(
      h('p', {}, 'The honest prover refuses: ', h('em', {}, refusal), '.'),
      h('p', {}, 'Attaching a valid proof made for a different ballot (an encryption of 1) to the encryption of 2:'),
      equationList(check.holds, 'two'),
      check.ok ? verdict('fail', 'UNEXPECTED: the proof verified.') : verdict('alarm', 'Rejected: the 0/1 proof fails, so the board refuses this ballot.'),
    );
    shown = true;
  });

  root.append(
    panelIntro(
      'Cast a ballot',
      'The question is yes or no. Your choice v is 1 or 0, and it is encrypted with exponential ElGamal: (R, S) = (g^r, g^v · X^r), where X is the election\'s public key and r is fresh randomness. Without the private key, an encryption of 1 and an encryption of 0 look alike.',
      'A ballot also carries a proof that it encrypts 0 or 1 — two Chaum–Pedersen proofs joined with OR, one of them real and one simulated, so the proof does not reveal which. This is the proof Helios uses, with one change: its challenge hash includes the election, the key and the ciphertext (see the Weak Fiat–Shamir tab for why).',
    ),
    h('fieldset', { class: 'controls' }, h('legend', {}, 'Your vote on Measure 1'), h('div', { class: 'radio-row' }, h('label', { class: 'radio', for: 'cast-yes' }, yes, 'Yes (v = 1)'), h('label', { class: 'radio', for: 'cast-no' }, no, 'No (v = 0)'))),
    h('div', { class: 'action-row spaced' }, run, ' ', two),
    out,
    note('info', 'Ballots with 0/1 proofs and a homomorphic tally are also the subject of Threshold Decrypt\'s Election Tally exhibit, which goes further on the tally and on receipt-freeness; this lab concentrates on what the voter can verify.'),
  );
}
