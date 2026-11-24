import { cryptoBytes, RFC5114_2048_256 as G } from '../group/modp';
import { auditCheck, catchProbability, prepare, reveal, simulateCatches, type Prepared } from '../election/audit';
import { newElection, shortTracker } from '../election/election';
import { DEFAULT_RNG, wilson } from '../rng';
import { checkRow, clear, control, evidenceRetired, h, numberInput, panelIntro, readNumber, select, selectWrap, threatModel, verdict } from './dom';

export function renderAuditPanel(root: HTMLElement): void {
  const e = newElection(G, 'crypto-lab-verifiable-ballot/measure-1', cryptoBytes);
  const flipSel = select('audit-flip', [['0', 'Honest — never changes a vote'], ['0.1', 'Changes 10% of votes'], ['0.5', 'Changes half the votes'], ['1', 'Changes every vote']], '1');
  const yes = h('input', { type: 'radio', name: 'audit-choice', id: 'audit-yes', value: '1', checked: true }) as HTMLInputElement;
  const no = h('input', { type: 'radio', name: 'audit-choice', id: 'audit-no', value: '0' }) as HTMLInputElement;
  const prep = h('button', { class: 'btn btn-primary', type: 'button', id: 'audit-prepare' }, 'Prepare my ballot') as HTMLButtonElement;
  const castBtn = h('button', { class: 'btn btn-ghost', type: 'button', id: 'audit-cast', disabled: true }, 'Cast it') as HTMLButtonElement;
  const auditBtn = h('button', { class: 'btn btn-primary', type: 'button', id: 'audit-audit', disabled: true }, 'Audit it') as HTMLButtonElement;
  const out = h('div', { class: 'output', id: 'audit-out', role: 'status', 'aria-live': 'polite' });
  let current: Prepared | null = null;

  const retire = (): void => {
    if (!out.hasChildNodes()) return;
    current = null;
    castBtn.disabled = true;
    auditBtn.disabled = true;
    clear(out);
    out.append(evidenceRetired('The device or your choice changed, so the ballot shown no longer belongs to them. Prepare a new one.'));
  };
  for (const el of [flipSel, yes, no]) el.addEventListener('change', retire);

  prep.addEventListener('click', () => {
    const choice = yes.checked ? 1 : 0;
    current = prepare(e, { flip: Number(flipSel.value) }, choice, DEFAULT_RNG, cryptoBytes);
    clear(out);
    out.append(
      h('p', {}, 'The device has encrypted your ballot and committed to it by showing its tracker: ', h('code', { 'data-claim': 'audit-tracker' }, shortTracker(current.tracker))),
      h('p', { class: 'help' }, 'Only now do you choose. The device cannot change the ballot behind this tracker.'),
    );
    castBtn.disabled = false;
    auditBtn.disabled = false;
  });

  castBtn.addEventListener('click', () => {
    if (!current) return;
    clear(out);
    out.append(verdict('pass', `Cast. Your receipt is ${shortTracker(current.tracker)}. Whether it encrypts your choice was not checked — this ballot was not audited.`));
    current = null;
    castBtn.disabled = true;
    auditBtn.disabled = true;
  });

  auditBtn.addEventListener('click', () => {
    if (!current) return;
    const r = reveal(current);
    const res = auditCheck(e, current.ballot, current.tracker, current.choice, r);
    clear(out);
    out.append(
      h('p', {}, 'The device reveals the randomness r. Your own tool re-encrypts your choice with it and compares the result with the ballot committed under the tracker.'),
      h('ul', { class: 'check-list' }, checkRow(res.ok, res.reason, 'audit-check', res.ok ? 'this audited ballot encrypted your choice' : 'the audit detected a changed vote')),
      res.ok
        ? verdict('pass', 'This ballot encrypted your choice. It is now spoiled — a revealed ballot could be sold — so prepare a new one to cast.')
        : verdict('alarm', 'CAUGHT: the device encrypted the other answer. Report the device.'),
    );
    current = null;
    castBtn.disabled = true;
    auditBtn.disabled = true;
  });

  // ── How often does a cheating device get caught? ──
  const aIn = numberInput('audit-a', '0.1');
  const fIn = numberInput('audit-f', '0.5');
  const nSel = select('audit-n', [['1000', '1 000 rounds'], ['10000', '10 000 rounds'], ['100000', '100 000 rounds']], '10000');
  const simBtn = h('button', { class: 'btn btn-primary', type: 'button', id: 'audit-sim' }, 'Simulate') as HTMLButtonElement;
  const probOut = h('div', { class: 'output', id: 'audit-prob', role: 'status', 'aria-live': 'polite' });
  const simOut = h('div', { class: 'output', id: 'audit-sim-out' });
  let simShown = false;
  const compute = (): { a: number; f: number } | null => {
    clear(probOut);
    const a = readNumber(aIn, 0, 1);
    const f = readNumber(fIn, 0, 1);
    if (a === null || f === null) {
      probOut.append(verdict('fail', 'Enter both rates as decimals from 0 to 1.'));
      simBtn.disabled = true;
      return null;
    }
    simBtn.disabled = false;
    probOut.append(h('p', {}, 'P(caught on one ballot) = a · f = ', h('strong', { 'data-claim': 'audit-p' }, String(+(catchProbability(a, f)).toFixed(6)))));
    return { a, f };
  };
  const updateExperiment = (): void => {
    if (simShown) {
      simShown = false;
      clear(simOut);
      simOut.append(evidenceRetired('The rates or trial count changed. Run the simulation again for these settings.'));
    }
    compute();
  };
  for (const el of [aIn, fIn]) el.addEventListener('input', updateExperiment);
  nSel.addEventListener('change', updateExperiment);
  simBtn.addEventListener('click', () => {
    const v = compute();
    if (!v) return;
    const r = simulateCatches(v.a, v.f, Number(nSel.value), DEFAULT_RNG);
    const ci = wilson(r.caught, r.n);
    clear(simOut);
    simOut.append(
      h('p', {}, 'Rounds ', h('strong', { 'data-claim': 'audit-sim-n' }, r.n.toLocaleString('en-US')), ' · caught ', h('strong', {}, r.caught.toLocaleString('en-US')), ' · estimate ', h('strong', {}, (r.caught / r.n).toFixed(4)), ' · 95% interval ', h('strong', { 'data-claim': 'audit-sim-ci' }, `[${ci.lo.toFixed(4)}, ${ci.hi.toFixed(4)}]`)),
      h('p', { class: 'help' }, 'Observed in this experiment, not a test. Randomness: crypto.getRandomValues.'),
    );
    simShown = true;
  });

  root.append(
    panelIntro(
      'Audit: cast as intended',
      'The voting device does the encrypting, so it could encrypt the opposite of what you chose — and the 0/1 proof would still verify, because the cheating ballot is still a well-formed 0 or 1. Benaloh\'s answer is the challenge: the device must commit to the ballot before you say whether you will cast it or audit it. An audit reveals the randomness, so you can check the encryption yourself.',
      'The device cannot tell which ballots will be audited. If it changes a fraction f of votes and voters audit at rate a, the chance of detection per ballot is a · f under independent auditing. Across N independent rounds the chance of at least one detection is 1 − (1 − a · f)^N. If nobody audits, a changed vote cannot be detected this way.',
    ),
    h(
      'div',
      { class: 'controls' },
      control('audit-flip', 'The voting device', selectWrap(flipSel)),
      h('fieldset', { class: 'control' }, h('legend', { class: 'control-label' }, 'Your vote'), h('div', { class: 'radio-row' }, h('label', { class: 'radio', for: 'audit-yes' }, yes, 'Yes'), h('label', { class: 'radio', for: 'audit-no' }, no, 'No'))),
    ),
    h('div', { class: 'action-row spaced' }, prep, ' ', castBtn, ' ', auditBtn),
    out,
    h('h3', {}, 'How often is a cheating device caught?'),
    h('div', { class: 'controls' }, control('audit-a', 'Audit rate a', aIn, 'Share of ballots voters audit, 0 to 1.'), control('audit-f', 'Cheating rate f', fIn, 'Share of votes the device changes, 0 to 1.'), control('audit-n', 'Rounds', selectWrap(nSel))),
    probOut,
    h('div', { class: 'action-row spaced' }, simBtn),
    simOut,
    threatModel({
      attacker: 'The voting device: it chooses what to encrypt, ballot by ballot.',
      access: 'It sees the voter\'s choice, but not whether the voter will audit — it must commit first.',
      trusted: 'The voter\'s own checking tool, and the order: commitment before the choice.',
      success: 'A changed vote is cast without any audit catching the device.',
      notShown: 'That the ballot actually cast was checked (audited ballots are spoiled), or anything about the board and the tally.',
    }),
  );
  compute();
}
