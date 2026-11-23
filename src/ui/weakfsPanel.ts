import { cryptoBytes, RFC5114_2048_256 as G } from '../group/modp';
import { forgeWeak } from '../attacks/weakfs';
import { Board } from '../election/board';
import { makeBallot, type Election } from '../election/election';
import { trusteeDecrypts, verifyTally } from '../election/tally';
import type { FsMode } from '../proofs/challenge';
import { verifyZeroOne } from '../proofs/orverify';
import { boardTable } from './boardPanel';
import { equationList } from './castPanel';
import { brokenBadge, checkRow, clear, h, note, panelIntro, threatModel, verdict } from './dom';

export const HONEST_VOTES: readonly (0 | 1)[] = [1, 0, 0, 1, 0];
export const FORGED_M = 3n;

export function runForgedElection(mode: FsMode) {
  const context = 'crypto-lab-verifiable-ballot/measure-2';
  // The corrupt trustees build the forgery FIRST and derive the election key from its challenge.
  const fg = forgeWeak(G, FORGED_M, cryptoBytes);
  const e: Election = { G, context, x: fg.x, X: fg.X };
  const board = new Board(e, mode);
  const admissions = HONEST_VOTES.map((v, i) => board.submit(`b-0${i + 1}`, makeBallot(e, v, cryptoBytes, mode).ballot));
  const mallory = board.submit('b-06', { ct: fg.ct, proof: fg.proof });
  const eq = verifyZeroOne(G, e.X, fg.ct, fg.proof, context, mode);
  const tally = verifyTally(board, trusteeDecrypts(board, cryptoBytes));
  return { board, admissions, mallory, eq, tally };
}

export function renderWeakFsPanel(root: HTMLElement): void {
  const weakBtn = h('button', { class: 'btn btn-primary', type: 'button', id: 'wfs-weak' }, 'Run the election with the weak hash') as HTMLButtonElement;
  const strongBtn = h('button', { class: 'btn btn-ghost', type: 'button', id: 'wfs-strong' }, 'Run it again with the strong hash') as HTMLButtonElement;
  const out = h('div', { class: 'output', id: 'wfs-out' });

  const show = (mode: FsMode): void => {
    const r = runForgedElection(mode);
    const honestYes = HONEST_VOTES.filter((v) => v === 1).length;
    clear(out);
    out.append(
      mode === 'weak' ? brokenBadge('Broken mode: c = H(A0, B0, A1, B1), as Helios hashed it. Never the default.') : h('p', { class: 'help' }, 'Strong mode: c = H(election, X, R, S, A0, B0, A1, B1) — the default everywhere else in this lab.'),
      h('h3', {}, mode === 'weak' ? 'Weak hash' : 'Strong hash'),
      h('p', {}, `Five honest voters vote ${HONEST_VOTES.map((v) => (v ? 'yes' : 'no')).join(', ')} — ${honestYes} yes. Mallory, working with the trustees, submits ballot b-06, which encrypts ${FORGED_M}.`),
      h('h4', {}, 'Mallory\'s 0/1 proof'),
      equationList(r.eq.holds, `wfs-${mode}`),
      r.mallory.ok ? verdict('alarm', 'The board ACCEPTED b-06: its proof says "0 or 1".') : verdict('pass', `The board rejected b-06: ${r.mallory.reason}.`),
      h('h4', {}, 'The bulletin board'),
      boardTable(r.board),
      h(
        'ul',
        { class: 'check-list' },
        checkRow(r.board.entries.length === (r.mallory.ok ? 6 : 5), `Every ballot on the board passed its 0/1 proof (${r.board.entries.length} ballots)`, `wfs-${mode}-proofs`),
        checkRow(r.tally.ok, r.tally.ok ? 'The decryption proof verifies' : `The tally does not verify: ${r.tally.reason}`, `wfs-${mode}-decrypt`),
      ),
      h('p', {}, 'Published tally: ', h('strong', { 'data-claim': `wfs-${mode}-tally` }, r.tally.ok ? String(r.tally.total) : 'withheld'), ` yes, from ${honestYes} honest yes votes.`),
      mode === 'weak' && r.tally.ok
        ? verdict('alarm', `Every check passed and the tally is ${r.tally.total} — Mallory's one ballot counted as ${FORGED_M} yes votes.`)
        : verdict('pass', 'With the statement inside the hash, the key cannot be chosen after the challenge, and the forged ballot fails equation (5).'),
    );
  };
  weakBtn.addEventListener('click', () => show('weak'));
  strongBtn.addEventListener('click', () => show('strong'));

  root.append(
    panelIntro(
      'Weak Fiat–Shamir',
      'A non-interactive proof replaces the verifier\'s random challenge with a hash. Bernhard, Pereira and Warinschi (2012) showed that it matters what goes into that hash. The weak form hashes only the prover\'s commitments; the strong form also hashes the statement being proved — here the election key X and the ciphertext. Helios used the weak form for every proof.',
      'With the weak hash, the challenge exists before the key does. Trustees who generate the election key can choose it afterwards, as a function of the challenge, and then build a ballot that encrypts any number m with a proof that it is "0 or 1". The construction is in §3 of their paper; this exhibit runs it with m = 3.',
    ),
    h('div', { class: 'action-row spaced' }, weakBtn, ' ', strongBtn),
    out,
    note('info', 'Elections that ask for one choice among a few are less exposed, the authors note, because Helios also proves the sum of a ballot\'s choices is in range — this lab\'s single yes/no question has no such second proof. They also found that Helios\'s decryption proofs used the weak form, letting a trustee publish a wrong decryption undetected; this lab\'s decryption proof hashes the full statement.'),
    threatModel({
      attacker: 'The trustees who generate the election key, and one voter (Mallory) who casts the forged ballot.',
      access: 'Key generation, before voting starts.',
      trusted: 'Nothing beyond the proofs — that is the point of universal verifiability.',
      success: 'A ballot worth m votes passes every public check.',
      notShown: 'Whether any deployed election was affected; the authors report that all known Helios elections produced valid tallies.',
    }),
  );
}
