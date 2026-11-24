import { cryptoBytes, mul, RFC5114_2048_256 as G } from '../group/modp';
import { Board } from '../election/board';
import { makeBallot, newElection, shortTracker, tracker } from '../election/election';
import { trusteeDecrypts, verifyTally, type PublishedTally } from '../election/tally';
import { verifyDecryption } from '../proofs/cpverify';
import { abbrev, checkRow, clear, h, note, panelIntro, select, selectWrap, verdict } from './dom';

export const BOARD_VOTES: readonly (0 | 1)[] = [1, 0, 1, 1, 0, 0, 1, 0];

export function boardTable(board: Board, highlight?: string): HTMLElement {
  return h(
    'div',
    { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'The bulletin board' },
    h(
      'table',
      { class: 'kat-table board-table' },
      h('caption', { class: 'sr-caption' }, 'The bulletin board'),
      h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Ballot ID'), h('th', { scope: 'col' }, 'Tracker'), h('th', { scope: 'col' }, 'R (short)'), h('th', { scope: 'col' }, '0/1 proof'))),
      h(
        'tbody',
        {},
        ...board.entries.map((en) =>
          h(
            'tr',
            { 'data-ballot': en.id, class: en.tracker === highlight ? 'row-mine' : '' },
            h('td', {}, en.id),
            h('td', {}, h('code', {}, shortTracker(en.tracker))),
            h('td', {}, h('code', {}, abbrev(en.ballot.ct.R))),
            h('td', {}, h('span', { class: 'tone tone-optimal' }, h('span', { class: 'tone-icon', 'aria-hidden': 'true' }, '✓'), h('span', {}, 'verified on entry'))),
          ),
        ),
      ),
    ),
  );
}

export function renderBoardPanel(root: HTMLElement): void {
  const e = newElection(G, 'crypto-lab-verifiable-ballot/measure-1', cryptoBytes);
  let board: Board | null = null;
  let receipts: string[] = [];
  let published: PublishedTally | null = null;

  const open = h('button', { class: 'btn btn-primary', type: 'button', id: 'board-open' }, 'Run the election: 8 voters') as HTMLButtonElement;
  const boardOut = h('div', { id: 'board-out' });
  const voterSel = select('board-voter', BOARD_VOTES.map((_, i) => [String(i), `Voter ${i + 1}`]), '0');
  const lookup = h('button', { class: 'btn btn-ghost', type: 'button', id: 'board-lookup', disabled: true }, 'Look up my tracker') as HTMLButtonElement;
  const lookupOut = h('div', { class: 'output', id: 'board-lookup-out', role: 'status', 'aria-live': 'polite' });
  const dup = h('button', { class: 'btn btn-ghost', type: 'button', id: 'board-dup', disabled: true }, 'Submit a ballot under a used ID') as HTMLButtonElement;
  const dupOut = h('div', { class: 'output', id: 'board-dup-out' });
  const tally = h('button', { class: 'btn btn-primary', type: 'button', id: 'board-tally', disabled: true }, 'Tally and verify') as HTMLButtonElement;
  const badTally = h('button', { class: 'btn btn-ghost', type: 'button', id: 'board-badtally', disabled: true }, 'A trustee publishes a wrong decryption factor') as HTMLButtonElement;
  const tallyOut = h('div', { class: 'output', id: 'board-tally-out' });

  open.addEventListener('click', () => {
    board = new Board(e);
    receipts = [];
    for (let i = 0; i < BOARD_VOTES.length; i++) {
      const { ballot } = makeBallot(e, BOARD_VOTES[i], cryptoBytes);
      const res = board.submit(`b-${String(i + 1).padStart(2, '0')}`, ballot);
      if (!res.ok) throw new Error(res.reason);
      receipts.push(tracker(ballot));
    }
    published = null;
    clear(boardOut);
    clear(lookupOut);
    clear(dupOut);
    clear(tallyOut);
    boardOut.append(h('h3', {}, 'The bulletin board'), boardTable(board));
    for (const b of [lookup, dup, tally, badTally]) b.disabled = false;
  });

  voterSel.addEventListener('change', () => {
    if (!board || !lookupOut.hasChildNodes()) return;
    clear(lookupOut);
    boardOut.replaceChildren(h('h3', {}, 'The bulletin board'), boardTable(board));
  });

  lookup.addEventListener('click', () => {
    if (!board) return;
    const i = Number(voterSel.value);
    const t = receipts[i];
    clear(boardOut);
    boardOut.append(h('h3', {}, 'The bulletin board'), boardTable(board, t));
    clear(lookupOut);
    lookupOut.append(
      h('ul', { class: 'check-list' }, checkRow(board.has(t), `Voter ${i + 1}'s tracker ${shortTracker(t)} is on the board`, 'lookup', 'supports recorded as cast')),
      note('info', 'What this check does not show: that the ballot behind the tracker encrypts your choice (that is the audit), or that nobody else was given the same tracker (that is the clash attack).'),
    );
  });

  dup.addEventListener('click', () => {
    if (!board) return;
    const res = board.submit('b-01', makeBallot(e, 1, cryptoBytes).ballot);
    clear(dupOut);
    dupOut.append(res.ok ? verdict('fail', 'UNEXPECTED: accepted.') : verdict('alarm', `Rejected: ${res.reason}.`));
  });

  const showTally = (pub: PublishedTally, label: string): void => {
    if (!board) return;
    const res = verifyTally(board, pub);
    const dv = verifyDecryption(G, e.X, board.product(), pub.T, pub.proof, e.context);
    clear(tallyOut);
    tallyOut.append(
      h('p', { class: 'help' }, label),
      h(
        'ul',
        { class: 'check-list' },
        checkRow(true, `Every ballot's 0/1 proof verified when it entered the board (${board.entries.length} ballots)`, 'tally-proofs', 'supports tallied as recorded'),
        checkRow(true, 'The product of the ballots on the board was recomputed here', 'tally-product', 'supports tallied as recorded'),
        checkRow(dv.ok, dv.ok ? 'The decryption proof verifies: T = R^x for the election key' : `The decryption proof fails: ${dv.failures.join('; ')}`, 'tally-decrypt', dv.ok ? 'supports tallied as recorded' : 'the decryption evidence failed'),
      ),
      res.ok
        ? h('div', {}, verdict('pass', `Tally: ${res.total} yes of ${board.entries.length} ballots.`), h('p', {}, 'Yes votes: ', h('strong', { 'data-claim': 'tally-total' }, String(res.total))))
        : verdict('alarm', `No tally announced: ${res.reason}.`),
    );
  };
  tally.addEventListener('click', () => {
    if (!board) return;
    published = trusteeDecrypts(board, cryptoBytes);
    showTally(published, `Product, decryption factor T and proof published by the trustee. Decrypted by recovering t from g^t = S / T.`);
  });
  badTally.addEventListener('click', () => {
    if (!board) return;
    const honest = published ?? trusteeDecrypts(board, cryptoBytes);
    showTally({ ...honest, T: mul(G, honest.T, G.g) }, 'The trustee publishes T · g instead of T, with the proof made for the true T.');
  });

  root.append(
    panelIntro(
      'Board & tally',
      'Every cast ballot goes on a public bulletin board, next to a ballot ID, with its tracker — a hash of the ballot that the voter took home as her receipt. The board admits a ballot only if its ID is new and its 0/1 proof verifies.',
      'To count, anyone multiplies all the ballots on the board. Because exponential ElGamal adds under multiplication, the product encrypts the number of yes votes. The trustee who holds the key publishes a decryption factor T = R^x with a Chaum–Pedersen proof that it used the election key; anyone checks that proof and recovers the total. No single ballot is ever decrypted.',
    ),
    h('div', { class: 'action-row spaced' }, open),
    boardOut,
    h('h3', {}, 'Recorded as cast: look up a tracker'),
    h('div', { class: 'controls' }, h('div', { class: 'control' }, h('label', { for: 'board-voter' }, 'Which voter are you?'), selectWrap(voterSel))),
    h('div', { class: 'action-row spaced' }, lookup, ' ', dup),
    lookupOut,
    dupOut,
    h('h3', {}, 'Tallied as recorded'),
    h('div', { class: 'action-row spaced' }, tally, ' ', badTally),
    tallyOut,
    note('caveat', 'Mixnet tallying — shuffling the ballots and decrypting each one, as Helios 1.0 did — is not built here; this board uses the homomorphic tally.'),
  );
}
