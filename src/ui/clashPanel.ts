import { cryptoBytes, RFC5114_2048_256 as G } from '../group/modp';
import { receiptsCollide, runClash } from '../attacks/clash';
import { newElection, shortTracker } from '../election/election';
import { boardTable } from './boardPanel';
import { brokenBadge, checkRow, clear, h, note, panelIntro, threatModel, verdict } from './dom';

export function renderClashPanel(root: HTMLElement): void {
  const e = newElection(G, 'crypto-lab-verifiable-ballot/measure-1', cryptoBytes);
  const run = runClash(e, cryptoBytes);
  const compare = h('button', { class: 'btn btn-ghost', type: 'button', id: 'clash-compare' }, 'Have the voters compare receipts') as HTMLButtonElement;
  const compareOut = h('div', { class: 'output', id: 'clash-compare-out', role: 'status', 'aria-live': 'polite' });
  compare.addEventListener('click', () => {
    const hit = receiptsCollide(run.voters);
    clear(compareOut);
    compareOut.append(
      hit
        ? verdict('alarm', `DETECTED: ${hit[0]} and ${hit[1]} hold the same receipt, ${shortTracker(run.voters[0].receipt)}. Two voters cannot have cast the same ballot.`)
        : verdict('pass', 'No two receipts are the same.'),
      note('info', 'Nothing in the voting procedure asks voters to do this, and comparing receipts naively costs privacy. The paper\'s fixes (§3.3): let each voter add her own random string to the encryption randomness, or have voters check that every ballot the device makes for them is different.'),
    );
  });

  const t = run.tally;
  const fixture = h(
    'div',
    { class: 'fixture-card', id: 'clash-fixture' },
    brokenBadge('Broken mode: a dishonest device and a dishonest bulletin board. Never the default.'),
    h('h3', {}, 'Three voters, three yes votes'),
    h(
      'div',
      { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Each voter and her receipt' },
      h(
        'table',
        { class: 'kat-table', id: 'clash-voters' },
        h('caption', { class: 'sr-caption' }, 'Each voter, her vote and her receipt'),
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Voter'), h('th', { scope: 'col' }, 'Vote'), h('th', { scope: 'col' }, 'Receipt (tracker)'))),
        h('tbody', {}, ...run.voters.map((v) => h('tr', { 'data-voter': v.name }, h('th', { scope: 'row' }, v.name), h('td', {}, v.vote === 1 ? 'Yes' : 'No'), h('td', {}, h('code', {}, shortTracker(v.receipt)))))),
      ),
    ),
    h('p', {}, 'Names published (detached from the ballots): ', h('strong', { 'data-claim': 'clash-names' }, run.board.names.join(', '))),
    h('h4', {}, 'The bulletin board'),
    boardTable(run.board),
    h(
      'ul',
      { class: 'check-list', id: 'clash-checks' },
      ...run.voters.map((v) => checkRow(v.finds, `${v.name} finds her receipt on the board`, `clash-find-${v.name}`, 'recorded as cast')),
      checkRow(run.proofsOk, 'Every ballot\'s 0/1 proof verifies', 'clash-proofs', 'tallied as recorded'),
      checkRow(run.distinctIds, 'No ballot ID appears twice on the board', 'clash-ids'),
      checkRow(run.distinctTrackers, 'No tracker appears twice on the board', 'clash-trackers'),
      checkRow(run.ballotsMatchNames, `One ballot for each listed voter (${run.board.entries.length} ballots, ${run.board.names.length} names)`, 'clash-count'),
      checkRow(t.ok, t.ok ? 'The decryption proof verifies' : `The tally does not verify: ${t.reason}`, 'clash-decrypt', 'tallied as recorded'),
    ),
    h('p', {}, 'Published tally: ', h('strong', { 'data-claim': 'clash-tally' }, t.ok ? String(t.total) : 'withheld'), ' yes · votes actually cast: ', h('strong', { 'data-claim': 'clash-cast' }, String(run.votesCast))),
    h(
      'div',
      { class: 'callout callout-danger negative-claim', 'data-negative-claim': 'clash' },
      h('p', { class: 'negative-claim-title' }, h('span', { 'aria-hidden': 'true' }, '⚠ '), 'EVERY CHECK PASSED — AND A VOTE IS MISSING'),
      h('p', {}, 'Every voter\'s personal check passed and the published tally verifies. Individual verification does not prove each voter saw a different ballot — two voters can be shown the same one.'),
      h(
        'p',
        {},
        'The device gave V1 and V2 the same ballot, so one copy on the board satisfies both. The board replaced the other copy with an encryption of 0 that it made itself — a perfectly valid ballot — so the count of ballots still matches the list of voters.',
      ),
    ),
  );

  root.append(
    panelIntro(
      'The clash attack',
      'Küsters, Truderung and Vogt pointed out a gap between "my ballot is on the board" and "my vote counted". If a dishonest device gives two voters who chose the same answer the very same ballot — same randomness, same ciphertext, same receipt — then one copy on the board satisfies both of them. The board is then free to replace the other copy with anything it likes.',
      'It works even when everyone knows exactly who voted and how many ballots there should be, and it needs no broken cryptography: every proof below is genuine.',
    ),
    fixture,
    h('div', { class: 'action-row spaced' }, compare),
    compareOut,
    note('info', 'Where it does not work: the original Helios published each voter\'s name next to her ballot, so two voters cannot share one entry — the paper finds that variant immune (§3.1). The attack applies to variants that publish ballots under aliases or with the names detached (§3.2), and to Wombat (§2).'),
    threatModel({
      attacker: 'The ballot-preparation device and the bulletin board, working together; the tally is computed honestly.',
      access: 'The device sees each voter\'s choice; the board decides what it publishes.',
      trusted: 'The decryption key holder, and every proof checker.',
      success: 'Every voter\'s check passes, every proof verifies, and the tally is not the votes cast.',
      notShown: 'How often a real device could get away with it, or anything about a deployed system.',
    }),
  );
}
