import { validateGroup, RFC5114_2048_256 } from '../group/modp';
import { h, note, panelIntro } from './dom';

export function renderIntroPanel(root: HTMLElement): void {
  const problems = validateGroup(RFC5114_2048_256);
  root.append(
    panelIntro(
      'Why verifiable',
      'A secret ballot hides how you voted. That is also what makes it hard to check: if nobody may see your vote, how do you know it was counted, and counted as you cast it? End-to-end verifiable voting answers with mathematics. Ballots are encrypted, posted on a public bulletin board, and added up while still encrypted; only the total is ever decrypted, and every step comes with a proof anyone can check.',
      'But each check covers one step. This lab is organised around the three steps and shows, for each, an attack that lives in the gap between them.',
    ),
    h(
      'div',
      { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'The three verifiability properties' },
      h(
        'table',
        { class: 'kat-table', id: 'properties' },
        h('caption', { class: 'sr-caption' }, 'The three verifiability properties'),
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Property'), h('th', { scope: 'col' }, 'Who checks, and how'), h('th', { scope: 'col' }, 'What the check does not cover'))),
        h(
          'tbody',
          {},
          h('tr', {}, h('th', { scope: 'row' }, 'Cast as intended'), h('td', {}, 'The voter audits a ballot: the device reveals its randomness and she re-encrypts her choice (Audit tab).'), h('td', {}, 'The ballot she actually casts — an audited ballot is spoiled. Only random audits keep the device honest.')),
          h('tr', {}, h('th', { scope: 'row' }, 'Recorded as cast'), h('td', {}, 'The voter looks up her tracker — a hash of her ballot — on the public board (Board & tally tab).'), h('td', {}, 'Whether anyone else holds the same tracker (Clash attack tab).')),
          h('tr', {}, h('th', { scope: 'row' }, 'Tallied as recorded'), h('td', {}, 'Anyone multiplies the ballots on the board, checks every 0/1 proof and the decryption proof (Board & tally tab).'), h('td', {}, 'Proofs whose hash leaves out what they prove (Weak Fiat–Shamir tab).')),
        ),
      ),
    ),
    h(
      'p',
      { class: 'help', id: 'group-status' },
      problems.length
        ? `Group check FAILED: ${problems.join('; ')}.`
        : 'Group: RFC 5114 §2.3 — a 2048-bit prime p with a 256-bit prime-order subgroup. Checked on load: q divides p − 1 and g has order q. Every element received is checked to lie in that subgroup.',
    ),
    note(
      'caveat',
      'Not production software — a teaching demo, and not a statement about any deployed voting system. The cryptography is real (exponential ElGamal over the RFC 5114 group, SHA-256 Fiat–Shamir proofs); the elections are small and simulated in your browser.',
    ),
  );
}
