import { h, panelIntro } from './dom';

const link = (href: string, text: string): HTMLElement => h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text);

export function renderScopePanel(root: HTMLElement): void {
  root.append(
    panelIntro('Scope & sources', 'What this lab does not do, and where each piece comes from.'),
    h('h3', {}, 'Not covered'),
    h(
      'ul',
      { class: 'plain-list' },
      h('li', {}, 'Coercion resistance: a voter here can prove how she voted by revealing her randomness. Selene (Ryan, Rønne and Iovino, 2016) is one design that mitigates coercion.'),
      h('li', {}, 'Mixnets: shuffling encrypted ballots before decrypting them one by one. Not built here.'),
      h('li', {}, 'Threshold keys: one trustee holds the key; see Threshold Decrypt for sharing it.'),
      h('li', {}, 'Real elections, and any statement about a deployed system.'),
    ),
    h('h3', {}, 'Sources'),
    h(
      'ul',
      { class: 'plain-list sources' },
      h('li', {}, 'B. Adida, "Helios: Web-based Open-Audit Voting", 17th USENIX Security Symposium, 2008 — ballot preparation, cast-or-audit and decryption proofs (§2).'),
      h('li', {}, 'J. Benaloh, "Simple Verifiable Elections", USENIX/ACCURATE EVT 2006 — the cast-or-audit challenge (§4.2).'),
      h('li', {}, 'R. Küsters, T. Truderung, A. Vogt, "Clash Attacks on the Verifiability of E-Voting Systems", IEEE S&P 2012 (full version IACR ePrint 2012/116) — §2.2, §3.1–3.3. ', link('https://eprint.iacr.org/2012/116', 'eprint.iacr.org/2012/116')),
      h('li', {}, 'D. Bernhard, O. Pereira, B. Warinschi, "How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios", ASIACRYPT 2012 — §3 and Appendix B. ', link('https://doi.org/10.1007/978-3-642-34961-4_38', 'doi:10.1007/978-3-642-34961-4_38')),
      h('li', {}, 'R. Cramer, I. Damgård, B. Schoenmakers, "Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols", CRYPTO 1994 — the OR construction. ', link('https://doi.org/10.1007/3-540-48658-5_19', 'doi:10.1007/3-540-48658-5_19')),
      h('li', {}, 'V. Cortier, B. Smyth, "Attacking and fixing Helios: An analysis of ballot secrecy", IEEE CSF 2011. ', link('https://doi.org/10.1109/csf.2011.27', 'doi:10.1109/csf.2011.27')),
      h('li', {}, 'P. Y. A. Ryan, P. B. Rønne, V. Iovino, "Selene: Voting with Transparent Verifiability and Coercion-Mitigation", Financial Cryptography and Data Security 2016. ', link('https://doi.org/10.1007/978-3-662-53357-4_12', 'doi:10.1007/978-3-662-53357-4_12')),
      h('li', {}, 'M. Lepinski, S. Kent, RFC 5114, "Additional Diffie-Hellman Groups for Use with IETF Standards", 2008 — §2.3 and Appendix A.3. ', link('https://datatracker.ietf.org/doc/html/rfc5114', 'datatracker.ietf.org')),
    ),
  );
}
