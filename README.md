# Verifiable Ballot

**Homomorphic tally · disjunctive Chaum–Pedersen · Benaloh challenge**

Browser-based end-to-end verifiable voting — encrypted ballots, zero-knowledge proofs that each ballot is 0 or 1, a homomorphic tally decrypted with a proof, and the cast-or-audit challenge side by side, with a cheating voting device caught by an audit and a clash attack shown fooling individual verification.

## What It Is

A Helios-style election in the browser, organised around the three things a verifiable election lets people check:

- **Cast as intended** — the Benaloh challenge. The device encrypts the voter's choice and commits to it by showing the ballot's tracker; only then does the voter choose to cast it or audit it. An audit reveals the randomness and the voter's own tool re-encrypts her choice.
- **Recorded as cast** — the voter looks up her tracker (a SHA-256 hash of her ballot) on the public bulletin board.
- **Tallied as recorded** — every ballot carries a disjunctive Chaum–Pedersen proof that it encrypts 0 or 1; anyone multiplies the ballots (exponential ElGamal adds under multiplication) and checks the trustee's Chaum–Pedersen proof of the decryption.

Primitives: exponential ElGamal over the RFC 5114 §2.3 group (2048-bit p, 256-bit prime-order subgroup), the disjunctive Chaum–Pedersen 0/1 proof exactly as Helios builds it (Bernhard–Pereira–Warinschi, Appendix B) but with a strong Fiat–Shamir hash, a Chaum–Pedersen decryption proof, SHA-256 (`@noble/hashes`). Security model: one trustee holds the key; the attack exhibits name their own threat model. The verifier modules (`orverify.ts`, `cpverify.ts`) are separate from the provers and do not import them. **Not production software — a teaching demo**, and not a statement about any deployed system.

### Exact encodings

- Every hash input is a list of fields; each field is a 4-byte big-endian length followed by its bytes — UTF-8 for strings, minimal big-endian for integers (0 is one 0x00 byte).
- 0/1 proof challenge (strong, the default): SHA-256 of `"crypto-lab-verifiable-ballot/v1", "zero-one", context, g, X, R, S, A0, B0, A1, B1`, read as a big-endian integer, mod q. The weak form, used only in the Weak Fiat–Shamir exhibit, hashes `A0, B0, A1, B1` alone, as Helios did.
- Decryption proof challenge: `"crypto-lab-verifiable-ballot/v1", "decrypt", context, g, X, R, S, T, A, B`.
- Tracker: SHA-256 of `"tracker", R, S, A0, B0, A1, B1, c0, c1, f0, f1`; the page shows its first 16 hex digits.
- Ballot: (R, S) = (g^r, g^v · X^r), v ∈ {0, 1}. Scalars are drawn by rejection sampling 32 bytes from `crypto.getRandomValues`.

## Exhibits

1. **Why verifiable** — the three properties, who checks each, and what each check does not cover.
2. **Cast a ballot** — encrypt yes or no, see the five proof equations hold, and try a ballot that encrypts 2.
3. **Board & tally** — eight voters, a tracker lookup, a used ballot ID refused, a verified tally and a withheld one.
4. **Audit** — a device that changes votes, caught by cast-or-audit; P(caught) = a · f and a simulation with N and a 95% interval.
5. **Clash attack** — three voters, one shared receipt, every check green and a vote missing.
6. **Weak Fiat–Shamir** — the Bernhard–Pereira–Warinschi forgery: a ballot worth 3 votes passes with the weak hash and fails with the strong one.
7. **Scope & sources.**

## When to Use It

- To see what each verification step proves, and what it leaves open.
- To watch a cast-or-audit challenge catch a dishonest device.
- To understand why Fiat–Shamir hashes must include the statement.
- **Do NOT** use this as voting software, or to judge any real election system.
- **Do NOT** read a passing check here as "secure": every exhibit says which property it supports and which it does not.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-verifiable-ballot/

Cast an encrypted ballot, check the tally, catch a cheating device with an audit, watch a clash attack pass every voter's check, and forge a 0/1 proof against the weak hash.

## What Can Go Wrong

Voters can check that their ballot was counted, and anyone can check the tally, without anyone learning how a voter voted. The checks are mathematics — but each check covers a specific step, and attacks live in the steps no one checks.

## Real-World Usage

- Helios (Adida, USENIX Security 2008) is a web-based open-audit voting system built on Benaloh's cast-or-audit approach; its 2008 version tallied with a mixnet.
- Küsters, Truderung and Vogt (IEEE S&P 2012) showed clash attacks on Wombat voting, used in an election at an Israeli college, and on Helios variants with aliases or detached names; they found the original Helios immune.
- Bernhard, Pereira and Warinschi (ASIACRYPT 2012) showed that Helios used the weak Fiat–Shamir transformation in all its proofs, and report that all known Helios elections produced a valid tally.

## How to Run Locally

```bash
npm ci
npm run dev          # http://localhost:5173/crypto-lab-verifiable-ballot/
npm test             # unit tests and KATs (Vitest)
npm run test:e2e:all # accessibility gate + claims suite (Playwright, builds first)
npm run test:mutations
```

## Related Demos

- [Threshold Decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/) — its Election Tally exhibit covers 0/1-proof ballots, a threshold-decrypted tally and receipt-freeness.
- [ElGamal Plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/) — ElGamal and its homomorphism.
- [ZK Proof Lab](https://systemslibrarian.github.io/crypto-lab-zk-proof-lab/) — zero-knowledge proofs.
- [Commit Gate](https://systemslibrarian.github.io/crypto-lab-commit-gate/) — commitments.
- [Silent Tally](https://systemslibrarian.github.io/crypto-lab-silent-tally/) and [Proof Tally](https://systemslibrarian.github.io/crypto-lab-proof-tally/) — private sums by secret sharing.

## Build & Verify

- **Unit tests (Vitest): 48 tests**, including:
  - Group: RFC 5114 §2.3 structure, p and q probable primes, and the RFC's Appendix A.3 vector g^xA = yA.
  - Encodings: fixed byte strings for the field encoding and SHA-256 checked against node:crypto.
  - A. Soundness: 1,000 seeded 0/1 ballots verify; the honest prover refuses v = 2 and v = −1; every one of the eight proof fields, the ciphertext, the key and the context, perturbed, fails; six named forgery attempts for an encryption of 2 fail.
  - B. Tally: 101 random ballots decrypt to the count of ones, also checked as S / R^x = g^count.
  - C. Audit: an always-flipping device is caught on the first audit; an honest one passes; P = a · f exactly.
  - D. Clash fixture: every receipt found, every proof valid, IDs and trackers distinct, three ballots for three names, tally 2 of 3, and the receipt collision.
  - E. Weak Fiat–Shamir: the BPW forgery passes the weak verifier for m = 3 and m = −2 and fails the strong one at equation (5) only; BPW's rerandomisation works only against the weak hash.
  - G. Fail-closed: a ballot encrypting 2, a duplicate ballot ID, an invalid decryption proof (tally withheld), and a strong-hash board by default.
- **Claims suite (Playwright): 10 tests** — the cast ballot's five equations and its tracker recomputed from the printed hex with code written in the test, the tally, the audit, both retirements, the weak and strong Fiat–Shamir runs, and the negative claim in its fixture (§4.1d).
- **Maintenance controls: 12 tests** on the workflow, pinning and provenance, run before every build.
- **Mutation ledger: 15 of 15 killed** — the brief's four (challenge split not enforced; only one tally component multiplied; a decryption equation skipped; the audit revealing a different ballot's randomness), the two §4.1d bites, two retirement mutations, the strong hash losing the ciphertext, the subgroup check, the prover's refusal, duplicate IDs, the byte source, the tracker's inputs, and one proving the accessibility gate bites. Run by `scripts/mutate.mjs`; its record is `mutations/observed.json`.
- **Accessibility gate:** axe-core WCAG 2.1 A/AA plus arithmetic contrast, non-text contrast, reflow at 380px, scroll-region and focus oracles over every driven state at desktop and phone width. Zero violations.

## Claim-to-evidence table

The full table is in [claims.md](claims.md): claim, execution mode, the test that pins it, the source section and its interpretation limit. Deterministic correctness, source KATs and property tests gate CI; the audit simulation is displayed with N and a 95% interval and never gates.

## Negative claim

> Every voter's personal check passed and the published tally verifies. Individual verification does not prove each voter saw a different ballot — two voters can be shown the same one.

Evidence fixture (the Clash attack tab): V1, V2 and V3 all vote yes. The device gives V1 and V2 the same ballot; the board keeps one copy and replaces the other with an encryption of 0 it made itself. Three names, three ballots, every receipt found, every proof valid, no repeated ballot ID or tracker, a valid decryption proof — and a tally of 2, under **EVERY CHECK PASSED — AND A VOTE IS MISSING**.

## Notes on the brief

- **Clash fixture corrected.** The brief's fixture had the board record two ballots. In the paper's attack (§2.2, §3.2) the board *replaces* the duplicate with a ballot of its choice, so the number of ballots still matches the voters — that is why the attack survives even when everyone knows who voted. The fixture follows the paper.
- **Which Helios.** Helios 2008 (Adida) tallied with a mixnet and proved decryptions with Chaum–Pedersen. The disjunctive 0/1 proof is the one later Helios versions used, transcribed from Bernhard–Pereira–Warinschi, Appendix B.
- **Benaloh's audit** in the 2006 paper has the device decrypt the audited ballot (§4.2.1); Helios instead reveals the randomness (§2.1). This lab does what Helios does.

## Performance

Making a ballot takes about 17 ms and verifying it about 27 ms (Node 22, RFC 5114 group, BigInt arithmetic); the largest exhibit makes and verifies eight ballots, so everything runs on the main thread. The audit simulation draws two numbers per round.

## Non-goals

Coercion resistance (see Selene), mixnets (marked as an extension point, not built), threshold keys, real elections, and any statement about a deployed system.

## Sources

- B. Adida, "Helios: Web-based Open-Audit Voting", 17th USENIX Security Symposium, 2008 — §2.
- J. Benaloh, "Simple Verifiable Elections", USENIX/ACCURATE EVT 2006 — §4.2.
- R. Küsters, T. Truderung, A. Vogt, "Clash Attacks on the Verifiability of E-Voting Systems", IEEE S&P 2012; full version IACR ePrint 2012/116 — https://eprint.iacr.org/2012/116
- D. Bernhard, O. Pereira, B. Warinschi, "How not to Prove Yourself: Pitfalls of the Fiat-Shamir Heuristic and Applications to Helios", ASIACRYPT 2012 — https://doi.org/10.1007/978-3-642-34961-4_38
- R. Cramer, I. Damgård, B. Schoenmakers, "Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols", CRYPTO 1994 — https://doi.org/10.1007/3-540-48658-5_19
- V. Cortier, B. Smyth, "Attacking and fixing Helios: An analysis of ballot secrecy", IEEE CSF 2011 — https://doi.org/10.1109/csf.2011.27
- P. Y. A. Ryan, P. B. Rønne, V. Iovino, "Selene: Voting with Transparent Verifiability and Coercion-Mitigation", Financial Cryptography and Data Security 2016 — https://doi.org/10.1007/978-3-662-53357-4_12
- M. Lepinski, S. Kent, RFC 5114, "Additional Diffie-Hellman Groups for Use with IETF Standards", 2008 — https://datatracker.ietf.org/doc/html/rfc5114

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
