# Claims and their evidence — Verifiable Ballot

Batch requirement 1. Every claim the page makes, how it is produced, the test that pins it, the source, and how far it can be read.

| Claim | Execution mode | Evidence (test name) | Source | Interpretation limit |
|---|---|---|---|---|
| The group is RFC 5114 §2.3: p and q prime, q divides p − 1, g of order q | computed | unit `RFC 5114 §2.3: the structural checks pass`, `p and q are (probable) primes`, `RFC 5114 Appendix A.3 test vector: g^xA = yA` | RFC 5114 §2.3, App. A.3 | Probable primality (24 Miller–Rabin bases) |
| Every element received is in the order-q subgroup; scalars are in [0, q) | computed | unit `subgroup membership refuses…`, `elements outside the subgroup and scalars outside [0, q) are refused…` | — | — |
| A ballot's 0/1 proof verifies, by the five equations of BPW App. B with a strong hash | computed | unit `1,000 seeded ballots, v ∈ {0, 1}: every proof verifies`; claims `a cast ballot: the five equations re-checked here…` | BPW 2012 App. B; Cramer–Damgård–Schoenmakers 1994 | A proof of well-formedness, not of the voter's intent |
| No proof for an encryption of 2: the honest prover refuses; malformed and forged transcripts fail | computed | unit `the honest prover refuses…`, `every field … perturbed, fails…`, `curated forgery attempts for an encryption of 2` (F1–F6); claims `a ballot encrypting 2…` | — | Six named forgery attempts, not a soundness proof |
| The tally equals the number of yes votes, and is announced only if the decryption proof verifies | computed | unit `101 random ballots…`, `an invalid decryption proof: the tally is withheld…`; claims `the board: 8 ballots…` | Helios 2008 §2 (Chaum–Pedersen decryption proof) | One trustee; no threshold |
| A voter finds her tracker on the board; a used ballot ID is refused | computed | unit `a duplicate ballot ID is rejected`; claims `the board…` | Helios 2008 §2.1, §2.4 | Says nothing about who else holds the tracker |
| An audit catches a device that changed the vote; an honest device passes | computed | unit `a device that always flips is caught by the first audit…`, `an honest device passes every audit…`; claims `audit: …` | Benaloh 2006 §4.2.1; Helios 2008 §2.1 | Audited ballots are spoiled; the cast ballot is not checked |
| P(caught on one ballot) = a · f | computed (exact) | unit `P(caught in one round) = a · f, exactly`; claims `P(caught in one round) printed is a · f…` | Benaloh 2006 §4 (the device cannot tell who audits) | Assumes the device cannot predict audits |
| The audit simulation agrees with a · f | simulated model (crypto.getRandomValues) | displayed with N and a 95% Wilson interval, not gated | — | Observed in one run |
| Clash fixture: every check passes and the tally is 2 of 3 | computed | unit `D. Clash attack fixture…` (four tests); claims `the negative claim: every check passed and a vote is missing` | Küsters–Truderung–Vogt §3.2 | Needs a dishonest device AND board; the original Helios (names beside ballots) is immune (§3.1) |
| Comparing receipts reveals the clash | computed | unit `V1 and V2 hold the same receipt…`; claims `clash: V1 and V2 printed the same receipt…` | KTV §2.3, §3.3 | Not part of the voting procedure |
| With the weak hash, trustees forge a "0 or 1" proof for an encryption of 3; the strong hash rejects it | computed | unit `E. Weak Fiat–Shamir…` (four tests); claims `weak Fiat–Shamir: …` | BPW 2012 §3 | Requires corrupt trustees who choose the key |
| Weak-hash ballots can be rerandomised; strong-hash ballots cannot | computed | unit `BPW §3 rerandomisation…` | BPW 2012 §3 | — |
| The shipped randomness is crypto.getRandomValues; no UI module imports the seeded test generator | computed | unit `the shipped byte source…`, `the shipped default RNG…`, `no UI module imports…` | batch requirement 3 | — |
