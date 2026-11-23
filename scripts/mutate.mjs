#!/usr/bin/env node
/*
 * Mutation runner (§4.1c). Every mutation is a CONCRETE PATCH — file, an anchor
 * that must occur exactly once, its replacement — never a sentence. A KILL is
 * defined by four rules, all enforced here:
 *   1. the owning test PASSED unmutated, in this same run;
 *   2. the patch actually CHANGED the file (anchor found exactly once);
 *   3. the run served the MUTATED code — the built bundle's hash moved;
 *   4. a patch that does not compile is DOES NOT BUILD, never a kill.
 * A red run whose output is a build error, a server that never started or a
 * refused connection is classified, not counted. Playwright runs with CI=1 so
 * `reuseExistingServer` is off and no stale server can answer.
 *
 * The records in mutations/observed.json are written by this script from what
 * it ran. Nothing in that file is typed by hand.
 *
 * Usage: node scripts/mutate.mjs            all mutations
 *        node scripts/mutate.mjs M03 M07    selected ids
 */
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

// Both runners treat the name as a REGULAR EXPRESSION. An unescaped "[00]" in a
// test name once matched nothing, ran zero tests and passed — the §4.1e hazard —
// so names are escaped here AND every owner run must report a nonzero count.
const re = (name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const UNIT = (name) => `npx vitest run -t ${JSON.stringify(re(name))}`;
// --retries=0: a retry that passes on a lucky draw would read as a survivor.
const CLAIM = (name) => `npx playwright test --project=claims --retries=0 -g ${JSON.stringify(re(name))}`;
const A11Y = `npx playwright test --project=a11y --retries=0 -g "dark theme$"`;

export const MUTATIONS = [
  {
    id: 'M01', what: 'OR-proof challenge split not enforced: c0 + c1 = c never checked (brief F1)',
    file: 'src/proofs/orverify.ts',
    anchor: 'modq(G, pf.c0 + pf.c1) === zeroOneChallenge(G, mode, context, X, ct, pf),',
    replace: 'modq(G, pf.c0 + pf.c1) === zeroOneChallenge(G, mode, context, X, ct, pf) || true,',
    owner: UNIT('F3: both branches simulated'),
  },
  {
    id: 'M02', what: 'tally multiplies only the first component; S is kept from one ballot (brief F2)',
    file: 'src/elgamal/exp.ts',
    anchor: '    S = mul(G, S, c.S);',
    replace: '    if (S === 1n) S = c.S;',
    owner: UNIT('101 random ballots'),
  },
  {
    id: 'M03', what: 'decryption proof skips equation (b) R^f = B·T^c (brief F3)',
    file: 'src/proofs/cpverify.ts',
    anchor: "  if (exp(G, ct.R, pf.f) !== mul(G, pf.B, exp(G, T, pf.c))) failures.push('equation (b) R^f = B·T^c fails');\n",
    replace: '',
    owner: UNIT('a transcript where only equation (b) fails is rejected'),
  },
  {
    id: 'M04', what: 'audit reveals the randomness of a different ballot (brief F4)',
    file: 'src/election/audit.ts',
    anchor: 'return p.secret.r;',
    replace: 'return p.secret.r + 1n;',
    owner: UNIT('an honest device passes every audit'),
  },
  {
    id: 'M05', what: 'negative-claim sentence deleted from the clash fixture (§4.1d bite, assertion 3)',
    file: 'src/ui/clashPanel.ts',
    anchor: "h('p', {}, 'Every voter\\'s personal check passed and the published tally verifies. Individual verification does not prove each voter saw a different ballot — two voters can be shown the same one.'),",
    replace: '',
    owner: CLAIM('the negative claim: every check passed and a vote is missing'),
  },
  {
    id: 'M06', what: 'a check inside the fixture broken: "one ballot per listed voter" miscounts (§4.1d bite, assertion 2)',
    file: 'src/attacks/clash.ts',
    anchor: 'ballotsMatchNames: board.entries.length === board.names.length,',
    replace: 'ballotsMatchNames: board.entries.length === board.names.length + 1,',
    owner: CLAIM('the negative claim: every check passed and a vote is missing'),
  },
  {
    id: 'M07', what: 'changing the choice no longer retires the shown ballot',
    file: 'src/ui/castPanel.ts',
    anchor: "  yes.addEventListener('change', retire);\n  no.addEventListener('change', retire);\n",
    replace: '  void retire; // still referenced, so the patch compiles\n',
    owner: CLAIM('changing the choice retires the shown ballot'),
  },
  {
    id: 'M08', what: 'changing the device no longer retires the prepared ballot',
    file: 'src/ui/auditPanel.ts',
    anchor: 'for (const el of [flipSel, yes, no]) el.addEventListener',
    replace: 'for (const el of [yes, no]) el.addEventListener',
    owner: CLAIM('changing the device retires the prepared ballot'),
  },
  {
    id: 'M09', what: 'strong challenge drops the ciphertext (R, S) from the hash',
    file: 'src/proofs/challenge.ts',
    anchor: "[DOMAIN, 'zero-one', context, G.g, X, ct.R, ct.S, k.A0, k.B0, k.A1, k.B1]",
    replace: "[DOMAIN, 'zero-one', context, G.g, X, ...(ct ? [] : []), k.A0, k.B0, k.A1, k.B1]", // ct stays referenced so the patch compiles
    owner: UNIT('BPW §3 rerandomisation'),
  },
  {
    id: 'M10', what: 'subgroup membership check reduced to a range check',
    file: 'src/group/modp.ts',
    anchor: "return typeof x === 'bigint' && x >= 1n && x < G.p && modpow(x, G.q, G.p) === 1n;",
    replace: "return typeof x === 'bigint' && x >= 1n && x < G.p;",
    owner: UNIT('subgroup membership refuses'),
  },
  {
    id: 'M11', what: 'honest prover no longer refuses v ∉ {0, 1}',
    file: 'src/proofs/orproof.ts',
    anchor: 'if (v !== 0n && v !== 1n) throw',
    replace: 'if (false && v !== 0n && v !== 1n) throw',
    owner: UNIT('the honest prover refuses to prove v = 2'),
  },
  {
    id: 'M12', what: 'duplicate ballot IDs accepted',
    file: 'src/election/board.ts',
    anchor: "    if (this.entries.some((e) => e.id === id)) return { ok: false, reason: `ballot ID ${id} is already on the board` };\n",
    replace: '',
    owner: UNIT('a duplicate ballot ID is rejected'),
  },
  {
    id: 'M13', what: 'shipped byte source swapped for Math.random',
    file: 'src/group/modp.ts',
    anchor: 'export const cryptoBytes: ByteSource = (n) => crypto.getRandomValues(new Uint8Array(n));',
    replace: 'export const cryptoBytes: ByteSource = (n) => Uint8Array.from({ length: n }, () => Math.floor(Math.random() * 256));',
    owner: UNIT('the shipped byte source for keys and nonces is crypto.getRandomValues'),
  },
  {
    id: 'M14', what: 'tracker hashes the ciphertext only, not the proof',
    file: 'src/election/election.ts',
    anchor: "digestHex(['tracker', b.ct.R, b.ct.S, p.A0, p.B0, p.A1, p.B1, p.c0, p.c1, p.f0, p.f1])",
    replace: "digestHex(['tracker', b.ct.R, b.ct.S, p.A0 * 0n])",
    owner: CLAIM('a cast ballot: the five equations re-checked here'),
  },
  {
    id: 'M15', what: 'gate bite: muted text token darkened below 4.5:1',
    file: 'src/style.css',
    anchor: '--text-dim: #b3bdc8;',
    replace: '--text-dim: #4a525c;',
    owner: A11Y,
  },
];

const sh = (cmd) => {
  try {
    return { ok: true, out: execSync(cmd, { encoding: 'utf8', stdio: 'pipe', env: { ...process.env, CI: '1' }, maxBuffer: 64 << 20 }) };
  } catch (e) {
    return { ok: false, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
};
const bundleHash = () => {
  const dir = join('dist', 'assets');
  const h = createHash('md5');
  for (const f of readdirSync(dir).sort()) h.update(f).update(readFileSync(join(dir, f)));
  return h.digest('hex');
};
/** Tests actually executed, from the runner's own summary line; 0 means the run proved nothing. */
const testsRan = (out) => {
  const v = /Tests\s+(?:\d+ failed \| )?(\d+) passed/.exec(out) ?? /Tests\s+(\d+) failed/.exec(out);
  const p = /(\d+) passed \(/.exec(out) ?? /(\d+) failed/.exec(out);
  return Number((v ?? p)?.[1] ?? 0);
};
const INFRA = /webServer|ECONNREFUSED|was not able to start|Error: Cannot find module|error TS\d+/;

const wanted = process.argv.slice(2);
const list = wanted.length ? MUTATIONS.filter((m) => wanted.includes(m.id)) : MUTATIONS;

const build0 = sh('npm run build');
if (!build0.ok) throw new Error('baseline build fails; refusing to mutate');
const baseHash = bundleHash();
const ownerBaseline = new Map();
for (const owner of new Set(list.map((m) => m.owner))) {
  const r = sh(owner);
  const n = testsRan(r.out);
  ownerBaseline.set(owner, r.ok && n > 0);
  console.log(`baseline ${r.ok ? 'PASS' : 'FAIL'} (${n} test${n === 1 ? '' : 's'})  ${owner}`);
}

const records = [];
for (const m of list) {
  const src = readFileSync(m.file, 'utf8');
  const count = src.split(m.anchor).length - 1;
  const rec = { id: m.id, what: m.what, file: m.file, owner: m.owner, ownerPassedUnmutated: ownerBaseline.get(m.owner) };
  if (count !== 1) {
    records.push({ ...rec, result: `ANCHOR FOUND ${count} TIMES` });
    console.log(`${m.id} ANCHOR FOUND ${count} TIMES`);
    continue;
  }
  const mutated = src.replace(m.anchor, m.replace);
  writeFileSync(m.file, mutated);
  try {
    const b = sh('npm run build');
    if (!b.ok) {
      records.push({ ...rec, result: 'DOES NOT BUILD' });
      console.log(`${m.id} DOES NOT BUILD`);
      continue;
    }
    const h = bundleHash();
    const t = sh(m.owner);
    const infra = !t.ok && INFRA.test(t.out);
    const killed = rec.ownerPassedUnmutated && h !== baseHash && !t.ok && !infra;
    const result = killed ? 'KILLED' : infra ? 'INCONCLUSIVE (infrastructure failure)' : h === baseHash ? 'INCONCLUSIVE (bundle unchanged)' : 'SURVIVED';
    const failLine = t.out.split('\n').find((l) => /✘|FAIL|AssertionError|Expected|expect\(/.test(l)) ?? '';
    records.push({ ...rec, bundleHashChanged: h !== baseHash, ownerFailedMutated: !t.ok, result, evidence: failLine.trim().slice(0, 240) });
    console.log(`${m.id} ${result}  ${m.what}`);
  } finally {
    writeFileSync(m.file, src);
  }
}
const restored = sh('npm run build');
const restoredHash = restored.ok ? bundleHash() : 'BUILD FAILED';
const summary = {
  ranAt: new Date().toISOString(),
  baselineBundle: baseHash,
  restoredBundleMatches: restoredHash === baseHash,
  killed: records.filter((r) => r.result === 'KILLED').length,
  total: records.length,
  records,
};
mkdirSync('mutations', { recursive: true });
if (!wanted.length) writeFileSync('mutations/observed.json', JSON.stringify(summary, null, 2) + '\n');
console.log(`\n${summary.killed}/${summary.total} killed; restored bundle matches baseline: ${summary.restoredBundleMatches}`);
if (summary.killed !== summary.total || !summary.restoredBundleMatches) process.exit(1);
