import { createHash } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { boot } from './gate';

/**
 * The claims suite (§4.1b): what the page SAYS, re-derived here by a route the
 * source does not take. The group arithmetic, the hash encoding and the proof
 * equations below are written separately from src/.
 */

// RFC 5114 §2.3 p and g, typed from the RFC (checked there against Appendix A.3).
const P = BigInt('0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597');
const Q = BigInt('0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3');
const G = BigInt('0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659');

const pw = (b: bigint, e: bigint): bigint => {
  let r = 1n;
  b %= P;
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
  }
  return r;
};
const inv = (a: bigint): bigint => pw(a, P - 2n); // Fermat, p prime — a different route from src's extended Euclid
/** The README's encoding: each field a 4-byte big-endian length then its bytes; integers minimal big-endian. */
const field = (f: string | bigint): Buffer => {
  let body: Buffer;
  if (typeof f === 'string') body = Buffer.from(f, 'utf8');
  else {
    let hx = f.toString(16);
    if (hx.length % 2) hx = `0${hx}`;
    body = Buffer.from(hx, 'hex');
  }
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length);
  return Buffer.concat([len, body]);
};
const sha = (fields: (string | bigint)[]): string => createHash('sha256').update(Buffer.concat(fields.map(field))).digest('hex');

async function openTab(page: Page, name: RegExp): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
}
const text = async (page: Page, sel: string): Promise<string> => (await page.locator(sel).first().innerText()).trim();

test.describe('displayed claims', () => {
  test('a cast ballot: the five equations re-checked here, and the tracker is SHA-256 of the printed ballot', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /Cast a ballot/);
    await page.locator('#cast-run').click();
    await expect(page.locator('#cast-out .verdict-pass')).toHaveCount(1);
    await page.locator('#cast-fields > summary').click();
    const rows = await page.locator('#cast-fields .field').evaluateAll((els) => els.map((e) => [e.querySelector('.field-label')!.textContent!.trim(), e.querySelector('code')!.textContent!.trim()]));
    const v = Object.fromEntries(rows.map(([k, x]) => [k.split(' ')[0] === 'Election' ? 'X' : k.split(' ')[0], BigInt(`0x${x}`)])) as Record<string, bigint>;
    const { X, R, S, A0, B0, A1, B1, c0, c1, f0, f1 } = v;
    expect(pw(G, f0)).toBe((A0 * pw(R, c0)) % P);
    expect(pw(G, f1)).toBe((A1 * pw(R, c1)) % P);
    expect(pw(X, f0)).toBe((B0 * pw(S, c0)) % P);
    expect(pw(X, f1)).toBe((B1 * pw((S * inv(G)) % P, c1)) % P);
    const context = await text(page, '[data-claim="cast-context"]');
    const c = BigInt(`0x${sha(['crypto-lab-verifiable-ballot/v1', 'zero-one', context, G, X, R, S, A0, B0, A1, B1])}`) % Q;
    expect((c0 + c1) % Q).toBe(c);
    const t = sha(['tracker', R, S, A0, B0, A1, B1, c0, c1, f0, f1]);
    expect((await text(page, '[data-claim="cast-tracker"]')).replace(/ /g, '')).toBe(t.slice(0, 16));
  });

  test('a ballot encrypting 2: the honest prover refuses and a borrowed proof is rejected', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /Cast a ballot/);
    await page.locator('#cast-two').click();
    await expect(page.locator('#cast-out')).toContainText('cannot prove that an encryption of 2 is 0 or 1');
    await expect(page.locator('#cast-out .verdict-alarm')).toContainText('Rejected');
    await expect(page.locator('#cast-out [data-ok="false"]')).not.toHaveCount(0);
  });

  test('changing the choice retires the shown ballot, and the page says it did', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /Cast a ballot/);
    await page.locator('#cast-run').click();
    await expect(page.locator('[data-claim="cast-tracker"]')).toHaveCount(1);
    await page.locator('#cast-no').check();
    await expect(page.locator('[data-claim="cast-tracker"]')).toHaveCount(0);
    await expect(page.locator('#cast-out .evidence-retired')).toContainText('other answer');
  });

  test('the board: 8 ballots, a voter finds her tracker, a used ID is refused, and the tally is the 4 yes votes', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /Board & tally/);
    await page.locator('#board-open').click();
    await expect(page.locator('#board-out tbody tr')).toHaveCount(8);
    await page.locator('#board-voter').selectOption('2');
    await page.locator('#board-lookup').click();
    await expect(page.locator('[data-check="lookup"]')).toHaveAttribute('data-ok', 'true');
    await expect(page.locator('#board-out tr.row-mine')).toHaveCount(1);
    await page.locator('#board-dup').click();
    await expect(page.locator('#board-dup-out .verdict-alarm')).toContainText('already on the board');
    await page.locator('#board-tally').click();
    // The page's votes are [1,0,1,1,0,0,1,0]: count them here.
    expect([1, 0, 1, 1, 0, 0, 1, 0].reduce((a, b) => a + b, 0)).toBe(4);
    await expect(page.locator('[data-claim="tally-total"]')).toHaveText('4');
    await page.locator('#board-badtally').click();
    await expect(page.locator('#board-tally-out .verdict-alarm')).toContainText('No tally announced');
    await expect(page.locator('[data-claim="tally-total"]')).toHaveCount(0);
  });

  test('audit: a device that always flips is caught on the first audit; an honest one passes', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /^Audit$/);
    await page.locator('#audit-prepare').click();
    await page.locator('#audit-audit').click();
    await expect(page.locator('#audit-out .verdict-alarm')).toContainText('CAUGHT');
    await expect(page.locator('[data-check="audit-check"] .check-prop')).toHaveText(/audit detected a changed vote/);
    await page.locator('#audit-flip').selectOption('0');
    await page.locator('#audit-prepare').click();
    await page.locator('#audit-audit').click();
    await expect(page.locator('[data-check="audit-check"]')).toHaveAttribute('data-ok', 'true');
    await expect(page.locator('[data-check="audit-check"] .check-prop')).toHaveText(/this audited ballot encrypted your choice/);
    await page.locator('#audit-flip').selectOption('1');
    await expect(page.locator('[data-check="audit-check"]')).toHaveCount(0);
  });

  test('changing the device retires the prepared ballot, and the page says it did', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /^Audit$/);
    await page.locator('#audit-prepare').click();
    await expect(page.locator('#audit-audit')).toBeEnabled();
    await page.locator('#audit-flip').selectOption('0.5');
    await expect(page.locator('#audit-audit')).toBeDisabled();
    await expect(page.locator('#audit-out .evidence-retired')).toContainText('no longer belongs');
  });

  test('P(caught in one round) printed is a · f, recomputed here', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /^Audit$/);
    await page.locator('#audit-a').fill('0.2');
    await page.locator('#audit-f').fill('0.35');
    await expect(page.locator('[data-claim="audit-p"]')).toHaveText(String(+(0.2 * 0.35).toFixed(6)));
    await page.locator('#audit-sim').click();
    await page.locator('#audit-n').selectOption('1000');
    await expect(page.locator('[data-claim="audit-sim-n"]')).toHaveCount(0);
    await expect(page.locator('#audit-sim-out .evidence-retired')).toBeVisible();
  });

  test('the negative claim: every check passed and a vote is missing', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /Clash attack/);
    const fixture = page.locator('#clash-fixture');
    // 1. Reached.
    await expect(fixture).toBeVisible();
    // 2. Every check rendered in the fixture passes.
    const oks = await fixture.locator('[data-check]').evaluateAll((els) => els.map((e) => e.getAttribute('data-ok')));
    expect(oks).toHaveLength(8);
    expect(new Set(oks)).toEqual(new Set(['true']));
    await expect(page.locator('[data-claim="clash-tally"]')).toHaveText('2');
    await expect(page.locator('[data-claim="clash-cast"]')).toHaveText('3');
    // Three names listed, three ballots on the board.
    await expect(page.locator('[data-claim="clash-names"]')).toHaveText('V1, V2, V3');
    await expect(fixture.locator('.board-table tbody tr')).toHaveCount(3);
    // 3. The limitation is on screen, in that state, tied to the fixture.
    const claim = fixture.locator('[data-negative-claim="clash"]');
    await expect(claim).toBeVisible();
    await expect(claim).toContainText('EVERY CHECK PASSED — AND A VOTE IS MISSING');
    await expect(claim).toContainText('Every voter\'s personal check passed and the published tally verifies. Individual verification does not prove each voter saw a different ballot — two voters can be shown the same one.');
  });

  test('clash: V1 and V2 printed the same receipt, and comparing receipts detects it', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /Clash attack/);
    const receipts = await page.locator('#clash-voters tbody td code').allInnerTexts();
    expect(receipts[0]).toBe(receipts[1]);
    expect(receipts[2]).not.toBe(receipts[0]);
    await page.locator('#clash-compare').click();
    await expect(page.locator('#clash-compare-out .verdict-alarm')).toContainText('V1 and V2');
  });

  test('weak Fiat–Shamir: the forged ballot is accepted and the tally is the honest 2 plus 3; the strong hash rejects it', async ({ page }) => {
    await boot(page, 'dark');
    await openTab(page, /Weak Fiat–Shamir/);
    await page.locator('#wfs-weak').click();
    await expect(page.locator('#wfs-out .broken-badge')).toHaveCount(1);
    await expect(page.locator('[data-claim="wfs-weak-tally"]')).toHaveText(String(2 + 3));
    expect(await page.locator('#wfs-out [data-check^="wfs-weak-eq"]').evaluateAll((els) => els.map((e) => e.getAttribute('data-ok')))).toEqual(['true', 'true', 'true', 'true', 'true']);
    await page.locator('#wfs-strong').click();
    await expect(page.locator('#wfs-out .broken-badge')).toHaveCount(0);
    await expect(page.locator('[data-claim="wfs-strong-tally"]')).toHaveText('2');
    expect(await page.locator('#wfs-out [data-check^="wfs-strong-eq"]').evaluateAll((els) => els.map((e) => e.getAttribute('data-ok')))).toEqual(['true', 'true', 'true', 'true', 'false']);
  });
});
