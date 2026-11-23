import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the intro; a cast ballot with
 * its five equations and full transcript, retired by a changed choice, and a
 * ballot encrypting 2; the board, a tracker lookup, a used ID, a verified and a
 * withheld tally; the audit catching a device, an unaudited cast, the
 * simulation and an invalid rate; the clash fixture and its detection; the weak
 * and strong Fiat–Shamir runs; the sources;
 * three hover states and two focus rings. Every state is scanned at desktop
 * and phone width. See `gate.ts` for why nothing is injected, nothing is
 * revealed from script, and `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
