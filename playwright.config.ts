import { defineConfig, devices } from '@playwright/test';

/**
 * E2E runs against the production build served by `vite preview`, so what passes
 * here is what ships:
 *   - a11y.spec.ts   — the axe WCAG gate plus this repo's own oracles.
 *   - claims.spec.ts — what the page SAYS, recomputed independently.
 *
 * Port 4756 is this lab's own. It was the next free port in the catalog's
 * tools/playwright-ports.json registry on 2026-11-23; pinning it there is the
 * catalog session's step (never the Vite default 4173).
 *
 * PW_CHROMIUM_PATH lets a local run point at an installed browser when the
 * Playwright download is unavailable; CI leaves it unset and uses the image's.
 */
const executablePath = process.env.PW_CHROMIUM_PATH || undefined;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 90_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4756/crypto-lab-verifiable-ballot/',
    launchOptions: { executablePath },
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'], colorScheme: 'dark', launchOptions: { executablePath } } },
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'], launchOptions: { executablePath } } },
  ],
  webServer: {
    // Build before serving: `vite preview` only serves whatever is already in
    // dist/, so without this a failing build leaves the previous good bundle in
    // place and the suite passes green against code that no longer compiles.
    command: 'npm run build && npm run preview -- --port 4756 --strictPort',
    url: 'http://localhost:4756/crypto-lab-verifiable-ballot/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
