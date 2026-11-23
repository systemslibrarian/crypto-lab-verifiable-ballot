/** A uniform [0, 1) source. The page uses `DEFAULT_RNG`; tests inject a seeded one. */
export type Rng = () => number;

const BUF = new Uint32Array(1024);
let pos = BUF.length;

/** crypto.getRandomValues, 32 bits per draw, refilled 1024 words at a time. */
export const cryptoRng: Rng = () => {
  if (pos === BUF.length) {
    crypto.getRandomValues(BUF);
    pos = 0;
  }
  return BUF[pos++] / 2 ** 32;
};

/** The only generator the UI uses. A unit test pins it to `cryptoRng`. */
export const DEFAULT_RNG: Rng = cryptoRng;

/** Wilson score interval for k successes in n independent trials, 95% (z = 1.96). */
export function wilson(k: number, n: number, z = 1.96): { lo: number; hi: number } {
  if (n === 0) return { lo: 0, hi: 1 };
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n);
  const r = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return { lo: Math.max(0, (c - r) / d), hi: Math.min(1, (c + r) / d) };
}

/** 95% interval for a mean from independent batch means (Student t, df = batches − 1; 20 batches → 2.093). */
export function batchInterval(means: number[]): { mean: number; lo: number; hi: number } {
  const b = means.length;
  const mean = means.reduce((x, y) => x + y, 0) / b;
  const sd = Math.sqrt(means.reduce((s, m) => s + (m - mean) ** 2, 0) / (b - 1));
  const t = b === 20 ? 2.093 : 1.96;
  const half = (t * sd) / Math.sqrt(b);
  return { mean, lo: mean - half, hi: mean + half };
}
