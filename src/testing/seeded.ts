import type { Rng } from '../rng';

/** mulberry32 — a small deterministic generator for TESTS ONLY (never imported by the UI). */
export function seeded(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Deterministic bytes for tests: four bytes per mulberry32 draw. TESTS ONLY. */
export function seededBytes(seed: number): (n: number) => Uint8Array {
  const r = seeded(seed);
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 4) {
      const v = Math.floor(r() * 2 ** 32);
      for (let k = 0; k < 4 && i + k < n; k++) out[i + k] = (v >>> (8 * k)) & 0xff;
    }
    return out;
  };
}
