import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { batchInterval, cryptoRng, DEFAULT_RNG, wilson } from './rng';
import { cryptoBytes } from './group/modp';

describe('Randomness (batch requirement 3)', () => {
  it('the shipped default RNG is crypto.getRandomValues', () => {
    expect(DEFAULT_RNG).toBe(cryptoRng);
    const spy = vi.spyOn(crypto, 'getRandomValues');
    for (let i = 0; i < 2048; i++) {
      const u = DEFAULT_RNG();
      expect(u >= 0 && u < 1).toBe(true);
    }
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
  it('the shipped byte source for keys and nonces is crypto.getRandomValues', () => {
    const spy = vi.spyOn(crypto, 'getRandomValues');
    expect(cryptoBytes(32)).toHaveLength(32);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });
  it('no UI module imports the seeded test generator', () => {
    const dir = join(__dirname, 'ui');
    for (const f of readdirSync(dir)) expect(readFileSync(join(dir, f), 'utf8')).not.toMatch(/testing\/seeded|Math\.random/);
    expect(readFileSync(join(__dirname, 'main.ts'), 'utf8')).not.toMatch(/testing\/seeded|Math\.random/);
  });
});

describe('Intervals', () => {
  it('Wilson: 5 of 100 → [0.0215, 0.1118] (textbook value)', () => {
    const r = wilson(5, 100);
    expect(r.lo).toBeCloseTo(0.0215, 4);
    expect(r.hi).toBeCloseTo(0.1118, 4);
  });
  it('Wilson stays inside [0, 1] at the edges', () => {
    expect(wilson(0, 10).lo).toBe(0);
    expect(wilson(10, 10).hi).toBe(1);
  });
  it('batch interval: constant batches give a zero-width interval at the mean', () => {
    const r = batchInterval(new Array(20).fill(0.3));
    expect(r.mean).toBeCloseTo(0.3, 15);
    expect(r.hi - r.lo).toBeCloseTo(0, 15);
  });
});
