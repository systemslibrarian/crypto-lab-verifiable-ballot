import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { seededBytes } from '../testing/seeded';
import { encodeField, encodeFields, digestHex } from './hash';
import { isElement, modinv, modpow, randomScalar, RFC5114_2048_256 as G, validateGroup } from './modp';

/** Miller–Rabin written here, separately from src/, with 24 fixed bases. */
function probablePrime(n: bigint): boolean {
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }
  const pow = (b: bigint, e: bigint): bigint => {
    let r = 1n;
    b %= n;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % n;
      b = (b * b) % n;
      e >>= 1n;
    }
    return r;
  };
  outer: for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n]) {
    let x = pow(a, d);
    if (x === 1n || x === n - 1n) continue;
    for (let i = 1; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) continue outer;
    }
    return false;
  }
  return true;
}

describe('Group parameters (invariant 1)', () => {
  it('RFC 5114 §2.3: the structural checks pass', () => {
    expect(validateGroup(G)).toEqual([]);
  });
  it('p and q are (probable) primes', () => {
    expect(probablePrime(G.q)).toBe(true);
    expect(probablePrime(G.p)).toBe(true);
  }, 60_000);
  it('RFC 5114 Appendix A.3 test vector: g^xA = yA', () => {
    const xA = 0x0881382cdb87660c6dc13e614938d5b9c8b2f248581cc5e31b35454397fce50en;
    const yA = BigInt(
      '0x2E9380C8323AF97545BC4941DEB0EC3742C62FE0ECE824A6ABDBE66C59BEE0242911BFB967235CEBA35AE13E4EC752BE630B92DC4BDE2847A9C62CB8152745421FB7EB60A63C0FE9159FCCE726CE7CD8523D7450667EF840E4919121EB5F01C8C9B0D3D648A93BFB75689E8244AC134AF544711CE79A02DCC34226684780DDDCB498594106C37F5BC79856487AF5AB022A2E5E42F09897C1A85A11EA0212AF04D9B4CEBC937C3C1A3E15A8A0342E337615C84E7FE3B8B9B87FB1E73A15AF12A30D746E06DFC34F290D797CE51AA13AA785BF6658AFF5E4B093003CBEAF665B3C2E113A3A4E905269341DC0711426685F4EF37E868A8126FF3F2279B57CA67E29',
    );
    expect(modpow(G.g, xA, G.p)).toBe(yA);
  });
  it('subgroup membership refuses 0, 1-off-range values and the order-2 element p − 1', () => {
    expect(isElement(G, 0n)).toBe(false);
    expect(isElement(G, G.p)).toBe(false);
    expect(isElement(G, G.p - 1n)).toBe(false);
    expect(isElement(G, G.g)).toBe(true);
    expect(isElement(G, 1n)).toBe(true);
  });
  it('modinv and random scalars', () => {
    expect((modinv(12345n, G.q) * 12345n) % G.q).toBe(1n);
    const b = seededBytes(3);
    for (let i = 0; i < 50; i++) {
      const s = randomScalar(G, b);
      expect(s >= 0n && s < G.q).toBe(true);
    }
  });
});

describe('Exact encodings (batch requirement 4)', () => {
  it('each field is a 4-byte big-endian length, then its bytes', () => {
    expect(Buffer.from(encodeField('ab')).toString('hex')).toBe('000000026162');
    expect(Buffer.from(encodeField(0n)).toString('hex')).toBe('0000000100');
    expect(Buffer.from(encodeField(256n)).toString('hex')).toBe('000000020100');
  });
  it('the digest is SHA-256 of the concatenated fields (node:crypto as the oracle)', () => {
    const bytes = Buffer.concat([Buffer.from('0000000161', 'hex'), Buffer.from('00000001ff', 'hex')]);
    expect(Buffer.from(encodeFields(['a', 255n])).equals(bytes)).toBe(true);
    expect(digestHex(['a', 255n])).toBe(createHash('sha256').update(bytes).digest('hex'));
  });
  it('length prefixes keep ("ab","c") and ("a","bc") apart', () => {
    expect(digestHex(['ab', 'c'])).not.toBe(digestHex(['a', 'bc']));
  });
});
