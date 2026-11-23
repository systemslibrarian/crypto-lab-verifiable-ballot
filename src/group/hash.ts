import { sha256 } from '@noble/hashes/sha2.js';
import type { Group } from './modp';

/**
 * Exact encodings (batch requirement 4). Every hash input is a sequence of fields;
 * each field is a 4-byte big-endian length followed by its bytes:
 *   - a string: its UTF-8 bytes;
 *   - an integer (group element or scalar): its minimal big-endian bytes (zero is one 0x00 byte).
 * The length prefix makes the encoding unambiguous. A challenge is the SHA-256 digest
 * read as a big-endian integer, reduced mod q.
 */
const enc = new TextEncoder();

export type Field = string | bigint;

export function encodeField(f: Field): Uint8Array {
  let body: Uint8Array;
  if (typeof f === 'string') body = enc.encode(f);
  else {
    if (f < 0n) throw new RangeError('negative integer in a hash input');
    let hex = f.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    body = Uint8Array.from(hex.match(/../g)!.map((x) => parseInt(x, 16)));
  }
  const out = new Uint8Array(4 + body.length);
  new DataView(out.buffer).setUint32(0, body.length, false);
  out.set(body, 4);
  return out;
}

export function encodeFields(fields: Field[]): Uint8Array {
  const parts = fields.map(encodeField);
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function digestHex(fields: Field[]): string {
  return Array.from(sha256(encodeFields(fields)), (x) => x.toString(16).padStart(2, '0')).join('');
}

export function hashToScalar(G: Group, fields: Field[]): bigint {
  return BigInt(`0x${digestHex(fields)}`) % G.q;
}

/** Domain label at the front of every strong hash in this lab. */
export const DOMAIN = 'crypto-lab-verifiable-ballot/v1';
