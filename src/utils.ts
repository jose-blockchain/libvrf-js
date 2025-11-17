// Licensed under the MIT license.

import { createHash, randomBytes } from 'crypto';

/**
 * Check if running in browser environment
 */
export function isBrowser(): boolean {
  return typeof globalThis !== 'undefined' && 
         typeof (globalThis as any).window !== 'undefined' && 
         typeof (globalThis as any).window.crypto !== 'undefined';
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Compare two Uint8Arrays for equality
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Hash data using specified algorithm
 */
export function hash(algorithm: string, data: Uint8Array): Uint8Array {
  if (isBrowser()) {
    throw new Error('Browser crypto not yet implemented for hash');
  }
  const hashObj = createHash(algorithm);
  hashObj.update(data);
  return new Uint8Array(hashObj.digest());
}

/**
 * Generate random bytes
 */
export function getRandomBytes(length: number): Uint8Array {
  if (isBrowser()) {
    const bytes = new Uint8Array(length);
    (globalThis as any).window.crypto.getRandomValues(bytes);
    return bytes;
  }
  return new Uint8Array(randomBytes(length));
}

/**
 * Convert BigInt to Uint8Array (big-endian)
 */
export function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const hex = value.toString(16).padStart(length * 2, '0');
  return hexToBytes(hex);
}

/**
 * Convert Uint8Array to BigInt (big-endian)
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + bytesToHex(bytes));
}

/**
 * Perform modular exponentiation: (base^exp) mod modulus
 */
export function modPow(base: bigint, exp: bigint, modulus: bigint): bigint {
  let result = 1n;
  base = base % modulus;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exp = exp >> 1n;
    base = (base * base) % modulus;
  }
  return result;
}

/**
 * Compute modular inverse using extended Euclidean algorithm
 */
export function modInverse(a: bigint, m: bigint): bigint {
  const m0 = m;
  let x0 = 0n;
  let x1 = 1n;

  if (m === 1n) return 0n;

  while (a > 1n) {
    const q = a / m;
    let t = m;
    m = a % m;
    a = t;
    t = x0;
    x0 = x1 - q * x0;
    x1 = t;
  }

  if (x1 < 0n) x1 += m0;
  return x1;
}

/**
 * XOR two byte arrays
 */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const length = Math.min(a.length, b.length);
  const result = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/**
 * I2OSP: Integer to Octet String Primitive (RFC 8017)
 */
export function i2osp(x: bigint, xLen: number): Uint8Array {
  if (x >= 256n ** BigInt(xLen)) {
    throw new Error('Integer too large');
  }
  return bigIntToBytes(x, xLen);
}

/**
 * OS2IP: Octet String to Integer Primitive (RFC 8017)
 */
export function os2ip(x: Uint8Array): bigint {
  return bytesToBigInt(x);
}

