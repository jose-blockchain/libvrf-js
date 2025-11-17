// Licensed under the MIT license.

import { hexToBytes, bytesToHex, concatBytes, bytesEqual } from '../src/utils';

describe('Utility Functions', () => {
  describe('hexToBytes', () => {
    test('converts hex string to bytes', () => {
      const hex = '48656c6c6f';
      const bytes = hexToBytes(hex);
      expect(bytes).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    test('handles empty string', () => {
      const bytes = hexToBytes('');
      expect(bytes).toEqual(new Uint8Array(0));
    });

    test('handles uppercase hex', () => {
      const hex = '48656C6C6F';
      const bytes = hexToBytes(hex);
      expect(bytes).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });
  });

  describe('bytesToHex', () => {
    test('converts bytes to hex string', () => {
      const bytes = new Uint8Array([72, 101, 108, 108, 111]);
      const hex = bytesToHex(bytes);
      expect(hex).toBe('48656c6c6f');
    });

    test('handles empty array', () => {
      const hex = bytesToHex(new Uint8Array(0));
      expect(hex).toBe('');
    });

    test('pads single digit hex values', () => {
      const bytes = new Uint8Array([0, 1, 15, 16]);
      const hex = bytesToHex(bytes);
      expect(hex).toBe('00010f10');
    });
  });

  describe('concatBytes', () => {
    test('concatenates multiple byte arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([3, 4]);
      const c = new Uint8Array([5, 6]);
      const result = concatBytes(a, b, c);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
    });

    test('handles empty arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array(0);
      const c = new Uint8Array([3, 4]);
      const result = concatBytes(a, b, c);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4]));
    });

    test('handles single array', () => {
      const a = new Uint8Array([1, 2, 3]);
      const result = concatBytes(a);
      expect(result).toEqual(new Uint8Array([1, 2, 3]));
    });
  });

  describe('bytesEqual', () => {
    test('returns true for equal arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3]);
      expect(bytesEqual(a, b)).toBe(true);
    });

    test('returns false for different arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);
      expect(bytesEqual(a, b)).toBe(false);
    });

    test('returns false for different lengths', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2]);
      expect(bytesEqual(a, b)).toBe(false);
    });

    test('returns true for empty arrays', () => {
      const a = new Uint8Array(0);
      const b = new Uint8Array(0);
      expect(bytesEqual(a, b)).toBe(true);
    });
  });

  describe('Round-trip conversions', () => {
    test('hex -> bytes -> hex', () => {
      const original = '0123456789abcdef';
      const bytes = hexToBytes(original);
      const result = bytesToHex(bytes);
      expect(result).toBe(original);
    });

    test('bytes -> hex -> bytes', () => {
      const original = new Uint8Array([0, 15, 255, 128, 64]);
      const hex = bytesToHex(original);
      const result = hexToBytes(hex);
      expect(result).toEqual(original);
    });
  });
});

