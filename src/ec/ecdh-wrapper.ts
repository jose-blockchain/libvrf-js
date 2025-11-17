// Licensed under the MIT license.

import { createECDH, ECDH } from 'crypto';
import { isBrowser } from '../utils';

/**
 * Unified ECDH interface for both Node.js and browsers
 */
export interface ECDHInterface {
  getPrivateKey(): Uint8Array;
  getPublicKey(): Uint8Array;
  setPrivateKey(key: Uint8Array): Promise<void>;
  generateKeys(): Promise<void>;
}

/**
 * Create ECDH instance for the given curve
 * Works in both Node.js and browsers
 */
export async function createECDHAsync(curve: string): Promise<ECDHInterface> {
  if (isBrowser()) {
    const instance = new BrowserECDH(curve);
    await instance.initialize();
    return instance;
  } else {
    return new NodeECDH(curve);
  }
}

/**
 * Node.js ECDH implementation (synchronous)
 */
class NodeECDH implements ECDHInterface {
  private ecdh: ECDH;

  constructor(curve: string) {
    this.ecdh = createECDH(curve);
    // Generate keys immediately for backward compatibility
    this.ecdh.generateKeys();
  }

  getPrivateKey(): Uint8Array {
    return new Uint8Array(this.ecdh.getPrivateKey());
  }

  getPublicKey(): Uint8Array {
    // Return compressed format
    const key = this.ecdh.getPublicKey(undefined, 'compressed');
    return new Uint8Array(key);
  }

  async setPrivateKey(key: Uint8Array): Promise<void> {
    this.ecdh.setPrivateKey(Buffer.from(key));
  }

  async generateKeys(): Promise<void> {
    this.ecdh.generateKeys();
  }
}

/**
 * Browser ECDH implementation using WebCrypto API
 */
class BrowserECDH implements ECDHInterface {
  private privateKeyBytes: Uint8Array = new Uint8Array(0);
  private publicKeyBytes: Uint8Array = new Uint8Array(0);
  private curve: string;

  constructor(curve: string) {
    // Map Node.js curve names to WebCrypto names
    if (curve === 'prime256v1') {
      this.curve = 'P-256';
    } else {
      this.curve = curve;
    }
  }

  async initialize(): Promise<void> {
    // Initialization will happen in generateKeys() or setPrivateKey()
  }

  getPrivateKey(): Uint8Array {
    return new Uint8Array(this.privateKeyBytes);
  }

  getPublicKey(): Uint8Array {
    return new Uint8Array(this.publicKeyBytes);
  }

  async setPrivateKey(key: Uint8Array): Promise<void> {
    if (key.length !== 32) {
      throw new Error('Private key must be 32 bytes for P-256');
    }
    
    this.privateKeyBytes = new Uint8Array(key);
    
    try {
      // For simplified VRF, we'll compute public key using a helper
      // In a production implementation, use proper EC point multiplication
      const publicKeyUncompressed = await this.computePublicKey(key);
      this.publicKeyBytes = this.compressPublicKey(publicKeyUncompressed);
      
    } catch (error) {
      console.error('Error setting private key:', error);
      throw error;
    }
  }

  async generateKeys(): Promise<void> {
    const crypto = (globalThis as any).window?.crypto || (globalThis as any).crypto;
    
    const cryptoKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: this.curve
      },
      true,
      ['deriveBits']
    );
    
    // Export private key
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', cryptoKeyPair.privateKey);
    
    // Convert base64url to bytes
    const dBase64url = privateKeyJwk.d!;
    this.privateKeyBytes = this.base64UrlToBytes(dBase64url);
    
    // Export public key
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', cryptoKeyPair.publicKey);
    const x = this.base64UrlToBytes(publicKeyJwk.x!);
    const y = this.base64UrlToBytes(publicKeyJwk.y!);
    
    // Create uncompressed format: 0x04 || x || y
    const uncompressed = new Uint8Array(65);
    uncompressed[0] = 0x04;
    uncompressed.set(x, 1);
    uncompressed.set(y, 33);
    
    // Compress to: 0x02/0x03 || x
    this.publicKeyBytes = this.compressPublicKey(uncompressed);
  }

  /**
   * Compress an uncompressed EC public key
   * Input: 0x04 || x (32 bytes) || y (32 bytes)
   * Output: 0x02 or 0x03 || x (32 bytes)
   */
  private compressPublicKey(uncompressed: Uint8Array): Uint8Array {
    if (uncompressed[0] !== 0x04 || uncompressed.length !== 65) {
      throw new Error('Invalid uncompressed public key format');
    }
    
    const x = uncompressed.slice(1, 33);
    const y = uncompressed.slice(33, 65);
    
    const compressed = new Uint8Array(33);
    // If y is even, prefix is 0x02; if odd, prefix is 0x03
    compressed[0] = (y[31] & 1) === 0 ? 0x02 : 0x03;
    compressed.set(x, 1);
    
    return compressed;
  }

  /**
   * Compute public key from private key for P-256
   * Returns uncompressed format: 0x04 || x || y
   */
  private async computePublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
    // For P-256, we need to multiply the generator point G by the private key
    // PublicKey = privateKey * G
    
    // Using WebCrypto, we can import the private key and export the public key
    const crypto = (globalThis as any).window?.crypto || (globalThis as any).crypto;
    
    // Create JWK for private key
    const d = this.bytesToBase64Url(privateKey);
    
    // Import private key as JWK
    const privateKeyJwk = {
      kty: 'EC',
      crv: this.curve,
      d: d,
      ext: true
    };
    
    try {
      const cryptoPrivateKey = await crypto.subtle.importKey(
        'jwk',
        privateKeyJwk,
        {
          name: 'ECDH',
          namedCurve: this.curve
        },
        true,
        ['deriveBits']
      );
      
      // Export as JWK to get x and y coordinates
      const exportedJwk = await crypto.subtle.exportKey('jwk', cryptoPrivateKey);
      
      // If x and y are present, use them; otherwise compute using EC multiplication
      if (exportedJwk.x && exportedJwk.y) {
        const x = this.base64UrlToBytes(exportedJwk.x);
        const y = this.base64UrlToBytes(exportedJwk.y);
        
        const uncompressed = new Uint8Array(65);
        uncompressed[0] = 0x04;
        uncompressed.set(x, 1);
        uncompressed.set(y, 33);
        
        return uncompressed;
      }
    } catch (error) {
      console.error('Error computing public key:', error);
    }
    
    // Fallback: use elliptic curve point multiplication
    // For P-256, implement secp256r1 point multiplication
    // This is complex, so for now we'll throw an error
    throw new Error('Unable to compute public key from private key in browser');
  }


  /**
   * Convert base64url string to Uint8Array
   */
  private base64UrlToBytes(base64url: string): Uint8Array {
    // Convert base64url to base64
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(padding);
    
    // Decode base64
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Convert Uint8Array to base64url string
   */
  private bytesToBase64Url(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}

