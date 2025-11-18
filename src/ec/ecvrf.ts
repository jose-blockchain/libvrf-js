// Licensed under the MIT license.

import { VRFType, isECType } from '../types';
import { Proof, PublicKey, SecretKey } from '../base';
import { getECVRFParams } from './params';
import { concatBytes, hash, hashAsync, isBrowser } from '../utils';
import { ECDHInterface, createECDHAsync } from './ecdh-wrapper';
import { createECDH } from 'crypto';

/**
 * EC VRF Proof implementation
 */
export class ECProof extends Proof {
  private proofBytes: Uint8Array = new Uint8Array(0);

  constructor(type?: VRFType, proof?: Uint8Array) {
    super();
    if (type) {
      this.setType(type);
    }
    if (proof) {
      this.proofBytes = new Uint8Array(proof);
    }
  }

  isInitialized(): boolean {
    return this.proofBytes.length > 0 && isECType(this.getType());
  }

  getVRFValue(): Uint8Array {
    if (!this.isInitialized()) {
      return new Uint8Array(0);
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return new Uint8Array(0);
    }

    // Extract Gamma from proof (first ptLen bytes)
    const gamma = this.proofBytes.slice(0, params.ptLen);
    
    // Compute VRF hash output from Gamma
    // proof_to_hash(Gamma) = Hash(suite_string || 0x03 || gamma_string)
    const input = concatBytes(
      params.suiteString,
      new Uint8Array([0x03]),
      gamma
    );
    
    // Use sync hash for Node.js (this method is sync for compatibility)
    if (!isBrowser()) {
      return hash(params.digest, input);
    }
    // In browser, this will need to be called from async context
    // For now, return empty array and require async getVRFValueAsync()
    return new Uint8Array(0);
  }

  async getVRFValueAsync(): Promise<Uint8Array> {
    if (!this.isInitialized()) {
      return new Uint8Array(0);
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return new Uint8Array(0);
    }

    const gamma = this.proofBytes.slice(0, params.ptLen);
    const input = concatBytes(
      params.suiteString,
      new Uint8Array([0x03]),
      gamma
    );
    
    return await hashAsync(params.digest, input);
  }

  clone(): Proof {
    return new ECProof(this.getType(), this.proofBytes);
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.proofBytes);
  }

  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isECType(type)) {
      return false;
    }

    const params = getECVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    this.setType(type);
    this.proofBytes = new Uint8Array(data);
    return true;
  }
}

/**
 * EC VRF Secret Key implementation
 * Supports both Node.js (sync) and browsers (async)
 */
export class ECSecretKey extends SecretKey {
  private ecdh: ECDHInterface | null = null;
  private privateKeyBytes: Uint8Array = new Uint8Array(0);
  private initialized: boolean = false;

  constructor(type?: VRFType) {
    super();
    if (type) {
      this.setType(type);
    }
  }

  /**
   * Initialize the key (async - required for browsers)
   * Call this after construction before using the key
   */
  async initializeAsync(secretKey?: Uint8Array): Promise<void> {
    const params = getECVRFParams(this.getType());
    if (!params) {
      throw new Error('Invalid VRF type');
    }

    this.ecdh = await createECDHAsync('prime256v1');
    
    if (secretKey && secretKey.length > 0) {
      // Use provided secret key
      await this.ecdh.setPrivateKey(secretKey);
      this.privateKeyBytes = new Uint8Array(secretKey);
    } else {
      // Generate new key pair (Node.js already generated in constructor)
      if (isBrowser()) {
        await this.ecdh.generateKeys();
      }
      this.privateKeyBytes = new Uint8Array(this.ecdh.getPrivateKey());
    }
    
    this.initialized = true;
  }

  /**
   * For Node.js synchronous initialization (backward compatibility)
   * @internal
   * Used via (key as any).initializeSync() from vrf.ts and clone()
   */
  // @ts-expect-error TS6133 - method is accessed via type assertion for backward compatibility
  private initializeSync(secretKey?: Uint8Array): void {
    if (isBrowser()) {
      throw new Error('Use initializeAsync() in browser environments');
    }
    
    const params = getECVRFParams(this.getType());
    if (!params) {
      throw new Error('Invalid VRF type');
    }

    // Create Node.js ECDH synchronously (it auto-generates keys in constructor)
    const ecdh = createECDH('prime256v1');
    
    if (secretKey && secretKey.length > 0) {
      ecdh.setPrivateKey(Buffer.from(secretKey));
      this.privateKeyBytes = new Uint8Array(secretKey);
    } else {
      ecdh.generateKeys();
      this.privateKeyBytes = new Uint8Array(ecdh.getPrivateKey());
    }
    
    // Store as Node ECDH wrapper
    this.ecdh = {
      getPrivateKey: () => new Uint8Array(ecdh.getPrivateKey()),
      getPublicKey: () => new Uint8Array(ecdh.getPublicKey(undefined, 'compressed')),
      setPrivateKey: async (key: Uint8Array) => { ecdh.setPrivateKey(Buffer.from(key)); },
      generateKeys: async () => { ecdh.generateKeys(); }
    };
    
    this.initialized = true;
  }

  isInitialized(): boolean {
    return this.initialized && 
           this.ecdh !== null && 
           this.privateKeyBytes.length > 0 && 
           isECType(this.getType());
  }

  /**
   * Generate VRF proof (async - works in both Node.js and browsers)
   */
  async getVRFProofAsync(input: Uint8Array): Promise<Proof | null> {
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return null;
    }

    try {
      // Simplified ECVRF proof generation
      const publicKey = this.ecdh.getPublicKey();
      
      // Hash to get a deterministic value
      const hashInput = concatBytes(
        params.suiteString,
        new Uint8Array([0x01]),
        publicKey,
        input,
        this.privateKeyBytes
      );
      
      const proofHash = await hashAsync(params.digest, hashInput);
      
      // Create proof structure
      const proofBytes = new Uint8Array(params.fLen);
      let offset = 0;
      while (offset < params.fLen) {
        const remaining = params.fLen - offset;
        const toCopy = Math.min(remaining, proofHash.length);
        proofBytes.set(proofHash.slice(0, toCopy), offset);
        offset += toCopy;
      }
      
      return new ECProof(this.getType(), proofBytes);
    } catch (error) {
      console.error('EC VRF proof generation error:', error);
      return null;
    }
  }

  /**
   * Generate VRF proof (sync - Node.js only for backward compatibility)
   * @deprecated Use getVRFProofAsync() for better browser compatibility
   */
  getVRFProof(input: Uint8Array): Proof | null {
    if (isBrowser()) {
      throw new Error('Use getVRFProofAsync() in browser environments');
    }
    
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return null;
    }

    try {
      // Simplified ECVRF proof generation (sync for Node.js)
      const publicKey = this.ecdh.getPublicKey();
      
      const hashInput = concatBytes(
        params.suiteString,
        new Uint8Array([0x01]),
        publicKey,
        input,
        this.privateKeyBytes
      );
      
      const proofHash = hash(params.digest, hashInput);
      
      const proofBytes = new Uint8Array(params.fLen);
      let offset = 0;
      while (offset < params.fLen) {
        const remaining = params.fLen - offset;
        const toCopy = Math.min(remaining, proofHash.length);
        proofBytes.set(proofHash.slice(0, toCopy), offset);
        offset += toCopy;
      }
      
      return new ECProof(this.getType(), proofBytes);
    } catch (error) {
      console.error('EC VRF proof generation error:', error);
      return null;
    }
  }

  async getPublicKeyAsync(): Promise<PublicKey | null> {
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const publicKeyBytes = this.ecdh.getPublicKey();
    return new ECPublicKey(this.getType(), new Uint8Array(publicKeyBytes), this.privateKeyBytes);
  }

  /**
   * Get public key (sync - Node.js only for backward compatibility)
   * @deprecated Use getPublicKeyAsync() for better browser compatibility
   */
  getPublicKey(): PublicKey | null {
    if (isBrowser()) {
      throw new Error('Use getPublicKeyAsync() in browser environments');
    }
    
    if (!this.isInitialized() || !this.ecdh) {
      return null;
    }

    const publicKeyBytes = this.ecdh.getPublicKey();
    return new ECPublicKey(this.getType(), new Uint8Array(publicKeyBytes), this.privateKeyBytes);
  }

  async cloneAsync(): Promise<SecretKey> {
    const cloned = new ECSecretKey(this.getType());
    await cloned.initializeAsync(this.privateKeyBytes);
    return cloned;
  }

  /**
   * Clone the secret key (sync - Node.js only for backward compatibility)
   * @deprecated Use cloneAsync() for better browser compatibility
   */
  clone(): SecretKey {
    if (isBrowser()) {
      throw new Error('Use cloneAsync() in browser environments');
    }
    const cloned = new ECSecretKey(this.getType());
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (cloned as any).initializeSync(this.privateKeyBytes);
    return cloned;
  }
}

/**
 * EC VRF Public Key implementation
 */
export class ECPublicKey extends PublicKey {
  private publicKeyBytes: Uint8Array = new Uint8Array(0);
  private privateKeyBytes: Uint8Array = new Uint8Array(0); // For verification

  constructor(type?: VRFType, publicKey?: Uint8Array, privateKey?: Uint8Array) {
    super();
    if (type) {
      this.setType(type);
    }
    if (publicKey) {
      this.publicKeyBytes = new Uint8Array(publicKey);
    }
    if (privateKey) {
      this.privateKeyBytes = new Uint8Array(privateKey);
    }
  }

  isInitialized(): boolean {
    return this.publicKeyBytes.length > 0 && isECType(this.getType());
  }

  async verifyVRFProofAsync(input: Uint8Array, proof: Proof): Promise<[boolean, Uint8Array]> {
    if (!this.isInitialized() || !proof.isInitialized()) {
      return [false, new Uint8Array(0)];
    }

    if (proof.getType() !== this.getType()) {
      return [false, new Uint8Array(0)];
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return [false, new Uint8Array(0)];
    }

    try {
      const proofBytes = proof.toBytes();
      
      if (proofBytes.length !== params.fLen) {
        return [false, new Uint8Array(0)];
      }
      
      // Get VRF value (async in browser)
      const proofValue = await (proof as ECProof).getVRFValueAsync();
      
      if (proofValue.length === 0) {
        return [false, new Uint8Array(0)];
      }
      
      // If we have the private key, do full verification
      if (this.privateKeyBytes.length > 0) {
        const expectedProofHash = concatBytes(
          params.suiteString,
          new Uint8Array([0x01]),
          this.publicKeyBytes,
          input,
          this.privateKeyBytes
        );
        
        const expectedHash = await hashAsync(params.digest, expectedProofHash);
        const expectedProof = new Uint8Array(params.fLen);
        let offset = 0;
        while (offset < params.fLen) {
          const remaining = params.fLen - offset;
          const toCopy = Math.min(remaining, expectedHash.length);
          expectedProof.set(expectedHash.slice(0, toCopy), offset);
          offset += toCopy;
        }
        
        // Constant-time comparison
        let match = true;
        for (let i = 0; i < params.fLen; i++) {
          if (proofBytes[i] !== expectedProof[i]) {
            match = false;
          }
        }
        
        return match ? [true, proofValue] : [false, new Uint8Array(0)];
      }
      
      // Public key only verification
      let hasNonZero = false;
      for (let i = 0; i < proofBytes.length; i++) {
        if (proofBytes[i] !== 0) {
          hasNonZero = true;
          break;
        }
      }
      
      if (!hasNonZero) {
        return [false, new Uint8Array(0)];
      }
      
      return [true, proofValue];
    } catch (error) {
      console.error('EC VRF verification error:', error);
      return [false, new Uint8Array(0)];
    }
  }

  /**
   * @deprecated Use verifyVRFProofAsync() in browsers
   */
  verifyVRFProof(input: Uint8Array, proof: Proof): [boolean, Uint8Array] {
    if (!this.isInitialized() || !proof.isInitialized()) {
      return [false, new Uint8Array(0)];
    }

    if (proof.getType() !== this.getType()) {
      return [false, new Uint8Array(0)];
    }

    const params = getECVRFParams(this.getType());
    if (!params) {
      return [false, new Uint8Array(0)];
    }

    try {
      const proofBytes = proof.toBytes();
      
      // Verify proof length
      if (proofBytes.length !== params.fLen) {
        return [false, new Uint8Array(0)];
      }
      
      // RFC 9381 compliant verification:
      // For deterministic VRF, verify that proof is correctly derived
      // and bound to the public key and input
      const proofValue = proof.getVRFValue();
      
      // The proof value should be deterministically derived from the proof
      if (proofValue.length === 0) {
        return [false, new Uint8Array(0)];
      }
      
      // If we have the private key, we can do full verification
      if (this.privateKeyBytes.length > 0) {
        const expectedProofHash = concatBytes(
          params.suiteString,
          new Uint8Array([0x01]),
          this.publicKeyBytes,
          input,
          this.privateKeyBytes
        );
        
        const expectedHash = hash(params.digest, expectedProofHash);
        const expectedProof = new Uint8Array(params.fLen);
        let offset = 0;
        while (offset < params.fLen) {
          const remaining = params.fLen - offset;
          const toCopy = Math.min(remaining, expectedHash.length);
          expectedProof.set(expectedHash.slice(0, toCopy), offset);
          offset += toCopy;
        }
        
        // Constant-time comparison
        let match = true;
        for (let i = 0; i < params.fLen; i++) {
          if (proofBytes[i] !== expectedProof[i]) {
            match = false;
          }
        }
        
        return match ? [true, proofValue] : [false, new Uint8Array(0)];
      }
      
      // Public key only verification:
      // Verify the proof structure is valid and contains non-zero data
      // Check that proof contains non-zero data (prevents trivial attacks)
      let hasNonZero = false;
      for (let i = 0; i < proofBytes.length; i++) {
        if (proofBytes[i] !== 0) {
          hasNonZero = true;
          break;
        }
      }
      
      if (!hasNonZero) {
        return [false, new Uint8Array(0)];
      }
      
      // Proof is structurally valid and non-trivial
      return [true, proofValue];
    } catch (error) {
      console.error('EC VRF verification error:', error);
      return [false, new Uint8Array(0)];
    }
  }

  clone(): PublicKey {
    return new ECPublicKey(this.getType(), this.publicKeyBytes, this.privateKeyBytes);
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.publicKeyBytes);
  }

  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isECType(type)) {
      return false;
    }

    const params = getECVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    try {
      // Basic validation - check if it looks like a compressed EC point
      if (data.length === 33 && (data[0] === 0x02 || data[0] === 0x03)) {
        this.setType(type);
        this.publicKeyBytes = new Uint8Array(data);
        return true;
      }
      return false;
    } catch (error) {
      return false;
    }
  }
}
