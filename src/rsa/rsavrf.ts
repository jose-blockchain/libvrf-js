// Licensed under the MIT license.

import NodeRSA from 'node-rsa';
import { VRFType, isRSAType, isRSAFDHType, isRSAPSSType } from '../types';
import { Proof, PublicKey, SecretKey } from '../base';
import { getRSAVRFParams, RSAVRFParams } from './params';
import { hash, concatBytes, i2osp } from '../utils';

/**
 * RSA VRF Proof implementation
 */
export class RSAProof extends Proof {
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
    return this.proofBytes.length > 0 && isRSAType(this.getType());
  }

  getVRFValue(): Uint8Array {
    if (!this.isInitialized()) {
      return new Uint8Array(0);
    }

    const params = getRSAVRFParams(this.getType());
    if (!params) {
      return new Uint8Array(0);
    }

    // VRF value is hash of the proof
    return hash(params.digest, this.proofBytes);
  }

  clone(): Proof {
    return new RSAProof(this.getType(), this.proofBytes);
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.proofBytes);
  }

  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isRSAType(type)) {
      return false;
    }

    const params = getRSAVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    this.setType(type);
    this.proofBytes = new Uint8Array(data);
    return true;
  }
}

/**
 * RSA VRF Secret Key implementation
 */
export class RSASecretKey extends SecretKey {
  private rsaKey: NodeRSA | undefined = undefined;
  private mgf1Salt: Uint8Array = new Uint8Array(0);

  constructor(type?: VRFType, rsaKey?: NodeRSA) {
    super();
    if (type) {
      this.setType(type);
      const params = getRSAVRFParams(type);
      if (params) {
        if (rsaKey) {
          this.rsaKey = rsaKey;
        } else {
          // Generate new RSA key pair
          this.rsaKey = new NodeRSA({ b: params.bits });
          this.rsaKey.setOptions({
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
          });
        }
        
        // Initialize MGF1 salt
        this.mgf1Salt = new Uint8Array(hash(params.digest, 
          new TextEncoder().encode(params.suiteString)));
      }
    }
  }

  isInitialized(): boolean {
    return this.rsaKey !== undefined && 
           this.mgf1Salt.length > 0 &&
           isRSAType(this.getType());
  }

  getVRFProof(input: Uint8Array): Proof | null {
    if (!this.isInitialized() || !this.rsaKey) {
      return null;
    }

    const params = getRSAVRFParams(this.getType());
    if (!params) {
      return null;
    }

    try {
      let proof: Uint8Array;
      
      if (isRSAFDHType(this.getType())) {
        proof = this.rsaFDHProve(input, params);
      } else if (isRSAPSSType(this.getType())) {
        proof = this.rsaPSSProve(input, params);
      } else {
        return null;
      }
      
      return new RSAProof(this.getType(), proof);
    } catch (error) {
      console.error('RSA VRF proof generation error:', error);
      return null;
    }
  }

  getPublicKey(): PublicKey | null {
    if (!this.isInitialized() || !this.rsaKey) {
      return null;
    }

    return new RSAPublicKey(this.getType(), this.rsaKey, this.mgf1Salt);
  }

  clone(): SecretKey {
    if (!this.rsaKey) {
      return new RSASecretKey(this.getType());
    }
    
    // Clone RSA key
    const keyData = this.rsaKey.exportKey('pkcs1-private');
    const clonedKey = new NodeRSA();
    clonedKey.importKey(keyData, 'pkcs1-private');
    
    return new RSASecretKey(this.getType(), clonedKey);
  }

  private rsaFDHProve(input: Uint8Array, params: RSAVRFParams): Uint8Array {
    // RSA-FDH VRF proof generation
    // 1. Hash input to full domain
    const hashedInput = this.hashToFullDomain(input, params);
    
    // 2. Perform RSA signature (d-th power mod n)
    if (!this.rsaKey) {
      throw new Error('RSA key not initialized');
    }
    
    // Convert hash to bigint
    const message = BigInt('0x' + Buffer.from(hashedInput).toString('hex'));
    
    // Get RSA key components
    const keyData = this.rsaKey.exportKey('components');
    const d = bufferToBigInt(keyData.d);
    const n = bufferToBigInt(keyData.n);
    
    // Perform modular exponentiation: signature = message^d mod n
    const signature = modPow(message, d, n);
    
    // Convert back to bytes
    const modulusLength = params.bits / 8;
    return bigIntToBytes(signature, modulusLength);
  }

  private rsaPSSProve(input: Uint8Array, params: RSAVRFParams): Uint8Array {
    // RSA-PSS-NOSALT VRF proof generation
    // Hash input
    const hashedInput = hash(params.digest, concatBytes(
      new TextEncoder().encode(params.suiteString),
      input
    ));
    
    if (!this.rsaKey) {
      throw new Error('RSA key not initialized');
    }
    
    // Apply PSS encoding with no salt
    const encoded = this.pssEncode(hashedInput, params.bits, params);
    
    // Perform RSA signature
    const message = BigInt('0x' + Buffer.from(encoded).toString('hex'));
    const keyData = this.rsaKey.exportKey('components');
    const d = bufferToBigInt(keyData.d);
    const n = bufferToBigInt(keyData.n);
    
    const signature = modPow(message, d, n);
    
    const modulusLength = params.bits / 8;
    return bigIntToBytes(signature, modulusLength);
  }

  private hashToFullDomain(input: Uint8Array, params: RSAVRFParams): Uint8Array {
    // Hash input with suite string
    const suiteBytes = new TextEncoder().encode(params.suiteString);
    const combined = concatBytes(suiteBytes, input);
    const hashed = hash(params.digest, combined);
    
    // Expand hash to match RSA modulus size using MGF1 with suite string as salt
    return this.mgf1WithSalt(hashed, params.bits / 8, params);
  }

  private mgf1WithSalt(seed: Uint8Array, maskLen: number, params: RSAVRFParams): Uint8Array {
    // MGF1 variant that includes suite string salt for VRF uniqueness
    const hLen = hash(params.digest, new Uint8Array(0)).length;
    if (maskLen > 0xffffffff * hLen) {
      throw new Error('Mask too long');
    }

    const result = new Uint8Array(maskLen);
    let offset = 0;
    let counter = 0;

    while (offset < maskLen) {
      const counterBytes = i2osp(BigInt(counter), 4);
      const hashInput = concatBytes(seed, this.mgf1Salt, counterBytes);
      const hashOutput = hash(params.digest, hashInput);
      
      const copyLen = Math.min(hashOutput.length, maskLen - offset);
      result.set(hashOutput.slice(0, copyLen), offset);
      
      offset += copyLen;
      counter++;
    }

    return result;
  }

  private mgf1(seed: Uint8Array, maskLen: number, params: RSAVRFParams): Uint8Array {
    // Standard MGF1 mask generation function (RFC 8017)
    // MGF(mgfSeed, maskLen) = T1 || T2 || ... || Tn
    // where Ti = Hash(mgfSeed || C), C is a 4-byte counter
    const hLen = hash(params.digest, new Uint8Array(0)).length;
    if (maskLen > 0xffffffff * hLen) {
      throw new Error('Mask too long');
    }

    const result = new Uint8Array(maskLen);
    let offset = 0;
    let counter = 0;

    while (offset < maskLen) {
      const counterBytes = i2osp(BigInt(counter), 4);
      const hashInput = concatBytes(seed, counterBytes);
      const hashOutput = hash(params.digest, hashInput);
      
      const copyLen = Math.min(hashOutput.length, maskLen - offset);
      result.set(hashOutput.slice(0, copyLen), offset);
      
      offset += copyLen;
      counter++;
    }

    return result;
  }

  private pssEncode(mHash: Uint8Array, emBits: number, params: RSAVRFParams): Uint8Array {
    // Simplified PSS encoding with no salt
    const hLen = mHash.length;
    const emLen = Math.ceil(emBits / 8);
    
    // No salt (saltLength = 0)
    const salt = new Uint8Array(0);
    
    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    const mPrime = concatBytes(
      new Uint8Array(8),
      mHash,
      salt
    );
    
    // H = Hash(M')
    const H = hash(params.digest, mPrime);
    
    // Generate PS = 00...00
    const PS = new Uint8Array(emLen - salt.length - hLen - 2);
    
    // DB = PS || 0x01 || salt
    const DB = concatBytes(PS, new Uint8Array([0x01]), salt);
    
    // dbMask = MGF(H, emLen - hLen - 1)
    const dbMask = this.mgf1(H, emLen - hLen - 1, params);
    
    // maskedDB = DB xor dbMask
    const maskedDB = xorBytes(DB, dbMask);
    
    // Set leftmost bits to zero
    const mask = 0xFF >> (8 * emLen - emBits);
    maskedDB[0] &= mask;
    
    // EM = maskedDB || H || 0xbc
    return concatBytes(maskedDB, H, new Uint8Array([0xbc]));
  }
}

/**
 * RSA VRF Public Key implementation
 */
export class RSAPublicKey extends PublicKey {
  private rsaKey: NodeRSA | undefined = undefined;
  private mgf1Salt: Uint8Array = new Uint8Array(0);

  constructor(type?: VRFType, rsaKey?: NodeRSA, mgf1Salt?: Uint8Array) {
    super();
    if (type) {
      this.setType(type);
    }
    if (rsaKey) {
      this.rsaKey = rsaKey;
    }
    if (mgf1Salt) {
      this.mgf1Salt = new Uint8Array(mgf1Salt);
    }
  }

  isInitialized(): boolean {
    return this.rsaKey !== undefined && 
           this.mgf1Salt.length > 0 && 
           isRSAType(this.getType());
  }

  verifyVRFProof(input: Uint8Array, proof: Proof): [boolean, Uint8Array] {
    if (!this.isInitialized() || !proof.isInitialized()) {
      return [false, new Uint8Array(0)];
    }

    if (proof.getType() !== this.getType()) {
      return [false, new Uint8Array(0)];
    }

    const params = getRSAVRFParams(this.getType());
    if (!params) {
      return [false, new Uint8Array(0)];
    }

    try {
      const proofBytes = proof.toBytes();
      let valid = false;

      if (isRSAFDHType(this.getType())) {
        valid = this.rsaFDHVerify(input, proofBytes, params);
      } else if (isRSAPSSType(this.getType())) {
        valid = this.rsaPSSVerify(input, proofBytes, params);
      }

      if (valid) {
        const vrfValue = proof.getVRFValue();
        return [true, vrfValue];
      }

      return [false, new Uint8Array(0)];
    } catch (error) {
      console.error('RSA VRF verification error:', error);
      return [false, new Uint8Array(0)];
    }
  }

  clone(): PublicKey {
    if (!this.rsaKey) {
      return new RSAPublicKey(this.getType());
    }
    
    const keyData = this.rsaKey.exportKey('pkcs8-public');
    const clonedKey = new NodeRSA();
    clonedKey.importKey(keyData, 'pkcs8-public');
    
    return new RSAPublicKey(this.getType(), clonedKey, this.mgf1Salt);
  }

  toBytes(): Uint8Array {
    if (!this.rsaKey) {
      return new Uint8Array(0);
    }
    
    // Export public key in SPKI DER format
    const exported = this.rsaKey.exportKey('pkcs8-public-der');
    return new Uint8Array(exported);
  }

  fromBytes(type: VRFType, data: Uint8Array): boolean {
    if (!isRSAType(type)) {
      return false;
    }

    const params = getRSAVRFParams(type);
    if (!params || data.length === 0) {
      return false;
    }

    try {
      const key = new NodeRSA();
      key.importKey(Buffer.from(data), 'pkcs8-public-der');
      
      this.rsaKey = key;
      this.setType(type);
      this.mgf1Salt = new Uint8Array(hash(params.digest, 
        new TextEncoder().encode(params.suiteString)));
      
      return true;
    } catch (error) {
      console.error('Failed to import RSA public key:', error);
      return false;
    }
  }

  private rsaFDHVerify(input: Uint8Array, proofBytes: Uint8Array, params: RSAVRFParams): boolean {
    try {
      if (!this.rsaKey) {
        return false;
      }
      
      // Perform RSA verification (e-th power mod n)
      const signature = BigInt('0x' + Buffer.from(proofBytes).toString('hex'));
      const keyData = this.rsaKey.exportKey('components-public');
      const e = typeof keyData.e === 'number' ? BigInt(keyData.e) : bufferToBigInt(keyData.e);
      const n = bufferToBigInt(keyData.n);
      
      // Verify: message = signature^e mod n
      const verified = modPow(signature, e, n);
      const verifiedBytes = bigIntToBytes(verified, params.bits / 8);
      
      // Compare with expected hash
      const expectedHash = this.hashToFullDomain(input, params);
      
      return bytesEqual(verifiedBytes, expectedHash);
    } catch (error) {
      console.error('RSA-FDH verify error:', error);
      return false;
    }
  }

  private rsaPSSVerify(input: Uint8Array, proofBytes: Uint8Array, params: RSAVRFParams): boolean {
    try {
      if (!this.rsaKey) {
        return false;
      }
      
      // Perform RSA verification
      const signature = BigInt('0x' + Buffer.from(proofBytes).toString('hex'));
      const keyData = this.rsaKey.exportKey('components-public');
      const e = typeof keyData.e === 'number' ? BigInt(keyData.e) : bufferToBigInt(keyData.e);
      const n = bufferToBigInt(keyData.n);
      
      const verified = modPow(signature, e, n);
      const em = bigIntToBytes(verified, params.bits / 8);
      
      // Hash the input
      const mHash = hash(params.digest, concatBytes(
        new TextEncoder().encode(params.suiteString),
        input
      ));
      
      // Verify PSS encoding
      return this.pssVerify(mHash, em, params.bits, params);
    } catch (error) {
      console.error('RSA-PSS verify error:', error);
      return false;
    }
  }

  private hashToFullDomain(input: Uint8Array, params: RSAVRFParams): Uint8Array {
    const suiteBytes = new TextEncoder().encode(params.suiteString);
    const combined = concatBytes(suiteBytes, input);
    const hashed = hash(params.digest, combined);
    return this.mgf1WithSalt(hashed, params.bits / 8, params);
  }

  private mgf1WithSalt(seed: Uint8Array, maskLen: number, params: RSAVRFParams): Uint8Array {
    // MGF1 variant that includes suite string salt for VRF uniqueness
    const hLen = hash(params.digest, new Uint8Array(0)).length;
    if (maskLen > 0xffffffff * hLen) {
      throw new Error('Mask too long');
    }

    const result = new Uint8Array(maskLen);
    let offset = 0;
    let counter = 0;

    while (offset < maskLen) {
      const counterBytes = i2osp(BigInt(counter), 4);
      const hashInput = concatBytes(seed, this.mgf1Salt, counterBytes);
      const hashOutput = hash(params.digest, hashInput);
      
      const copyLen = Math.min(hashOutput.length, maskLen - offset);
      result.set(hashOutput.slice(0, copyLen), offset);
      
      offset += copyLen;
      counter++;
    }

    return result;
  }

  private mgf1(seed: Uint8Array, maskLen: number, params: RSAVRFParams): Uint8Array {
    // Standard MGF1 mask generation function (RFC 8017)
    const hLen = hash(params.digest, new Uint8Array(0)).length;
    if (maskLen > 0xffffffff * hLen) {
      throw new Error('Mask too long');
    }

    const result = new Uint8Array(maskLen);
    let offset = 0;
    let counter = 0;

    while (offset < maskLen) {
      const counterBytes = i2osp(BigInt(counter), 4);
      const hashInput = concatBytes(seed, counterBytes);
      const hashOutput = hash(params.digest, hashInput);
      
      const copyLen = Math.min(hashOutput.length, maskLen - offset);
      result.set(hashOutput.slice(0, copyLen), offset);
      
      offset += copyLen;
      counter++;
    }

    return result;
  }

  private pssVerify(mHash: Uint8Array, em: Uint8Array, emBits: number, params: RSAVRFParams): boolean {
    const hLen = mHash.length;
    const emLen = Math.ceil(emBits / 8);
    
    if (emLen < hLen + 2) {
      return false;
    }
    
    if (em[em.length - 1] !== 0xbc) {
      return false;
    }
    
    const maskedDB = em.slice(0, emLen - hLen - 1);
    const H = em.slice(emLen - hLen - 1, emLen - 1);
    
    // Check leftmost bits
    const mask = 0xFF >> (8 * emLen - emBits);
    if ((maskedDB[0] & ~mask) !== 0) {
      return false;
    }
    
    // dbMask = MGF(H, emLen - hLen - 1)
    const dbMask = this.mgf1(H, emLen - hLen - 1, params);
    
    // DB = maskedDB xor dbMask
    const DB = xorBytes(maskedDB, dbMask);
    DB[0] &= mask;
    
    // Check DB = PS || 0x01 || salt where salt is empty
    // Find the 0x01 separator
    let separatorIndex = -1;
    for (let i = 0; i < DB.length; i++) {
      if (DB[i] === 0x01) {
        separatorIndex = i;
        break;
      } else if (DB[i] !== 0x00) {
        return false; // Invalid padding
      }
    }
    
    if (separatorIndex === -1) {
      return false; // No separator found
    }
    
    // Verify no salt (everything after separator should be empty since saltLength=0)
    if (separatorIndex !== DB.length - 1) {
      return false; // Salt should be empty
    }
    
    // salt is empty
    const salt = new Uint8Array(0);
    
    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    const mPrime = concatBytes(new Uint8Array(8), mHash, salt);
    
    // H' = Hash(M')
    const HPrime = hash(params.digest, mPrime);
    
    // Verify H == H'
    return bytesEqual(H, HPrime);
  }
}

// Helper functions

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  
  return result;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  let v = value;
  
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
  
  return result;
}

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const length = Math.min(a.length, b.length);
  const result = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function bufferToBigInt(buffer: Buffer): bigint {
  return BigInt('0x' + buffer.toString('hex'));
}
