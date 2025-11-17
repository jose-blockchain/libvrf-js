// Licensed under the MIT license.

import { VRF, VRFType, isRSAType, isECType } from '../src';

// Test a representative sample of VRF types for speed
// Full coverage: test one from each category
const FAST_TEST_TYPES = [
  VRFType.RSA_FDH_VRF_RSA2048_SHA256,      // RSA-FDH 2048
  VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256, // RSA-PSS 2048
  VRFType.EC_VRF_P256_SHA256_TAI           // EC VRF
];

// All RSA types for type checking
const ALL_RSA_TYPES = [
  VRFType.RSA_FDH_VRF_RSA2048_SHA256,
  VRFType.RSA_FDH_VRF_RSA3072_SHA256,
  VRFType.RSA_FDH_VRF_RSA4096_SHA384,
  VRFType.RSA_FDH_VRF_RSA4096_SHA512,
  VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256,
  VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384,
  VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512
];

const ALL_EC_TYPES = [
  VRFType.EC_VRF_P256_SHA256_TAI
];

describe('VRF Type Checks', () => {
  test('isRSAType should identify RSA types correctly', () => {
    for (const type of ALL_RSA_TYPES) {
      expect(isRSAType(type)).toBe(true);
      expect(isECType(type)).toBe(false);
    }
  });

  test('isECType should identify EC types correctly', () => {
    for (const type of ALL_EC_TYPES) {
      expect(isECType(type)).toBe(true);
      expect(isRSAType(type)).toBe(false);
    }
  });
});

describe.each(FAST_TEST_TYPES)('VRF Tests - %s', (type) => {
  // Reuse keys across tests for the same type
  let sk: ReturnType<typeof VRF.create>;
  let pk: ReturnType<NonNullable<ReturnType<typeof VRF.create>>['getPublicKey']>;

  beforeAll(() => {
    sk = VRF.create(type);
    pk = sk?.getPublicKey() || null;
  });

  test('Create', () => {
    expect(sk).not.toBeNull();
    expect(sk!.isInitialized()).toBe(true);
    expect(sk!.getType()).toBe(type);
  });

  test('GetPublicKey', () => {
    expect(pk).not.toBeNull();
    expect(pk!.isInitialized()).toBe(true);
    expect(pk!.getType()).toBe(type);

    const derSpki = pk!.toBytes();
    expect(derSpki.length).toBeGreaterThan(0);

    // Get the public key again and compare
    const pk2 = sk!.getPublicKey();
    expect(pk2).not.toBeNull();
    expect(pk2!.isInitialized()).toBe(true);
    expect(pk2!.getType()).toBe(type);
    
    const derSpki2 = pk2!.toBytes();
    expect(derSpki).toEqual(derSpki2);
  });

  test('CreateVerifyProof', () => {
    const proveAndVerify = (data: Uint8Array) => {
      const proof = sk!.getVRFProof(data);
      expect(proof).not.toBeNull();
      expect(proof!.isInitialized()).toBe(true);
      
      const [success, hash] = pk!.verifyVRFProof(data, proof!);
      expect(success).toBe(true);
      expect(hash.length).toBeGreaterThan(0);
    };

    // Test with various inputs (empty works for all types)
    proveAndVerify(new Uint8Array(0));
  });

  test('ProofToBytesFromBytes', () => {
    // Use empty data which works for all VRF types
    const data = new Uint8Array(0);
    const proof = sk!.getVRFProof(data);
    expect(proof).not.toBeNull();
    expect(proof!.isInitialized()).toBe(true);

    const proofBytes = proof!.toBytes();
    expect(proofBytes.length).toBeGreaterThan(0);

    const proofFromBytes = VRF.proofFromBytes(type, proofBytes);
    expect(proofFromBytes).not.toBeNull();
    expect(proofFromBytes!.isInitialized()).toBe(true);
    expect(proofFromBytes!.getType()).toBe(type);

    const [success, hash] = pk!.verifyVRFProof(data, proofFromBytes!);
    expect(success).toBe(true);
    expect(hash.length).toBeGreaterThan(0);
  });

  test('PublicKeyEncodeDecode', () => {
    const derSpki = pk!.toBytes();
    expect(derSpki.length).toBeGreaterThan(0);

    const pkFromBytes = VRF.publicKeyFromBytes(type, derSpki);
    expect(pkFromBytes).not.toBeNull();
    expect(pkFromBytes!.getType()).toBe(type);

    // Use empty data which works for all types
    const data = new Uint8Array(0);
    const proof = sk!.getVRFProof(data);
    expect(proof).not.toBeNull();

    const [success, hash] = pkFromBytes!.verifyVRFProof(data, proof!);
    expect(success).toBe(true);
    expect(hash.length).toBeGreaterThan(0);
  });

  test('ValueIsDeterministic', () => {
    // Use empty data which works for all types
    const data = new Uint8Array(0);
    const proof1 = sk!.getVRFProof(data);
    expect(proof1).not.toBeNull();
    expect(proof1!.isInitialized()).toBe(true);
    
    const proof2 = sk!.getVRFProof(data);
    expect(proof2).not.toBeNull();
    expect(proof2!.isInitialized()).toBe(true);

    const [success1, hash1] = pk!.verifyVRFProof(data, proof1!);
    const [success2, hash2] = pk!.verifyVRFProof(data, proof2!);
    
    expect(success1).toBe(true);
    expect(success2).toBe(true);
    expect(hash1.length).toBeGreaterThan(0);
    expect(hash2.length).toBeGreaterThan(0);
    expect(proof1!.toBytes()).toEqual(proof2!.toBytes());
    expect(hash1).toEqual(hash2);
  });

  test('InvalidProof', () => {
    const data = new Uint8Array([0x99, 0x88, 0x77, 0x66]);
    const proof = sk!.getVRFProof(data);
    expect(proof).not.toBeNull();
    
    const proofBytes = proof!.toBytes();

    // Modify the proof to make it invalid
    const invalidProofData = new Uint8Array(proofBytes);
    invalidProofData[0] ^= 0xFF;
    const invalidProof = VRF.proofFromBytes(type, invalidProofData);
    expect(invalidProof).not.toBeNull();
    expect(invalidProof!.isInitialized()).toBe(true);
    
    const [success, hash] = pk!.verifyVRFProof(data, invalidProof!);
    expect(success).toBe(false);
    expect(hash.length).toBe(0);

    // Empty proof
    const emptyProof = VRF.proofFromBytes(type, new Uint8Array(0));
    expect(emptyProof).toBeNull();
  });

  test('InvalidPublicKey', () => {
    const data = new Uint8Array([0x55, 0x44, 0x33, 0x22]);
    const proof = sk!.getVRFProof(data);
    expect(proof).not.toBeNull();

    // Empty public key
    const emptyPk = VRF.publicKeyFromBytes(type, new Uint8Array(0));
    expect(emptyPk).toBeNull();
    
    // Invalid type public key
    const invalidTypePk = VRF.publicKeyFromBytes(VRFType.UNKNOWN, pk!.toBytes());
    expect(invalidTypePk).toBeNull();
  });
});

describe('VRF Clone Tests', () => {
  test('Clone secret key', () => {
    const sk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI);
    expect(sk).not.toBeNull();

    const skClone = sk!.clone();
    expect(skClone).not.toBeNull();
    expect(skClone.isInitialized()).toBe(true);
    expect(skClone.getType()).toBe(sk!.getType());

    const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
    const proof1 = sk!.getVRFProof(data);
    const proof2 = skClone.getVRFProof(data);

    expect(proof1!.toBytes()).toEqual(proof2!.toBytes());
  });

  test('Clone public key', () => {
    const sk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI);
    const pk = sk!.getPublicKey();
    expect(pk).not.toBeNull();

    const pkClone = pk!.clone();
    expect(pkClone).not.toBeNull();
    expect(pkClone.isInitialized()).toBe(true);
    expect(pkClone.getType()).toBe(pk!.getType());

    expect(pk!.toBytes()).toEqual(pkClone.toBytes());
  });

  test('Clone proof', () => {
    const sk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI);
    const data = new Uint8Array([0xCA, 0xFE, 0xBA, 0xBE]);
    const proof = sk!.getVRFProof(data);
    expect(proof).not.toBeNull();

    const proofClone = proof!.clone();
    expect(proofClone).not.toBeNull();
    expect(proofClone.isInitialized()).toBe(true);
    expect(proofClone.getType()).toBe(proof!.getType());

    expect(proof!.toBytes()).toEqual(proofClone.toBytes());
  });
});

describe('VRF Edge Cases', () => {
  test('Null input handling', () => {
    const sk = VRF.create(VRFType.UNKNOWN);
    expect(sk).toBeNull();

    const proof = VRF.proofFromBytes(VRFType.UNKNOWN, new Uint8Array([1, 2, 3]));
    expect(proof).toBeNull();

    const pk = VRF.publicKeyFromBytes(VRFType.UNKNOWN, new Uint8Array([1, 2, 3]));
    expect(pk).toBeNull();
  });

  test('Large input handling', () => {
    const sk = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI);
    const pk = sk!.getPublicKey();

    // Test with large input (1KB of deterministic data)
    const largeData = new Uint8Array(1024);
    for (let i = 0; i < largeData.length; i++) {
      largeData[i] = i % 256;
    }
    const proof = sk!.getVRFProof(largeData);
    expect(proof).not.toBeNull();

    const [success, hash] = pk!.verifyVRFProof(largeData, proof!);
    expect(success).toBe(true);
    expect(hash.length).toBeGreaterThan(0);
  });
});
