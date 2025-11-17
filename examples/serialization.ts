// Licensed under the MIT license.

import { VRF, VRFType } from '../src';

/**
 * Serialization example of libvrf-js
 */
function serializationExample() {
  console.log('=== Serialization Example ===\n');

  // 1. Create a VRF key pair
  const type = VRFType.EC_VRF_P256_SHA256_TAI;
  console.log('Creating VRF key pair with type:', type);
  
  const secretKey = VRF.create(type);
  if (!secretKey) {
    throw new Error('Failed to create secret key');
  }
  
  const publicKey = secretKey.getPublicKey();
  if (!publicKey) {
    throw new Error('Failed to get public key');
  }
  console.log('✓ Key pair created\n');

  // 2. Serialize the public key
  console.log('=== Serializing Public Key ===\n');
  const publicKeyBytes = publicKey.toBytes();
  console.log('Public key size:', publicKeyBytes.length, 'bytes');
  console.log('Public key (hex):', Buffer.from(publicKeyBytes).toString('hex').substring(0, 64), '...');
  console.log('Public key (base64):', Buffer.from(publicKeyBytes).toString('base64').substring(0, 64), '...\n');

  // 3. Deserialize the public key
  console.log('=== Deserializing Public Key ===\n');
  const loadedPublicKey = VRF.publicKeyFromBytes(type, publicKeyBytes);
  if (!loadedPublicKey || !loadedPublicKey.isInitialized()) {
    throw new Error('Failed to deserialize public key');
  }
  console.log('✓ Public key deserialized successfully\n');

  // 4. Generate a proof with the original key
  console.log('=== Generating and Serializing Proof ===\n');
  const input = new Uint8Array([1, 2, 3, 4, 5]);
  const proof = secretKey.getVRFProof(input);
  if (!proof) {
    throw new Error('Failed to create proof');
  }
  
  const proofBytes = proof.toBytes();
  console.log('Proof size:', proofBytes.length, 'bytes');
  console.log('Proof (hex):', Buffer.from(proofBytes).toString('hex').substring(0, 64), '...\n');

  // 5. Deserialize the proof
  console.log('=== Deserializing Proof ===\n');
  const loadedProof = VRF.proofFromBytes(type, proofBytes);
  if (!loadedProof || !loadedProof.isInitialized()) {
    throw new Error('Failed to deserialize proof');
  }
  console.log('✓ Proof deserialized successfully\n');

  // 6. Verify with the loaded public key and proof
  console.log('=== Verifying with Loaded Key and Proof ===\n');
  const [success, vrfValue] = loadedPublicKey.verifyVRFProof(input, loadedProof);
  
  if (success) {
    console.log('✓ Proof verified successfully with loaded key and proof!');
    console.log('VRF Value:', Buffer.from(vrfValue).toString('hex'));
  } else {
    console.log('✗ Proof verification failed');
  }

  // 7. Compare original and loaded VRF values
  console.log('\n=== Comparing Values ===\n');
  const [success2, vrfValue2] = publicKey.verifyVRFProof(input, proof);
  console.log('Original VRF Value === Loaded VRF Value:', 
    Buffer.compare(vrfValue, vrfValue2) === 0);
  
  // 8. Test serialization of all supported types
  console.log('\n=== Testing All VRF Types ===\n');
  const types = [
    VRFType.EC_VRF_P256_SHA256_TAI,
    VRFType.RSA_FDH_VRF_RSA2048_SHA256,
    VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256
  ];

  for (const testType of types) {
    const sk = VRF.create(testType);
    if (!sk) continue;
    
    const pk = sk.getPublicKey();
    if (!pk) continue;
    
    const pkBytes = pk.toBytes();
    const loadedPk = VRF.publicKeyFromBytes(testType, pkBytes);
    
    console.log(`${testType}:`);
    console.log(`  Public key size: ${pkBytes.length} bytes`);
    console.log(`  Serialization: ${loadedPk !== null ? '✓' : '✗'}`);
  }
}

// Run the example
serializationExample();

