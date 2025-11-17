// Licensed under the MIT license.

import { VRF, VRFType } from '../src';

/**
 * Basic usage example of libvrf-js
 */
function basicExample() {
  console.log('=== Basic VRF Example ===\n');

  // 1. Choose a VRF type and generate a key pair
  const type = VRFType.RSA_FDH_VRF_RSA2048_SHA256;
  console.log('Creating VRF key pair with type:', type);
  
  const secretKey = VRF.create(type);
  if (!secretKey || !secretKey.isInitialized()) {
    throw new Error('Failed to create secret key');
  }
  console.log('✓ Secret key created\n');

  // 2. Get the public key
  const publicKey = secretKey.getPublicKey();
  if (!publicKey || !publicKey.isInitialized()) {
    throw new Error('Failed to get public key');
  }
  console.log('✓ Public key extracted\n');

  // 3. Generate a VRF proof for some input
  const input = new TextEncoder().encode('hello world');
  console.log('Input:', Buffer.from(input).toString());
  
  const proof = secretKey.getVRFProof(input);
  if (!proof || !proof.isInitialized()) {
    throw new Error('Failed to create proof');
  }
  console.log('✓ Proof generated\n');

  // 4. Verify the proof and get the VRF value
  const [success, vrfValue] = publicKey.verifyVRFProof(input, proof);
  
  if (success) {
    console.log('✓ Proof verified successfully!');
    console.log('VRF Value (hex):', Buffer.from(vrfValue).toString('hex'));
    console.log('VRF Value (base64):', Buffer.from(vrfValue).toString('base64'));
  } else {
    console.log('✗ Proof verification failed');
  }

  // 5. Demonstrate determinism
  console.log('\n=== Testing Determinism ===\n');
  const proof2 = secretKey.getVRFProof(input);
  const [success2, vrfValue2] = publicKey.verifyVRFProof(input, proof2);
  
  console.log('Proof 1 === Proof 2:', Buffer.compare(proof.toBytes(), proof2.toBytes()) === 0);
  console.log('VRF Value 1 === VRF Value 2:', Buffer.compare(vrfValue, vrfValue2) === 0);

  // 6. Different input produces different output
  console.log('\n=== Testing Different Input ===\n');
  const input2 = new TextEncoder().encode('goodbye world');
  const proof3 = secretKey.getVRFProof(input2);
  const [success3, vrfValue3] = publicKey.verifyVRFProof(input2, proof3);
  
  console.log('Input 2:', Buffer.from(input2).toString());
  console.log('VRF Value 3 (hex):', Buffer.from(vrfValue3).toString('hex'));
  console.log('VRF Value 1 === VRF Value 3:', Buffer.compare(vrfValue, vrfValue3) === 0);
}

// Run the example
basicExample();

