// Licensed under the MIT license.

import { VRFType, isRSAType, isECType } from './types';
import { Proof, PublicKey, SecretKey } from './base';
import { ECSecretKey, ECProof, ECPublicKey } from './ec/ecvrf';
import { RSASecretKey, RSAProof, RSAPublicKey } from './rsa/rsavrf';

/**
 * The main VRF class that encapsulates VRF operations. All methods are static.
 */
export class VRF {
  /**
   * Creates a new VRF secret key for the specified VRF type.
   * Returns the created secret key object, or null if key generation fails.
   */
  static create(type: VRFType): SecretKey | null {
    try {
      if (isECType(type)) {
        return new ECSecretKey(type);
      } else if (isRSAType(type)) {
        return new RSASecretKey(type);
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Deserializes a VRF proof from a Uint8Array for the specified VRF type.
   * Returns the deserialized proof object, or null if deserialization fails.
   */
  static proofFromBytes(type: VRFType, data: Uint8Array): Proof | null {
    try {
      let proof: Proof;
      
      if (isECType(type)) {
        proof = new ECProof();
      } else if (isRSAType(type)) {
        proof = new RSAProof();
      } else {
        return null;
      }

      const success = proof.fromBytes(type, data);
      return success && proof.isInitialized() ? proof : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Deserializes a VRF public key from a Uint8Array for the specified VRF type.
   * Returns the deserialized public key object, or null if deserialization fails.
   */
  static publicKeyFromBytes(type: VRFType, data: Uint8Array): PublicKey | null {
    try {
      let publicKey: PublicKey;
      
      if (isECType(type)) {
        publicKey = new ECPublicKey();
      } else if (isRSAType(type)) {
        publicKey = new RSAPublicKey();
      } else {
        return null;
      }

      const success = publicKey.fromBytes(type, data);
      return success && publicKey.isInitialized() ? publicKey : null;
    } catch (error) {
      return null;
    }
  }
}

