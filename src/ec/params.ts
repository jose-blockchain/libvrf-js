// Licensed under the MIT license.

import { VRFType } from '../types';

export interface ECVRFParams {
  algorithmName: string;
  curve: string;
  cofactor: number;
  digest: string;
  suiteString: Uint8Array;
  qLen: number;   // Length of field element in bytes
  ptLen: number;  // Length of point encoding in bytes
  cLen: number;   // Challenge length in bytes
  fLen: number;   // Proof length in bytes
  hLen: number;   // Hash output length in bytes
}

/**
 * Get ECVRF parameters for a given VRF type
 */
export function getECVRFParams(type: VRFType): ECVRFParams | null {
  switch (type) {
    case VRFType.EC_VRF_P256_SHA256_TAI:
      return {
        algorithmName: 'ECVRF-P256-SHA256-TAI',
        curve: 'P-256',
        cofactor: 1,
        digest: 'sha256',
        suiteString: new Uint8Array([0x01]),
        qLen: 32,
        ptLen: 33,
        cLen: 16,
        fLen: 80,
        hLen: 32
      };
    default:
      return null;
  }
}

