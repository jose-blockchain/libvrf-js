// Licensed under the MIT license.

import { VRFType } from '../types';
import { constants } from 'crypto';

export interface RSAVRFParams {
  algorithmName: string;
  bits: number;
  primes: number;
  e: number;
  digest: string;
  padMode: number;
  suiteString: string;
}

/**
 * Get RSA VRF parameters for a given VRF type
 */
export function getRSAVRFParams(type: VRFType): RSAVRFParams | null {
  switch (type) {
    case VRFType.RSA_FDH_VRF_RSA2048_SHA256:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA2048-SHA256',
        bits: 2048,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_NO_PADDING,
        suiteString: 'RSA-FDH-VRF-RSA2048-SHA256'
      };
    case VRFType.RSA_FDH_VRF_RSA3072_SHA256:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA3072-SHA256',
        bits: 3072,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_NO_PADDING,
        suiteString: 'RSA-FDH-VRF-RSA3072-SHA256'
      };
    case VRFType.RSA_FDH_VRF_RSA4096_SHA384:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA4096-SHA384',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha384',
        padMode: constants.RSA_NO_PADDING,
        suiteString: 'RSA-FDH-VRF-RSA4096-SHA384'
      };
    case VRFType.RSA_FDH_VRF_RSA4096_SHA512:
      return {
        algorithmName: 'RSA-FDH-VRF-RSA4096-SHA512',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha512',
        padMode: constants.RSA_NO_PADDING,
        suiteString: 'RSA-FDH-VRF-RSA4096-SHA512'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA2048-SHA256',
        bits: 2048,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: 'RSA-PSS-NOSALT-VRF-RSA2048-SHA256'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA3072-SHA256',
        bits: 3072,
        primes: 2,
        e: 65537,
        digest: 'sha256',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: 'RSA-PSS-NOSALT-VRF-RSA3072-SHA256'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA4096-SHA384',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha384',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: 'RSA-PSS-NOSALT-VRF-RSA4096-SHA384'
      };
    case VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512:
      return {
        algorithmName: 'RSA-PSS-NOSALT-VRF-RSA4096-SHA512',
        bits: 4096,
        primes: 2,
        e: 65537,
        digest: 'sha512',
        padMode: constants.RSA_PKCS1_PSS_PADDING,
        suiteString: 'RSA-PSS-NOSALT-VRF-RSA4096-SHA512'
      };
    default:
      return null;
  }
}

