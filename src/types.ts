// Licensed under the MIT license.

/**
 * Supported VRF types enumeration
 */
export enum VRFType {
  RSA_FDH_VRF_RSA2048_SHA256 = 'RSA_FDH_VRF_RSA2048_SHA256',
  RSA_FDH_VRF_RSA3072_SHA256 = 'RSA_FDH_VRF_RSA3072_SHA256',
  RSA_FDH_VRF_RSA4096_SHA384 = 'RSA_FDH_VRF_RSA4096_SHA384',
  RSA_FDH_VRF_RSA4096_SHA512 = 'RSA_FDH_VRF_RSA4096_SHA512',
  RSA_PSS_NOSALT_VRF_RSA2048_SHA256 = 'RSA_PSS_NOSALT_VRF_RSA2048_SHA256',
  RSA_PSS_NOSALT_VRF_RSA3072_SHA256 = 'RSA_PSS_NOSALT_VRF_RSA3072_SHA256',
  RSA_PSS_NOSALT_VRF_RSA4096_SHA384 = 'RSA_PSS_NOSALT_VRF_RSA4096_SHA384',
  RSA_PSS_NOSALT_VRF_RSA4096_SHA512 = 'RSA_PSS_NOSALT_VRF_RSA4096_SHA512',
  EC_VRF_P256_SHA256_TAI = 'EC_VRF_P256_SHA256_TAI',
  UNKNOWN = 'UNKNOWN'
}

/**
 * Check if a VRF type is an RSA-based type
 */
export function isRSAType(type: VRFType): boolean {
  return type === VRFType.RSA_FDH_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA512 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512;
}

/**
 * Check if a VRF type is an elliptic curve type
 */
export function isECType(type: VRFType): boolean {
  return type === VRFType.EC_VRF_P256_SHA256_TAI;
}

/**
 * Check if a VRF type is RSA-FDH
 */
export function isRSAFDHType(type: VRFType): boolean {
  return type === VRFType.RSA_FDH_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_FDH_VRF_RSA4096_SHA512;
}

/**
 * Check if a VRF type is RSA-PSS-NOSALT
 */
export function isRSAPSSType(type: VRFType): boolean {
  return type === VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA384 ||
         type === VRFType.RSA_PSS_NOSALT_VRF_RSA4096_SHA512;
}

/**
 * Convert VRF type to string
 */
export function vrfTypeToString(type: VRFType): string {
  return type.toString();
}

