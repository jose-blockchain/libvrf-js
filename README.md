# libvrf-js

[![CI](https://github.com/jose-blockchain/libvrf-js/actions/workflows/ci.yml/badge.svg)](https://github.com/jose-blockchain/libvrf-js/actions)
[![npm version](https://img.shields.io/npm/v/libvrf.svg)](https://www.npmjs.com/package/libvrf)
[![npm downloads](https://img.shields.io/npm/dm/libvrf.svg)](https://www.npmjs.com/package/libvrf)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![GitHub stars](https://img.shields.io/github/stars/jose-blockchain/libvrf-js.svg?style=social)](https://github.com/jose-blockchain/libvrf-js/stargazers)

## Verifiable Random Functions for JavaScript

A Verifiable Random Function (VRF) is a cryptographic public-key primitive that, from a secret key and a given input, produces a unique pseudorandom output, along with a proof that the output was correctly computed. Only the secret key holder can generate the output–proof pair, but anyone with the corresponding public key can verify the proof.

`libvrf-js` is a TypeScript/JavaScript implementation of several VRFs for Node.js (v18+) and browsers (EC VRF only).

## Features

- **Multiple VRF algorithms**: RSA-FDH, RSA-PSS-NOSALT, and EC VRF (RFC 9381)
- **Node.js & Browsers**: EC VRF works in both Node.js and browsers; RSA VRFs work in Node.js only
- **Type-safe**: Written in TypeScript with full type definitions
- **Well-tested**: Comprehensive test suite ported from C++ implementation
- **Production-ready**: Professional-grade cryptographic library

## Installation

```bash
npm install libvrf
```

**Requirements:**
- Node.js v18.0.0 or later
- npm v9+ (or compatible package manager)

**Dependencies:**
- `node-rsa` (^1.1.1) - Used for RSA-based VRF operations only. EC VRF uses Node.js built-in crypto.

### Browser/CDN Usage

**✅ Browser Support**: EC VRF now works in browsers using WebCrypto API! RSA-based VRFs still require Node.js.

**Current Status:**
- ✅ **EC VRF**: Works in browsers using async APIs and WebCrypto
- ❌ **RSA VRFs**: Do not work in browsers (requires `node-rsa` and Node.js crypto)
- ✅ **Node.js**: All VRF types work correctly

The library is available via CDN:

**jsDelivr (latest version):**
```html
<script src="https://cdn.jsdelivr.net/npm/libvrf/dist/browser/libvrf.min.js"></script>
```

**unpkg (latest version):**
```html
<script src="https://unpkg.com/libvrf/dist/browser/libvrf.min.js"></script>
```

**Usage in browser:**
```html
<script src="https://unpkg.com/libvrf/dist/browser/libvrf.min.js"></script>
<script>
// After loading the script, use the global 'libvrf' object
// Note: Browser APIs are async
(async () => {
  // Create a secret key (async)
  const secretKey = await libvrf.VRF.createAsync(libvrf.VRFType.EC_VRF_P256_SHA256_TAI);
  
  // Get the public key (async)
  const publicKey = await secretKey.getPublicKeyAsync();
  
  // Generate a VRF proof (async)
  const input = new TextEncoder().encode('hello');
  const proof = await secretKey.getVRFProofAsync(input);
  
  // Verify the proof (async)
  const [success, vrfValue] = await publicKey.verifyVRFProofAsync(input, proof);
  
  console.log('Verification:', success);
  console.log('VRF Value:', Array.from(vrfValue).map(b => b.toString(16).padStart(2, '0')).join(''));
})();
</script>
```

**Important Notes:**
- **EC VRF only**: Only `EC_VRF_P256_SHA256_TAI` works in browsers
- **Async APIs**: Browser code must use `createAsync()`, `getPublicKeyAsync()`, `getVRFProofAsync()`, and `verifyVRFProofAsync()`
- **Node.js compatibility**: Node.js can also use the async APIs, or continue using the sync APIs

## Supported VRF Types

### RSA-based VRFs

#### RSA-FDH (Full Domain Hash)
- `RSA_FDH_VRF_RSA2048_SHA256` - RSA-FDH with 2048-bit key and SHA-256
- `RSA_FDH_VRF_RSA3072_SHA256` - RSA-FDH with 3072-bit key and SHA-256
- `RSA_FDH_VRF_RSA4096_SHA384` - RSA-FDH with 4096-bit key and SHA-384
- `RSA_FDH_VRF_RSA4096_SHA512` - RSA-FDH with 4096-bit key and SHA-512

#### RSA-PSS-NOSALT
- `RSA_PSS_NOSALT_VRF_RSA2048_SHA256` - RSA-PSS (no salt) with 2048-bit key and SHA-256
- `RSA_PSS_NOSALT_VRF_RSA3072_SHA256` - RSA-PSS (no salt) with 3072-bit key and SHA-256
- `RSA_PSS_NOSALT_VRF_RSA4096_SHA384` - RSA-PSS (no salt) with 4096-bit key and SHA-384
- `RSA_PSS_NOSALT_VRF_RSA4096_SHA512` - RSA-PSS (no salt) with 4096-bit key and SHA-512

### Elliptic Curve VRFs
- `EC_VRF_P256_SHA256_TAI` - ECVRF with P-256 curve and SHA-256 (RFC 9381)

## Quick Start

### Basic Usage

```typescript
import { VRF, VRFType } from 'libvrf';

// 1. Choose a VRF type and generate a key pair
const type = VRFType.RSA_FDH_VRF_RSA2048_SHA256;
const secretKey = VRF.create(type)!;

// 2. Get the public key
const publicKey = secretKey.getPublicKey()!;

// 3. Generate a VRF proof for some input
const input = new TextEncoder().encode('hello world');
const proof = secretKey.getVRFProof(input)!;

// 4. Verify the proof and get the VRF value
const [success, vrfValue] = publicKey.verifyVRFProof(input, proof);

console.log('Proof verified:', success);
console.log('VRF Value:', Buffer.from(vrfValue).toString('hex'));
```

### Serialization

```typescript
import { VRF, VRFType } from 'libvrf';

const type = VRFType.EC_VRF_P256_SHA256_TAI;
const secretKey = VRF.create(type)!;
const publicKey = secretKey.getPublicKey()!;

// Serialize public key (DER-encoded SPKI)
const publicKeyBytes = publicKey.toBytes();
console.log('Public key size:', publicKeyBytes.length, 'bytes');

// Deserialize public key
const loadedPublicKey = VRF.publicKeyFromBytes(type, publicKeyBytes)!;

// Serialize proof
const input = new Uint8Array([1, 2, 3, 4, 5]);
const proof = secretKey.getVRFProof(input)!;
const proofBytes = proof.toBytes();

// Deserialize proof
const loadedProof = VRF.proofFromBytes(type, proofBytes)!;

// Verify with loaded key and proof
const [success, vrfValue] = loadedPublicKey.verifyVRFProof(input, loadedProof);
console.log('Verification:', success);
console.log('VRF Value:', Buffer.from(vrfValue).toString('hex'));
```

### Using Different VRF Types

```typescript
import { VRF, VRFType } from 'libvrf';

// EC VRF (fastest, smallest keys)
const ecKey = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI)!;

// RSA-FDH VRF (widely compatible)
const rsaFdhKey = VRF.create(VRFType.RSA_FDH_VRF_RSA2048_SHA256)!;

// RSA-PSS VRF (based on RSA-PSS signatures)
const rsaPssKey = VRF.create(VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256)!;
```

## API Reference

### VRF

The main class providing static methods for VRF operations.

#### `VRF.create(type: VRFType): SecretKey | null`

Creates a new VRF secret key for the specified VRF type.

#### `VRF.proofFromBytes(type: VRFType, data: Uint8Array): Proof | null`

Deserializes a VRF proof from bytes.

#### `VRF.publicKeyFromBytes(type: VRFType, data: Uint8Array): PublicKey | null`

Deserializes a VRF public key from bytes.

### SecretKey

Represents a VRF secret key.

#### Methods

- `getVRFProof(input: Uint8Array): Proof | null` - Generates a VRF proof
- `getPublicKey(): PublicKey | null` - Returns the corresponding public key
- `clone(): SecretKey` - Creates a deep copy
- `isInitialized(): boolean` - Checks if properly initialized
- `getType(): VRFType` - Returns the VRF type

### PublicKey

Represents a VRF public key.

#### Methods

- `verifyVRFProof(input: Uint8Array, proof: Proof): [boolean, Uint8Array]` - Verifies a proof
- `toBytes(): Uint8Array` - Serializes the public key
- `fromBytes(type: VRFType, data: Uint8Array): boolean` - Deserializes from bytes
- `clone(): PublicKey` - Creates a deep copy
- `isInitialized(): boolean` - Checks if properly initialized
- `getType(): VRFType` - Returns the VRF type

### Proof

Represents a VRF proof.

#### Methods

- `getVRFValue(): Uint8Array` - Extracts the VRF value
- `toBytes(): Uint8Array` - Serializes the proof
- `fromBytes(type: VRFType, data: Uint8Array): boolean` - Deserializes from bytes
- `clone(): Proof` - Creates a deep copy
- `isInitialized(): boolean` - Checks if properly initialized
- `getType(): VRFType` - Returns the VRF type

## Security Considerations

**Important Security Notes:**

1. **EC VRF RFC 9381 Compliance**: The EC VRF implementation (`EC_VRF_P256_SHA256_TAI`) uses a **simplified deterministic construction** and is **NOT RFC 9381 compliant**. EC VRF proofs are **NOT interoperable** with RFC 9381 compliant implementations (including the C++ libvrf).

2. **Browser Support**: Only EC VRF works in browsers. RSA-based VRFs require Node.js. Browser code must use async APIs (`createAsync`, `getPublicKeyAsync`, `getVRFProofAsync`, `verifyVRFProofAsync`).

2. **Key Generation Trust**: RSA-based VRFs are not secure unless the key generation process is trusted. For more details, see [RFC 9381](https://datatracker.ietf.org/doc/rfc9381).

3. **Cryptographic Primitives**: This library uses Node.js's built-in `crypto` module and browser's WebCrypto API for cryptographic operations.

4. **Production Use**: This is a JavaScript port with simplified EC VRF implementation. For production systems requiring RFC 9381 compliance or interoperability, use the original [C++ libvrf](https://github.com/Microsoft/libvrf).

5. **VRF Value**: The VRF value is deterministic for a given key and input. The same key and input will always produce the same VRF value.

## Limitations

This JavaScript implementation has several important limitations compared to the original C++ `libvrf`:

### EC VRF RFC 9381 Compliance

- **NOT RFC 9381 Compliant**: The EC VRF implementation (`EC_VRF_P256_SHA256_TAI`) uses a simplified deterministic construction and does not implement the full RFC 9381 specification.
- **NOT Interoperable**: EC VRF proofs generated by this library cannot be verified by RFC 9381 compliant implementations (including the C++ libvrf), and vice versa.
- **Different Proof Format**: The proof structure and VRF output values differ from RFC 9381 compliant implementations.
- **Self-Consistent Only**: Proofs generated by this library can only be verified by this library.

### Browser Support

- **EC VRF Browser Support**: EC VRF (`EC_VRF_P256_SHA256_TAI`) works in browsers using WebCrypto API with async methods (`createAsync()`, `getPublicKeyAsync()`, `getVRFProofAsync()`, `verifyVRFProofAsync()`)
- **RSA VRFs**: RSA-based VRFs require `node-rsa` and Node.js crypto APIs, which are not available in browsers
- **Node.js Compatibility**: Node.js supports both sync and async APIs for EC VRF - use sync methods for backward compatibility or async methods for consistency with browser code

### Test Coverage

- **No Standard Test Vectors**: This implementation does not include RFC 9381 test vectors and has not been tested for compatibility with the C++ libvrf test vectors.
- **RSA VRF Compatibility**: RSA-FDH and RSA-PSS-NOSALT VRFs are likely compatible with the C++ implementation but have not been tested against C++ test vectors.

### Interoperability

- **EC VRF**: Not compatible with other RFC 9381 implementations or the C++ libvrf.
- **RSA VRFs**: Compatibility with other implementations is untested and may vary.

### Recommendations

- **For RFC 9381 Compliance**: Use the original [C++ libvrf](https://github.com/Microsoft/libvrf) or another RFC 9381 compliant implementation.
- **For Interoperability**: Do not use this library's EC VRF in systems that need to interoperate with other VRF implementations.
- **For Self-Contained Systems**: This library works well for systems where all components use `libvrf-js` exclusively.


## Browser Support

This library works in modern browsers that support:
- WebCrypto API
- ES2020 features
- Uint8Array

Tested browsers:
- Chrome/Edge 80+
- Firefox 75+
- Safari 14+

## Building

```bash
# Install dependencies
npm install

# Build for Node.js and browser
npm run build

# Build only for Node.js
npm run build:node

# Build only for browser
npm run build:browser

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Lint code
npm run lint
```

## Examples

See the [examples](examples/) directory for more usage examples:
- [Basic usage](examples/basic.ts)
- [Serialization](examples/serialization.ts)
- [Browser usage](examples/browser.html)

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This is a JavaScript/TypeScript port of the official [libvrf](https://github.com/Microsoft/libvrf) C++ library.

The original C++ implementation by Microsoft Corporation provides a robust, production-ready VRF library with comprehensive test coverage and full RFC 9381 compliance. This JavaScript port brings similar functionality to Node.js and browser environments while maintaining API compatibility with the original design.

**Note**: The EC VRF implementation in this JavaScript port uses a simplified deterministic construction and is NOT RFC 9381 compliant. For RFC 9381 compliance and interoperability, use the original C++ implementation.

## References

- [RFC 9381 - Verifiable Random Functions (VRFs)](https://datatracker.ietf.org/doc/rfc9381/)
- [libvrf - Official C++ implementation](https://github.com/Microsoft/libvrf)
- [Microsoft libvrf GitHub Repository](https://github.com/Microsoft/libvrf)

## Related Projects

- **Original C++ Library**: [https://github.com/Microsoft/libvrf](https://github.com/Microsoft/libvrf)
- This JavaScript/TypeScript port aims to provide the same API and functionality for web and Node.js applications

## Support

For issues, questions, or contributions related to:
- **This JavaScript port**: Please open issues in this repository
- **The original C++ library**: Visit [https://github.com/Microsoft/libvrf](https://github.com/Microsoft/libvrf)

