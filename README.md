# libvrf-js

[![CI](https://github.com/jose-blockchain/libvrf-js/workflows/CI/badge.svg)](https://github.com/jose-blockchain/libvrf-js/actions)
[![npm version](https://badge.fury.io/js/libvrf.svg)](https://badge.fury.io/js/libvrf)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Verifiable Random Functions for JavaScript

A Verifiable Random Function (VRF) is a cryptographic public-key primitive that, from a secret key and a given input, produces a unique pseudorandom output, along with a proof that the output was correctly computed. Only the secret key holder can generate the output–proof pair, but anyone with the corresponding public key can verify the proof.

`libvrf-js` is a TypeScript/JavaScript implementation of several VRFs that works in both Node.js (v18+) and modern browsers.

## Features

- **Multiple VRF algorithms**: RSA-FDH, RSA-PSS-NOSALT, and EC VRF (RFC 9381)
- **Universal**: Works in Node.js and browsers
- **Zero dependencies**: Uses native crypto APIs
- **Type-safe**: Written in TypeScript with full type definitions
- **Well-tested**: Comprehensive test suite ported from C++ implementation
- **Production-ready**: Professional-grade cryptographic library

## Installation

```bash
npm install libvrf
```

**Requirements:**
- Node.js v24 (Krypton LTS) or later
- npm v11+

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
const secretKey = VRF.create(type);

if (!secretKey || !secretKey.isInitialized()) {
  throw new Error('VRF secret key creation failed');
}

// 2. Get the public key
const publicKey = secretKey.getPublicKey();

if (!publicKey || !publicKey.isInitialized()) {
  throw new Error('VRF public key creation failed');
}

// 3. Generate a VRF proof for some input
const input = new TextEncoder().encode('hello world');
const proof = secretKey.getVRFProof(input);

if (!proof || !proof.isInitialized()) {
  throw new Error('Proof creation failed');
}

// 4. Verify the proof and get the VRF value
const [success, vrfValue] = publicKey.verifyVRFProof(input, proof);

if (success) {
  console.log('Proof verified successfully!');
  console.log('VRF Value:', Buffer.from(vrfValue).toString('hex'));
} else {
  console.log('Proof verification failed');
}
```

### Serialization

```typescript
import { VRF, VRFType } from 'libvrf';

const type = VRFType.EC_VRF_P256_SHA256_TAI;
const secretKey = VRF.create(type);
const publicKey = secretKey.getPublicKey();

// Serialize public key (DER-encoded SPKI)
const publicKeyBytes = publicKey.toBytes();
console.log('Public key size:', publicKeyBytes.length, 'bytes');

// Deserialize public key
const loadedPublicKey = VRF.publicKeyFromBytes(type, publicKeyBytes);

// Serialize proof
const input = new Uint8Array([1, 2, 3, 4, 5]);
const proof = secretKey.getVRFProof(input);
const proofBytes = proof.toBytes();

// Deserialize proof
const loadedProof = VRF.proofFromBytes(type, proofBytes);

// Verify with loaded key and proof
const [success, vrfValue] = loadedPublicKey.verifyVRFProof(input, loadedProof);
console.log('Verification:', success);
```

### Using Different VRF Types

```typescript
import { VRF, VRFType } from 'libvrf';

// EC VRF (fastest, smallest keys)
const ecKey = VRF.create(VRFType.EC_VRF_P256_SHA256_TAI);

// RSA-FDH VRF (widely compatible)
const rsaFdhKey = VRF.create(VRFType.RSA_FDH_VRF_RSA2048_SHA256);

// RSA-PSS VRF (based on RSA-PSS signatures)
const rsaPssKey = VRF.create(VRFType.RSA_PSS_NOSALT_VRF_RSA2048_SHA256);
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

1. **EC VRF RFC 9381 Compliance**: The EC VRF implementation (`EC_VRF_P256_SHA256_TAI`) uses a **simplified deterministic construction** and is **NOT RFC 9381 compliant**. See [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md) for details. EC VRF proofs are **NOT interoperable** with RFC 9381 compliant implementations (including the C++ libvrf).

2. **Key Generation Trust**: RSA-based VRFs are not secure unless the key generation process is trusted. For more details, see [RFC 9381](https://datatracker.ietf.org/doc/rfc9381).

3. **Cryptographic Primitives**: This library uses Node.js's built-in `crypto` module and browser's WebCrypto API for cryptographic operations.

4. **Production Use**: This is a JavaScript port with simplified EC VRF implementation. For production systems requiring RFC 9381 compliance or interoperability, use the original [C++ libvrf](https://github.com/Microsoft/libvrf).

5. **VRF Value**: The VRF value is deterministic for a given key and input. The same key and input will always produce the same VRF value.

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

Contributions are welcome! Please read our [Contributing Guide](../CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This is a JavaScript/TypeScript port of the official [libvrf](https://github.com/Microsoft/libvrf) C++ library.

The original C++ implementation by Microsoft Corporation provides a robust, production-ready VRF library with comprehensive test coverage and full RFC 9381 compliance. This JavaScript port brings similar functionality to Node.js and browser environments while maintaining API compatibility with the original design.

**Note**: The EC VRF implementation in this JavaScript port uses a simplified deterministic construction and is NOT RFC 9381 compliant. For RFC 9381 compliance and interoperability, use the original C++ implementation. See [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md) for detailed compatibility information.

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

