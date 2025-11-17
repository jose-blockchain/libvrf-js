# Security

## Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in `libvrf-js`, please report it privately by:

1. Opening a security advisory on GitHub (preferred)
2. Emailing the repository maintainer directly

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

## Security Considerations

This library implements Verifiable Random Functions (VRFs) which are cryptographic primitives. When using this library:

1. **Key Management**: Protect secret keys appropriately. Never commit them to version control.
2. **Random Number Generation**: This library uses Node.js's `crypto.randomBytes()` which is cryptographically secure.
3. **Side-Channel Attacks**: While we attempt constant-time operations where feasible, complete side-channel resistance is not guaranteed.
4. **Production Use**: This is a JavaScript port of Microsoft's libvrf. For production systems requiring maximum security, consider the original C++ implementation.

## Supported Versions

Security updates are provided for the latest released version only.

## Acknowledgments

This library is a port of [Microsoft's libvrf](https://github.com/Microsoft/libvrf). Security issues in the underlying cryptographic algorithms should be reported to both projects.

