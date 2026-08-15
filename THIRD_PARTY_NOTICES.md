# Third-party notices

This package has **no third-party dependencies**.

- `src/SystemLocker.Bedrock/ThirdParty/Ed25519/Ed25519Verifier.cs` was
  written for this project (see its README); it implements the public
  algorithms of RFC 8032 (Edwards-Curve Digital Signature Algorithm),
  which is freely implementable by anyone.
- All other code is part of the System Locker Bedrock .NET client.

The vendored implementation is validated against RFC 8032 test vectors
published by the IETF.
