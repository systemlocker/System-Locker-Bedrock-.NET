# Vendored Ed25519 (verification only)

`Ed25519Verifier.cs` is a dependency-free Ed25519 (RFC 8032) **signature
verifier** written for this library. The .NET base class library ships no
Ed25519 support, and the System Locker protocol requires verifying every
server response against a pinned key, so the implementation is vendored
here under `ThirdParty/Ed25519/`.

## Design

- **Verification only.** The client never signs anything. Signing exists
  solely in the test suite (`TestSigner`), which the production library
  never references.
- **BigInteger field arithmetic.** Curve operations run on
  `System.Numerics.BigInteger` with explicit mod-p reduction, kept small
  and auditable. A verification takes a few milliseconds — irrelevant for
  license checks. This is a deliberate trade for auditability over speed.
- **No constant-time claims.** Constant-time engineering protects secret
  scalars; every input here (key, message, signature) is public. This is
  not a limitation for signature verification, but the code must never be
  reused for signing or secret handling.
- **Strict decoding** (RFC 8032 §5.1.3/§5.1.7 guidance):
  - points with y ≥ p are rejected (non-canonical encodings),
  - a sign bit on x = 0 is rejected,
  - scalars S ≥ L are rejected, which together with recomputing R blocks
    signature malleability.

## Validation

The verifier is validated against:

- RFC 8032 §7.1 test vectors 1–3,
- tampered message / tampered signature rejection,
- malleability (S + L) rejection,
- non-canonical public-key rejection,
- the shared cross-language conformance vectors, including bodies signed
  by an independent implementation (Go `crypto/ed25519`).

## Provenance

Written for the System Locker Bedrock .NET client; not extracted from any
third-party project. No license restrictions apply beyond the repository's
own terms.
