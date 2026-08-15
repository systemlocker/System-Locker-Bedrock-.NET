# Security Policy

## Threat model

Bedrock assumes the client machine is **untrusted**: an attacker can read
memory, intercept traffic, and replay captured messages. The controls that
matter therefore live in the protocol, not in obfuscation:

- Every response is Ed25519-signed and verified against the pinned
  `SigningPublicKey` **before parsing**. Nothing unsigned is ever trusted —
  with one denial-only exception (`SIGNING_KEY_REVOKED`), which can only end
  a session.
- Per-request 64-byte challenges from `RandomNumberGenerator` must be echoed
  exactly, binding each response to one request and defeating replay.
- `server_time` freshness, system/identity echoes, and token rotation
  (`BRK_`/`BRF_`) are all verified on every response.
- The vendored Ed25519 verifier uses strict decoding (y < p, S < L, no sign
  bit on zero), blocking signature malleability and non-canonical point
  forgeries. See `src/SystemLocker.Bedrock/ThirdParty/Ed25519/README.md`.

## Accepted limitations

- .NET strings cannot be wiped deterministically; credentials remain in
  garbage-collected memory until collection.
- Debugger-detection and code self-integrity checks from the C++ client do
  not meaningfully port to a managed runtime and are not implemented. The
  signature verification remains the real control.
- The vendored verifier uses `BigInteger` arithmetic and is not
  constant-time; every verified input is public, so no secret-timing
  attack surface exists for verification. Do not reuse it for signing.
- Downloads to disk are written unencrypted (parity with the C++ client);
  protect them at the application layer if needed.
- TLS certificate validation is always on; TLS public-key pinning is not
  implemented (the response signature already provides the
  man-in-the-middle defense).

## Reporting a vulnerability

Report privately through the System Locker developer dashboard. Do not open
public issues for security problems.
