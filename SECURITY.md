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

## SL-HWID module

The default threshold HWID module makes copied state and casual spoofing
harder by requiring a stored enrollment plus enough current recovery slots.
Schema-v2 groups correlated platform, display, and software signals so one
change in a group consumes at most one threshold slot. New enrollment and
re-centering require at least eight slots; from eight upward, recovery uses a
`ceil(70% of enrolled slots)` threshold and every mandatory slot must be
present. Existing schema-v1 helpers keep their stored threshold until a
successful authenticated commit migrates them.

This reduces HWID churn from ordinary hardware changes but does not change
the threat model for a determined local attacker who can read or patch the
client process. Raw signals are not stored in the helper; it stores threshold
shares. The random key itself is never persisted. .NET's garbage collector cannot
deterministically wipe every intermediate value; managed runtimes, allocators,
debuggers, crash reporters, or the operating system may retain copies.

Applications using the same store share one enrollment and HWID. Protect that
store and choose a separate explicit store when isolation is required.

## Reporting a vulnerability

Report privately through the System Locker developer dashboard. Do not open
public issues for security problems.
