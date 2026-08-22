# System Locker Bedrock — .NET

Official C#/.NET 8+ client for **System Locker Bedrock**, the
license-verification protocol for software distributed to **untrusted
machines**. Every server response is Ed25519-signed and verified against a
pinned public key before parsing, sessions rotate tokens on every heartbeat,
and each request carries a fresh cryptographic challenge — replay attacks
and forged responses are infeasible even for an attacker who fully controls
the network.

If your code runs on a machine you control, look at the System Locker Simple
clients instead.

## Install

```sh
dotnet add package SystemLocker.Bedrock
```

**Zero NuGet dependencies** — Ed25519 verification is vendored under
`ThirdParty/Ed25519/` (see its README for design and validation notes).

## Quickstart

```csharp
using SystemLocker.Bedrock;

var client = new BedrockClient(new BedrockConfig
{
    SystemId = "abcdefghijklmnopqrst",             // from the dashboard
    SigningPublicKey = "…base64url Ed25519 key…",  // from the dashboard
    Version = "1.0.0",
});

client.OnHeartbeatFailure(failure =>
{
    Console.WriteLine("session ended: " + failure.Error.Message);
    Environment.Exit(1); // save state and exit — the license is no longer live
});

var result = await client.AuthenticateWithKeyAsync("SL-XXXX-XXXX-XXXX",
    new InitializationOptions { RequestInvisibleFolderToken = true });
if (!result.SessionStarted) return;

// …your protected application logic; heartbeats run on a PeriodicTimer…
await client.ShutdownAsync();
```

## What the client enforces for you

- **Signed responses only.** The Ed25519 signature is verified against the
  pinned key _before_ any parsing; tampered payloads never reach your code.
- **Challenge echoes.** Every init/beat carries a fresh 86-character CSPRNG
  challenge (`RandomNumberGenerator`) that the server must echo exactly.
- **Freshness.** `server_time` must be within `MaxServerClockSkew`
  (default 120 s) of the local clock.
- **Identity binding.** The response's `license_key_hash`/`username_hash`
  must equal the locally computed SHA-256 of the submitted credential.
- **Token rotation.** Init tokens start with `BRK_`, every heartbeat rotates
  to a `BRF_` token; a lost heartbeat response is retried once, idempotently.
- **Denial-only unsigned responses.** Exactly one unsigned response is ever
  accepted: a `SIGNING_KEY_REVOKED` termination, which only ends the session.

Failures throw `BedrockError` whose `Kind` (`ErrorKind.InvalidSignature`,
`ErrorKind.FreshnessViolation`, …) distinguishes infrastructure problems
from attacks from legitimate denials.

## Heartbeats

With `AutomaticHeartbeats = true` (the default) a background `Task` driven
by a `PeriodicTimer` beats every `BeatRate` (25–3600 s). When it fails,
your `OnHeartbeatFailure` hook fires once and the session is dead. Disable
it and `await client.HeartbeatNowAsync()` yourself for manual control.

## Invisible Folder file delivery

```csharp
var folder = client.InvisibleFolder;
var result = await folder.DownloadIfNewAsync("app-assets-v1", lastRevision, "assets.zip");
if (result.Downloaded) lastRevision = result.Revision; // persist this
```

`DownloadAsync` (bytes), `DownloadToFileAsync` (disk, unencrypted),
`GetMetadataAsync`, and `DownloadIfNewAsync` (revision-checked) are
available. Tokens live in memory only and clear on `ShutdownAsync`.

## Google SSO (account authentication)

Accounts created through Google sign-in have no local password on the
server. A `username`/`password` authentication for such an account is
answered with a signed `GOOGLE_SSO_REQUIRED` denial whose payload carries
`sso_url` — the portal where the user completes Google sign-in and receives
a system-specific password (valid 180 days) to use as their account
password. There is no callback; the user transcribes the generated password
into your login form and then attempts to login again.

```csharp
var result = await client.AuthenticateWithPasswordAsync(username, password);
if (result.Response.Code == ResponseCode.GoogleSsoRequired)
{
    // The denial's URL is authoritative; open it in the default browser.
    var portal = result.Response.SsoUrl ?? client.GoogleSsoUrl();
    if (!GoogleSso.OpenUrl(portal))
    {
        Console.WriteLine($"Finish Google sign-in at: {portal}"); // headless fallback
    }
}
```

You can also start the flow before any denial: `client.BeginGoogleSso(out
var opened)` (or `GoogleSso.Begin(systemId, out opened)`) opens the portal
and returns its URL.

## Device identifiers (HWID)

The library derives a hardware ID by default; set `config.Hwid = "1"` only to
explicitly disable device locking.

```csharp
using SystemLocker.Bedrock.Hwid;

config.Hwid = HwidCollector.DeviceHwid();
```

Derives a stable identifier from the machine GUID, hardware UUID, CPU id,
and MAC (Windows and Linux). Passing your own stable value works just as
well — and avoids hardware-enumeration quirks entirely.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
