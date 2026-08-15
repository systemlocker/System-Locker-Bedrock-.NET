using SystemLocker.Bedrock;
using SystemLocker.Bedrock.Hwid;

// Smallest working Bedrock integration.
string hwid;
try
{
    hwid = HwidCollector.DeviceHwid();
}
catch (Exception)
{
    hwid = "my-own-stable-identifier"; // developer-supplied fallback
}

var client = new BedrockClient(new BedrockConfig
{
    SystemId = "abcdefghijklmnopqrst",             // from the dashboard
    SigningPublicKey = "…base64url Ed25519 key…",  // from the dashboard
    Hwid = hwid,
    Version = "1.0.0",
});
client.OnHeartbeatFailure(failure =>
{
    Console.WriteLine($"session ended: {failure.Error.Message}");
    Environment.Exit(1); // save state and exit — the license is no longer live
});

var result = await client.AuthenticateWithKeyAsync(
    "SL-XXXX-XXXX-XXXX",
    new InitializationOptions { RequestInvisibleFolderToken = true, Variables = new[] { "tier" } });
if (!result.SessionStarted)
{
    Console.WriteLine($"rejected: {result.Response.HumanResponse}");
    return;
}

Console.WriteLine("authenticated; heartbeating automatically");
// …your protected application logic…
await client.ShutdownAsync();
