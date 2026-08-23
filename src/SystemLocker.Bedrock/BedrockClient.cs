using System.Diagnostics;
using SystemLocker.Bedrock.Hwid;

namespace SystemLocker.Bedrock;

/// <summary>Delivered to the failure callback exactly once per session.</summary>
public sealed class HeartbeatFailure
{
    public required BedrockError Error { get; init; }
    public BedrockResponse? Response { get; init; }
    public long CompletedHeartbeats { get; init; }
}

/// <summary>Options for an authenticate call.</summary>
public sealed class InitializationOptions
{
    public bool RequestInvisibleFolderToken { get; init; }
    public IReadOnlyList<string> Variables { get; init; } = Array.Empty<string>();
}

/// <summary>Options for a heartbeat.</summary>
public sealed class HeartbeatOptions
{
    public bool RequestInvisibleFolderToken { get; init; }
}

/// <summary>The outcome of an authenticate call.</summary>
public sealed class AuthenticationResult
{
    public required BedrockResponse Response { get; init; }
    public bool SessionStarted { get; init; }
}

/// <summary>
/// Bedrock client for one system: authenticate once, then the background
/// heartbeat keeps the session alive (or drive <see cref="HeartbeatNowAsync"/>
/// manually with <c>AutomaticHeartbeats = false</c>). Thread-safe.
/// </summary>
public sealed class BedrockClient : IAsyncDisposable
{
    private static readonly TimeSpan ClockJumpTolerance = TimeSpan.FromSeconds(2);

    private readonly BedrockConfig _config;
    private readonly IHttpClient _http;
    private readonly Func<DateTimeOffset> _now;
    private readonly object _stateLock = new();
    private BedrockSession? _session;
    private Action<HeartbeatFailure>? _failureHook;
    private readonly InvisibleFolder _invisibleFolder;
    private readonly Dictionary<string, SLHwidSession> _ssSessions = new();
    private bool _disposed;

    // Swappable in tests to drive the secret-sharing module without touching
    // real hardware or storage.
    internal static Func<SLHwidOptions, SLHwidSession>? SlHwidPrepareOverride { get; set; }

    public BedrockClient(BedrockConfig config, IHttpClient? http = null, Func<DateTimeOffset>? now = null)
    {
        if (config.HwidMode != "legacy" && config.HwidMode != "sl-hwid")
        {
            throw new BedrockError(ErrorKind.Configuration, "HWID mode must be \"legacy\" or \"sl-hwid\".");
        }
        // An explicit hwid always wins. With an empty hwid, "legacy" derives
        // the pre-1.0 hardware hash eagerly; "sl-hwid" (the default since
        // 1.0.0) defers to the SL-HWID module at authentication time.
        if (string.IsNullOrEmpty(config.Hwid) && config.HwidMode == "legacy")
        {
            try
            {
                config.Hwid = HwidCollector.DeviceHwid();
            }
            catch (Exception error) when (error is InvalidOperationException or NotSupportedException)
            {
                throw new BedrockError(ErrorKind.Configuration, $"Could not derive the default hardware ID: {error.Message}. Supply a custom HWID or use \"1\" to disable device checks.");
            }
        }
        ValidateConfig(config);
        _config = config;
        _http = http ?? new DefaultHttpClient(config.RequestTimeout, config.UserAgent);
        _now = now ?? (static () => DateTimeOffset.UtcNow);
        _invisibleFolder = new InvisibleFolder(this);
    }

    public BedrockConfig Config => _config;

    internal IHttpClient Transport => _http;

    internal Func<DateTimeOffset> Now => _now;

    internal string Endpoint(string baseUrl, string path) => baseUrl.TrimEnd('/') + path;

    internal IReadOnlyDictionary<string, string> SignedHeaders() =>
        _config.SigningKeyId is null
            ? new Dictionary<string, string>()
            : new Dictionary<string, string> { ["X-Bedrock-Key-Id"] = _config.SigningKeyId };

    // Recovers (or enrolls) the §4A module's HWID for the identity, cached
    // per identity.
    private SLHwidSession PrepareSecretSharing(string identity)
    {
        lock (_stateLock)
        {
            if (_ssSessions.TryGetValue(identity, out var cached))
            {
                return cached;
            }
        }
        var sessionOptions = new SLHwidOptions
        {
            StorePath = _config.SLHwidStore ?? "",
            ExtraMandatory = _config.SLHwidExtraMandatory ?? Array.Empty<string>(),
        };
        SLHwidSession session;
        try
        {
            session = SlHwidPrepareOverride?.Invoke(sessionOptions) ?? SLHwid.Prepare(sessionOptions);
        }
        catch (Exception error) when (error is SLHwidDriftException or SLHwidCorruptDataException or InvalidOperationException)
        {
            throw new BedrockError(ErrorKind.LocalFailure, $"Secret-sharing HWID unavailable: {error.Message}");
        }
        lock (_stateLock)
        {
            _ssSessions[identity] = session;
        }
        return session;
    }

    private static void ValidateConfig(BedrockConfig config)
    {
        if (config.SystemId.Length != 20 || !config.SystemId.All(char.IsAsciiLetterOrDigit))
        {
            throw new BedrockError(ErrorKind.Configuration, "System ID must be exactly 20 alphanumeric characters.");
        }
        if (config.BeatRate < TimeSpan.FromSeconds(25) || config.BeatRate > TimeSpan.FromSeconds(3600))
        {
            throw new BedrockError(ErrorKind.Configuration, "Bedrock heartbeat interval must be from 25 through 3600 seconds.");
        }
        if (!config.BaseUrl.StartsWith("https://", StringComparison.Ordinal))
        {
            throw new BedrockError(ErrorKind.Configuration, "Bedrock base URL must use HTTPS.");
        }
        if (config.MaxServerClockSkew <= TimeSpan.Zero || config.MaxServerClockSkew > TimeSpan.FromHours(1))
        {
            throw new BedrockError(ErrorKind.Configuration, "Bedrock clock-skew allowance must be greater than zero and no more than one hour.");
        }
        try
        {
            if (Verification.Base64UrlDecode(config.SigningPublicKey).Length != 32)
            {
                throw new BedrockError(ErrorKind.Configuration, "The Bedrock public key must decode to exactly 32 bytes.");
            }
        }
        catch (BedrockError error) when (error.Kind == ErrorKind.InvalidPayload)
        {
            throw new BedrockError(ErrorKind.Configuration, "The Bedrock public key must decode to exactly 32 bytes.");
        }
    }

    // ── authentication ─────────────────────────────────────────────

    /// <exception cref="BedrockError">on any failure.</exception>
    public Task<AuthenticationResult> AuthenticateWithKeyAsync(string licenseKey, InitializationOptions? options = null, CancellationToken cancellationToken = default)
    {
        var fields = new Dictionary<string, string> { ["key"] = licenseKey };
        return AuthenticateAsync(fields, licenseKey, keyAuthentication: true, options ?? new InitializationOptions(), cancellationToken);
    }

    /// <exception cref="BedrockError">on any failure.</exception>
    public Task<AuthenticationResult> AuthenticateWithPasswordAsync(string username, string password, InitializationOptions? options = null, CancellationToken cancellationToken = default)
    {
        var fields = new Dictionary<string, string> { ["username"] = username, ["password"] = password };
        return AuthenticateAsync(fields, username, keyAuthentication: false, options ?? new InitializationOptions(), cancellationToken);
    }

    // ── Google SSO ────────────────────────────────────────────────

    /// <summary>Returns the Google SSO portal URL for the configured system.</summary>
    public string GoogleSsoUrl() => GoogleSso.PortalUrl(_config.SystemId);

    /// <summary>Opens the Google SSO portal for the configured system; see
    /// <see cref="GoogleSso.Begin"/> for the result contract.</summary>
    public string BeginGoogleSso(out bool opened) => GoogleSso.Begin(_config.SystemId, out opened);

    private async Task<AuthenticationResult> AuthenticateAsync(Dictionary<string, string> fields, string identity, bool keyAuthentication, InitializationOptions options, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var hwidValue = _config.Hwid;
        SLHwidSession? ssSession = null;
        if (string.IsNullOrEmpty(hwidValue)) // secret_sharing mode: recover or enroll at auth time
        {
            ssSession = PrepareSecretSharing(identity);
            hwidValue = ssSession.Hwid;
        }

        var challenge = Verification.GenerateChallenge();
        fields["system"] = _config.SystemId;
        fields["hwid"] = hwidValue;
        fields["version"] = _config.Version;
        fields["beatrate"] = ((int)_config.BeatRate.TotalSeconds).ToString();
        fields["challenge"] = challenge;
        if (_config.ProgramDigest is not null)
        {
            fields["digest"] = _config.ProgramDigest;
        }
        if (options.RequestInvisibleFolderToken)
        {
            fields["init-if"] = "true";
        }
        var postFields = new List<KeyValuePair<string, string>>(fields);
        foreach (var variable in options.Variables)
        {
            postFields.Add(new("variables[]", variable));
        }

        var httpResponse = await _http.PostFormAsync(
            Endpoint(_config.BaseUrl, "/auth/bedrock/init"), postFields, SignedHeaders(), cancellationToken).ConfigureAwait(false);
        if (!httpResponse.Ok)
        {
            var message = httpResponse.TransportError is not null
                ? $"Bedrock initialization transport failed: {httpResponse.TransportError}"
                : $"Bedrock initialization returned HTTP {httpResponse.StatusCode}.";
            throw new BedrockError(ErrorKind.Transport, message);
        }

        var response = Verification.VerifySignedResponse(_config, httpResponse, challenge, _now());

        var authenticatedCode = response.Code is ResponseCode.Ok or ResponseCode.Outdated;
        if (response.Authed != authenticatedCode)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock authentication flags contradict the response code.");
        }

        if (!response.Authed)
        {
            if (response.Variables.Count > 0 || response.InvisibleFolderToken is not null)
            {
                throw new BedrockError(ErrorKind.InvalidPayload, "A rejected Bedrock initialization returned successful-only data.");
            }
            return new AuthenticationResult { Response = response, SessionStarted = false };
        }
        if (response.SessionToken is null)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Authenticated Bedrock response did not contain a session token.");
        }
        if (!response.SessionToken.StartsWith("BRK_", StringComparison.Ordinal))
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock initialization returned an invalid session token format.");
        }

        var identityHash = Verification.Sha256Hex(identity);
        var responseHash = keyAuthentication ? response.LicenseKeyHash : response.UsernameHash;
        if (responseHash != identityHash)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock response identity hash does not match the authentication request.");
        }

        // The server accepted this identity on this device: re-center the
        // secret-sharing shares on the hardware observed this launch.
        // Failures are non-fatal — the next launch re-derives.
        ssSession?.Commit();

        BedrockSession? previous;
        lock (_stateLock)
        {
            previous = _session;
            _session = null;
        }
        if (previous is not null)
        {
            await previous.ShutdownAsync().ConfigureAwait(false);
        }

        var session = new BedrockSession(this, response.SessionToken, _failureHook);
        lock (_stateLock)
        {
            _session = session;
        }
        if (_config.AutomaticHeartbeats)
        {
            session.Start();
        }

        if (response.InvisibleFolderToken is not null)
        {
            _invisibleFolder.SetToken(response.InvisibleFolderToken);
        }
        return new AuthenticationResult { Response = response, SessionStarted = true };
    }

    // ── session control ────────────────────────────────────────────

    public async Task<BedrockResponse> HeartbeatNowAsync(HeartbeatOptions? options = null, CancellationToken cancellationToken = default)
    {
        BedrockSession? session;
        lock (_stateLock)
        {
            session = _session;
        }
        if (session is null)
        {
            throw new BedrockError(ErrorKind.SessionTerminated, "No Bedrock session is active.");
        }
        var response = await session.HeartbeatAsync(options ?? new HeartbeatOptions(), cancellationToken).ConfigureAwait(false);
        if (response.Authed && response.InvisibleFolderToken is not null)
        {
            _invisibleFolder.SetToken(response.InvisibleFolderToken);
        }
        return response;
    }

    public void OnHeartbeatFailure(Action<HeartbeatFailure> hook)
    {
        lock (_stateLock)
        {
            _failureHook = hook;
            _session?.SetHook(hook);
        }
    }

    public bool IsAuthenticated()
    {
        lock (_stateLock)
        {
            return _session is not null && _session.IsAlive;
        }
    }

    public long HeartbeatCount()
    {
        lock (_stateLock)
        {
            return _session?.CompletedHeartbeats ?? 0;
        }
    }

    public InvisibleFolder InvisibleFolder => _invisibleFolder;

    public async ValueTask DisposeAsync()
    {
        _disposed = true;
        await ShutdownAsync().ConfigureAwait(false);
        await _http.DisposeAsyncIfDisposable().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }

    public async Task ShutdownAsync()
    {
        BedrockSession? previous;
        lock (_stateLock)
        {
            previous = _session;
            _session = null;
        }
        if (previous is not null)
        {
            await previous.ShutdownAsync().ConfigureAwait(false);
        }
        _invisibleFolder.ClearToken();
    }
}

/// <summary>One authenticated session: rotating token and the heartbeat loop.</summary>
internal sealed class BedrockSession
{
    private readonly BedrockClient _client;
    private readonly object _tokenLock = new();
    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private string _token;
    private Action<HeartbeatFailure>? _hook;
    private volatile bool _alive = true;
    private long _completed;
    private CancellationTokenSource? _loopCancellation;
    private Task? _loopTask;

    public BedrockSession(BedrockClient client, string token, Action<HeartbeatFailure>? hook)
    {
        _client = client;
        _token = token;
        _hook = hook;
    }

    public bool IsAlive => _alive;

    public long CompletedHeartbeats => Interlocked.Read(ref _completed);

    public void SetHook(Action<HeartbeatFailure> hook) => _hook = hook;

    public void Start()
    {
        _loopCancellation = new CancellationTokenSource();
        var token = _loopCancellation.Token;
        _loopTask = Task.Run(() => RunAsync(token), token);
    }

    public async Task ShutdownAsync()
    {
        _alive = false;
        _loopCancellation?.Cancel();
        if (_loopTask is not null)
        {
            try
            {
                await _loopTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
        _loopCancellation?.Dispose();
        _loopCancellation = null;
    }

    public void Fail(BedrockError error, BedrockResponse? response = null)
    {
        var wasAlive = _alive;
        _alive = false;
        _loopCancellation?.Cancel();
        if (!wasAlive)
        {
            return;
        }
        var hook = _hook;
        if (hook is not null)
        {
            try
            {
                hook(new HeartbeatFailure { Error = error, Response = response, CompletedHeartbeats = Interlocked.Read(ref _completed) });
            }
            catch
            {
                // a throwing user hook must not break the session machinery
            }
        }
    }

    public async Task<BedrockResponse> HeartbeatAsync(HeartbeatOptions options, CancellationToken cancellationToken)
    {
        await _requestLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await HeartbeatOnceAsync(options, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _requestLock.Release();
        }
    }

    private async Task<BedrockResponse> HeartbeatOnceAsync(HeartbeatOptions options, CancellationToken cancellationToken)
    {
        if (!_alive)
        {
            throw new BedrockError(ErrorKind.SessionTerminated, "Bedrock session is not active.");
        }

        var challenge = Verification.GenerateChallenge();
        string token;
        lock (_tokenLock)
        {
            token = _token;
        }
        var fields = new List<KeyValuePair<string, string>>
        {
            new("session_token", token),
            new("system", _client.Config.SystemId),
            new("challenge", challenge),
        };
        if (options.RequestInvisibleFolderToken)
        {
            fields.Add(new("init-if", "true"));
        }

        var url = _client.Endpoint(_client.Config.BaseUrl, "/auth/bedrock/beat");
        var httpResponse = await _client.Transport.PostFormAsync(url, fields, _client.SignedHeaders(), cancellationToken).ConfigureAwait(false);
        // A transport failure may mean the server committed the rotation but
        // the response was lost. Repeat the exact token/challenge once so
        // Bedrock can return its cached signed response.
        if (httpResponse.TransportError is not null)
        {
            httpResponse = await _client.Transport.PostFormAsync(url, fields, _client.SignedHeaders(), cancellationToken).ConfigureAwait(false);
        }

        if (!httpResponse.Ok)
        {
            var message = httpResponse.TransportError is not null
                ? $"Bedrock heartbeat transport failed: {httpResponse.TransportError}"
                : $"Bedrock heartbeat returned HTTP {httpResponse.StatusCode}.";
            var error = new BedrockError(ErrorKind.Transport, message);
            Fail(error);
            throw error;
        }

        BedrockResponse response;
        try
        {
            response = Verification.VerifySignedResponse(_client.Config, httpResponse, challenge, _client.Now());
        }
        catch (BedrockError error)
        {
            if (error.Kind == ErrorKind.UnsignedResponse)
            {
                try
                {
                    response = Verification.ParseUnsignedRevocation(_client.Config, httpResponse, challenge, _client.Now());
                }
                catch (BedrockError revocationError)
                {
                    Fail(revocationError);
                    throw;
                }
            }
            else
            {
                Fail(error);
                throw;
            }
        }

        if (response.Code != ResponseCode.Ok || !response.Authed || response.SessionToken is null)
        {
            var message = response.TerminationMessage ?? response.HumanResponse;
            var error = new BedrockError(ErrorKind.SessionTerminated, message);
            Fail(error, response);
            return response;
        }
        if (!response.SessionToken.StartsWith("BRF_", StringComparison.Ordinal))
        {
            var error = new BedrockError(ErrorKind.InvalidPayload, "Bedrock heartbeat returned an invalid rotated token format.");
            Fail(error);
            throw error;
        }

        lock (_tokenLock)
        {
            _token = response.SessionToken;
        }
        Interlocked.Increment(ref _completed);
        return response;
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        var previousSteady = Stopwatch.GetTimestamp();
        var previousWall = DateTimeOffset.UtcNow;

        using var timer = new PeriodicTimer(_client.Config.BeatRate);
        while (!cancellationToken.IsCancellationRequested &&
               await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            var steady = Stopwatch.GetTimestamp();
            var wall = DateTimeOffset.UtcNow;
            var steadyElapsed = Stopwatch.GetElapsedTime(previousSteady, steady);
            var wallElapsed = wall - previousWall;
            previousSteady = steady;
            previousWall = wall;
            if (Math.Abs((steadyElapsed - wallElapsed).TotalSeconds) > 2.0)
            {
                Fail(new BedrockError(ErrorKind.LocalFailure, "Local clock changed unexpectedly during a Bedrock session."));
                return;
            }

            try
            {
                await HeartbeatAsync(new HeartbeatOptions(), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (BedrockError)
            {
                return; // Fail() already ran through the heartbeat error paths
            }
            if (!_alive)
            {
                return;
            }
        }
    }
}

file static class HttpClientDisposal
{
    public static ValueTask DisposeAsyncIfDisposable(this IHttpClient client)
    {
        if (client is IAsyncDisposable asyncDisposable)
        {
            return asyncDisposable.DisposeAsync();
        }
        if (client is IDisposable disposable)
        {
            disposable.Dispose();
        }
        return ValueTask.CompletedTask;
    }
}
