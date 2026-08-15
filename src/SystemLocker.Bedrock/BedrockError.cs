namespace SystemLocker.Bedrock;

/// <summary>Error kinds, identical across all official System Locker clients.</summary>
public enum ErrorKind
{
    /// <summary>The local configuration is invalid; no request was sent.</summary>
    Configuration,

    /// <summary>The HTTP exchange failed or returned a non-2xx status.</summary>
    Transport,

    /// <summary>The response lacked its signed transport headers.</summary>
    UnsignedResponse,

    /// <summary>Ed25519 verification against the pinned key failed.</summary>
    InvalidSignature,

    /// <summary>The signed payload violates the protocol or this request.</summary>
    InvalidPayload,

    /// <summary>server_time is outside the configured clock-skew window.</summary>
    FreshnessViolation,

    /// <summary>The session ended, by the server or locally.</summary>
    SessionTerminated,

    /// <summary>Local runtime failure (I/O, CSPRNG, clock).</summary>
    LocalFailure,
}

/// <summary>Every client operation throws this; <see cref="Kind"/> categorizes it.</summary>
public sealed class BedrockError : Exception
{
    public BedrockError(ErrorKind kind, string message) : base(message)
    {
        Kind = kind;
    }

    public ErrorKind Kind { get; }
}
