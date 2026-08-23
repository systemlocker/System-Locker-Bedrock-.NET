namespace SystemLocker.Bedrock;

/// <summary>Configures a <see cref="BedrockClient"/>.</summary>
public sealed class BedrockConfig
{
    /// <summary>20-character alphanumeric system ID from the dashboard. Required.</summary>
    public required string SystemId { get; set; }

    /// <summary>Client version; "bypass" (the default) skips the version gate.</summary>
    public string Version { get; set; } = "bypass";

    /// <summary>Device identifier. Empty (the default) derives hardware factors; use "1" to disable device locking.</summary>
    public string Hwid { get; set; } = "";

    /// <summary>How the device identifier is derived when Hwid is empty. The
    /// default since 1.0.0 is "sl-hwid": the SL-HWID fault-tolerant threshold
    /// module (opt out with "legacy" to restore the pre-1.0
    /// hardware-factor hash). An explicit Hwid always takes precedence.</summary>
    public string HwidMode { get; set; } = "sl-hwid";

    /// <summary>Optionally redirects the SL-HWID module's storage to a
    /// directory (files on every platform); empty uses the platform default.</summary>
    public string? SLHwidStore { get; set; }

    /// <summary>Names additional hard-locked SL-HWID slots beyond the
    /// module's own persisted value (for example, "machine_guid").</summary>
    public string[]? SLHwidExtraMandatory { get; set; }

    /// <summary>Heartbeat interval; 25–3600 seconds.</summary>
    public TimeSpan BeatRate { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Per-request HTTP timeout.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>Allowed server_time drift; greater than zero, at most one hour.</summary>
    public TimeSpan MaxServerClockSkew { get; set; } = TimeSpan.FromSeconds(120);

    /// <summary>System Locker API root. HTTPS is enforced.</summary>
    public string BaseUrl { get; set; } = "https://systemlocker.net";

    /// <summary>Invisible Folder root. HTTPS is enforced.</summary>
    public string InvisibleFolderBaseUrl { get; set; } = "https://invisiblefolder.net";

    /// <summary>User agent reported to the server.</summary>
    public string UserAgent { get; set; } = "systemlocker-bedrock-dotnet/1.0";

    /// <summary>Optional program digest.</summary>
    public string? ProgramDigest { get; set; }

    /// <summary>Optional server signing-key pin sent as X-Bedrock-Key-Id.</summary>
    public string? SigningKeyId { get; set; }

    /// <summary>Optional API key for Invisible Folder metadata of non-Advanced files.</summary>
    public string? InvisibleFolderApiKey { get; set; }

    /// <summary>Base64url-encoded raw 32-byte Ed25519 public key. Required.</summary>
    public required string SigningPublicKey { get; set; }

    /// <summary>Run the background heartbeat loop (default). Disable for manual heartbeats.</summary>
    public bool AutomaticHeartbeats { get; set; } = true;
}
