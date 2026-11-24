using System.Text.Json;

namespace SystemLocker.Bedrock;

/// <summary>A Bedrock response code. Unrecognized codes are protocol violations.</summary>
public enum ResponseCode
{
    Unknown,
    Ok,
    Outdated,
    MissingField,
    InvalidRequest,
    InvalidSystem,
    InvalidCredentials,
    GoogleSsoRequired,
    UserNotVerified,
    InvalidKey,
    KeyFrozen,
    HwidBanned,
    HwidMismatch,
    SpoofSuspected,
    SystemPaused,
    PlanInactive,
    ProductionAuthUnavailable,
    UserLimitReached,
    ExpiredKey,
    ProgramDigestMismatch,
    InvalidBeatRate,
    NoActiveSigningKey,
    InvalidSession,
    SessionTerminated,
    StaleSession,
    HeartbeatTooEarly,
    HeartbeatVarianceExceeded,
    SigningKeyRevoked,
    ConcurrentHeartbeat,
    InternalError,
    NightflyerLeaseActive,
}

/// <summary>A single server-side variable; <see cref="Found"/> distinguishes absent (JSON false) from an empty string.</summary>
public readonly record struct VariableValue(string? Value, bool Found);

/// <summary>A fully verified Bedrock response payload.</summary>
public sealed class BedrockResponse
{
    public ResponseCode Code { get; internal init; } = ResponseCode.Unknown;
    public string ResponseCodeName { get; internal init; } = "";
    public string HumanResponse { get; internal init; } = "";
    public bool IsError { get; internal init; }
    public bool IsFailure { get; internal init; }
    public bool Authed { get; internal init; }
    public string ProtocolVersion { get; internal init; } = "";
    /// <summary>Signing-key ULID authenticated inside the signed payload.</summary>
    public string? KeyId { get; internal init; }
    public string System { get; internal init; } = "";
    public string Challenge { get; internal init; } = "";
    public long ServerTime { get; internal init; }
    public string HumanTime { get; internal init; } = "";
    public string? SessionToken { get; internal init; }
    public string? LicenseKeyHash { get; internal init; }
    public string? UsernameHash { get; internal init; }
    public string? TerminationMessage { get; internal init; }
    /// <summary>Google SSO portal URL, on <see cref="ResponseCode.GoogleSsoRequired"/> denials.</summary>
    public string? SsoUrl { get; internal init; }
    public string? InvisibleFolderToken { get; internal init; }
    public IReadOnlyDictionary<string, VariableValue> Variables { get; internal init; } =
        new Dictionary<string, VariableValue>();
}

internal static class ResponseCodes
{
    private static readonly Dictionary<string, ResponseCode> Codes = new()
    {
        ["OK"] = ResponseCode.Ok,
        ["OUTDATED"] = ResponseCode.Outdated,
        ["MISSING_FIELD"] = ResponseCode.MissingField,
        ["INVALID_REQUEST"] = ResponseCode.InvalidRequest,
        ["INVALID_SYSTEM"] = ResponseCode.InvalidSystem,
        ["INVALID_CREDENTIALS"] = ResponseCode.InvalidCredentials,
        ["GOOGLE_SSO_REQUIRED"] = ResponseCode.GoogleSsoRequired,
        ["USER_NOT_VERIFIED"] = ResponseCode.UserNotVerified,
        ["INVALID_KEY"] = ResponseCode.InvalidKey,
        ["KEY_FROZEN"] = ResponseCode.KeyFrozen,
        ["HWID_BANNED"] = ResponseCode.HwidBanned,
        ["HWID_MISMATCH"] = ResponseCode.HwidMismatch,
        ["SPOOF_SUSPECTED"] = ResponseCode.SpoofSuspected,
        ["SYSTEM_PAUSED"] = ResponseCode.SystemPaused,
        ["PLAN_INACTIVE"] = ResponseCode.PlanInactive,
        ["PRODUCTION_AUTH_UNAVAILABLE"] = ResponseCode.ProductionAuthUnavailable,
        ["USER_LIMIT_REACHED"] = ResponseCode.UserLimitReached,
        ["EXPIRED_KEY"] = ResponseCode.ExpiredKey,
        ["PROGRAM_DIGEST_MISMATCH"] = ResponseCode.ProgramDigestMismatch,
        ["INVALID_BEATRATE"] = ResponseCode.InvalidBeatRate,
        ["NO_ACTIVE_SIGNING_KEY"] = ResponseCode.NoActiveSigningKey,
        ["INVALID_SESSION"] = ResponseCode.InvalidSession,
        ["SESSION_TERMINATED"] = ResponseCode.SessionTerminated,
        ["STALE_SESSION"] = ResponseCode.StaleSession,
        ["HEARTBEAT_TOO_EARLY"] = ResponseCode.HeartbeatTooEarly,
        ["HEARTBEAT_VARIANCE_EXCEEDED"] = ResponseCode.HeartbeatVarianceExceeded,
        ["SIGNING_KEY_REVOKED"] = ResponseCode.SigningKeyRevoked,
        ["CONCURRENT_HEARTBEAT"] = ResponseCode.ConcurrentHeartbeat,
        ["NIGHTFLYER_LEASE_ACTIVE"] = ResponseCode.NightflyerLeaseActive,
        ["INTERNAL_ERROR"] = ResponseCode.InternalError,
    };

    public static ResponseCode FromString(string value) =>
        Codes.TryGetValue(value, out var code) ? code : ResponseCode.Unknown;

    public static bool ExpectedAuthenticated(ResponseCode code) =>
        code is ResponseCode.Ok or ResponseCode.Outdated;

    public static readonly HashSet<ResponseCode> FailureCodes = new()
    {
        ResponseCode.MissingField, ResponseCode.InvalidRequest, ResponseCode.InvalidSystem,
        ResponseCode.SystemPaused, ResponseCode.PlanInactive, ResponseCode.ProductionAuthUnavailable,
        ResponseCode.ProgramDigestMismatch, ResponseCode.InvalidBeatRate,
        ResponseCode.NoActiveSigningKey, ResponseCode.InternalError,
    };

    public static bool ExpectedFailure(ResponseCode code) => FailureCodes.Contains(code);

    public static bool ExpectedError(ResponseCode code) => code != ResponseCode.Ok && !FailureCodes.Contains(code);
}
