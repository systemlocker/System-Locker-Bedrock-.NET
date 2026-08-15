using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SystemLocker.Bedrock;

/// <summary>The Bedrock verification pipeline, in the specification's exact order:
/// transport headers, encoding, Ed25519 signature, then payload validation.</summary>
public static class Verification
{
    public const string ProtocolVersion = "bedrock-v1";
    private const int SignatureBytes = 64;
    private const int PublicKeyBytes = 32;
    private const int ChallengeBytes = 64;
    private const int MaxTransportBytes = 1024 * 1024;

    /// <summary>Fresh 64-byte base64url challenge from the system CSPRNG.</summary>
    public static string GenerateChallenge()
    {
        var random = new byte[ChallengeBytes];
        RandomNumberGenerator.Fill(random);
        return Base64UrlEncode(random);
    }

    /// <summary>Lowercase-hex SHA-256 of a string (identity hashes).</summary>
    public static string Sha256Hex(string value)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>Unpadded base64url encoding.</summary>
    public static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Strict base64url decoding (charset and length validated like every official client).</summary>
    public static byte[] Base64UrlDecode(string value)
    {
        if (value.Length == 0 || value.Length > MaxTransportBytes || value.Length % 4 == 1)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Invalid base64url length.");
        }
        foreach (var character in value)
        {
            var valid = character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!valid)
            {
                throw new BedrockError(ErrorKind.InvalidPayload, "Invalid base64url character.");
            }
        }
        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 += new string('=', (4 - base64.Length % 4) % 4);
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Invalid base64url value.");
        }
    }

    /// <exception cref="BedrockError">on any protocol violation.</exception>
    public static BedrockResponse VerifySignedResponse(BedrockConfig config, HttpExchange httpResponse, string expectedChallenge, DateTimeOffset now)
    {
        if (httpResponse.Header("x-bedrock-protocol") != ProtocolVersion ||
            httpResponse.Header("x-bedrock-signed") == "false")
        {
            throw new BedrockError(ErrorKind.UnsignedResponse, "Bedrock response is missing its signed transport headers.");
        }

        byte[] signedBytes;
        try
        {
            signedBytes = Base64UrlDecode(Encoding.Latin1.GetString(httpResponse.Body));
        }
        catch (BedrockError)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock signed response has an invalid encoding or length.");
        }
        if (signedBytes.Length <= SignatureBytes)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock signed response has an invalid encoding or length.");
        }

        byte[] publicKey;
        try
        {
            publicKey = Base64UrlDecode(config.SigningPublicKey);
        }
        catch (BedrockError)
        {
            throw new BedrockError(ErrorKind.Configuration, "Pinned Bedrock public key is not a raw 32-byte Ed25519 key.");
        }
        if (publicKey.Length != PublicKeyBytes)
        {
            throw new BedrockError(ErrorKind.Configuration, "Pinned Bedrock public key is not a raw 32-byte Ed25519 key.");
        }

        var signature = signedBytes.AsSpan(0, SignatureBytes);
        var message = signedBytes.AsSpan(SignatureBytes);
        if (!ThirdParty.Ed25519.Ed25519Verifier.Verify(publicKey, signature, message))
        {
            throw new BedrockError(ErrorKind.InvalidSignature, "Bedrock response signature verification failed.");
        }

        return ParsePayload(config, Encoding.UTF8.GetString(message), expectedChallenge, now, httpResponse);
    }

    /// <summary>The single permitted unsigned response: a SIGNING_KEY_REVOKED termination, denial-only.</summary>
    public static BedrockResponse ParseUnsignedRevocation(BedrockConfig config, HttpExchange httpResponse, string expectedChallenge, DateTimeOffset now)
    {
        if (httpResponse.Header("x-bedrock-signed") != "false" ||
            httpResponse.Header("x-bedrock-protocol") != ProtocolVersion)
        {
            throw new BedrockError(ErrorKind.UnsignedResponse, "Bedrock returned an unauthenticated response.");
        }
        var parsed = ParsePayload(config, Encoding.UTF8.GetString(httpResponse.Body), expectedChallenge, now);
        if (parsed.Code != ResponseCode.SigningKeyRevoked || parsed.TerminationMessage is null)
        {
            throw new BedrockError(ErrorKind.UnsignedResponse, "Unsigned Bedrock response is diagnostic only and cannot be trusted.");
        }
        return parsed;
    }

    internal static BedrockResponse ParsePayload(BedrockConfig config, string jsonText, string expectedChallenge, DateTimeOffset now, HttpExchange? httpResponse = null)
    {
        JsonElement json;
        try
        {
            json = JsonSerializer.Deserialize<JsonElement>(jsonText);
        }
        catch (JsonException)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock response JSON is invalid.");
        }
        if (json.ValueKind != JsonValueKind.Object)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock payload is not a JSON object.");
        }

        string RequireString(string name) =>
            json.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
                ? element.GetString()!
                : throw PayloadError(name);

        bool RequireBool(string name) =>
            json.TryGetProperty(name, out var element) && element.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? element.GetBoolean()
                : throw PayloadError(name);

        string? OptionalString(string name)
        {
            if (!json.TryGetProperty(name, out var element) || element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            return element.ValueKind == JsonValueKind.String
                ? element.GetString()
                : throw PayloadError(name);
        }

        if (!json.TryGetProperty("server_time", out var serverTimeElement) ||
            serverTimeElement.ValueKind != JsonValueKind.Number ||
            !serverTimeElement.TryGetInt64(out var serverTime))
        {
            throw PayloadError("server_time");
        }

        var responseCodeName = RequireString("response_code");
        var variables = ParseVariables(json);

        var response = new BedrockResponse
        {
            ProtocolVersion = RequireString("protocol_version"),
            KeyId = OptionalString("kid"),
            System = RequireString("system"),
            ResponseCodeName = responseCodeName,
            Code = ResponseCodes.FromString(responseCodeName),
            HumanResponse = RequireString("human_response"),
            IsError = RequireBool("is_error"),
            IsFailure = RequireBool("is_failure"),
            Authed = RequireBool("authed"),
            HumanTime = RequireString("human_time"),
            Challenge = RequireString("challenge"),
            ServerTime = serverTime,
            SessionToken = OptionalString("session_token"),
            LicenseKeyHash = OptionalString("license_key_hash"),
            UsernameHash = OptionalString("username_hash"),
            TerminationMessage = OptionalString("termination_message"),
            InvisibleFolderToken = OptionalString("invisible_folder_token"),
            Variables = variables,
        };

        if (response.ProtocolVersion != ProtocolVersion)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Unsupported Bedrock protocol version.");
        }
        if (httpResponse is not null &&
            (response.KeyId is null || httpResponse.Header("x-bedrock-key-id") != response.KeyId ||
             config.SigningKeyId is not null && response.KeyId != config.SigningKeyId))
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock response signing key ID is missing or inconsistent.");
        }
        if (response.Code == ResponseCode.Unknown)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock response contains an unknown response code.");
        }
        if (response.Authed != ResponseCodes.ExpectedAuthenticated(response.Code) ||
            response.IsError != ResponseCodes.ExpectedError(response.Code) ||
            response.IsFailure != ResponseCodes.ExpectedFailure(response.Code))
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock response flags contradict its response code.");
        }
        if (response.System != config.SystemId)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock response is bound to a different system.");
        }
        if (response.Challenge != expectedChallenge)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock response challenge does not match the request.");
        }
        var difference = Math.Abs(response.ServerTime - now.ToUnixTimeSeconds());
        if (difference > (long)config.MaxServerClockSkew.TotalSeconds)
        {
            throw new BedrockError(ErrorKind.FreshnessViolation, "Bedrock response server time is outside the configured freshness window.");
        }
        return response;

        static BedrockError PayloadError(string field) =>
            new(ErrorKind.InvalidPayload, $"Bedrock field '{field}' is missing or has the wrong type.");
    }

    private static IReadOnlyDictionary<string, VariableValue> ParseVariables(JsonElement json)
    {
        if (!json.TryGetProperty("variables", out var variablesElement))
        {
            return new Dictionary<string, VariableValue>();
        }
        if (variablesElement.ValueKind != JsonValueKind.Object)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock field 'variables' has the wrong type.");
        }
        var variables = new Dictionary<string, VariableValue>();
        foreach (var entry in variablesElement.EnumerateObject())
        {
            variables[entry.Name] = entry.Value.ValueKind switch
            {
                JsonValueKind.String => new VariableValue(entry.Value.GetString(), Found: true),
                JsonValueKind.False => new VariableValue(null, Found: false),
                _ => throw new BedrockError(ErrorKind.InvalidPayload, "Bedrock variable has the wrong type."),
            };
        }
        return variables;
    }
}
