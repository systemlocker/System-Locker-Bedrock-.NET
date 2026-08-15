using System.Text;
using System.Text.Json;

namespace SystemLocker.Bedrock;

/// <summary>A file description plus its metadata entries.</summary>
public sealed class InvisibleFolderMetadata
{
    public required string Id { get; init; }
    public required string ReferenceId { get; init; }
    public required string Name { get; init; }
    public required string MimeType { get; init; }
    public required long Size { get; init; }
    public required long Downloads { get; init; }
    public required string UploadedAt { get; init; }
    public required long PermissionTypeId { get; init; }
    public required IReadOnlyDictionary<string, (string Value, string? CreatedAt)> Values { get; init; }
}

/// <summary>The outcome of <see cref="InvisibleFolder.DownloadIfNewAsync"/>.</summary>
public sealed class DownloadIfNewResult
{
    public bool Downloaded { get; init; }
    public required string Revision { get; init; }
    public required InvisibleFolderMetadata Metadata { get; init; }
    public byte[]? Bytes { get; init; }
    public string? Destination { get; init; }
}

/// <summary>Accesses Invisible Folder through the authenticated Bedrock session.</summary>
public sealed class InvisibleFolder
{
    private const string RevisionsKey = "__revisions";
    private readonly BedrockClient _client;
    private readonly object _tokenLock = new();
    private string _token = "";

    internal InvisibleFolder(BedrockClient client) => _client = client;

    internal void SetToken(string token)
    {
        lock (_tokenLock)
        {
            _token = token;
        }
    }

    internal void ClearToken()
    {
        lock (_tokenLock)
        {
            _token = "";
        }
    }

    public bool HasToken()
    {
        lock (_tokenLock)
        {
            return _token != "";
        }
    }

    private void CheckPrerequisites(string referenceId)
    {
        if (!_client.Config.InvisibleFolderBaseUrl.StartsWith("https://", StringComparison.Ordinal))
        {
            throw new BedrockError(ErrorKind.Configuration, "Invisible Folder base URL must use HTTPS.");
        }
        if (referenceId.Length is < 4 or > 128 || !referenceId.All(static c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-'))
        {
            throw new BedrockError(ErrorKind.Configuration, "Invisible Folder reference ID must be 4 through 128 URL-safe characters.");
        }
    }

    public async Task<byte[]> DownloadAsync(string referenceId, CancellationToken cancellationToken = default)
    {
        CheckPrerequisites(referenceId);
        string token;
        lock (_tokenLock)
        {
            token = _token;
        }
        if (token == "")
        {
            throw new BedrockError(ErrorKind.SessionTerminated, "No Invisible Folder token is available. Request one during initialization or a heartbeat.");
        }

        var url = _client.Endpoint(_client.Config.InvisibleFolderBaseUrl, "/a/") + referenceId;
        var response = await _client.Transport.PostFormAsync(
            url,
            new[] { new KeyValuePair<string, string>("invisiblefolder_token", token) },
            headers: null,
            cancellationToken).ConfigureAwait(false);
        if (!response.Ok)
        {
            var message = ParseErrorMessage(response);
            throw message is null
                ? TransportError("download", response)
                : new BedrockError(ErrorKind.Transport, $"Invisible Folder download failed: {message}");
        }
        return response.Body;
    }

    public async Task<string> DownloadToFileAsync(string referenceId, string destination, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(destination))
        {
            throw new BedrockError(ErrorKind.Configuration, "Invisible Folder download destination cannot be empty.");
        }
        var payload = await DownloadAsync(referenceId, cancellationToken).ConfigureAwait(false);
        try
        {
            await File.WriteAllBytesAsync(destination, payload, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new BedrockError(ErrorKind.LocalFailure, "Could not write Invisible Folder download destination.");
        }
        return destination;
    }

    public async Task<InvisibleFolderMetadata> GetMetadataAsync(string referenceId, IReadOnlyList<string>? keys = null, CancellationToken cancellationToken = default)
    {
        CheckPrerequisites(referenceId);

        var headers = new Dictionary<string, string>();
        if (_client.Config.InvisibleFolderApiKey is not null)
        {
            headers["X-Api-Key"] = _client.Config.InvisibleFolderApiKey;
        }
        lock (_tokenLock)
        {
            if (_token != "")
            {
                headers["X-Invisiblefolder-Token"] = _token;
            }
        }

        var url = _client.Endpoint(_client.Config.InvisibleFolderBaseUrl, "/api/v1/files/") + referenceId + "/metadata";
        if (keys is { Count: > 0 })
        {
            url += "?keys[]=" + string.Join("&keys[]=", keys.Select(Uri.EscapeDataString));
        }

        var response = await _client.Transport.GetAsync(url, headers, cancellationToken).ConfigureAwait(false);
        if (!response.Ok)
        {
            var message = ParseErrorMessage(response);
            throw message is null
                ? TransportError("metadata request", response)
                : new BedrockError(ErrorKind.Transport, $"Invisible Folder metadata request failed: {message}");
        }
        return ParseMetadata(response.Body);
    }

    public async Task<DownloadIfNewResult> DownloadIfNewAsync(string referenceId, string knownRevision = "", string? destination = null, CancellationToken cancellationToken = default)
    {
        var metadata = await GetMetadataAsync(referenceId, new[] { RevisionsKey }, cancellationToken).ConfigureAwait(false);
        if (!metadata.Values.TryGetValue(RevisionsKey, out var revision))
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Invisible Folder metadata did not contain __revisions.");
        }

        if (knownRevision != "" && knownRevision == revision.Value)
        {
            return new DownloadIfNewResult { Downloaded = false, Revision = revision.Value, Metadata = metadata };
        }

        if (destination is not null)
        {
            var saved = await DownloadToFileAsync(referenceId, destination, cancellationToken).ConfigureAwait(false);
            return new DownloadIfNewResult { Downloaded = true, Revision = revision.Value, Metadata = metadata, Destination = saved };
        }
        var bytes = await DownloadAsync(referenceId, cancellationToken).ConfigureAwait(false);
        return new DownloadIfNewResult { Downloaded = true, Revision = revision.Value, Metadata = metadata, Bytes = bytes };
    }

    private static string? ParseErrorMessage(HttpExchange response)
    {
        try
        {
            var json = JsonSerializer.Deserialize<JsonElement>(response.Body);
            if (json.ValueKind == JsonValueKind.Object)
            {
                if (json.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.String)
                {
                    return message.GetString();
                }
                if (json.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String)
                {
                    return error.GetString();
                }
            }
        }
        catch (JsonException)
        {
        }
        return null;
    }

    private static BedrockError TransportError(string action, HttpExchange response) =>
        response.TransportError is not null
            ? new BedrockError(ErrorKind.Transport, $"Invisible Folder {action} failed: {response.TransportError}")
            : new BedrockError(ErrorKind.Transport, $"Invisible Folder {action} returned HTTP {response.StatusCode}.");

    private static InvisibleFolderMetadata ParseMetadata(byte[] body)
    {
        JsonElement json;
        try
        {
            json = JsonSerializer.Deserialize<JsonElement>(body);
        }
        catch (JsonException)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Invisible Folder metadata JSON is invalid.");
        }
        var data = json.ValueKind == JsonValueKind.Object && json.TryGetProperty("data", out var dataElement)
            ? dataElement
            : throw new BedrockError(ErrorKind.InvalidPayload, "Invisible Folder metadata response has the wrong shape.");
        if (data.ValueKind != JsonValueKind.Object ||
            !data.TryGetProperty("file", out var file) || file.ValueKind != JsonValueKind.Object ||
            !data.TryGetProperty("metadata", out var metadataElement) || metadataElement.ValueKind != JsonValueKind.Object)
        {
            throw new BedrockError(ErrorKind.InvalidPayload, "Invisible Folder metadata response has the wrong shape.");
        }

        string String(string name) =>
            file.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
                ? element.GetString()!
                : throw new BedrockError(ErrorKind.InvalidPayload, $"Invisible Folder file field '{name}' is missing or has the wrong type.");
        long Integer(string name) =>
            file.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.Number && element.TryGetInt64(out var value)
                ? value
                : throw new BedrockError(ErrorKind.InvalidPayload, $"Invisible Folder file field '{name}' is missing or has the wrong type.");

        var values = new Dictionary<string, (string, string?)>();
        foreach (var entry in metadataElement.EnumerateObject())
        {
            if (entry.Value.ValueKind != JsonValueKind.Object ||
                !entry.Value.TryGetProperty("value", out var value) ||
                value.ValueKind != JsonValueKind.String)
            {
                throw new BedrockError(ErrorKind.InvalidPayload, "Invisible Folder metadata entry has the wrong type.");
            }
            string? createdAt = null;
            if (entry.Value.TryGetProperty("created_at", out var createdAtElement) && createdAtElement.ValueKind != JsonValueKind.Null)
            {
                if (createdAtElement.ValueKind != JsonValueKind.String)
                {
                    throw new BedrockError(ErrorKind.InvalidPayload, "Invisible Folder metadata creation time has the wrong type.");
                }
                createdAt = createdAtElement.GetString();
            }
            values[entry.Name] = (value.GetString()!, createdAt);
        }

        return new InvisibleFolderMetadata
        {
            Id = String("id"),
            ReferenceId = String("reference_id"),
            Name = String("name"),
            MimeType = String("mime_type"),
            Size = Integer("size"),
            Downloads = Integer("downloads"),
            UploadedAt = String("uploaded_at"),
            PermissionTypeId = Integer("permission_type_id"),
            Values = values,
        };
    }
}
