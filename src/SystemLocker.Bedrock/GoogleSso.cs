using System.Diagnostics;

namespace SystemLocker.Bedrock;

/// <summary>
/// Google SSO helpers for Bedrock account authentication. Google-backed accounts
/// have no local password on the server; after Google sign-in at the portal, the
/// page shows a system-specific password (valid 180 days) that is then used as
/// the account password.
/// </summary>
public static class GoogleSso
{
    /// <summary>The server mints this URL in GOOGLE_SSO_REQUIRED denials; the
    /// client mirrors it so the flow can start before a denial is ever seen.</summary>
    public const string PortalBaseUrl = "https://systemlocker.net/user/sso?system=";

    /// <summary>Returns the Google SSO portal URL for a system.</summary>
    public static string PortalUrl(string systemId) =>
        PortalBaseUrl + Uri.EscapeDataString(systemId);

    /// <summary>
    /// Launches the default browser at a URL. Returns whether a browser launched;
    /// hosts without one (servers, containers) return false and the caller falls
    /// back to displaying the URL.
    /// </summary>
    public static bool OpenUrl(string url)
    {
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }
        try
        {
            using var process = Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            return process is not null;
        }
        catch (Exception ex) when (
            ex is System.ComponentModel.Win32Exception
                or InvalidOperationException
                or PlatformNotSupportedException
                or FileNotFoundException
                or DirectoryNotFoundException)
        {
            return false;
        }
    }

    /// <summary>
    /// Opens the Google SSO portal for a system in the default browser. The URL
    /// is always returned so flows without a browser can hand it to the
    /// developer; <paramref name="opened"/> reports whether the launch succeeded.
    /// </summary>
    public static string Begin(string systemId, out bool opened)
    {
        var url = PortalUrl(systemId);
        opened = OpenUrl(url);
        return url;
    }
}
