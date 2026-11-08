using Microsoft.Win32;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Neexitlag.Desktop;

// Only a server-issued bearer cookie is persisted, opt-in, under the current
// Windows user. The stored value contains no OTP, email or cached account data.
internal sealed class PersonalCabinetSession
{
    const string RegistryPath = @"Software\VELIQ\CabinetSessions";
    const string CookieName = "veliq_session";
    const string AccountPath = "/api/v1/account";
    readonly Uri endpoint;
    readonly byte[] entropy;
    readonly string valueName;
    internal CookieContainer Cookies { get; private set; } = new();

    internal PersonalCabinetSession(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != "https" || uri.UserInfo.Length != 0)
            throw new NativeAccountException("ACCOUNT_LINK_INVALID");
        endpoint = new Uri(uri.GetLeftPart(UriPartial.Authority) + AccountPath);
        entropy = SHA256.HashData(Encoding.UTF8.GetBytes("VELIQ cabinet v1 " + endpoint.AbsoluteUri));
        valueName = Convert.ToHexString(entropy);
    }

    internal static bool PersonalDevice(AccountConnectionView device, bool duringPersonalSetup = false)
    {
        if (device.ImagePreparation || device.ImageReady || device.Kind == "club") return false;
        if (!(device.Linked && device.Kind == "player") &&
            !(duringPersonalSetup && device.State is "NOT_LINKED" or "STARTING" or "WAITING_FOR_BROWSER")) return false;
        string marker = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VELIQ", "club-mode.json");
        try { _ = File.GetAttributes(marker); return false; }
        catch (FileNotFoundException) { return true; }
        catch (DirectoryNotFoundException) { return true; }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    static bool ValidToken(string token) => Regex.IsMatch(token, @"\A[A-Za-z0-9_-]{43}\z");

    internal bool Restore()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RegistryPath);
        if (key?.GetValue(valueName) is not byte[] sealedBytes) return false;
        try
        {
            if (sealedBytes.Length > 4096) throw new CryptographicException();
            byte[] bytes = ProtectedData.Unprotect(sealedBytes, entropy, DataProtectionScope.CurrentUser);
            string value;
            try { value = Encoding.ASCII.GetString(bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            if (!ValidToken(value)) throw new CryptographicException();
            Cookies.Add(endpoint, new Cookie(CookieName, value, AccountPath) { Secure = true, HttpOnly = true });
            return true;
        }
        catch (CryptographicException) { Forget(); return false; }
    }

    internal void Save()
    {
        var cookie = Cookies.GetCookies(endpoint)[CookieName];
        if (cookie is null || cookie.Expired || !cookie.Secure || !cookie.HttpOnly || cookie.Path != AccountPath ||
            !string.Equals(cookie.Domain, endpoint.Host, StringComparison.OrdinalIgnoreCase) || !ValidToken(cookie.Value))
            throw new NativeAccountException("ACCOUNT_SESSION_SAVE_FAILED");
        byte[] bytes = Encoding.ASCII.GetBytes(cookie.Value);
        try
        {
            byte[] sealedBytes = ProtectedData.Protect(bytes, entropy, DataProtectionScope.CurrentUser);
            using var key = Registry.CurrentUser.CreateSubKey(RegistryPath);
            key.SetValue(valueName, sealedBytes, RegistryValueKind.Binary);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal void Forget()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RegistryPath, writable: true);
        key?.DeleteValue(valueName, throwOnMissingValue: false);
        // The old client keeps its own jar long enough to revoke it on the server.
        Cookies = new();
    }
}
