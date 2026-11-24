using System.Runtime.InteropServices;

namespace Veliq.Desktop;

// The non-elevated owner-user GUI requests a user GP refresh; never machine GP.
// Chromium's Windows loader watches user GP notifications. The API is async:
// success means requested, NOT observed live PAC uptake or a site PASS.
internal static class BrowserNativePolicy
{
    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool RefreshPolicyEx([MarshalAs(UnmanagedType.Bool)] bool machine, uint options);
    internal static string RequestRefresh() => RefreshPolicyEx(false, 1)
        ? "USER_POLICY_REFRESH_REQUESTED; LIVE_UPTAKE_NOT_OBSERVED"
        : "USER_POLICY_REFRESH_FAILED_" + Marshal.GetLastWin32Error();
}
