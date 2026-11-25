using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
namespace Veliq.Desktop;

internal static class SetupUpdateBarrier
{
    internal static string NameFor(string directory)
    {
        var path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)).ToLowerInvariant();
        return @"Global\VELIQ-GUI-Update-" + Convert.ToHexString(SHA256.HashData(Encoding.Unicode.GetBytes(path))).ToLowerInvariant();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenEvent(uint access, bool inherit, string name);
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    internal static bool IsActive(string directory)
    {
        // SYNCHRONIZE позволяет читать признак, не изменяя объект установщика.
        var handle = OpenEvent(0x00100000, false, NameFor(directory));
        if (handle == IntPtr.Zero) return Marshal.GetLastWin32Error() != 2;
        try { return WaitForSingleObject(handle, 0) != 258; }
        finally { CloseHandle(handle); }
    }
}
