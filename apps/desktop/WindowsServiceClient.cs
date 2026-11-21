using System.Runtime.InteropServices;
namespace Neexitlag.Desktop;
public sealed class WindowsServiceClient : IServiceClient
{
    readonly ServiceClient client = new();
    public async Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await client.Call<T>(method, payload, cancellationToken);
        }
        catch (ServiceException e) when (e.Failure is ServiceFailure.NotInstalled or ServiceFailure.Unavailable) { throw new ServiceException(Inspect() ?? (e.Failure == ServiceFailure.NotInstalled ? ServiceFailure.Unavailable : e.Failure)); }
    }
    public static ServiceFailure? Inspect() => Inspect(out _);
    public static bool IsRunning()
    {
        Inspect(out var running);
        return running;
    }
    static ServiceFailure? Inspect(out bool running)
    {
        running = false;
        var scm = OpenSCManager(null, null, 1);
        if (scm == IntPtr.Zero)
            return null;
        try
        {
            var service = OpenService(scm, "VELIQ", 4);
            if (service == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == 1060 ? ServiceFailure.NotInstalled : null;
            try
            {
                if (QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _))
                {
                    running = status.CurrentState == 4;
                    if (status.CurrentState == 1)
                        return ServiceFailure.Stopped;
                }
                return null;
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ServiceStatus
    {
        public uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
    }
    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, out ServiceStatus status, int size, out int needed);
    [DllImport("advapi32.dll")][return: MarshalAs(UnmanagedType.Bool)] static extern bool CloseServiceHandle(IntPtr handle);
}
