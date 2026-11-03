using Microsoft.Win32;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
namespace Neexitlag.Desktop;

internal static class EmergencyPasswordStore
{
    internal const string KeyPath = @"SOFTWARE\VELIQ\EmergencyExit";
    public static void OpenSetup()
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Не найден VELIQ.");
        using var process = Process.Start(new ProcessStartInfo(executable, "--configure-emergency-password")
        {
            UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory
        });
    }
    public static async Task SaveAsync(byte[] password)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Для настройки нужны права администратора Windows.");
        var status = await new ServiceClient().Call<EmergencyStatus>("emergency.status");
        if (string.IsNullOrWhiteSpace(status.OwnerSid) || identity.User?.Value != status.OwnerSid)
            throw new InvalidOperationException("Откройте настройку из учётной записи Windows владельца установки.");
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var acl = new RegistrySecurity();
        acl.SetOwner(admins);
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { admins, system })
            acl.AddAccessRule(new RegistryAccessRule(sid, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        byte[] verifier = EmergencyPasswordVerifier.Create(password, status.OwnerSid);
        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = machine.CreateSubKey(KeyPath, RegistryKeyPermissionCheck.ReadWriteSubTree) ??
                throw new IOException("Не удалось открыть защищённое хранилище VELIQ.");
            // Protect before storing any verifier. Setup is an explicit elevated
            // owner action; resetting this value is unavailable to a club guest.
            key.SetAccessControl(acl);
            var actual = key.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            if (!actual.AreAccessRulesProtected || !admins.Equals(actual.GetOwner(typeof(SecurityIdentifier))))
                throw new IOException("Не удалось защитить пароль VELIQ.");
            var rules = actual.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<RegistryAccessRule>().ToArray();
            if (rules.Length != 2 || rules.Any(r => r.IsInherited || r.AccessControlType != AccessControlType.Allow ||
                r.RegistryRights != RegistryRights.FullControl || r.PropagationFlags != PropagationFlags.None ||
                !(r.IdentityReference.Equals(admins) || r.IdentityReference.Equals(system))))
                throw new IOException("Права хранилища пароля VELIQ не подтверждены.");
            key.SetValue("Verifier", verifier, RegistryValueKind.Binary);
            key.Flush();
        }
        finally { CryptographicOperations.ZeroMemory(verifier); }
    }
}
