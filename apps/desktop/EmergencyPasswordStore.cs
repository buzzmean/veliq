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
        byte[] verifier = EmergencyPasswordVerifier.Create(password, status.OwnerSid);
        try
        {
            using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            SaveVerifier(machine,KeyPath,verifier);
        }
        finally { CryptographicOperations.ZeroMemory(verifier); }
    }

    // The test host supplies a disposable HKCU key. Production always supplies
    // the fixed 64-bit machine key above; there is no IPC/path override.
    internal static void SaveVerifier(RegistryKey parent,string name,byte[] verifier)
    {
        // CreateSubKey's ordinary read/write handle cannot change owner/DACL.
        // Open explicitly with FullControl before setting the protected ACL.
        using (parent.CreateSubKey(name,RegistryKeyPermissionCheck.ReadWriteSubTree)) { }
        using var key = parent.OpenSubKey(name,RegistryKeyPermissionCheck.ReadWriteSubTree,RegistryRights.FullControl) ??
            throw new IOException("Не удалось открыть защищённое хранилище VELIQ.");
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        var acl = new RegistrySecurity();
        acl.SetOwner(admins);
        acl.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{admins,system})
            acl.AddAccessRule(new RegistryAccessRule(sid,RegistryRights.FullControl,InheritanceFlags.ContainerInherit,PropagationFlags.None,AccessControlType.Allow));
        key.SetAccessControl(acl);
        var actual=key.GetAccessControl(AccessControlSections.Owner|AccessControlSections.Access);
        if(!actual.AreAccessRulesProtected||!admins.Equals(actual.GetOwner(typeof(SecurityIdentifier))))
            throw new IOException("Не удалось защитить пароль VELIQ.");
        var rules=actual.GetAccessRules(true,true,typeof(SecurityIdentifier)).Cast<RegistryAccessRule>().ToArray();
        if(rules.Length!=2||rules.Any(r=>r.IsInherited||r.AccessControlType!=AccessControlType.Allow||
            r.RegistryRights!=RegistryRights.FullControl||r.PropagationFlags!=PropagationFlags.None||
            !(r.IdentityReference.Equals(admins)||r.IdentityReference.Equals(system))))
            throw new IOException("Права хранилища пароля VELIQ не подтверждены.");
        key.SetValue("Verifier",verifier,RegistryValueKind.Binary);
        key.Flush();
    }
}
