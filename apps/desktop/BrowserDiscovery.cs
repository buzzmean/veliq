using Microsoft.Win32;
namespace Veliq.Desktop;

// Read-only owner registry discovery; no launch, scanner or elevation.
internal static class BrowserDiscovery {
 internal static IReadOnlyList<InstalledBrowser> Installed()=>BrowserCatalog.Discover(File.Exists,Environment.GetEnvironmentVariable,Registered);
 static IEnumerable<string> Registered(string id){
  var exe=id switch{"chrome"=>"chrome.exe","edge"=>"msedge.exe","firefox"=>"firefox.exe","brave"=>"brave.exe","yandex"=>"browser.exe","opera" or "opera-gx"=>"opera.exe",_=>""};
  if(exe=="")yield break;
  var found=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
  foreach(var hive in new[]{RegistryHive.CurrentUser,RegistryHive.LocalMachine})foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}){
   try {
    using var root=RegistryKey.OpenBaseKey(hive,view);
    using(var app=root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\App Paths\"+exe))Add(app?.GetValue(null) as string);
    using var clients=root.OpenSubKey(@"Software\Clients\StartMenuInternet");
    if(clients is not null)foreach(var name in clients.GetSubKeyNames().Take(128)){
     using var command=clients.OpenSubKey(name+@"\shell\open\command");Add(command?.GetValue(null) as string);
    }
   }catch(Exception e)when(e is UnauthorizedAccessException or System.Security.SecurityException or IOException){}
  }
  foreach(var path in found.Take(32))yield return path;
  void Add(string? value){
   var text=value?.Trim();if(string.IsNullOrWhiteSpace(text))return;
   string path=text.StartsWith('"')?text.Split('"').ElementAtOrDefault(1)??"":text;
   if(Path.IsPathFullyQualified(path)&&Path.GetFileName(path).Equals(exe,StringComparison.OrdinalIgnoreCase)&&File.Exists(path))found.Add(Path.GetFullPath(path));
  }
 }
}
