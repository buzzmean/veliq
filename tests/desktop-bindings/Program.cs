// Dev/test-only HTTP adapter. Production desktop uses only authenticated named pipes.
using System.Text;
using System.Text.Json;
using Neexitlag.Desktop;
string? url = null, tokenPath = null;
for (int i = 0; i < args.Length - 1; i++) { if (args[i] == "--demo-url") url = args[++i]; else if (args[i] == "--demo-token-file") tokenPath = args[++i]; }
if (url is null || tokenPath is null) throw new ArgumentException("Dev smoke requires --demo-url and --demo-token-file");
var uri = new Uri(url);
if (uri.Scheme != "http" || !uri.IsLoopback) throw new ArgumentException("Only loopback dev demo is supported");
var token = (await File.ReadAllTextAsync(tokenPath)).Trim();
using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(8) };
async Task<T> Call<T>(string method) { string id = Guid.NewGuid().ToString("N"); using var content = new StringContent(JsonSerializer.Serialize(new { version = 1, id, sent_at = DateTimeOffset.UtcNow, token, method }, WireJson.Options), Encoding.UTF8, "application/json"); using var response = await http.PostAsync(new Uri(uri, "/api/ipc"), content); response.EnsureSuccessStatusCode(); using var document = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()); var root = document.RootElement; if (root.GetProperty("version").GetInt32() != 1 || root.GetProperty("id").GetString() != id || !root.GetProperty("ok").GetBoolean()) throw new Exception("Invalid dev IPC response"); return root.GetProperty("data").Deserialize<T>(WireJson.Options)!; }
var status = await Call<Snapshot>("status");
if (!status.Connected || !status.Demo || status.Routes.Length < 1) throw new Exception("Demo state unavailable");
var profiles = await Call<Profile[]>("profiles");
var diagnostics = await Call<Check[]>("diagnostics");
if (profiles.Length < 3 || diagnostics.Length < 4) throw new Exception("Demo bindings incomplete");
Console.WriteLine($"Dev desktop bindings PASS: {status.Routes.Length} measured routes, {profiles.Length} profiles, {diagnostics.Length} diagnostics");
