using System.Xml.Linq;
using System.Text.RegularExpressions;
using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class ResourceTests
{
    static string Root()
    {
        var folder = new DirectoryInfo(AppContext.BaseDirectory);
        while (folder is not null && !File.Exists(Path.Combine(folder.FullName, "NeExitLag.sln")))
            folder = folder.Parent;
        return folder?.FullName ?? throw new Exception("Repository root missing");
    }
    [Fact]
    public void AllPublishedResourcesAreRussianExceptProtocolAndBrandNames()
    {
        var resources = XDocument.Load(Path.Combine(Root(), "apps/desktop-core/Resources/Strings.resx"));
        var data = resources.Descendants("data").ToArray();
        Assert.True(data.Length > 90);
        foreach (var entry in data)
        {
            string key = entry.Attribute("name")!.Value;
            string text = Text.Get(key);
            Assert.Equal(entry.Element("value")!.Value, text);
            if (text != "VELIQ")
                Assert.Matches("[А-Яа-яЁё]", text);
        }
    }
    [Fact]
    public void VisibleXamlStringsUseExistingResources()
    {
        var windows = new[] { "MainWindow.xaml", "AddApplicationWindow.xaml" }.Select(name => XDocument.Load(Path.Combine(Root(), "apps/desktop", name)));
        foreach (var a in windows.SelectMany(xaml => xaml.Descendants().Attributes()).Where(a => new[] { "Text", "Content", "Header", "Title", "ToolTip" }.Contains(a.Name.LocalName)))
        {
            if (a.Value.StartsWith("{ui:Tr "))
            {
                var key = a.Value[7..^1];
                Assert.False(string.IsNullOrEmpty(Text.Get(key)));
            }
            else
                Assert.True(a.Value.StartsWith("{Binding") || a.Value == "VELIQ", $"Unlocalized visible XAML: {a}");
        }
    }
    [Fact]
    public void ProductionDesktopDoesNotContainBrowserTransportOrRequireElevation()
    {
        string root = Root();
        Assert.Contains("asInvoker", File.ReadAllText(Path.Combine(root, "apps/desktop/app.manifest")));
        var productionFiles = Directory.GetFiles(Path.Combine(root, "apps/desktop"), "*.cs").Concat(Directory.GetFiles(Path.Combine(root, "apps/desktop-core"), "*.cs"));
        foreach (var path in productionFiles)
        {
            string code = File.ReadAllText(path);
            // The native account API is the only desktop HTTPS transport.
            // Browser/proxy transport and loopback servers remain prohibited.
            if (Path.GetFullPath(path) != Path.GetFullPath(Path.Combine(root, "apps/desktop-core/NativeAccountClient.cs")))
                Assert.DoesNotContain("HttpClient", code);
            Assert.DoesNotContain("--demo-url", code);
            Assert.DoesNotContain("WebBrowser", code);
            Assert.DoesNotContain("127.0.0.1", code);
        }
    }
}
