// Native Windows regression host. Loads the production compiled BAML and runs
// real Window/NotifyIcon handlers on an STA dispatcher, not an XML approximation.
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Neexitlag.Desktop;
using Application = System.Windows.Application;
using ComboBox = System.Windows.Controls.ComboBox;
using Point = System.Windows.Point;

internal static class Program
{
    static readonly string Output = Path.GetFullPath("bin/native-ui-tests");
    static string settings = "";
    [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
    static void Require(bool condition, string message) { if (!condition) throw new Exception(message); }
    static void Pump()
    {
        for (int i = 0; i < 4; i++)
        {
            var frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => frame.Continue = false));
            Dispatcher.PushFrame(frame);
            Thread.Sleep(25);
        }
    }
    static void Pass(string label) => Console.WriteLine("PASS " + label);
    sealed class AbsentService : IServiceClient
    {
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
            => throw new ServiceException(ServiceFailure.NotInstalled);
    }
    sealed class ExitService : IServiceClient
    {
        public bool Reject = true;
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
            => throw new ServiceException(Reject ? ServiceFailure.Rejected : ServiceFailure.NotInstalled);
    }
    static MainWindow Window(LocalPreferences p) => new(p, false, false, settings, new AbsentService());
    static void Key(ComboBox box, System.Windows.Input.Key key)
    {
        box.RaiseEvent(new System.Windows.Input.KeyEventArgs(Keyboard.PrimaryDevice, PresentationSource.FromVisual(box)!, 0, key) { RoutedEvent = Keyboard.KeyDownEvent });
        Pump();
    }
    static void SaveImage(FrameworkElement element, string name)
    {
        element.UpdateLayout();
        Require(element.ActualWidth > 0 && element.ActualHeight > 0,
            $"Empty visual: {name}; Visibility={element.Visibility}, IsVisible={element.IsVisible}, size={element.ActualWidth}x{element.ActualHeight}");
        var image = new RenderTargetBitmap((int)Math.Ceiling(element.ActualWidth), (int)Math.Ceiling(element.ActualHeight), 96, 96, PixelFormats.Pbgra32);
        image.Render(element);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
        using var stream = File.Create(Path.Combine(Output, name + ".png")); encoder.Save(stream);
    }
    static string Color(System.Windows.Media.Brush brush) => ((SolidColorBrush)brush).Color.ToString();
    static void Brush(System.Windows.Media.Brush brush, string hex, string message) => Require(Color(brush) == hex, message + ": " + Color(brush));
    static void Hover(FrameworkElement target)
    {
        var p = target.PointToScreen(new Point(target.ActualWidth / 2, target.ActualHeight / 2));
        Require(SetCursorPos((int)p.X, (int)p.Y), "Cannot position native mouse"); Pump();
        Require(target.IsMouseOver, "Mouse did not reach actual visual");
    }
    sealed class PickerService : IServiceClient
    {
        public Task<T> Call<T>(string method, object? payload = null, CancellationToken cancellationToken = default)
        {
            if (method != "processes") throw new Exception("Unexpected picker request " + method);
            return Task.FromResult((T)(object)new RunningApplicationList { Applications = [new() {
                Name = "long-application.exe", DisplayName = "A long application title that wraps onto multiple lines in the application picker",
                Path = @"C:\Applications\A very long folder name\Another long folder name\Application\bin\long-application.exe",
                Pid = 42, Pids = Enumerable.Range(1000, 20).Select(x => (uint)x).ToArray(), ProcessCount = 20
            }] });
        }
    }
    static void Picker()
    {
        var owner = Window(new() { MinimizeToTray = false }); owner.Show(); Pump();
        var picker = new AddApplicationWindow(owner, new DesktopViewModel(new PickerService()), CancellationToken.None);
        picker.Show(); Pump();
        var grid = (DataGrid)picker.FindName("ProcessGrid");
        Require(double.IsNaN(grid.RowHeight), "Picker must use content-driven row height, not inherited fixed height");
        Require(grid.MinRowHeight == 82, "Picker minimum row height lost");
        // Enrichment is asynchronous; pump until the service metadata is displayed.
        var deadline = System.Diagnostics.Stopwatch.StartNew();
        while (grid.Items.Count == 0 && deadline.Elapsed < TimeSpan.FromSeconds(10)) Pump();
        Require(grid.Items.Count == 1, "Picker metadata did not render"); grid.UpdateLayout();
        var row = (DataGridRow)grid.ItemContainerGenerator.ContainerFromIndex(0);
        Require(row.ActualHeight > 82, "Long title/path/PIDs must expand the row");
        Require(((System.Windows.Controls.Button)picker.FindName("ManualButton")).IsEnabled, "Manual file picker unavailable");
        SaveImage(picker, "add-application"); picker.Close(); owner.Close(); Pump();
        Pass("Add application window opens (production BAML, long title/path/PIDs)");
    }
    static void Lifecycle()
    {
        foreach (bool start in new[] { false, true }) foreach (bool tray in new[] { false, true })
        {
            var prefs = new LocalPreferences { StartMinimized = start, MinimizeToTray = tray };
            prefs.Save(settings);
            // Recreate with persisted preferences, as on GUI restart.
            var w = Window(LocalPreferences.Load(settings)); bool closed = false; w.Closed += (_, _) => closed = true;
            w.Show(); Pump();
            Require(w.Title == "VELIQ" && (w.TrayIcon.Text == "VELIQ" || w.TrayIcon.Text.StartsWith("VELIQ: ")), "VELIQ window/tray branding");
            Require(w.TrayVisible == tray, "Startup tray visibility");
            Require(w.IsVisible == !(start && tray), "Startup must hide only in tray mode");
            Require(!start || w.WindowState == WindowState.Minimized, "StartMinimized must minimize");
            Require(w.ShowInTaskbar, "Normal minimized window must remain in taskbar");
            w.TrayIcon.ContextMenuStrip!.Items[0].PerformClick(); Pump(); Require(w.IsVisible && w.WindowState == WindowState.Normal, "Tray Open restore failed");
            w.WindowState = WindowState.Minimized; Pump();
            Require(w.IsVisible == !tray, "Minimize visibility does not match tray setting");
            w.ShowFromTray(); w.Close();
            Require(!closed, "Synchronous cleanup must not re-enter WPF Closing; defer final Close to dispatcher");
            Pump();
            Require(closed == !tray, "X must close when OFF, hide when ON even with service absent");
            if (tray)
            {
                Require(!w.IsVisible && w.TrayVisible, "X tray state");
                w.ShowFromTray(); Pump(); Require(w.IsVisible, "Open after X");
                w.TrayIcon.ContextMenuStrip!.Items[^1].PerformClick();
                Require(!closed, "Synchronous tray cleanup must defer final Close to dispatcher");
                Pump(); Require(closed && !w.TrayVisible, "Tray Exit must really close and remove icon");
            }
            Pass($"StartMinimized={start} / MinimizeToTray={tray}: startup, minimize, X, Open, Exit, restart");
        }
        var failingService = new ExitService();
        var failed = new MainWindow(new() { MinimizeToTray = false }, false, false, settings, failingService);
        bool failedClosed = false; failed.Closed += (_, _) => failedClosed = true;
        failed.Show(); Pump(); failed.Close(); Pump();
        Require(!failedClosed && failed.IsVisible, "Rejected routing shutdown must leave real GUI open");
        Require(!string.IsNullOrWhiteSpace(((DesktopViewModel)failed.DataContext).Error), "Rejected shutdown must show its error");
        failingService.Reject = false; failed.Exit(); Pump(); Require(failedClosed, "Known removed service must allow GUI exit");
        Pass("IPC rejection keeps GUI open; explicit absence allows exit");
        var live = Window(new() { MinimizeToTray = true }); live.Show(); Pump();
        live.WindowState = WindowState.Minimized; Pump(); Require(!live.IsVisible, "Initial tray minimize");
        live.SaveLocalPreferences(true, false); Pump();
        Require(live.IsVisible && live.WindowState == WindowState.Minimized && !live.TrayVisible, "Save OFF must immediately restore taskbar window and remove tray");
        var saved = LocalPreferences.Load(settings);
        Require(saved.StartMinimized && !saved.MinimizeToTray, "OFF preference persistence");
        live.SaveLocalPreferences(false, true); Pump();
        Require(!live.IsVisible && live.TrayVisible, "Save ON must immediately enable tray for already minimized window");
        saved = LocalPreferences.Load(settings); Require(!saved.StartMinimized && saved.MinimizeToTray, "ON preference persistence");
        live.Exit(); Pump();
        Pass("MinimizeToTray OFF"); Pass("MinimizeToTray ON"); Pass("StartMinimized combinations"); Pass("Save applies immediately and preferences persist");
    }
    static void TechnicalDropdownsHidden(MainWindow main)
    {
        main.ShowPage("Applications"); Pump();
        foreach (string name in new[] { "RelayChoice", "ProfileFallback", "AppAdvanced" })
            Require(((FrameworkElement)main.FindName(name)).Visibility == Visibility.Collapsed, name + " exposed without technical preference");
        Require(!((ComboBox)main.FindName("AppPreset")).IsVisible, "Preset visible through collapsed technical expander");
        main.ShowPage("Diagnostics"); main.ShowDiagnosticsTab("LocalStrategies"); Pump();
        Require(!((ComboBox)main.FindName("LocalMechanism")).IsVisible, "Local mechanism visible through collapsed technical container");
    }
    static void TechnicalPreference(MainWindow main, bool enabled)
    {
        main.ShowPage("Settings");
        var toggle = (System.Windows.Controls.CheckBox)main.FindName("ShowTechnical");
        toggle.BringIntoView(); Pump();
        // Exercise the real user preference/Click handler, not local Visibility
        // overrides or synthetic dimensions on the production controls.
        toggle.SetCurrentValue(ToggleButton.IsCheckedProperty, enabled);
        toggle.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)); Pump();
        Require(((DesktopViewModel)main.DataContext).ShowTechnical == enabled, "Technical preference did not reach bindings");
        Require(LocalPreferences.Load(settings).ShowTechnical == enabled, "Technical preference was not persisted");
    }
    static void ActualDropdownKeyboard(ComboBox box, string name)
    {
        Require(box.IsEnabled && box.Items.Count >= 2, name + " needs an enabled production state with selectable fixture data");
        int saved = box.SelectedIndex;
        box.SelectedIndex = 0; Require(box.Focus(), name + " cannot receive keyboard focus"); Pump();
        Key(box, System.Windows.Input.Key.Down); Require(box.SelectedIndex == 1, name + " arrow selection broken");
        Key(box, System.Windows.Input.Key.F4); Require(box.IsDropDownOpen, name + " F4 open broken");
        var popup = (Popup)box.Template.FindName("PART_Popup", box);
        Require(popup.IsOpen, name + " production popup did not open");
        var border = (Border)box.Template.FindName("PopupBorder", box);
        Brush(border.Background, "#FF131417", name + " popup background");
        var selected = box.ItemContainerGenerator.ContainerFromIndex(box.SelectedIndex) as ComboBoxItem;
        Require(selected is not null, name + " selected item was not realized");
        selected!.ApplyTemplate(); Brush(selected.Background, "#FF22252A", name + " selected background");
        Brush(selected.Foreground, "#FFFFFFFF", name + " selected foreground");
        SaveImage(border, "actual-popup-" + name);
        Key(box, System.Windows.Input.Key.Escape); Require(!box.IsDropDownOpen, name + " Escape close broken");
        Key(box, System.Windows.Input.Key.F4); Key(box, System.Windows.Input.Key.Enter);
        Require(!box.IsDropDownOpen, name + " Enter close broken");
        box.Focus(); Pump();
        Require(box.MoveFocus(new TraversalRequest(FocusNavigationDirection.Next)), name + " Tab traversal failed"); Pump();
        Require(!box.IsKeyboardFocusWithin, name + " Tab remained trapped in ComboBox");
        box.SelectedIndex = saved; Pump();
        Pass(name + " production ComboBox: natural layout, dark popup, selection, arrows/F4/Escape/Enter/Tab");
    }
    static void Dropdowns()
    {
        var main = Window(new() { MinimizeToTray = false }); main.Show(); main.Activate(); Pump();
        TechnicalDropdownsHidden(main);
        main.ShowPage("Settings"); Pump();
        foreach (string name in new[] { "Fallback", "Channel" })
        {
            var offline = (ComboBox)main.FindName(name); offline.BringIntoView(); Pump(); offline.ApplyTemplate();
            Require(offline.IsVisible && !offline.IsEnabled, name + " must be visible but disabled without service");
            Brush(offline.Foreground, "#FF8E939C", name + " offline foreground");
            SaveImage(offline, "actual-offline-" + name);
        }
        // Same DTO/application path as IPC polling, without a real service,
        // driver, registry policy or network. Data permits real keyboard choices.
        var model = (DesktopViewModel)main.DataContext;
        model.Apply(new Snapshot { Connected = true, Backend = new() { Ready = true, Capabilities = new() { Tcp = true } },
            Routes = [new() { Id = "native-fixture-a", Status = "healthy", ObservedAt = DateTimeOffset.UtcNow },
                      new() { Id = "native-fixture-b", Status = "healthy", ObservedAt = DateTimeOffset.UtcNow }] });
        ((ComboBox)main.FindName("AppPreset")).ItemsSource = new LocalStrategyPreset[] {
            new() { Id = "native-fixture-a", Name = "Fixture A", Version = 1 },
            new() { Id = "native-fixture-b", Name = "Fixture B", Version = 1 } };
        TechnicalPreference(main, true);
        var style = (Style)Application.Current.FindResource(typeof(ComboBox));
        foreach (string name in new[] { "Mode", "RelayChoice", "ProfileFallback", "AppPreset", "LocalMechanism", "Fallback", "Channel" })
        {
            string section = name is "Fallback" or "Channel" ? "Settings" : name == "LocalMechanism" ? "Diagnostics" : "Applications";
            main.ShowPage(section);
            if (section == "Diagnostics") main.ShowDiagnosticsTab("LocalStrategies");
            if (section == "Applications") ((Expander)main.FindName("AppAdvanced")).IsExpanded = true;
            var mode = (ComboBox)main.FindName("Mode");
            if (name == "RelayChoice") { Require(!((ComboBox)main.FindName(name)).IsEnabled, "AUTO must not enable fixed relay"); mode.SelectedValue = "MANUAL"; }
            var box = (ComboBox)main.FindName(name); box.BringIntoView(); Pump(); box.ApplyTemplate();
            Require(box.IsVisible, name + " hidden in its intended page/technical state");
            Require(box.Style == style, name + " does not use shared dark style");
            Require(box.Template.FindName("Chrome", box) is Border, name + " native light template still active");
            Require(box.Template.FindName("PART_Popup", box) is Popup, name + " missing popup");
            SaveImage(box, "actual-" + name);
            ActualDropdownKeyboard(box, name);
            if (name == "RelayChoice")
            {
                mode.SelectedValue = "AUTO"; Pump(); Require(!box.IsEnabled, "AUTO must disable fixed relay");
                Brush(box.Foreground, "#FF8E939C", "RelayChoice AUTO disabled foreground");
                SaveImage(box, "actual-disabled-RelayChoice");
            }
        }
        TechnicalPreference(main, false); TechnicalDropdownsHidden(main);
        main.Close(); Pump();
        var combo = new ComboBox { Width = 300, ItemsSource = new[] { "Normal / selected", "Hover / keyboard", "Third item" }, SelectedIndex = 0 };
        var next = new System.Windows.Controls.Button { Content = "Next focus target" };
        var panel = new StackPanel { Margin = new Thickness(20) }; panel.Children.Add(combo); panel.Children.Add(next);
        var host = new System.Windows.Window { Title = "Native dark ComboBox states", Width = 420, Height = 240, Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(16,21,28)), Content = panel, WindowStartupLocation = WindowStartupLocation.CenterScreen };
        host.Show(); host.Activate(); Pump();
        SetCursorPos(0, 0); Pump();
        var chrome = (Border)combo.Template.FindName("Chrome", combo);
        Brush(chrome.Background, "#FF131417", "Normal background"); Brush(combo.Foreground, "#FFFFFFFF", "Normal text");
        SaveImage(host, "combo-normal"); Pass("dark ComboBox normal");
        Hover(combo); Brush(chrome.Background, "#FF1A1C20", "Hover background");
        SaveImage(host, "combo-hover"); Pass("dark ComboBox hover");
        combo.Focus(); Key(combo, System.Windows.Input.Key.Down); Require(combo.SelectedIndex == 1, "Arrow selection broken");
        Key(combo, System.Windows.Input.Key.F4); Require(combo.IsDropDownOpen, "F4 dropdown keyboard open broken"); Pump();
        var popup = (Popup)combo.Template.FindName("PART_Popup", combo);
        var border = (Border)combo.Template.FindName("PopupBorder", combo);
        Brush(border.Background, "#FF131417", "Popup background");
        var selected = (ComboBoxItem)combo.ItemContainerGenerator.ContainerFromIndex(combo.SelectedIndex);
        selected.ApplyTemplate(); Brush(selected.Background, "#FF22252A", "Selected background"); Brush(selected.Foreground, "#FFFFFFFF", "Selected text");
        SaveImage(border, "combo-popup-selected"); Pass("dark ComboBox selected");
        var unselected = (ComboBoxItem)combo.ItemContainerGenerator.ContainerFromIndex(2); Hover(unselected);
        Brush(unselected.Background, "#FF1A1C20", "Popup item hover"); SaveImage(border, "combo-popup-hover");
        Key(combo, System.Windows.Input.Key.Escape); Require(!combo.IsDropDownOpen, "Escape must close popup");
        Key(combo, System.Windows.Input.Key.F4); Key(combo, System.Windows.Input.Key.Enter); Require(!combo.IsDropDownOpen, "Enter must close popup");
        combo.Focus(); combo.MoveFocus(new TraversalRequest(FocusNavigationDirection.Next)); Pump(); Require(next.IsKeyboardFocused, "Tab traversal broken");
        combo.Focus(); Pump(); Brush(chrome.BorderBrush, "#FFF0502A", "Keyboard focus border");
        combo.IsEnabled = false; Pump(); Brush(combo.Foreground, "#FF8E939C", "Disabled text"); Brush(chrome.Background, "#FF060607", "Disabled background");
        Require(Color(combo.Foreground) != Color(chrome.Background), "Disabled foreground equals background");
        SaveImage(host, "combo-disabled"); Pass("dark ComboBox disabled"); Pass("ComboBox keyboard arrows/F4/Enter/Escape/Tab and focus");
        host.Close(); Pump();
    }
    static void StrategiesNull()
    {
        var main=Window(new(){MinimizeToTray=false});main.Show();Pump();
        Require(!((Expander)main.FindName("AppAdvanced")).IsExpanded,"Advanced controls exposed by default");
        var grid=(DataGrid)main.FindName("LocalGrid");
        var p=System.Text.Json.JsonSerializer.Deserialize<LocalStrategyProfile>("{\"ports\":null,\"domains\":null,\"ips\":null,\"exclude_domains\":null,\"exclude_ips\":null,\"actions\":null}",WireJson.Options)!;
        grid.ItemsSource=new[]{p};grid.SelectedItem=p;Pump();
        Require(((System.Windows.Controls.TextBox)main.FindName("LocalDomains")).Text=="","Null arrays were not safe in real WPF selection handler");main.Close();Pump();Pass("real WPF null strategy arrays and collapsed Advanced controls");
    }
    static void ChromeProxyValue()
    {
        using var value=System.Text.Json.JsonDocument.Parse(ChromePolicy.CreateValue(["--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,dGVzdA=="]));
        var root=value.RootElement;
        Require(root.GetProperty("ProxyMode").GetString()=="pac_script","Chrome-only PAC mode missing");
        Require(root.GetProperty("ProxyPacMandatory").GetBoolean(),"PAC evaluation failure must not authorize DIRECT");
        Require(!root.TryGetProperty("ProxyBypassList",out _),"Chrome rejects ProxyBypassList in pac_script policy mode");
        Pass("Chrome PAC mandatory policy encoding; no registry or Windows proxy modified by test");
    }
    static void ChromeRecoveryGuard(){
        var p=new Profile{Id="chrome",Executables=[@"C:\Apps\chrome.exe"],Mode="AUTO"};
        var pac=ChromePolicy.ClosedGuard(p);
        var script=System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(pac.Split(',')[1]));
        var info=new System.Diagnostics.ProcessStartInfo("node"){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        info.ArgumentList.Add("-e");info.ArgumentList.Add("let s='';process.stdin.on('data',b=>s+=b);process.stdin.on('end',()=>{const vm=require('vm'),c={};vm.createContext(c);vm.runInContext(s,c);console.log(JSON.stringify(['vk.com','chatgpt.com','api.openai.com','openai.com.evil.test','music.yandex.ru'].map(h=>c.FindProxyForURL('https://'+h,h))));});");
        using var node=System.Diagnostics.Process.Start(info)!;node.StandardInput.Write(script);node.StandardInput.Close();var raw=node.StandardOutput.ReadToEnd();if(!node.WaitForExit(10000))throw new Exception("PAC evaluator timeout");
        Require(node.ExitCode==0,node.StandardError.ReadToEnd());var routes=System.Text.Json.JsonSerializer.Deserialize<string[]>(raw)!;
        Require(routes[0]=="DIRECT"&&routes[3]=="DIRECT"&&routes[4]=="DIRECT","Ordinary recovery routes broken");
        Require(routes[1].StartsWith("PROXY ")&&routes[2].StartsWith("PROXY ")&&!routes[1].Contains("DIRECT")&&!routes[2].Contains("DIRECT"),"OpenAI guard leaked DIRECT");
        Pass("Chrome recovery PAC executes: ordinary DIRECT; protected OpenAI fail-closed; suffix boundary exact");
    }
    static void ChromePolicyRecoveryLifecycle(){
        if(Environment.GetEnvironmentVariable("NEEXITLAG_TEST_CHROME_POLICY")!="1")return;
        using var key=Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Policies\Google\Chrome");
        Require(key.GetValue("ProxySettings")is null,"Refusing an existing Chrome policy in native UI fixture");
        var folder=Path.Combine(Path.GetTempPath(),"neexitlag-policy-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(folder);ChromePolicy.TestStatePath=Path.Combine(folder,"owned.json");
        try{
            var closed=ChromePolicy.ClosedGuard(new(){Id="chrome",Executables=[@"C:\Apps\chrome.exe"]});
            var script="function FindProxyForURL(url,host){return 'PROXY localhost:12345';}";
            var online="data:application/x-ns-proxy-autoconfig;base64,"+Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(script));
            ChromePolicy.Install(["--proxy-pac-url="+online],["--proxy-pac-url="+closed]);
            var first=(string)key.GetValue("ProxySettings")!;
            Require(ChromePolicy.Monitored&&ChromePolicy.Applied&&!ChromePolicy.Suspended,"Online ownership/readiness wrong");
            ChromePolicy.Suspend(true);var guard=(string)key.GetValue("ProxySettings")!;
            Require(guard==first&&ChromePolicy.Suspended&&ChromePolicy.Applied,"IPC outage must preserve the stable dual-endpoint PAC");
            ChromePolicy.Suspend(false);Require(ChromePolicy.Resume(),"Repeated outage forgot previous Optimize state");
            Require((string)key.GetValue("ProxySettings")! == first&&!ChromePolicy.Suspended,"Online PAC not restored");
            key.SetValue("ProxySettings",guard);ChromePolicy.Check(); // interrupted known transition is recoverable
            ChromePolicy.Guard(new(){Id="chrome",Mode="AUTO",Executables=[@"C:\Apps\chrome.exe"]});
            Require(!ChromePolicy.Monitored,"Explicit rollback can silently auto-resume");
            key.SetValue("ProxySettings","foreign-value");bool rejected=false;try{ChromePolicy.Suspend(true);ChromePolicy.Guard(new());}catch(InvalidOperationException){rejected=true;}
            Require(rejected&&(string)key.GetValue("ProxySettings")! == "foreign-value","Foreign policy overwritten");
            Pass("actual HKCU Chrome policy: online/outage/recovery, idempotence, previous state, explicit disable and foreign refusal");
        }finally{key.DeleteValue("ProxySettings",false);ChromePolicy.TestStatePath=null;Directory.Delete(folder,true);}
    }
    [STAThread]
    static int Main()
    {
        Directory.CreateDirectory(Output); settings = Path.Combine(Path.GetTempPath(), "neexitlag-native-" + Guid.NewGuid() + ".json");
        var app = new App(); app.InitializeComponent(); app.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        try { FreshPCSetupChecks.Run(); ChromeProxyValue(); ChromeRecoveryGuard(); ChromePolicyRecoveryLifecycle(); Picker(); StrategiesNull(); Lifecycle(); Dropdowns(); Pass("native WPF desktop regression suite"); return 0; }
        catch (Exception e) { Console.Error.WriteLine(e); File.WriteAllText(Path.Combine(Output, "failure.txt"), e.ToString()); return 1; }
        finally { foreach (System.Windows.Window w in app.Windows.Cast<System.Windows.Window>().ToArray()) { if (w is MainWindow m) m.Exit(); else w.Close(); } app.Shutdown(); File.Delete(settings); }
    }
}
