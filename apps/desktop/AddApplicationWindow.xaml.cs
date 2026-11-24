using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
namespace Veliq.Desktop;

public partial class AddApplicationWindow : Window
{
    readonly RunningApplicationsViewModel model;
    readonly DesktopViewModel desktop;
    readonly CancellationTokenSource lifetime;
    readonly CancellationToken token;
    bool saving;
    public AddApplicationWindow(Window owner, DesktopViewModel desktop, CancellationToken ct)
    {
        InitializeComponent(); WindowTheme.UseDarkCaption(this);
        Owner = owner; Icon = owner.Icon;
        this.desktop = desktop;
        model = desktop.CreateApplicationPicker();
        DataContext = model;
        lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        token = lifetime.Token;
        Loaded += async (_, _) => { SearchBox.Focus(); await Refresh(); };
        Closed += (_, _) => { lifetime.Cancel(); lifetime.Dispose(); };
    }
    async Task Refresh()
    {
        AddError.Text = "";
        await model.RefreshAsync(token, rows => Task.Run(() =>
        {
            foreach (var row in rows)
            {
                token.ThrowIfCancellationRequested();
                Enrich(row);
            }
        }, token));
    }
    // Optional presentation metadata only: local fixed/removable executable
    // resources, no process handles, shell launch, signature claim or network I/O.
    static void Enrich(RunningApplication row)
    {
        try
        {
            var root = Path.GetPathRoot(row.Path);
            if (root is null || !Path.IsPathFullyQualified(row.Path) || !row.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;
            if (new DriveInfo(root).DriveType is not (DriveType.Fixed or DriveType.Removable)) return;
            if (!File.Exists(row.Path)) return;
            var description = FileVersionInfo.GetVersionInfo(row.Path).FileDescription;
            if (!string.IsNullOrWhiteSpace(description)) row.DisplayName = new string(description.Where(c => !char.IsControl(c)).Take(120).ToArray()).Trim();
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(row.Path);
            if (icon is not null)
            {
                var bitmap = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromWidthAndHeight(28, 28));
                bitmap.Freeze(); row.Icon = bitmap;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or Win32Exception or NotSupportedException) { /* Optional metadata: retain exe name, omit icon. */ }
    }
    async void RefreshProcesses(object sender, RoutedEventArgs e) => await Refresh();
    void SelectionChanged(object sender, SelectionChangedEventArgs e) => AddButton.IsEnabled = !saving && ProcessGrid.SelectedItem is RunningApplication;
    async void AddSelected(object sender, RoutedEventArgs e)
    {
        if (ProcessGrid.SelectedItem is RunningApplication row) await AddPath(row.Path);
    }
    async void ChooseOnDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source && ItemsControl.ContainerFromElement(ProcessGrid, source) is DataGridRow && ProcessGrid.SelectedItem is RunningApplication row)
            await AddPath(row.Path);
    }
    async void ChooseFileManually(object sender, RoutedEventArgs e)
    {
        if (saving) return;
        await Save(() => desktop.AddApplicationFromFileAsync(() =>
        {
            var picker = new OpenFileDialog { Title = Text.Get("ChooseExecutable"), Filter = Text.Get("ExecutableFilter"), CheckFileExists = true, Multiselect = false };
            return picker.ShowDialog(this) == true ? picker.FileName : null;
        }, token));
    }
    Task AddPath(string path) => Save(async () => await desktop.AddApplicationAsync(path, token));
    async Task Save(Func<Task<bool?>> action)
    {
        if (saving || token.IsCancellationRequested) return;
        saving = true; AddButton.IsEnabled = false; ManualButton.IsEnabled = false; AddError.Text = "";
        try
        {
            bool? ok = await action();
            if (!token.IsCancellationRequested)
            {
                if (ok == true) DialogResult = true;
                else if (ok == false) AddError.Text = desktop.Error;
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception e) { if (!token.IsCancellationRequested) AddError.Text = Text.Failure(e); }
        finally { saving = false; AddButton.IsEnabled = ProcessGrid.SelectedItem is RunningApplication; ManualButton.IsEnabled = true; }
    }
}
