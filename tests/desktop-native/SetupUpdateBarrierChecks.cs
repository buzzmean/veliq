using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using Veliq.Desktop;

internal static partial class Program
{
    static int SetupBarrierChild(string[] args)
    {
        if (args[0] == "--setup-barrier-owner-child")
        {
            using var owned = new EventWaitHandle(true, EventResetMode.ManualReset, args[1]);
            File.WriteAllText(args[2], "ready");
            Thread.Sleep(Timeout.Infinite);
            return 0;
        }
        var child = new App(); child.InitializeComponent();
        bool started = false;
        child.Startup += (_, _) => started = true;
        child.Exit += (_, _) => File.WriteAllText(args[1], JsonSerializer.Serialize(new { startup = started, windows = child.Windows.Count }));
        return child.Run();
    }

    static Process StartSetupBarrierChild(params string[] args)
    {
        var info = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false };
        foreach (var arg in args) info.ArgumentList.Add(arg);
        return Process.Start(info)!;
    }

    static void SetupUpdateBarrierChecks()
    {
        var directory = AppContext.BaseDirectory;
        var name = SetupUpdateBarrier.NameFor(directory);
        Require(name == SetupUpdateBarrier.NameFor(directory.ToUpperInvariant().TrimEnd('\\') + "\\"), "Разный регистр/конечный разделитель меняет барьер установки");
        using (var gate = new EventWaitHandle(false, EventResetMode.ManualReset, name))
        {
            Require(!SetupUpdateBarrier.IsActive(directory), "Сброшенный барьер блокирует GUI");
            gate.Set();
            Require(SetupUpdateBarrier.IsActive(directory), "Активный барьер не обнаружен");
            Require(!SetupUpdateBarrier.IsActive(Path.Combine(directory, "other-install")), "Барьер затрагивает другой путь установки");
            foreach (bool automatic in new[] { false, true })
            {
                var marker = Path.Combine(Path.GetTempPath(), "veliq-gate-" + Guid.NewGuid().ToString("N") + ".json");
                using var process = StartSetupBarrierChild(automatic
                    ? ["--setup-barrier-startup-child", marker, "--autostart"]
                    : ["--setup-barrier-startup-child", marker]);
                try
                {
                    Require(process.WaitForExit(10000), "GUI не завершил запуск при активном установщике");
                    Require(process.ExitCode == 0 && File.Exists(marker), "Не подтверждено штатное завершение запуска GUI");
                    using var result = JsonDocument.Parse(File.ReadAllText(marker));
                    Require(!result.RootElement.GetProperty("startup").GetBoolean() && result.RootElement.GetProperty("windows").GetInt32() == 0,
                        "При обновлении созданы окна или запущена обычная инициализация");
                }
                finally { if (!process.HasExited) { process.Kill(); process.WaitForExit(); } File.Delete(marker); }
            }
            gate.Reset();
            Require(!SetupUpdateBarrier.IsActive(directory), "Барьер не снят до возобновления GUI");
        }
        Require(!SetupUpdateBarrier.IsActive(directory), "После закрытия установщика остался барьер");

        var isolated = Path.Combine(Path.GetTempPath(), "veliq-crash-gate-" + Guid.NewGuid().ToString("N"));
        var ready = isolated + ".ready";
        using (var owner = StartSetupBarrierChild("--setup-barrier-owner-child", SetupUpdateBarrier.NameFor(isolated), ready))
        {
            try
            {
                var deadline = Stopwatch.StartNew();
                while (!File.Exists(ready) && !owner.HasExited && deadline.ElapsedMilliseconds < 10000) Thread.Sleep(25);
                Require(File.Exists(ready) && SetupUpdateBarrier.IsActive(isolated), "Дочерний установщик не создал барьер");
                owner.Kill(); owner.WaitForExit();
                Require(!SetupUpdateBarrier.IsActive(isolated), "Завершившийся установщик оставил постоянную блокировку");
            }
            finally { if (!owner.HasExited) { owner.Kill(); owner.WaitForExit(); } File.Delete(ready); }
        }
        Pass("Барьер Setup: реальный App startup/autostart без окон, регистр/путь, сброс и завершение владельца");
    }
}
