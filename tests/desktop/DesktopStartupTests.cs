using Veliq.Desktop;
using Xunit;

namespace Veliq.Tests;

public sealed class DesktopStartupTests
{
    [Theory]
    [InlineData("--autostart", false, true)]
    [InlineData("--AUTOSTART", false, true)]
    [InlineData("--autostart", true, false)]
    [InlineData("--autostart=0", false, false)]
    [InlineData("", false, false)]
    public void OnlyWindowsAutostartUsesTheTray(string argument, bool freshSetup, bool expected) =>
        Assert.Equal(expected, DesktopStartup.IsAutomatic([argument], freshSetup));

    [Fact]
    public void AnExplicitOpenRequestRestoresTheWindow()
    {
        Assert.True(DesktopStartup.StayInTray(true, false));
        Assert.False(DesktopStartup.StayInTray(true, true));
        Assert.False(DesktopStartup.StayInTray(false, false));
    }
}
