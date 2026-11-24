using Neexitlag.Desktop;
using Xunit;

namespace NeExitLag.Tests;

public sealed class SettingsConnectionTests
{
    static ActivationView Activated() => new() { State = "ACTIVATED", HasIdentity = true };

    [Fact]
    public void ExistingCodeDoesNotRequirePersonalSignIn()
    {
        var view = SettingsConnection.Evaluate(Activated(), new());
        Assert.Equal("Компьютер подключён", view.Title);
        Assert.False(view.ShowCabinet);
        Assert.DoesNotContain("Войдите", view.Hint);
    }

    [Fact]
    public void KnownClubKeepsItsSubscriptionLabel()
    {
        var view = SettingsConnection.Evaluate(Activated(), new() { Kind = "club", State = "LINKED" });
        Assert.Equal("Клубная подписка", view.Title);
        Assert.Equal("Компьютер подключён", view.Hint);
    }

    [Fact]
    public void RevokedCodeDoesNotLookConnected()
    {
        var activation = Activated(); activation.Error = "DEVICE_REVOKED";
        var view = SettingsConnection.Evaluate(activation, new());
        Assert.NotEqual("Компьютер подключён", view.Title);
        Assert.Contains("отозван", view.Hint);
    }

    [Fact]
    public void ActiveSubscriptionWithoutDateDoesNotCreateEmptyRenewalCard()
    {
        Assert.False(new SubscriptionView { State = "ACTIVE" }.ShowInSettings);
        Assert.True(new SubscriptionView { State = "EXPIRED" }.ShowInSettings);
        Assert.True(new SubscriptionView { State = "ACTIVE", PaidUntil = DateTimeOffset.UtcNow.AddMonths(1) }.ShowInSettings);
    }
}
