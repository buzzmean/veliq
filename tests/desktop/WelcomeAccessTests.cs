using Neexitlag.Desktop;
using Xunit;
namespace NeExitLag.Tests;
public sealed class WelcomeAccessTests
{
    static ActivationView Active() => new() { State="ACTIVATED", HasIdentity=true, CapturePermitted=true };
    static AccountConnectionView Player() => new() { State="LINKED", Kind="player" };
    [Fact] public void FreshInstallDoesNotOpenRoutingWindow()
    { Assert.False(WelcomeAccess.Evaluate(new(){State="CODE_REQUIRED"},new(),new()).CanContinue); }
    [Fact] public void SavedPersonalAccountResumesWithoutNewLogin()
    { Assert.True(WelcomeAccess.Evaluate(Active(),Player(),new(){State="ACTIVE"}).CanContinue); }
    [Fact] public void ValidSavedCodeIsNamedExplicitlyAndDoesNotInventAccount()
    { var s=WelcomeAccess.Evaluate(Active(),new(),new());Assert.True(s.CanContinue);Assert.Equal("CODE_READY",s.State); }
    [Theory][InlineData("WAITING_FOR_BROWSER")][InlineData("STARTING")][InlineData("SIGN_IN_REQUIRED")][InlineData("ERROR")][InlineData("UNAVAILABLE")]
    public void UnconfirmedAccountCannotReuseOldIdentityToEnter(string state)
    { Assert.False(WelcomeAccess.Evaluate(Active(),new(){State=state,Kind="player"},new()).CanContinue); }
    [Fact] public void RevocationAndExpiredSubscriptionRemainBlocking()
    {
        var active=Active();active.Error="DEVICE_REVOKED";
        Assert.False(WelcomeAccess.Evaluate(active,Player(),new()).CanContinue);
        Assert.False(WelcomeAccess.Evaluate(Active(),Player(),new(){State="EXPIRED"}).CanContinue);
        active=Active();active.CapturePermitted=false;
        Assert.False(WelcomeAccess.Evaluate(active,Player(),new()).CanContinue);
    }
    [Fact] public void PreparedImageDoesNotEnrollOrOpenPersonalControls()
    { Assert.False(WelcomeAccess.Evaluate(Active(),new(){State="IMAGE_READY",Kind="club",ImagePreparation=true},new()).CanContinue); }
    [Fact] public void UnknownAccountKindCannotGrantAccess()
    { Assert.False(WelcomeAccess.Evaluate(Active(),new(){State="LINKED",Kind="unknown"},new()).CanContinue); }
}
