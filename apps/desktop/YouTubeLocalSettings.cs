using System.Windows;

namespace Neexitlag.Desktop;

public partial class MainWindow
{
    const string YouTubeLocalStatusMethod = "browser.youtube.local.status";
    const string YouTubeLocalSetMethod = "browser.youtube.local.set";
    bool loadingYouTubeLocal, savingYouTubeLocal;
    YouTubeLocalState? youtubeLocalState;

    sealed record YouTubeLocalState(bool Manageable, bool Enabled, bool Active, string Reason, string? LastFailure);

    async Task RefreshYouTubeLocalAsync()
    {
        if (loadingYouTubeLocal || savingYouTubeLocal || !model.Available)
            return;
        loadingYouTubeLocal = true;
        var previous = youtubeLocalState;
        try
        {
            var state = await service.Call<YouTubeLocalState>(YouTubeLocalStatusMethod, cancellationToken: lifetime.Token);
            if (!savingYouTubeLocal && ReferenceEquals(previous, youtubeLocalState))
                ApplyYouTubeLocalState(state);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (ServiceException error)
        {
            if (!savingYouTubeLocal && youtubeLocalState is not null)
                YouTubeLocalMessage.Text = Text.Failure(error);
        }
        finally { loadingYouTubeLocal = false; }
    }

    async void ToggleYouTubeLocal(object sender, RoutedEventArgs e)
    {
        if (savingYouTubeLocal || youtubeLocalState is not { Manageable: true } previous)
            return;
        savingYouTubeLocal = true;
        YouTubeLocalToggle.IsEnabled = false;
        bool enabled = YouTubeLocalToggle.IsChecked == true;
        try
        {
            var state = await service.Call<YouTubeLocalState>(YouTubeLocalSetMethod, new { enabled }, lifetime.Token);
            ApplyYouTubeLocalState(state);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        catch (ServiceException error)
        {
            ApplyYouTubeLocalState(previous);
            YouTubeLocalMessage.Text = Text.Failure(error);
        }
        finally { savingYouTubeLocal = false; }
    }

    void ApplyYouTubeLocalState(YouTubeLocalState state)
    {
        youtubeLocalState = state;
        YouTubeLocalPanel.Visibility = Visibility.Visible;
        YouTubeLocalToggle.IsEnabled = state.Manageable;
        YouTubeLocalToggle.IsChecked = state.Enabled;
        YouTubeLocalMessage.Text = state.Reason switch
        {
            "CLUB_ADMIN_MANAGED" => Text.Get("YouTubeLocalManaged"),
            "INSTALLATION_OWNER_UNAVAILABLE" => Text.Get("YouTubeLocalOwner"),
            "PREFERENCE_UNREADABLE" => Text.Get("YouTubeLocalPreferenceUnreadable"),
            "WAITING_FOR_CHROME_AUTO" => Text.Get("YouTubeLocalWaiting"),
            "WAITING_FOR_CHROME_AUTHORITY" => Text.Get("YouTubeLocalAuthority"),
            "WAITING_FOR_CAPTURE" => Text.Get("YouTubeLocalCapture"),
            "WAITING_FOR_LOCAL_GUARD" => Text.Get("YouTubeLocalGuard"),
            "WAITING_FOR_NETWORK" => Text.Get("YouTubeLocalNetwork"),
            "ACTIVATION_REQUIRED" => Text.Get("YouTubeLocalActivation"),
            _ when !state.Enabled => Text.Get("YouTubeLocalOff"),
            _ when state.Active && string.IsNullOrEmpty(state.LastFailure) => Text.Get("YouTubeLocalActive"),
            _ => string.Format(Text.Russian, Text.Get("YouTubeLocalFailed"), state.LastFailure ?? state.Reason),
        };
    }
}
