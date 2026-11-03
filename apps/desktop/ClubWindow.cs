using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using System.Text.Json;
namespace Neexitlag.Desktop;
// Club UI has no ordinary routing mutations. Emergency stop is independently
// password-authorized by the service; password setup requires the elevated owner.
// Actual authorization is enforced by the service, independently of this window.
// Layout follows the «Режим клуба» screen of app-ui/index.html.
public sealed class ClubWindow : Window
{
    readonly System.Windows.Forms.NotifyIcon tray=new();
    readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromSeconds(5)};
    readonly TextBlock title=new(){Text="Подготовка",FontSize=52,FontWeight=FontWeights.ExtraBold,TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,12)};
    readonly TextBlock status=new(){Text="Подготавливаем VELIQ…",FontSize=16,TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,0,0,22)};
    readonly TextBlock games=new(){TextWrapping=TextWrapping.Wrap,HorizontalAlignment=HorizontalAlignment.Right,TextAlignment=TextAlignment.Right};
    readonly TextBlock clubName=new(){Text="Клубный режим",TextWrapping=TextWrapping.Wrap,HorizontalAlignment=HorizontalAlignment.Right,TextAlignment=TextAlignment.Right};
    readonly Rectangle signal=new(){Visibility=Visibility.Collapsed};
    readonly Border badge=new(){Width=200,Height=200,CornerRadius=new CornerRadius(72),BorderThickness=new Thickness(2),ClipToBounds=true};
    readonly IServiceClient service=new ServiceClient();bool polling,exiting;string trayState="";System.Drawing.Icon? trayIcon;
    public ClubWindow()
    {
        Title="VELIQ";Width=760;Height=460;MinWidth=640;MinHeight=400;WindowStartupLocation=WindowStartupLocation.CenterScreen;
        Background=Res("Bg");Foreground=Res("Text");FontFamily=(FontFamily)FindResource("VeliqFont");FontSize=14;
        WindowTheme.UseDarkCaption(this);
        var icon=System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/VELIQ;component/Assets/VELIQ.ico"));
        if(icon is not null)Icon=System.Windows.Media.Imaging.BitmapFrame.Create(icon.Stream);
        Content=Layout();
        SetTray("connecting");
        tray.Text="VELIQ · клуб";tray.Visible=true;
        var menu=new System.Windows.Forms.ContextMenuStrip();menu.Items.Add("Состояние VELIQ",null,(_,_)=>Dispatcher.Invoke(ShowFromTray));menu.Items.Add("Аварийно отключить VELIQ…",null,(_,_)=>Dispatcher.Invoke(EmergencyExit));
        menu.Items.Add("Настроить пароль отключения…",null,(_,_)=>Dispatcher.Invoke(()=>{try{EmergencyPasswordStore.OpenSetup();}catch(System.ComponentModel.Win32Exception){}}));
        TrayMenuRenderer.Apply(menu);tray.ContextMenuStrip=menu;
        tray.MouseClick+=(_,args)=>{if(args.Button==System.Windows.Forms.MouseButtons.Left)Dispatcher.Invoke(ShowFromTray);};
        Closing+=(_,e)=>{if(!exiting){e.Cancel=true;Hide();}};
        timer.Tick+=async(_,_)=>await Poll();timer.Start();_=Poll();
    }
    Brush Res(string key)=>(Brush)FindResource(key);
    UIElement Layout()
    {
        title.Foreground=Res("Text");status.Foreground=Res("TextMuted");games.Foreground=Res("TextMuted");
        var list=new StackPanel();
        clubName.Foreground=Res("TextMuted");list.Children.Add(Row("Клуб",clubName));
        list.Children.Add(Row("Игры",games));
        list.Children.Add(Row("Если что-то не открывается",new TextBlock{Text="позовите администратора",Foreground=Res("TextMuted")}));
        var state=new StackPanel{VerticalAlignment=VerticalAlignment.Center};
        state.Children.Add(title);state.Children.Add(status);
        state.Children.Add(new Border{BorderBrush=Res("Line"),BorderThickness=new Thickness(0,1,0,0),Child=list});
        // Static Q outline: radius 36%, slit at 66%, signal bar when routing is ready.
        var shape=new Grid();
        shape.RowDefinitions.Add(new RowDefinition{Height=new GridLength(66,GridUnitType.Star)});
        shape.RowDefinitions.Add(new RowDefinition{Height=new GridLength(6,GridUnitType.Star)});
        shape.RowDefinitions.Add(new RowDefinition{Height=new GridLength(28,GridUnitType.Star)});
        var slit=new Rectangle{Fill=Res("Bg")};Grid.SetRow(slit,1);shape.Children.Add(slit);
        signal.Fill=Res("Accent");Grid.SetRow(signal,1);shape.Children.Add(signal);
        badge.Child=shape;badge.Background=Res("BgRaised");badge.BorderBrush=Res("LineStrong");
        var main=new Grid{Margin=new Thickness(40,32,40,0)};
        main.ColumnDefinitions.Add(new ColumnDefinition{Width=new GridLength(1,GridUnitType.Star)});
        main.ColumnDefinitions.Add(new ColumnDefinition{Width=GridLength.Auto});
        main.Children.Add(state);
        var right=new Grid{Margin=new Thickness(40,0,0,0),VerticalAlignment=VerticalAlignment.Center};right.Children.Add(badge);
        Grid.SetColumn(right,1);main.Children.Add(right);
        var foot=new Border{BorderBrush=Res("Line"),BorderThickness=new Thickness(0,1,0,0),Margin=new Thickness(40,0,40,20),Padding=new Thickness(0,14,0,0),
            Child=new TextBlock{Text="VELIQ, режим клуба. Включается сам после перезагрузки.",FontSize=12,Foreground=Res("TextFaint")}};
        var root=new DockPanel();DockPanel.SetDock(foot,Dock.Bottom);root.Children.Add(foot);root.Children.Add(main);
        return root;
    }
    UIElement Row(string label,TextBlock value)
    {
        var row=new DockPanel{Margin=new Thickness(0,10,0,10)};
        var name=new TextBlock{Text=label,Margin=new Thickness(0,0,24,0)};DockPanel.SetDock(name,Dock.Left);
        row.Children.Add(name);row.Children.Add(value);
        return new Border{BorderBrush=Res("Line"),BorderThickness=new Thickness(0,0,0,1),Child=row};
    }
    void ShowState(string heading,string text,string state)
    {
        title.Text=heading;status.Text=text;
        signal.Visibility=state=="on"?Visibility.Visible:Visibility.Collapsed;
        badge.BorderBrush=Res(state=="on"?"Text":state=="error"?"Danger":"LineStrong");
        badge.Background=Res(state=="on"?"Bg":"BgRaised");
        SetTray(state);
    }
    void SetTray(string state)
    {
        if(state==trayState)return;
        try{var next=TrayIcons.Load(state);tray.Icon=next;trayIcon?.Dispose();trayIcon=next;trayState=state;}
        catch(Exception error) when (error is IOException or ArgumentException or NullReferenceException){}
    }
    async Task Poll()
    {
        if(polling)return;polling=true;
        try {var s=await service.Call<JsonElement>("club.status");var state=s.GetProperty("state").GetString();
            if(state=="BASELINE_PASS_RUNTIME_UNVERIFIED")ShowState("Работает","Маршрутизация новых соединений включена.","on");
            else if(state=="ACTIVATION_ERROR")ShowState("Нужен администратор","VELIQ требует внимания администратора.","error");
            else ShowState("Подготовка","Готовим подключение…","connecting");
            try{games.Text=ClubPresentation.GameLine(await service.Call<GameUdpStatus>("gameudp.status"));}
            catch{games.Text="PUBG: диагностика пока недоступна";}
            try{var account=await service.Call<AccountConnectionView>("account.status");clubName.Text=account.Kind=="club"&&account.Name.Length>0?account.Name:"Клубный режим";}catch{}
        }
        catch {ShowState("Подготовка","Ожидаем готовность службы VELIQ…","connecting");}
        finally {polling=false;}
    }
    void EmergencyExit()
    {
        timer.Stop();
        var dialog=new EmergencyPasswordWindow(false,service);
        if(IsVisible)dialog.Owner=this;
        dialog.ShowDialog();
        if(dialog.Succeeded)Exit();else timer.Start();
    }
    public void ShowFromTray(){Show();WindowState=WindowState.Normal;Activate();}
    // Same-owner installer activation pipe only; never disables service or browsers.
    public void Exit(){exiting=true;timer.Stop();tray.Visible=false;tray.Dispose();trayIcon?.Dispose();Close();System.Windows.Application.Current.Shutdown();}
    public static bool IsClubInstallation()
    {
        try{return ClubPresentation.Enabled(File.ReadAllText(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"VELIQ","club-mode.json")));}
        catch(IOException){return false;}catch(UnauthorizedAccessException){return false;}
    }
}
