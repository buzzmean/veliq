using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
namespace Veliq.Desktop;
public partial class GamesView:UserControl {
    public GamesView()=>InitializeComponent();
    GameCatalogViewModel? Vm=>DataContext as GameCatalogViewModel;
    void SelectGame(object sender,RoutedEventArgs e){if(Vm is {} vm && sender is Button {DataContext:GameCard game} tile){vm.Select(game);if(vm.Selected==game)Dispatcher.BeginInvoke(tile.BringIntoView,DispatcherPriority.Loaded);}}
    void ChooseRoute(object sender,RoutedEventArgs e){if(Vm is {} vm && sender is Button {DataContext:RouteOption route})vm.ChooseRoute(route);}
    async void Apply(object sender,RoutedEventArgs e){if(Vm is {Selected:{} game} vm)await vm.ApplyAsync(game);}
    async void Repair(object sender,RoutedEventArgs e){if(Vm is {Selected:{} game} vm)await vm.RepairLauncherAsync(game);}
    // The route strip closes on Esc, on a click anywhere except the strip or a game badge, and when the screen is left.
    void EscapeCloses(object sender,KeyEventArgs e){if(e.Key==Key.Escape && Vm is {HasSelection:true} vm){vm.Close();e.Handled=true;}}
    void ClickOutside(object sender,MouseButtonEventArgs e){if(Vm is {HasSelection:true} vm && !Within(e.OriginalSource as DependencyObject))vm.Close();}
    void Leave(object sender,RoutedEventArgs e)=>Vm?.Close();
    bool Within(DependencyObject? d){
        for(;d is not null;d=d is Visual or System.Windows.Media.Media3D.Visual3D?VisualTreeHelper.GetParent(d):LogicalTreeHelper.GetParent(d))
            if(d==RoutePanel || d is Button {DataContext:GameCard})return true;
        return false;
    }
}
