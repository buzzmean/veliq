using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
namespace Neexitlag.Desktop;
// Attached state for the navigation rail and segmented tabs (Assets/Theme.xaml).
public static class Nav
{
    public static readonly DependencyProperty IconProperty = DependencyProperty.RegisterAttached("Icon", typeof(Geometry), typeof(Nav), new PropertyMetadata(null));
    public static Geometry? GetIcon(DependencyObject target) => (Geometry?)target.GetValue(IconProperty);
    public static void SetIcon(DependencyObject target, Geometry? value) => target.SetValue(IconProperty, value);
    public static readonly DependencyProperty IsCurrentProperty = DependencyProperty.RegisterAttached("IsCurrent", typeof(bool), typeof(Nav), new PropertyMetadata(false));
    public static bool GetIsCurrent(DependencyObject target) => (bool)target.GetValue(IsCurrentProperty);
    public static void SetIsCurrent(DependencyObject target, bool value) => target.SetValue(IsCurrentProperty, value);
}
public sealed class BoolToCollapsedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is true ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
public sealed class EmptyToCollapsedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
