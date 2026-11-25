using System.Windows.Markup;
namespace Veliq.Desktop;
[MarkupExtensionReturnType(typeof(string))]
public sealed class TrExtension(string key) : MarkupExtension
{
    public string Key { get; } = key;
    public override object ProvideValue(IServiceProvider serviceProvider) => Text.Get(Key);
}
